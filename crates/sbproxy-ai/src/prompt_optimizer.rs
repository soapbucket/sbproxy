//! Offline, evaluation-gated system-prompt optimization.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::Duration;

const MAX_COMPLETION_RESPONSE_BYTES: usize = 1024 * 1024;

/// One customer-supplied deterministic evaluation case.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptEvalCase {
    /// Stable case identity used in diagnostics.
    pub id: String,
    /// User input evaluated with each candidate system prompt.
    pub input: String,
    /// Expected output interpreted by the selected metric.
    pub expected: serde_json::Value,
}

/// Closed deterministic quality metric for offline prompt compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptEvalMetric {
    /// Trimmed response text must equal the expected string.
    ExactMatch,
    /// Response text must contain the expected string.
    Contains,
    /// Response text must parse to the expected JSON value.
    JsonExact,
}

/// Bounds and model choices for one offline optimization run.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptOptimizationConfig {
    /// Prompt-store name written into the output artifact.
    pub name: String,
    /// Prompt-store version label written into the output artifact.
    pub version: String,
    /// Model used to score the original and candidate instructions.
    pub task_model: String,
    /// Model used once to propose instruction-only candidates.
    pub optimizer_model: String,
    /// Deterministic quality metric.
    pub metric: PromptEvalMetric,
    /// Maximum accepted quality drop from the baseline, from zero to one.
    pub noise_tolerance: f64,
    /// Maximum candidate instructions evaluated.
    pub max_candidates: usize,
    /// Hard cap on all model calls, including proposal generation.
    pub max_requests: usize,
}

/// One OpenAI-compatible chat message used by the optimizer client seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptOptimizationMessage {
    /// OpenAI-compatible role.
    pub role: String,
    /// Text content.
    pub content: String,
}

/// One bounded completion request made by the offline optimizer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PromptOptimizationRequest {
    /// Target model.
    pub model: String,
    /// System and user messages.
    pub messages: Vec<PromptOptimizationMessage>,
    /// Sampling temperature.
    pub temperature: f64,
}

/// Completion seam used by production HTTP and deterministic tests.
#[async_trait]
pub trait PromptOptimizationClient: Send + Sync {
    /// Execute one completion and return assistant text only.
    async fn complete(&self, request: PromptOptimizationRequest) -> Result<String>;
}

/// Bounded OpenAI-compatible HTTP client used by the offline CLI.
#[derive(Clone)]
pub struct OpenAiPromptOptimizationClient {
    http: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
    host_header: Option<reqwest::header::HeaderValue>,
}

impl std::fmt::Debug for OpenAiPromptOptimizationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiPromptOptimizationClient")
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("host_header", &self.host_header)
            .finish_non_exhaustive()
    }
}

impl OpenAiPromptOptimizationClient {
    /// Build a client for an OpenAI-compatible base URL or full chat endpoint.
    pub fn new(endpoint: &str, api_key: Option<String>, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            bail!("prompt optimizer timeout must be greater than zero");
        }
        let endpoint = normalized_chat_endpoint(endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("build prompt optimizer HTTP client")?;
        Ok(Self {
            http,
            endpoint,
            api_key,
            host_header: None,
        })
    }

    /// Override the HTTP `Host` header while retaining the endpoint's dial address.
    pub fn with_host_header(mut self, host: &str) -> Result<Self> {
        if host.trim().is_empty() || host.trim() != host {
            bail!("prompt optimizer Host header must be nonblank without surrounding whitespace");
        }
        self.host_header = Some(
            host.parse::<reqwest::header::HeaderValue>()
                .context("invalid prompt optimizer Host header")?,
        );
        Ok(self)
    }
}

#[async_trait]
impl PromptOptimizationClient for OpenAiPromptOptimizationClient {
    async fn complete(&self, request: PromptOptimizationRequest) -> Result<String> {
        let mut outbound = self.http.post(&self.endpoint);
        if let Some(host) = &self.host_header {
            outbound = outbound.header(reqwest::header::HOST, host);
        }
        if let Some(api_key) = self.api_key.as_deref().filter(|value| !value.is_empty()) {
            outbound = outbound.bearer_auth(api_key);
        }
        let response = outbound
            .json(&serde_json::json!({
                "model": request.model,
                "messages": request.messages,
                "temperature": request.temperature,
                "stream": false,
            }))
            .send()
            .await
            .context("OpenAI-compatible prompt optimizer request failed")?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "OpenAI-compatible prompt optimizer returned HTTP {}",
                status.as_u16()
            );
        }

        use futures::StreamExt as _;
        let mut stream = response.bytes_stream();
        let mut bytes = bytes::BytesMut::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("read prompt optimizer response body")?;
            if bytes.len().saturating_add(chunk.len()) > MAX_COMPLETION_RESPONSE_BYTES {
                bail!(
                    "prompt optimizer response exceeded {} bytes",
                    MAX_COMPLETION_RESPONSE_BYTES
                );
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).context("prompt optimizer response was not JSON")?;
        body.pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
            .filter(|content| !content.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("prompt optimizer response had no assistant content"))
    }
}

/// Admin-ready versioned prompt payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizedPromptVersion {
    /// Version label supplied by the operator.
    pub version: String,
    /// Optimized static template.
    pub template: String,
    /// Static template variables; empty for instruction-only optimization.
    pub variables: serde_json::Map<String, serde_json::Value>,
}

/// Deterministic optimization artifact and its quality evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizedPromptArtifact {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Prompt-store name.
    pub name: String,
    /// SHA-256 of the source prompt.
    pub source_sha256: String,
    /// Metric used for the gate.
    pub metric: PromptEvalMetric,
    /// Baseline aggregate score.
    pub baseline_score: f64,
    /// Selected candidate aggregate score.
    pub optimized_score: f64,
    /// Configured maximum quality drop.
    pub noise_tolerance: f64,
    /// Target-model tokens in the original prompt.
    pub original_tokens: u64,
    /// Target-model tokens in the optimized prompt.
    pub optimized_tokens: u64,
    /// Admin API payload for `POST .../<name>/versions`.
    pub prompt_version: OptimizedPromptVersion,
}

/// Parse newline-delimited evaluation cases.
pub fn parse_prompt_eval_jsonl(bytes: &[u8]) -> Result<Vec<PromptEvalCase>> {
    let source = std::str::from_utf8(bytes).context("eval set must be UTF-8 JSONL")?;
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let case: PromptEvalCase = serde_json::from_str(line)
            .with_context(|| format!("invalid eval JSON on line {line_number}"))?;
        validate_case(&case).with_context(|| format!("invalid eval case on line {line_number}"))?;
        if !ids.insert(case.id.clone()) {
            bail!("duplicate eval case id {:?}", case.id);
        }
        cases.push(case);
    }
    if cases.is_empty() {
        bail!("eval set must contain at least one case");
    }
    Ok(cases)
}

/// Compile a shorter prompt and accept it only when quality stays within noise.
pub async fn optimize_prompt(
    client: &dyn PromptOptimizationClient,
    source_prompt: &str,
    cases: &[PromptEvalCase],
    config: &PromptOptimizationConfig,
) -> Result<OptimizedPromptArtifact> {
    validate_run(source_prompt, cases, config)?;

    let mut requests_used = 0usize;
    let baseline_score =
        evaluate_prompt(client, source_prompt, cases, config, &mut requests_used).await?;

    reserve_requests(requests_used, 1, config.max_requests)?;
    let proposal = client
        .complete(candidate_request(source_prompt, config))
        .await
        .context("optimizer model failed to propose candidates")?;
    requests_used += 1;

    let original_tokens =
        crate::token_estimate::estimate_text_tokens(&config.task_model, source_prompt);
    let mut seen = BTreeSet::new();
    let mut candidates = parse_candidates(&proposal)?
        .into_iter()
        .filter_map(|candidate| {
            let candidate = candidate.trim().to_string();
            (!candidate.is_empty()
                && candidate != source_prompt.trim()
                && !looks_like_few_shot(&candidate)
                && !looks_like_dynamic_template(&candidate)
                && seen.insert(candidate.clone()))
            .then_some(candidate)
        })
        .map(|candidate| {
            (
                crate::token_estimate::estimate_text_tokens(&config.task_model, &candidate),
                candidate,
            )
        })
        .filter(|(candidate_tokens, _)| *candidate_tokens < original_tokens)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        bail!("optimizer model returned no usable shorter instruction-only candidates");
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let evaluation_slots = config
        .max_requests
        .saturating_sub(requests_used)
        .checked_div(cases.len())
        .unwrap_or(0);
    candidates.truncate(config.max_candidates.min(evaluation_slots));

    let minimum_score = (baseline_score - config.noise_tolerance).max(0.0);
    let mut accepted = Vec::new();
    for (candidate_tokens, candidate) in candidates {
        let score = evaluate_prompt(client, &candidate, cases, config, &mut requests_used).await?;
        if score + f64::EPSILON >= minimum_score {
            accepted.push((candidate_tokens, score, candidate));
        }
    }

    accepted.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| right.1.partial_cmp(&left.1).unwrap_or(Ordering::Equal))
            .then_with(|| left.2.cmp(&right.2))
    });
    let Some((optimized_tokens, optimized_score, template)) = accepted.into_iter().next() else {
        bail!(
            "no shorter candidate scored within {:.4} of baseline {:.4}",
            config.noise_tolerance,
            baseline_score
        );
    };

    Ok(OptimizedPromptArtifact {
        schema_version: 1,
        name: config.name.clone(),
        source_sha256: hex::encode(Sha256::digest(source_prompt.as_bytes())),
        metric: config.metric,
        baseline_score,
        optimized_score,
        noise_tolerance: config.noise_tolerance,
        original_tokens,
        optimized_tokens,
        prompt_version: OptimizedPromptVersion {
            version: config.version.clone(),
            template,
            variables: serde_json::Map::new(),
        },
    })
}

fn validate_case(case: &PromptEvalCase) -> Result<()> {
    if case.id.trim().is_empty() {
        bail!("id must not be blank");
    }
    if case.input.trim().is_empty() {
        bail!("input must not be blank");
    }
    if case
        .expected
        .as_str()
        .is_some_and(|expected| expected.trim().is_empty())
    {
        bail!("expected must not be blank");
    }
    if case.expected.is_null() {
        bail!("expected must not be null");
    }
    Ok(())
}

fn validate_run(
    source_prompt: &str,
    cases: &[PromptEvalCase],
    config: &PromptOptimizationConfig,
) -> Result<()> {
    if source_prompt.trim().is_empty() {
        bail!("source prompt must not be blank");
    }
    if looks_like_dynamic_template(source_prompt) {
        bail!("source prompt must be a static instruction without template markers");
    }
    if cases.is_empty() {
        bail!("eval set must contain at least one case");
    }
    for case in cases {
        validate_case(case)?;
        if matches!(
            config.metric,
            PromptEvalMetric::ExactMatch | PromptEvalMetric::Contains
        ) && case.expected.as_str().is_none()
        {
            bail!(
                "eval case {:?} expected must be a string for {:?}",
                case.id,
                config.metric
            );
        }
    }
    for (name, value) in [
        ("name", config.name.as_str()),
        ("version", config.version.as_str()),
        ("task_model", config.task_model.as_str()),
        ("optimizer_model", config.optimizer_model.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("{name} must not be blank");
        }
    }
    if !config.noise_tolerance.is_finite() || !(0.0..=1.0).contains(&config.noise_tolerance) {
        bail!("noise_tolerance must be finite and between 0 and 1");
    }
    if !(1..=64).contains(&config.max_candidates) {
        bail!("max_candidates must be between 1 and 64");
    }
    let minimum_requests = cases.len().saturating_mul(2).saturating_add(1);
    reserve_requests(0, minimum_requests, config.max_requests)?;
    Ok(())
}

fn reserve_requests(used: usize, additional: usize, maximum: usize) -> Result<()> {
    if used.saturating_add(additional) > maximum {
        bail!(
            "prompt optimization request budget exceeded: {used} used + {additional} required > {maximum}"
        );
    }
    Ok(())
}

async fn evaluate_prompt(
    client: &dyn PromptOptimizationClient,
    prompt: &str,
    cases: &[PromptEvalCase],
    config: &PromptOptimizationConfig,
    requests_used: &mut usize,
) -> Result<f64> {
    reserve_requests(*requests_used, cases.len(), config.max_requests)?;
    let mut matched = 0usize;
    for case in cases {
        let output = client
            .complete(PromptOptimizationRequest {
                model: config.task_model.clone(),
                messages: vec![
                    PromptOptimizationMessage {
                        role: "system".to_string(),
                        content: prompt.to_string(),
                    },
                    PromptOptimizationMessage {
                        role: "user".to_string(),
                        content: case.input.clone(),
                    },
                ],
                temperature: 0.0,
            })
            .await
            .with_context(|| format!("task model failed on eval case {:?}", case.id))?;
        *requests_used += 1;
        if score_output(config.metric, &output, &case.expected)? {
            matched += 1;
        }
    }
    Ok(matched as f64 / cases.len() as f64)
}

fn score_output(
    metric: PromptEvalMetric,
    output: &str,
    expected: &serde_json::Value,
) -> Result<bool> {
    match metric {
        PromptEvalMetric::ExactMatch => Ok(output.trim()
            == expected
                .as_str()
                .expect("validated exact-match expected string")
                .trim()),
        PromptEvalMetric::Contains => Ok(output.contains(
            expected
                .as_str()
                .expect("validated contains expected string"),
        )),
        PromptEvalMetric::JsonExact => Ok(serde_json::from_str::<serde_json::Value>(output.trim())
            .is_ok_and(|actual| actual == *expected)),
    }
}

fn candidate_request(
    source_prompt: &str,
    config: &PromptOptimizationConfig,
) -> PromptOptimizationRequest {
    PromptOptimizationRequest {
        model: config.optimizer_model.clone(),
        messages: vec![
            PromptOptimizationMessage {
                role: "system".to_string(),
                content: concat!(
                    "You optimize system instructions offline. Return only a JSON array of ",
                    "shorter, self-contained instruction strings. Preserve every requirement. ",
                    "Do not add examples, demonstrations, commentary, Markdown, or variables."
                )
                .to_string(),
            },
            PromptOptimizationMessage {
                role: "user".to_string(),
                content: format!(
                    "Produce at most {} candidates shorter than this instruction:\n\n{}",
                    config.max_candidates, source_prompt
                ),
            },
        ],
        temperature: 0.7,
    }
}

fn parse_candidates(output: &str) -> Result<Vec<String>> {
    let trimmed = output.trim();
    let json = if let Some(inner) = trimmed
        .strip_prefix("```json")
        .and_then(|value| value.strip_suffix("```"))
    {
        inner.trim()
    } else if let Some(inner) = trimmed
        .strip_prefix("```")
        .and_then(|value| value.strip_suffix("```"))
    {
        inner.trim()
    } else {
        trimmed
    };
    serde_json::from_str::<Vec<String>>(json)
        .context("optimizer response must be a JSON array of strings")
}

fn looks_like_few_shot(candidate: &str) -> bool {
    let lower = candidate.to_ascii_lowercase();
    let lines = lower.lines().map(str::trim_start).collect::<Vec<_>>();
    let has_label = |label: &str| {
        lines.iter().any(|line| {
            line.strip_prefix(label)
                .is_some_and(|rest| rest.starts_with(':'))
        })
    };
    let has_numbered_example = lines
        .iter()
        .any(|line| line.starts_with("example ") && line.contains(':'));

    lower.contains("example:")
        || lower.contains("examples:")
        || lower.contains("for example")
        || lower.contains("few-shot")
        || lower.contains("few shot")
        || has_numbered_example
        || (has_label("input") && has_label("output"))
        || (has_label("user") && has_label("assistant"))
        || (has_label("question") && has_label("answer"))
        || (has_label("q") && has_label("a"))
}

fn looks_like_dynamic_template(candidate: &str) -> bool {
    candidate.contains("{{") || candidate.contains("{%") || candidate.contains("{#")
}

fn normalized_chat_endpoint(endpoint: &str) -> Result<String> {
    let mut url = url::Url::parse(endpoint).context("invalid prompt optimizer endpoint")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("prompt optimizer endpoint must use http or https");
    }
    if url.host_str().is_none() {
        bail!("prompt optimizer endpoint must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("prompt optimizer endpoint must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("prompt optimizer endpoint must not contain a query or fragment");
    }

    let path = url.path().trim_end_matches('/').to_string();
    if !path.ends_with("/chat/completions") {
        url.set_path(&format!("{path}/chat/completions"));
    } else {
        url.set_path(&path);
    }
    Ok(url.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeClient {
        responses: Mutex<VecDeque<String>>,
        requests: Mutex<Vec<PromptOptimizationRequest>>,
    }

    impl FakeClient {
        fn new(responses: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(str::to_string).collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PromptOptimizationClient for FakeClient {
        async fn complete(&self, request: PromptOptimizationRequest) -> Result<String> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("fake response queue exhausted"))
        }
    }

    fn cases() -> Vec<PromptEvalCase> {
        vec![
            PromptEvalCase {
                id: "one".to_string(),
                input: "Say alpha".to_string(),
                expected: serde_json::json!("alpha"),
            },
            PromptEvalCase {
                id: "two".to_string(),
                input: "Say beta".to_string(),
                expected: serde_json::json!("beta"),
            },
        ]
    }

    fn config() -> PromptOptimizationConfig {
        PromptOptimizationConfig {
            name: "concise-answer".to_string(),
            version: "2".to_string(),
            task_model: "task-model".to_string(),
            optimizer_model: "optimizer-model".to_string(),
            metric: PromptEvalMetric::ExactMatch,
            noise_tolerance: 0.1,
            max_candidates: 4,
            max_requests: 16,
        }
    }

    #[test]
    fn openai_client_debug_redacts_api_key_and_preserves_operational_context() {
        let raw_key = "sk-debug-secret";
        let bearer_value = format!("Bearer {raw_key}");
        let client = OpenAiPromptOptimizationClient::new(
            "https://gateway.example/v1",
            Some(raw_key.to_string()),
            Duration::from_secs(2),
        )
        .expect("client configuration is valid")
        .with_host_header("ai.internal")
        .expect("Host override is valid");

        let debug = format!("{client:?}");

        assert!(debug.contains("OpenAiPromptOptimizationClient"), "{debug}");
        assert!(
            debug.contains("https://gateway.example/v1/chat/completions"),
            "{debug}"
        );
        assert!(debug.contains("api_key"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("ai.internal"), "{debug}");
        assert!(!debug.contains(raw_key), "{debug}");
        assert!(!debug.contains(&bearer_value), "{debug}");
    }

    #[test]
    fn parses_nonblank_jsonl_and_rejects_duplicate_ids() {
        let parsed = parse_prompt_eval_jsonl(
            br#"
{"id":"one","input":"Say alpha","expected":"alpha"}
{"id":"two","input":"Return JSON","expected":{"ok":true}}
"#,
        )
        .expect("valid JSONL");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].expected, serde_json::json!({"ok": true}));

        let duplicate = br#"{"id":"same","input":"a","expected":"a"}
{"id":"same","input":"b","expected":"b"}"#;
        assert!(parse_prompt_eval_jsonl(duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn rejects_blank_string_expectations_in_jsonl() {
        for expected in [r#""""#, r#"" \t ""#] {
            let jsonl = format!(r#"{{"id":"blank","input":"classify","expected":{expected}}}"#);
            let error = format!(
                "{:#}",
                parse_prompt_eval_jsonl(jsonl.as_bytes())
                    .expect_err("blank expected string must be rejected")
            );
            assert!(error.contains("expected must not be blank"), "{error}");
        }
    }

    #[tokio::test]
    async fn rejects_blank_expectations_for_string_metrics_before_model_calls() {
        for metric in [PromptEvalMetric::ExactMatch, PromptEvalMetric::Contains] {
            let fake = FakeClient::new([]);
            let mut config = config();
            config.metric = metric;
            let blank_case = PromptEvalCase {
                id: "blank".to_string(),
                input: "classify".to_string(),
                expected: serde_json::json!(" \t "),
            };

            let error = optimize_prompt(&fake, "Classify the input.", &[blank_case], &config)
                .await
                .expect_err("blank expected string must fail before evaluation")
                .to_string();

            assert!(error.contains("expected must not be blank"), "{error}");
            assert!(fake.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn selects_shortest_candidate_that_stays_within_noise() {
        let source =
            "You are a careful assistant. Return exactly the requested word and no other text.";
        let fake = FakeClient::new([
            "alpha",
            "beta",
            r#"["Return only the requested word.", "Be brief."]"#,
            "wrong",
            "beta",
            "alpha",
            "beta",
        ]);

        let artifact = optimize_prompt(&fake, source, &cases(), &config())
            .await
            .expect("one shorter candidate retains baseline quality");

        assert_eq!(
            artifact.prompt_version.template,
            "Return only the requested word."
        );
        assert_eq!(artifact.baseline_score, 1.0);
        assert_eq!(artifact.optimized_score, 1.0);
        assert!(artifact.optimized_tokens < artifact.original_tokens);
        assert_eq!(artifact.prompt_version.variables, serde_json::Map::new());
        assert_eq!(fake.requests.lock().unwrap().len(), 7);
    }

    #[tokio::test]
    async fn fails_when_no_shorter_candidate_meets_the_quality_gate() {
        let source = "Answer exactly.";
        let fake = FakeClient::new([
            "alpha",
            "beta",
            r#"["This candidate instruction is much longer than the original prompt.", "Short."]"#,
            "wrong",
            "wrong",
        ]);

        let error = optimize_prompt(&fake, source, &cases(), &config())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("no shorter candidate"));
    }

    #[tokio::test]
    async fn request_cap_stops_candidate_evaluation_without_discarding_an_accepted_result() {
        let source =
            "You are a careful assistant. Return exactly the requested word and no other text.";
        let fake = FakeClient::new([
            "alpha",
            "beta",
            r#"["Answer.", "Return only the requested word."]"#,
            "alpha",
            "beta",
        ]);
        let mut bounded = config();
        bounded.max_requests = 5;

        let artifact = optimize_prompt(&fake, source, &cases(), &bounded)
            .await
            .expect("one bounded candidate evaluation should produce an artifact");

        assert_eq!(artifact.prompt_version.template, "Answer.");
        assert_eq!(fake.requests.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn rejects_dynamic_source_templates_before_model_calls() {
        let fake = FakeClient::new([]);
        let error = optimize_prompt(
            &fake,
            "Answer for {{ variables.audience }}.",
            &cases(),
            &config(),
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(error.contains("static"));
        assert!(fake.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn invalid_json_scores_as_a_miss_instead_of_aborting_the_eval() {
        assert!(!score_output(
            PromptEvalMetric::JsonExact,
            "not JSON",
            &serde_json::json!({"ok": true}),
        )
        .expect("invalid task output is a deterministic miss"));
    }

    #[test]
    fn recognizes_common_few_shot_demonstration_markers() {
        for candidate in [
            "Examples:\nInput: yes\nOutput: approved",
            "Example 1: classify this as approved.",
            "User: access granted\nAssistant: approved",
            "Question: access granted?\nAnswer: approved",
            "Q: access granted?\nA: approved",
            "For example, map access granted to approved.",
            "Use a few shot demonstration.",
        ] {
            assert!(looks_like_few_shot(candidate), "{candidate}");
        }
        assert!(!looks_like_few_shot(
            "Return approved when the input says access granted."
        ));
    }

    #[tokio::test]
    async fn rejects_dynamic_templates_and_emits_a_prompt_store_compatible_version() {
        let source =
            "You are a careful assistant. Return exactly the requested word and no other text.";
        let fake = FakeClient::new([
            "alpha",
            "beta",
            r#"["Return {{ request.answer }}.", "Return only the requested word."]"#,
            "alpha",
            "beta",
        ]);

        let artifact = optimize_prompt(&fake, source, &cases(), &config())
            .await
            .expect("static candidate retains quality");
        assert_eq!(
            artifact.prompt_version.template,
            "Return only the requested word."
        );

        let prompt_version: crate::prompts::PromptVersion =
            serde_json::from_value(serde_json::to_value(&artifact.prompt_version).unwrap())
                .expect("artifact version uses the runtime prompt-store payload");
        let store = crate::prompts::PromptStore {
            templates: std::iter::once((
                artifact.name.clone(),
                crate::prompts::NamedPrompt {
                    default_version: Some(artifact.prompt_version.version.clone()),
                    versions: std::iter::once((
                        artifact.prompt_version.version.clone(),
                        prompt_version,
                    ))
                    .collect(),
                    labels: std::collections::HashMap::new(),
                },
            ))
            .collect(),
            partials: std::collections::HashMap::new(),
        };
        let rendered = store
            .render(&artifact.name, &serde_json::json!({}))
            .expect("runtime renders the static optimized artifact");
        assert_eq!(rendered.text, artifact.prompt_version.template);
    }

    #[test]
    fn normalizes_openai_compatible_endpoint_without_dropping_v1() {
        assert_eq!(
            normalized_chat_endpoint("https://gateway.example/v1").unwrap(),
            "https://gateway.example/v1/chat/completions"
        );
        assert_eq!(
            normalized_chat_endpoint("https://gateway.example/v1/").unwrap(),
            "https://gateway.example/v1/chat/completions"
        );
        assert_eq!(
            normalized_chat_endpoint("https://gateway.example/v1/chat/completions").unwrap(),
            "https://gateway.example/v1/chat/completions"
        );
        assert!(normalized_chat_endpoint("file:///tmp/provider").is_err());
        assert!(normalized_chat_endpoint("https://user:pass@gateway.example/v1").is_err());
    }

    #[tokio::test]
    async fn openai_client_sends_auth_and_returns_assistant_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let body = r#"{"choices":[{"message":{"content":"candidate"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                .await
                .unwrap();
            request
        });

        let client = OpenAiPromptOptimizationClient::new(
            &format!("http://{address}/v1"),
            Some("secret-token".to_string()),
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let output = client
            .complete(PromptOptimizationRequest {
                model: "optimizer".to_string(),
                messages: vec![PromptOptimizationMessage {
                    role: "user".to_string(),
                    content: "shorten this".to_string(),
                }],
                temperature: 0.7,
            })
            .await
            .unwrap();
        assert_eq!(output, "candidate");

        let request = server.await.unwrap();
        assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-token\r\n"));
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["model"], "optimizer");
        assert_eq!(json["stream"], false);
        assert_eq!(json["temperature"], 0.7);
    }

    #[tokio::test]
    async fn openai_client_can_override_the_http_host_for_a_local_gateway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let body = r#"{"choices":[{"message":{"content":"candidate"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                .await
                .unwrap();
            request
        });

        let client = OpenAiPromptOptimizationClient::new(
            &format!("http://{address}/v1"),
            None,
            std::time::Duration::from_secs(2),
        )
        .unwrap()
        .with_host_header("ai.local")
        .unwrap();
        client
            .complete(PromptOptimizationRequest {
                model: "optimizer".to_string(),
                messages: vec![PromptOptimizationMessage {
                    role: "user".to_string(),
                    content: "shorten this".to_string(),
                }],
                temperature: 0.7,
            })
            .await
            .unwrap();

        let request = server.await.unwrap();
        assert!(
            request
                .to_ascii_lowercase()
                .contains("\r\nhost: ai.local\r\n"),
            "{request}"
        );
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt as _;

        let mut bytes = Vec::new();
        let mut scratch = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut scratch).await.unwrap();
            assert!(read > 0, "client closed before request headers");
            bytes.extend_from_slice(&scratch[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .map(str::to_string)
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut scratch).await.unwrap();
            assert!(read > 0, "client closed before request body");
            bytes.extend_from_slice(&scratch[..read]);
        }
        String::from_utf8(bytes).unwrap()
    }
}
