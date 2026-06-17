//! `semantic_constraint` policy (WOR-203 PR 3b).
//!
//! Routes a request through the
//! [`JudgeClient`](sbproxy_ai::judge::JudgeClient) at evaluation time
//! and translates the verdict into a
//! [`PolicyDecision`](sbproxy_plugin::PolicyDecision). The policy is
//! the run-time half of the WOR-147 NL policy authoring story: NL
//! goes through the [`NlCompiler`](crate::policy::nl_compiler::NlCompiler)
//! at authoring time, the resulting prompt template is stored in
//! this policy's config, and live traffic is judged against it on
//! every request.
//!
//! The OSS slice does not link the Cedar evaluator. A
//! `semantic_constraint` policy in OSS is therefore a "raw prompt"
//! policy: the configured `prompt_template` is rendered against the
//! request context and sent straight to the judge. The
//! `policy_id` field is recorded for audit linkage to a pinned
//! [`CompiledPolicy`](crate::policy::compiled_policy_store::CompiledPolicy)
//! when one is available; the OSS path does not consult the
//! [`CompiledPolicyStore`](crate::policy::compiled_policy_store::CompiledPolicyStore)
//! at evaluation time.
//!
//! ## Verdict mapping
//!
//! | Judge return | Enforcer return |
//! |---|---|
//! | `Ok(Allow)` | `Allow` |
//! | `Ok(AllowWithHeaders { headers })` | `AllowWithHeaders { headers }` (passthrough) |
//! | `Ok(Confirm { .. })` | `Confirm { .. }` (passthrough; the OSS dispatcher bridges to `AllowWithHeaders` per the verdict-shape ADR) |
//! | `Ok(Deny { .. })` and `violations_block = true` | passthrough Deny |
//! | `Ok(Deny { .. })` and `violations_block = false` | log + `Allow` (informational mode) |
//! | `Err(BudgetExhausted)` | `Deny { 429, "judge_budget_exhausted" }` |
//! | `Err(_)` | `Deny { 500, "semantic_constraint_judge_failure" }` (fail-closed) |
//!
//! ## Template rendering
//!
//! The `prompt_template` is rendered with [`minijinja`] (already a
//! workspace dep used by `transform/text.rs`). The available context
//! keys for v1 are:
//!
//! - `request.method` (string)
//! - `request.path` (string)
//! - `request.host` (string)
//! - `request.query` (string, empty when no query)
//!
//! Template errors at evaluation time fall through to the
//! `semantic_constraint_template_error` deny path so a malformed
//! template never silently allows traffic.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use sbproxy_ai::judge::{JudgeClient, JudgeError};
use sbproxy_plugin::PolicyDecision;
use serde::Deserialize;
use tracing::warn;

/// Configuration for a single `semantic_constraint` policy entry.
///
/// Lives at the YAML layer; built by
/// [`SemanticConstraintPolicy::from_config`] from a `serde_json::Value`.
/// `judge` is the per-policy judge wiring (endpoint, API-key env var,
/// budget) so multiple `semantic_constraint` blocks in one origin can
/// point at different providers without sharing state.
#[derive(Debug, Clone, Deserialize)]
pub struct SemanticConstraintConfig {
    /// minijinja template rendered against the request context to
    /// produce the prompt sent to the judge.
    pub prompt_template: String,
    /// When `true`, a judge `Deny` verdict is returned verbatim. When
    /// `false`, a judge `Deny` verdict is logged and the request is
    /// allowed; this is the "monitor mode" used during rollout.
    #[serde(default)]
    pub violations_block: bool,
    /// Optional reference to a pinned
    /// [`CompiledPolicy`](crate::policy::compiled_policy_store::CompiledPolicy)
    /// in the [`CompiledPolicyStore`](crate::policy::compiled_policy_store::CompiledPolicyStore).
    /// Stored as a string at the YAML layer (the workspace `uuid`
    /// crate is built without the `serde` feature) and parsed by the
    /// caller. OSS records the value on the audit event but does not
    /// consult the store at evaluation time.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Per-policy judge wiring. Required; a `semantic_constraint`
    /// policy without a configured judge cannot evaluate.
    pub judge: JudgeWiring,
}

/// YAML-friendly subset of [`sbproxy_ai::judge::JudgeConfig`].
///
/// Mirrors the public fields with sensible defaults so a minimal YAML
/// only needs to carry `endpoint` and `api_key_env`. The endpoint is
/// stored as a string at the YAML layer (the workspace `url` crate
/// is built without the `serde` feature) and parsed in
/// [`SemanticConstraintPolicy::from_config`].
#[derive(Debug, Clone, Deserialize)]
pub struct JudgeWiring {
    /// Upstream chat-completions endpoint, parsed at config-compile
    /// time. A malformed URL surfaces as a config error from
    /// [`SemanticConstraintPolicy::from_config`].
    pub endpoint: String,
    /// Environment variable holding the bearer API key.
    pub api_key_env: String,
    /// Per-call timeout in milliseconds. Defaults to
    /// [`sbproxy_ai::judge::JudgeConfig::DEFAULT_TIMEOUT_MS`].
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    /// LRU cache capacity. Defaults to
    /// [`sbproxy_ai::judge::JudgeConfig::DEFAULT_CACHE_CAPACITY`].
    #[serde(default)]
    pub cache_capacity: Option<usize>,
    /// Per-process token budget. Defaults to 100_000.
    #[serde(default)]
    pub budget_tokens: Option<u64>,
}

const DEFAULT_BUDGET_TOKENS: u64 = 100_000;

/// Compiled `semantic_constraint` policy ready to evaluate.
///
/// Holds the rendered config plus an `Arc<JudgeClient>` so the
/// enforcer can evaluate without rebuilding the HTTP client per
/// request. Cheap to clone (`Arc` shared).
#[derive(Clone)]
pub struct SemanticConstraintPolicy {
    config: SemanticConstraintConfig,
    judge: Arc<JudgeClient>,
}

impl std::fmt::Debug for SemanticConstraintPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticConstraintPolicy")
            .field("prompt_template", &self.config.prompt_template)
            .field("violations_block", &self.config.violations_block)
            .field("policy_id", &self.config.policy_id)
            .finish()
    }
}

impl SemanticConstraintPolicy {
    /// Build from a JSON config (the `compile_policy` entry point).
    ///
    /// The JSON shape is the deserialised form of
    /// [`SemanticConstraintConfig`]. The `judge` block is required;
    /// every other field except `prompt_template` is optional.
    pub fn from_config(value: serde_json::Value) -> Result<Self> {
        let config: SemanticConstraintConfig = serde_json::from_value(value)?;
        if config.prompt_template.trim().is_empty() {
            return Err(anyhow!(
                "semantic_constraint policy: prompt_template must not be empty"
            ));
        }
        let judge = build_judge_client(&config.judge)?;
        Ok(Self {
            config,
            judge: Arc::new(judge),
        })
    }

    /// Build with a caller-supplied judge client. Useful when the
    /// runtime wants to share one judge instance across many
    /// `semantic_constraint` policies (single-provider deployments)
    /// or for testing.
    pub fn with_judge(config: SemanticConstraintConfig, judge: Arc<JudgeClient>) -> Self {
        Self { config, judge }
    }

    /// Borrow the underlying config. Test + diagnostic accessor.
    pub fn config(&self) -> &SemanticConstraintConfig {
        &self.config
    }

    /// Borrow the underlying judge client. Test + diagnostic accessor.
    pub fn judge(&self) -> &Arc<JudgeClient> {
        &self.judge
    }

    /// Render the prompt template against the request context and
    /// evaluate.
    ///
    /// `request_ctx` is the JSON shape exposed to the template:
    ///
    /// ```json
    /// {"request": {"method": "GET", "path": "/v1/x", "host": "api.local", "query": ""}}
    /// ```
    ///
    /// Callers in the request pipeline build this from the live
    /// request; tests construct it directly.
    pub async fn enforce(&self, request_ctx: serde_json::Value) -> PolicyDecision {
        let rendered = match render_prompt(&self.config.prompt_template, &request_ctx) {
            Ok(s) => s,
            Err(err) => {
                warn!(
                    target: "sbproxy::semantic_constraint",
                    error = %err,
                    "template render failed; failing closed"
                );
                return PolicyDecision::Deny {
                    status: 500,
                    message: "semantic_constraint_template_error".to_string(),
                };
            }
        };
        // Pass an empty payload for the OSS scope; the prompt itself
        // carries the rendered request shape. The enterprise wiring
        // forwards the redacted body via sbproxy-security PII redactor.
        let payload = serde_json::Value::Object(serde_json::Map::new());
        match self.judge.semantic(&rendered, payload).await {
            Ok(PolicyDecision::Deny { status, message }) => {
                if self.config.violations_block {
                    PolicyDecision::Deny { status, message }
                } else {
                    warn!(
                        target: "sbproxy::semantic_constraint",
                        status = status,
                        message = %message,
                        "judge denied but violations_block=false; allowing"
                    );
                    PolicyDecision::Allow
                }
            }
            // Allow / AllowWithHeaders / Confirm pass through verbatim;
            // the OSS dispatcher bridges Confirm to AllowWithHeaders
            // per the verdict-shape ADR. `Confirm` is `#[non_exhaustive]`
            // so we forward the verdict value rather than destructuring
            // and reconstructing it here.
            Ok(other) => other,
            Err(JudgeError::BudgetExhausted) => PolicyDecision::Deny {
                status: 429,
                message: "judge_budget_exhausted".to_string(),
            },
            Err(err) => {
                warn!(
                    target: "sbproxy::semantic_constraint",
                    error = %err,
                    "judge call failed; failing closed"
                );
                PolicyDecision::Deny {
                    status: 500,
                    message: "semantic_constraint_judge_failure".to_string(),
                }
            }
        }
    }
}

/// Build a [`JudgeClient`] from the YAML wiring. Defaults pulled
/// from [`sbproxy_ai::judge::JudgeConfig`] constants. A malformed
/// `endpoint` URL surfaces as a config error.
fn build_judge_client(wiring: &JudgeWiring) -> Result<JudgeClient> {
    use sbproxy_ai::judge::JudgeConfig;
    let endpoint = url::Url::parse(&wiring.endpoint)
        .map_err(|e| anyhow!("invalid judge endpoint URL '{}': {}", wiring.endpoint, e))?;
    let cfg = JudgeConfig {
        endpoint,
        api_key_env: wiring.api_key_env.clone(),
        timeout_ms: wiring.timeout_ms.unwrap_or(JudgeConfig::DEFAULT_TIMEOUT_MS),
        cache_capacity: wiring
            .cache_capacity
            .unwrap_or(JudgeConfig::DEFAULT_CACHE_CAPACITY),
        budget_tokens: wiring.budget_tokens.unwrap_or(DEFAULT_BUDGET_TOKENS),
    };
    Ok(JudgeClient::new(cfg))
}

/// Render the prompt template via minijinja. The template is parsed
/// per call; for v1 the parse cost is acceptable next to the network
/// round-trip to the judge. A future optimisation can pre-parse once
/// at config-compile time.
fn render_prompt(template: &str, ctx: &serde_json::Value) -> Result<String> {
    let env = minijinja::Environment::new();
    let rendered = env.render_str(template, ctx)?;
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::judge::{BudgetTracker, JudgeCache, JudgeConfig};

    /// Build a `JudgeClient` whose cache is pre-loaded with a
    /// verdict for the given prompt + payload pair. The endpoint
    /// points at a closed port so a cache miss surfaces as a
    /// transport error.
    fn primed_client(
        prompt: &str,
        payload: &serde_json::Value,
        verdict: PolicyDecision,
        budget: u64,
    ) -> Arc<JudgeClient> {
        let endpoint = url::Url::parse("http://127.0.0.1:1/judge").unwrap();
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_SC_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 16,
            budget_tokens: budget,
        };
        let cache = Arc::new(JudgeCache::new(cfg.cache_capacity));
        let budget_tracker = Arc::new(BudgetTracker::new(cfg.budget_tokens));
        let client = Arc::new(JudgeClient::with_components(
            cfg,
            cache.clone(),
            budget_tracker,
            String::new(),
        ));
        let key = sbproxy_ai::judge::cache::cache_key(prompt, payload);
        cache.put(key, verdict);
        client
    }

    fn config(violations_block: bool) -> SemanticConstraintConfig {
        SemanticConstraintConfig {
            prompt_template: "classify {{ request.path }}".to_string(),
            violations_block,
            policy_id: None,
            judge: JudgeWiring {
                endpoint: "http://127.0.0.1:1/".to_string(),
                api_key_env: "SBPROXY_SC_TEST_KEY".to_string(),
                timeout_ms: Some(1_500),
                cache_capacity: Some(16),
                budget_tokens: Some(100),
            },
        }
    }

    fn request_ctx(path: &str) -> serde_json::Value {
        serde_json::json!({
            "request": {
                "method": "GET",
                "path": path,
                "host": "api.local",
                "query": "",
            }
        })
    }

    #[tokio::test]
    async fn judge_allow_returns_allow() {
        let cfg = config(true);
        let payload = serde_json::Value::Object(serde_json::Map::new());
        let prompt = render_prompt(&cfg.prompt_template, &request_ctx("/x")).unwrap();
        let judge = primed_client(&prompt, &payload, PolicyDecision::Allow, 100);
        let policy = SemanticConstraintPolicy::with_judge(cfg, judge);

        let decision = policy.enforce(request_ctx("/x")).await;
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn judge_deny_blocks_when_violations_block() {
        let cfg = config(true);
        let payload = serde_json::Value::Object(serde_json::Map::new());
        let prompt = render_prompt(&cfg.prompt_template, &request_ctx("/secret")).unwrap();
        let verdict = PolicyDecision::Deny {
            status: 403,
            message: "secret path".to_string(),
        };
        let judge = primed_client(&prompt, &payload, verdict, 100);
        let policy = SemanticConstraintPolicy::with_judge(cfg, judge);

        let decision = policy.enforce(request_ctx("/secret")).await;
        match decision {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 403);
                assert_eq!(message, "secret path");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn judge_deny_passes_when_violations_block_false() {
        let cfg = config(false);
        let payload = serde_json::Value::Object(serde_json::Map::new());
        let prompt = render_prompt(&cfg.prompt_template, &request_ctx("/secret")).unwrap();
        let verdict = PolicyDecision::Deny {
            status: 403,
            message: "secret path".to_string(),
        };
        let judge = primed_client(&prompt, &payload, verdict, 100);
        let policy = SemanticConstraintPolicy::with_judge(cfg, judge);

        let decision = policy.enforce(request_ctx("/secret")).await;
        assert_eq!(
            decision,
            PolicyDecision::Allow,
            "monitor mode must allow even on Deny"
        );
    }

    #[tokio::test]
    async fn judge_budget_exhausted_returns_429() {
        let cfg = config(true);
        // Zero-budget client. The semantic call will hard-fail
        // before reaching the network. The cache is unprimed; this
        // path never consults it because the budget gate fires
        // before the cache lookup... actually the cache lookup
        // happens first per JudgeClient::semantic, so an unprimed
        // cache + zero budget produces BudgetExhausted on the
        // budget gate. Confirmed via the judge backend tests.
        let endpoint = url::Url::parse("http://127.0.0.1:1/judge").unwrap();
        let judge_cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_SC_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 4,
            budget_tokens: 0,
        };
        let judge = Arc::new(JudgeClient::new(judge_cfg));
        let policy = SemanticConstraintPolicy::with_judge(cfg, judge);

        let decision = policy.enforce(request_ctx("/anything")).await;
        match decision {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 429);
                assert_eq!(message, "judge_budget_exhausted");
            }
            other => panic!("expected 429 budget Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_with_headers_passes_through() {
        // The OSS dispatcher bridges Confirm to AllowWithHeaders so
        // the dispatcher only needs to know about Allow / Deny /
        // AllowWithHeaders shapes. We exercise the AllowWithHeaders
        // passthrough here because `PolicyDecision::Confirm` is
        // `#[non_exhaustive]` and can only be constructed from
        // inside `sbproxy-plugin`.
        let cfg = config(true);
        let payload = serde_json::Value::Object(serde_json::Map::new());
        let prompt = render_prompt(&cfg.prompt_template, &request_ctx("/x")).unwrap();
        let verdict = PolicyDecision::AllowWithHeaders {
            headers: vec![(
                "X-Policy-Confirm".to_string(),
                "needs human review".to_string(),
            )],
        };
        let judge = primed_client(&prompt, &payload, verdict, 100);
        let policy = SemanticConstraintPolicy::with_judge(cfg, judge);

        let decision = policy.enforce(request_ctx("/x")).await;
        match decision {
            PolicyDecision::AllowWithHeaders { headers } => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].0, "X-Policy-Confirm");
            }
            other => panic!("expected AllowWithHeaders passthrough, got {other:?}"),
        }
    }

    #[test]
    fn from_config_rejects_empty_template() {
        let json = serde_json::json!({
            "prompt_template": "   ",
            "judge": {
                "endpoint": "http://127.0.0.1:1/",
                "api_key_env": "X",
            }
        });
        let err = SemanticConstraintPolicy::from_config(json).expect_err("empty must fail");
        assert!(err.to_string().contains("prompt_template"));
    }

    #[test]
    fn from_config_accepts_minimal_yaml_shape() {
        let json = serde_json::json!({
            "prompt_template": "classify {{ request.path }}",
            "judge": {
                "endpoint": "http://127.0.0.1:1/",
                "api_key_env": "SBPROXY_SC_TEST_KEY",
            }
        });
        let policy = SemanticConstraintPolicy::from_config(json).expect("minimal config compiles");
        assert!(!policy.config.violations_block);
        assert!(policy.config.policy_id.is_none());
    }
}
