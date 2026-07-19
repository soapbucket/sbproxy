//! Translate a LiteLLM `config.yaml` into an sbproxy `sb.yml`.
//!
//! This is the config-translation layer of the LiteLLM drop-in effort: a team
//! running the LiteLLM proxy can convert their existing config into an
//! equivalent sbproxy `ai_proxy` origin. It is both a shipped feature
//! (`sbproxy config import-litellm`) and the discovery tool for parity gaps:
//! every LiteLLM key that has no sbproxy target is surfaced as a warning rather
//! than silently dropped.

use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// How a single LiteLLM source path was handled during translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Key mapped to an emitted sbproxy field.
    Mapped,
    /// Key was recognized but needs manual attention (warning emitted).
    Warned,
    /// Key has no sbproxy target; recorded so it is not silently dropped.
    Unsupported,
}

/// Structured accounting for one LiteLLM source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LitellmKeyAccount {
    /// Dot/bracket path into the source document, e.g. `litellm_settings.success_callback[0]`.
    pub path: String,
    /// Whether the path was mapped, warned, or left unsupported.
    pub disposition: Disposition,
}

/// The result of translating a LiteLLM `config.yaml`.
pub struct LitellmTranslation {
    /// The emitted sbproxy `sb.yml` document.
    pub sb_yaml: String,
    /// One message per LiteLLM key that could not be mapped 1:1, so the
    /// operator knows what still needs manual attention.
    pub warnings: Vec<String>,
    /// Machine-readable disposition for every accounted source path.
    pub key_accounts: Vec<LitellmKeyAccount>,
}

/// A single `model_list` entry in a LiteLLM config.
#[derive(Debug, Deserialize)]
struct ModelEntry {
    model_name: String,
    #[serde(default)]
    litellm_params: LitellmParams,
}

/// The `litellm_params` of a model entry. Known keys are mapped; the rest are
/// captured in `extra` so they can be surfaced as warnings.
#[derive(Debug, Default, Deserialize)]
struct LitellmParams {
    model: Option<String>,
    api_key: Option<String>,
    api_base: Option<String>,
    api_version: Option<String>,
    organization: Option<String>,
    weight: Option<u32>,
    rpm: Option<u64>,
    tpm: Option<u64>,
    /// USD spend cap for this deployment (LiteLLM budget kwarg).
    max_budget: Option<f64>,
    /// Rolling window for [`Self::max_budget`] (e.g. `30d`, `1mo`, `daily`).
    budget_duration: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

/// LiteLLM `router_settings`.
#[derive(Debug, Default, Deserialize)]
struct RouterSettings {
    routing_strategy: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

/// LiteLLM `litellm_settings`.
#[derive(Debug, Default, Deserialize)]
struct LitellmSettings {
    cache: Option<serde_yaml::Value>,
    #[serde(default)]
    callbacks: Vec<String>,
    #[serde(default)]
    success_callback: Vec<String>,
    #[serde(default)]
    failure_callback: Vec<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

/// LiteLLM `general_settings`.
#[derive(Debug, Default, Deserialize)]
struct GeneralSettings {
    master_key: Option<String>,
    database_url: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

/// A LiteLLM top-level `guardrails[]` entry.
#[derive(Debug, Deserialize)]
struct GuardrailEntry {
    #[serde(default)]
    guardrail_name: Option<String>,
}

/// The subset of a LiteLLM `config.yaml` the translator reads.
#[derive(Debug, Default, Deserialize)]
struct LitellmConfig {
    #[serde(default)]
    model_list: Vec<ModelEntry>,
    #[serde(default)]
    router_settings: RouterSettings,
    #[serde(default)]
    litellm_settings: LitellmSettings,
    #[serde(default)]
    general_settings: GeneralSettings,
    #[serde(default)]
    guardrails: Vec<GuardrailEntry>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

/// LiteLLM callback names that map to an sbproxy usage-sink rather than a
/// Python module path. Anything else in a callback list is a Python hook that
/// needs manual rewrite.
const KNOWN_SINK_CALLBACKS: &[&str] = &[
    "langfuse",
    "langsmith",
    "datadog",
    "datadog_llm_observability",
    "s3",
    "s3_v2",
    "gcs_bucket",
    "otel",
    "prometheus",
    "helicone",
];

/// Callbacks that emit a real [`usage_sink`](sbproxy) config entry.
const EMITTABLE_SINK_CALLBACKS: &[&str] = &[
    "langfuse",
    "datadog",
    "datadog_llm_observability",
    "s3",
    "s3_v2",
    "gcs_bucket",
    "otel",
];

/// Translate a LiteLLM `config.yaml` into an sbproxy `sb.yml` containing a
/// single `ai_proxy` origin.
///
/// Returns `Err` only when the input is not valid YAML. Keys that have no
/// sbproxy equivalent are collected into [`LitellmTranslation::warnings`], not
/// treated as failures.
pub fn translate_litellm(input: &str) -> Result<LitellmTranslation> {
    let cfg: LitellmConfig =
        serde_yaml::from_str(input).map_err(|e| anyhow::anyhow!("parse LiteLLM config: {e}"))?;
    let mut warnings = Vec::new();
    let mut key_accounts = Vec::new();

    let mut providers = Vec::new();
    let mut model_rate_limits = Map::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();
    let mut budget_candidates: Vec<(String, f64, String)> = Vec::new();

    for (idx, entry) in cfg.model_list.iter().enumerate() {
        let prefix = format!("model_list[{idx}]");
        account(
            &mut key_accounts,
            format!("{prefix}.model_name"),
            Disposition::Mapped,
        );

        let params_prefix = format!("{prefix}.litellm_params");
        let raw_model = entry.litellm_params.model.clone().unwrap_or_default();
        let (provider_type, upstream_model) = split_provider_model(&raw_model);
        let name = uniquify(&mut used_names, &provider_type);

        if entry.litellm_params.model.is_some() {
            account(
                &mut key_accounts,
                format!("{params_prefix}.model"),
                Disposition::Mapped,
            );
        }

        // rpm / tpm -> model_rate_limits keyed by the public model name.
        if entry.litellm_params.rpm.is_some() || entry.litellm_params.tpm.is_some() {
            let mut limits = Map::new();
            if let Some(rpm) = entry.litellm_params.rpm {
                limits.insert("requests_per_minute".into(), json!(rpm));
                account(
                    &mut key_accounts,
                    format!("{params_prefix}.rpm"),
                    Disposition::Mapped,
                );
            }
            if let Some(tpm) = entry.litellm_params.tpm {
                limits.insert("tokens_per_minute".into(), json!(tpm));
                account(
                    &mut key_accounts,
                    format!("{params_prefix}.tpm"),
                    Disposition::Mapped,
                );
            }
            model_rate_limits.insert(entry.model_name.clone(), Value::Object(limits));
        }

        if let Some(max_budget) = entry.litellm_params.max_budget {
            let period = entry
                .litellm_params
                .budget_duration
                .clone()
                .unwrap_or_else(|| "monthly".to_string());
            budget_candidates.push((entry.model_name.clone(), max_budget, period));
            account(
                &mut key_accounts,
                format!("{params_prefix}.max_budget"),
                Disposition::Mapped,
            );
            if entry.litellm_params.budget_duration.is_some() {
                account(
                    &mut key_accounts,
                    format!("{params_prefix}.budget_duration"),
                    Disposition::Mapped,
                );
            }
        }

        // Surface any litellm_params key we did not map.
        for key in entry.litellm_params.extra.keys() {
            let path = format!("{params_prefix}.{key}");
            warn_account(
                &mut warnings,
                &mut key_accounts,
                &path,
                format!(
                    "model '{}': litellm_params.{key} has no sbproxy mapping; review manually",
                    entry.model_name
                ),
                Disposition::Warned,
            );
        }

        let mut p = Map::new();
        p.insert("name".into(), json!(name));
        p.insert("provider_type".into(), json!(provider_type));
        if let Some(k) = &entry.litellm_params.api_key {
            p.insert("api_key".into(), json!(env_interp(k)));
            account(
                &mut key_accounts,
                format!("{params_prefix}.api_key"),
                Disposition::Mapped,
            );
        }
        if let Some(b) = &entry.litellm_params.api_base {
            p.insert("base_url".into(), json!(env_interp(b)));
            account(
                &mut key_accounts,
                format!("{params_prefix}.api_base"),
                Disposition::Mapped,
            );
        }
        if let Some(v) = &entry.litellm_params.api_version {
            p.insert("api_version".into(), json!(env_interp(v)));
            account(
                &mut key_accounts,
                format!("{params_prefix}.api_version"),
                Disposition::Mapped,
            );
        }
        if let Some(o) = &entry.litellm_params.organization {
            p.insert("organization".into(), json!(env_interp(o)));
            account(
                &mut key_accounts,
                format!("{params_prefix}.organization"),
                Disposition::Mapped,
            );
        }
        if let Some(w) = entry.litellm_params.weight {
            p.insert("weight".into(), json!(w));
            account(
                &mut key_accounts,
                format!("{params_prefix}.weight"),
                Disposition::Mapped,
            );
        }
        p.insert("models".into(), json!([entry.model_name]));
        p.insert("default_model".into(), json!(entry.model_name));
        let mut model_map = Map::new();
        model_map.insert(entry.model_name.clone(), json!(upstream_model));
        p.insert("model_map".into(), Value::Object(model_map));

        providers.push(Value::Object(p));
    }

    // litellm_settings.cache -> semantic_cache (enabled; tuning left to defaults).
    let mut semantic_cache: Option<Value> = None;
    if let Some(cache) = &cfg.litellm_settings.cache {
        let on = !matches!(cache, serde_yaml::Value::Bool(false));
        if on {
            semantic_cache = Some(json!({ "enabled": true }));
        }
        account(
            &mut key_accounts,
            "litellm_settings.cache",
            Disposition::Mapped,
        );
    }

    // Callback lists: emit real usage_sinks for known sink names; Python
    // module-path callbacks need manual rewrite.
    let mut usage_sinks: Vec<Value> = Vec::new();
    let mut emitted_sink_types: HashSet<&'static str> = HashSet::new();
    let callback_lists: [(&str, &[String]); 3] = [
        (
            "litellm_settings.callbacks",
            &cfg.litellm_settings.callbacks,
        ),
        (
            "litellm_settings.success_callback",
            &cfg.litellm_settings.success_callback,
        ),
        (
            "litellm_settings.failure_callback",
            &cfg.litellm_settings.failure_callback,
        ),
    ];
    for (list_path, list) in callback_lists {
        for (i, cb) in list.iter().enumerate() {
            let path = format!("{list_path}[{i}]");
            match sink_config_for_callback(cb) {
                Some((sink_type, sink)) => {
                    if emitted_sink_types.insert(sink_type) {
                        usage_sinks.push(sink);
                    }
                    account(&mut key_accounts, path, Disposition::Mapped);
                }
                None if KNOWN_SINK_CALLBACKS.contains(&cb.as_str()) => {
                    warn_account(
                        &mut warnings,
                        &mut key_accounts,
                        &path,
                        format!(
                            "callback '{cb}' is a known LiteLLM sink with no auto-emitted \
                             sbproxy usage_sink yet; configure usage_sinks manually"
                        ),
                        Disposition::Unsupported,
                    );
                }
                None => {
                    warn_account(
                        &mut warnings,
                        &mut key_accounts,
                        &path,
                        format!(
                            "callback '{cb}' looks like a Python hook with no auto-mapping; \
                             rewrite it as a CEL/Lua/JS/WASM script (see the migration guide)"
                        ),
                        Disposition::Warned,
                    );
                }
            }
        }
    }

    for key in cfg.litellm_settings.extra.keys() {
        let path = format!("litellm_settings.{key}");
        warn_account(
            &mut warnings,
            &mut key_accounts,
            &path,
            format!("{path} has no sbproxy mapping; review manually"),
            Disposition::Warned,
        );
    }

    // general_settings: master_key / database_url drive proxy auth + the
    // (enterprise) key store, which have no direct config translation.
    if cfg.general_settings.master_key.is_some() {
        warn_account(
            &mut warnings,
            &mut key_accounts,
            "general_settings.master_key",
            "general_settings.master_key has no direct sbproxy mapping; configure proxy \
             authentication (see the migration guide)"
                .to_string(),
            Disposition::Warned,
        );
    }
    if cfg.general_settings.database_url.is_some() {
        warn_account(
            &mut warnings,
            &mut key_accounts,
            "general_settings.database_url",
            "general_settings.database_url maps to the runtime key/spend store \
             (enterprise); not emitted"
                .to_string(),
            Disposition::Warned,
        );
    }
    for key in cfg.general_settings.extra.keys() {
        let path = format!("general_settings.{key}");
        warn_account(
            &mut warnings,
            &mut key_accounts,
            &path,
            format!("{path} has no sbproxy mapping; review manually"),
            Disposition::Warned,
        );
    }

    // Top-level guardrails are external-provider adapters in LiteLLM; surface
    // them so the operator wires the equivalent sbproxy guardrail.
    for (i, g) in cfg.guardrails.iter().enumerate() {
        let label = g.guardrail_name.as_deref().unwrap_or("<unnamed>");
        let path = format!("guardrails[{i}]");
        warn_account(
            &mut warnings,
            &mut key_accounts,
            &path,
            format!(
                "guardrail '{label}' is an external guardrail; map it to an sbproxy \
                 built-in or external guardrail adapter (see the migration guide)"
            ),
            Disposition::Warned,
        );
    }

    for key in cfg.extra.keys() {
        let path = key.clone();
        warn_account(
            &mut warnings,
            &mut key_accounts,
            &path,
            format!("top-level '{path}' has no sbproxy mapping; review manually"),
            Disposition::Warned,
        );
    }

    let mut action = Map::new();
    action.insert("type".into(), json!("ai_proxy"));
    if let Some(strategy) = &cfg.router_settings.routing_strategy {
        let (mapped, known) = map_routing_strategy(strategy, &mut warnings);
        action.insert("routing".into(), json!(mapped));
        account(
            &mut key_accounts,
            "router_settings.routing_strategy",
            if known {
                Disposition::Mapped
            } else {
                Disposition::Warned
            },
        );
    }
    for key in cfg.router_settings.extra.keys() {
        let path = format!("router_settings.{key}");
        warn_account(
            &mut warnings,
            &mut key_accounts,
            &path,
            format!("{path} has no sbproxy mapping; review manually"),
            Disposition::Warned,
        );
    }

    action.insert("providers".into(), Value::Array(providers));
    if !model_rate_limits.is_empty() {
        action.insert("model_rate_limits".into(), Value::Object(model_rate_limits));
    }
    if let Some(sc) = semantic_cache {
        action.insert("semantic_cache".into(), sc);
    }
    if !usage_sinks.is_empty() {
        action.insert("usage_sinks".into(), Value::Array(usage_sinks));
    }
    if let Some(budget) = emit_budget_from_candidates(&budget_candidates, &mut warnings) {
        action.insert("budget".into(), budget);
    }

    let config = json!({
        "proxy": { "http_bind_port": 8080 },
        "origins": { "ai.local": { "action": Value::Object(action) } },
    });
    let sb_yaml = serde_yaml::to_string(&config)?;
    Ok(LitellmTranslation {
        sb_yaml,
        warnings,
        key_accounts,
    })
}

fn account(
    accounts: &mut Vec<LitellmKeyAccount>,
    path: impl Into<String>,
    disposition: Disposition,
) {
    accounts.push(LitellmKeyAccount {
        path: path.into(),
        disposition,
    });
}

fn warn_account(
    warnings: &mut Vec<String>,
    accounts: &mut Vec<LitellmKeyAccount>,
    path: &str,
    message: String,
    disposition: Disposition,
) {
    warnings.push(message);
    account(accounts, path.to_string(), disposition);
}

/// Build an sbproxy usage-sink JSON object for a LiteLLM callback name.
/// Returns `(canonical_type, config)` so duplicate callbacks across success/
/// failure lists emit once.
fn sink_config_for_callback(name: &str) -> Option<(&'static str, Value)> {
    if !EMITTABLE_SINK_CALLBACKS.contains(&name) {
        return None;
    }
    match name {
        "langfuse" => Some((
            "langfuse",
            json!({
                "type": "langfuse",
                "host": "${LANGFUSE_HOST}",
                "public_key": "${LANGFUSE_PUBLIC_KEY}",
                "secret_key": "${LANGFUSE_SECRET_KEY}",
            }),
        )),
        "datadog" | "datadog_llm_observability" => Some((
            "datadog",
            json!({
                "type": "datadog",
                "api_key": "${DD_API_KEY}",
            }),
        )),
        "otel" => Some(("otel", json!({ "type": "otel" }))),
        "s3" | "s3_v2" => Some((
            "s3",
            json!({
                "type": "s3",
                "bucket": "${AWS_S3_BUCKET_NAME}",
                "prefix": "",
            }),
        )),
        "gcs_bucket" => Some((
            "gcs",
            json!({
                "type": "gcs",
                "bucket": "${GCS_BUCKET_NAME}",
                "prefix": "",
            }),
        )),
        _ => None,
    }
}

/// Emit an action-level `budget` when LiteLLM `max_budget` values map cleanly
/// (a single shared USD cap + period). Differing per-model caps stay warned.
fn emit_budget_from_candidates(
    candidates: &[(String, f64, String)],
    warnings: &mut Vec<String>,
) -> Option<Value> {
    if candidates.is_empty() {
        return None;
    }
    let (_, first_cost, first_period) = &candidates[0];
    let uniform = candidates.iter().all(|(_, cost, period)| {
        (cost - first_cost).abs() < f64::EPSILON && period == first_period
    });
    if !uniform {
        for (model, cost, period) in candidates {
            warnings.push(format!(
                "model '{model}': litellm_params.max_budget={cost} (period {period}) differs \
                 from other model budgets; configure an action-level budget: block manually"
            ));
        }
        return None;
    }
    Some(json!({
        "on_exceed": "block",
        "limits": [{
            "scope": "workspace",
            "max_cost_usd": first_cost,
            "period": first_period,
        }],
    }))
}

/// Map a LiteLLM `routing_strategy` name to the nearest sbproxy strategy.
/// Unknown strategies warn and fall back to `round_robin`. Returns
/// `(mapped_name, was_known)`.
fn map_routing_strategy(name: &str, warnings: &mut Vec<String>) -> (String, bool) {
    let (mapped, known) = match name {
        "simple-shuffle" => ("round_robin", true),
        "latency-based-routing" => ("lowest_latency", true),
        "usage-based-routing" | "usage-based-routing-v2" => ("least_token_usage", true),
        "least-busy" => ("least_connections", true),
        "cost-based-routing" => ("cost_optimized", true),
        other => {
            warnings.push(format!(
                "router_settings.routing_strategy '{other}' has no direct sbproxy \
                 equivalent; defaulting to round_robin"
            ));
            ("round_robin", false)
        }
    };
    (mapped.to_string(), known)
}

/// Split a LiteLLM model string (`openai/gpt-4o`, `bedrock/...`, or a bare
/// `gpt-4o`) into an sbproxy `provider_type` and the upstream model name. A
/// string with no provider prefix defaults to the `openai` provider, matching
/// LiteLLM's own default.
fn split_provider_model(raw: &str) -> (String, String) {
    match raw.split_once('/') {
        Some((prefix, rest)) => (map_provider_prefix(prefix), rest.to_string()),
        None => ("openai".to_string(), raw.to_string()),
    }
}

/// Map a LiteLLM provider prefix to the sbproxy `provider_type` name where they
/// differ; otherwise pass it through.
fn map_provider_prefix(prefix: &str) -> String {
    match prefix {
        "vertex_ai" => "vertex",
        "google" => "gemini",
        other => other,
    }
    .to_string()
}

/// Convert LiteLLM's `os.environ/VAR` indirection into sbproxy's `${VAR}`
/// interpolation; pass other values through unchanged.
fn env_interp(value: &str) -> String {
    match value.strip_prefix("os.environ/") {
        Some(var) => format!("${{{var}}}"),
        None => value.to_string(),
    }
}

/// Produce a provider name that is unique within this config: the first use of
/// a base name is unsuffixed, later collisions get `-2`, `-3`, and so on.
fn uniquify(used: &mut HashMap<String, u32>, base: &str) -> String {
    let n = used.entry(base.to_string()).or_insert(0);
    *n += 1;
    if *n == 1 {
        base.to_string()
    } else {
        format!("{base}-{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile_config;

    const SINGLE_PROVIDER: &str = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
"#;

    fn action_of(sb_yaml: &str) -> serde_yaml::Value {
        let v: serde_yaml::Value = serde_yaml::from_str(sb_yaml).unwrap();
        let origins = v.get("origins").unwrap().as_mapping().unwrap();
        let (_host, origin) = origins.iter().next().unwrap();
        origin.get("action").unwrap().clone()
    }

    #[test]
    fn rpm_tpm_become_model_rate_limits() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      rpm: 100
      tpm: 200000
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        let mrl = action
            .get("model_rate_limits")
            .unwrap()
            .as_mapping()
            .unwrap();
        let limits = mrl.get(serde_yaml::Value::from("gpt-4")).unwrap();
        assert_eq!(
            limits.get("requests_per_minute").unwrap().as_u64(),
            Some(100)
        );
        assert_eq!(
            limits.get("tokens_per_minute").unwrap().as_u64(),
            Some(200000)
        );
    }

    #[test]
    fn cache_true_enables_semantic_cache() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
litellm_settings:
  cache: true
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        let sc = action.get("semantic_cache").unwrap();
        assert_eq!(sc.get("enabled").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn unmapped_litellm_param_is_warned_not_dropped() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      some_unknown_kwarg: 42
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("some_unknown_kwarg")),
            "expected a warning naming the unmapped key, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn unknown_router_settings_key_is_warned_not_dropped() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params: { model: openai/gpt-4o }
router_settings:
  routing_strategy: latency-based-routing
  totally_unknown_router_knob: true
"#;
        let out = translate_litellm(input).unwrap();
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("totally_unknown_router_knob")),
            "expected a warning naming the unmapped router key, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn unknown_litellm_settings_and_top_level_keys_are_warned() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params: { model: openai/gpt-4o }
litellm_settings:
  cache: true
  unknown_flag: true
weird_key: something
"#;
        let out = translate_litellm(input).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.contains("unknown_flag")),
            "expected a warning naming litellm_settings.unknown_flag, got {:?}",
            out.warnings
        );
        assert!(
            out.warnings.iter().any(|w| w.contains("weird_key")),
            "expected a warning naming top-level weird_key, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn unknown_general_settings_key_is_warned_not_dropped() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params: { model: openai/gpt-4o }
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  totally_unknown_general_knob: 1
"#;
        let out = translate_litellm(input).unwrap();
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("totally_unknown_general_knob")),
            "expected a warning naming the unmapped general_settings key, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn unknown_routing_strategy_warns_naming_original() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params: { model: openai/gpt-4o }
router_settings:
  routing_strategy: totally-made-up-strategy
"#;
        let out = translate_litellm(input).unwrap();
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        assert_eq!(
            action.get("routing").unwrap().as_str(),
            Some("round_robin"),
            "unknown strategy still falls back to round_robin"
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("totally-made-up-strategy")),
            "fallback must record a warning that names the original strategy, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn known_sink_callbacks_emit_usage_sink_config() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params: { model: openai/gpt-4o }
litellm_settings:
  callbacks: ["langfuse", "datadog", "otel", "s3", "gcs_bucket"]
"#;
        let out = translate_litellm(input).unwrap();
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        let sinks = action
            .get("usage_sinks")
            .expect("known callbacks must emit usage_sinks")
            .as_sequence()
            .expect("usage_sinks is a list");
        let types: Vec<&str> = sinks
            .iter()
            .filter_map(|s| s.get("type").and_then(|t| t.as_str()))
            .collect();
        for expected in ["langfuse", "datadog", "otel", "s3", "gcs"] {
            assert!(
                types.contains(&expected),
                "expected usage_sink type {expected} in {types:?}"
            );
        }
    }

    #[test]
    fn max_budget_emits_budget_window() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      max_budget: 25.0
      budget_duration: 30d
"#;
        let out = translate_litellm(input).unwrap();
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        let budget = action.get("budget").expect("max_budget must emit budget");
        let limits = budget
            .get("limits")
            .and_then(|l| l.as_sequence())
            .expect("budget.limits");
        assert!(!limits.is_empty());
        let limit = &limits[0];
        assert_eq!(
            limit.get("max_cost_usd").and_then(|v| v.as_f64()),
            Some(25.0)
        );
        assert_eq!(limit.get("period").and_then(|v| v.as_str()), Some("30d"));
        assert!(
            !out.warnings.iter().any(|w| w.contains("max_budget")),
            "mapped max_budget must not also warn as unmapped, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn supported_key_silent_drop_fails_gate() {
        // Regression net: every accounted path must land in key_accounts as
        // Mapped, Warned, or Unsupported. A silently dropped key has no row.
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      some_unknown_kwarg: 42
router_settings:
  routing_strategy: latency-based-routing
  totally_unknown_router_knob: true
litellm_settings:
  cache: true
  unknown_flag: true
  callbacks: ["otel"]
general_settings:
  master_key: os.environ/K
  totally_unknown_general_knob: 1
weird_key: something
"#;
        let out = translate_litellm(input).unwrap();
        let paths: Vec<&str> = out.key_accounts.iter().map(|a| a.path.as_str()).collect();
        for required in [
            "model_list[0].litellm_params.some_unknown_kwarg",
            "router_settings.totally_unknown_router_knob",
            "litellm_settings.unknown_flag",
            "general_settings.totally_unknown_general_knob",
            "weird_key",
            "litellm_settings.callbacks[0]",
            "router_settings.routing_strategy",
            "litellm_settings.cache",
            "general_settings.master_key",
        ] {
            assert!(
                paths.contains(&required),
                "silent-drop gate: missing key_accounts row for {required}; have {paths:?}"
            );
        }
        assert!(out.key_accounts.iter().any(|a| {
            a.path == "litellm_settings.callbacks[0]" && a.disposition == Disposition::Mapped
        }));
        assert!(out.key_accounts.iter().any(|a| {
            a.path == "router_settings.totally_unknown_router_knob"
                && a.disposition == Disposition::Warned
        }));
    }

    #[test]
    fn master_key_is_warned() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        assert!(
            out.warnings.iter().any(|w| w.contains("master_key")),
            "expected a master_key warning, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn external_guardrails_block_is_warned() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
guardrails:
  - guardrail_name: my-presidio
    litellm_params:
      guardrail: presidio
      mode: pre_call
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        assert!(
            out.warnings
                .iter()
                .any(|w| w.to_lowercase().contains("guardrail")),
            "expected a guardrails warning, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn python_callback_paths_are_warned() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
litellm_settings:
  callbacks: ["my_module.MyCustomHandler"]
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        assert!(
            out.warnings
                .iter()
                .any(|w| w.to_lowercase().contains("callback")
                    && w.contains("my_module.MyCustomHandler")),
            "expected a warning about the Python callback, got {:?}",
            out.warnings
        );
    }

    #[test]
    fn routing_strategy_name_is_mapped() {
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
router_settings:
  routing_strategy: latency-based-routing
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        // LiteLLM latency-based-routing -> sbproxy lowest_latency.
        assert_eq!(
            action.get("routing").unwrap().as_str(),
            Some("lowest_latency")
        );
    }

    #[test]
    fn model_group_shares_one_public_name_across_deployments() {
        // Two model_list entries with the same model_name form a load-balanced
        // group: both deployments are routable under the public name.
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: azure/gpt-4-east
      api_base: https://east.example.com/
      api_key: os.environ/AZURE_EAST
  - model_name: gpt-4
    litellm_params:
      model: azure/gpt-4-west
      api_base: https://west.example.com/
      api_key: os.environ/AZURE_WEST
router_settings:
  routing_strategy: simple-shuffle
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("compiles");
        let action = action_of(&out.sb_yaml);
        let providers = action.get("providers").unwrap().as_sequence().unwrap();
        assert_eq!(providers.len(), 2, "two deployments in the group");
        for p in providers {
            let models = p.get("models").unwrap().as_sequence().unwrap();
            assert!(
                models.iter().any(|m| m.as_str() == Some("gpt-4")),
                "each deployment is routable under the public name"
            );
        }
        let names: Vec<_> = providers
            .iter()
            .map(|p| p.get("name").unwrap().as_str().unwrap().to_string())
            .collect();
        assert_ne!(
            names[0], names[1],
            "deployments get distinct provider names"
        );
    }

    #[test]
    fn migration_guide_worked_example_compiles() {
        // Keep docs/migration-litellm.md honest: its worked example must
        // translate and compile.
        let input = r#"
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
      rpm: 100
  - model_name: claude
    litellm_params:
      model: anthropic/claude-haiku-4-5
      api_key: os.environ/ANTHROPIC_API_KEY
router_settings:
  routing_strategy: latency-based-routing
litellm_settings:
  cache: true
"#;
        let out = translate_litellm(input).expect("translate ok");
        compile_config(&out.sb_yaml).expect("worked example compiles");
    }

    #[test]
    fn single_provider_translates_and_compiles() {
        let out = translate_litellm(SINGLE_PROVIDER).expect("translate ok");

        // The headline acceptance: the emitted config compiles.
        compile_config(&out.sb_yaml).expect("emitted sb.yml must compile");

        // And it maps the provider correctly.
        let v: serde_yaml::Value = serde_yaml::from_str(&out.sb_yaml).unwrap();
        let origins = v.get("origins").unwrap().as_mapping().unwrap();
        let (_host, origin) = origins.iter().next().unwrap();
        let action = origin.get("action").unwrap();
        assert_eq!(action.get("type").unwrap().as_str(), Some("ai_proxy"));

        let providers = action.get("providers").unwrap().as_sequence().unwrap();
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        // openai/gpt-4o -> provider_type openai, upstream model gpt-4o.
        assert_eq!(p.get("provider_type").unwrap().as_str(), Some("openai"));
        // os.environ/VAR -> ${VAR} interpolation.
        assert_eq!(
            p.get("api_key").unwrap().as_str(),
            Some("${OPENAI_API_KEY}")
        );
        // The public model name is routable and maps to the upstream model.
        let models = p.get("models").unwrap().as_sequence().unwrap();
        assert!(models.iter().any(|m| m.as_str() == Some("gpt-4")));
        let mm = p.get("model_map").unwrap().as_mapping().unwrap();
        assert_eq!(
            mm.get(serde_yaml::Value::from("gpt-4")).unwrap().as_str(),
            Some("gpt-4o")
        );
    }

    /// Drop-in regression net: every representative LiteLLM config in
    /// `tests/litellm/` must translate without error and produce an `sb.yml`
    /// that compiles. A translator change that breaks a real-world config
    /// shape fails here, and the corpus doubles as worked migration examples.
    #[test]
    fn litellm_corpus_translates_and_compiles() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/litellm");
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read corpus dir {dir}: {e}"))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        paths.sort();
        for path in &paths {
            let yaml = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let out = translate_litellm(&yaml)
                .unwrap_or_else(|e| panic!("translate {}: {e}", path.display()));
            compile_config(&out.sb_yaml)
                .unwrap_or_else(|e| panic!("compile translated {}: {e}", path.display()));
        }
        assert!(
            paths.len() >= 7,
            "expected >=7 corpus fixtures under {dir}, found {}",
            paths.len()
        );
    }
}
