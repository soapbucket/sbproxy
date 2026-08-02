//! Route-level controls for concise model reasoning.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::provider::ProviderConfig;
use crate::providers::{get_provider_info, ProviderFormat};

/// System instruction used when no safe native reasoning control is known.
///
/// The fixed string is intentionally short and contains no request-derived
/// content, which keeps the fallback deterministic and safe to label.
pub const PROMPT_FALLBACK_INSTRUCTION: &str =
    "Use brief, compact draft reasoning with only essential intermediate steps, then give the answer.";

/// Opt-in reasoning policy applied independently to each provider attempt.
///
/// The externally tagged representation intentionally matches the route
/// configuration surface: `"off"`, `"concise"`, or `{"budget": N}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningPolicy {
    /// Preserve the request byte-for-byte.
    #[default]
    Off,
    /// Ask the selected model to reason briefly.
    Concise,
    /// Bound native reasoning (and provider completion output where required).
    Budget(#[schemars(range(min = 1))] u32),
}

impl ReasoningPolicy {
    /// Validate values that serde can represent but the runtime cannot honor.
    pub fn validate(self) -> Result<(), &'static str> {
        if matches!(self, Self::Budget(0)) {
            return Err("reasoning budget must be greater than zero");
        }
        Ok(())
    }
}

/// Stable, content-free outcome recorded for one provider attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningOutcome {
    /// A provider-native control was applied.
    Native,
    /// A fixed concise-reasoning system instruction was used.
    PromptFallback,
    /// The route policy was disabled.
    Off,
    /// Tool or function declarations made the request ineligible.
    ToolBypass,
    /// A code-shaped prompt made the request ineligible.
    CodeBypass,
}

impl ReasoningOutcome {
    /// Stable telemetry label for this outcome.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::PromptFallback => "prompt_fallback",
            Self::Off => "off",
            Self::ToolBypass => "tool_bypass",
            Self::CodeBypass => "code_bypass",
        }
    }
}

/// Result of applying a route reasoning policy to one provider attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasoningTransform {
    /// Whether the canonical request body changed.
    pub applied: bool,
    /// Stable reason for applying, skipping, or bypassing the policy.
    pub outcome: ReasoningOutcome,
}

/// Eligibility facts captured before any request-body compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasoningEligibility {
    has_tool_declarations: bool,
    code_shaped: bool,
}

impl ReasoningTransform {
    const fn new(applied: bool, outcome: ReasoningOutcome) -> Self {
        Self { applied, outcome }
    }

    /// Stable telemetry label for this attempt.
    pub const fn outcome_label(self) -> &'static str {
        self.outcome.label()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeTransform {
    OpenAi,
    AnthropicAdaptive,
    AnthropicBudget(u32),
    GeminiLevel,
    GeminiBudget(u32),
    BedrockAnthropicAdaptive,
    BedrockAnthropicBudget(u32),
    PromptFallback,
}

/// Apply a route policy to a model-mapped canonical request for one provider.
///
/// Call this independently for every provider attempt, after mapping the
/// logical model to `model`. A `true` [`ReasoningTransform::applied`] value
/// tells the caller that any native-byte bypass must be disabled and the
/// transformed canonical body must be translated instead.
pub fn apply_reasoning_policy(
    policy: ReasoningPolicy,
    provider: &ProviderConfig,
    model: &str,
    request: &mut Value,
) -> ReasoningTransform {
    let eligibility = reasoning_eligibility(request);
    apply_reasoning_policy_with_eligibility(policy, provider, model, request, eligibility)
}

/// Capture reasoning safety facts before any lossy request transformation.
pub fn reasoning_eligibility(request: &Value) -> ReasoningEligibility {
    ReasoningEligibility {
        has_tool_declarations: has_tool_declarations(request),
        code_shaped: is_code_shaped_prompt(request),
    }
}

/// Apply a route policy while preserving pre-compression safety eligibility.
pub fn apply_reasoning_policy_with_eligibility(
    policy: ReasoningPolicy,
    provider: &ProviderConfig,
    model: &str,
    request: &mut Value,
    eligibility: ReasoningEligibility,
) -> ReasoningTransform {
    if policy == ReasoningPolicy::Off {
        return ReasoningTransform::new(false, ReasoningOutcome::Off);
    }
    if eligibility.has_tool_declarations || has_tool_declarations(request) {
        return ReasoningTransform::new(false, ReasoningOutcome::ToolBypass);
    }
    if eligibility.code_shaped || is_code_shaped_prompt(request) {
        return ReasoningTransform::new(false, ReasoningOutcome::CodeBypass);
    }

    let transform = native_transform_for(policy, provider, model);
    let (applied, outcome) = match transform {
        NativeTransform::OpenAi => (apply_openai(policy, request), ReasoningOutcome::Native),
        NativeTransform::AnthropicAdaptive => {
            (apply_anthropic_adaptive(request), ReasoningOutcome::Native)
        }
        NativeTransform::AnthropicBudget(budget) => (
            apply_anthropic_budget(request, budget, false),
            ReasoningOutcome::Native,
        ),
        NativeTransform::GeminiLevel => (
            apply_gemini_thinking(request, json!({"thinkingLevel": "low"})),
            ReasoningOutcome::Native,
        ),
        NativeTransform::GeminiBudget(budget) => (
            apply_gemini_thinking(request, json!({"thinkingBudget": budget})),
            ReasoningOutcome::Native,
        ),
        NativeTransform::BedrockAnthropicAdaptive => (
            apply_bedrock_anthropic_adaptive(request),
            ReasoningOutcome::Native,
        ),
        NativeTransform::BedrockAnthropicBudget(budget) => (
            apply_anthropic_budget(request, budget, true),
            ReasoningOutcome::Native,
        ),
        NativeTransform::PromptFallback => (
            apply_prompt_fallback(policy, request),
            ReasoningOutcome::PromptFallback,
        ),
    };
    ReasoningTransform::new(applied, outcome)
}

fn native_transform_for(
    policy: ReasoningPolicy,
    provider: &ProviderConfig,
    model: &str,
) -> NativeTransform {
    let provider_key = provider
        .provider_type
        .as_deref()
        .unwrap_or(provider.name.as_str());
    let Some(provider_info) = get_provider_info(provider_key) else {
        return NativeTransform::PromptFallback;
    };
    let format = provider_info.format;

    match format {
        ProviderFormat::OpenAi
            if openai_provider_supports_reasoning(&provider_info.name)
                && openai_supports_reasoning(model) =>
        {
            NativeTransform::OpenAi
        }
        ProviderFormat::Anthropic => match policy {
            ReasoningPolicy::Concise if anthropic_supports_adaptive(model) => {
                NativeTransform::AnthropicAdaptive
            }
            ReasoningPolicy::Budget(budget)
                if budget >= 1_024 && anthropic_supports_manual_thinking(model) =>
            {
                NativeTransform::AnthropicBudget(budget)
            }
            _ => NativeTransform::PromptFallback,
        },
        ProviderFormat::Google => match policy {
            ReasoningPolicy::Concise if gemini_uses_thinking_level(model) => {
                NativeTransform::GeminiLevel
            }
            ReasoningPolicy::Concise if gemini_uses_thinking_budget(model) => {
                NativeTransform::GeminiBudget(1_024)
            }
            ReasoningPolicy::Budget(budget) if gemini_accepts_thinking_budget(model, budget) => {
                NativeTransform::GeminiBudget(budget)
            }
            _ => NativeTransform::PromptFallback,
        },
        ProviderFormat::Bedrock if is_bedrock_anthropic_model(model) => match policy {
            ReasoningPolicy::Concise if anthropic_supports_adaptive(model) => {
                NativeTransform::BedrockAnthropicAdaptive
            }
            ReasoningPolicy::Budget(budget)
                if budget >= 1_024 && anthropic_supports_manual_thinking(model) =>
            {
                NativeTransform::BedrockAnthropicBudget(budget)
            }
            _ => NativeTransform::PromptFallback,
        },
        ProviderFormat::OpenAi | ProviderFormat::Bedrock | ProviderFormat::Custom => {
            NativeTransform::PromptFallback
        }
    }
}

fn openai_supports_reasoning(model: &str) -> bool {
    let model = normalized_model_name(model);
    !model.contains("-pro")
        && ["o1", "o3", "o4", "gpt-5"]
            .iter()
            .any(|prefix| model.starts_with(prefix))
        || model.contains("codex")
}

fn openai_provider_supports_reasoning(provider_name: &str) -> bool {
    matches!(provider_name, "openai" | "azure" | "azure_foundry")
}

fn anthropic_supports_adaptive(model: &str) -> bool {
    let model = normalized_model_name(model);
    model.contains("claude")
        && [
            "4-6", "4.6", "4-7", "4.7", "4-8", "4.8", "opus-5", "sonnet-5", "fable-5", "mythos",
        ]
        .iter()
        .any(|family| model.contains(family))
}

fn anthropic_supports_manual_thinking(model: &str) -> bool {
    let model = normalized_model_name(model);
    let adaptive_only = [
        "4-7", "4.7", "4-8", "4.8", "opus-5", "sonnet-5", "fable-5", "mythos-5",
    ]
    .iter()
    .any(|family| model.contains(family));
    !adaptive_only
        && model.contains("claude")
        && ([
            "claude-3-7",
            "claude-3.7",
            "claude-sonnet-4",
            "claude-opus-4",
            "claude-haiku-4",
            "claude-4",
        ]
        .iter()
        .any(|family| model.contains(family)))
}

fn gemini_uses_thinking_level(model: &str) -> bool {
    normalized_model_name(model).starts_with("gemini-3")
}

fn gemini_uses_thinking_budget(model: &str) -> bool {
    normalized_model_name(model).starts_with("gemini-2.5")
}

fn gemini_accepts_thinking_budget(model: &str, budget: u32) -> bool {
    if !gemini_uses_thinking_budget(model) {
        return false;
    }
    let model = normalized_model_name(model);
    let minimum = if model.contains("pro") {
        128
    } else if model.contains("lite") {
        512
    } else {
        1
    };
    let maximum = if model.contains("pro") {
        32_768
    } else {
        24_576
    };
    (minimum..=maximum).contains(&budget)
}

fn is_bedrock_anthropic_model(model: &str) -> bool {
    normalized_model_name(model).contains("claude")
}

fn normalized_model_name(model: &str) -> String {
    model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase()
}

fn apply_openai(policy: ReasoningPolicy, request: &mut Value) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    if is_responses_request(obj) {
        let mut changed = merge_object_field(obj, "reasoning", "effort", json!("low"));
        if let ReasoningPolicy::Budget(budget) = policy {
            changed |= cap_numeric_field(obj, "max_output_tokens", u64::from(budget));
        }
        return changed;
    }
    let mut changed = set_value(obj, "reasoning_effort", json!("low"));
    if let ReasoningPolicy::Budget(budget) = policy {
        changed |= cap_numeric_field(obj, "max_completion_tokens", u64::from(budget));
    }
    changed
}

fn apply_anthropic_adaptive(request: &mut Value) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    let mut changed = set_value(obj, "thinking", json!({"type": "adaptive"}));
    changed |= merge_object_field(obj, "output_config", "effort", json!("low"));
    changed
}

fn apply_anthropic_budget(request: &mut Value, budget: u32, bedrock: bool) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    let thinking = json!({"type": "enabled", "budget_tokens": budget});
    let already_applied = if bedrock {
        obj.get("additionalModelRequestFields")
            .and_then(|fields| fields.get("thinking"))
            == Some(&thinking)
    } else {
        obj.get("thinking") == Some(&thinking)
    };

    let mut changed = if bedrock {
        merge_object_field(obj, "additionalModelRequestFields", "thinking", thinking)
    } else {
        set_value(obj, "thinking", thinking)
    };
    let output_budget_is_invalid = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .is_none_or(|max_tokens| max_tokens <= u64::from(budget));
    if !already_applied || output_budget_is_invalid {
        changed |= preserve_output_budget(obj, u64::from(budget));
    }
    changed
}

fn apply_gemini_thinking(request: &mut Value, thinking: Value) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    let generation = ensure_object(obj, "generationConfig");
    set_value(generation, "thinkingConfig", thinking)
}

fn apply_bedrock_anthropic_adaptive(request: &mut Value) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    let fields = ensure_object(obj, "additionalModelRequestFields");
    let mut changed = set_value(fields, "thinking", json!({"type": "adaptive"}));
    changed |= merge_object_field(fields, "output_config", "effort", json!("low"));
    changed
}

fn apply_prompt_fallback(policy: ReasoningPolicy, request: &mut Value) -> bool {
    let Some(obj) = request.as_object_mut() else {
        return false;
    };
    let responses = is_responses_request(obj);
    let mut changed = if responses {
        inject_responses_prompt_fallback(obj)
    } else {
        inject_prompt_fallback(obj)
    };
    if let ReasoningPolicy::Budget(budget) = policy {
        changed |= if responses {
            cap_numeric_field(obj, "max_output_tokens", u64::from(budget))
        } else {
            cap_custom_completion(obj, u64::from(budget))
        };
    }
    changed
}

fn is_responses_request(obj: &Map<String, Value>) -> bool {
    obj.contains_key("input") && !obj.contains_key("messages")
}

fn inject_responses_prompt_fallback(obj: &mut Map<String, Value>) -> bool {
    let value = match obj.get("instructions") {
        Some(Value::String(instructions)) if instructions == PROMPT_FALLBACK_INSTRUCTION => {
            return false;
        }
        Some(Value::String(instructions)) if !instructions.is_empty() => {
            Value::String(format!("{PROMPT_FALLBACK_INSTRUCTION}\n\n{instructions}"))
        }
        _ => Value::String(PROMPT_FALLBACK_INSTRUCTION.to_string()),
    };
    set_value(obj, "instructions", value)
}

fn preserve_output_budget(obj: &mut Map<String, Value>, budget: u64) -> bool {
    let visible_output = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(1_024);
    set_value(
        obj,
        "max_tokens",
        Value::from(visible_output.saturating_add(budget)),
    )
}

fn inject_prompt_fallback(obj: &mut Map<String, Value>) -> bool {
    let messages = obj
        .entry("messages".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(messages) = messages.as_array_mut() else {
        return false;
    };
    let already_present = messages.iter().any(|message| {
        message.get("role").and_then(Value::as_str) == Some("system")
            && message.get("content").and_then(Value::as_str) == Some(PROMPT_FALLBACK_INSTRUCTION)
    });
    if already_present {
        return false;
    }
    messages.insert(
        0,
        json!({
            "role": "system",
            "content": PROMPT_FALLBACK_INSTRUCTION,
        }),
    );
    true
}

fn cap_custom_completion(obj: &mut Map<String, Value>, budget: u64) -> bool {
    let mut changed = false;
    let has_max_completion_tokens = obj.contains_key("max_completion_tokens");
    let has_max_tokens = obj.contains_key("max_tokens");
    if has_max_completion_tokens {
        changed |= cap_numeric_field(obj, "max_completion_tokens", budget);
    }
    if has_max_tokens {
        changed |= cap_numeric_field(obj, "max_tokens", budget);
    }
    if !has_max_completion_tokens && !has_max_tokens {
        changed |= set_value(obj, "max_tokens", Value::from(budget));
    }
    changed
}

fn cap_numeric_field(obj: &mut Map<String, Value>, field: &str, cap: u64) -> bool {
    let value = obj
        .get(field)
        .and_then(Value::as_u64)
        .map_or(cap, |existing| existing.min(cap));
    set_value(obj, field, Value::from(value))
}

fn merge_object_field(
    obj: &mut Map<String, Value>,
    object_field: &str,
    field: &str,
    value: Value,
) -> bool {
    set_value(ensure_object(obj, object_field), field, value)
}

fn ensure_object<'a>(obj: &'a mut Map<String, Value>, field: &str) -> &'a mut Map<String, Value> {
    let value = obj
        .entry(field.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().expect("object inserted above")
}

fn set_value(obj: &mut Map<String, Value>, field: &str, value: Value) -> bool {
    if obj.get(field) == Some(&value) {
        return false;
    }
    obj.insert(field.to_string(), value);
    true
}

fn has_tool_declarations(request: &Value) -> bool {
    ["tools", "functions"].iter().any(|field| {
        request.get(field).is_some_and(|value| match value {
            Value::Array(values) => !values.is_empty(),
            Value::Object(values) => !values.is_empty(),
            Value::Null => false,
            _ => true,
        })
    })
}

/// Return whether a canonical request contains a code-shaped prompt.
///
/// This detector avoids broad keyword matching: prose that merely mentions a
/// “function” or “coding” remains eligible, while fenced source, source-like
/// syntax, or an explicit coding action paired with a programming artifact or
/// source filename is bypassed. Ambiguous code work favors bypass because
/// truncating its reasoning can damage correctness.
pub fn is_code_shaped_prompt(request: &Value) -> bool {
    prompt_texts(request).into_iter().any(is_code_shaped_text)
}

fn prompt_texts(request: &Value) -> Vec<&str> {
    let mut texts = Vec::new();
    if let Some(instructions) = request.get("instructions") {
        collect_content_text(instructions, &mut texts);
    }
    if let Some(prompt) = request.get("prompt").and_then(Value::as_str) {
        texts.push(prompt);
    }
    if let Some(input) = request.get("input") {
        collect_content_text(input, &mut texts);
    }
    if let Some(messages) = request.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(content) = message.get("content") {
                collect_content_text(content, &mut texts);
            }
        }
    }
    texts
}

fn collect_content_text<'a>(value: &'a Value, texts: &mut Vec<&'a str>) {
    match value {
        Value::String(text) => texts.push(text),
        Value::Array(values) => {
            for value in values {
                if let Some(text) = value.get("text").and_then(Value::as_str) {
                    texts.push(text);
                } else if let Some(content) = value.get("content") {
                    collect_content_text(content, texts);
                }
            }
        }
        Value::Object(value) => {
            if let Some(text) = value.get("text").and_then(Value::as_str) {
                texts.push(text);
            }
            if let Some(content) = value.get("content") {
                collect_content_text(content, texts);
            }
        }
        _ => {}
    }
}

fn is_code_shaped_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("```") || lower.contains("~~~") || lower.matches('`').count() >= 2 {
        return true;
    }

    let words: Vec<&str> = lower
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
        .collect();
    let requests_code = [
        "write",
        "implement",
        "debug",
        "fix",
        "refactor",
        "compile",
        "review",
        "create",
        "generate",
        "build",
        "develop",
        "author",
    ]
    .iter()
    .any(|word| words.contains(word));
    let names_code_artifact = [
        "code",
        "function",
        "method",
        "class",
        "script",
        "program",
        "regex",
        "sql",
        "python",
        "rust",
        "javascript",
        "typescript",
        "golang",
        "java",
        "fn",
    ]
    .iter()
    .any(|word| words.contains(word));
    let analyzes_code = ["analyze", "explain", "inspect", "diagnose"]
        .iter()
        .any(|word| words.contains(word));
    let names_unambiguous_code_artifact = [
        "code",
        "script",
        "program",
        "regex",
        "sql",
        "python",
        "rust",
        "javascript",
        "typescript",
        "golang",
        "java",
        "source",
        "snippet",
    ]
    .iter()
    .any(|word| words.contains(word));
    let names_source_file = contains_source_filename(&lower);
    if (requests_code && (names_code_artifact || names_source_file))
        || (analyzes_code && (names_unambiguous_code_artifact || names_source_file))
    {
        return true;
    }

    let source_line = lower.lines().any(|line| {
        let line = line.trim_start();
        [
            "fn ",
            "def ",
            "class ",
            "function ",
            "const ",
            "let ",
            "var ",
            "import ",
            "#include",
            "package ",
            "using namespace ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
            || (line.starts_with("from ") && line.contains(" import "))
    });
    source_line
        || (lower.contains("=>") && (lower.contains(';') || lower.contains('{')))
        || (lower.contains("->") && lower.contains('('))
        || (lower.contains("::") && (lower.contains('(') || lower.contains('<')))
}

fn contains_source_filename(text: &str) -> bool {
    const SOURCE_EXTENSIONS: &[&str] = &[
        ".bash", ".c", ".cc", ".cpp", ".cs", ".css", ".cxx", ".fish", ".go", ".h", ".hpp", ".html",
        ".java", ".js", ".jsx", ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".scala", ".sh",
        ".sql", ".svelte", ".swift", ".ts", ".tsx", ".vue", ".zsh",
    ];

    text.split_whitespace().any(|token| {
        let candidate = token
            .trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\''
                        | '`'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | ','
                        | ';'
                        | ':'
                        | '!'
                        | '?'
                )
            })
            .trim_end_matches('.');
        SOURCE_EXTENSIONS.iter().any(|extension| {
            candidate
                .strip_suffix(extension)
                .is_some_and(|stem| stem.chars().any(char::is_alphanumeric))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderConfig;
    use crate::translators;
    use serde_json::{json, Value};

    fn provider(name: &str, provider_type: Option<&str>) -> ProviderConfig {
        serde_json::from_value(json!({
            "name": name,
            "provider_type": provider_type,
            "api_key": "test-key",
            "base_url": "https://example.test/v1",
        }))
        .expect("provider fixture")
    }

    fn request(prompt: &str) -> Value {
        json!({
            "model": "logical-model",
            "messages": [{"role": "user", "content": prompt}],
        })
    }

    #[test]
    fn policy_schema_matches_the_closed_config_surface() {
        assert_eq!(
            serde_json::to_value(ReasoningPolicy::Off).unwrap(),
            json!("off")
        );
        assert_eq!(
            serde_json::to_value(ReasoningPolicy::Concise).unwrap(),
            json!("concise")
        );
        assert_eq!(
            serde_json::to_value(ReasoningPolicy::Budget(2048)).unwrap(),
            json!({"budget": 2048})
        );

        let schema = serde_json::to_value(schemars::schema_for!(ReasoningPolicy)).unwrap();
        let encoded = schema.to_string();
        assert!(encoded.contains("\"off\""), "{encoded}");
        assert!(encoded.contains("\"concise\""), "{encoded}");
        assert!(encoded.contains("\"budget\""), "{encoded}");
        assert!(encoded.contains("\"minimum\":1"), "{encoded}");
    }

    #[test]
    fn off_is_a_byte_compatible_noop() {
        let provider = provider("openai", None);
        let mut body = request("Compare these two proposals.");
        let original = body.clone();

        let result = apply_reasoning_policy(ReasoningPolicy::Off, &provider, "gpt-5", &mut body);

        assert_eq!(body, original);
        assert!(!result.applied);
        assert_eq!(result.outcome, ReasoningOutcome::Off);
        assert_eq!(result.outcome_label(), "off");
    }

    #[test]
    fn tool_and_legacy_function_declarations_are_always_bypassed() {
        let provider = provider("openai", None);
        for declaration in [
            json!({"tools": [{"type": "function", "function": {"name": "lookup"}}]}),
            json!({"functions": [{"name": "lookup"}]}),
        ] {
            let mut body = request("Find the current value.");
            body.as_object_mut()
                .unwrap()
                .extend(declaration.as_object().unwrap().clone());
            let original = body.clone();

            let result =
                apply_reasoning_policy(ReasoningPolicy::Concise, &provider, "gpt-5", &mut body);

            assert_eq!(body, original);
            assert!(!result.applied);
            assert_eq!(result.outcome, ReasoningOutcome::ToolBypass);
            assert_eq!(result.outcome_label(), "tool_bypass");
        }
    }

    #[test]
    fn code_shape_detector_is_conservative() {
        for prompt in [
            "```rust\nfn main() { println!(\"hi\"); }\n```",
            "Please debug this Rust function and explain the failing branch.",
            "const answer = values.map((value) => value * 2);",
            "Create a Python script that validates the input.",
            "Generate a SQL query for the weekly totals.",
            "Explain this Python function.",
            "Why does `values.map(|value| value + 1)` fail?",
            "Fix src/main.rs.",
            "Implement authentication in app.py",
        ] {
            assert!(
                is_code_shaped_prompt(&request(prompt)),
                "expected code shape: {prompt}"
            );
        }

        for prompt in [
            "Compare the economic proposals and give a recommendation.",
            "Which medical coding system does this hospital use?",
            "Explain the function of the liver in one paragraph.",
        ] {
            assert!(
                !is_code_shaped_prompt(&request(prompt)),
                "ordinary prose must remain eligible: {prompt}"
            );
        }
    }

    #[test]
    fn responses_instructions_are_part_of_code_eligibility() {
        let body = json!({
            "model": "gpt-5-mini",
            "instructions": "Create a Python script that validates the input.",
            "input": "Use the attached requirements.",
        });

        assert!(is_code_shaped_prompt(&body));

        let provider = provider("openai", None);
        let mut transformed = body.clone();
        let result = apply_reasoning_policy(
            ReasoningPolicy::Concise,
            &provider,
            "gpt-5-mini",
            &mut transformed,
        );
        assert_eq!(result.outcome, ReasoningOutcome::CodeBypass);
        assert_eq!(transformed, body);
    }

    #[test]
    fn code_shaped_prompts_are_bypassed_without_mutation() {
        let provider = provider("openai", None);
        let mut body = request("Implement fn parse(input: &str) -> Result<Value, Error>.");
        let original = body.clone();

        let result =
            apply_reasoning_policy(ReasoningPolicy::Concise, &provider, "gpt-5", &mut body);

        assert_eq!(body, original);
        assert!(!result.applied);
        assert_eq!(result.outcome, ReasoningOutcome::CodeBypass);
        assert_eq!(result.outcome_label(), "code_bypass");
    }

    #[test]
    fn pre_compression_eligibility_preserves_code_bypass() {
        let provider = provider("openai", None);
        let original = request("Implement fn parse(input: &str) -> Result<Value, Error>.");
        let eligibility = reasoning_eligibility(&original);
        let mut compressed = request("Implement the requested parser.");
        let unchanged = compressed.clone();

        let result = apply_reasoning_policy_with_eligibility(
            ReasoningPolicy::Concise,
            &provider,
            "gpt-5",
            &mut compressed,
            eligibility,
        );

        assert_eq!(compressed, unchanged);
        assert!(!result.applied);
        assert_eq!(result.outcome, ReasoningOutcome::CodeBypass);
    }

    #[test]
    fn openai_uses_native_effort_and_numeric_completion_cap() {
        let provider = provider("openai-primary", Some("openai"));
        let mut concise = request("Summarize the tradeoffs.");
        let result = apply_reasoning_policy(
            ReasoningPolicy::Concise,
            &provider,
            "gpt-5-mini",
            &mut concise,
        );
        assert!(result.applied);
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(concise["reasoning_effort"], "low");
        assert!(concise.get("max_completion_tokens").is_none());

        let mut budgeted = request("Summarize the tradeoffs.");
        budgeted["max_completion_tokens"] = json!(8192);
        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "o3-mini",
            &mut budgeted,
        );
        assert!(result.applied);
        assert_eq!(result.outcome_label(), "native");
        assert_eq!(budgeted["reasoning_effort"], "low");
        assert_eq!(budgeted["max_completion_tokens"], 2048);
    }

    #[test]
    fn openai_responses_uses_native_reasoning_and_output_fields() {
        let provider = provider("openai-primary", Some("openai"));
        let mut body = json!({
            "model": "gpt-5-mini",
            "input": "Summarize the tradeoffs.",
            "max_output_tokens": 8192,
        });

        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "gpt-5-mini",
            &mut body,
        );

        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(body["reasoning"], json!({"effort": "low"}));
        assert_eq!(body["max_output_tokens"], 2048);
        assert!(body.get("reasoning_effort").is_none());
        assert!(body.get("max_completion_tokens").is_none());
    }

    #[test]
    fn responses_prompt_fallback_uses_instructions_and_output_cap() {
        let provider = provider("custom-primary", Some("custom"));
        let mut body = json!({
            "model": "custom-model",
            "input": "Summarize the tradeoffs.",
            "max_output_tokens": 8192,
        });

        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "custom-model",
            &mut body,
        );

        assert_eq!(result.outcome, ReasoningOutcome::PromptFallback);
        assert_eq!(body["instructions"], PROMPT_FALLBACK_INSTRUCTION);
        assert_eq!(body["max_output_tokens"], 2048);
        assert!(body.get("messages").is_none());
    }

    #[test]
    fn openai_compatible_provider_without_native_capability_uses_fallback() {
        let provider = provider("groq", None);
        let mut body = request("Compare the options.");

        let result =
            apply_reasoning_policy(ReasoningPolicy::Concise, &provider, "gpt-5-mini", &mut body);

        assert_eq!(result.outcome, ReasoningOutcome::PromptFallback);
        assert!(body.get("reasoning_effort").is_none());
        assert_eq!(body["messages"][0]["content"], PROMPT_FALLBACK_INSTRUCTION);
    }

    #[test]
    fn anthropic_uses_adaptive_effort_or_manual_budget_by_model_family() {
        let provider = provider("anthropic-primary", Some("anthropic"));
        let mut concise = request("Compare the options.");
        let result = apply_reasoning_policy(
            ReasoningPolicy::Concise,
            &provider,
            "claude-sonnet-4-6",
            &mut concise,
        );
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(concise["thinking"], json!({"type": "adaptive"}));
        assert_eq!(concise["output_config"], json!({"effort": "low"}));

        let mut budgeted = request("Compare the options.");
        budgeted["max_tokens"] = json!(512);
        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "claude-sonnet-4-5",
            &mut budgeted,
        );
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(
            budgeted["thinking"],
            json!({"type": "enabled", "budget_tokens": 2048})
        );
        assert_eq!(
            budgeted["max_tokens"], 2560,
            "the caller's visible output allowance remains available"
        );
    }

    #[test]
    fn anthropic_existing_thinking_budget_still_gets_a_valid_output_allowance() {
        let provider = provider("anthropic-primary", Some("anthropic"));
        let mut body = request("Compare the options.");
        body["thinking"] = json!({"type": "enabled", "budget_tokens": 2048});
        body["max_tokens"] = json!(512);

        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "claude-sonnet-4-5",
            &mut body,
        );

        assert!(result.applied);
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(body["max_tokens"], 2560);
    }

    #[test]
    fn current_anthropic_adaptive_models_use_native_concise_policy() {
        let provider = provider("anthropic-primary", Some("anthropic"));
        for model in [
            "claude-opus-4-8",
            "claude-sonnet-5",
            "claude-fable-5",
            "claude-mythos-5",
        ] {
            let mut body = request("Compare the options.");
            let result =
                apply_reasoning_policy(ReasoningPolicy::Concise, &provider, model, &mut body);

            assert_eq!(result.outcome, ReasoningOutcome::Native, "{model}");
            assert_eq!(body["thinking"], json!({"type": "adaptive"}), "{model}");
            assert_eq!(body["output_config"]["effort"], "low", "{model}");
        }
    }

    #[test]
    fn unsupported_native_budgets_use_the_safe_prompt_fallback() {
        let provider = provider("anthropic-primary", Some("anthropic"));
        for (model, budget) in [
            ("claude-sonnet-4-5", 512),
            ("claude-opus-4-8", 2048),
            ("claude-sonnet-5", 2048),
        ] {
            let mut body = request("Compare the options.");
            let result = apply_reasoning_policy(
                ReasoningPolicy::Budget(budget),
                &provider,
                model,
                &mut body,
            );

            assert_eq!(result.outcome, ReasoningOutcome::PromptFallback, "{model}");
            assert!(body.get("thinking").is_none(), "{model}");
            assert_eq!(body["max_tokens"], budget, "{model}");
        }
    }

    #[test]
    fn anthropic_adaptive_only_model_uses_fallback_for_numeric_policy() {
        let provider = provider("anthropic-primary", Some("anthropic"));
        let mut body = request("Compare the options.");

        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(512),
            &provider,
            "claude-sonnet-4-7",
            &mut body,
        );

        assert_eq!(result.outcome, ReasoningOutcome::PromptFallback);
        assert!(body.get("thinking").is_none());
        assert_eq!(body["max_tokens"], 512);
    }

    #[test]
    fn gemini_selects_thinking_level_or_budget_by_model_family() {
        let provider = provider("google-primary", Some("gemini"));
        let mut level = request("Compare the options.");
        let result = apply_reasoning_policy(
            ReasoningPolicy::Concise,
            &provider,
            "gemini-3-pro-preview",
            &mut level,
        );
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(
            level["generationConfig"]["thinkingConfig"],
            json!({"thinkingLevel": "low"})
        );

        let mut budget = request("Compare the options.");
        let result = apply_reasoning_policy(
            ReasoningPolicy::Budget(768),
            &provider,
            "gemini-2.5-flash",
            &mut budget,
        );
        assert_eq!(result.outcome, ReasoningOutcome::Native);
        assert_eq!(
            budget["generationConfig"]["thinkingConfig"],
            json!({"thinkingBudget": 768})
        );
    }

    #[test]
    fn gemini_reasoning_fields_survive_native_translation() {
        let provider = provider("google-primary", Some("gemini"));
        let mut body = request("Compare the options.");
        body["temperature"] = json!(0.2);
        apply_reasoning_policy(
            ReasoningPolicy::Concise,
            &provider,
            "gemini-3-pro-preview",
            &mut body,
        );

        let (native, _) = translators::gemini::request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            native["generationConfig"]["thinkingConfig"],
            json!({"thinkingLevel": "low"})
        );
        assert_eq!(native["generationConfig"]["temperature"], 0.2);
    }

    #[test]
    fn bedrock_anthropic_fields_survive_native_translation() {
        let provider = provider("bedrock-primary", Some("bedrock"));
        let mut body = request("Compare the options.");
        body["max_tokens"] = json!(256);
        apply_reasoning_policy(
            ReasoningPolicy::Budget(2048),
            &provider,
            "anthropic.claude-sonnet-4-5-v1:0",
            &mut body,
        );

        let (native, _) = translators::bedrock::request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            native["additionalModelRequestFields"]["thinking"],
            json!({"type": "enabled", "budget_tokens": 2048})
        );
        assert_eq!(native["inferenceConfig"]["maxTokens"], 2304);
    }

    #[test]
    fn unknown_models_and_custom_providers_use_one_prompt_fallback() {
        let providers = [
            provider("openai-primary", Some("openai")),
            provider("private-model", Some("private-api")),
        ];
        for provider in providers {
            let mut body = request("Compare the options.");
            body["max_tokens"] = json!(4096);

            let first = apply_reasoning_policy(
                ReasoningPolicy::Budget(512),
                &provider,
                "unrecognized-model-family",
                &mut body,
            );
            let second = apply_reasoning_policy(
                ReasoningPolicy::Budget(512),
                &provider,
                "unrecognized-model-family",
                &mut body,
            );

            assert_eq!(first.outcome, ReasoningOutcome::PromptFallback);
            assert_eq!(first.outcome_label(), "prompt_fallback");
            assert_eq!(body["max_tokens"], 512);
            let inserted = body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|message| {
                    message.get("role").and_then(Value::as_str) == Some("system")
                        && message.get("content").and_then(Value::as_str)
                            == Some(PROMPT_FALLBACK_INSTRUCTION)
                })
                .count();
            assert_eq!(inserted, 1, "fallback instruction must be idempotent");
            assert!(!second.applied, "a second application changes no bytes");
        }
    }
}
