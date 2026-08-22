//! Provider trait and configuration.

use serde::Deserialize;
use std::collections::HashMap;

use crate::ids::{ModelId, ProviderName};
use crate::providers::get_provider_info;

/// Provider configuration from YAML/JSON.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ProviderConfig {
    /// Unique provider name used to reference this provider.
    pub name: ProviderName,
    /// Optional provider type (e.g. "openai", "anthropic"); inferred from name if absent.
    #[serde(default)]
    pub provider_type: Option<String>,
    /// Canonical model-host deployment ID. This is required when
    /// `provider_type` is `managed_model` and rejected for every other provider.
    #[serde(default)]
    pub deployment: Option<String>,
    /// API key used to authenticate with the upstream provider.
    pub api_key: Option<String>,
    /// Canonical native-provider label whose caller-owned credential this
    /// exact provider destination may receive.
    ///
    /// This is an explicit destination trust decision. It defaults to
    /// disabled and must match `provider_type` (or `name` when no type is
    /// configured). For example, `openai` permits an OpenAI-shaped native key
    /// to replace `api_key` only for this provider entry and its effective
    /// `base_url`.
    #[serde(default)]
    pub accept_native_credentials_for: Option<String>,
    /// Override the upstream base URL (defaults to the provider's well-known URL).
    #[serde(default)]
    pub base_url: Option<String>,
    /// Models served by this provider; empty defers to the provider catalog.
    #[serde(default)]
    pub models: Vec<ModelId>,
    /// Default model used when the request omits an explicit model.
    #[serde(default)]
    pub default_model: Option<ModelId>,
    /// Per-provider mapping from logical model name to upstream model name.
    #[serde(default)]
    pub model_map: HashMap<ModelId, ModelId>,
    /// Weight used by weighted routing strategies.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Priority used by priority-based routing (lower runs first).
    #[serde(default)]
    pub priority: Option<u32>,
    /// Whether this provider is eligible for routing.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum retry attempts on transient upstream failures.
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Request timeout in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Organization identifier (used by providers that scope keys per org).
    #[serde(default)]
    pub organization: Option<String>,
    /// API version header value (used by Anthropic and Azure OpenAI).
    #[serde(default)]
    pub api_version: Option<String>,
    /// Override the `Host` header sent to the AI provider. Defaults to the
    /// provider's base URL hostname (api.openai.com, api.anthropic.com, ...).
    /// Set this when fronting the provider through a custom domain.
    #[serde(default)]
    pub host_override: Option<String>,
    /// When true, suppress the `X-Forwarded-Host` header that the proxy
    /// would otherwise set to the client's original `Host` whenever it
    /// rewrites the upstream `Host`.
    #[serde(default)]
    pub disable_forwarded_host_header: bool,
    /// Allow this provider's `base_url` to point at a private/loopback
    /// address. Defaults to `false`: a `base_url` resolving to
    /// a loopback, link-local, or RFC1918 target is rejected at config
    /// load as an SSRF risk. Set `true` for a local model server
    /// (Ollama, vLLM, LM Studio on `127.0.0.1`/LAN). Non-`http(s)`
    /// schemes (`file://`, ...) are always rejected regardless.
    #[serde(default)]
    pub allow_private_base_url: bool,
    /// Operator's declaration that this provider does not retain or
    /// train on the prompts sent to it, per the provider's published
    /// data-handling agreement. There is no standardized per-request
    /// training opt-out header across providers, so SBproxy treats
    /// this as a deployment-level fact: a request that opts out of
    /// training (the `x-sbproxy-disallow-prompt-training` signal) is
    /// routed only to providers marked here. Defaults to `false`.
    #[serde(default)]
    pub no_prompt_training: bool,
    /// Operator override of this destination's declared data-handling
    /// posture, consulted by the `data_posture:` routing eligibility
    /// filter. The provider catalog supplies the vendor default from
    /// its published terms; this block declares what holds for this
    /// deployment, for example `zdr: true` on an entry whose account
    /// has a signed zero-data-retention agreement. That declaration is
    /// the only thing that makes a vendor which retains by default
    /// eligible for `require_zdr`. Unset keeps the catalog's
    /// declaration. See `sbproxy_ai::data_posture`.
    #[serde(default)]
    pub data_posture: Option<crate::data_posture::DataPostureOverride>,
    /// WOR-1652: optional local model-serving block. When set, the
    /// gateway itself hosts the models (pull weights, fit an engine to
    /// the GPU, supervise it) and registers them as local providers
    /// ahead of any cloud fallback, instead of proxying `base_url` to
    /// an already-running server. `None` keeps the proxy-only behavior.
    /// The lifecycle half (spawn/evict) ships in phases of the model-host
    /// epic; this field is the config surface it reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve: Option<sbproxy_model_host::ModelHostConfig>,
    /// Sign this provider's requests with AWS Signature
    /// Version 4 instead of forwarding a static credential. Required
    /// by Bedrock and SageMaker, which do not accept a bearer token.
    /// Presence of this block is what selects the signer, so a
    /// provider entry either sets `api_key` or sets this, never both.
    /// `region` is required and is the credential scope; it is never
    /// inferred from `base_url`, matching the AWS SDKs, where an
    /// endpoint override leaves the signing region alone. When
    /// `base_url` is unset, `region` also fills the `{region}`
    /// placeholder in the provider catalog's default endpoint. See
    /// `sbproxy_ai::aws_sigv4`.
    #[serde(default)]
    // Boxed deliberately, and a plain comment rather than rustdoc
    // because this rustdoc ships as the operator-facing schema
    // description and an operator does not care where the bytes live.
    // `AwsSigV4Config` is 256 bytes and almost every entry leaves it
    // unset, so inlining it grew every `ProviderConfig` by 50% and,
    // with it, every async state machine holding one across an await.
    // That was enough to overflow the Pingora worker thread's stack on
    // the AI request path.
    pub aws_sigv4: Option<Box<crate::aws_sigv4::AwsSigV4Config>>,
    /// Amazon Bedrock guardrail applied inline by the Converse call
    /// itself.
    ///
    /// Set this to have Bedrock evaluate the prompt and the completion
    /// inside the same request that generates them, rather than as a
    /// separate `ApplyGuardrail` call. An intervention comes back on a
    /// 200 response as `stopReason: guardrail_intervened`; SBproxy
    /// turns that into a 403 `guardrail_violation`, records it on the
    /// output guardrail decision feed under the name
    /// `bedrock_guardrail`, and never admits the response to any
    /// cache.
    ///
    /// Valid only when this provider entry resolves to the Bedrock
    /// wire format. Configuring it on any other provider is refused at
    /// config load.
    ///
    /// This is a different control from `guardrails.external[]` with
    /// `provider: bedrock`, which is an out-of-band `ApplyGuardrail`
    /// call against the same AWS guardrail object. Both may be
    /// configured; the account is then charged for two evaluations.
    ///
    /// There is no failure posture for this block. The guardrail runs
    /// inside the generation call, so a rejected or unauthorized
    /// guardrail configuration fails the whole call before any tokens
    /// are produced and is handled by the ordinary provider-failure
    /// path.
    #[serde(default)]
    // Boxed for the same reason `aws_sigv4` is, and with the same
    // plain-comment treatment because the rustdoc above ships as the
    // operator-facing schema description: almost every provider entry
    // leaves this unset, and `ProviderConfig` is held across awaits on
    // the AI request path where the Pingora worker stack is already at
    // its 2MB ceiling.
    pub bedrock_guardrail: Option<Box<BedrockGuardrailPassthrough>>,
}

/// Inline Bedrock Converse guardrail settings.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BedrockGuardrailPassthrough {
    /// Bedrock guardrail identifier, sent as `guardrailIdentifier`.
    pub identifier: String,
    /// Bedrock guardrail version, sent as `guardrailVersion`. Use
    /// `DRAFT` for the working version.
    pub version: String,
    /// Ask Bedrock for the guardrail assessment trace. The trace is
    /// used to name the policies that fired in the block reason and is
    /// never relayed to the caller. Defaults to `false`.
    #[serde(default)]
    pub trace: bool,
}

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

impl ProviderConfig {
    /// Provider protocol/catalog key used to select wire format.
    pub fn effective_provider_type(&self) -> &str {
        self.provider_type.as_deref().unwrap_or(&self.name)
    }

    /// Whether this exact destination explicitly accepts the canonical
    /// caller-owned native credential.
    pub fn accepts_native_credential_for(&self, native_provider: &str) -> bool {
        self.accept_native_credentials_for
            .as_deref()
            .is_some_and(|bound| {
                bound == bound.trim().to_ascii_lowercase()
                    && bound.eq_ignore_ascii_case(native_provider.trim())
                    && bound.eq_ignore_ascii_case(self.effective_provider_type().trim())
                    && !self.is_managed_model()
                    && self.serve.is_none()
            })
    }

    /// Validate the explicit native-credential destination binding.
    pub fn validate_native_credential_binding(&self) -> Result<(), String> {
        let Some(bound) = self.accept_native_credentials_for.as_deref() else {
            return Ok(());
        };
        let canonical = bound.trim().to_ascii_lowercase();
        if canonical.is_empty() {
            return Err("accept_native_credentials_for must not be empty".to_string());
        }
        if bound != canonical {
            return Err(
                "accept_native_credentials_for must be a trimmed lowercase provider label"
                    .to_string(),
            );
        }
        if self.is_managed_model() || self.serve.is_some() {
            return Err(
                "managed or locally served providers cannot accept native cloud credentials"
                    .to_string(),
            );
        }
        if !self
            .effective_provider_type()
            .trim()
            .eq_ignore_ascii_case(&canonical)
        {
            return Err(format!(
                "accept_native_credentials_for {bound:?} must match provider_type {:?}",
                self.effective_provider_type()
            ));
        }
        Ok(())
    }

    /// Whether this provider routes to an SBproxy-managed deployment.
    pub fn is_managed_model(&self) -> bool {
        self.provider_type.as_deref() == Some("managed_model")
    }

    /// Validate the managed-deployment reference and reject ambiguous upstream state.
    pub fn validate_managed_model(&self) -> Result<(), String> {
        if !self.is_managed_model() {
            if self.deployment.is_some() {
                return Err(
                    "deployment is only valid when provider_type is managed_model".to_string(),
                );
            }
            return Ok(());
        }

        if self
            .deployment
            .as_deref()
            .is_none_or(|deployment| deployment.trim().is_empty())
        {
            return Err("provider_type managed_model requires deployment".to_string());
        }
        if self.base_url.is_some() {
            return Err("managed_model provider must not set base_url".to_string());
        }
        if self.serve.is_some() {
            return Err("managed_model provider must not also set legacy serve".to_string());
        }
        if self.api_key.is_some() {
            return Err("managed_model provider must not set api_key".to_string());
        }
        Ok(())
    }

    /// Validate the inline Bedrock Converse guardrail block.
    ///
    /// `bedrock_guardrail` writes `guardrailConfig` into a Converse
    /// request body. No other wire format has that field, so an entry
    /// that is not Bedrock would silently drop the block and claim a
    /// guardrail it never applied.
    pub fn validate_bedrock_guardrail(&self) -> Result<(), String> {
        let Some(guardrail) = self.bedrock_guardrail.as_deref() else {
            return Ok(());
        };
        let format = crate::client::provider_format(self);
        if format != crate::providers::ProviderFormat::Bedrock {
            return Err(format!(
                "bedrock_guardrail is only valid on a Bedrock provider; \
                 provider_type {:?} resolves to the {format:?} wire format, \
                 which has no guardrailConfig field",
                self.effective_provider_type()
            ));
        }
        if guardrail.identifier.trim().is_empty() {
            return Err("bedrock_guardrail.identifier must not be empty".to_string());
        }
        if guardrail.version.trim().is_empty() {
            return Err("bedrock_guardrail.version must not be empty".to_string());
        }
        Ok(())
    }

    /// Get the effective base URL for this provider.
    ///
    /// Priority: explicit `base_url` > registry default > fallback localhost.
    ///
    /// WOR-2648: the AWS catalog entries default to the templates
    /// `https://bedrock-runtime.{region}.amazonaws.com` and
    /// `https://runtime.sagemaker.{region}.amazonaws.com`, and nothing
    /// used to substitute that placeholder, which is why a literal
    /// `{region}` reached the upstream and 404'd. An `aws_sigv4:` block
    /// supplies the region, so it fills the placeholder here, the same
    /// way APISIX's `host_template` and Kong's `upstream_url_format`
    /// build a Bedrock host from a configured region. This is gated on
    /// the block being present, so a provider without one keeps the
    /// previous behavior byte for byte, and an explicit `base_url`
    /// still wins outright, which is what makes a VPC endpoint
    /// reachable without changing the region a signature is scoped to.
    pub fn effective_base_url(&self) -> String {
        let url = match self.base_url {
            Some(ref url) => url.clone(),
            None => {
                let ptype = self.provider_type.as_deref().unwrap_or(&self.name);
                get_provider_info(ptype)
                    .map(|info| info.default_base_url)
                    .unwrap_or_else(|| "http://localhost:8080/v1".to_string())
            }
        };
        match self.aws_sigv4.as_ref() {
            Some(sigv4) if url.contains("{region}") => url.replace("{region}", sigv4.region.trim()),
            _ => url,
        }
    }

    /// Validate an operator-supplied `base_url` for SSRF safety.
    ///
    /// When no `base_url` is set the provider uses a registry default
    /// (a known-good public URL), so there is nothing to check. When one
    /// is set:
    ///
    /// - Non-`http(s)` schemes (`file://`, `gopher://`, ...) are always
    ///   rejected.
    /// - By default the URL must not target a private/loopback/link-local
    ///   address (blocks `http://169.254.169.254/`, `http://127.0.0.1/`,
    ///   internal hosts), via [`sbproxy_security::ssrf::validate_url`].
    /// - When `allow_private_base_url` is set, the private-address block is
    ///   skipped (for a local model server) but the scheme check still
    ///   applies.
    ///
    /// # Errors
    ///
    /// Returns the human-readable reason the URL was rejected.
    pub fn validate_base_url(&self) -> Result<(), String> {
        let Some(url) = self.base_url.as_deref() else {
            return Ok(());
        };
        if self.allow_private_base_url {
            // Operator opted into a local/private model server. Still
            // reject non-http(s) schemes; allow any host/IP otherwise.
            let parsed =
                reqwest::Url::parse(url).map_err(|e| format!("invalid base_url {url:?}: {e}"))?;
            match parsed.scheme() {
                "http" | "https" => Ok(()),
                other => Err(format!(
                    "base_url {url:?}: blocked scheme {other:?}; only http/https are permitted"
                )),
            }
        } else {
            sbproxy_security::ssrf::validate_url(url)
        }
    }

    /// Validate an `aws_sigv4:` block against the rest of the entry.
    ///
    /// Checks the block's own rules (a non-empty `region`, a resolvable
    /// signing service, a credential source whose required fields are
    /// present) plus the cross-field rules that only make sense here:
    ///
    /// - `api_key` and `aws_sigv4` are mutually exclusive. Both set is
    ///   an operator who believes one of them is doing something it is
    ///   not, and the signer overwrites `Authorization` either way, so
    ///   the static credential would be silently discarded.
    /// - `accept_native_credentials_for` is refused. That key hands a
    ///   caller-owned key to a destination in place of `api_key`, and a
    ///   signed provider has no `api_key` to replace; a tenant cannot
    ///   supply an AWS signature through it.
    /// - A locally served (`serve:`) or `managed_model` provider is
    ///   refused, because neither dials AWS at all.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing reason the entry was rejected. The
    /// message names configuration keys and never a credential value.
    pub fn validate_aws_sigv4(&self) -> Result<(), String> {
        let Some(sigv4) = self.aws_sigv4.as_ref() else {
            return Ok(());
        };
        if self.api_key.is_some() {
            return Err(
                "`api_key` and `aws_sigv4` are mutually exclusive: a SigV4 provider \
                 computes its own `Authorization` header, so a static credential set \
                 alongside it would be discarded"
                    .to_string(),
            );
        }
        if self.accept_native_credentials_for.is_some() {
            return Err(
                "`accept_native_credentials_for` cannot be combined with `aws_sigv4`: \
                 it substitutes a caller-owned key for `api_key`, which a signed \
                 provider does not use"
                    .to_string(),
            );
        }
        if self.serve.is_some() || self.is_managed_model() {
            return Err(
                "`aws_sigv4` is for an upstream AWS endpoint; a locally served or \
                 managed_model provider never dials one"
                    .to_string(),
            );
        }
        sigv4
            .validate(self.effective_provider_type())
            .map_err(|error| error.to_string())
    }

    /// Get the auth header name and formatted value for this provider.
    ///
    /// Returns `(header_name, header_value)` where header_value includes
    /// any required prefix (e.g. "Bearer sk-xxx" or raw "sk-xxx").
    /// The header name and value are owned because the registry now
    /// holds YAML-loaded strings rather than `&'static` constants.
    pub fn auth_header(&self) -> (String, String) {
        let ptype = self.provider_type.as_deref().unwrap_or(&self.name);
        let info = get_provider_info(ptype);
        let header = info
            .as_ref()
            .map(|i| i.auth_header.clone())
            .unwrap_or_else(|| "Authorization".to_string());
        let prefix = info
            .as_ref()
            .map(|i| i.auth_prefix.clone())
            .unwrap_or_else(|| "Bearer ".to_string());
        let key = self.api_key.as_deref().unwrap_or("");
        (header, format!("{}{}", prefix, key))
    }

    /// Map a requested model to the provider's model name.
    pub fn map_model(&self, model: &str) -> String {
        self.model_map
            .get(model)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| model.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_schema_carries_the_serve_surface() {
        // WOR-1686: the committed ai-proxy-provider schema must expose
        // the serve: block so an editor autocompletes it. Anchor that
        // the derive actually reaches ModelHostConfig's fields.
        let schema = schemars::schema_for!(ProviderConfig);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("\"serve\""), "serve field present");
        // A serve/ModelHostConfig-specific field proves the subtree, not
        // just the field name, is in the schema.
        assert!(
            json.contains("keep_alive") || json.contains("catalog_file"),
            "serve subtree (ServeEntry/ModelHostConfig fields) present"
        );
    }

    fn make_provider(name: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            provider_type: None,
            deployment: None,
            api_key: None,
            accept_native_credentials_for: None,
            base_url: None,
            models: Vec::new(),
            default_model: None,
            model_map: HashMap::new(),
            weight: 1,
            priority: None,
            enabled: true,
            max_retries: None,
            timeout_ms: None,
            organization: None,
            api_version: None,
            host_override: None,
            disable_forwarded_host_header: false,
            allow_private_base_url: false,
            no_prompt_training: false,
            data_posture: None,
            serve: None,
            aws_sigv4: None,
            bedrock_guardrail: None,
        }
    }

    fn sigv4_provider(json: serde_json::Value) -> ProviderConfig {
        serde_json::from_value(json).expect("fixture provider parses")
    }

    #[test]
    fn effective_base_url_openai() {
        let p = make_provider("openai");
        assert_eq!(p.effective_base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn effective_base_url_anthropic() {
        let p = make_provider("anthropic");
        assert_eq!(p.effective_base_url(), "https://api.anthropic.com/v1");
    }

    #[test]
    fn effective_base_url_gemini() {
        let p = make_provider("gemini");
        assert_eq!(
            p.effective_base_url(),
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }

    #[test]
    fn effective_base_url_unknown_provider() {
        let p = make_provider("local-llm");
        assert_eq!(p.effective_base_url(), "http://localhost:8080/v1");
    }

    #[test]
    fn effective_base_url_custom_override() {
        let mut p = make_provider("openai");
        p.base_url = Some("https://custom.proxy.com/v1".to_string());
        assert_eq!(p.effective_base_url(), "https://custom.proxy.com/v1");
    }

    #[test]
    fn effective_base_url_provider_type_override() {
        let mut p = make_provider("my-openai");
        p.provider_type = Some("openai".to_string());
        assert_eq!(p.effective_base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn map_model_passthrough() {
        let p = make_provider("openai");
        assert_eq!(p.map_model("gpt-4"), "gpt-4");
    }

    #[test]
    fn map_model_mapped() {
        let mut p = make_provider("openai");
        p.model_map.insert("fast".into(), "gpt-3.5-turbo".into());
        assert_eq!(p.map_model("fast"), "gpt-3.5-turbo");
        assert_eq!(p.map_model("gpt-4"), "gpt-4");
    }

    #[test]
    fn provider_config_from_json() {
        let json = serde_json::json!({
            "name": "openai",
            "api_key": "sk-test",
            "models": ["gpt-4", "gpt-3.5-turbo"],
            "default_model": "gpt-4",
            "weight": 5,
            "priority": 1
        });
        let p: ProviderConfig = serde_json::from_value(json).unwrap();
        assert_eq!(p.name, "openai");
        assert_eq!(p.api_key.as_deref(), Some("sk-test"));
        assert_eq!(p.models.len(), 2);
        assert_eq!(p.weight, 5);
        assert_eq!(p.priority, Some(1));
        assert!(p.enabled);
    }

    #[test]
    fn provider_config_defaults() {
        let json = serde_json::json!({"name": "test"});
        let p: ProviderConfig = serde_json::from_value(json).unwrap();
        assert_eq!(p.weight, 1);
        assert!(p.enabled);
        assert!(p.api_key.is_none());
        assert!(p.base_url.is_none());
        assert!(p.models.is_empty());
    }

    #[test]
    fn native_credential_destination_requires_explicit_canonical_binding() {
        let unbound: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "primary",
            "provider_type": "openai",
            "base_url": "https://gateway.example/v1"
        }))
        .unwrap();
        assert!(!unbound.accepts_native_credential_for("openai"));

        let bound: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "primary",
            "provider_type": "openai",
            "base_url": "https://gateway.example/v1",
            "accept_native_credentials_for": "openai"
        }))
        .unwrap();
        assert!(bound.accepts_native_credential_for(" OPENAI "));
        assert!(!bound.accepts_native_credential_for("anthropic"));
        assert!(bound.validate_native_credential_binding().is_ok());
    }

    #[test]
    fn native_credential_destination_rejects_ambiguous_or_local_bindings() {
        for json in [
            serde_json::json!({
                "name": "primary",
                "provider_type": "openai",
                "accept_native_credentials_for": " OpenAI "
            }),
            serde_json::json!({
                "name": "primary",
                "provider_type": "anthropic",
                "accept_native_credentials_for": "openai"
            }),
            serde_json::json!({
                "name": "managed",
                "provider_type": "managed_model",
                "deployment": "local",
                "accept_native_credentials_for": "managed_model"
            }),
        ] {
            let provider: ProviderConfig = serde_json::from_value(json).unwrap();
            assert!(provider.validate_native_credential_binding().is_err());
        }
    }

    #[test]
    fn native_credential_binding_is_present_in_provider_schema() {
        let schema = schemars::schema_for!(ProviderConfig);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("\"accept_native_credentials_for\""));
    }

    // --- auth_header tests ---

    #[test]
    fn auth_header_openai_bearer() {
        let mut p = make_provider("openai");
        p.api_key = Some("sk-test123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer sk-test123");
    }

    #[test]
    fn auth_header_anthropic_x_api_key() {
        let mut p = make_provider("anthropic");
        p.api_key = Some("sk-ant-test".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "sk-ant-test");
    }

    #[test]
    fn auth_header_azure_api_key() {
        let mut p = make_provider("azure");
        p.api_key = Some("az-key-123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "api-key");
        assert_eq!(value, "az-key-123");
    }

    #[test]
    fn auth_header_unknown_defaults_to_bearer() {
        let mut p = make_provider("custom-llm");
        p.api_key = Some("mykey".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer mykey");
    }

    #[test]
    fn auth_header_no_key() {
        let p = make_provider("openai");
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer ");
    }

    #[test]
    fn auth_header_respects_provider_type() {
        let mut p = make_provider("my-custom-name");
        p.provider_type = Some("anthropic".to_string());
        p.api_key = Some("key123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "key123");
    }

    // --- Registry-backed base URL tests ---

    #[test]
    fn effective_base_url_groq() {
        let p = make_provider("groq");
        assert_eq!(p.effective_base_url(), "https://api.groq.com/openai/v1");
    }

    #[test]
    fn effective_base_url_mistral() {
        let p = make_provider("mistral");
        assert_eq!(p.effective_base_url(), "https://api.mistral.ai/v1");
    }

    #[test]
    fn effective_base_url_together() {
        let p = make_provider("together");
        assert_eq!(p.effective_base_url(), "https://api.together.ai/v1");
    }

    #[test]
    fn effective_base_url_deepseek() {
        let p = make_provider("deepseek");
        assert_eq!(p.effective_base_url(), "https://api.deepseek.com/v1");
    }

    #[test]
    fn effective_base_url_ollama() {
        let p = make_provider("ollama");
        assert_eq!(p.effective_base_url(), "http://localhost:11434/v1");
    }

    // --- WOR-603: base_url SSRF validation ---

    fn provider_with_base_url(url: &str, allow_private: bool) -> ProviderConfig {
        let mut p = make_provider("custom");
        p.base_url = Some(url.to_string());
        p.allow_private_base_url = allow_private;
        p
    }

    #[test]
    fn base_url_none_is_ok() {
        // No override -> registry default -> nothing to validate.
        assert!(make_provider("openai").validate_base_url().is_ok());
    }

    #[test]
    fn base_url_public_https_is_ok() {
        assert!(provider_with_base_url("https://8.8.8.8/v1", false)
            .validate_base_url()
            .is_ok());
    }

    #[test]
    fn base_url_file_scheme_rejected_even_when_private_allowed() {
        // Non-http(s) is always blocked, regardless of allow_private.
        assert!(provider_with_base_url("file:///etc/passwd", false)
            .validate_base_url()
            .is_err());
        assert!(provider_with_base_url("file:///etc/passwd", true)
            .validate_base_url()
            .is_err());
    }

    #[test]
    fn base_url_link_local_metadata_rejected_by_default() {
        // The classic SSRF target: cloud metadata at 169.254.169.254.
        assert!(
            provider_with_base_url("http://169.254.169.254/latest/meta-data", false)
                .validate_base_url()
                .is_err()
        );
    }

    #[test]
    fn base_url_loopback_rejected_by_default_but_allowed_with_opt_in() {
        // A local model server: blocked by default, allowed when the
        // operator opts in (e.g. Ollama on 127.0.0.1).
        assert!(provider_with_base_url("http://127.0.0.1:11434/v1", false)
            .validate_base_url()
            .is_err());
        assert!(provider_with_base_url("http://127.0.0.1:11434/v1", true)
            .validate_base_url()
            .is_ok());
    }

    #[test]
    fn a_sigv4_region_fills_the_catalog_endpoint_template() {
        // The catalog default is the literal template
        // `https://bedrock-runtime.{region}.amazonaws.com`, and before
        // WOR-2648 nothing substituted it, so the placeholder reached
        // the upstream and 404'd. The region on the signing block is
        // the only value in the config that can fill it.
        let bedrock = sigv4_provider(serde_json::json!({
            "name": "bedrock",
            "aws_sigv4": {"region": "eu-west-1"},
        }));
        assert_eq!(
            bedrock.effective_base_url(),
            "https://bedrock-runtime.eu-west-1.amazonaws.com"
        );
        let sagemaker = sigv4_provider(serde_json::json!({
            "name": "sagemaker",
            "aws_sigv4": {"region": "ap-southeast-2"},
        }));
        assert_eq!(
            sagemaker.effective_base_url(),
            "https://runtime.sagemaker.ap-southeast-2.amazonaws.com"
        );
    }

    #[test]
    fn an_explicit_base_url_wins_and_does_not_change_the_signing_region() {
        // This is the PrivateLink case the AWS SDKs handle the same
        // way: the endpoint moves, the credential scope does not.
        let vpce = sigv4_provider(serde_json::json!({
            "name": "bedrock",
            "base_url": "https://vpce-0a1b.bedrock-runtime.us-east-1.vpce.amazonaws.com",
            "aws_sigv4": {"region": "us-east-1"},
        }));
        assert_eq!(
            vpce.effective_base_url(),
            "https://vpce-0a1b.bedrock-runtime.us-east-1.vpce.amazonaws.com"
        );
        assert_eq!(
            vpce.aws_sigv4.as_ref().map(|s| s.region.as_str()),
            Some("us-east-1")
        );
    }

    #[test]
    fn the_placeholder_still_survives_without_a_signing_block() {
        // Substitution is gated on the block, so an entry that does not
        // sign behaves exactly as it did before this feature.
        let bare = make_provider("bedrock");
        assert_eq!(
            bare.effective_base_url(),
            "https://bedrock-runtime.{region}.amazonaws.com"
        );
    }

    #[test]
    fn api_key_and_aws_sigv4_are_mutually_exclusive() {
        let both = sigv4_provider(serde_json::json!({
            "name": "bedrock",
            "api_key": "Bearer whatever",
            "aws_sigv4": {"region": "us-east-1"},
        }));
        let error = both
            .validate_aws_sigv4()
            .expect_err("both credentials set is refused");
        assert!(error.contains("mutually exclusive"), "{error}");
    }

    #[test]
    fn a_signed_provider_refuses_the_native_credential_swap() {
        let swap = sigv4_provider(serde_json::json!({
            "name": "bedrock",
            "accept_native_credentials_for": "bedrock",
            "aws_sigv4": {"region": "us-east-1"},
        }));
        let error = swap
            .validate_aws_sigv4()
            .expect_err("a caller-owned key cannot replace a signature");
        assert!(error.contains("accept_native_credentials_for"), "{error}");
    }

    #[test]
    fn a_signing_block_on_a_non_aws_provider_type_needs_an_explicit_service() {
        let odd = sigv4_provider(serde_json::json!({
            "name": "mystery",
            "provider_type": "openai",
            "aws_sigv4": {"region": "us-east-1"},
        }));
        let error = odd
            .validate_aws_sigv4()
            .expect_err("no default signing service for a non-AWS provider type");
        assert!(error.contains("aws_sigv4.service"), "{error}");

        let named = sigv4_provider(serde_json::json!({
            "name": "mystery",
            "provider_type": "openai",
            "aws_sigv4": {"region": "us-east-1", "service": "execute-api"},
        }));
        named
            .validate_aws_sigv4()
            .expect("an explicit service is accepted");
    }

    #[test]
    fn a_provider_without_a_signing_block_validates_trivially() {
        make_provider("openai")
            .validate_aws_sigv4()
            .expect("no block, nothing to check");
    }

    #[test]
    fn bedrock_guardrail_on_a_non_bedrock_provider_is_refused() {
        // `guardrailConfig` is a Converse request field. On any other
        // wire format the translator has nowhere to put it, so the
        // provider entry would claim a guardrail it silently never
        // applies.
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "openai",
            "api_key": "sk-test",
            "bedrock_guardrail": {"identifier": "gr-1", "version": "DRAFT"},
        }))
        .expect("fixture provider parses");
        let error = provider
            .validate_bedrock_guardrail()
            .expect_err("an OpenAI-format provider cannot carry guardrailConfig");
        assert!(error.contains("bedrock_guardrail"), "{error}");
        assert!(error.contains("provider_type"), "{error}");
        assert!(error.contains("openai"), "{error}");

        let bedrock: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "bedrock",
            "aws_sigv4": {"region": "us-east-1"},
            "bedrock_guardrail": {"identifier": "gr-1", "version": "DRAFT"},
        }))
        .expect("fixture provider parses");
        bedrock
            .validate_bedrock_guardrail()
            .expect("a Bedrock provider accepts the block");
    }

    #[test]
    fn an_empty_bedrock_guardrail_identifier_or_version_is_refused() {
        for (field, body) in [
            (
                "identifier",
                serde_json::json!({"identifier": "  ", "version": "DRAFT"}),
            ),
            (
                "version",
                serde_json::json!({"identifier": "gr-1", "version": ""}),
            ),
        ] {
            let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
                "name": "bedrock",
                "aws_sigv4": {"region": "us-east-1"},
                "bedrock_guardrail": body,
            }))
            .expect("fixture provider parses");
            let error = provider
                .validate_bedrock_guardrail()
                .expect_err("a blank {field} is not a guardrail reference");
            assert!(error.contains(field), "{error}");
        }
    }

    #[test]
    fn json_schema_carries_the_bedrock_guardrail_surface() {
        // This rustdoc ships verbatim as the operator-facing schema
        // description, so the schema is the doc.
        let schema = schemars::schema_for!(ProviderConfig);
        let json = serde_json::to_string(&schema).expect("schema serializes");
        for needle in [
            "\"bedrock_guardrail\"",
            "BedrockGuardrailPassthrough",
            "\"identifier\"",
            "guardrailIdentifier",
        ] {
            assert!(json.contains(needle), "schema is missing {needle}");
        }
        assert!(
            !json.contains("Boxed"),
            "the boxing rationale must stay a plain comment; it ships as \
             the operator-facing schema description otherwise"
        );
    }

    #[test]
    fn json_schema_carries_the_aws_sigv4_surface() {
        // The committed ai-proxy-provider schema is what an editor
        // autocompletes against, and a security-relevant block that is
        // absent from it is one an operator will mistype in silence.
        let schema = schemars::schema_for!(ProviderConfig);
        let json = serde_json::to_string(&schema).expect("schema serializes");
        for needle in [
            "\"aws_sigv4\"",
            "AwsSigV4Config",
            "AwsCredentialsConfig",
            "AwsCredentialSource",
            "\"secret_access_key\"",
            "\"assume_role\"",
        ] {
            assert!(json.contains(needle), "schema is missing {needle}");
        }
    }
}
