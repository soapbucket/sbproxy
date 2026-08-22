//! Upstream service tier as an operator-configured routing axis (WOR-2652).
//!
//! Several vendors sell the same model at more than one latency and price
//! point, selected by a `service_tier` field on the request. Before this
//! module the gateway had no opinion: a caller POSTing
//! `{"service_tier": "priority"}` to `/v1/chat/completions` reached an
//! OpenAI-shaped upstream verbatim, because that surface never round-trips
//! through the canonical hub request. Raising the tier raises the bill and
//! the operator pays it, so the tier belongs to the provider entry.
//!
//! The shape follows [`crate::data_posture`], which made the same calls
//! first: a catalog declaration of what each vendor supports, an operator
//! override on the provider entry, a load-time refusal for an entry that can
//! never serve what it asks for, and a bounded refusal message that names
//! what was excluded.
//!
//! The tier is a property of a provider *entry*, not of a request. An
//! operator who wants two tiers of one vendor declares two `providers[]`
//! entries; the router then treats them as two candidates with independent
//! weights, health, cooldowns, and realized latency. Widening the candidate
//! set by a request parameter instead would mean reindexing every
//! positionally-indexed router array, which buys nothing this does not.

use serde::{Deserialize, Serialize};

use crate::provider::ProviderConfig;
use crate::providers::get_provider_info;

/// Canonical service tier vocabulary.
///
/// Deliberately closed rather than a passthrough vendor string: a closed set
/// can be validated at config load, used as a bounded metric label, and
/// translated per vendor. Each variant is translated to the vendor's own
/// wire value by that vendor's catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTier {
    /// Slower, cheaper capacity for work that tolerates queueing.
    Flex,
    /// The vendor's ordinary capacity.
    Standard,
    /// Faster, more expensive capacity.
    Priority,
}

impl ServiceTier {
    /// Canonical spelling, as written in config and as used for metric
    /// labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flex => "flex",
            Self::Standard => "standard",
            Self::Priority => "priority",
        }
    }
}

impl std::fmt::Display for ServiceTier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl schemars::JsonSchema for ServiceTier {
    fn schema_name() -> String {
        "ServiceTier".to_string()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = <String as schemars::JsonSchema>::json_schema(generator).into_object();
        schema.enum_values = Some(
            ["flex", "standard", "priority"]
                .iter()
                .map(|value| serde_json::Value::String((*value).to_string()))
                .collect(),
        );
        schema.into()
    }
}

/// One vendor's service-tier vocabulary, as declared by its catalog entry.
///
/// `field` is the request field the vendor reads. The three optional values
/// are that vendor's wire spelling for each canonical tier; an absent one
/// means the vendor does not sell that tier and an entry asking for it is
/// refused at config load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogServiceTiers {
    /// Request field the vendor reads the tier from.
    pub field: String,
    /// Vendor wire value for [`ServiceTier::Flex`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flex: Option<String>,
    /// Vendor wire value for [`ServiceTier::Standard`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    /// Vendor wire value for [`ServiceTier::Priority`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
}

impl CatalogServiceTiers {
    /// The vendor's wire value for one canonical tier, if it sells it.
    #[must_use]
    pub(crate) fn wire_value(&self, tier: ServiceTier) -> Option<&str> {
        match tier {
            ServiceTier::Flex => self.flex.as_deref(),
            ServiceTier::Standard => self.standard.as_deref(),
            ServiceTier::Priority => self.priority.as_deref(),
        }
    }

    /// Canonical tiers this vendor sells, in ascending cost order.
    #[must_use]
    pub fn supported(&self) -> Vec<ServiceTier> {
        [
            ServiceTier::Flex,
            ServiceTier::Standard,
            ServiceTier::Priority,
        ]
        .into_iter()
        .filter(|tier| self.wire_value(*tier).is_some())
        .collect()
    }
}

/// The tier vocabulary of a configured provider, from its catalog entry.
///
/// A provider whose catalog entry declares nothing has no vocabulary, so the
/// gateway sends no tier field for it and refuses any entry that asks for
/// one.
#[must_use]
pub(crate) fn provider_tier_vocabulary(provider: &ProviderConfig) -> Option<CatalogServiceTiers> {
    get_provider_info(provider.effective_provider_type())
        .and_then(|info| info.service_tiers.clone())
}

/// The wire field and value one provider entry should send, if any.
///
/// `None` means "send no tier field": either the entry declares no tier, or
/// the vendor has no vocabulary for it. Every request to that provider then
/// has any caller-supplied tier field removed, so the vendor serves on its
/// own default rather than on whatever the caller asked for.
#[must_use]
pub fn resolved_wire_tier(provider: &ProviderConfig) -> Option<(String, String)> {
    let tier = provider.service_tier?;
    let vocabulary = provider_tier_vocabulary(provider)?;
    let value = vocabulary.wire_value(tier)?;
    Some((vocabulary.field.clone(), value.to_string()))
}

/// Refuse at config-compile time a provider entry that asks for a tier its
/// vendor does not sell.
///
/// Same disposition as [`crate::data_posture::validate_posture_requirement`]'s
/// blackhole refusal, and for the same reason: an entry whose tier can never
/// be honored would boot green and then serve every request on a tier the
/// operator did not choose, which they would discover from the invoice.
pub fn validate_provider_tier(provider: &ProviderConfig) -> Result<(), String> {
    let Some(tier) = provider.service_tier else {
        return Ok(());
    };
    let provider_type = provider.effective_provider_type();
    let Some(vocabulary) = provider_tier_vocabulary(provider) else {
        return Err(format!(
            "`service_tier: {tier}` is not available: the provider catalog records no \
             service-tier vocabulary for provider type {provider_type:?}. Remove the key \
             to let the vendor serve on its own default, or ship a catalog entry \
             declaring the vendor's `service_tiers` block via \
             `proxy.ai_providers_file`."
        ));
    };
    if vocabulary.wire_value(tier).is_some() {
        return Ok(());
    }
    let supported = vocabulary
        .supported()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let supported = if supported.is_empty() {
        "none".to_string()
    } else {
        supported.join(", ")
    };
    Err(format!(
        "`service_tier: {tier}` is not sold by provider type {provider_type:?}; that \
         catalog entry declares {supported}. Pick a declared tier, or remove the key to \
         let the vendor serve on its own default."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, provider_type: &str, tier: Option<ServiceTier>) -> ProviderConfig {
        let mut config: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": name,
            "provider_type": provider_type,
            "api_key": "k",
        }))
        .expect("provider fixture");
        config.service_tier = tier;
        config
    }

    #[test]
    fn a_tier_the_vendor_does_not_sell_is_refused_at_load() {
        // Anthropic declares no `service_tiers` block, so there is no
        // vocabulary to translate into and the entry can never serve the
        // tier it names.
        let entry = provider("claude", "anthropic", Some(ServiceTier::Flex));
        let error = validate_provider_tier(&entry).expect_err("unsupported tier is refused");
        assert!(error.contains("service_tier: flex"), "{error}");
        assert!(error.contains("anthropic"), "{error}");
    }

    #[test]
    fn a_declared_tier_passes_and_resolves_to_the_vendor_wire_value() {
        let entry = provider("oai", "openai", Some(ServiceTier::Standard));
        validate_provider_tier(&entry).expect("openai sells a standard tier");
        assert_eq!(
            resolved_wire_tier(&entry),
            Some(("service_tier".to_string(), "default".to_string())),
            "the canonical `standard` tier is OpenAI's `default` on the wire"
        );

        let flex = provider("oai-flex", "openai", Some(ServiceTier::Flex));
        assert_eq!(
            resolved_wire_tier(&flex),
            Some(("service_tier".to_string(), "flex".to_string()))
        );
    }

    #[test]
    fn an_entry_with_no_tier_sends_no_tier_field() {
        let entry = provider("oai", "openai", None);
        validate_provider_tier(&entry).expect("no tier is always valid");
        assert_eq!(resolved_wire_tier(&entry), None);
    }
}
