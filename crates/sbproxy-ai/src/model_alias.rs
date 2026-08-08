//! Global model aliases and migration safety.
//!
//! A `model_aliases:` entry binds one friendly name a caller may send in
//! the request's `model` field to the upstream model id, and optionally to
//! the provider that serves it. Resolution runs on the dispatch path
//! before every model gate and before provider selection.
//!
//! That ordering is the whole point, and it is what the per-provider
//! [`ProviderConfig::model_map`](crate::provider::ProviderConfig::model_map)
//! cannot express. `model_map` is applied by `map_model` after the router
//! has already chosen a provider, so it renames a model on the way to one
//! upstream and has no say in which upstream that is. With the same
//! logical name in two providers' maps, the model the caller actually
//! reaches depends on whichever provider the routing strategy happened to
//! pick. An alias is resolved once, before that choice, so `model: fast`
//! means one model everywhere on the origin.
//!
//! Precedence is therefore fixed and one-way: an alias resolves the
//! caller's name to an upstream model id, and the selected provider's
//! `model_map` may then rename that id again on the wire. Aliases never
//! chain into other aliases; [`validate_model_aliases`] rejects an entry
//! whose target is itself an alias so resolution stays a single lookup.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use tracing::warn;

use crate::ids::{ModelId, ProviderName};
use crate::provider::ProviderConfig;

/// A mapping from a friendly alias to an upstream model id.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAlias {
    /// The friendly name callers send as `model` (for example `fast`).
    pub alias: ModelId,
    /// Provider this alias is pinned to.
    ///
    /// When set, the routing set is narrowed to that provider before any
    /// strategy runs, so the alias names one exact destination. When
    /// omitted the alias is a rename only, and provider selection falls
    /// through to the usual path: providers that declare the resolved
    /// model in `models:` are preferred, then the configured strategy
    /// picks among them.
    #[serde(default)]
    pub provider: Option<ProviderName>,
    /// The model id sent upstream in place of the alias.
    pub model_id: ModelId,
    /// When true, a deprecation warning is logged on every resolution.
    #[serde(default)]
    pub deprecated: bool,
    /// Alias to migrate to. Only valid together with `deprecated`, whose
    /// log line is the only place it surfaces.
    #[serde(default)]
    pub replacement: Option<ModelId>,
}

/// Registry of an origin's model aliases, built once per config load.
///
/// Immutable after construction, so the dispatch path shares one instance
/// across requests and resolution is a single map lookup.
#[derive(Debug, Default)]
pub struct ModelAliasRegistry {
    aliases: HashMap<String, ModelAlias>,
}

impl ModelAliasRegistry {
    /// Build a registry from the configured alias list.
    ///
    /// [`validate_model_aliases`] has already rejected duplicates at config
    /// load, so the last entry winning here is unreachable rather than a
    /// documented rule.
    pub fn from_config(aliases: Vec<ModelAlias>) -> Self {
        let aliases = aliases
            .into_iter()
            .map(|alias| (alias.alias.as_str().to_string(), alias))
            .collect();
        Self { aliases }
    }

    /// Whether this origin configured no aliases at all.
    ///
    /// The dispatch path checks this before touching the request body so an
    /// origin without aliases pays nothing for the feature.
    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }

    /// Resolve a requested model name to its alias entry.
    ///
    /// Returns `None` when the name is not an alias, which the caller
    /// treats as a literal model id. Logs a deprecation warning when the
    /// resolved alias is marked deprecated.
    pub fn resolve(&self, name: &str) -> Option<&ModelAlias> {
        let alias = self.aliases.get(name)?;
        if alias.deprecated {
            match &alias.replacement {
                Some(replacement) => warn!(
                    alias = name,
                    replacement = replacement.as_str(),
                    model_id = alias.model_id.as_str(),
                    "model alias {:?} is deprecated; use {:?} instead",
                    name,
                    replacement.as_str()
                ),
                None => warn!(
                    alias = name,
                    model_id = alias.model_id.as_str(),
                    "model alias {:?} is deprecated and has no replacement",
                    name
                ),
            }
        }
        Some(alias)
    }
}

/// Validate an origin's alias list against its providers at config load.
///
/// The checks that matter operationally are the shadowing ones. An alias
/// that reuses a name a provider already serves, either in its `models:`
/// list or as a `model_map` key, silently rewrites every request that asks
/// for the real model, and nothing downstream can tell that happened.
/// Refusing the config is the only point where an operator still sees it.
///
/// # Errors
///
/// Returns the human-readable reason the alias list was rejected.
pub fn validate_model_aliases(
    aliases: &[ModelAlias],
    providers: &[ProviderConfig],
) -> Result<(), String> {
    let mut names: HashSet<&str> = HashSet::new();
    for (index, alias) in aliases.iter().enumerate() {
        let name = alias.alias.as_str();
        if name.trim().is_empty() {
            return Err(format!("model_aliases[{index}]: alias must not be empty"));
        }
        if name.trim() != name {
            return Err(format!(
                "model_aliases[{index}]: alias {name:?} has leading or trailing whitespace, \
                 which no caller can send"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "model_aliases[{index}]: alias {name:?} is configured more than once"
            ));
        }
    }

    for (index, alias) in aliases.iter().enumerate() {
        let name = alias.alias.as_str();
        let target = alias.model_id.as_str();
        if target.trim().is_empty() {
            return Err(format!(
                "model_aliases[{index}] ({name:?}): model_id must not be empty"
            ));
        }
        if target == name {
            return Err(format!(
                "model_aliases[{index}]: alias {name:?} resolves to itself; remove the entry"
            ));
        }
        if names.contains(target) {
            return Err(format!(
                "model_aliases[{index}]: alias {name:?} resolves to {target:?}, which is itself \
                 an alias. Aliases resolve in one pass; point this entry at the upstream model id."
            ));
        }
        for provider in providers {
            if provider.models.iter().any(|model| model.as_str() == name) {
                return Err(format!(
                    "model_aliases[{index}]: alias {name:?} shadows a model provider {:?} \
                     serves. Every request asking for the real {name:?} would be rewritten to \
                     {target:?}; rename the alias.",
                    provider.name.as_str()
                ));
            }
            if provider.model_map.contains_key(name) {
                return Err(format!(
                    "model_aliases[{index}]: alias {name:?} shadows a model_map entry on \
                     provider {:?}, which would never be reached. Keep one of the two.",
                    provider.name.as_str()
                ));
            }
            let shadows_default = provider
                .default_model
                .as_ref()
                .is_some_and(|default| default.as_str() == name);
            if shadows_default {
                return Err(format!(
                    "model_aliases[{index}]: alias {name:?} shadows provider {:?}'s \
                     default_model; rename the alias.",
                    provider.name.as_str()
                ));
            }
        }

        if let Some(pinned) = alias.provider.as_ref() {
            let Some(provider) = providers
                .iter()
                .find(|provider| provider.name.as_str() == pinned.as_str())
            else {
                return Err(format!(
                    "model_aliases[{index}] ({name:?}): provider {:?} is not configured on this \
                     origin",
                    pinned.as_str()
                ));
            };
            // An empty `models:` list defers to the upstream catalog and
            // accepts anything, so there is nothing to check against. A
            // populated one is a claim about what the provider serves, and
            // a pin at a model outside it dispatches a request the upstream
            // rejects.
            let serves_target = provider.models.is_empty()
                || provider.models.iter().any(|model| model.as_str() == target)
                || provider.model_map.contains_key(target);
            if !serves_target {
                return Err(format!(
                    "model_aliases[{index}] ({name:?}): provider {:?} does not serve {target:?}. \
                     Add it to that provider's models: list, or pin the alias at a provider \
                     that serves it.",
                    pinned.as_str()
                ));
            }
        }

        if let Some(replacement) = alias.replacement.as_ref() {
            if !alias.deprecated {
                return Err(format!(
                    "model_aliases[{index}] ({name:?}): replacement is only logged for a \
                     deprecated alias; set deprecated: true or drop the field"
                ));
            }
            if !names.contains(replacement.as_str()) {
                return Err(format!(
                    "model_aliases[{index}] ({name:?}): replacement {:?} is not a configured \
                     alias",
                    replacement.as_str()
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alias(alias: &str, model_id: &str) -> ModelAlias {
        ModelAlias {
            alias: alias.into(),
            provider: None,
            model_id: model_id.into(),
            deprecated: false,
            replacement: None,
        }
    }

    fn pinned_alias(alias: &str, provider: &str, model_id: &str) -> ModelAlias {
        ModelAlias {
            provider: Some(provider.into()),
            ..make_alias(alias, model_id)
        }
    }

    fn provider(name: &str, models: &[&str]) -> ProviderConfig {
        let json = serde_json::json!({
            "name": name,
            "api_key": "test-key",
            "models": models,
        });
        serde_json::from_value(json).expect("provider fixture")
    }

    #[test]
    fn resolve_returns_the_upstream_model_and_pin() {
        let registry =
            ModelAliasRegistry::from_config(vec![pinned_alias("fast", "openai", "gpt-4o-mini")]);

        let resolved = registry.resolve("fast").expect("alias resolves");
        assert_eq!(resolved.model_id, "gpt-4o-mini");
        assert_eq!(
            resolved.provider.as_ref().map(ProviderName::as_str),
            Some("openai")
        );
    }

    #[test]
    fn unknown_name_is_not_an_alias() {
        let registry = ModelAliasRegistry::from_config(vec![make_alias("fast", "gpt-4o-mini")]);
        assert!(registry.resolve("gpt-4o").is_none());
    }

    #[test]
    fn empty_registry_reports_itself_empty() {
        let empty = ModelAliasRegistry::from_config(Vec::new());
        let populated = ModelAliasRegistry::from_config(vec![make_alias("fast", "gpt-4o-mini")]);
        assert!(empty.is_empty());
        assert!(!populated.is_empty());
    }

    #[test]
    fn deprecated_alias_still_resolves_with_its_replacement() {
        let registry = ModelAliasRegistry::from_config(vec![
            make_alias("smart", "gpt-4o"),
            ModelAlias {
                deprecated: true,
                replacement: Some("smart".into()),
                ..make_alias("legacy", "gpt-4")
            },
        ]);

        let resolved = registry.resolve("legacy").expect("alias resolves");
        assert!(resolved.deprecated);
        assert_eq!(resolved.model_id, "gpt-4");
        assert_eq!(
            resolved.replacement.as_ref().map(ModelId::as_str),
            Some("smart")
        );
    }

    #[test]
    fn a_plain_alias_list_validates() {
        let providers = vec![
            provider("openai", &["gpt-4o-mini", "gpt-4o"]),
            provider("anthropic", &["claude-sonnet-4-20250514"]),
        ];
        let aliases = vec![
            pinned_alias("fast", "openai", "gpt-4o-mini"),
            pinned_alias("smart", "anthropic", "claude-sonnet-4-20250514"),
        ];
        assert_eq!(validate_model_aliases(&aliases, &providers), Ok(()));
    }

    #[test]
    fn an_alias_that_shadows_a_served_model_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini", "gpt-4o"])];
        let aliases = vec![make_alias("gpt-4o", "gpt-4o-mini")];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("shadowing a served model is rejected");
        assert!(
            error.contains("shadows a model provider") && error.contains("gpt-4o"),
            "{error}"
        );
    }

    #[test]
    fn an_alias_that_shadows_a_model_map_key_is_rejected() {
        let mut openai = provider("openai", &["gpt-4o-mini"]);
        openai
            .model_map
            .insert("cheap".into(), "gpt-4o-mini".into());
        let aliases = vec![make_alias("cheap", "gpt-4o")];

        let error = validate_model_aliases(&aliases, &[openai])
            .expect_err("shadowing a model_map key is rejected");
        assert!(error.contains("shadows a model_map entry"), "{error}");
    }

    #[test]
    fn an_alias_that_shadows_a_default_model_is_rejected() {
        let mut openai = provider("openai", &[]);
        openai.default_model = Some("gpt-4o".into());
        let aliases = vec![make_alias("gpt-4o", "gpt-4o-mini")];

        let error = validate_model_aliases(&aliases, &[openai])
            .expect_err("shadowing a default_model is rejected");
        assert!(error.contains("default_model"), "{error}");
    }

    #[test]
    fn a_duplicate_alias_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini", "gpt-4o"])];
        let aliases = vec![
            make_alias("fast", "gpt-4o-mini"),
            make_alias("fast", "gpt-4o"),
        ];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("a duplicate alias is rejected");
        assert!(error.contains("configured more than once"), "{error}");
    }

    #[test]
    fn an_alias_chain_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini"])];
        let aliases = vec![
            make_alias("fast", "cheap"),
            make_alias("cheap", "gpt-4o-mini"),
        ];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("an alias pointing at another alias is rejected");
        assert!(error.contains("resolve in one pass"), "{error}");
    }

    #[test]
    fn a_self_referential_alias_is_rejected() {
        let aliases = vec![make_alias("fast", "fast")];
        let error = validate_model_aliases(&aliases, &[])
            .expect_err("a self-referential alias is rejected");
        assert!(error.contains("resolves to itself"), "{error}");
    }

    #[test]
    fn a_pin_at_an_unconfigured_provider_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini"])];
        let aliases = vec![pinned_alias("fast", "openai-typo", "gpt-4o-mini")];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("a pin at an unconfigured provider is rejected");
        assert!(
            error.contains("is not configured on this origin"),
            "{error}"
        );
    }

    #[test]
    fn a_pin_at_a_provider_that_does_not_serve_the_model_is_rejected() {
        let providers = vec![
            provider("openai", &["gpt-4o-mini"]),
            provider("anthropic", &["claude-sonnet-4-20250514"]),
        ];
        let aliases = vec![pinned_alias("fast", "anthropic", "gpt-4o-mini")];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("a pin at a provider that does not serve the model is rejected");
        assert!(error.contains("does not serve"), "{error}");
    }

    #[test]
    fn a_pin_at_a_provider_with_no_declared_models_is_accepted() {
        let providers = vec![provider("openai", &[])];
        let aliases = vec![pinned_alias("fast", "openai", "gpt-4o-mini")];
        assert_eq!(validate_model_aliases(&aliases, &providers), Ok(()));
    }

    #[test]
    fn a_replacement_without_deprecated_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini", "gpt-4o"])];
        let aliases = vec![
            make_alias("smart", "gpt-4o"),
            ModelAlias {
                replacement: Some("smart".into()),
                ..make_alias("legacy", "gpt-4o-mini")
            },
        ];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("an inert replacement is rejected");
        assert!(
            error.contains("only logged for a deprecated alias"),
            "{error}"
        );
    }

    #[test]
    fn a_replacement_naming_an_unknown_alias_is_rejected() {
        let providers = vec![provider("openai", &["gpt-4o-mini"])];
        let aliases = vec![ModelAlias {
            deprecated: true,
            replacement: Some("nonexistent".into()),
            ..make_alias("legacy", "gpt-4o-mini")
        }];

        let error = validate_model_aliases(&aliases, &providers)
            .expect_err("a replacement naming an unknown alias is rejected");
        assert!(error.contains("is not a configured alias"), "{error}");
    }

    #[test]
    fn an_unknown_field_is_rejected_at_parse() {
        let error = serde_json::from_value::<ModelAlias>(serde_json::json!({
            "alias": "fast",
            "model": "gpt-4o-mini",
        }))
        .expect_err("a misspelled model_id is rejected");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}
