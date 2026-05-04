//! Model aliasing and migration safety.
//!
//! Maps friendly model names to provider-specific model IDs.
//! Supports deprecation warnings for old model names.

use std::collections::HashMap;

use serde::Deserialize;
use tracing::warn;

/// A mapping from a friendly alias to a provider-specific model ID.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelAlias {
    /// The friendly alias (e.g. `"gpt4"`, `"claude-fast"`).
    pub alias: String,
    /// The provider this alias targets (e.g. `"openai"`, `"anthropic"`).
    pub provider: String,
    /// The actual model ID sent to the provider (e.g. `"gpt-4o"`).
    pub model_id: String,
    /// When true, a deprecation warning is logged on resolution.
    #[serde(default)]
    pub deprecated: bool,
    /// Suggested replacement alias if this one is deprecated.
    pub replacement: Option<String>,
}

/// Registry of model aliases. Thread-safe via immutable access after construction.
pub struct ModelAliasRegistry {
    aliases: HashMap<String, ModelAlias>,
}

impl ModelAliasRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
        }
    }

    /// Register an alias, overwriting any existing entry with the same alias name.
    pub fn register(&mut self, alias: ModelAlias) {
        self.aliases.insert(alias.alias.clone(), alias);
    }

    /// Resolve an alias to its [`ModelAlias`] entry.
    ///
    /// Returns `None` if the name is not a registered alias (treat as a literal model ID).
    /// Logs a deprecation warning if the alias is marked deprecated.
    pub fn resolve(&self, name: &str) -> Option<&ModelAlias> {
        let alias = self.aliases.get(name)?;
        if alias.deprecated {
            match &alias.replacement {
                Some(replacement) => warn!(
                    alias = name,
                    replacement = replacement.as_str(),
                    "Model alias '{}' is deprecated. Use '{}' instead.",
                    name,
                    replacement
                ),
                None => warn!(
                    alias = name,
                    "Model alias '{}' is deprecated and has no replacement.", name
                ),
            }
        }
        Some(alias)
    }

    /// Load a registry from a list of alias configs.
    pub fn from_config(aliases: Vec<ModelAlias>) -> Self {
        let mut registry = Self::new();
        for alias in aliases {
            registry.register(alias);
        }
        registry
    }

    /// List all registered aliases (order is not guaranteed).
    pub fn list(&self) -> Vec<&ModelAlias> {
        self.aliases.values().collect()
    }
}

impl Default for ModelAliasRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alias(alias: &str, provider: &str, model_id: &str) -> ModelAlias {
        ModelAlias {
            alias: alias.to_string(),
            provider: provider.to_string(),
            model_id: model_id.to_string(),
            deprecated: false,
            replacement: None,
        }
    }

    fn make_deprecated(
        alias: &str,
        provider: &str,
        model_id: &str,
        replacement: &str,
    ) -> ModelAlias {
        ModelAlias {
            alias: alias.to_string(),
            provider: provider.to_string(),
            model_id: model_id.to_string(),
            deprecated: true,
            replacement: Some(replacement.to_string()),
        }
    }

    #[test]
    fn register_and_resolve_alias() {
        let mut registry = ModelAliasRegistry::new();
        registry.register(make_alias("gpt4", "openai", "gpt-4o"));

        let resolved = registry.resolve("gpt4").unwrap();
        assert_eq!(resolved.provider, "openai");
        assert_eq!(resolved.model_id, "gpt-4o");
    }

    #[test]
    fn unknown_alias_returns_none() {
        let registry = ModelAliasRegistry::new();
        assert!(registry.resolve("nonexistent-alias").is_none());
    }

    #[test]
    fn deprecated_alias_resolves_but_returns_entry() {
        let mut registry = ModelAliasRegistry::new();
        registry.register(make_deprecated(
            "claude-old",
            "anthropic",
            "claude-2",
            "claude-fast",
        ));

        let resolved = registry.resolve("claude-old").unwrap();
        assert!(resolved.deprecated);
        assert_eq!(resolved.replacement.as_deref(), Some("claude-fast"));
        assert_eq!(resolved.model_id, "claude-2");
    }

    #[test]
    fn deprecated_alias_without_replacement_resolves() {
        let mut registry = ModelAliasRegistry::new();
        registry.register(ModelAlias {
            alias: "old-model".to_string(),
            provider: "openai".to_string(),
            model_id: "gpt-3.5-turbo-0301".to_string(),
            deprecated: true,
            replacement: None,
        });

        let resolved = registry.resolve("old-model").unwrap();
        assert!(resolved.deprecated);
        assert!(resolved.replacement.is_none());
    }

    #[test]
    fn from_config_loads_all_aliases() {
        let aliases = vec![
            make_alias("fast", "openai", "gpt-4o-mini"),
            make_alias("smart", "anthropic", "claude-opus-4"),
            make_alias("embed", "openai", "text-embedding-3-small"),
        ];
        let registry = ModelAliasRegistry::from_config(aliases);

        assert!(registry.resolve("fast").is_some());
        assert!(registry.resolve("smart").is_some());
        assert!(registry.resolve("embed").is_some());
        assert!(registry.resolve("unknown").is_none());
    }

    #[test]
    fn list_returns_all_aliases() {
        let mut registry = ModelAliasRegistry::new();
        registry.register(make_alias("a", "openai", "gpt-4o"));
        registry.register(make_alias("b", "anthropic", "claude-sonnet-4-5"));
        registry.register(make_alias("c", "gemini", "gemini-2.0-flash"));

        let listed = registry.list();
        assert_eq!(listed.len(), 3);

        let aliases: Vec<&str> = listed.iter().map(|a| a.alias.as_str()).collect();
        assert!(aliases.contains(&"a"));
        assert!(aliases.contains(&"b"));
        assert!(aliases.contains(&"c"));
    }

    #[test]
    fn register_overwrites_existing_alias() {
        let mut registry = ModelAliasRegistry::new();
        registry.register(make_alias("fast", "openai", "gpt-3.5-turbo"));
        registry.register(make_alias("fast", "openai", "gpt-4o-mini"));

        let resolved = registry.resolve("fast").unwrap();
        assert_eq!(resolved.model_id, "gpt-4o-mini");
    }

    #[test]
    fn list_empty_registry() {
        let registry = ModelAliasRegistry::new();
        assert!(registry.list().is_empty());
    }

    #[test]
    fn from_config_preserves_deprecated_flag() {
        let aliases = vec![make_deprecated("legacy", "openai", "gpt-4", "gpt4")];
        let registry = ModelAliasRegistry::from_config(aliases);

        let resolved = registry.resolve("legacy").unwrap();
        assert!(resolved.deprecated);
        assert_eq!(resolved.replacement.as_deref(), Some("gpt4"));
    }
}
