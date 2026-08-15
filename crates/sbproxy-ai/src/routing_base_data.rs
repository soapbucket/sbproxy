//! Reloadable base data for the operator-authored routing policy (WOR-2366).
//!
//! A routing policy consults facts that change without the policy changing:
//! what a model costs and how much context it can hold. Those facts already
//! live in this crate, the operator price table plus the built-in price
//! catalog (`budget.rs`), and the static context-window table
//! (`context_window.rs`), but none of them were readable from a policy. This
//! module projects them into one CEL document, bound as `ai.catalog`:
//!
//! ```text
//! ai.catalog["gpt-4o-mini"].input_per_million   // USD per million prompt tokens
//! ai.catalog["gpt-4o-mini"].output_per_million  // USD per million completion tokens
//! ai.catalog["gpt-4o-mini"].context_window      // tokens
//! ```
//!
//! Prices are USD per million tokens, the same unit the operator already
//! writes in `model_prices` (`input_per_million: 3.0`), so a policy compares
//! against numbers the operator recognizes.
//!
//! ## Shape and lifetime
//!
//! The catalog's key set is the union of the models the origin's providers
//! declare (`models: [...]`), the only models a plan can route to, so the
//! document is bounded by config. A model with neither a known price nor a
//! known context window is omitted entirely; a policy guards with
//! `ai.model in ai.catalog`. Within an entry, only known facts appear, so
//! `has()` distinguishes "unpriced but windowed" from absent.
//!
//! The document is built once per config generation (a lazy `OnceLock` on
//! the handler config, like the router) and converted to a
//! [`CelValue::Shared`], so each request binds it by reference-count bump
//! rather than deep copy. Reload swaps in a new handler config, whose
//! catalog rebuilds against the then-current price table; `set_price_table`
//! runs inside `from_config`, before any request can trigger the build.

use std::collections::{BTreeSet, HashMap};

use sbproxy_extension::cel::CelValue;

use crate::provider::ProviderConfig;

/// Build the `ai.catalog` document for one origin's provider set, already
/// converted to the shared form so every per-request bind is a
/// reference-count bump.
pub fn build_catalog_cel(providers: &[ProviderConfig]) -> CelValue {
    CelValue::Map(catalog_entries(providers)).into_shared()
}

/// The owned entries behind [`build_catalog_cel`], separated so tests can
/// inspect content without reaching into the converted form.
fn catalog_entries(providers: &[ProviderConfig]) -> HashMap<String, CelValue> {
    // BTreeSet: dedupe across providers and keep iteration deterministic.
    let models: BTreeSet<&str> = providers
        .iter()
        .flat_map(|p| p.models.iter().map(|m| m.as_str()))
        .collect();

    let mut entries = HashMap::new();
    for model in models {
        let mut entry = HashMap::new();
        if let Some(price) = crate::budget::catalog_price(model) {
            entry.insert(
                "input_per_million".to_string(),
                CelValue::Float(price.input_per_million),
            );
            entry.insert(
                "output_per_million".to_string(),
                CelValue::Float(price.output_per_million),
            );
        }
        if let Some(window) = crate::context_window::model_context_window(model) {
            entry.insert(
                "context_window".to_string(),
                CelValue::Int(i64::try_from(window).unwrap_or(i64::MAX)),
            );
        }
        // A model this process knows nothing about would be an entry of
        // absent fields; omit it so `ai.model in ai.catalog` is the guard.
        if !entry.is_empty() {
            entries.insert(model.to_string(), CelValue::Map(entry));
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{set_price_table, ModelPrice, PriceSource, PriceTable};

    fn provider_with_models(models: &[&str]) -> ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": "base-data-test-provider",
            "models": models,
        }))
        .expect("a name + models provider config must deserialize")
    }

    #[test]
    fn catalog_carries_prices_and_windows_and_omits_the_unknown() {
        let mut table = PriceTable::new();
        table.insert(
            "base-data-test-model",
            ModelPrice::tokens(3.0, 15.0),
            PriceSource::Config,
        );
        set_price_table(table);

        let providers = [
            provider_with_models(&["base-data-test-model", "base-data-unknown-model"]),
            // Duplicate declaration across providers must not duplicate entries.
            provider_with_models(&["base-data-test-model", "gpt-4o"]),
        ];
        let entries = catalog_entries(&providers);

        // Priced via the operator table.
        let CelValue::Map(priced) = &entries["base-data-test-model"] else {
            panic!("entry must be a map");
        };
        assert!(matches!(
            priced["input_per_million"],
            CelValue::Float(v) if v == 3.0
        ));
        assert!(matches!(
            priced["output_per_million"],
            CelValue::Float(v) if v == 15.0
        ));

        // A real model gets its context window from the static table.
        let CelValue::Map(windowed) = &entries["gpt-4o"] else {
            panic!("entry must be a map");
        };
        assert!(matches!(windowed["context_window"], CelValue::Int(w) if w > 0));

        // No price, no window: not in the catalog at all.
        assert!(!entries.contains_key("base-data-unknown-model"));
    }

    #[test]
    fn the_built_catalog_is_shared() {
        let providers = [provider_with_models(&["gpt-4o"])];
        assert!(
            matches!(build_catalog_cel(&providers), CelValue::Shared(_)),
            "the catalog must bind by refcount bump, not deep copy"
        );
    }
}
