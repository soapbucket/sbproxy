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
//! declare (`models: [...]`), so the document is bounded by config. A
//! provider that omits `models` defers to the provider catalog and declares
//! nothing here; an origin whose providers all defer gets an empty catalog
//! (and a load-time warning, since a policy reading it can never match).
//! Keys are the declared strings verbatim, so declare models in the casing
//! callers request them with. A model with neither a known price nor a
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
///
/// This is only called from the policy-gated view sites, so the warning
/// below fires exactly when a configured policy is about to read an empty
/// catalog, once per config generation (the caller caches the result).
pub fn build_catalog_cel(providers: &[ProviderConfig]) -> CelValue {
    let entries = catalog_entries(providers);
    if entries.is_empty() && providers.iter().all(|p| p.models.is_empty()) {
        // A provider with no `models:` defers to the provider catalog and is
        // perfectly serviceable, but it declares nothing for this document,
        // so a policy guarding with `ai.model in ai.catalog` will decline on
        // every request and nothing else would say why.
        tracing::warn!(
            "ai.catalog is empty because no provider declares `models`; a policy \
             reading it will never match. Declare `models` on the providers to \
             populate the catalog."
        );
    }
    CelValue::Map(entries).into_shared()
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
        // The price layers match case-insensitively but the window table is
        // exact; fall back to the lowercase form so a mixed-case declared
        // model does not end up priced-but-windowless.
        let window = crate::context_window::model_context_window(model)
            .or_else(|| crate::context_window::model_context_window(&model.to_lowercase()));
        if let Some(window) = window {
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

    fn provider_with_models(models: &[&str]) -> ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": "base-data-test-provider",
            "models": models,
        }))
        .expect("a name + models provider config must deserialize")
    }

    #[test]
    fn catalog_carries_prices_and_windows_and_omits_the_unknown() {
        // `gpt-4o` is priced by the built-in catalog and windowed by the
        // static context table; the operator-price layer over the same
        // resolution is proven by the e2e (`model_prices` -> plan).
        let providers = [
            provider_with_models(&["gpt-4o", "base-data-unknown-model"]),
            // Duplicate declaration across providers must not duplicate entries.
            provider_with_models(&["gpt-4o"]),
        ];
        let entries = catalog_entries(&providers);
        assert_eq!(entries.len(), 1, "unknown models must be omitted");

        let CelValue::Map(entry) = &entries["gpt-4o"] else {
            panic!("entry must be a map");
        };
        assert!(matches!(
            entry["input_per_million"],
            CelValue::Float(v) if v > 0.0
        ));
        assert!(matches!(
            entry["output_per_million"],
            CelValue::Float(v) if v > 0.0
        ));
        assert!(matches!(entry["context_window"], CelValue::Int(w) if w > 0));

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
