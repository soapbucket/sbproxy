// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Which top-level `proxy:` config keys are inert, and how boot says so.
//!
//! `proxy.alerting` accepted a PagerDuty routing key, validated it, and had no
//! consumer anywhere in the boot path. An operator who configured it believed
//! they were paged, and nothing disagreed. That is the config-key instance of
//! the pattern the capability registry exists to close: a surface that parses
//! input and does nothing while presenting as complete.
//!
//! Only inert keys are listed here. A stable key is the default and needs no
//! entry; the coverage test asserts that every key named here is genuinely a
//! real config key (so a rename cannot leave a stale classification), and the
//! boot path warns for each one an operator has actually set.

use sbproxy_capability::{ConfigKeyCapability, SupportLevel};

/// The top-level `proxy:` keys that parse but do not yet do what they imply.
///
/// Kept deliberately short. An entry is a promise that the key is inert *and*
/// that boot warns when it is set; the moment a key's consumer lands, its entry
/// is deleted and the warning stops.
pub const INERT_CONFIG_KEYS: &[ConfigKeyCapability] = &[
    ConfigKeyCapability {
        path: "proxy.alerting",
        support: SupportLevel::ConfigOnly,
        consumer: None,
        note: Some(
            "Channels parse and validate, but no dispatcher is wired at boot, so no \
             alert is delivered. WOR-1884 wires the dispatcher.",
        ),
    },
    ConfigKeyCapability {
        path: "proxy.http3",
        support: SupportLevel::ConfigOnly,
        consumer: None,
        note: Some(
            "Parsed and ignored: HTTP/3 is disabled until native QUIC support lands \
             in the proxy engine. Enabling it starts no listener.",
        ),
    },
];

/// Every top-level `proxy:` key the schema actually declares.
///
/// Reflected from the `ProxyServerConfig` JSON schema rather than hand-listed,
/// so it cannot drift from the struct. This is the set the coverage check
/// validates the registry against.
pub fn declared_top_level_keys() -> Vec<String> {
    let schema = schemars::schema_for!(crate::types::ProxyServerConfig);
    let mut out = Vec::new();
    if let Some(object) = schema.schema.object {
        for property in object.properties.keys() {
            out.push(format!("proxy.{property}"));
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_capability::validate_config_key_coverage;

    #[test]
    fn the_inert_key_registry_is_consistent_with_the_schema() {
        let declared = declared_top_level_keys();
        let declared_refs: Vec<&str> = declared.iter().map(String::as_str).collect();

        let errors = validate_config_key_coverage(INERT_CONFIG_KEYS, &declared_refs);

        assert!(
            errors.is_empty(),
            "config-key registry is inconsistent:\n{}",
            errors
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn every_inert_key_names_the_ticket_that_activates_it() {
        for key in INERT_CONFIG_KEYS {
            let note = key.note.unwrap_or("");
            assert!(
                note.contains("WOR-") || note.contains("engine"),
                "inert key {} must explain itself and point at the work that fixes \
                 it: '{note}'",
                key.path
            );
        }
    }

    #[test]
    fn alerting_is_a_real_key_and_is_classified_inert() {
        // Guards the exact regression: proxy.alerting must be both a real
        // schema key and listed here as inert, so the boot warning fires. If
        // WOR-1884 wires it, this test is what reminds you to delete the entry.
        assert!(declared_top_level_keys().contains(&"proxy.alerting".to_string()));
        assert!(INERT_CONFIG_KEYS.iter().any(|k| k.path == "proxy.alerting"));
    }
}
