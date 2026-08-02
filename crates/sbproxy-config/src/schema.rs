// SPDX-License-Identifier: Apache-2.0
//! The config file's JSON Schema, generated from the types the binary
//! parses with.
//!
//! One generator, three consumers: the `generate-schema` binary that
//! writes the committed copy, the freshness gate in
//! `scripts/check-config-schema.sh` that diffs it, and the admin API route
//! that serves it to an editor. They all call
//! [`config_json_schema`], so the document an editor validates against is
//! the running binary's own view of its configuration rather than a file
//! that happened to be committed alongside it.
//!
//! That distinction is the point. A schema read off disk at request time
//! can be older or newer than the binary serving it, and a form built from
//! a stale schema is wrong in the most expensive way: it offers fields the
//! proxy will reject and hides fields it would accept. Generating from
//! [`crate::ConfigFile`] makes that failure mode unreachable, and the
//! committed file stays useful as an editor-integration artifact that CI
//! proves is current.

use std::sync::OnceLock;

/// Path of the committed copy, relative to the repository root.
///
/// Named here so the freshness test and any tooling that wants to point an
/// operator at the file agree on where it is.
pub const CONFIG_SCHEMA_FILE: &str = "schemas/sb-config.schema.json";

/// The config file's JSON Schema as pretty-printed JSON, without a
/// trailing newline.
///
/// Generated once per process and cached, because the document is around
/// 300KB and the generation walks every type in the config tree. Callers
/// serving it over HTTP get a `&'static str` they can hand straight to a
/// response body with no per-request cost.
///
/// The committed copy at [`CONFIG_SCHEMA_FILE`] is this string plus the
/// trailing newline `println!` adds. `schema_is_committed_verbatim` in
/// this module pins that relationship.
#[must_use]
pub fn config_json_schema() -> &'static str {
    static SCHEMA: OnceLock<String> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let schema = schemars::schema_for!(crate::ConfigFile);
        serde_json::to_string_pretty(&schema).expect("the config schema serializes to JSON")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated schema and the committed file must match byte for
    /// byte, because `scripts/check-config-schema.sh` diffs them in CI and
    /// a mismatch fails a required lane.
    ///
    /// This test exists so that failure arrives during `cargo test`
    /// instead of twenty minutes later in CI. The local gate does not run
    /// the schema script, so before this test a rustdoc edit on any
    /// config type could pass every local check and still fail the merge.
    #[test]
    fn schema_is_committed_verbatim() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(CONFIG_SCHEMA_FILE);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let generated = config_json_schema();
        assert_eq!(
            committed.trim_end_matches('\n'),
            generated,
            "{CONFIG_SCHEMA_FILE} is stale. Regenerate it with \
             scripts/check-config-schema.sh or:\n  cargo run -p sbproxy-config \
             --bin generate-schema > {CONFIG_SCHEMA_FILE}"
        );
        assert!(
            committed.ends_with('\n'),
            "the committed schema should end with exactly the newline println! adds"
        );
    }

    #[test]
    fn schema_is_cached_across_calls() {
        assert!(
            std::ptr::eq(config_json_schema(), config_json_schema()),
            "generation is expensive enough that a second call must not repeat it"
        );
    }

    #[test]
    fn schema_describes_the_config_file_root() {
        let value: serde_json::Value =
            serde_json::from_str(config_json_schema()).expect("valid JSON");
        assert_eq!(value["title"], "ConfigFile");
        assert!(
            value["properties"].get("proxy").is_some(),
            "the root should expose the proxy block"
        );
    }
}
