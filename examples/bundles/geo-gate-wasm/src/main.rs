//! geo-gate: a proposed sbproxy WASM bundle.
//!
//! Status: design preview, not runnable against sbproxy today — see
//! examples/bundles/README.md and
//! https://github.com/soapbucket/sbproxy/issues/890.
//!
//! Bundles compiled to WASM use sbproxy's envelope-routed dispatch
//! convention on top of the existing bare-WASI ABI (stdin/stdout, one
//! `_start` call per invocation) rather than proxy-wasm — see the
//! design doc's §3 "WASM hook dispatch and ABI" for why:
//! https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054
//!
//! The host writes one JSON envelope to stdin per call:
//!
//!   { "hook": { "kind": "policy" | "transform", "type": "<hook type>" },
//!     "config": <config_schema-validated object from bundle.yaml>,
//!     "request": { "headers": { ... } } }
//!
//! and reads one JSON verdict back from stdout. This module implements
//! both hooks declared in bundle.yaml and routes between them on
//! `hook.type` — the reason this convention exists at all: one `_start`,
//! multiple named hooks, no shared SDK to depend on.
//!
//! Build:
//!     ./build.sh              # Docker, no local toolchain needed
//!     LOCAL=1 ./build.sh      # host toolchain (rustup target add wasm32-wasip1)
//!
//! Output: target/wasm32-wasip1/release/geo_gate.wasm

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Envelope {
    hook: Hook,
    #[serde(default)]
    config: serde_json::Value,
    request: Request,
}

#[derive(Deserialize)]
struct Hook {
    #[serde(rename = "type")]
    hook_type: String,
}

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    headers: HashMap<String, String>,
}

#[derive(Deserialize)]
struct GeoBlockConfig {
    #[serde(default)]
    denylist: Vec<String>,
    #[serde(default = "default_country_header")]
    country_header: String,
}

fn default_country_header() -> String {
    "x-geo-country".to_string()
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyDecision {
    Allow,
    Deny { status: u16, message: String },
}

#[derive(Serialize)]
struct TransformResult {
    headers: Vec<(String, String)>,
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("geo-gate: failed to read envelope from stdin");
    let envelope: Envelope =
        serde_json::from_str(&input).expect("geo-gate: failed to parse envelope JSON");

    let output = match envelope.hook.hook_type.as_str() {
        "geo_block" => {
            serde_json::to_string(&geo_block(&envelope)).expect("geo-gate: serialize verdict")
        }
        "tag_geo_header" => serde_json::to_string(&tag_geo_header(&envelope))
            .expect("geo-gate: serialize transform result"),
        other => {
            panic!("geo-gate: unknown hook type '{other}' — check bundle.yaml's hooks[]");
        }
    };

    io::stdout()
        .write_all(output.as_bytes())
        .expect("geo-gate: failed to write verdict to stdout");
}

fn geo_block(envelope: &Envelope) -> PolicyDecision {
    let config: GeoBlockConfig = serde_json::from_value(envelope.config.clone()).unwrap_or(
        GeoBlockConfig {
            denylist: Vec::new(),
            country_header: default_country_header(),
        },
    );
    let country = envelope
        .request
        .headers
        .get(&config.country_header)
        .map(String::as_str)
        .unwrap_or("");

    if config.denylist.iter().any(|c| c == country) {
        PolicyDecision::Deny {
            status: 451,
            message: format!("requests from '{country}' are not permitted"),
        }
    } else {
        PolicyDecision::Allow
    }
}

fn tag_geo_header(envelope: &Envelope) -> TransformResult {
    let country = envelope
        .request
        .headers
        .get("x-geo-country")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    TransformResult {
        headers: vec![("x-geo-gate-evaluated".to_string(), country)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Loads a fixture from `fixtures/<name>.json`, runs it through the
    /// same dispatch `main()` uses, and asserts the output matches the
    /// fixture's `expect` field. Keeps the fixtures honest: if the
    /// dispatch logic drifts from what the README documents, this fails.
    fn run_fixture(name: &str) -> (serde_json::Value, serde_json::Value) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(format!("{name}.json"));
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        let fixture: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture JSON");

        let envelope: Envelope =
            serde_json::from_value(fixture.clone()).expect("fixture is a valid envelope");
        let actual = match envelope.hook.hook_type.as_str() {
            "geo_block" => serde_json::to_value(geo_block(&envelope)).unwrap(),
            "tag_geo_header" => serde_json::to_value(tag_geo_header(&envelope)).unwrap(),
            other => panic!("fixture {name} has unknown hook type '{other}'"),
        };
        (actual, fixture["expect"].clone())
    }

    #[test]
    fn geo_block_denies_listed_country() {
        let (actual, expect) = run_fixture("geo_block_deny");
        assert_eq!(actual, expect);
    }

    #[test]
    fn geo_block_allows_unlisted_country() {
        let (actual, expect) = run_fixture("geo_block_allow");
        assert_eq!(actual, expect);
    }

    #[test]
    fn tag_geo_header_echoes_country() {
        let (actual, expect) = run_fixture("tag_geo_header");
        assert_eq!(actual, expect);
    }
}
