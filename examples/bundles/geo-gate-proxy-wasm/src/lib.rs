//! geo-gate-proxy-wasm: the same "deny requests from denylisted
//! countries" policy as ../geo-gate-wasm/, implemented against the real
//! proxy-wasm host ABI (the standard Envoy/Kong WasmX/Apache APISIX
//! share) instead of sbproxy's own envelope-routed bare-WASI
//! convention.
//!
//! Status: design preview. sbproxy does not implement the proxy-wasm
//! host ABI yet (that's real new infrastructure — see the design doc's
//! §3 "WASM hook dispatch and ABI"), so this module can't run against
//! sbproxy today. It genuinely compiles against the real `proxy-wasm`
//! SDK crate and has been built to a real `.wasm` binary targeting
//! `wasm32-unknown-unknown` (not `wasm32-wasi` — proxy-wasm modules use
//! no WASI, no stdio; all I/O goes through host-imported functions the
//! ABI defines). See examples/bundles/README.md and
//! https://github.com/soapbucket/sbproxy/issues/890 /
//! https://github.com/soapbucket/sbproxy/issues/893.
//!
//! Design doc: https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054
//!
//! Config comes through proxy-wasm's own configuration mechanism
//! (`on_configure`/`get_plugin_configuration`, populated by the host
//! from whatever config block the proxy's own config format attaches to
//! this filter) rather than sbproxy's `config_schema`/envelope
//! convention — this is deliberate: a proxy-wasm module is meant to be
//! portable across hosts that each have their own config-attachment
//! story, so it can't assume sbproxy's `bundle.yaml` shape exists.
//!
//! Build:
//!     ./build.sh              # Docker, no local toolchain needed
//!     LOCAL=1 ./build.sh      # host toolchain (rustup target add wasm32-unknown-unknown)
//!
//! Output: target/wasm32-unknown-unknown/release/geo_gate_proxy_wasm.wasm

use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};
use serde::Deserialize;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(GeoGateRoot::default()) });
}}

#[derive(Deserialize, Default, Clone)]
struct GeoBlockConfig {
    #[serde(default)]
    denylist: Vec<String>,
    #[serde(default = "default_country_header")]
    country_header: String,
}

fn default_country_header() -> String {
    "x-geo-country".to_string()
}

/// Pure decision logic, pulled out of `HttpContext` so it's unit-testable
/// on a native target — `HttpContext`/`RootContext` methods call into
/// `hostcalls::` externs that only resolve when linked into a real
/// proxy-wasm host, so they can't run under plain `cargo test`.
fn is_denied(country: &str, config: &GeoBlockConfig) -> bool {
    config.denylist.iter().any(|c| c == country)
}

#[derive(Default)]
struct GeoGateRoot {
    config: GeoBlockConfig,
}

impl Context for GeoGateRoot {}

impl RootContext for GeoGateRoot {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        match self.get_plugin_configuration() {
            Some(bytes) => match serde_json::from_slice(&bytes) {
                Ok(config) => {
                    self.config = config;
                    true
                }
                Err(_) => false,
            },
            // No configuration block at all: keep the zero-value default
            // (empty denylist) rather than failing plugin startup.
            None => true,
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(GeoGate {
            config: self.config.clone(),
        }))
    }
}

struct GeoGate {
    config: GeoBlockConfig,
}

impl Context for GeoGate {}

impl HttpContext for GeoGate {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let country = self
            .get_http_request_header(&self.config.country_header)
            .unwrap_or_default();

        if is_denied(&country, &self.config) {
            let message = format!("requests from '{country}' are not permitted");
            self.send_http_response(
                451,
                vec![("content-type", "text/plain")],
                Some(message.as_bytes()),
            );
            return Action::Pause;
        }

        self.add_http_request_header("x-geo-gate-evaluated", &country);
        Action::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(denylist: &[&str]) -> GeoBlockConfig {
        GeoBlockConfig {
            denylist: denylist.iter().map(|s| s.to_string()).collect(),
            country_header: default_country_header(),
        }
    }

    #[test]
    fn denies_listed_country() {
        assert!(is_denied("KP", &config(&["KP", "IR"])));
    }

    #[test]
    fn allows_unlisted_country() {
        assert!(!is_denied("US", &config(&["KP", "IR"])));
    }

    #[test]
    fn config_parses_from_plugin_configuration_json() {
        let raw = br#"{"denylist":["KP","IR"],"country_header":"x-geo-country"}"#;
        let parsed: GeoBlockConfig = serde_json::from_slice(raw).unwrap();
        assert_eq!(parsed.denylist, vec!["KP", "IR"]);
        assert_eq!(parsed.country_header, "x-geo-country");
    }

    #[test]
    fn config_defaults_country_header_when_omitted() {
        let raw = br#"{"denylist":["KP"]}"#;
        let parsed: GeoBlockConfig = serde_json::from_slice(raw).unwrap();
        assert_eq!(parsed.country_header, "x-geo-country");
    }
}
