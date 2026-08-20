use sbproxy_config::{BundleHookKind, BundleRuntime};
use sbproxy_plugin::{PluginError, PluginResult};
use serde::Serialize;
use serde_json::Value;

use super::envelope_wasm::{prepare_wasm_program, EnvelopeWasmProgram};
use super::javascript::{prepare_program, JavascriptProgram};
use super::{BundleLoadError, LoadedBundleHook};

#[derive(Clone)]
pub(super) enum EnvelopeEventProgram {
    Javascript(JavascriptProgram),
    Wasm(EnvelopeWasmProgram),
}

impl std::fmt::Debug for EnvelopeEventProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Javascript(program) => {
                formatter.debug_tuple("Javascript").field(program).finish()
            }
            Self::Wasm(program) => formatter.debug_tuple("Wasm").field(program).finish(),
        }
    }
}

impl EnvelopeEventProgram {
    pub(super) fn prepare(
        hook: &LoadedBundleHook,
        expected_kind: BundleHookKind,
        config: Value,
    ) -> Result<Self, BundleLoadError> {
        match hook.manifest().runtime {
            BundleRuntime::Javascript => {
                let (_, program) = prepare_program(hook, expected_kind, config)?;
                Ok(Self::Javascript(program))
            }
            BundleRuntime::Wasm => {
                let (_, program) = prepare_wasm_program(hook, expected_kind, config)?;
                Ok(Self::Wasm(program))
            }
            BundleRuntime::ProxyWasm => Err(BundleLoadError::new(
                "event",
                "Proxy-Wasm event hooks use the streaming HTTP callback adapter",
            )),
            // WOR-2482: a Rego bundle hook is `kind: policy` or
            // `kind: transform` only (anything else is refused earlier
            // at manifest validation), so this arm is a defensive
            // backstop rather than a reachable path.
            BundleRuntime::Rego => Err(BundleLoadError::new(
                "event",
                "runtime rego does not support envelope event hooks",
            )),
        }
    }

    pub(super) async fn invoke<T: Serialize>(
        &self,
        payload_name: &str,
        payload: &T,
    ) -> PluginResult<Vec<u8>> {
        let value = serde_json::to_value(payload).map_err(|_| {
            PluginError::Internal(anyhow::anyhow!("bundle event payload could not be encoded"))
        })?;
        match self {
            Self::Javascript(program) => program.invoke(payload_name, value).await,
            Self::Wasm(program) => program.invoke(payload_name, value).await,
        }
    }
}
