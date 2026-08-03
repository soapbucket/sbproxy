use std::sync::Arc;

use sbproxy_config::{BundleHookKind, EnforcementMode, FailureMode};
use sbproxy_plugin::{PaymentExtensionDecision, PaymentExtensionEvent, PluginError, PluginResult};

use super::envelope::decode_payment_decision;
use super::events::EnvelopeEventProgram;
use super::{BundleLoadError, BundleRegistry};

#[derive(Clone)]
struct PreparedPaymentHook {
    id: String,
    enforcement_mode: EnforcementMode,
    failure_posture: FailureMode,
    program: EnvelopeEventProgram,
}

/// Immutable payment hook chain pinned to one compiled pipeline generation.
pub struct PaymentExtensionChain {
    hooks: Arc<[PreparedPaymentHook]>,
}

impl std::fmt::Debug for PaymentExtensionChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentExtensionChain")
            .field("hooks", &self.hooks.len())
            .finish()
    }
}

impl PaymentExtensionChain {
    /// Prepare every JavaScript or envelope WASM payment hook in stable order.
    ///
    /// # Errors
    ///
    /// Returns a load error when one hook cannot be prepared.
    pub fn from_registry(registry: &dyn BundleRegistry) -> Result<Self, BundleLoadError> {
        let hooks = registry
            .payment_hooks()
            .into_iter()
            .map(|hook| {
                Ok(PreparedPaymentHook {
                    id: format!("{}:{}", hook.manifest().name, hook.hook().type_name),
                    enforcement_mode: hook.hook().enforcement_mode,
                    failure_posture: hook.manifest().failure_posture,
                    program: EnvelopeEventProgram::prepare(
                        hook,
                        BundleHookKind::Payment,
                        serde_json::json!({}),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, BundleLoadError>>()?;
        Ok(Self {
            hooks: Arc::from(hooks),
        })
    }

    /// True when no payment hooks were prepared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Await block-mode hooks for a payment `started` event.
    ///
    /// # Errors
    ///
    /// Returns the first closed-posture runtime or decision-envelope failure.
    pub async fn enforce_started(
        &self,
        event: &PaymentExtensionEvent,
    ) -> PluginResult<PaymentExtensionDecision> {
        for hook in self
            .hooks
            .iter()
            .filter(|hook| hook.enforcement_mode == EnforcementMode::Block)
        {
            match invoke(hook, event).await {
                Ok(PaymentExtensionDecision::Reject) => {
                    return Ok(PaymentExtensionDecision::Reject);
                }
                Ok(PaymentExtensionDecision::Continue) => {}
                Err(error) if hook.failure_posture.admits() => {
                    tracing::warn!(
                        hook = %hook.id,
                        posture = hook.failure_posture.as_label(),
                        error = %error,
                        "payment extension hook failed under an admitting posture"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(PaymentExtensionDecision::Continue)
    }

    /// Deliver a started event to observe-mode hooks.
    pub async fn observe_started(&self, event: &PaymentExtensionEvent) {
        self.observe_matching(event, false).await;
    }

    /// Deliver a terminal event to every hook without applying a decision.
    pub async fn observe_terminal(&self, event: &PaymentExtensionEvent) {
        self.observe_matching(event, true).await;
    }

    async fn observe_matching(&self, event: &PaymentExtensionEvent, terminal: bool) {
        for hook in self
            .hooks
            .iter()
            .filter(|hook| terminal || hook.enforcement_mode == EnforcementMode::Observe)
        {
            if let Err(error) = invoke(hook, event).await {
                tracing::warn!(hook = %hook.id, error = %error, "payment observation hook failed");
            }
        }
    }
}

async fn invoke(
    hook: &PreparedPaymentHook,
    event: &PaymentExtensionEvent,
) -> PluginResult<PaymentExtensionDecision> {
    let output = hook.program.invoke("event", event).await?;
    decode_payment_decision(&output).map_err(|error| {
        PluginError::Internal(anyhow::anyhow!(
            "payment bundle hook returned {}",
            error.code()
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_plugin::{PaymentExtensionOutcome, PaymentExtensionPhase};
    use tempfile::TempDir;

    use super::*;
    use crate::bundle::DynamicBundleRegistry;

    fn event() -> PaymentExtensionEvent {
        PaymentExtensionEvent::builder(
            PaymentExtensionPhase::Settle,
            PaymentExtensionOutcome::Started,
            "x402",
            1_000_000,
            "USD",
        )
        .intent_id("intent-fixture")
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn javascript_payment_rejection_is_awaited() {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: payment-block\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: payment\n    type: payment_block\n    export: inspect\n    execution:\n      body_mode: none\n",
        )
        .unwrap();
        std::fs::write(
            bundle.join("entry.js"),
            br#"export function inspect(input) { if (input.event.rail !== "x402") throw new Error("wrong event"); return {version:"sbproxy-envelope/v1",decision:"reject"}; }"#,
        )
        .unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        let chain = PaymentExtensionChain::from_registry(registry.as_ref()).unwrap();
        assert_eq!(
            chain.enforce_started(&event()).await.unwrap(),
            PaymentExtensionDecision::Reject
        );
    }

    #[tokio::test]
    async fn envelope_wasm_payment_rejection_is_awaited() {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: payment-wasm\nversion: 1.0.0\nruntime: wasm\nabi: sbproxy-envelope/v1\nentry: entry.wasm\nhooks:\n  - kind: payment\n    type: payment_block\n    execution:\n      body_mode: none\n",
        )
        .unwrap();
        std::fs::write(
            bundle.join("entry.wasm"),
            include_bytes!("testdata/wasm/payment-event-reject.wasm"),
        )
        .unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        let chain = PaymentExtensionChain::from_registry(registry.as_ref()).unwrap();

        assert_eq!(
            chain.enforce_started(&event()).await.unwrap(),
            PaymentExtensionDecision::Reject
        );
    }
}
