//! [`PolicyEnforcer`] for a signed extension bundle's `runtime: rego`
//! policy hook (WOR-2482).
//!
//! A bundled Rego module rides the exact same verify-then-activate
//! flow the JavaScript and WASM bundle assets already use (signing,
//! digest verification, candidate load, last-good-on-failure): see
//! `compile_rego_hook` in `bundle::loader` for the load-time compile
//! and `docs/extension-bundles.md`'s citation of [OPA's bundle
//! management](https://www.openpolicyagent.org/docs/management-bundles)
//! as the model for that posture. This module is the request-time
//! half: it wraps the engine `bundle::loader` already compiled and
//! proved evaluable, and answers each request without a worker pool
//! or a WASM instantiation, because Rego performs no I/O during
//! evaluation.
//!
//! # Input contract
//!
//! A bundled Rego policy hook reads the same JSON request envelope a
//! JavaScript or WASM bundle policy hook reads (`request` plus the
//! attachment's resolved `config`), not the `CelContext` vocabulary
//! `policy: rego` shares with `policy: expression`. Bundle hooks see
//! only the wire-level HTTP request; they do not get the internally
//! resolved `RequestContext` (trust tier, principal) a built-in
//! enforcer can reach, and a bundled Rego module keeps that same
//! boundary rather than widening it. A module written for this
//! surface reads `input.request.method`, `input.request.uri`,
//! `input.request.headers`, and `input.config`, matching the table in
//! `docs/extension-bundles.md`'s "JavaScript and load-time
//! TypeScript" section.
//!
//! # Output contract
//!
//! Simpler than the JavaScript/WASM envelope's `allow`/`deny` result:
//! the pinned query must evaluate to a Rego boolean, exactly like
//! `policy: rego`. `true` allows; `false`, an evaluation error, or a
//! non-boolean result all deny with a fixed status and message,
//! matching `policy: rego`'s own defaults and its fail-closed posture.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sbproxy_config::{BundleHookKind, BundleRuntime};
use sbproxy_plugin::{PluginError, PluginResult, PolicyDecision, PolicyEnforcer};
use serde_json::Value;

use super::envelope;
use super::{BundleLoadError, LoadedBundleHook};
use crate::rego::CompiledRego;

/// Status returned when a bundled Rego policy hook's rule evaluates
/// false or fails closed, matching `policy: rego`'s own default.
const DENY_STATUS: u16 = 403;

/// Message returned alongside [`DENY_STATUS`], matching
/// `policy: rego`'s own default.
const DENY_MESSAGE: &str = "forbidden by policy";

/// Map a bounded envelope-construction failure onto a plugin error.
fn envelope_failure(error: envelope::EnvelopeError) -> PluginError {
    PluginError::Internal(anyhow::anyhow!("rego bundle hook failed: {}", error.code()))
}

/// Rego policy adapter backed by the engine `bundle::loader` compiled
/// once at candidate load (WOR-2482).
pub struct RegoPolicyAdapter {
    type_name: String,
    compiled: Arc<Mutex<CompiledRego>>,
    config: Arc<Value>,
    max_input_bytes: usize,
}

impl std::fmt::Debug for RegoPolicyAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegoPolicyAdapter")
            .field("type_name", &self.type_name)
            .finish_non_exhaustive()
    }
}

/// Build a policy adapter from a validated Rego bundle hook.
///
/// # Errors
///
/// Returns a bounded load error for a mismatched hook, invalid
/// attachment config, or a candidate that has no compiled Rego engine
/// for this hook (a loader invariant violation rather than an
/// operator-facing config mistake: manifest validation and
/// `compile_rego_hook` should make this unreachable).
pub fn build_rego_policy(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<RegoPolicyAdapter, BundleLoadError> {
    if hook.manifest().runtime != BundleRuntime::Rego || hook.hook().kind != BundleHookKind::Policy
    {
        return Err(BundleLoadError::new(
            "rego",
            "hook kind does not match the requested Rego policy adapter",
        ));
    }
    let mut config = config;
    if let Some(schema) = hook.hook().config_schema.as_ref() {
        envelope::apply_schema_defaults(&mut config, schema);
    }
    // WOR-2289: resolve secret references in the hook's declared
    // `secret_vars` before any evaluation, matching every other bundle
    // hook adapter.
    envelope::resolve_declared_secrets(&mut config, &hook.hook().secret_vars)
        .map_err(|detail| BundleLoadError::new("config", detail))?;
    hook.validate_config(&config)
        .map_err(|error| BundleLoadError::new("config", error.to_string()))?;
    let compiled = hook.prepared_rego().ok_or_else(|| {
        BundleLoadError::new("rego", "bundle has no compiled Rego engine for this hook")
    })?;
    let max_input_bytes = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .map_err(|_| BundleLoadError::new("rego", "input limit is unsupported"))?;
    Ok(RegoPolicyAdapter {
        type_name: hook.hook().type_name.clone(),
        compiled: Arc::clone(compiled),
        config: Arc::new(config),
        max_input_bytes,
    })
}

impl PolicyEnforcer for RegoPolicyAdapter {
    fn policy_type(&self) -> &str {
        &self.type_name
    }

    fn enforce(
        &self,
        request: &http::Request<Bytes>,
        _context: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
        let request_value = envelope::request_value(request, self.max_input_bytes);
        Box::pin(async move {
            let request_value = request_value.map_err(envelope_failure)?;
            let input = envelope::hook_envelope(
                "request",
                envelope::hook_kind_label(BundleHookKind::Policy),
                &self.type_name,
                self.config.as_ref(),
                request_value,
            );
            let mut compiled = match self.compiled.lock() {
                Ok(guard) => guard,
                // A panic mid-evaluation poisons the lock. Recovering
                // is right, matching `RegoPolicy::evaluate`: the
                // alternative is that one panicking request denies
                // every later one forever.
                Err(poisoned) => poisoned.into_inner(),
            };
            let allowed = match compiled.eval_bool_json(input, "") {
                Ok(allowed) => allowed,
                Err(error) => {
                    tracing::warn!(
                        type_name = %self.type_name,
                        %error,
                        "rego bundle policy failed to evaluate; denying"
                    );
                    false
                }
            };
            drop(compiled);
            Ok(if allowed {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny {
                    status: DENY_STATUS,
                    message: DENY_MESSAGE.to_owned(),
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use bytes::Bytes;
    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};
    use serde_json::json;
    use tempfile::TempDir;

    use super::build_rego_policy;
    use crate::bundle::{BundleLoadError, BundleRegistry, DynamicBundleRegistry, LoadedBundleHook};

    const ALLOW_HEALTH_CHECKS: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
    input.request.uri == "/health"
}
"#;

    #[derive(Debug)]
    struct RegoFixture {
        _directory: TempDir,
        registry: Arc<DynamicBundleRegistry>,
        type_name: String,
    }

    impl RegoFixture {
        fn hook(&self) -> &LoadedBundleHook {
            self.registry
                .policy(&self.type_name)
                .expect("fixture hook should be loaded")
        }
    }

    fn try_fixture(module: &str, extra_hook_yaml: &str) -> Result<RegoFixture, BundleLoadError> {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir_all(&bundle).unwrap();
        let type_name = "rego_policy_fixture".to_owned();
        std::fs::write(bundle.join("policy.rego"), module).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: rego-fixture\nversion: 1.0.0\nruntime: rego\nentry: policy.rego\nhooks:\n  - kind: policy\n    type: {type_name}\n    execution:\n      body_mode: none\n{extra_hook_yaml}"
            ),
        )
        .unwrap();
        let config = ExtensionBundlesConfig {
            bundles_dir: Some(directory.path().display().to_string()),
            sources: Vec::new(),
            grants: std::collections::BTreeMap::new(),
        };
        let registry = DynamicBundleRegistry::load(&config, directory.path(), &BTreeSet::new())?;
        Ok(RegoFixture {
            _directory: directory,
            registry,
            type_name,
        })
    }

    fn fixture(module: &str, extra_hook_yaml: &str) -> RegoFixture {
        try_fixture(module, extra_hook_yaml).expect("fixture should load")
    }

    fn request(method: &str, uri: &str) -> http::Request<Bytes> {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Bytes::new())
            .unwrap()
    }

    #[tokio::test]
    async fn a_signed_bundle_carrying_a_rego_module_activates_and_its_policy_evaluates() {
        let fixture = fixture(ALLOW_HEALTH_CHECKS, "");
        let adapter =
            build_rego_policy(fixture.hook(), json!({})).expect("adapter builds from the hook");

        let allowed = adapter
            .enforce(&request("GET", "/health"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(allowed, PolicyDecision::Allow));

        let denied = adapter
            .enforce(&request("POST", "/health"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(denied, PolicyDecision::Deny { status: 403, .. }));
    }

    #[tokio::test]
    async fn a_declared_query_overrides_the_default_rule_reference() {
        const CUSTOM_RULE: &str = r#"
package sbproxy

default permit := false

permit if {
    input.request.method == "GET"
}
"#;
        let fixture = fixture(CUSTOM_RULE, "    query: data.sbproxy.permit\n");
        let adapter = build_rego_policy(fixture.hook(), json!({})).expect("adapter builds");

        let allowed = adapter
            .enforce(&request("GET", "/anything"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(allowed, PolicyDecision::Allow));

        let denied = adapter
            .enforce(&request("POST", "/anything"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(denied, PolicyDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn attachment_config_reaches_the_module_as_input_config() {
        const READS_CONFIG: &str = r#"
package sbproxy

default allow := false

allow if {
    input.config.mode == "strict"
}
"#;
        let fixture = fixture(READS_CONFIG, "");

        let strict =
            build_rego_policy(fixture.hook(), json!({"mode": "strict"})).expect("adapter builds");
        let allowed = strict
            .enforce(&request("GET", "/"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(allowed, PolicyDecision::Allow));

        let lenient =
            build_rego_policy(fixture.hook(), json!({"mode": "lenient"})).expect("adapter builds");
        let denied = lenient
            .enforce(&request("GET", "/"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(denied, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn a_malformed_rego_module_refuses_the_candidate() {
        let error = try_fixture("this is not rego !!!", "")
            .expect_err("a syntactically broken module must not load");
        assert!(error.to_string().contains("rego"), "{error}");
    }

    #[test]
    fn a_query_naming_no_rule_refuses_the_candidate() {
        // Mirrors `policy: rego`'s own load-time "prove_evaluable"
        // check: a query naming nothing must not compile clean and
        // then deny every request forever once attached.
        let error = try_fixture(ALLOW_HEALTH_CHECKS, "    query: data.sbproxy.nonexistent\n")
            .expect_err("a query naming no rule must not load");
        assert!(error.to_string().contains("rego"), "{error}");
    }
}
