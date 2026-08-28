//! [`PolicyEnforcer`] and [`TransformHandler`] for a signed extension
//! bundle's `runtime: rego` policy and transform hooks (WOR-2482;
//! transforms added for WOR-2493 item 6).
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
//! # Input contract (policy hooks)
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
//! # Output contract (policy hooks)
//!
//! Simpler than the JavaScript/WASM envelope's `allow`/`deny` result:
//! the pinned query must evaluate to a Rego boolean, exactly like
//! `policy: rego`. `true` allows; `false` denies, with the fixed
//! [`DENY_STATUS`]/[`DENY_MESSAGE`] `policy: rego` itself defaults to.
//!
//! A budget-exceeded, non-boolean-result, or other internal
//! evaluation fault is different from a `false` result: it is not a
//! decision, so [`RegoPolicyAdapter::enforce`] propagates it as an
//! `Err` rather than folding it into a deny. That is what lets the
//! bundle's own `failure_posture` (the same knob every other bundle
//! policy hook's fault reaches, via the shared handling in
//! `sbproxy-core::server`) decide whether the request is admitted or
//! refused, instead of this adapter unilaterally denying regardless
//! of what the operator configured. `policy: rego` has no
//! `failure_posture` of its own and fails closed unconditionally on a
//! fault; a bundled Rego policy is not that surface and must not
//! silently inherit its posture.
//!
//! # Transform hooks (WOR-2493 item 6)
//!
//! A `kind: transform` hook rides the identical engine setup: the
//! module `bundle::loader` compiled and proved evaluable at candidate
//! load, evaluated under the same wall-time budget, with the pinned
//! query defaulting to `data.sbproxy.transform` instead of
//! `data.sbproxy.allow`. The input mirrors the JavaScript bundle
//! transform's envelope: `input.body.body_base64` (the complete
//! buffered response body), `input.body.content_type`,
//! `input.body.origin`, and `input.config`.
//!
//! The output mirrors the policy hook's "one plain Rego value"
//! philosophy rather than the JS wire envelope: the query must
//! evaluate to a base64 string, which becomes the replacement body
//! (bounded by the sandbox's `max_output_bytes`). An undefined rule
//! value is the transform declining for this input, so the body
//! passes through unchanged, the same reading `eval_value` documents
//! for the AI routing hook. Anything else (a non-string document,
//! invalid base64, an over-limit replacement, a budget fault) is an
//! `Err`, never a partial write: the transform fails closed through
//! the same shared `failure_posture` handling the policy hook's
//! faults reach.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use sbproxy_config::{BundleHookKind, BundleRuntime};
use sbproxy_plugin::{
    PluginError, PluginResult, PolicyDecision, PolicyEnforcer, TransformContext, TransformHandler,
};
use serde_json::{json, Value};

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
    // One choke point for defaults, secret resolution, and schema
    // validation, shared with every other bundle hook adapter
    // (WOR-2289, WOR-2433).
    let config = envelope::prepare_hook_config(hook, config)?;
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
            // WOR-2482 review (I1): an evaluation fault (budget
            // exceeded, a non-boolean rule result, an internal
            // Regorus error) is not a decision, so it must not be
            // swallowed into a hardcoded deny the way a real `false`
            // result is below. Propagating it as `Err`, exactly like
            // `JavascriptPolicyAdapter::enforce`'s
            // `RuntimeFailure::into_plugin_error` does, is what lets
            // the shared `failure_posture` handling in
            // `sbproxy-core::server` (the same path every other
            // bundle policy hook's fault reaches) decide admit or
            // refuse. Swallowing it here made `failure_posture: open`
            // silently behave like `closed` for this hook alone.
            let allowed = compiled.eval_bool_json(input, "").map_err(|error| {
                PluginError::Internal(anyhow::anyhow!(
                    "rego bundle policy `{}` failed to evaluate: {error}",
                    self.type_name
                ))
            })?;
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

/// Buffered-body Rego transform adapter backed by the engine
/// `bundle::loader` compiled once at candidate load (WOR-2493 item 6).
///
/// See the module docs for the input and output contract. Like every
/// other dynamic bundle transform, the compiled `Transform::Plugin`
/// wrapper in `sbproxy-modules` reports this adapter as
/// request-dependent, so an origin with `response_cache` refuses the
/// pairing at config load, the same cacheability posture the
/// JavaScript and Lua transform surfaces carry.
pub struct RegoTransformAdapter {
    type_name: String,
    compiled: Arc<Mutex<CompiledRego>>,
    config: Arc<Value>,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl std::fmt::Debug for RegoTransformAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegoTransformAdapter")
            .field("type_name", &self.type_name)
            .finish_non_exhaustive()
    }
}

/// Build a transform adapter from a validated Rego bundle hook.
///
/// # Errors
///
/// Returns a bounded load error under the same contract as
/// [`build_rego_policy`]: a mismatched hook, invalid attachment
/// config, or a candidate with no compiled Rego engine for this hook.
pub fn build_rego_transform(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<RegoTransformAdapter, BundleLoadError> {
    if hook.manifest().runtime != BundleRuntime::Rego
        || hook.hook().kind != BundleHookKind::Transform
    {
        return Err(BundleLoadError::new(
            "rego",
            "hook kind does not match the requested Rego transform adapter",
        ));
    }
    // One choke point for defaults, secret resolution, and schema
    // validation, shared with every other bundle hook adapter
    // (WOR-2289, WOR-2433).
    let config = envelope::prepare_hook_config(hook, config)?;
    let compiled = hook.prepared_rego().ok_or_else(|| {
        BundleLoadError::new("rego", "bundle has no compiled Rego engine for this hook")
    })?;
    let max_input_bytes = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .map_err(|_| BundleLoadError::new("rego", "input limit is unsupported"))?;
    let max_output_bytes = usize::try_from(hook.manifest().sandbox.max_output_bytes)
        .map_err(|_| BundleLoadError::new("rego", "output limit is unsupported"))?;
    Ok(RegoTransformAdapter {
        type_name: hook.hook().type_name.clone(),
        compiled: Arc::clone(compiled),
        config: Arc::new(config),
        max_input_bytes,
        max_output_bytes,
    })
}

impl TransformHandler for RegoTransformAdapter {
    fn transform_type(&self) -> &str {
        &self.type_name
    }

    fn apply<'a>(
        &'a self,
        body: &'a mut BytesMut,
        content_type: Option<&'a str>,
        context: &'a TransformContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if body.len() > self.max_input_bytes {
                return Err(envelope_failure(envelope::EnvelopeError::new(
                    "input_limit",
                )));
            }
            let payload = json!({
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&body[..]),
                "content_type": content_type,
                "origin": context.origin,
            });
            let input = envelope::hook_envelope(
                "body",
                envelope::hook_kind_label(BundleHookKind::Transform),
                &self.type_name,
                self.config.as_ref(),
                payload,
            );
            let mut compiled = match self.compiled.lock() {
                Ok(guard) => guard,
                // Same poisoned-lock recovery as `RegoPolicyAdapter`:
                // one panicking evaluation must not fault every later
                // one forever.
                Err(poisoned) => poisoned.into_inner(),
            };
            // An evaluation fault (budget exceeded, an internal
            // Regorus error) is propagated as `Err`, never folded into
            // a silent pass-through: the same "a fault is not a
            // decision" contract `RegoPolicyAdapter::enforce` carries,
            // so the shared `failure_posture` handling decides what a
            // faulted transform does to the response.
            let value = compiled.eval_value(input, "").map_err(|error| {
                PluginError::Internal(anyhow::anyhow!(
                    "rego bundle transform `{}` failed to evaluate: {error}",
                    self.type_name
                ))
            })?;
            drop(compiled);
            let replacement = match value {
                // The rule is undefined for this input: the transform
                // declined, and the body passes through untouched. The
                // same reading `CompiledRego::eval_value` documents
                // for the AI routing hook.
                Value::Null => return Ok(()),
                Value::String(encoded) => {
                    // Enforce the cap ahead of the replacement
                    // allocation, not after it: canonical padded
                    // base64 decodes to exactly len / 4 * 3 minus its
                    // padding bytes, so an over-limit replacement is
                    // refused before a byte of it is decoded
                    // (saturating, because a guest can return a bare
                    // "=="; anything non-canonical fails the decode
                    // below anyway).
                    let padding = encoded
                        .as_bytes()
                        .iter()
                        .rev()
                        .take(2)
                        .filter(|byte| **byte == b'=')
                        .count();
                    if (encoded.len() / 4 * 3).saturating_sub(padding) > self.max_output_bytes {
                        return Err(envelope_failure(envelope::EnvelopeError::new(
                            "output_limit",
                        )));
                    }
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|_| {
                            envelope_failure(envelope::EnvelopeError::new("invalid_envelope"))
                        })?
                }
                // Deliberately does not echo the value: a rule result
                // can embed body or config content that must not reach
                // logs.
                _ => {
                    return Err(PluginError::Internal(anyhow::anyhow!(
                        "rego bundle transform `{}` rule returned a non-string value; \
                         the query must evaluate to a base64 string replacement body, \
                         or be undefined to decline",
                        self.type_name
                    )));
                }
            };
            if replacement.len() > self.max_output_bytes {
                return Err(envelope_failure(envelope::EnvelopeError::new(
                    "output_limit",
                )));
            }
            body.clear();
            body.extend_from_slice(&replacement);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use bytes::{Bytes, BytesMut};
    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_plugin::{PolicyDecision, PolicyEnforcer, TransformContext, TransformHandler};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{build_rego_policy, build_rego_transform};
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

        fn transform_hook(&self) -> &LoadedBundleHook {
            self.registry
                .transform(&self.type_name)
                .expect("fixture transform hook should be loaded")
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

    fn try_transform_fixture(
        module: &str,
        extra_hook_yaml: &str,
        trailing_yaml: &str,
    ) -> Result<RegoFixture, BundleLoadError> {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir_all(&bundle).unwrap();
        let type_name = "rego_transform_fixture".to_owned();
        std::fs::write(bundle.join("transform.rego"), module).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: rego-fixture\nversion: 1.0.0\nruntime: rego\nentry: transform.rego\nhooks:\n  - kind: transform\n    type: {type_name}\n    execution:\n      body_mode: buffered\n{extra_hook_yaml}{trailing_yaml}"
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

    fn transform_fixture(module: &str, extra_hook_yaml: &str) -> RegoFixture {
        try_transform_fixture(module, extra_hook_yaml, "").expect("transform fixture should load")
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

    /// Hook YAML declaring `token` as a secret var and supplying the
    /// manifest's own default for it.
    fn authored_secret_var(default: &str) -> String {
        format!(
            "    secret_vars: [token]\n    config_schema:\n      type: object\n      properties:\n        token:\n          type: string\n          default: \"{default}\"\n"
        )
    }

    #[test]
    fn a_manifest_default_may_not_resolve_a_host_backed_secret_var() {
        // WOR-2433 re-review. `env:PATH` stands in for a credential:
        // the manifest declares the var, supplies the reference itself,
        // and no line of the operator's attachment config names it.
        let host_value = std::env::var("PATH").expect("PATH is set in the test environment");
        let fixture = fixture(ALLOW_HEALTH_CHECKS, &authored_secret_var("env:PATH"));

        let error = build_rego_policy(fixture.hook(), json!({}))
            .expect_err("a manifest-authored host-backed reference must be refused");

        let rendered = error.to_string();
        assert!(rendered.contains("rego-fixture"), "{rendered}");
        assert!(rendered.contains("token"), "{rendered}");
        assert!(
            !rendered.contains(&host_value),
            "the refusal echoed the host's environment"
        );
    }

    #[test]
    fn a_manifest_default_may_not_read_a_host_file() {
        let directory = TempDir::new().unwrap();
        let secret = directory.path().join("host-owned");
        std::fs::write(&secret, "DISTINCTIVE_REGO_HOST_FILE_2d9a").unwrap();
        let fixture = fixture(
            ALLOW_HEALTH_CHECKS,
            &authored_secret_var(&format!("file:{}", secret.display())),
        );

        let error = build_rego_policy(fixture.hook(), json!({}))
            .expect_err("a manifest-authored host path must be refused");

        assert!(
            !error
                .to_string()
                .contains("DISTINCTIVE_REGO_HOST_FILE_2d9a"),
            "{error}"
        );
    }

    #[test]
    fn an_operator_supplied_value_for_the_same_var_still_resolves() {
        // The boundary is about who authored the value, not about the
        // key. The operator writing the very reference the manifest
        // wanted resolves, because the operator owns the host's
        // secrets.
        let expected = std::env::var("PATH").expect("PATH is set in the test environment");
        let fixture = fixture(ALLOW_HEALTH_CHECKS, &authored_secret_var("env:PATH"));

        let adapter = build_rego_policy(fixture.hook(), json!({ "token": "env:PATH" }))
            .expect("an operator-authored reference still resolves");

        assert_eq!(
            adapter.config["token"], expected,
            "the operator's reference must resolve into the hook's config"
        );
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

    #[tokio::test]
    async fn an_evaluation_fault_propagates_as_a_plugin_error_rather_than_denying() {
        // WOR-2482 review finding I1: `enforce` used to swallow an
        // evaluation fault into a hardcoded `Ok(Deny)`, which made
        // `failure_posture: open` silently behave like `closed` for
        // this hook alone (the shared posture handling in
        // `sbproxy-core::server` only ever sees an `Err`). A rule that
        // returns a document rather than a boolean passes candidate
        // load (the load-time trial only proves the rule evaluates,
        // not that its value is boolean) and faults here instead.
        const RETURNS_A_DOCUMENT: &str = r#"
package sbproxy

allow := {"reason": "not a boolean"}
"#;
        let fixture = fixture(RETURNS_A_DOCUMENT, "");
        let adapter = build_rego_policy(fixture.hook(), json!({})).expect("adapter builds");

        let error = adapter
            .enforce(&request("GET", "/"), &mut ())
            .await
            .expect_err("a non-boolean rule result is a fault, not a decision");
        assert!(
            error.to_string().contains("rather than a boolean"),
            "{error}"
        );
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

    // --- kind: transform (WOR-2493 item 6) ---

    const REWRITES_PLAIN_TEXT: &str = r#"
package sbproxy

transform := base64.encode("rewritten") if {
    input.body.content_type == "text/plain"
}
"#;

    async fn apply_transform(
        adapter: &super::RegoTransformAdapter,
        body: &[u8],
        content_type: Option<&str>,
    ) -> (BytesMut, Result<(), sbproxy_plugin::PluginError>) {
        let mut buffer = BytesMut::from(body);
        let outcome = adapter
            .apply(
                &mut buffer,
                content_type,
                &TransformContext::new("fixture.example"),
            )
            .await;
        (buffer, outcome)
    }

    #[tokio::test]
    async fn a_signed_bundle_carrying_a_rego_transform_activates_and_rewrites_the_body() {
        // WOR-2493 item 6: before this landed, the manifest was refused
        // at candidate load ("runtime rego may declare only policy
        // hooks") and `compile.rs` carried a matching backstop bail.
        let fixture = transform_fixture(REWRITES_PLAIN_TEXT, "");
        let adapter = build_rego_transform(fixture.transform_hook(), json!({}))
            .expect("adapter builds from the hook");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        outcome.expect("the transform evaluates");
        assert_eq!(&body[..], b"rewritten");
    }

    #[tokio::test]
    async fn an_undefined_transform_rule_leaves_the_body_unchanged() {
        // The rule fires for text/plain only; any other content type
        // leaves the query undefined, which is the transform declining,
        // not a fault.
        let fixture = transform_fixture(REWRITES_PLAIN_TEXT, "");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) =
            apply_transform(&adapter, b"{\"a\":1}", Some("application/json")).await;
        outcome.expect("declining is not a fault");
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    #[tokio::test]
    async fn attachment_config_reaches_the_transform_as_input_config() {
        const READS_CONFIG: &str = r#"
package sbproxy

transform := base64.encode(input.config.replacement)
"#;
        let fixture = transform_fixture(READS_CONFIG, "");
        let adapter = build_rego_transform(
            fixture.transform_hook(),
            json!({"replacement": "from config"}),
        )
        .expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        outcome.expect("the transform evaluates");
        assert_eq!(&body[..], b"from config");
    }

    #[tokio::test]
    async fn a_declared_query_overrides_the_default_transform_rule() {
        const CUSTOM_RULE: &str = r#"
package sbproxy

rewrite := base64.encode("custom")
"#;
        let fixture = transform_fixture(CUSTOM_RULE, "    query: data.sbproxy.rewrite\n");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", None).await;
        outcome.expect("the transform evaluates");
        assert_eq!(&body[..], b"custom");
    }

    #[tokio::test]
    async fn a_non_string_transform_result_is_a_fault_and_the_body_is_untouched() {
        // A document is not an answer to "what are the replacement
        // bytes", so it must fail the transform closed rather than be
        // coerced or silently skipped, mirroring the policy adapter's
        // non-boolean contract.
        const RETURNS_A_DOCUMENT: &str = r#"
package sbproxy

transform := {"body": "not a string"}
"#;
        let fixture = transform_fixture(RETURNS_A_DOCUMENT, "");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        let error = outcome.expect_err("a non-string rule result is a fault, not a rewrite");
        assert!(error.to_string().contains("non-string value"), "{error}");
        assert_eq!(
            &body[..],
            b"original",
            "a faulted transform must not touch the body"
        );
    }

    #[tokio::test]
    async fn an_invalid_base64_result_is_a_fault() {
        const RETURNS_BAD_BASE64: &str = r#"
package sbproxy

transform := "!!! not base64 !!!"
"#;
        let fixture = transform_fixture(RETURNS_BAD_BASE64, "");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        let error = outcome.expect_err("undecodable output is a fault, not a rewrite");
        assert!(error.to_string().contains("invalid_envelope"), "{error}");
        assert_eq!(&body[..], b"original");
    }

    #[tokio::test]
    async fn a_replacement_over_max_output_bytes_is_a_fault() {
        let fixture =
            try_transform_fixture(REWRITES_PLAIN_TEXT, "", "sandbox:\n  max_output_bytes: 4\n")
                .expect("transform fixture should load");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        let error = outcome.expect_err("an over-limit replacement is a fault");
        assert!(error.to_string().contains("output_limit"), "{error}");
        assert_eq!(&body[..], b"original");
    }

    #[tokio::test]
    async fn a_replacement_exactly_at_max_output_bytes_passes() {
        // Boundary pin for the pre-decode size estimate: it must not
        // refuse a replacement that is exactly at the cap, with and
        // without base64 padding in play ("rewritten" is 9 bytes and
        // encodes unpadded; "test" is 4 bytes and encodes with two
        // padding characters).
        let fixture =
            try_transform_fixture(REWRITES_PLAIN_TEXT, "", "sandbox:\n  max_output_bytes: 9\n")
                .expect("transform fixture should load");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");
        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        outcome.expect("an exactly-at-cap replacement is not a fault");
        assert_eq!(&body[..], b"rewritten");

        const REWRITES_TO_TEST: &str = r#"
package sbproxy

transform := base64.encode("test")
"#;
        let fixture =
            try_transform_fixture(REWRITES_TO_TEST, "", "sandbox:\n  max_output_bytes: 4\n")
                .expect("transform fixture should load");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");
        let (body, outcome) = apply_transform(&adapter, b"original", None).await;
        outcome.expect("padding must not inflate the size estimate");
        assert_eq!(&body[..], b"test");
    }

    #[tokio::test]
    async fn a_body_over_max_buffer_bytes_is_a_fault() {
        let fixture =
            try_transform_fixture(REWRITES_PLAIN_TEXT, "", "sandbox:\n  max_buffer_bytes: 4\n")
                .expect("transform fixture should load");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"original", Some("text/plain")).await;
        let error = outcome.expect_err("an over-limit input is a fault");
        assert!(error.to_string().contains("input_limit"), "{error}");
        assert_eq!(&body[..], b"original");
    }

    #[tokio::test]
    async fn one_bundle_can_carry_a_policy_and_a_transform_with_distinct_default_queries() {
        // The loader compiles one engine per hook so each pins its own
        // query: the policy hook defaults to `data.sbproxy.allow`, the
        // transform hook to `data.sbproxy.transform`, over the same
        // module text.
        const BOTH_RULES: &str = r#"
package sbproxy

default allow := false

allow if input.request.method == "GET"

transform := base64.encode("rewritten") if {
    input.body.content_type == "text/plain"
}
"#;
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("both.rego"), BOTH_RULES).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: rego-fixture\nversion: 1.0.0\nruntime: rego\nentry: both.rego\nhooks:\n  - kind: policy\n    type: rego_both_policy\n    execution:\n      body_mode: none\n  - kind: transform\n    type: rego_both_transform\n    execution:\n      body_mode: buffered\n",
        )
        .unwrap();
        let config = ExtensionBundlesConfig {
            bundles_dir: Some(directory.path().display().to_string()),
            sources: Vec::new(),
            grants: std::collections::BTreeMap::new(),
        };
        let registry = DynamicBundleRegistry::load(&config, directory.path(), &BTreeSet::new())
            .expect("a bundle mixing policy and transform hooks must load");

        let policy_hook = registry
            .policy("rego_both_policy")
            .expect("policy hook loads");
        let policy = build_rego_policy(policy_hook, json!({})).expect("policy adapter builds");
        let allowed = policy
            .enforce(&request("GET", "/health"), &mut ())
            .await
            .expect("evaluates");
        assert!(matches!(allowed, PolicyDecision::Allow));

        let transform_hook = registry
            .transform("rego_both_transform")
            .expect("transform hook loads");
        let transform =
            build_rego_transform(transform_hook, json!({})).expect("transform adapter builds");
        let (body, outcome) = apply_transform(&transform, b"original", Some("text/plain")).await;
        outcome.expect("the transform evaluates");
        assert_eq!(&body[..], b"rewritten");
    }

    #[test]
    fn a_policy_hook_refuses_the_transform_adapter() {
        // The kind check is the load-time guard against wiring a hook
        // into the wrong adapter; both directions must refuse.
        let policy = fixture(ALLOW_HEALTH_CHECKS, "");
        let error = build_rego_transform(policy.hook(), json!({}))
            .expect_err("a policy hook must not build a transform adapter");
        assert!(error.to_string().contains("rego"), "{error}");

        let transform = transform_fixture(REWRITES_PLAIN_TEXT, "");
        let error = build_rego_policy(transform.transform_hook(), json!({}))
            .expect_err("a transform hook must not build a policy adapter");
        assert!(error.to_string().contains("rego"), "{error}");
    }

    #[tokio::test]
    async fn a_transform_result_encoding_is_exact_bytes() {
        // Round-trip sanity: what the rule base64-encodes is exactly
        // what lands in the buffer, byte for byte.
        const ECHOES_UPPER: &str = r#"
package sbproxy

transform := base64.encode(upper(base64.decode(input.body.body_base64)))
"#;
        let fixture = transform_fixture(ECHOES_UPPER, "");
        let adapter =
            build_rego_transform(fixture.transform_hook(), json!({})).expect("adapter builds");

        let (body, outcome) = apply_transform(&adapter, b"hello, rego", None).await;
        outcome.expect("the transform evaluates");
        assert_eq!(&body[..], b"HELLO, REGO");
    }
}
