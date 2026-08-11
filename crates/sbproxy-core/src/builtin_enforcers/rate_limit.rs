//! Wrapper enforcer for the `Policy::RateLimit` variant.
//!
//! Stashes the resulting `RateLimitInfo` on the request context so the
//! dispatcher's 429 response handler can emit the `X-RateLimit-*`
//! headers.
//!
//! ## Which admission path runs (WOR-2332)
//!
//! A local-only policy calls the synchronous
//! [`sbproxy_modules::policy::RateLimitPolicy::allow_with_info_for`]
//! here, in `enforce`, exactly as it always has.
//!
//! A policy with an L2 (Redis) store or a mesh cluster tier attached
//! cannot: consulting that tier is an await, and this trait method may
//! not hold the request context across one. So admission for those
//! policies happens one level up, at the `check_policies` call site,
//! through the internal `SharedAdmission` seam (see the
//! `builtin_enforcers::shared_admission` module), and `enforce` consumes
//! the decision from
//! [`crate::context::RequestContext::shared_rate_limit_decision`].
//!
//! Until that seam existed the wrapper always took the synchronous path,
//! so an operator who configured Redis-backed distributed rate limiting
//! got purely local enforcement and ten replicas admitted ten times the
//! configured rate.
//!
//! When `policy.key` is a non-empty CEL expression the wrapper
//! evaluates it against the per-request CEL context (method, path,
//! headers, query, client_ip, hostname, envelope namespace, feature
//! flags) and uses the result as the rate-limit bucket key.
//!
//! ## Failure posture (WOR-2164)
//!
//! The `key:` expression is compiled exactly once, in
//! [`RateLimitEnforcer::new`], at config-compile time. Malformed CEL
//! rejects the candidate config with an error naming the origin and the
//! bad expression, so boot and reload both refuse it. It used to be
//! parsed once per request and, on failure, quietly dropped the request
//! into the default bucket.
//!
//! Runtime evaluation errors keep rate limiting on, in a bucket
//! namespace of their own: see [`CEL_KEY_ERROR_BUCKET_PREFIX`].
//!
//! Per-deny-reason label: `"rate_limit"`. Single denial shape
//! (`429 Too Many Requests`) plus a populated
//! `ctx.rate_limit_info`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use compact_str::CompactString;
use sbproxy_extension::cel::CompiledCel;
use sbproxy_modules::policy::{RateLimitInfo, RateLimitPolicy};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use super::shared_admission::SharedAdmission;
use crate::context::RequestContext;

/// Bucket-key prefix used when the compiled `key:` expression fails to
/// evaluate for a request.
///
/// Three postures were available and this is the middle one, on
/// purpose.
///
/// Refusing the request is wrong here: with syntax errors now rejected
/// at boot, the failures left are request-shaped (a header this caller
/// did not send, a claim this token does not carry). Turning those into
/// 429s or 500s would take traffic down over a condition the operator
/// never asked to block on.
///
/// Falling back to the bare default key is what the code used to do,
/// and it is the reason this constant exists. The default key is the
/// client IP, or the hostname when no client IP is known, so an
/// expression that fails for every request merges all of that traffic
/// into buckets keyed by something coarser than the operator chose, and
/// in the no-client-IP case into a single origin-wide bucket. Both let
/// a caller leave its own identity bucket, with its accumulated count,
/// by making the expression fail: a rate-limit bypass wearing a
/// fallback's clothes.
///
/// So: still bucket, still per client, but in a namespace of its own so
/// error traffic never shares a bucket with correctly keyed traffic and
/// the operator can see it in the logs. A caller that forces the error
/// path gains a separate budget, not a shared one.
pub const CEL_KEY_ERROR_BUCKET_PREFIX: &str = "__cel_key_error__:";

/// What evaluating a compiled `key:` expression produced.
pub(crate) enum CelKeyOutcome {
    /// A non-empty bucket key.
    Resolved(String),
    /// The expression evaluated fine and said this request has no key
    /// (null, or an empty string). That is the operator's own logic
    /// talking, so the default client key applies.
    NoKey,
    /// The expression could not be evaluated, or produced something
    /// that is not usable as a key. See
    /// [`CEL_KEY_ERROR_BUCKET_PREFIX`].
    EvalError,
}

/// Wrapper that adapts [`RateLimitPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct RateLimitEnforcer {
    policy: Arc<RateLimitPolicy>,
    metric_policy: CompactString,
    /// The policy's `key:` expression, compiled once at config load.
    /// `None` when the policy configures no key (the default client-IP
    /// behaviour).
    ///
    /// Behind an `Arc` so the shared-admission handle can derive the same
    /// bucket key from the same compiled expression without recompiling
    /// it or holding a borrow of the enforcer.
    compiled_key: Option<Arc<CompiledCel>>,
}

impl RateLimitEnforcer {
    /// Pair a compiled rate-limit policy with its bounded route-pattern
    /// label, compiling the policy's `key:` CEL expression once.
    ///
    /// Returns an error naming the policy and quoting the expression
    /// when the key does not parse, so the candidate config is rejected
    /// at boot and at reload rather than every request silently landing
    /// in the default bucket.
    pub fn new(policy: Arc<RateLimitPolicy>, metric_policy: &str) -> anyhow::Result<Self> {
        let compiled_key = match policy.key.as_deref() {
            Some(expr) if !expr.is_empty() => Some(Arc::new(CompiledCel::compile(
                "policy `rate_limiting` key",
                expr,
            )?)),
            _ => None,
        };
        Ok(Self {
            policy,
            metric_policy: CompactString::new(metric_policy),
            compiled_key,
        })
    }

    /// A handle that admits this policy against its cluster-shared tier,
    /// for policies that have one.
    ///
    /// `None` for a local-only policy, which is the common case: the
    /// request path then never enters the seam and keeps exactly the
    /// synchronous behaviour it had before WOR-2332.
    pub(crate) fn shared_admission(&self) -> Option<Arc<dyn SharedAdmission>> {
        if !self.policy.has_shared_tier() {
            return None;
        }
        Some(Arc::new(RateLimitSharedAdmission {
            policy: Arc::clone(&self.policy),
            compiled_key: self.compiled_key.clone(),
        }))
    }
}

/// The shared-tier half of [`RateLimitEnforcer`], split out so the bucket
/// key can be derived under a context borrow that ends before the await.
///
/// Shares the policy and the compiled key expression with the enforcer by
/// `Arc`, so there is one policy, one set of counters, and one compiled
/// CEL program no matter which half runs.
struct RateLimitSharedAdmission {
    policy: Arc<RateLimitPolicy>,
    compiled_key: Option<Arc<CompiledCel>>,
}

impl SharedAdmission for RateLimitSharedAdmission {
    fn shared_admission_key(
        &self,
        req: &http::Request<Bytes>,
        ctx: &RequestContext,
    ) -> Option<String> {
        Some(bucket_key(self.compiled_key.as_deref(), req, ctx))
    }

    fn shared_admit<'a>(
        &'a self,
        key: String,
    ) -> Pin<Box<dyn Future<Output = RateLimitInfo> + Send + 'a>> {
        Box::pin(async move { self.policy.allow_with_info_async(&key).await })
    }
}

/// Resolve the rate-limit bucket key for one request.
///
/// Shared by the synchronous enforcer and the shared-admission handle so
/// the two cannot bucket the same request differently. Splitting it out
/// is what makes the seam work at all: this is the only part of admission
/// that needs the request context, and it needs it only synchronously.
fn bucket_key(
    compiled_key: Option<&CompiledCel>,
    req: &http::Request<Bytes>,
    ctx: &RequestContext,
) -> String {
    let default_client_id = ctx
        .client_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| ctx.hostname.to_string());
    match compiled_key {
        Some(expr) => match rate_limit_key_from_cel(req, ctx, expr) {
            CelKeyOutcome::Resolved(key) => key,
            CelKeyOutcome::NoKey => default_client_id,
            CelKeyOutcome::EvalError => {
                format!("{CEL_KEY_ERROR_BUCKET_PREFIX}{default_client_id}")
            }
        },
        None => default_client_id,
    }
}

impl PolicyEnforcer for RateLimitEnforcer {
    fn policy_type(&self) -> &'static str {
        "rate_limit"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.policy);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "rate_limit enforcer: bad context".to_string(),
                    })
                });
            }
        };
        // Take, do not peek: a chain may carry more than one rate-limit
        // policy, and the second must not inherit the first's decision.
        // `check_policies` fills this slot immediately before dispatching
        // the enforcer it belongs to.
        let info = match ctx.shared_rate_limit_decision.take() {
            // WOR-2332: the shared tier already decided, at the
            // `check_policies` call site, where the await is legal. The
            // bucket key was derived there from this same request and
            // context, so nothing is recomputed here.
            Some(precomputed) => precomputed,
            // Local-only policy: the synchronous token bucket, unchanged.
            // No shared tier is attached, so there is nothing to consult
            // and no reason to pay for an await.
            //
            // This branch is not a fallback for a failed shared call.
            // `allow_with_info_async` has its own fail-open posture and
            // returns an admitting `RateLimitInfo` when Redis is
            // unreachable, so a store outage never lands here.
            None => {
                let client_id = bucket_key(self.compiled_key.as_deref(), req, ctx);
                policy.allow_with_info_for(&client_id)
            }
        };
        // The label is the configured route pattern captured once during
        // pipeline compilation, never a request-derived hostname. The metric
        // helper additionally applies the shared cardinality cap.
        sbproxy_observe::metrics::record_rate_limit_decision(
            self.metric_policy.as_str(),
            if info.allowed {
                "allow"
            } else {
                "throttle_route"
            },
        );
        if !info.allowed {
            ctx.rate_limit_info = Some(info);
            ctx.deny_policy_type = Some("rate_limit");
            Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 429,
                    message: "rate limited".to_string(),
                })
            })
        } else {
            ctx.rate_limit_info = Some(info);
            Box::pin(async move { Ok(PolicyDecision::Allow) })
        }
    }
}

/// Evaluate a precompiled `key:` CEL expression against the current
/// request and report what it produced.
///
/// The expression arrives already compiled (at config load), so this
/// only ever evaluates. Callers map the outcome onto their own bucket
/// policy: see [`CEL_KEY_ERROR_BUCKET_PREFIX`] for the rate limiter's,
/// and `resolve_block_key` in the WAF enforcer for the persistent-block
/// one.
pub(crate) fn rate_limit_key_from_cel(
    req: &http::Request<Bytes>,
    ctx: &RequestContext,
    expr: &CompiledCel,
) -> CelKeyOutcome {
    use sbproxy_extension::cel::context::{
        build_request_context, populate_envelope_namespace, populate_features_namespace,
        EnvelopeView, FeatureFlagsView,
    };
    use sbproxy_extension::cel::CelValue;

    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query();
    let client_ip = ctx.client_ip.map(|ip| ip.to_string());

    let mut cel_ctx = build_request_context(
        method,
        path,
        req.headers(),
        query,
        client_ip.as_deref(),
        ctx.hostname.as_str(),
    );
    let session_str = ctx.session_id.map(|s| s.to_string());
    let parent_str = ctx.parent_session_id.map(|s| s.to_string());
    let envelope = EnvelopeView {
        user_id: ctx.user_id.as_deref(),
        user_id_source: ctx.user_id_source.map(|s| s.as_str()),
        session_id: session_str.as_deref(),
        parent_session_id: parent_str.as_deref(),
        workspace_id: None,
        properties: Some(&ctx.properties),
    };
    populate_envelope_namespace(&mut cel_ctx, &envelope);
    // `request.key_id` is the rotation-safe bucket expression. Keying on
    // `request.headers["x-api-key"]` buckets on the presented secret, so a
    // rotation silently hands the caller a fresh budget.
    sbproxy_extension::cel::context::populate_resolved_key_id(
        &mut cel_ctx,
        ctx.resolved_inbound_key
            .as_deref()
            .or(ctx.native_key_policy_record.as_deref())
            .map(|record| record.key_id.as_str()),
    );
    let features = FeatureFlagsView {
        debug: ctx.flags.debug,
        trace: ctx.flags.trace,
        no_cache: ctx.flags.no_cache,
        extra: &ctx.flags.extra,
    };
    populate_features_namespace(&mut cel_ctx, &features);

    let value = match expr.eval(&cel_ctx) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                error = %err,
                site = expr.site(),
                expression = expr.source(),
                "rate-limit key CEL evaluation failed; bucketing under the error-key namespace"
            );
            return CelKeyOutcome::EvalError;
        }
    };
    let s = match value {
        CelValue::String(s) => s,
        CelValue::Int(i) => i.to_string(),
        CelValue::Float(f) => f.to_string(),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Null => return CelKeyOutcome::NoKey,
        CelValue::Map(_) | CelValue::List(_) => {
            tracing::warn!(
                site = expr.site(),
                expression = expr.source(),
                "rate-limit key CEL expression produced a map/list, which cannot be a bucket key"
            );
            return CelKeyOutcome::EvalError;
        }
    };
    if s.is_empty() {
        CelKeyOutcome::NoKey
    } else {
        CelKeyOutcome::Resolved(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision_count(policy: &str, result: &str) -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_rate_limit_decisions_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        let label = |name: &str| {
                            metric
                                .get_label()
                                .iter()
                                .find(|label| label.name() == name)
                                .map(|label| label.value())
                        };
                        label("policy") == Some(policy) && label("result") == Some(result)
                    })
                    .map(|metric| metric.get_counter().value() as u64)
                    .sum()
            })
            .unwrap_or_default()
    }

    fn request_context(hostname: &str) -> RequestContext {
        let mut ctx = RequestContext::new();
        ctx.hostname = hostname.into();
        ctx
    }

    fn one_request_enforcer(metric_policy: &str) -> RateLimitEnforcer {
        RateLimitEnforcer::new(
            Arc::new(
                RateLimitPolicy::from_config(serde_json::json!({
                    "requests_per_second": 0.001,
                    "burst": 1
                }))
                .unwrap(),
            ),
            metric_policy,
        )
        .expect("no key expression to compile")
    }

    #[test]
    fn malformed_key_expression_is_rejected_at_config_load() {
        // WOR-2164: the source used to be carried to the request path
        // and reparsed there, where a failure quietly bucketed the
        // request under the default key.
        let policy = RateLimitPolicy::from_config(serde_json::json!({
            "requests_per_second": 1.0,
            "key": "this is not valid CEL !!!"
        }))
        .unwrap();
        let err = RateLimitEnforcer::new(Arc::new(policy), "bad-key.example")
            .err()
            .expect("malformed CEL must not compile");
        let msg = err.to_string();
        assert!(msg.contains("rate_limiting"), "must name the policy: {msg}");
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "must quote the expression: {msg}"
        );
    }

    #[test]
    fn valid_key_expression_compiles_once() {
        let policy = RateLimitPolicy::from_config(serde_json::json!({
            "requests_per_second": 1.0,
            "key": "request.key_id"
        }))
        .unwrap();
        let enforcer =
            RateLimitEnforcer::new(Arc::new(policy), "good-key.example").expect("valid CEL");
        assert_eq!(
            enforcer.compiled_key.as_ref().map(|c| c.source()),
            Some("request.key_id")
        );
    }

    #[tokio::test]
    async fn key_expression_buckets_by_its_resolved_value() {
        // The happy path, unchanged: two requests with different header
        // values land in different buckets, so the second is not
        // throttled by the first.
        let policy = RateLimitPolicy::from_config(serde_json::json!({
            "requests_per_second": 0.001,
            "burst": 1,
            "key": r#"request.headers["x-tenant"]"#
        }))
        .unwrap();
        let enforcer = RateLimitEnforcer::new(Arc::new(policy), "keyed.example").expect("valid");

        let req_a = http::Request::builder()
            .uri("/")
            .header("x-tenant", "tenant-a")
            .body(Bytes::new())
            .unwrap();
        let req_b = http::Request::builder()
            .uri("/")
            .header("x-tenant", "tenant-b")
            .body(Bytes::new())
            .unwrap();
        let mut ctx_a = request_context("keyed.example");
        let mut ctx_b = request_context("keyed.example");
        assert!(matches!(
            enforcer.enforce(&req_a, &mut ctx_a).await.unwrap(),
            PolicyDecision::Allow
        ));
        assert!(
            matches!(
                enforcer.enforce(&req_b, &mut ctx_b).await.unwrap(),
                PolicyDecision::Allow
            ),
            "a different key is a different bucket"
        );
        let mut ctx_a_again = request_context("keyed.example");
        assert!(
            matches!(
                enforcer.enforce(&req_a, &mut ctx_a_again).await.unwrap(),
                PolicyDecision::Deny { status: 429, .. }
            ),
            "the same key shares one bucket"
        );
    }

    #[tokio::test]
    async fn key_evaluation_error_buckets_under_the_error_namespace() {
        // Posture pinned: a request whose key expression cannot
        // evaluate is still rate limited, in a namespace of its own, so
        // it neither shares a bucket with correctly keyed traffic nor
        // collapses the whole origin into one bucket. The expression
        // below parses (so the config is accepted) and fails at
        // evaluation (the namespace it reads does not exist).
        let policy = RateLimitPolicy::from_config(serde_json::json!({
            "requests_per_second": 0.001,
            "burst": 1,
            "key": "no_such_namespace.field"
        }))
        .unwrap();
        let enforcer =
            RateLimitEnforcer::new(Arc::new(policy), "err-key.example").expect("parses fine");
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();

        let mut first = request_context("err-key.example");
        assert!(matches!(
            enforcer.enforce(&req, &mut first).await.unwrap(),
            PolicyDecision::Allow
        ));
        // Second request, same client identity: the error bucket is a
        // real bucket, so the burst of 1 is spent.
        let mut second = request_context("err-key.example");
        assert!(
            matches!(
                enforcer.enforce(&req, &mut second).await.unwrap(),
                PolicyDecision::Deny { status: 429, .. }
            ),
            "an evaluation error must keep rate limiting, not switch it off"
        );
        assert!(
            CEL_KEY_ERROR_BUCKET_PREFIX.ends_with(':'),
            "the prefix has to be unmistakable in a log line"
        );
    }

    #[tokio::test]
    async fn bad_context_short_circuits_with_deny() {
        let cfg = serde_json::json!({"requests_per_second": 1.0, "burst": 1});
        let policy: RateLimitPolicy = serde_json::from_value(cfg).expect("default rate-limit");
        let enforcer = RateLimitEnforcer::new(Arc::new(policy), "bad-context.example")
            .expect("no key expression to compile");
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();
        let mut wrong: i32 = 0;
        let decision = enforcer.enforce(&req, &mut wrong).await.unwrap();
        match decision {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Deny(500), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn production_enforcer_records_an_allowed_decision() {
        let metric_policy = "*.rate-limit-allow-metric.example";
        let enforcer = one_request_enforcer(metric_policy);
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();
        let mut ctx = request_context("customer-42.rate-limit-allow-metric.example");
        let before = decision_count(metric_policy, "allow");

        assert!(matches!(
            enforcer.enforce(&req, &mut ctx).await.unwrap(),
            PolicyDecision::Allow
        ));
        assert_eq!(decision_count(metric_policy, "allow"), before + 1);
    }

    #[tokio::test]
    async fn production_enforcer_records_a_route_throttle_decision() {
        let metric_policy = "*.rate-limit-deny-metric.example";
        let enforcer = one_request_enforcer(metric_policy);
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();
        let mut first = request_context("customer-1.rate-limit-deny-metric.example");
        assert!(matches!(
            enforcer.enforce(&req, &mut first).await.unwrap(),
            PolicyDecision::Allow
        ));
        let before = decision_count(metric_policy, "throttle_route");

        let mut second = request_context("customer-2.rate-limit-deny-metric.example");
        assert!(matches!(
            enforcer.enforce(&req, &mut second).await.unwrap(),
            PolicyDecision::Deny { status: 429, .. }
        ));
        assert_eq!(decision_count(metric_policy, "throttle_route"), before + 1);
    }
}
