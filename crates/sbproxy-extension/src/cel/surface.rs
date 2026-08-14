// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! What each config site offers a CEL expression, and the config-load
//! check that holds it to that.
//!
//! Seven places in a config accept CEL, and each builds its own evaluation
//! context. They overlap but are not equal: a `transform: cel` gets
//! `request.headless_signal`, a `policy: expression` does not; a
//! `policy: expression` gets `principal`, a `transform: cel` does not.
//! Nothing declared that, so an expression naming a binding its site
//! never populates compiled fine and missed at evaluation. On
//! `rate_limit.key` the miss landed in the `__cel_key_error__` bucket,
//! which degrades bucketing rather than failing, so it could run in
//! production indefinitely without anyone noticing.
//!
//! [`CelSurface`] names the sites and declares what each offers.
//! [`CelSurface::validate`] refuses, at config load, an expression that
//! reaches for anything else, and names the site, the path, and what is
//! actually available.
//!
//! # Why the check reads paths rather than root identifiers
//!
//! The obvious implementation asks the `cel` crate for the variables a
//! program references and checks them against a per-site set. It has no
//! teeth here. The shared builders expose only eight roots (`agent`,
//! `connection`, `envelope`, `features`, `jwt`, `principal`, `request`,
//! `response`), and every interesting difference between the sites is a
//! *field of `request`*: `trust_tier`, `tls`, `ml_classification`,
//! `aipref`, `kya`, `headless_signal` are all stamped into that one map
//! by separate `populate_*` calls. A root-level check sees `request` on
//! both sides and passes everything. (`custom_log` is the exception
//! that proves it, with seven roots of its own and a `request` that is
//! not the shared one.)
//!
//! So [`referenced_paths`] walks the AST itself and reports dotted paths
//! two levels deep.
//!
//! # Why the walk is scope-aware
//!
//! `cel`'s own [`references`](cel::Program::references) cannot be used
//! for this, and the reason is worth stating because it is a silent
//! wrong answer rather than a missing feature. Its walker descends into
//! a comprehension body without removing the variable that body binds,
//! so `request.headers.all(k, k != "x")` reports `k` as a free
//! variable. Checking that against a declared set would refuse every
//! expression using `all`, `exists`, `map`, `filter`, or `exists_one`,
//! which is to say most non-trivial ones. Configs that work today would
//! stop loading on upgrade.
//!
//! [`referenced_paths`] therefore tracks binding scope and subtracts
//! `iter_var`, `iter_var2`, and `accu_var` for the duration of the
//! bodies that can see them.

use std::collections::BTreeSet;

use cel::common::ast::{EntryExpr, Expr, IdedExpr};

/// A config site that accepts a CEL expression.
///
/// Each variant declares the bindings its site populates.
///
/// The declarations are hand-written, and only two of them are held to
/// the code by a test: `REQUEST_BASE` against `build_request_context`,
/// and [`Self::PolicyAssertion`] against `build_response_context`. The
/// per-site `populate_*` lists are not, because the sequence of
/// `populate_*` calls lives at the call site rather than in this crate.
/// So when you add a `populate_*` call to a site, add its binding here
/// in the same change. Nothing will fail if you forget; the binding
/// will simply be refused, and the operator will be told to use
/// something the config already supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CelSurface {
    /// `policy: expression`, the widest surface.
    PolicyExpression,
    /// `policy: assertion`, evaluated after the response is available.
    PolicyAssertion,
    /// `transform: cel` header rules.
    TransformCel,
    /// `rate_limit.key`, evaluated to produce a bucket key.
    RateLimitKey,
    /// A `custom_log` field with `engine: cel`.
    CustomLogField,
    /// A forward rule's `when:` predicate.
    ///
    /// The narrowest surface, and deliberately so. Forward rules match
    /// during routing, before authentication, identity enrichment, the
    /// TLS fingerprint pass, and the classifiers have run, so none of
    /// what those produce exists yet. It gets the request as it
    /// arrived and nothing else.
    ForwardRuleWhen,
    /// `waf` policy `persistent_block` with `track_by: cel`.
    ///
    /// Shares [`Self::RateLimitKey`]'s bindings exactly, because it
    /// shares its evaluator: `resolve_block_key` in
    /// `builtin_enforcers/waf.rs` calls `rate_limit_key_from_cel`. It
    /// stays a separate variant only so a diagnostic names the WAF
    /// rather than a rate limit the operator did not write.
    WafPersistent,
    /// An `ai_proxy` action's `ai_policy.expression`.
    ///
    /// The one surface whose whole vocabulary is a single namespace:
    /// the gateway-computed `ai` decision view. Nothing request-shaped
    /// is populated, so `request.*` here is a typo to refuse at load,
    /// not a binding that reads empty.
    AiPolicy,
    /// An `ai_proxy` action's `ai_routing_policy.expression` (WOR-2366).
    ///
    /// Shares [`Self::AiPolicy`]'s vocabulary exactly: the same
    /// gateway-computed `ai` decision view, no request-shaped bindings.
    /// It is a distinct site so a routing policy and a security policy
    /// each get their own label and can diverge later without one reading
    /// the other's empty bindings.
    AiRouting,
}

/// Bindings shared by every site that starts from `build_request_context`.
const REQUEST_BASE: &[&str] = &[
    "connection.remote_ip",
    "jwt.claims",
    "request.headers",
    "request.host",
    "request.method",
    "request.path",
    "request.query",
    "request.time",
    "request.unix_nanos",
];

impl CelSurface {
    /// The operator-facing name of this site, as it appears in config.
    pub const fn label(self) -> &'static str {
        match self {
            Self::PolicyExpression => "policy `expression`",
            Self::PolicyAssertion => "policy `assertion`",
            Self::TransformCel => "transform `cel`",
            Self::RateLimitKey => "policy `rate_limiting` key",
            Self::CustomLogField => "custom log field",
            Self::ForwardRuleWhen => "forward rule `when`",
            Self::WafPersistent => "waf persistent rule",
            Self::AiPolicy => "ai_policy `expression`",
            Self::AiRouting => "ai_routing_policy `expression`",
        }
    }

    /// Every binding this site populates, as dotted paths.
    ///
    /// A path here is a prefix, not a leaf: `request.headers` admits
    /// `request.headers["x-api-key"]` because what lives under it is
    /// request data rather than a fixed schema.
    pub fn available(self) -> Vec<&'static str> {
        let mut paths: Vec<&'static str> = match self {
            Self::PolicyExpression => vec![
                "agent",
                "features",
                "principal",
                // Stamped by `populate_agent_detect_namespace`, which is
                // a different map from the `agent_*` scalars below.
                // `request.agent.headless_score` is the documented
                // headless-detection gate.
                "request.agent",
                "request.agent_class",
                "request.agent_id",
                "request.agent_id_source",
                "request.agent_purpose",
                "request.agent_rdns_hostname",
                "request.agent_vendor",
                "request.aipref",
                "request.kya",
                "request.ml_classification",
                "request.tls",
                "request.trust_tier",
            ],
            Self::PolicyAssertion => vec!["request.trust_tier", "response"],
            // Nothing beyond the base. Everything else in this module's
            // vocabulary is stamped by a pass that has not run yet at
            // routing time, so declaring any of it would promise a
            // binding that reads empty rather than one that reads
            // wrong, which is the harder failure to debug.
            Self::ForwardRuleWhen => Vec::new(),
            // Deliberately without `REQUEST_BASE`. The transform's
            // request half is a placeholder: `build_response_eval_context`
            // calls `build_request_context("GET", "/", &HeaderMap::new(),
            // None, None, "")`, so `request.method` is always `"GET"`,
            // the headers are always empty, and `connection.remote_ip`
            // is a missing key that errors. Declaring those would
            // promise bindings that silently evaluate to a placeholder,
            // which is the failure this module exists to end rather
            // than one to inherit.
            Self::TransformCel => vec![
                "agent",
                "request.agent_class",
                "request.agent_id",
                "request.agent_id_source",
                "request.agent_purpose",
                "request.agent_rdns_hostname",
                "request.agent_vendor",
                "request.headless_signal",
                "request.tls",
                "response",
            ],
            // Both of these run through `rate_limit_key_from_cel`, so
            // one list serves them. Splitting it would let the two
            // drift apart while the evaluator stayed shared.
            Self::RateLimitKey | Self::WafPersistent => {
                vec!["envelope", "features", "request.key_id"]
            }
            // The evaluator sets exactly one variable: `ai`, from
            // `AiDecisionView::to_cel`. See ai-policy-cel.md. The routing
            // policy reads the same decision view.
            Self::AiPolicy | Self::AiRouting => vec!["ai"],
            // custom_log builds its own JSON context rather than using
            // the shared builders, which is why its shape is unlike the
            // rest. It is the only site with `attribution` and the only
            // one whose `request` has no `time`.
            Self::CustomLogField => vec![
                "attribution",
                "client_ip",
                "model",
                "provider",
                "request.headers",
                "request.host",
                "request.method",
                "request.path",
                "request.query",
                "response.status",
                "tenant_id",
                "tokens_in",
                "tokens_out",
            ],
        };
        if self.uses_shared_request_context() {
            paths.extend_from_slice(REQUEST_BASE);
        }
        paths.sort_unstable();
        paths.dedup();
        paths
    }

    /// Whether this site builds a real request context with the
    /// request's own method, path, headers, and peer.
    ///
    /// Two sites do not, for different reasons. `custom_log` assembles
    /// a `serde_json::Value` of its own and never calls the shared
    /// builder. `transform: cel` calls it with placeholder arguments,
    /// so the bindings exist but describe no actual request.
    const fn uses_shared_request_context(self) -> bool {
        !matches!(
            self,
            Self::CustomLogField | Self::TransformCel | Self::AiPolicy | Self::AiRouting
        )
    }

    /// Refuse an expression that reaches for a binding this site does
    /// not populate.
    ///
    /// `site` is the specific config entry, as passed to
    /// [`CompiledCel::compile`](super::compiled::CompiledCel::compile);
    /// it leads the message so the operator can find the expression.
    /// [`Self::label`] names the surface class the entry belongs to.
    ///
    /// # Errors
    ///
    /// Returns the offending paths and the bindings that are available,
    /// so the operator can fix the expression without reading the
    /// populate calls.
    pub fn validate(self, site: &str, source: &str, program: &cel::Program) -> Result<(), String> {
        let available = self.available();
        let unknown: Vec<String> = referenced_paths(program)
            .into_iter()
            .filter(|path| !is_available(path, &available))
            .collect();
        if unknown.is_empty() {
            return Ok(());
        }
        // `referenced_paths` returns a BTreeSet, so this is already
        // sorted and the message is stable across runs.
        let offending = unknown.join(", ");
        let offered = available.join(", ");
        Err(format!(
            "{site}: expression {source:?} references {offending}, which {label} does not \
             provide. Available here: {offered}",
            label = self.label(),
        ))
    }
}

/// Whether `path` is covered by one of the `available` declarations.
///
/// Matching runs in both directions, and both are load bearing:
///
/// * A declaration can be a prefix of the reference. `request.headers`
///   admits `request.headers.authorization`, because the fields under it
///   are request data rather than a schema this module could enumerate.
/// * A reference can be a prefix of a declaration. Naming bare `request`
///   is fine wherever any `request.*` is populated, which is what an
///   expression like `has(request.method)` or a map-valued comparison
///   does.
fn is_available(path: &str, available: &[&'static str]) -> bool {
    available
        .iter()
        .any(|candidate| is_prefix(candidate, path) || is_prefix(path, candidate))
}

/// Whether `prefix` is `value` or a dot-separated ancestor of it.
///
/// Compares segment-wise so `request.host` is not treated as a prefix of
/// `request.hostname`.
fn is_prefix(prefix: &str, value: &str) -> bool {
    if prefix == value {
        return true;
    }
    value
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('.'))
}

/// Dotted paths a compiled program reads, up to two segments deep,
/// with comprehension-bound names removed.
///
/// Two segments is the useful depth: it is where the sites differ, and
/// anything deeper is data rather than contract. See the module docs for
/// why this does not delegate to `cel`'s own reference walker.
pub fn referenced_paths(program: &cel::Program) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    walk(program.expression(), &mut Vec::new(), &mut found);
    found
}

/// Collect free paths from `node`, treating everything in `bound` as
/// locally bound rather than a context lookup.
fn walk(node: &IdedExpr, bound: &mut Vec<String>, found: &mut BTreeSet<String>) {
    match &node.expr {
        Expr::Unspecified | Expr::Literal(_) => {}
        Expr::Ident(name) => {
            if let Some(path) = free_root(name, bound) {
                found.insert(path);
            }
        }
        Expr::Select(select) => {
            // `a.b.c` nests as Select(Select(Ident(a), b), c). Resolve
            // the whole chain here so the path is reported once at the
            // depth we care about, rather than as a bare root.
            if let Some(path) = select_path(node, bound) {
                found.insert(path);
                return;
            }
            walk(&select.operand, bound, found);
        }
        Expr::Call(call) => {
            // `request["trust_tier"]` parses as a call to `_[_]`, not as
            // a Select, so without this it would report a bare
            // `request` and slip through: every surface populates some
            // `request.*`, and a bare root matches any of them. Bracket
            // notation is what the header docs steer operators toward,
            // so the hole would have been the common shape rather than
            // an exotic one.
            if let Some(path) = index_path(call, bound) {
                found.insert(path);
                return;
            }
            if let Some(target) = &call.target {
                walk(target, bound, found);
            }
            for arg in &call.args {
                walk(arg, bound, found);
            }
        }
        Expr::List(list) => {
            for element in &list.elements {
                walk(element, bound, found);
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                walk_entry(&entry.expr, bound, found);
            }
        }
        Expr::Struct(structure) => {
            for entry in &structure.entries {
                walk_entry(&entry.expr, bound, found);
            }
        }
        Expr::Comprehension(comprehension) => {
            // The range and the accumulator seed are evaluated before
            // the loop names exist, so they see the outer scope only.
            walk(&comprehension.iter_range, bound, found);
            walk(&comprehension.accu_init, bound, found);

            let depth = bound.len();
            bound.push(comprehension.iter_var.clone());
            if let Some(second) = &comprehension.iter_var2 {
                bound.push(second.clone());
            }
            bound.push(comprehension.accu_var.clone());
            walk(&comprehension.loop_cond, bound, found);
            walk(&comprehension.loop_step, bound, found);
            walk(&comprehension.result, bound, found);
            bound.truncate(depth);
        }
    }
}

/// Walk a map or struct entry.
fn walk_entry(entry: &EntryExpr, bound: &mut Vec<String>, found: &mut BTreeSet<String>) {
    match entry {
        EntryExpr::StructField(field) => walk(&field.value, bound, found),
        EntryExpr::MapEntry(pair) => {
            walk(&pair.key, bound, found);
            walk(&pair.value, bound, found);
        }
    }
}

/// The `root.field` path for a select chain, when it bottoms out in a
/// free identifier. `None` when the chain is rooted in a bound name or
/// in something that is not an identifier at all, such as
/// `[1, 2].size()`.
fn select_path(node: &IdedExpr, bound: &[String]) -> Option<String> {
    let Expr::Select(select) = &node.expr else {
        return None;
    };
    match &select.operand.expr {
        Expr::Ident(root) => {
            let root = free_root(root, bound)?;
            Some(format!("{root}.{}", select.field))
        }
        // Deeper than two segments: report the first two and stop, since
        // that is the depth the surface contract is written at.
        Expr::Select(_) => select_path(&select.operand, bound),
        _ => None,
    }
}

/// The `root.key` path for `root["key"]`, when the index is a string
/// literal over a free identifier.
///
/// `None` for anything else, including a computed index like
/// `request[header_name]`, whose key is not knowable at config load.
/// Those fall through to the ordinary walk and report the bare root.
fn index_path(call: &cel::common::ast::CallExpr, bound: &[String]) -> Option<String> {
    if call.func_name != "_[_]" {
        return None;
    }
    // `_[_]` is a global call, so operand and index are both args.
    let [operand, index] = call.args.as_slice() else {
        return None;
    };
    let Expr::Ident(root) = &operand.expr else {
        return None;
    };
    let root = free_root(root, bound)?;
    match &index.expr {
        Expr::Literal(cel::common::ast::LiteralValue::String(key)) => {
            Some(format!("{root}.{}", key.inner()))
        }
        _ => None,
    }
}

/// The identifier as a path, unless it is comprehension-bound or one of
/// the parser's internal `@`-prefixed accumulator names.
fn free_root(name: &str, bound: &[String]) -> Option<String> {
    if name.starts_with('@') || bound.iter().any(|entry| entry == name) {
        return None;
    }
    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(source: &str) -> Vec<String> {
        let program = cel::Program::compile(source).expect("test expression compiles");
        referenced_paths(&program).into_iter().collect()
    }

    #[test]
    fn reports_a_two_segment_path() {
        assert_eq!(paths(r#"request.method == "GET""#), ["request.method"]);
    }

    #[test]
    fn reports_the_root_when_an_expression_names_one() {
        assert_eq!(paths("size(principal) > 0"), ["principal"]);
    }

    #[test]
    fn truncates_a_deeper_path_to_two_segments() {
        assert_eq!(paths("request.tls.ja4 == \"t13d\""), ["request.tls"]);
    }

    #[test]
    fn drops_a_comprehension_variable() {
        // The regression this whole module exists to avoid: `k` is bound
        // by `all`, and reporting it would refuse the expression.
        assert_eq!(
            paths(r#"request.headers.all(k, k != "x-evil")"#),
            ["request.headers"]
        );
    }

    #[test]
    fn drops_nested_and_shadowing_comprehension_variables() {
        assert_eq!(
            paths(r#"principal.roles.map(r, r).exists(r, r == "admin")"#),
            ["principal.roles"]
        );
    }

    #[test]
    fn keeps_a_free_path_used_inside_a_comprehension_body() {
        // Binding `k` must not swallow the real lookup beside it.
        assert_eq!(
            paths("request.headers.all(k, k != request.trust_tier)"),
            ["request.headers", "request.trust_tier"]
        );
    }

    #[test]
    fn reports_nothing_for_an_expression_over_literals() {
        assert!(paths("[1, 2, 3].map(n, n * 2).size() > 0").is_empty());
    }

    #[test]
    fn reads_map_keys_and_values() {
        assert_eq!(
            paths(r#"{request.method: features.debug}.size() > 0"#),
            ["features.debug", "request.method"]
        );
    }

    #[test]
    fn a_prefix_match_does_not_run_past_a_segment_boundary() {
        assert!(is_prefix("request.host", "request.host"));
        assert!(is_prefix("request.host", "request.host.inner"));
        assert!(
            !is_prefix("request.host", "request.hostname"),
            "`host` must not admit `hostname`"
        );
    }

    #[test]
    fn accepts_an_expression_within_its_surface() {
        let source = r#"request.trust_tier == "named""#;
        let program = cel::Program::compile(source).expect("compiles");
        CelSurface::PolicyExpression
            .validate("policy `expression`", source, &program)
            .expect("trust_tier is populated for policy expressions");
    }

    #[test]
    fn refuses_a_binding_the_surface_does_not_populate() {
        // The bug in the wild: `headless_signal` is a transform-time
        // binding, and naming it from a policy expression evaluated to a
        // miss rather than an error.
        let source = "request.headless_signal.detected";
        let program = cel::Program::compile(source).expect("compiles");
        let error = CelSurface::PolicyExpression
            .validate("policy `expression`", source, &program)
            .expect_err("headless_signal is not a policy-expression binding");
        assert!(error.contains("policy `expression`"), "{error}");
        assert!(error.contains("request.headless_signal"), "{error}");
        assert!(
            error.contains("request.trust_tier"),
            "the error should list what is available: {error}"
        );
    }

    #[test]
    fn refuses_a_transform_binding_named_from_an_assertion() {
        let source = "request.tls.ja4 != \"\"";
        let program = cel::Program::compile(source).expect("compiles");
        CelSurface::PolicyAssertion
            .validate("policy `assertion` (no-5xx)", source, &program)
            .expect_err("assertions do not populate tls");
    }

    #[test]
    fn the_waf_key_offers_exactly_what_the_rate_limit_key_offers() {
        // They share `rate_limit_key_from_cel`. If someone widens one
        // evaluator without the other, this is the test that says so.
        assert_eq!(
            CelSurface::WafPersistent.available(),
            CelSurface::RateLimitKey.available()
        );
    }

    #[test]
    fn the_ai_routing_surface_offers_exactly_what_ai_policy_offers() {
        // Both read the same gateway-computed `ai` decision view. If one
        // is widened without the other, a routing policy and a security
        // policy would see different vocabularies at the same phase.
        assert_eq!(
            CelSurface::AiRouting.available(),
            CelSurface::AiPolicy.available()
        );
    }

    #[test]
    fn the_waf_key_accepts_the_request_bindings_its_evaluator_builds() {
        // Guards the refusal that would have shipped: declaring this
        // surface empty would have broken every `track_by: cel` config.
        let source = r#"request.headers["x-api-key"]"#;
        let program = cel::Program::compile(source).expect("compiles");
        CelSurface::WafPersistent
            .validate("waf policy `persistent_block` key", source, &program)
            .expect("the waf key builds a full request context");
    }

    #[test]
    fn a_comprehension_expression_survives_validation() {
        // Guards the upgrade hazard directly: this is valid config today
        // and must keep loading.
        let source = r#"request.headers.all(k, k != "x-evil")"#;
        let program = cel::Program::compile(source).expect("compiles");
        CelSurface::PolicyExpression
            .validate("policy `expression`", source, &program)
            .expect("a macro over request.headers must remain loadable");
    }

    /// Every `root` and `root.field` path a built context actually
    /// carries, in the same shape [`CelSurface::available`] declares.
    fn actual_paths(ctx: &crate::cel::CelContext) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (root, value) in &ctx.variables {
            match value {
                crate::cel::CelValue::Map(fields) if !fields.is_empty() => {
                    for field in fields.keys() {
                        out.insert(format!("{root}.{field}"));
                    }
                }
                _ => {
                    out.insert(root.clone());
                }
            }
        }
        out
    }

    #[test]
    fn the_shared_request_base_matches_what_the_builder_produces() {
        // The dangerous drift direction. If `build_request_context`
        // gains a binding and `REQUEST_BASE` does not, five of the six
        // surfaces refuse an expression that would have evaluated
        // correctly, and the operator is told to use something the
        // config already supports. Declaring by hand is only safe with
        // a test that reads the real thing.
        let ctx = crate::cel::context::build_request_context(
            "GET",
            "/v1/models",
            &http::HeaderMap::new(),
            Some("limit=10"),
            Some("203.0.113.7"),
            "api.example.com",
        );
        let actual = actual_paths(&ctx);
        let declared: BTreeSet<String> = REQUEST_BASE.iter().map(|p| (*p).to_owned()).collect();
        assert_eq!(
            actual, declared,
            "build_request_context and REQUEST_BASE have diverged"
        );
    }

    #[test]
    fn the_assertion_surface_covers_what_the_response_builder_produces() {
        // `build_response_context` layers the response onto the request
        // base, so the assertion surface has to declare both halves.
        let ctx = crate::cel::context::build_response_context(
            "GET",
            "/v1/models",
            &http::HeaderMap::new(),
            None,
            None,
            "api.example.com",
            200,
            &http::HeaderMap::new(),
            Some(1024),
        );
        let declared = CelSurface::PolicyAssertion.available();
        for path in actual_paths(&ctx) {
            assert!(
                is_available(&path, &declared),
                "build_response_context produces {path}, which the assertion surface does not \
                 declare, so an expression reading it would be refused"
            );
        }
    }

    #[test]
    fn the_agent_detect_map_is_a_policy_expression_binding() {
        // Regression for a refusal that would have broken production.
        // `populate_agent_detect_namespace` stamps `request.agent.*`,
        // which is a different map from the `request.agent_*` scalars,
        // and `request.agent.headless_score` is the gate documented in
        // headless-detection.md. Omitting it here refused a documented
        // config at load, and no CI lane would have caught it: the
        // reproduction lives in an e2e test and in a doc YAML, neither
        // of which the PR lane compiles.
        for source in [
            "request.agent.score < 80",
            "request.agent.headless_score < 50",
        ] {
            let program = cel::Program::compile(source).expect("compiles");
            CelSurface::PolicyExpression
                .validate("policy `expression`", source, &program)
                .expect("the agent-detect map is populated for policy expressions");
        }
    }

    #[test]
    fn the_transform_surface_does_not_promise_a_placeholder_request() {
        // `build_response_eval_context` builds its request half from
        // literals, so these evaluate to a placeholder rather than to
        // the request. Refusing is the honest answer; declaring them
        // would hand the operator a binding that always says "GET".
        for source in [
            r#"request.method == "POST""#,
            r#"request.headers["x-tenant"] != """#,
            r#"connection.remote_ip != """#,
        ] {
            let program = cel::Program::compile(source).expect("compiles");
            CelSurface::TransformCel
                .validate("transform `cel`", source, &program)
                .expect_err("the transform request context is a placeholder");
        }
    }

    #[test]
    fn the_rate_limit_key_declares_only_the_field_that_exists() {
        // `populate_resolved_key_id` inserts `key_id` and nothing else.
        // `request.name` and `request.weight` were declared for a while
        // and exist nowhere in the codebase; accepting them meant a key
        // that loaded clean and then bucketed every request under
        // `__cel_key_error__`, which is the exact bug being fixed.
        let program = cel::Program::compile("request.key_id").expect("compiles");
        CelSurface::RateLimitKey
            .validate("policy `rate_limiting` key", "request.key_id", &program)
            .expect("key_id is populated");

        for source in ["request.weight", "request.name"] {
            let program = cel::Program::compile(source).expect("compiles");
            CelSurface::RateLimitKey
                .validate("policy `rate_limiting` key", source, &program)
                .expect_err("no populate call stamps this");
        }
    }

    #[test]
    fn bracket_notation_is_checked_like_a_dotted_path() {
        // `request["headless_signal"]` parses as a call to `_[_]`, not
        // as a Select, so a walk that only understood Select reported a
        // bare `request` and let it through. Bracket notation is what
        // the header documentation steers operators toward, so this was
        // the common shape rather than an exotic one.
        assert_eq!(
            paths(r#"request["trust_tier"]"#),
            ["request.trust_tier"],
            "a string index should resolve to the same path as a select"
        );
        let source = r#"request["headless_signal"]"#;
        let program = cel::Program::compile(source).expect("compiles");
        CelSurface::PolicyExpression
            .validate("policy `expression`", source, &program)
            .expect_err("bracket notation must not bypass the check");
    }

    #[test]
    fn a_computed_index_falls_back_to_the_root_rather_than_guessing() {
        // The key is not knowable at config load, so the indexed path
        // cannot be resolved and the bare root is reported instead.
        // That keeps it permissive, which is the right direction to
        // fail when the alternative is refusing a config over a key we
        // cannot read. The expression *inside* the brackets is still a
        // real lookup and is still checked.
        assert_eq!(
            paths(r#"request[request.method]"#),
            ["request", "request.method"]
        );
    }

    #[test]
    fn the_forward_rule_surface_refuses_anything_a_later_pass_produces() {
        // The operator-visible half of this surface. Routing runs before
        // the passes that stamp these, so naming one has to be a
        // config-load error rather than an expression that reads empty
        // and routes traffic somewhere nobody chose.
        for source in [
            r#"request.trust_tier == "named""#,
            "request.tls.trustworthy",
            "features.debug",
            "principal.sub != \"\"",
        ] {
            let program = cel::Program::compile(source).expect("compiles");
            CelSurface::ForwardRuleWhen
                .validate("forward rule `r` when", source, &program)
                .expect_err("{source} is not available during routing");
        }
    }

    #[test]
    fn the_forward_rule_surface_accepts_the_request_as_it_arrived() {
        for source in [
            r#"request.path.startsWith("/v1")"#,
            r#"request.headers["x-tenant"] == "acme""#,
            r#"connection.remote_ip != """#,
        ] {
            let program = cel::Program::compile(source).expect("compiles");
            CelSurface::ForwardRuleWhen
                .validate("forward rule `r` when", source, &program)
                .expect("the request base is populated during routing");
        }
    }

    #[test]
    fn custom_log_offers_its_own_shape() {
        let available = CelSurface::CustomLogField.available();
        assert!(available.contains(&"attribution"));
        assert!(available.contains(&"tokens_in"));
        assert!(
            !available.contains(&"request.time"),
            "custom_log builds its own context and has no request.time"
        );
    }
}
