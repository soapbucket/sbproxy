//! Emit an OpenAPI 3.0 document describing the routes a gateway config exposes.
//!
//! Walks a [`sbproxy_config::CompiledConfig`] snapshot and produces an
//! OpenAPI 3.0 JSON document covering paths, methods, parameters, security
//! schemes, response codes, CORS, and cache directives. Buyers consume the
//! emitted spec with standard tooling (Postman, Swagger UI, ReadMe.io,
//! Stainless, etc.).
//!
//! # Mapping
//!
//! | Source                                        | OpenAPI target                                |
//! |-----------------------------------------------|-----------------------------------------------|
//! | `CompiledOrigin.hostname`                     | `servers[].url`                               |
//! | Forward rule `template` matcher               | `paths` key (template syntax verbatim)        |
//! | Forward rule `exact` matcher                  | `paths` key                                   |
//! | Forward rule `prefix` matcher                 | `paths` key + `x-sbproxy-prefix-match: true`  |
//! | Forward rule `regex` matcher                  | `x-sbproxy-regex-path` extension only         |
//! | `allowed_methods` entry OpenAPI 3.0 can name  | `Operation` per method                        |
//! | `allowed_methods` entry it cannot             | `x-sbproxy-unrepresentable-methods`, one entry per method and host |
//! | `CompiledOrigin.hostname`, per operation      | `servers[]` on the operation                  |
//! | Matcher `header` / `query` / `body` / `method` / `when` | `x-sbproxy-match` extension, shape only |
//! | Rule-level `parameters`                       | `parameters[]` per operation                  |
//! | `CompiledOrigin.auth_config`                  | `securitySchemes` + `security`                |
//! | `CompiledOrigin.response_cache.*_status`      | `responses` keys                              |
//! | `CompiledOrigin.error_pages`                  | `responses` keys                              |
//! | `CompiledOrigin.cors`                         | `x-sbproxy-cors` extension                    |
//! | `deprecation:` block (rule, else origin)      | `deprecated: true` + `x-sbproxy-sunset` / `x-sbproxy-successor` |
//! | Two rules on one path and method              | first wins + `x-sbproxy-alternate-operations` + `x-sbproxy-collisions` |
//!
//! Plugin-extensible auth types we don't recognize round-trip into an
//! `x-sbproxy-auth-type` extension and skip the `security` requirement so
//! the doc still validates.
//!
//! # Fidelity
//!
//! The document is a contract, so it says less rather than saying
//! something untrue. Two cases would otherwise make it lie. An
//! `allowed_methods` entry OpenAPI 3.0 has no Path Item field for
//! (`CONNECT`, `PROPFIND`, a custom token) is listed under
//! `x-sbproxy-unrepresentable-methods` instead of being folded onto a
//! verb the gateway would answer with a 405. Two forward rules that
//! resolve to the same path and method keep whichever the config
//! declares first, which within one origin is also the rule the runtime
//! matches first, and park the loser under the path item's
//! `x-sbproxy-alternate-operations` with a summary in the top-level
//! `x-sbproxy-collisions` array rather than overwriting it.
//!
//! # What this document does not carry
//!
//! Every byte here is public. `/.well-known/openapi.json` is served
//! without authentication to anyone who can reach the port, so nothing
//! the operator would not hand a stranger goes into it. That rules out
//! matcher values: a shared-secret routing header, an internal query
//! token, and the text of a `when:` predicate naming internal
//! infrastructure are all config, not contract.
//! `x-sbproxy-match` therefore publishes the field a rule looks at and
//! the comparison it performs, never what the comparison is against, and
//! nothing that reverses to the value goes in its place. The
//! `match_shape` helper carries the reasoning, including why the
//! discriminator that keeps two such rules apart is a counter rather
//! than a digest.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sbproxy_config::{CompiledConfig, RawForwardRule};
use serde_json::{json, Map, Value};

/// The verbs an origin with an empty `allowed_methods` is described as
/// serving.
///
/// Seven, not the eight OpenAPI names: an empty allowlist installs no
/// method check at all, so the honest answer is "whatever the upstream
/// takes" and any list is a guess. This one under-describes such an
/// origin rather than publishing a `trace` operation nobody asked for.
const DEFAULT_METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];

/// A place where the emitted document could not say what the config says.
///
/// Emission never resolves one of these by guessing, so the document is
/// not wrong; what the document cannot do is get an operator's
/// attention. Every case here is a property of the config rather than of
/// a request, so a config-reload path can log the whole list once and be
/// done.
///
/// That is why [`build`] itself stays silent. It runs on every fetch of
/// `/.well-known/openapi.json`, an unauthenticated endpoint, so a warn
/// in there is a log-flood primitive any client can pull. Reload runs
/// once per config change and can afford to say all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionWarning {
    /// Stable token naming the case, suitable as a log field:
    /// `collision`, `shadowed-annotation`, or `unrepresentable-method`.
    pub kind: &'static str,
    /// The `paths` key the problem sits on.
    pub path: String,
    /// One sentence saying what the document could not express and what
    /// it published instead.
    pub detail: String,
}

impl std::fmt::Display for EmissionWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}: {}", self.kind, self.path, self.detail)
    }
}

/// Build an OpenAPI 3.0 document from a compiled config snapshot.
///
/// When `host_filter` is `Some(host)`, only origins whose hostname matches
/// the filter are emitted - used by the per-host `/.well-known/openapi.json`
/// endpoint. When `None`, every configured origin is included.
pub fn build(snapshot: &CompiledConfig, host_filter: Option<&str>) -> Value {
    build_document(snapshot, host_filter).0
}

/// Everything a config reload would want to warn about in one pass over
/// the whole snapshot.
///
/// Same walk [`build`] does, over every origin rather than one host,
/// discarding the document and keeping the diagnostics. Sharing the walk
/// is the point: a separate scan could disagree with what the document
/// actually published, and then the warning would be the wrong shape of
/// wrong.
///
/// Empty means the document says everything the config says.
pub fn emission_warnings(snapshot: &CompiledConfig) -> Vec<EmissionWarning> {
    build_document(snapshot, None).1
}

fn build_document(
    snapshot: &CompiledConfig,
    host_filter: Option<&str>,
) -> (Value, Vec<EmissionWarning>) {
    // --- Top-level info ---
    let mut spec = Map::new();
    spec.insert("openapi".to_string(), Value::String("3.0.3".to_string()));
    spec.insert(
        "info".to_string(),
        json!({
            "title": "SoapBucket Gateway",
            "description": "Routes exposed by this SoapBucket gateway, derived from its live configuration. \
                Coverage is bounded by what the gateway config knows: path templates, methods, declared \
                parameters, auth schemes, and known response codes. Upstream request/response bodies are \
                not described here unless declared explicitly.",
            "version": snapshot_version(snapshot),
        }),
    );

    // --- Servers ---
    let servers: Vec<Value> = snapshot
        .origins
        .iter()
        .filter(|o| host_filter.is_none_or(|h| h == o.hostname.as_str()))
        .map(|o| {
            json!({
                "url": format!("https://{}", o.hostname),
                "description": format!("Origin {}", o.origin_id),
            })
        })
        .collect();
    if !servers.is_empty() {
        spec.insert("servers".to_string(), Value::Array(servers));
    }

    // --- Paths + per-origin securitySchemes ---
    let mut paths = Map::new();
    let mut security_schemes = Map::new();
    // Operations and path-level annotations that lost a first-wins
    // contest. Collected across every origin and published whole, so an
    // operator reads the losses off the document instead of diffing it
    // against the config that produced it.
    let mut collisions: Vec<Value> = Vec::new();
    // The same losses, plus the unrepresentable verbs, in the form a
    // reload-time caller logs. Never published.
    let mut warnings: Vec<EmissionWarning> = Vec::new();
    // Distinct condition sets seen under each published match shape, in
    // first-appearance order. The index into one of these vectors is
    // what `x-sbproxy-match` publishes as `variant`; the fingerprints
    // themselves carry matcher values and never leave this function.
    let mut variants: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for origin in &snapshot.origins {
        if let Some(h) = host_filter {
            if h != origin.hostname.as_str() {
                continue;
            }
        }

        // Auth scheme for this origin (if any), keyed by scheme name we
        // synthesize from the origin id so distinct origins can declare
        // distinct auth without collisions. A list-form block is an OR
        // of providers, and OpenAPI's `security` array is natively an
        // OR of requirement objects, so each entry becomes its own
        // scheme and its own single-scheme requirement. The scalar form
        // keeps its exact prior scheme name.
        let security_requirement = origin.auth_config.as_ref().and_then(|auth| {
            let entries: Vec<&Value> = match auth.as_array() {
                Some(list) => list.iter().collect(),
                None => vec![auth],
            };
            let single = entries.len() == 1;
            let mut requirements = Vec::new();
            for (index, entry) in entries.into_iter().enumerate() {
                let scheme_name = if single {
                    format!("{}_auth", origin.origin_id)
                } else {
                    format!("{}_auth_{index}", origin.origin_id)
                };
                if let Some(scheme) = map_auth(entry, &scheme_name) {
                    security_schemes.insert(scheme_name.clone(), scheme);
                    let mut req = Map::new();
                    req.insert(scheme_name, Value::Array(Vec::new()));
                    requirements.push(Value::Object(req));
                }
            }
            if requirements.is_empty() {
                None
            } else {
                Some(Value::Array(requirements))
            }
        });

        // Methods to emit per path, split into the ones OpenAPI 3.0 can
        // name and the ones it cannot. A non-empty allowlist is the
        // exact set the request path enforces with a 405, so it maps
        // across verbatim.
        let mut methods: Vec<&str> = Vec::new();
        let mut unrepresentable: Vec<String> = Vec::new();
        if origin.allowed_methods.is_empty() {
            methods.extend(DEFAULT_METHODS);
        } else {
            for method in &origin.allowed_methods {
                match openapi_path_item_verb(method) {
                    Some(verb) => {
                        if !methods.contains(&verb) {
                            methods.push(verb);
                        }
                    }
                    None => {
                        let token = method.as_str();
                        if !unrepresentable.iter().any(|m| m.as_str() == token) {
                            unrepresentable.push(token.to_string());
                        }
                    }
                }
            }
        }

        // Walk forward rules. Each rule's matchers become path keys; the
        // rule's parameters apply to every operation under those paths.
        for rule_json in &origin.forward_rules {
            let rule: RawForwardRule = match serde_json::from_value(rule_json.clone()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping malformed forward rule during OpenAPI emission");
                    continue;
                }
            };

            // WOR-2565: which deprecation announcement covers this
            // rule's operations. The rule's own block wins; the
            // origin-scope block covers rules without one. The rule
            // block re-compiles from its raw form here (config compile
            // already validated it, so a failure means a hand-built
            // snapshot; skip the mark rather than the whole rule).
            let rule_deprecation = rule
                .deprecation
                .as_ref()
                .and_then(|raw| sbproxy_config::compile_deprecation(raw, "openapi emission").ok());
            let deprecation = rule_deprecation.as_ref().or(origin.deprecation.as_ref());

            for matcher in &rule.rules {
                let (path_key, extensions) = match path_key_for_matcher(matcher) {
                    Some(v) => v,
                    None => continue,
                };
                let path_item = paths
                    .entry(path_key.as_str())
                    .or_insert_with(|| Value::Object(Map::new()));
                let path_obj = path_item.as_object_mut().expect("path item is object");
                for (k, v) in extensions {
                    // First wins here too. Two matchers can resolve to
                    // one path key (two regexes whose synthetic keys
                    // collapse together), and a later one silently
                    // rewriting the earlier one's annotation would make
                    // the key describe a rule it did not come from.
                    match path_obj.get(&k).cloned() {
                        Some(kept) if kept != v => {
                            warnings.push(EmissionWarning {
                                kind: "shadowed-annotation",
                                path: path_key.clone(),
                                detail: format!(
                                    "{k} describes the first rule on this key; a later rule's \
                                     value for it was not published"
                                ),
                            });
                            collisions.push(json!({
                                "path": path_key,
                                "extension": k,
                                "kept": kept,
                                "dropped": v,
                            }));
                        }
                        Some(_) => {}
                        None => {
                            path_obj.insert(k, v);
                        }
                    }
                }

                // Verbs this origin serves that the path item has no
                // field for. Several origins can share a path key, and
                // only one of them may serve the verb, so each entry
                // names the host it came from the way the operations do.
                // A bare list would have the all-hosts document claiming
                // a verb against a host that answers it with a 405,
                // which is the same lie the split set out to remove.
                if !unrepresentable.is_empty() {
                    let listed = path_obj
                        .entry("x-sbproxy-unrepresentable-methods")
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Some(list) = listed.as_array_mut() {
                        for token in &unrepresentable {
                            let entry = json!({
                                "method": token,
                                "servers": [{ "url": format!("https://{}", origin.hostname) }],
                            });
                            if !list.contains(&entry) {
                                list.push(entry);
                                warnings.push(EmissionWarning {
                                    kind: "unrepresentable-method",
                                    path: path_key.clone(),
                                    detail: format!(
                                        "{} serves {token}, which OpenAPI 3.0 has no path item \
                                         field for; it is listed under \
                                         x-sbproxy-unrepresentable-methods and has no operation",
                                        origin.hostname
                                    ),
                                });
                            }
                        }
                    }
                }

                // One matcher, one set of conditions, however many
                // methods hang off it. The shape is what gets published;
                // the fingerprint stays here and only decides which
                // `variant` number the shape carries.
                let conditions = match_shape(matcher).map(|mut shape| {
                    let shape_key = Value::Object(shape.clone()).to_string();
                    let fingerprint = match_fingerprint(matcher);
                    let seen = variants.entry(shape_key).or_default();
                    let already = seen.iter().position(|f| *f == fingerprint);
                    let index = match already {
                        Some(index) => index,
                        None => {
                            seen.push(fingerprint);
                            seen.len() - 1
                        }
                    };
                    shape.insert("variant".to_string(), Value::from(index + 1));
                    Value::Object(shape)
                });

                for method in &methods {
                    let mut op = Map::new();
                    op.insert(
                        "summary".to_string(),
                        Value::String(format!(
                            "{} via forward rule on {}",
                            method.to_uppercase(),
                            origin.hostname
                        )),
                    );
                    op.insert(
                        "operationId".to_string(),
                        Value::String(operation_id(
                            origin.origin_id.as_str(),
                            method,
                            &rule.origin.id,
                        )),
                    );
                    // The all-hosts document flattens every origin into
                    // one `paths` map, so the top-level `servers` list
                    // reads as though every host serves every path.
                    // Scoping the operation to its own origin says which
                    // one actually does, in OpenAPI's own vocabulary.
                    op.insert(
                        "servers".to_string(),
                        json!([{ "url": format!("https://{}", origin.hostname) }]),
                    );
                    if let Some(conditions) = &conditions {
                        op.insert("x-sbproxy-match".to_string(), conditions.clone());
                    }
                    if !rule.parameters.is_empty() {
                        op.insert(
                            "parameters".to_string(),
                            serde_json::to_value(&rule.parameters).unwrap_or(Value::Array(vec![])),
                        );
                    }
                    op.insert("responses".to_string(), build_responses(origin));
                    if let Some(sec) = &security_requirement {
                        op.insert("security".to_string(), sec.clone());
                    }
                    // WOR-2565: Zalando rule 187, deprecation reflected
                    // in the spec. The extensions carry the exact wire
                    // values the response filter stamps, so the emitted
                    // spec and the headers can never disagree.
                    if let Some(dep) = deprecation {
                        op.insert("deprecated".to_string(), Value::Bool(true));
                        if let Some(sunset) = dep.sunset_header.as_ref() {
                            op.insert(
                                "x-sbproxy-sunset".to_string(),
                                Value::String(sunset.clone()),
                            );
                        }
                        if let Some(successor) = dep.successor.as_ref() {
                            op.insert(
                                "x-sbproxy-successor".to_string(),
                                Value::String(successor.clone()),
                            );
                        }
                    }
                    insert_operation(
                        path_obj,
                        &path_key,
                        method,
                        Value::Object(op),
                        &mut collisions,
                        &mut warnings,
                    );
                }
            }
        }

        // CORS captured as an extension since OpenAPI 3.0 has no native
        // vocabulary for it.
        //
        // Unresolved, and deliberately left alone here rather than
        // quietly narrowed: this serializes the whole block, and
        // `allowed_origins` is a list an operator can fill with internal
        // hostnames. A browser only ever learns the one entry that
        // matched its own `Origin`, so publishing the list on an
        // unauthenticated endpoint hands over names a caller would
        // otherwise have to guess. That is weaker than the matcher
        // values `match_shape` withholds (names, not secrets) and it
        // predates the fidelity work, so changing it is its own change
        // with its own compatibility question for consumers already
        // reading the extension. Anything new added to this block should
        // be weighed against that, not waved through because CORS is
        // already here.
        if let Some(cors) = &origin.cors {
            spec.entry("x-sbproxy-cors")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(obj) = spec
                .get_mut("x-sbproxy-cors")
                .and_then(|v| v.as_object_mut())
            {
                obj.insert(
                    origin.hostname.to_string(),
                    serde_json::to_value(cors).unwrap_or(Value::Null),
                );
            }
        }
    }

    spec.insert("paths".to_string(), Value::Object(paths));
    if !collisions.is_empty() {
        spec.insert("x-sbproxy-collisions".to_string(), Value::Array(collisions));
    }
    if !security_schemes.is_empty() {
        let mut components = Map::new();
        components.insert(
            "securitySchemes".to_string(),
            Value::Object(security_schemes),
        );
        spec.insert("components".to_string(), Value::Object(components));
    }

    (Value::Object(spec), warnings)
}

/// Render a built spec as pretty-printed JSON.
pub fn render_json(spec: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(spec)?)
}

/// Render a built spec as YAML.
pub fn render_yaml(spec: &Value) -> anyhow::Result<String> {
    Ok(serde_yaml::to_string(spec)?)
}

// --- Helpers ---

fn snapshot_version(_snapshot: &CompiledConfig) -> String {
    // Origin set fingerprint would belong here, but the compiled config
    // itself does not carry the runtime config_revision (that lives on
    // CompiledPipeline). Callers who want to surface the live revision
    // can override this field after building the spec.
    "1.0.0".to_string()
}

/// The Path Item Object field an HTTP method lands in, if it has one.
///
/// OpenAPI 3.0 fixes eight operation fields on a Path Item, and that is
/// the whole set. `CONNECT`, `PROPFIND`, and any other token
/// `http::Method` accepts have no field, so they return `None`. The
/// caller reports those rather than folding them onto a verb: the
/// request path enforces `allowed_methods` exactly, with a 405 for
/// anything outside it, so an emitted `get` for a `PROPFIND`-only origin
/// published a method the gateway refuses and hid the one it serves.
fn openapi_path_item_verb(method: &http::Method) -> Option<&'static str> {
    Some(match *method {
        http::Method::GET => "get",
        http::Method::POST => "post",
        http::Method::PUT => "put",
        http::Method::PATCH => "patch",
        http::Method::DELETE => "delete",
        http::Method::HEAD => "head",
        http::Method::OPTIONS => "options",
        http::Method::TRACE => "trace",
        _ => return None,
    })
}

/// Place one operation on a path item, keeping the first that claims a
/// method.
///
/// Several rules can resolve to the same path and method: two origins in
/// an all-hosts document, or two rules on one origin separated by a
/// header, query, body, or `when` condition that OpenAPI has no field
/// for. Config order settles it instead of letting the last writer take
/// the key, which within one origin is the rule the runtime matches
/// first. A byte-identical repeat is a no-op. Anything else keeps
/// the incumbent, parks the loser under `x-sbproxy-alternate-operations`
/// so the operation is still readable, and records the pair in
/// `collisions` so a reader does not have to diff two operation objects
/// to find out what happened.
fn insert_operation(
    path_obj: &mut Map<String, Value>,
    path_key: &str,
    method: &str,
    op: Value,
    collisions: &mut Vec<Value>,
    warnings: &mut Vec<EmissionWarning>,
) {
    if !path_obj.contains_key(method) {
        path_obj.insert(method.to_string(), op);
        return;
    }
    if path_obj.get(method) == Some(&op) {
        // The same operation reached this key twice. Nothing was lost,
        // so there is nothing to report.
        return;
    }
    let kept_id = path_obj
        .get(method)
        .and_then(|kept| kept.get("operationId"))
        .cloned()
        .unwrap_or(Value::Null);
    let dropped_id = op.get("operationId").cloned().unwrap_or(Value::Null);
    warnings.push(EmissionWarning {
        kind: "collision",
        path: path_key.to_string(),
        detail: format!(
            "two forward rules resolve to {method}; {} holds the operation and {} is published \
             under x-sbproxy-alternate-operations, where standard tooling will not read it",
            kept_id.as_str().unwrap_or("an unnamed operation"),
            dropped_id.as_str().unwrap_or("an unnamed operation"),
        ),
    });
    collisions.push(json!({
        "path": path_key,
        "method": method,
        "emitted": kept_id,
        "alternate": dropped_id,
    }));
    let alternates = path_obj
        .entry("x-sbproxy-alternate-operations")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(list) = alternates.as_array_mut() {
        list.push(op);
    }
}

/// What a matcher looks at and how it compares, with none of the values
/// it compares against.
///
/// OpenAPI 3.0 can express a path and a method and nothing else about
/// routing, so two rules on one path that differ only in a header, a
/// query parameter, a JSON body field, a method restriction, or a CEL
/// predicate would emit as one operation. The document has to say
/// something about those conditions or the collision logic cannot tell a
/// genuine duplicate from a second rule worth keeping.
///
/// What it must not say is the value. `/.well-known/openapi.json` is
/// unauthenticated, and operators route on shared-secret headers,
/// internal query tokens, body fields carrying customer identifiers, and
/// `when:` predicates that name internal hosts. Publishing
/// `{"header": {"name": "x-partner-token", "value": "the real token"}}`
/// hands the routing credential to anyone who can fetch the spec, which
/// is the whole internet. So the extension carries the field name and
/// the comparison kind (`exact`, `prefix`, `present`) and stops there.
/// A `when:` predicate reduces to the single fact that one applies.
///
/// Methods are the exception, carried verbatim. Config load refuses a
/// `method:` entry that is not a valid HTTP method token, so the field
/// structurally cannot hold operator text, and the verbs are the
/// document's own vocabulary already.
///
/// Shape alone is not enough to keep two rules apart, because two rules
/// that differ only in a header value have the same shape. The caller
/// closes that with `variant`, a counter over the distinct condition
/// sets seen under one shape, in first-appearance order. Equal variants
/// mean equal conditions, different variants mean different ones, and
/// that is the entire bit `insert_operation` needs.
///
/// The counter is scoped to one built document, so the same rule can
/// hold `variant: 1` in its host's document and `variant: 2` in the
/// all-hosts one, where an earlier origin claimed the first number for a
/// different value. Comparing variants across two documents says
/// nothing; comparing them inside one is the whole contract.
///
/// A truncated digest of the value would be the other way to number
/// them, and it is rejected deliberately. It is stable under insertion,
/// which a counter is not, but it is also an offline oracle: anyone
/// holding the document can confirm a guessed token without ever sending
/// a request, at whatever rate their hardware allows and with no
/// rate limit or log line in the way. That is the disclosure this
/// function exists to prevent, only slower. A counter says two values
/// differ and says nothing whatever about either one.
fn match_shape(matcher: &sbproxy_config::ForwardRuleMatcher) -> Option<Map<String, Value>> {
    let mut shape = Map::new();
    if let Some(header) = &matcher.header {
        shape.insert(
            "header".to_string(),
            json!({
                "name": header.name,
                "compare": comparison(header.value.as_deref(), header.prefix.as_deref()),
            }),
        );
    }
    if let Some(query) = &matcher.query {
        shape.insert(
            "query".to_string(),
            json!({
                "name": query.name,
                "compare": comparison(query.value.as_deref(), None),
            }),
        );
    }
    if let Some(body) = &matcher.body {
        shape.insert(
            "body".to_string(),
            json!({
                "pointer": body.pointer,
                "compare": comparison(body.value.as_deref(), body.prefix.as_deref()),
            }),
        );
    }
    if let Some(method) = &matcher.method {
        shape.insert("method".to_string(), condition_json(method));
    }
    if matcher.when.is_some() {
        shape.insert("when".to_string(), Value::String("cel".to_string()));
    }
    if shape.is_empty() {
        None
    } else {
        Some(shape)
    }
}

/// Which comparison a matcher performs, given its two optional operands.
///
/// `value` wins over `prefix` here because it wins in the matcher: both
/// `HeaderMatcher` and `BodyMatcher` document `prefix` as ignored when
/// `value` is set. Neither one set means the rule fires on presence.
fn comparison(value: Option<&str>, prefix: Option<&str>) -> &'static str {
    match (value, prefix) {
        (Some(_), _) => "exact",
        (None, Some(_)) => "prefix",
        (None, None) => "present",
    }
}

/// The matcher's full condition set, values included, as one string.
///
/// This never reaches the document. It is the key the caller counts
/// distinct values under, so it has to see everything two rules could
/// differ by, including every part `match_shape` withholds. Two rules
/// with an identical fingerprint are the same route written twice and
/// dedupe; two rules with different fingerprints get different `variant`
/// numbers and stay two operations.
fn match_fingerprint(matcher: &sbproxy_config::ForwardRuleMatcher) -> String {
    let mut fields = Map::new();
    if let Some(header) = &matcher.header {
        fields.insert("header".to_string(), condition_json(header));
    }
    if let Some(query) = &matcher.query {
        fields.insert("query".to_string(), condition_json(query));
    }
    if let Some(body) = &matcher.body {
        fields.insert("body".to_string(), condition_json(body));
    }
    if let Some(method) = &matcher.method {
        fields.insert("method".to_string(), condition_json(method));
    }
    if let Some(when) = &matcher.when {
        fields.insert("when".to_string(), Value::String(when.clone()));
    }
    Value::Object(fields).to_string()
}

/// One matcher condition as JSON, or `null` if it will not serialize.
///
/// A matcher that cannot serialize is a hand-built snapshot rather than
/// anything config compilation produces. `null` keeps the caller
/// deterministic without inventing a value; two such matchers then
/// fingerprint alike and dedupe, which under-reports rather than
/// over-reports.
fn condition_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn operation_id(origin_id: &str, method: &str, rule_origin_id: &Option<String>) -> String {
    let suffix = rule_origin_id.as_deref().unwrap_or("default");
    format!(
        "{}_{}_{}",
        origin_id.replace([':', '/', ' '], "_"),
        method,
        suffix.replace([':', '/', ' '], "_")
    )
}

/// Convert a forward-rule matcher into an OpenAPI `paths` key plus any
/// path-level extensions to attach. Returns `None` for matchers that do
/// not yield a meaningful path entry (e.g. shorthand `match:` is treated
/// as a prefix here too).
fn path_key_for_matcher(
    matcher: &sbproxy_config::ForwardRuleMatcher,
) -> Option<(String, Vec<(String, Value)>)> {
    if let Some(path) = &matcher.path {
        if let Some(template) = &path.template {
            return Some((template.clone(), Vec::new()));
        }
        if let Some(regex) = &path.regex {
            // Regex matchers cannot map to a standard OpenAPI paths key.
            // Surface them under a synthetic path keyed on the pattern so
            // the doc remains valid, plus an extension flagging the source.
            return Some((
                format!("/__regex__/{}", regex.replace('/', "_")),
                vec![(
                    "x-sbproxy-regex-path".to_string(),
                    Value::String(regex.clone()),
                )],
            ));
        }
        if let Some(exact) = &path.exact {
            return Some((exact.clone(), Vec::new()));
        }
        if let Some(prefix) = &path.prefix {
            return Some((
                prefix.clone(),
                vec![("x-sbproxy-prefix-match".to_string(), Value::Bool(true))],
            ));
        }
    }
    if let Some(prefix) = &matcher.match_prefix {
        return Some((
            prefix.clone(),
            vec![("x-sbproxy-prefix-match".to_string(), Value::Bool(true))],
        ));
    }
    None
}

/// Build the `responses` map for an operation from origin-level signals.
///
/// We have three signals that hint at known status codes: cacheable status
/// codes from `response_cache`, status codes referenced by `error_pages`,
/// and a default `200`. We always emit `200` and `default` so the spec is
/// usable even when no signals are present.
fn build_responses(origin: &sbproxy_config::CompiledOrigin) -> Value {
    let mut responses = Map::new();
    responses.insert(
        "200".to_string(),
        json!({ "description": "Successful response" }),
    );

    if let Some(rc) = &origin.response_cache {
        for code in &rc.cacheable_status {
            let key = code.to_string();
            responses
                .entry(key)
                .or_insert_with(|| json!({ "description": format!("HTTP {}", code) }));
        }
    }

    if let Some(pages) = &origin.error_pages {
        for entry in pages {
            for code in entry.status.iter() {
                responses
                    .entry(code.to_string())
                    .or_insert_with(|| json!({ "description": format!("HTTP {}", code) }));
            }
        }
    }

    responses
        .entry("default".to_string())
        .or_insert_with(|| json!({ "description": "Unexpected error" }));

    Value::Object(responses)
}

/// A pluggable mapper from a gateway auth config to an OpenAPI 3.0
/// SecurityScheme.
///
/// SBproxy ships built-in mappers for every auth type the proxy
/// implements. A linked plugin crate registers a mapper for its own auth
/// type via [`inventory::submit!`], and may override a built-in when it
/// wants to publish fuller metadata.
///
/// WOR-2675 rewrote the built-in set. It previously covered three names,
/// two of which the proxy does not implement: `api_keys` (the real type
/// is `api_key`) and `oauth_client_creds` (no inbound provider of any
/// name). Every origin using a shipped auth type therefore published the
/// generic placeholder, telling a client to send `Authorization` when
/// the origin wanted `X-Api-Key`.
///
/// Registration is link-time: any crate compiled into the final binary
/// that submits an entry contributes its mapping. Resolution iterates
/// registered mappers in inventory order; extensions that
/// deliberately want last-word semantics should pick a unique
/// `auth_type` rather than relying on registration order.
pub struct AuthSchemeMapper {
    /// The auth `type:` value this mapper handles (e.g. `"saml"`).
    pub auth_type: &'static str,
    /// Build the SecurityScheme JSON. The closure receives the raw auth
    /// config block and the synthesized scheme name (so it can reference
    /// itself in `x-sbproxy-*` extensions if needed).
    pub map: fn(auth: &Value, scheme_name: &str) -> Value,
}

inventory::collect!(AuthSchemeMapper);

/// Map a gateway auth config to an OpenAPI 3.0 SecurityScheme.
///
/// Resolution order:
/// 1. Registered [`AuthSchemeMapper`] entries with a matching
///    `auth_type` (extension override path).
/// 2. Built-in mappers for the auth types the proxy implements.
/// 3. Generic fallback: `apiKey` placeholder + `x-sbproxy-auth-type`
///    extension so the doc still validates and operators see the
///    original type.
fn map_auth(auth: &Value, scheme_name: &str) -> Option<Value> {
    let auth_type = auth.get("type")?.as_str()?;

    // Registered out-of-tree mappers first.
    for entry in inventory::iter::<AuthSchemeMapper> {
        if entry.auth_type == auth_type {
            return Some((entry.map)(auth, scheme_name));
        }
    }

    // Built-in mappers, one per auth type the proxy implements.
    //
    // Everything these arms read is client-facing on purpose, and that
    // is the rule for anything added here. This document is served
    // unauthenticated on `/.well-known/openapi.json`, so a field only
    // earns its place if a caller cannot use the API without it: a
    // header name is the header the caller has to send, a required
    // scope is what its token has to carry, a KYA issuer is whose token
    // the origin accepts. No arm reads a key, a secret, a client id, an
    // introspection credential, or the address of an internal service,
    // and none should start, with one carve-out stated rather than
    // hidden: `oauth_client_creds` emits its `token_url`, because the
    // OpenAPI `clientCredentials` flow object requires `tokenUrl` and a
    // caller cannot get a token without it. That is a client-facing
    // endpoint by construction, unlike an introspection endpoint, which
    // only the gateway calls. The enterprise mappers this replaces
    // published an `oauth_introspection` endpoint URL and an `ext_authz`
    // service address on exactly this document; those are infrastructure
    // a caller has no use for and an attacker does. If a future auth
    // type needs one of those to be described, describe the shape and
    // leave the value in the config, the way `match_shape` does for
    // matchers.
    Some(match auth_type {
        // `noop` is an origin that challenges nobody. Returning `None`
        // rather than a scheme is what keeps the emitted document from
        // telling a client to send a credential the origin will not
        // look at.
        "noop" => return None,
        "api_key" | "api_keys" => {
            // `header_name` is the shipped field; `header` is what the
            // pre-WOR-2675 mapper read, kept so a plugin registering
            // `api_keys` with the older spelling still emits its header.
            let header = auth
                .get("header_name")
                .or_else(|| auth.get("header"))
                .and_then(|v| v.as_str())
                .unwrap_or("X-Api-Key");
            // The query form is opt-in and, when set, is the second way
            // in. OpenAPI 3.0 cannot express "either of these", so the
            // header is the scheme and the query parameter rides an
            // extension rather than being silently dropped.
            let mut scheme = json!({
                "type": "apiKey",
                "in": "header",
                "name": header,
                "x-sbproxy-auth-type": auth_type,
            });
            if let Some(param) = auth.get("query_param").and_then(|v| v.as_str()) {
                scheme["x-sbproxy-api-key-query-param"] = Value::String(param.to_string());
            }
            scheme
        }
        "basic_auth" => json!({
            "type": "http",
            "scheme": "basic",
            "x-sbproxy-auth-type": auth_type,
        }),
        "digest" => json!({
            "type": "http",
            "scheme": "digest",
            "description": "RFC 7616 digest authentication. The gateway challenges with \
                            SHA-256 unless the origin pinned MD5.",
            "x-sbproxy-auth-type": auth_type,
        }),
        "bearer" | "bearer_token" => {
            let mut scheme = json!({
                "type": "http",
                "scheme": "bearer",
                "x-sbproxy-auth-type": auth_type,
            });
            if auth.get("require_dpop").and_then(Value::as_bool) == Some(true) {
                scheme["description"] = Value::String(
                    "Bearer token bound to a DPoP proof (RFC 9449). Every request must carry \
                     a fresh `DPoP` proof header alongside the token."
                        .to_string(),
                );
                scheme["x-sbproxy-require-dpop"] = Value::Bool(true);
            }
            scheme
        }
        "jwt" => {
            let mut scheme = json!({
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "x-sbproxy-auth-type": auth_type,
            });
            // The audience a caller has to request is client-facing; the
            // JWKS URL the gateway fetches is not.
            if let Some(audience) = auth.get("audience").and_then(|v| v.as_str()) {
                scheme["x-sbproxy-required-audience"] = Value::String(audience.to_string());
            }
            if auth.get("require_dpop").and_then(Value::as_bool) == Some(true) {
                scheme["x-sbproxy-require-dpop"] = Value::Bool(true);
            }
            if auth.get("require_mtls_bound").and_then(Value::as_bool) == Some(true) {
                scheme["x-sbproxy-require-mtls-bound"] = Value::Bool(true);
            }
            scheme
        }
        // `Signature` is not an IANA HTTP authentication scheme, so
        // `{"type":"http","scheme":"signature"}` makes a generated
        // client send `Authorization: Signature ...`, which no RFC 9421
        // verifier reads. What the caller actually sends is a
        // `Signature` header, which `apiKey` expresses exactly.
        "hmac_auth" => json!({
            "type": "apiKey",
            "in": "header",
            "name": "Signature",
            "description": "RFC 9421 HTTP Message Signatures with `hmac-sha256`. Send \
                            `Signature` and `Signature-Input`; a token on its own is not \
                            accepted.",
            "x-sbproxy-auth-type": auth_type,
        }),
        "ldap_auth" | "ldap" => json!({
            "type": "http",
            "scheme": "basic",
            "description": "HTTP Basic credentials, bound against a directory on every \
                            request. A password the directory revokes stops working \
                            immediately.",
            "x-sbproxy-auth-type": auth_type,
        }),
        "bot_auth" | "web_bot_auth" => json!({
            "type": "apiKey",
            "in": "header",
            "name": "Signature",
            "description": "Web Bot Auth: an RFC 9421 message signature from a key in the \
                            gateway's agent directory. Send `Signature`, `Signature-Input`, \
                            and `Signature-Agent`.",
            "x-sbproxy-auth-type": auth_type,
        }),
        "cap" => json!({
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "cap",
            "description": "Crawler Authorization Protocol capability token, carrying its \
                            own path and rate grants.",
            "x-sbproxy-auth-type": auth_type,
        }),
        "oidc" => {
            // The browser login flow, described the way OpenAPI has a
            // vocabulary for. `issuer` is the IdP the origin pins, and
            // its discovery document is public by construction: an
            // OpenID Provider publishes it unauthenticated. The
            // `client_id`, the `client_secret`, and the `cookie_secret`
            // stay out.
            let mut scheme = json!({
                "type": "openIdConnect",
                "description": "OpenID Connect login at the gateway. A browser without a \
                                session cookie is redirected to the IdP and returns with \
                                one; the API is not callable with a bearer token here.",
                "x-sbproxy-auth-type": auth_type,
            });
            match auth.get("issuer").and_then(|v| v.as_str()) {
                Some(issuer) => {
                    scheme["openIdConnectUrl"] = Value::String(format!(
                        "{}/.well-known/openid-configuration",
                        issuer.trim_end_matches('/')
                    ));
                }
                // `openIdConnectUrl` is required on the scheme object,
                // so a block with no issuer would emit an invalid
                // document. Fall back to the shape OpenAPI can express
                // rather than to something that does not validate.
                None => {
                    scheme = json!({
                        "type": "apiKey",
                        "in": "cookie",
                        "name": auth
                            .get("session_cookie_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("__Host-sbproxy_session"),
                        "description": "OpenID Connect session cookie minted by the gateway \
                                        after a browser login.",
                        "x-sbproxy-auth-type": auth_type,
                    });
                }
            }
            scheme
        }
        "forward_auth" | "forward" => json!({
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "The gateway replays each request against an authorization \
                            service it runs. What that service requires is not described \
                            here, because the gateway does not know it.",
            "x-sbproxy-auth-type": auth_type,
        }),
        // WOR-2667 / WOR-2675: the three providers ported out of the
        // enterprise tree.
        "ext_authz" => {
            // The service decides on the headers the origin allowlisted,
            // so those names are precisely what a caller has to send.
            // The service's own address is not published: it is internal
            // infrastructure, and the enterprise mapper's habit of
            // emitting it is not carried over.
            let forwarded: Vec<&str> = auth
                .get("headers_to_forward")
                .and_then(|v| v.as_array())
                .map(|list| list.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut scheme = json!({
                "type": "apiKey",
                "in": "header",
                "name": forwarded.first().copied().unwrap_or("Authorization"),
                "description": "The admission decision is made by an authorization service \
                                the gateway calls. What it accepts is not described here, \
                                because the gateway does not know it.",
                "x-sbproxy-auth-type": auth_type,
            });
            if !forwarded.is_empty() {
                scheme["x-sbproxy-forwarded-headers"] = json!(forwarded);
            }
            scheme
        }
        "oauth_introspection" => {
            let mut scheme = json!({
                "type": "http",
                "scheme": "bearer",
                "description": "Opaque bearer token, validated against the issuing \
                                authorization server on every request the gateway's verdict \
                                cache cannot answer (RFC 7662). A revoked token stops \
                                working without waiting for its expiry.",
                "x-sbproxy-auth-type": auth_type,
            });
            // A caller cannot get in without the right scopes, so they
            // belong here. The introspection endpoint is the gateway's
            // business and stays out.
            if let Some(scopes) = auth.get("required_scopes").and_then(|v| v.as_array()) {
                if !scopes.is_empty() {
                    scheme["x-sbproxy-required-scopes"] = Value::Array(scopes.clone());
                }
            }
            scheme
        }
        "kya" => {
            let mut scheme = json!({
                "type": "apiKey",
                "in": "header",
                "name": "X-Skyfire-KYA",
                "description": "Know Your Agent token: an issuer-signed agent identity. \
                                Send it in `X-Skyfire-KYA`.",
                "x-sbproxy-auth-type": auth_type,
            });
            // Which issuers are trusted, and what balance clears the
            // floor, are both things an agent needs before it can call.
            // Both are public by nature: the issuer URL is one the agent
            // already talks to, and the floor is a number the origin
            // wants advertised.
            let issuers: Vec<&str> = auth
                .get("issuers")
                .and_then(|v| v.as_array())
                .map(|list| {
                    list.iter()
                        .filter_map(|issuer| issuer.get("url").and_then(Value::as_str))
                        .collect()
                })
                .unwrap_or_default();
            if !issuers.is_empty() {
                scheme["x-sbproxy-kya-issuers"] = json!(issuers);
            }
            if let Some(minimum) = auth.get("min_kyab_balance").and_then(Value::as_u64) {
                scheme["x-sbproxy-kya-min-balance"] = json!(minimum);
            }
            scheme
        }
        // Kept, and not because the proxy implements it. No auth type in
        // this workspace produces `oauth_client_creds`: the inbound
        // client-credentials provider the name suggests does not exist,
        // and the outbound client-credentials grant is
        // `outbound_credential`, which the proxy uses to get a token for
        // an upstream and which never appears in an origin's
        // `authentication:` block. WOR-2675 checked whether it collided
        // with the enterprise provider of a similar name and found it
        // did not: that one registers as `oauth_client_credentials` and
        // was not ported, because it admits any bearer token of eight or
        // more characters without verifying it. The arm stays so a
        // linked plugin that does implement an inbound client-credentials
        // type under this name keeps its oauth2 flow object instead of
        // dropping to the placeholder.
        "oauth_client_creds" => {
            let token_url = auth
                .get("token_url")
                .and_then(|v| v.as_str())
                .unwrap_or("https://example.com/token");
            json!({
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": token_url,
                        "scopes": {},
                    }
                },
                "x-sbproxy-auth-type": auth_type,
            })
        }
        // Unknown auth types: emit a placeholder so the doc validates
        // and surface the original type as an extension. When a plugin
        // mapper is linked in, the registered mapper above kicks in
        // instead.
        _ => json!({
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "x-sbproxy-auth-type": auth_type,
            "description": format!(
                "Gateway auth type '{}' has no registered OpenAPI mapper; emitted as a generic API key scheme.",
                auth_type
            ),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_snapshot() -> CompiledConfig {
        let mut host_map = std::collections::HashMap::new();
        host_map.insert(compact_str::CompactString::new("api.example.com"), 0);
        let mut origin = empty_origin("api.example.com", "api");
        origin.allowed_methods = smallvec::smallvec![http::Method::GET, http::Method::POST];
        origin.forward_rules = vec![serde_json::json!({
            "rules": [
                { "path": { "template": "/users/{id}" } },
                { "path": { "exact": "/health" } }
            ],
            "parameters": [
                {
                    "name": "id",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "integer" }
                }
            ],
            "origin": {
                "id": "users-api",
                "action": { "type": "proxy", "url": "http://127.0.0.1/" }
            }
        })];
        CompiledConfig {
            extension_bundles: Default::default(),
            origins: vec![origin],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
        }
    }

    fn empty_origin(host: &str, id: &str) -> sbproxy_config::CompiledOrigin {
        sbproxy_config::CompiledOrigin {
            hostname: compact_str::CompactString::new(host),
            origin_id: compact_str::CompactString::new(id),
            cache_config_fingerprint: compact_str::CompactString::default(),
            workspace_id: compact_str::CompactString::default(),
            tenant_id: compact_str::CompactString::const_new("__default__"),
            action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1/"}),
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            filters: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::smallvec![],
            request_modifiers: smallvec::smallvec![],
            response_modifiers: smallvec::smallvec![],
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            deprecation: None,
            message_signatures: None,
            olp: None,
            web_bot_auth_publish: None,
            idempotency: None,
            timeouts: sbproxy_config::UpstreamTimeouts::default(),
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: std::collections::HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
            observability: None,
            attestation: None,
            owasp_pack_manifest: None,
        }
    }

    #[test]
    fn build_emits_valid_top_level_shape() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        assert_eq!(spec["openapi"], "3.0.3");
        assert!(spec["info"].is_object());
        assert!(spec["paths"].is_object());
        assert!(spec["servers"].is_array());
    }

    #[test]
    fn build_includes_template_path() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/users/{id}"));
        assert!(paths.contains_key("/health"));
    }

    #[test]
    fn build_emits_methods_per_path() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let path = &spec["paths"]["/users/{id}"];
        assert!(path["get"].is_object());
        assert!(path["post"].is_object());
        // Allowed methods only: PUT/PATCH/DELETE not in allowed_methods.
        assert!(path.get("put").is_none());
    }

    #[test]
    fn build_propagates_parameters() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let params = spec["paths"]["/users/{id}"]["get"]["parameters"]
            .as_array()
            .expect("parameters array");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0]["name"], "id");
        assert_eq!(params[0]["in"], "path");
        assert_eq!(params[0]["required"], true);
        assert_eq!(params[0]["schema"]["type"], "integer");
    }

    #[test]
    fn build_filters_by_host() {
        let mut snap = make_minimal_snapshot();
        let mut other = empty_origin("web.example.com", "web");
        other.allowed_methods = smallvec::smallvec![http::Method::GET];
        other.forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/login" } }],
            "origin": { "id": "web-login", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        snap.host_map
            .insert(compact_str::CompactString::new("web.example.com"), 1);
        snap.origins.push(other);

        let spec = build(&snap, Some("web.example.com"));
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/login"));
        assert!(!paths.contains_key("/users/{id}"));
    }

    #[test]
    fn build_emits_security_scheme_for_oauth() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "oauth_client_creds",
            "token_url": "https://auth.example.com/token"
        }));
        let spec = build(&snap, None);
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");
        let scheme = schemes.values().next().expect("at least one scheme");
        assert_eq!(scheme["type"], "oauth2");
        assert_eq!(
            scheme["flows"]["clientCredentials"]["tokenUrl"],
            "https://auth.example.com/token"
        );
    }

    /// WOR-2675. The shipped type is `api_key` and its field is
    /// `header_name`; the pre-WOR-2675 mapper matched `api_keys` and
    /// read `header`, so every origin using the real type published a
    /// generic placeholder telling the caller to send `Authorization`.
    #[test]
    fn build_maps_the_api_key_type_the_proxy_actually_implements() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "api_key",
            "header_name": "X-Acme-Key",
            "api_keys": ["secret"],
            "query_param": "key",
        }));
        let spec = build(&snap, None);
        let scheme = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object")
            .values()
            .next()
            .expect("a scheme")
            .clone();
        assert_eq!(scheme["type"], "apiKey");
        assert_eq!(scheme["in"], "header");
        assert_eq!(scheme["name"], "X-Acme-Key");
        assert_eq!(scheme["x-sbproxy-api-key-query-param"], "key");
        assert!(
            scheme["description"].is_null(),
            "the real type must not fall through to the placeholder: {scheme}"
        );
    }

    /// The document is served unauthenticated. Nothing an operator
    /// configured as a credential may reach it.
    #[test]
    fn no_scheme_publishes_a_secret_from_its_auth_block() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!([
            {"type": "api_key", "header_name": "X-Acme-Key", "api_keys": ["key-material"]},
            {
                "type": "oauth_introspection",
                "introspection_url": "https://idp.internal/introspect",
                "client_id": "sbproxy-gateway",
                "client_secret": "client-secret-material",
                "required_scopes": ["api.read"],
            },
            {"type": "ext_authz", "url": "http://authz.internal:9002/check"},
        ]));
        let rendered = serde_json::to_string(&build(&snap, None)).expect("spec serializes");
        for forbidden in [
            "key-material",
            "client-secret-material",
            "sbproxy-gateway",
            "idp.internal",
            "authz.internal",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} reached an unauthenticated document"
            );
        }
        // The scope, by contrast, is exactly what a caller needs.
        assert!(rendered.contains("api.read"), "{rendered}");
    }

    #[test]
    fn build_maps_oauth_introspection_as_a_bearer_scheme() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "required_scopes": ["api.read", "api.write"],
        }));
        let spec = build(&snap, None);
        let scheme = spec["components"]["securitySchemes"]
            .as_object()
            .expect("schemes")
            .values()
            .next()
            .expect("a scheme")
            .clone();
        assert_eq!(scheme["type"], "http");
        assert_eq!(scheme["scheme"], "bearer");
        assert_eq!(scheme["x-sbproxy-required-scopes"][1], "api.write");
    }

    #[test]
    fn build_maps_ext_authz_to_its_allowlisted_header() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "ext_authz",
            "url": "http://authz.internal:9002/check",
            "headers_to_forward": ["x-tenant", "authorization"],
        }));
        let spec = build(&snap, None);
        let scheme = spec["components"]["securitySchemes"]
            .as_object()
            .expect("schemes")
            .values()
            .next()
            .expect("a scheme")
            .clone();
        assert_eq!(scheme["type"], "apiKey");
        assert_eq!(
            scheme["name"], "x-tenant",
            "the first allowlisted header is what a caller has to send"
        );
        assert_eq!(scheme["x-sbproxy-forwarded-headers"][1], "authorization");
    }

    #[test]
    fn build_maps_kya_with_its_issuers_and_balance_floor() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "kya",
            "issuers": [{"url": "https://api.skyfire.example"}],
            "min_kyab_balance": 1000,
        }));
        let spec = build(&snap, None);
        let scheme = spec["components"]["securitySchemes"]
            .as_object()
            .expect("schemes")
            .values()
            .next()
            .expect("a scheme")
            .clone();
        assert_eq!(scheme["type"], "apiKey");
        assert_eq!(scheme["name"], "X-Skyfire-KYA");
        assert_eq!(
            scheme["x-sbproxy-kya-issuers"][0],
            "https://api.skyfire.example"
        );
        assert_eq!(scheme["x-sbproxy-kya-min-balance"], 1000);
    }

    /// An origin that challenges nobody must not tell a client to send a
    /// credential. Before WOR-2675 `noop` fell through to the generic
    /// placeholder, which published an `Authorization` apiKey
    /// requirement on an origin that does not look at one.
    #[test]
    fn build_emits_no_security_requirement_for_noop() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({"type": "noop"}));
        let spec = build(&snap, None);
        assert!(
            spec["components"]["securitySchemes"]
                .as_object()
                .is_none_or(|schemes| schemes.is_empty()),
            "noop must publish no scheme: {}",
            spec["components"]["securitySchemes"]
        );
        assert!(
            spec["paths"]["/users/{id}"]["get"]["security"].is_null(),
            "noop must attach no security requirement"
        );
    }

    /// Every auth type the proxy dispatches has a mapper, so the generic
    /// placeholder is reserved for names that came from a plugin. A new
    /// built-in provider that forgets its mapper fails here rather than
    /// shipping a document that misdescribes it.
    #[test]
    fn every_built_in_auth_type_has_a_mapper_of_its_own() {
        for auth_type in sbproxy_config::KNOWN_AUTH_TYPES {
            if *auth_type == "noop" {
                // Deliberately mapped to no scheme at all.
                assert!(
                    map_auth(&serde_json::json!({"type": auth_type}), "s").is_none(),
                    "noop must map to no scheme"
                );
                continue;
            }
            let scheme = map_auth(&serde_json::json!({"type": auth_type}), "s")
                .unwrap_or_else(|| panic!("{auth_type} produced no scheme"));
            let description = scheme["description"].as_str().unwrap_or_default();
            assert!(
                !description.contains("has no registered OpenAPI mapper"),
                "{auth_type} falls through to the generic placeholder"
            );
        }
    }

    #[test]
    fn build_unknown_auth_type_falls_through_with_extension() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "custom_plugin_auth"
        }));
        let spec = build(&snap, None);
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");
        let scheme = schemes.values().next().unwrap();
        assert_eq!(scheme["x-sbproxy-auth-type"], "custom_plugin_auth");
        assert_eq!(
            scheme["description"],
            "Gateway auth type 'custom_plugin_auth' has no registered OpenAPI mapper; emitted as a generic API key scheme."
        );
    }

    #[test]
    fn build_emits_one_scheme_per_entry_for_an_auth_composition() {
        // WOR-2517: a list-form `authentication:` block is an OR of
        // providers, which OpenAPI expresses as multiple requirement
        // objects in the `security` array. Each entry gets its own
        // scheme keyed by slot index.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!([
            {"type": "basic_auth"},
            {"type": "oauth_client_creds", "token_url": "https://auth.example.com/token"},
        ]));
        let spec = build(&snap, None);
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");
        assert_eq!(schemes.len(), 2, "one scheme per composition entry");
        let security = spec["paths"]["/users/{id}"]["get"]["security"]
            .as_array()
            .expect("security array");
        assert_eq!(
            security.len(),
            2,
            "two alternative requirements express the OR"
        );
    }

    #[test]
    fn build_marks_prefix_path_with_extension() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "prefix": "/api/" } }],
            "origin": { "id": "api", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        let spec = build(&snap, None);
        assert_eq!(
            spec["paths"]["/api/"]["x-sbproxy-prefix-match"],
            serde_json::json!(true)
        );
    }

    // --- WOR-2565: deprecation marks on emitted operations ---

    fn dep_block(yaml: &str) -> sbproxy_config::CompiledDeprecation {
        sbproxy_config::compile_deprecation(
            &serde_yaml::from_str(yaml).expect("fixture block parses"),
            "test fixture",
        )
        .expect("fixture block compiles")
    }

    #[test]
    fn rule_level_deprecation_marks_its_operations() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].forward_rules = vec![
            serde_json::json!({
                "rules": [{ "path": { "prefix": "/v1/" } }],
                "deprecation": {
                    "deprecated": "2026-09-01",
                    "sunset": "2026-12-31T23:59:59Z",
                    "successor": "https://api.example.com/v2/"
                },
                "origin": { "id": "v1", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
            serde_json::json!({
                "rules": [{ "path": { "prefix": "/v2/" } }],
                "origin": { "id": "v2", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
        ];
        let spec = build(&snap, None);

        let v1 = &spec["paths"]["/v1/"]["get"];
        assert_eq!(v1["deprecated"], serde_json::json!(true));
        // The extensions carry the exact wire values, so the emitted
        // spec and the response headers can never disagree.
        let compiled = dep_block(
            "deprecated: 2026-09-01\nsunset: 2026-12-31T23:59:59Z\nsuccessor: https://api.example.com/v2/\n",
        );
        assert_eq!(
            v1["x-sbproxy-sunset"],
            serde_json::json!(compiled.sunset_header.expect("sunset compiles")),
        );
        assert_eq!(
            v1["x-sbproxy-successor"],
            serde_json::json!("https://api.example.com/v2/")
        );

        // The undeprecated sibling rule stays unmarked.
        let v2 = &spec["paths"]["/v2/"]["get"];
        assert!(v2.get("deprecated").is_none(), "got {v2}");
        assert!(v2.get("x-sbproxy-sunset").is_none());
    }

    #[test]
    fn origin_level_deprecation_marks_every_operation() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].deprecation = Some(dep_block("deprecated: 2026-09-01\n"));
        let spec = build(&snap, None);
        for path in ["/users/{id}", "/health"] {
            for method in ["get", "post"] {
                let op = &spec["paths"][path][method];
                assert_eq!(
                    op["deprecated"],
                    serde_json::json!(true),
                    "{method} {path} must be marked deprecated"
                );
            }
        }
        // No sunset configured: the extension is absent rather than null.
        assert!(spec["paths"]["/health"]["get"]
            .get("x-sbproxy-sunset")
            .is_none());
    }

    #[test]
    fn rule_block_overrides_the_origin_block() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].deprecation = Some(dep_block("deprecated: 2026-01-01\n"));
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/v1/jobs" } }],
            "deprecation": { "deprecated": "2026-09-01", "sunset": "2026-12-31" },
            "origin": { "id": "v1", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        let spec = build(&snap, None);
        let op = &spec["paths"]["/v1/jobs"]["get"];
        assert_eq!(op["deprecated"], serde_json::json!(true));
        let compiled = dep_block("deprecated: 2026-09-01\nsunset: 2026-12-31\n");
        assert_eq!(
            op["x-sbproxy-sunset"],
            serde_json::json!(compiled.sunset_header.expect("sunset compiles")),
        );
    }

    #[test]
    fn no_deprecation_config_emits_no_marks() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let op = &spec["paths"]["/users/{id}"]["get"];
        assert!(op.get("deprecated").is_none(), "got {op}");
    }

    // --- WOR-2617: verbs OpenAPI 3.0 cannot name ---

    fn propfind() -> http::Method {
        http::Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method token")
    }

    #[test]
    fn an_unrepresentable_verb_is_never_emitted_as_a_get_operation() {
        // `allowed_methods: [CONNECT, PROPFIND]` is the exact set the
        // request path enforces, with a 405 for everything else. Folding
        // both onto `get` published a method the gateway refuses, hid the
        // two it serves, and collapsed them onto one key so only the
        // second survived.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::CONNECT, propfind()];
        let spec = build(&snap, None);

        let path = &spec["paths"]["/users/{id}"];
        assert!(path.get("get").is_none(), "got {path}");
        assert!(path.get("post").is_none(), "got {path}");
        // Each entry names the host that serves the verb, the way the
        // operations name theirs.
        assert_eq!(
            path["x-sbproxy-unrepresentable-methods"],
            serde_json::json!([
                { "method": "CONNECT", "servers": [{ "url": "https://api.example.com" }] },
                { "method": "PROPFIND", "servers": [{ "url": "https://api.example.com" }] },
            ])
        );
        // Nothing but the note: the path exists, and the document does
        // not invent an operation to describe it.
        assert_eq!(
            path.as_object().expect("path item object").len(),
            1,
            "got {path}"
        );
    }

    #[test]
    fn a_representable_verb_survives_beside_an_unrepresentable_one() {
        // The repeated GET also pins the dedupe: one operation, not two
        // writes to the same key.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods =
            smallvec::smallvec![http::Method::GET, propfind(), http::Method::GET];
        let spec = build(&snap, None);

        let path = &spec["paths"]["/users/{id}"];
        assert!(path["get"].is_object());
        assert!(path.get("post").is_none(), "got {path}");
        assert_eq!(
            path["x-sbproxy-unrepresentable-methods"],
            serde_json::json!([
                { "method": "PROPFIND", "servers": [{ "url": "https://api.example.com" }] },
            ])
        );
        assert!(
            spec.get("x-sbproxy-collisions").is_none(),
            "a repeated verb is not a collision; got {spec}"
        );
    }

    #[test]
    fn an_unrepresentable_verb_names_only_the_host_that_serves_it() {
        // Two origins share `/docs`. Only one of them allows PROPFIND,
        // and a bare list of verbs on the shared path item would have the
        // all-hosts document claiming PROPFIND against the host that
        // answers it with a 405.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![propfind()];
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/docs" } }],
            "origin": { "id": "api-docs", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];

        let mut other = empty_origin("web.example.com", "web");
        other.allowed_methods = smallvec::smallvec![http::Method::GET];
        other.forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/docs" } }],
            "origin": { "id": "web-docs", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        snap.host_map
            .insert(compact_str::CompactString::new("web.example.com"), 1);
        snap.origins.push(other);

        let spec = build(&snap, None);
        let path = &spec["paths"]["/docs"];
        assert_eq!(
            path["x-sbproxy-unrepresentable-methods"],
            serde_json::json!([
                { "method": "PROPFIND", "servers": [{ "url": "https://api.example.com" }] },
            ]),
            "the verb belongs to api.example.com alone; got {path}"
        );
        // The other host's operation sits on the same path item, which is
        // exactly the ambiguity the attribution resolves.
        assert_eq!(path["get"]["servers"][0]["url"], "https://web.example.com");

        let warnings = emission_warnings(&snap);
        assert_eq!(warnings.len(), 1, "got {warnings:?}");
        assert_eq!(warnings[0].kind, "unrepresentable-method");
        assert_eq!(warnings[0].path, "/docs");
        assert!(
            warnings[0].detail.contains("api.example.com")
                && warnings[0].detail.contains("PROPFIND"),
            "a reload-time warn has to name the host and the verb; got {}",
            warnings[0]
        );
    }

    // --- WOR-2618: two rules resolving to one path and method ---

    #[test]
    fn two_hosts_sharing_path_and_method_keep_both_operations() {
        // The all-hosts document flattens every origin into one `paths`
        // map, so the later origin used to overwrite the earlier one's
        // operation and the document described one of two routes while
        // still listing both servers.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/users" } }],
            "origin": { "id": "api-users", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];

        let mut other = empty_origin("web.example.com", "web");
        other.allowed_methods = smallvec::smallvec![http::Method::GET];
        other.auth_config = Some(serde_json::json!({ "type": "basic_auth" }));
        other.forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/users" } }],
            "origin": { "id": "web-users", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        snap.host_map
            .insert(compact_str::CompactString::new("web.example.com"), 1);
        snap.origins.push(other);

        let spec = build(&snap, None);
        let path = &spec["paths"]["/users"];

        // First in config order keeps the key. These two hosts never
        // compete at request time; the shared key is the all-hosts
        // document flattening them, which is why each operation names
        // the origin that serves it.
        assert_eq!(path["get"]["operationId"], "api_get_api-users");
        assert_eq!(path["get"]["servers"][0]["url"], "https://api.example.com");

        let alternates = path["x-sbproxy-alternate-operations"]
            .as_array()
            .expect("alternate operations array");
        assert_eq!(alternates.len(), 1, "got {path}");
        assert_eq!(alternates[0]["operationId"], "web_get_web-users");
        assert_eq!(
            alternates[0]["servers"][0]["url"],
            "https://web.example.com"
        );

        let collisions = spec["x-sbproxy-collisions"]
            .as_array()
            .expect("collisions array");
        assert_eq!(collisions.len(), 1, "got {spec}");
        assert_eq!(collisions[0]["path"], "/users");
        assert_eq!(collisions[0]["method"], "get");
        assert_eq!(collisions[0]["emitted"], "api_get_api-users");
        assert_eq!(collisions[0]["alternate"], "web_get_web-users");

        // The same loss, in the form a config reload logs once.
        let warnings = emission_warnings(&snap);
        assert_eq!(warnings.len(), 1, "got {warnings:?}");
        assert_eq!(warnings[0].kind, "collision");
        assert_eq!(warnings[0].path, "/users");
        assert!(
            warnings[0].detail.contains("api_get_api-users")
                && warnings[0].detail.contains("web_get_web-users"),
            "the warn has to name both operations; got {}",
            warnings[0]
        );
    }

    #[test]
    fn two_rules_separated_by_a_header_condition_stay_distinguishable() {
        // Both rules name the same child origin id, so without
        // `x-sbproxy-match` the two operations are byte-identical, the
        // conditioned one dedupes away, and the document shows one route
        // where the gateway routes two.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        snap.origins[0].forward_rules = vec![
            serde_json::json!({
                "rules": [{
                    "path": { "exact": "/users" },
                    "header": { "name": "x-beta", "value": "1" }
                }],
                "origin": { "id": "users", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
            serde_json::json!({
                "rules": [{ "path": { "exact": "/users" } }],
                "origin": { "id": "users", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
        ];

        let spec = build(&snap, None);
        let path = &spec["paths"]["/users"];
        assert_eq!(
            path["get"]["x-sbproxy-match"],
            serde_json::json!({
                "header": { "name": "x-beta", "compare": "exact" },
                "variant": 1,
            }),
            "the field and the comparison, never the value it compares against"
        );

        let alternates = path["x-sbproxy-alternate-operations"]
            .as_array()
            .expect("alternate operations array");
        assert_eq!(alternates.len(), 1, "got {path}");
        assert!(
            alternates[0].get("x-sbproxy-match").is_none(),
            "the unconditioned rule is the alternate; got {}",
            alternates[0]
        );
    }

    // --- The document is unauthenticated, so matcher values stay out ---

    #[test]
    fn no_matcher_value_reaches_the_emitted_document() {
        // `/.well-known/openapi.json` needs no credential, so every
        // matcher value in this config is a value handed to anyone who
        // can reach the port: a routing shared secret, an internal query
        // token, a customer identifier in the body, and a CEL predicate
        // naming an internal host.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].expose_openapi = true;
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        snap.origins[0].forward_rules = vec![
            serde_json::json!({
                "rules": [{
                    "path": { "exact": "/partner" },
                    "header": { "name": "x-partner-token", "value": "sk-live-9f3ab2" }
                }],
                "origin": { "id": "partner", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
            serde_json::json!({
                "rules": [{
                    "path": { "exact": "/bearer" },
                    "header": { "name": "authorization", "prefix": "Bearer sk-live-abc" }
                }],
                "origin": { "id": "bearer", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
            serde_json::json!({
                "rules": [{
                    "path": { "exact": "/internal" },
                    "query": { "name": "access", "value": "qtok-77c1" },
                    "body": { "pointer": "/account", "prefix": "acct-secret" },
                    "when": "request.headers['x-src'] == 'vault.internal.corp'"
                }],
                "origin": { "id": "internal", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            }),
        ];

        let spec = build(&snap, Some("api.example.com"));
        let rendered = render_json(&spec).expect("spec renders");
        for secret in [
            "sk-live-9f3ab2",
            "Bearer sk-live-abc",
            "sk-live-abc",
            "qtok-77c1",
            "acct-secret",
            "vault.internal.corp",
            "request.headers",
        ] {
            assert!(
                !rendered.contains(secret),
                "the public document carries {secret}:\n{rendered}"
            );
        }

        // The shape is still there, which is what makes two conditioned
        // rules on one path tellable apart.
        assert_eq!(
            spec["paths"]["/partner"]["get"]["x-sbproxy-match"],
            serde_json::json!({
                "header": { "name": "x-partner-token", "compare": "exact" },
                "variant": 1,
            })
        );
        assert_eq!(
            spec["paths"]["/bearer"]["get"]["x-sbproxy-match"]["header"]["compare"],
            "prefix"
        );
        assert_eq!(
            spec["paths"]["/internal"]["get"]["x-sbproxy-match"],
            serde_json::json!({
                "query": { "name": "access", "compare": "exact" },
                "body": { "pointer": "/account", "compare": "prefix" },
                "when": "cel",
                "variant": 1,
            }),
            "a `when:` predicate reduces to the fact that one applies"
        );
    }

    #[test]
    fn two_rules_differing_only_in_a_header_value_stay_two_operations() {
        // Withholding the value must not cost the document the
        // distinction. These two rules share a path, a method, a child
        // origin id, and a header name, so shape alone would make them
        // byte-identical, the second would read as a duplicate, and the
        // gateway would route two ways where the document showed one.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        let rule = |value: &str| {
            serde_json::json!({
                "rules": [{
                    "path": { "exact": "/tenant" },
                    "header": { "name": "x-tenant", "value": value }
                }],
                "origin": { "id": "tenant", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
            })
        };
        snap.origins[0].forward_rules = vec![rule("tenant-a"), rule("tenant-b")];

        let spec = build(&snap, None);
        let path = &spec["paths"]["/tenant"];
        assert_eq!(path["get"]["x-sbproxy-match"]["variant"], 1);

        let alternates = path["x-sbproxy-alternate-operations"]
            .as_array()
            .expect("two rules, two operations");
        assert_eq!(alternates.len(), 1, "got {path}");
        assert_eq!(
            alternates[0]["x-sbproxy-match"]["variant"], 2,
            "different values, different variant; got {}",
            alternates[0]
        );
        assert_eq!(
            alternates[0]["x-sbproxy-match"]["header"]["name"], "x-tenant",
            "same shape, which is the point"
        );
        assert!(
            spec["x-sbproxy-collisions"].is_array(),
            "the second rule is reported, not swallowed; got {spec}"
        );
        // And still no values.
        let rendered = render_json(&spec).expect("spec renders");
        assert!(!rendered.contains("tenant-a"), "got {rendered}");
        assert!(!rendered.contains("tenant-b"), "got {rendered}");
    }

    #[test]
    fn the_variant_counter_is_scoped_to_one_document() {
        // Two origins, two paths, one shape, two values. The counter runs
        // across the whole document, so the second origin's rule is
        // variant 2 in the all-hosts document and variant 1 in its own
        // host's, which is the caveat the doc states and the reason a
        // variant is only comparable inside one document.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{
                "path": { "exact": "/a" },
                "header": { "name": "x-tenant", "value": "tenant-a" }
            }],
            "origin": { "id": "a", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];

        let mut other = empty_origin("web.example.com", "web");
        other.allowed_methods = smallvec::smallvec![http::Method::GET];
        other.forward_rules = vec![serde_json::json!({
            "rules": [{
                "path": { "exact": "/b" },
                "header": { "name": "x-tenant", "value": "tenant-b" }
            }],
            "origin": { "id": "b", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        snap.host_map
            .insert(compact_str::CompactString::new("web.example.com"), 1);
        snap.origins.push(other);

        let all = build(&snap, None);
        assert_eq!(all["paths"]["/a"]["get"]["x-sbproxy-match"]["variant"], 1);
        assert_eq!(all["paths"]["/b"]["get"]["x-sbproxy-match"]["variant"], 2);

        let web = build(&snap, Some("web.example.com"));
        assert_eq!(web["paths"]["/b"]["get"]["x-sbproxy-match"]["variant"], 1);
        assert!(web["paths"].get("/a").is_none(), "got {web}");
    }

    #[test]
    fn two_regex_matchers_on_one_synthetic_key_keep_the_first_pattern() {
        // The synthetic key rewrites `/` to `_`, so these two patterns
        // land on the same path key. The later one used to retitle the
        // earlier one's extension, leaving the key annotated with a
        // pattern it did not come from.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [
                { "path": { "regex": "^/v1/items" } },
                { "path": { "regex": "^_v1_items" } }
            ],
            "origin": { "id": "items", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];

        let spec = build(&snap, None);
        let path = &spec["paths"]["/__regex__/^_v1_items"];
        assert_eq!(path["x-sbproxy-regex-path"], "^/v1/items");

        let collisions = spec["x-sbproxy-collisions"]
            .as_array()
            .expect("collisions array");
        assert_eq!(collisions.len(), 1, "got {spec}");
        assert_eq!(collisions[0]["extension"], "x-sbproxy-regex-path");
        assert_eq!(collisions[0]["kept"], "^/v1/items");
        assert_eq!(collisions[0]["dropped"], "^_v1_items");

        let warnings = emission_warnings(&snap);
        assert_eq!(warnings.len(), 1, "got {warnings:?}");
        assert_eq!(warnings[0].kind, "shadowed-annotation");
        assert!(
            warnings[0].detail.contains("x-sbproxy-regex-path"),
            "got {}",
            warnings[0]
        );
    }

    #[test]
    fn an_identical_repeat_of_one_operation_is_not_a_collision() {
        // The repeated rule carries a condition, so this also pins the
        // other half of the variant rule: same condition set, same
        // variant, therefore one operation. Only a difference in the
        // withheld value is allowed to split them.
        let mut snap = make_minimal_snapshot();
        snap.origins[0].allowed_methods = smallvec::smallvec![http::Method::GET];
        let rule = serde_json::json!({
            "rules": [{
                "path": { "exact": "/health" },
                "header": { "name": "x-probe", "value": "1" }
            }],
            "origin": { "id": "healthcheck", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        });
        snap.origins[0].forward_rules = vec![rule.clone(), rule];

        let spec = build(&snap, None);
        let path = &spec["paths"]["/health"];
        assert!(path["get"].is_object());
        assert_eq!(
            path["get"]["x-sbproxy-match"],
            serde_json::json!({
                "header": { "name": "x-probe", "compare": "exact" },
                "variant": 1,
            }),
            "the repeat reuses the first variant rather than claiming a second"
        );
        assert!(
            path.get("x-sbproxy-alternate-operations").is_none(),
            "got {path}"
        );
        assert!(spec.get("x-sbproxy-collisions").is_none(), "got {spec}");
        assert!(emission_warnings(&snap).is_empty());
    }

    #[test]
    fn a_config_with_no_conflicts_carries_no_diagnostics() {
        // The diagnostics are additive. A config that emitted a clean
        // document before still emits one, carries none of the new
        // annotations, and produces nothing for a reload to warn about.
        // What it does gain is the per-operation `servers` entry, which
        // is what stops the all-hosts document reading as though every
        // host serves every path.
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        assert!(spec.get("x-sbproxy-collisions").is_none(), "got {spec}");
        assert!(emission_warnings(&snap).is_empty());
        for key in ["/users/{id}", "/health"] {
            let path = &spec["paths"][key];
            assert!(path["get"].is_object(), "got {path}");
            assert!(path["post"].is_object(), "got {path}");
            assert_eq!(
                path["get"]["servers"],
                serde_json::json!([{ "url": "https://api.example.com" }]),
                "got {path}"
            );
            assert!(
                path.get("x-sbproxy-alternate-operations").is_none(),
                "got {path}"
            );
            assert!(
                path.get("x-sbproxy-unrepresentable-methods").is_none(),
                "got {path}"
            );
            assert!(
                path["get"].get("x-sbproxy-match").is_none(),
                "no matcher conditions to report; got {path}"
            );
        }
    }

    #[test]
    fn render_json_round_trips() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let rendered = render_json(&spec).unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["openapi"], "3.0.3");
    }

    #[test]
    fn render_yaml_round_trips() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let yaml = render_yaml(&spec).unwrap();
        assert!(yaml.contains("openapi"));
        assert!(yaml.contains("3.0.3"));
    }
}
