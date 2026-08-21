//! Plan-time semantic validation. Implements step 3 of the
//! ADR (`docs/adr-config-plan-apply.md`): a sync library API that
//! walks a parsed [`ConfigFile`] and produces a list of
//! [`PlanFinding`]s the CLI surfaces under the diff.
//!
//! Three rule families are enforced today:
//!
//! * [`orphan-ref`](validate#orphan-references): a `fallback_origin`
//!   or forward-rule action target names a hostname that is not
//!   present under `origins.*` in the same proposed config.
//! * [`missing-secret`](validate#missing-secrets): a removed
//!   `secret:<name>` reference whose name does not appear under
//!   `proxy.secrets.map` in the proposed config. This diagnostic
//!   support does not make the removed colon form runtime-valid.
//!   Every URI-shaped reference (`secret://`, `secretfile://`,
//!   `vault://`, `awssm://`, `gcpsm://`, `azurekv://`,
//!   `k8ssecret://`) belongs to `compile_config`, which fails the
//!   load when the authority is not declared under
//!   `proxy.secrets.backends` with a matching backend type
//!   (WOR-2227). Plan time adds nothing there and does not look.
//! * [`unknown-type`](validate#unknown-types): an `action`,
//!   `authentication`, `policies[*]`, or `transforms[*]` `type:`
//!   discriminator that names a module not registered in the OSS
//!   built-in catalogs (`KNOWN_ACTION_TYPES`, ...). Operators
//!   running enterprise builds with extra plugins can extend the
//!   catalogs through [`ValidationOptions`].
//!
//! Two smaller rules cover the `proxy:` and `update:` blocks:
//! `update-zero-check-interval`, and `unknown-acme-storage-backend`
//! for an `acme.storage_backend` the proxy has no backend for.
//!
//! The validator never fetches secrets, opens a network socket, or
//! calls into the module crate. Plan-time validation is a structural
//! pass over the parsed [`ConfigFile`] only.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::types::{ConfigFile, RawOriginConfig};

// --- Public types --------------------------------------------------

/// Severity of a single [`PlanFinding`]. `Error` blocks apply; `Warn`
/// surfaces in the report but does not change the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Validator-level error. CLI exits 3 when any `Error` finding is
    /// present in the report.
    Error,
    /// Warning. Surfaces in the report and the text output but does
    /// not change the CLI exit code.
    Warn,
}

/// One semantic-validation finding emitted by [`validate`]. See the
/// module-level docs for the full rule list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFinding {
    /// Severity. See [`Severity`].
    pub severity: Severity,
    /// Stable rule identifier. The set of values is part of the v1
    /// JSON contract; new rules add new ids, existing ids never
    /// rename. Examples: `orphan-fallback-origin`,
    /// `missing-vault-key`, `unknown-action-type`.
    pub rule_id: String,
    /// JSONPath-shaped string rooted at the YAML document, e.g.
    /// `origins.api.example.com.fallback_origin`.
    pub path: String,
    /// Human-readable one-liner. Suitable for the text format and
    /// for log emission.
    pub message: String,
}

/// Caller-supplied catalog overrides. The default
/// (`ValidationOptions::default()`) uses the in-tree built-in
/// catalogs in [`KNOWN_ACTION_TYPES`] etc; enterprise builds that
/// link extra plugin crates can extend the lists by inserting names
/// here.
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// Extra action `type:` names to treat as known.
    pub extra_action_types: Vec<String>,
    /// Extra auth `type:` names to treat as known.
    pub extra_auth_types: Vec<String>,
    /// Extra policy `type:` names to treat as known.
    pub extra_policy_types: Vec<String>,
    /// Extra transform `type:` names to treat as known.
    pub extra_transform_types: Vec<String>,
}

// --- Built-in known-type catalogs ----------------------------------
//
// These mirror the explicit match arms in
// `crates/sbproxy-modules/src/compile.rs`. Plan-time validation
// cannot link the modules crate (it would create a dependency cycle:
// modules already depends on config), so the catalogs are duplicated
// here. Adding a new module type requires adding it both places. The
// duplication is small (a single string per module) and the cost of
// missing one is a `unknown-*-type` warning at plan time, which is
// noisy but not unsafe.

/// Built-in OSS action `type:` names. Mirrors the match arms in
/// `sbproxy_modules::compile_action`.
pub const KNOWN_ACTION_TYPES: &[&str] = &[
    "proxy",
    "redirect",
    "static",
    "echo",
    "mock",
    "beacon",
    "load_balancer",
    "ai_proxy",
    "websocket",
    "grpc",
    "graphql",
    "storage",
    "a2a",
    "mcp",
    "noop",
];

/// Built-in OSS auth `type:` names. Mirrors `sbproxy_modules::compile_auth`.
/// Unknown auth types are downgraded to `Warn` because the modules
/// crate falls through to the inventory-based plugin registry at
/// runtime; the plan-time validator does not see those registrations.
pub const KNOWN_AUTH_TYPES: &[&str] = &[
    "api_key",
    "basic_auth",
    "bearer",
    "bearer_token",
    "jwt",
    "digest",
    "hmac_auth",
    "forward_auth",
    "forward",
    "ldap_auth",
    "ldap",
    "bot_auth",
    "web_bot_auth",
    "cap",
    "oidc",
    "noop",
];

/// Built-in OSS policy `type:` names. Mirrors `sbproxy_modules::compile_policy`,
/// plus `owasp_api_top10` (WOR-2491): a pseudo-policy consumed and
/// removed by `sbproxy_config::owasp_api_pack::expand_owasp_pack`
/// before an origin's policies ever reach `compile_policy`'s
/// type-string match arms. It compiles cleanly as a real origin
/// policy entry, so this plan-time list treats it as one; leaving it
/// out would flag every config that uses the pack with a spurious
/// `unknown-policy-type` error.
pub const KNOWN_POLICY_TYPES: &[&str] = &[
    "rego",
    "rate_limit_budget",
    "rate_limiting",
    "ip_filter",
    "ip_filtering",
    "security_headers",
    "request_limit",
    "request_limiting",
    "csrf",
    "ddos",
    "ddos_protection",
    "waf",
    "sri",
    "expression",
    "assertion",
    "response_assertion",
    "request_validator",
    "body_threat_protection",
    "content_digest",
    "concurrent_limit",
    "concurrent_limiting",
    "ai_crawl_control",
    "pay_per_crawl",
    "object_authz",
    "bola",
    "exposed_credentials",
    "leaked_credentials",
    "page_shield",
    "dlp",
    "openapi_validation",
    "prompt_injection_v2",
    "http_framing",
    "agent_class",
    "a2a",
    // WOR-203 PR 3b: NL-as-a-policy via the LLM-as-judge backend.
    // See `crates/sbproxy-modules/src/policy/semantic_constraint.rs`.
    "semantic_constraint",
    "agent_budget",
    // WOR-2491: see this const's own doc comment above.
    "owasp_api_top10",
];

/// Built-in OSS transform `type:` names. Mirrors `sbproxy_modules::compile_transform`.
pub const KNOWN_TRANSFORM_TYPES: &[&str] = &[
    "json",
    "json_projection",
    "json_schema",
    "template",
    "replace_strings",
    "normalize",
    "encoding",
    "format_convert",
    "payload_limit",
    "discard",
    "sse_chunking",
    "html",
    "optimize_html",
    "html_to_markdown",
    "markdown",
    "css",
    "lua",
    "lua_json",
    "javascript",
    "js_json",
    "wasm",
    "boilerplate",
    "citation_block",
    "json_envelope",
    "cel",
    "a2a_agent_card_rewrite",
    "noop",
];

/// Return built-in policy, transform, and action hook names as deterministic,
/// kind-aware extension reservations.
///
/// Dynamic bundle loaders pass this set to
/// [`crate::extensions::BundleManifest::validate`] before constructing a
/// candidate registry, so a bundle cannot shadow a built-in hook type of
/// any kind, authentication included (WOR-2426).
#[must_use]
pub fn reserved_builtin_hook_names(
) -> std::collections::BTreeSet<(crate::extensions::BundleHookKind, String)> {
    let mut reservations = std::collections::BTreeSet::new();
    reservations.extend(KNOWN_POLICY_TYPES.iter().map(|type_name| {
        (
            crate::extensions::BundleHookKind::Policy,
            (*type_name).to_owned(),
        )
    }));
    reservations.extend(KNOWN_TRANSFORM_TYPES.iter().map(|type_name| {
        (
            crate::extensions::BundleHookKind::Transform,
            (*type_name).to_owned(),
        )
    }));
    reservations.extend(KNOWN_ACTION_TYPES.iter().map(|type_name| {
        (
            crate::extensions::BundleHookKind::Action,
            (*type_name).to_owned(),
        )
    }));
    reservations.extend(KNOWN_AUTH_TYPES.iter().map(|type_name| {
        (
            crate::extensions::BundleHookKind::Auth,
            (*type_name).to_owned(),
        )
    }));
    reservations
}

// --- Public entry point --------------------------------------------

/// Validate the proposed [`ConfigFile`] and return the list of
/// findings in deterministic order. The order is:
///
/// 1. Orphan-ref findings, sorted by origin then by sub-path.
/// 2. Missing-secret findings, sorted by origin then by reference path.
/// 3. Unknown-type findings, sorted by origin then by sub-path.
///
/// Orphan-ref and unknown-type findings emit at `Severity::Error`
/// because they fail the corresponding runtime compile call.
/// Missing-secret findings emit at `Severity::Error` when the proxy
/// has a `secrets:` block configured (the operator has opted into
/// validation) and at `Severity::Warn` when the block is absent (we
/// cannot know whether the value will resolve from the OS env).
pub fn validate(config: &ConfigFile, opts: &ValidationOptions) -> Vec<PlanFinding> {
    let mut findings: Vec<PlanFinding> = Vec::new();

    // Catalogue origin hostnames once; used by orphan-ref checks.
    let known_hosts: BTreeSet<&str> = config.origins.keys().map(|s| s.as_str()).collect();

    // Catalogue secret keys once; used by missing-secret checks.
    let secret_keys: BTreeSet<&str> = config
        .proxy
        .secrets
        .as_ref()
        .map(|s| s.map.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let secrets_block_present = config.proxy.secrets.is_some();

    // Walk origins in sorted order so the finding stream is stable
    // across runs.
    let mut hosts: Vec<&str> = config.origins.keys().map(|s| s.as_str()).collect();
    hosts.sort();

    // -- orphan-ref --
    for host in &hosts {
        let origin = &config.origins[*host];
        check_orphan_refs(host, origin, &known_hosts, &mut findings);
    }

    // -- missing-secret --
    for host in &hosts {
        let origin = &config.origins[*host];
        let json = serde_json::to_value(origin).unwrap_or(serde_json::Value::Null);
        check_missing_secrets(
            &format!("origins.{host}"),
            &json,
            &secret_keys,
            secrets_block_present,
            &mut findings,
        );
    }
    // Also walk the proxy block for secret references in admin /
    // metrics blocks, etc.
    let proxy_json = serde_json::to_value(&config.proxy).unwrap_or(serde_json::Value::Null);
    check_missing_secrets(
        "proxy",
        &proxy_json,
        &secret_keys,
        secrets_block_present,
        &mut findings,
    );

    // -- unknown-type --
    for host in &hosts {
        let origin = &config.origins[*host];
        check_unknown_types(host, origin, opts, &mut findings);
    }

    // -- owasp-api-pack (WOR-2491 review round, M2) --
    for host in &hosts {
        let origin = &config.origins[*host];
        check_owasp_pack_config(host, origin, &mut findings);
    }

    // -- acme --
    check_acme(config.proxy.acme.as_ref(), &mut findings);

    // -- update-config --
    check_update_config(&config.update, &mut findings);

    findings
}

/// Certificate store backends the proxy can actually open, in the order the
/// documentation lists them. Mirrors the match arms in `open_cert_backend`
/// (`crates/sbproxy-tls/src/lib.rs`); plan-time validation cannot link the
/// TLS crate, so the list is duplicated the same way the module catalogs
/// above are.
const KNOWN_ACME_STORAGE_BACKENDS: &[&str] = &[
    "redb", "sqlite", "file", "redis", "s3", "gcs", "azure", "memory",
];

/// Flag an `acme.storage_backend` naming a store the proxy cannot open.
///
/// An error, not a warning. The value used to fall through to an in-memory
/// store, which reads as a healthy proxy that quietly re-issues every
/// certificate on every restart until the CA rate-limits the domain. The
/// runtime now refuses the same value at startup; catching it at plan time
/// means the operator sees a typo in the diff instead of a boot failure.
fn check_acme(acme: Option<&crate::types::AcmeConfig>, out: &mut Vec<PlanFinding>) {
    let Some(acme) = acme else {
        return;
    };
    let backend = acme.storage_backend.as_str();
    if KNOWN_ACME_STORAGE_BACKENDS.contains(&backend) {
        return;
    }
    out.push(PlanFinding {
        severity: Severity::Error,
        rule_id: "unknown-acme-storage-backend".to_string(),
        path: "proxy.acme.storage_backend".to_string(),
        message: format!(
            "acme.storage_backend '{backend}' is not a certificate store backend sbproxy \
             knows how to open; use one of: {}",
            KNOWN_ACME_STORAGE_BACKENDS.join(", ")
        ),
    });
}

/// Flag an `update:` block that turns on the background check but sets a
/// zero interval, which would poll with no delay. A warning, not an error:
/// the field is only consulted when a background check is wired.
fn check_update_config(update: &crate::types::UpdateConfig, out: &mut Vec<PlanFinding>) {
    if update.auto && update.check_interval_secs == 0 {
        out.push(PlanFinding {
            severity: Severity::Warn,
            rule_id: "update-zero-check-interval".to_string(),
            path: "update.check_interval_secs".to_string(),
            message: "update.auto is on but check_interval_secs is 0; set a \
                      non-zero interval (for example 1d) so the background \
                      freshness check does not poll without delay"
                .to_string(),
        });
    }
}

// --- Orphan-ref check ----------------------------------------------

/// Flag origin references that name a hostname not present under
/// `origins.*`. The two emitter sites are:
///
/// * `fallback_origin`: an explicit JSON object whose `url` field is
///   parsed for a host. When the parsed host is not in the origin
///   set we emit `orphan-fallback-origin`.
/// * `forward_rules[*].origin.action`: each forward rule inlines a
///   child `action:` block. When the child action is `proxy` we
///   parse the URL host the same way and emit
///   `orphan-forward-rule-target` if it is missing.
fn check_orphan_refs(
    host: &str,
    origin: &RawOriginConfig,
    known_hosts: &BTreeSet<&str>,
    out: &mut Vec<PlanFinding>,
) {
    if let Some(fallback) = &origin.fallback_origin {
        if let Some(target_host) = extract_host_from_action(fallback) {
            if !target_host.is_empty()
                && !known_hosts.contains(target_host.as_str())
                && is_hostname_like(&target_host)
            {
                out.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "orphan-fallback-origin".to_string(),
                    path: format!("origins.{host}.fallback_origin"),
                    message: format!(
                        "fallback_origin for '{host}' targets host '{target_host}' which is not defined under origins"
                    ),
                });
            }
        }
    }

    for (idx, rule) in origin.forward_rules.iter().enumerate() {
        if let Some(target_host) = extract_host_from_action(&rule.origin.action) {
            if !target_host.is_empty()
                && !known_hosts.contains(target_host.as_str())
                && is_hostname_like(&target_host)
            {
                out.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "orphan-forward-rule-target".to_string(),
                    path: format!("origins.{host}.forward_rules[{idx}].origin.action"),
                    message: format!(
                        "forward_rule for '{host}' targets host '{target_host}' which is not defined under origins"
                    ),
                });
            }
        }
    }
}

/// Pull the host component out of an action JSON value. Returns
/// `None` when the action is not a `proxy` (or otherwise URL-bearing)
/// action, or when the URL cannot be parsed.
fn extract_host_from_action(action: &serde_json::Value) -> Option<String> {
    let url = action.get("url").and_then(|v| v.as_str())?;
    parse_url_host(url)
}

/// Lift the host out of a URL string without depending on a URL
/// crate. Accepts `scheme://host[:port]/path...` and bare hostnames.
fn parse_url_host(url: &str) -> Option<String> {
    let after_scheme = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    // Drop user info before the host.
    let after_userinfo = match after_scheme.rsplit_once('@') {
        Some((_, rest)) => rest,
        None => after_scheme,
    };
    let host = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Reject targets that look like raw IPs or `localhost`. Orphan-ref
/// validation is about cross-origin name references inside the same
/// document, not about validating every URL.
fn is_hostname_like(host: &str) -> bool {
    if host == "localhost" {
        return false;
    }
    // Skip raw IPv4 / IPv6 hosts.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // Heuristic: a hostname-style ref has at least one dot. This
    // skips upstreams like `backend` (Docker DNS) which the operator
    // never intends as an in-document reference.
    host.contains('.')
}

// --- Missing-secret check ------------------------------------------

/// Walk a JSON value tree and emit a finding for each removed
/// `secret:<name>` map reference whose name is not in `secret_keys`.
/// References embedded in arbitrary string fields (e.g. `auth.secret:
/// "secret:my_jwt"`) are caught for migration diagnostics.
///
/// When the proxy has no `secrets:` block at all
/// (`secrets_block_present = false`), missing references downgrade
/// to `Warn` because we cannot verify them against the OS env.
fn check_missing_secrets(
    base_path: &str,
    value: &serde_json::Value,
    secret_keys: &BTreeSet<&str>,
    secrets_block_present: bool,
    out: &mut Vec<PlanFinding>,
) {
    walk_secrets(base_path, value, secret_keys, secrets_block_present, out);
}

fn walk_secrets(
    path: &str,
    value: &serde_json::Value,
    secret_keys: &BTreeSet<&str>,
    secrets_block_present: bool,
    out: &mut Vec<PlanFinding>,
) {
    match value {
        serde_json::Value::String(s) => {
            for r in extract_secret_refs(s) {
                if !secret_keys.contains(r.as_str()) {
                    let severity = if secrets_block_present {
                        Severity::Error
                    } else {
                        Severity::Warn
                    };
                    let rule_id = if secrets_block_present {
                        "missing-vault-key"
                    } else {
                        "unverified-secret-reference"
                    };
                    out.push(PlanFinding {
                        severity,
                        rule_id: rule_id.to_string(),
                        path: path.to_string(),
                        message: if secrets_block_present {
                            format!(
                                "secret reference '{r}' at {path} is not declared under proxy.secrets.map"
                            )
                        } else {
                            format!(
                                "secret reference '{r}' at {path} cannot be verified at plan time (no proxy.secrets block)"
                            )
                        },
                    });
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let sub = format!("{path}[{i}]");
                walk_secrets(&sub, item, secret_keys, secrets_block_present, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let sub = format!("{path}.{k}");
                walk_secrets(&sub, v, secret_keys, secrets_block_present, out);
            }
        }
        _ => {}
    }
}

/// Pull every removed `secret:<name>` map reference out of a free-form
/// string. Returns the bare logical name for each match. Multiple
/// references in one string (e.g. an interpolated template) are all
/// returned.
fn extract_secret_refs(input: &str) -> Vec<String> {
    const PREFIX: &str = "secret:";
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(idx) = input[start..].find(PREFIX) {
        let abs = start + idx;
        let after = &input[abs + PREFIX.len()..];
        // `secret://<backend>/<key>` is a provider URI, not a logical
        // name. `compile_config` rejects one whose backend is not
        // declared under `proxy.secrets.backends` (WOR-2227), so a
        // second, weaker check against the inert `map` here would only
        // report the same configs twice and the broken ones never.
        if after.starts_with("//") {
            start = abs + PREFIX.len();
            continue;
        }
        // The reference ends at the first whitespace or quote /
        // closing brace, mirroring how the runtime resolver
        // tokenises template values.
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"' || c == '}' || c == '\'')
            .unwrap_or(after.len());
        let name = &after[..end];
        if !name.is_empty() {
            // Strip the canonical `system:` / `origin:host:` /
            // `shared:` scope so the validation key matches the
            // logical name in `proxy.secrets.map`.
            out.push(strip_scope_prefix(name));
        }
        start = abs + PREFIX.len() + end;
    }
    out
}

/// Strip the optional scope segment from a parsed reference. Mirrors
/// `sbproxy_vault::scope::parse_scope` but returns just the name
/// portion as an owned `String`.
fn strip_scope_prefix(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("system:") {
        rest.to_string()
    } else if let Some(rest) = name.strip_prefix("shared:") {
        rest.to_string()
    } else if let Some(rest) = name.strip_prefix("origin:") {
        // origin:<host>:<key>
        if let Some(idx) = rest.find(':') {
            rest[idx + 1..].to_string()
        } else {
            name.to_string()
        }
    } else {
        name.to_string()
    }
}

// --- Unknown-type check --------------------------------------------

fn check_unknown_types(
    host: &str,
    origin: &RawOriginConfig,
    opts: &ValidationOptions,
    out: &mut Vec<PlanFinding>,
) {
    if let Some(t) = type_of(&origin.action) {
        if !known_action(t, opts) {
            out.push(PlanFinding {
                severity: Severity::Error,
                rule_id: "unknown-action-type".to_string(),
                path: format!("origins.{host}.action"),
                message: format!("origin '{host}' uses unknown action type '{t}'"),
            });
        }
    }

    if let Some(auth) = &origin.authentication {
        // The scalar form is one entry at the block's own path; the
        // list-form composition (WOR-2517) checks each entry at its
        // indexed path.
        let entries: Vec<(String, &serde_json::Value)> = match auth.as_array() {
            Some(list) => list
                .iter()
                .enumerate()
                .map(|(idx, entry)| (format!("origins.{host}.authentication[{idx}]"), entry))
                .collect(),
            None => vec![(format!("origins.{host}.authentication"), auth)],
        };
        for (path, entry) in entries {
            if let Some(t) = type_of(entry) {
                if !known_auth(t, opts) {
                    out.push(PlanFinding {
                        // `Warn` because compile_auth falls through to
                        // the inventory plugin registry at runtime; an
                        // unknown name here may resolve in an enterprise
                        // build with extra plugins linked in.
                        severity: Severity::Warn,
                        rule_id: "unknown-auth-type".to_string(),
                        path,
                        message: format!(
                            "origin '{host}' uses auth type '{t}' which is not in the OSS catalog (will fail at runtime if no plugin registers it)"
                        ),
                    });
                }
            }
        }
    }

    for (idx, policy) in origin.policies.iter().enumerate() {
        if let Some(t) = type_of(policy) {
            if !known_policy(t, opts) {
                out.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "unknown-policy-type".to_string(),
                    path: format!("origins.{host}.policies[{idx}]"),
                    message: format!("origin '{host}' uses unknown policy type '{t}'"),
                });
            }
        }
    }

    for (idx, transform) in origin.transforms.iter().enumerate() {
        if let Some(t) = type_of(transform) {
            if !known_transform(t, opts) {
                out.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "unknown-transform-type".to_string(),
                    path: format!("origins.{host}.transforms[{idx}]"),
                    message: format!("origin '{host}' uses unknown transform type '{t}'"),
                });
            }
        }
    }
}

/// WOR-2491 review round, M2: `sbproxy_config::plan`'s text preview
/// (`owasp_pack_preview`) runs the real
/// `owasp_api_pack::expand_owasp_pack` expander over the proposed
/// config's `owasp_api_top10` entry to render the per-item rows, but
/// silently drops an `Err` (a malformed entry - an unknown item name,
/// a duplicate `enable` entry, an out-of-range `per_item.api4.rps`,
/// and so on) rather than surfacing it, because that preview has
/// nowhere to put a plan-time finding. This check runs the same
/// expander here instead, over a scratch clone of the origin's own
/// `policies`/`transforms`/`expose_openapi`/action type so the real
/// fields are never mutated, and turns a refusal into a real
/// `PlanFinding` an operator sees under `sbproxy plan`'s
/// `Validation:` section - the same severity `unknown-policy-type`
/// already uses, since both mean "this config will not compile".
///
/// A well-formed entry (or no entry at all) adds nothing here; the
/// expander's own synthesis and manifest construction have no failure
/// mode once the input parses and validates, so there is nothing left
/// to check past `Err`.
fn check_owasp_pack_config(host: &str, origin: &RawOriginConfig, out: &mut Vec<PlanFinding>) {
    let has_pack_entry = origin
        .policies
        .iter()
        .any(|p| type_of(p) == Some("owasp_api_top10"));
    if !has_pack_entry {
        return;
    }
    let mut policies = origin.policies.clone();
    let mut transforms = origin.transforms.clone();
    let mut expose_openapi = origin.expose_openapi;
    let action_type = type_of(&origin.action).unwrap_or("");
    if let Err(error) = crate::owasp_api_pack::expand_owasp_pack(
        host,
        &mut policies,
        &mut transforms,
        &mut expose_openapi,
        action_type,
    ) {
        out.push(PlanFinding {
            severity: Severity::Error,
            rule_id: "invalid-owasp-api-pack-config".to_string(),
            path: format!("origins.{host}.policies"),
            message: format!("{error:#}"),
        });
    }
}

fn type_of(value: &serde_json::Value) -> Option<&str> {
    value.get("type").and_then(|v| v.as_str())
}

fn known_action(t: &str, opts: &ValidationOptions) -> bool {
    KNOWN_ACTION_TYPES.contains(&t) || opts.extra_action_types.iter().any(|x| x == t)
}

fn known_auth(t: &str, opts: &ValidationOptions) -> bool {
    KNOWN_AUTH_TYPES.contains(&t) || opts.extra_auth_types.iter().any(|x| x == t)
}

fn known_policy(t: &str, opts: &ValidationOptions) -> bool {
    KNOWN_POLICY_TYPES.contains(&t) || opts.extra_policy_types.iter().any(|x| x == t)
}

fn known_transform(t: &str, opts: &ValidationOptions) -> bool {
    KNOWN_TRANSFORM_TYPES.contains(&t) || opts.extra_transform_types.iter().any(|x| x == t)
}

// --- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConfigFile;

    fn parse(yaml: &str) -> ConfigFile {
        serde_yaml::from_str::<ConfigFile>(yaml).expect("ConfigFile parse")
    }

    // -- update-config --

    #[test]
    fn update_auto_with_zero_interval_warns() {
        let cfg = parse("update:\n  auto: true\n  check_interval_secs: 0\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        let zero: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "update-zero-check-interval")
            .collect();
        assert_eq!(zero.len(), 1, "got findings: {findings:?}");
        assert_eq!(zero[0].severity, Severity::Warn);
    }

    #[test]
    fn update_auto_with_positive_interval_is_clean() {
        let cfg = parse("update:\n  auto: true\n  check_interval_secs: 1d\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "update-zero-check-interval"));
    }

    #[test]
    fn update_block_absent_is_clean() {
        let cfg = parse("proxy: {}\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "update-zero-check-interval"));
    }

    // -- unknown-acme-storage-backend --

    #[test]
    fn unknown_acme_storage_backend_is_an_error() {
        // The value parses (it is a free-form string) and used to fall
        // through to an in-memory cert store, so the proxy re-issued every
        // certificate on every restart with nothing in the plan to show for
        // it. Plan time now refuses it.
        let cfg = parse("proxy:\n  acme:\n    enabled: true\n    storage_backend: postgres\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-acme-storage-backend")
            .collect();
        assert_eq!(hits.len(), 1, "got findings: {findings:?}");
        assert_eq!(hits[0].severity, Severity::Error);
        assert_eq!(hits[0].path, "proxy.acme.storage_backend");
        assert!(hits[0].message.contains("postgres"), "{:?}", hits[0]);
    }

    #[test]
    fn every_backend_the_proxy_can_open_validates() {
        // Keeps this catalog honest against `open_cert_backend`. `sqlite` is
        // the one that matters: it was documented, parsed, and had no arm.
        for backend in KNOWN_ACME_STORAGE_BACKENDS {
            let cfg = parse(&format!(
                "proxy:\n  acme:\n    enabled: true\n    storage_backend: {backend}\n"
            ));
            let findings = validate(&cfg, &ValidationOptions::default());
            assert!(
                !findings
                    .iter()
                    .any(|f| f.rule_id == "unknown-acme-storage-backend"),
                "{backend} must validate: {findings:?}"
            );
        }
    }

    #[test]
    fn the_default_acme_storage_backend_validates() {
        let cfg = parse("proxy:\n  acme:\n    enabled: true\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "unknown-acme-storage-backend"));
    }

    #[test]
    fn no_acme_block_emits_no_backend_finding() {
        let cfg = parse("proxy: {}\n");
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "unknown-acme-storage-backend"));
    }

    // -- orphan-ref --

    #[test]
    fn orphan_fallback_origin_is_flagged() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    fallback_origin:
      type: proxy
      url: https://undefined.example.com
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let orphan: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "orphan-fallback-origin")
            .collect();
        assert_eq!(orphan.len(), 1, "got findings: {findings:?}");
        assert_eq!(orphan[0].severity, Severity::Error);
        assert!(orphan[0].path.contains("fallback_origin"));
        assert!(orphan[0].message.contains("undefined.example.com"));
    }

    #[test]
    fn fallback_origin_referencing_known_host_is_clean() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    fallback_origin:
      type: proxy
      url: https://www.example.com
  www.example.com:
    action:
      type: static
      body: hi
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "orphan-fallback-origin"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn forward_rule_orphan_target_is_flagged() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    forward_rules:
      - rules:
          - match: "/v2/"
        origin:
          action:
            type: proxy
            url: https://undefined.example.com/v2/
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let orphan: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "orphan-forward-rule-target")
            .collect();
        assert_eq!(orphan.len(), 1, "got findings: {findings:?}");
        assert!(orphan[0].path.contains("forward_rules[0]"));
    }

    #[test]
    fn ip_and_localhost_targets_are_not_orphans() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    fallback_origin:
      type: proxy
      url: http://127.0.0.1:9000
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings.iter().all(|f| !f.rule_id.starts_with("orphan-")),
            "got findings: {findings:?}"
        );
    }

    // -- missing-secret --

    #[test]
    fn missing_vault_key_is_flagged_when_secrets_block_present() {
        let yaml = r#"
proxy:
  secrets:
    backend: env
    map:
      jwt_signing_key: KV_JWT_KEY
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: "secret:wrong_key_name"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "missing-vault-key")
            .collect();
        assert_eq!(missing.len(), 1, "got findings: {findings:?}");
        assert_eq!(missing[0].severity, Severity::Error);
        assert!(missing[0].message.contains("wrong_key_name"));
    }

    #[test]
    fn known_vault_key_is_clean() {
        let yaml = r#"
proxy:
  secrets:
    backend: env
    map:
      jwt_signing_key: KV_JWT_KEY
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: "secret:jwt_signing_key"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings.iter().all(|f| f.rule_id != "missing-vault-key"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn missing_secret_warns_when_no_secrets_block() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: "secret:some_key"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let warns: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unverified-secret-reference")
            .collect();
        assert_eq!(warns.len(), 1, "got findings: {findings:?}");
        assert_eq!(warns[0].severity, Severity::Warn);
    }

    /// Every `secret://` shape is `compile_config`'s business now
    /// (WOR-2227): it checks the authority against
    /// `proxy.secrets.backends` and fails the load. Plan time keeps
    /// only the removed colon form, so the two checks do not overlap.
    #[test]
    fn secret_uri_forms_are_left_to_the_load_time_backend_check() {
        let yaml = r#"
proxy:
  secrets:
    backend: env
    map: {}
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: "secret://missing_key"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings.iter().all(|f| f.rule_id != "missing-vault-key"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn provider_secret_reference_uris_are_not_proxy_secret_map_keys() {
        let yaml = r#"
proxy:
  secrets:
    backend: env
    map: {}
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: bearer
      tokens:
        - "vault://primary/secret/data/inbound/admin-token?key=token"
        - "awssm://primary/prod/sbproxy-inbound-tokens?version=3&key=admin"
        - "gcpsm://primary/inbound-token?version=latest"
        - "azurekv://primary/inbound-token?version=abc123def456"
        - "k8ssecret://primary/sbproxy-secrets/inbound-token"
        - "secretfile://local/inbound-admin?key=current"
        - "secret://local/inbound-admin-token"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings.iter().all(|f| f.rule_id != "missing-vault-key"),
            "got findings: {findings:?}"
        );
    }

    // -- unknown-type --

    #[test]
    fn unknown_action_type_is_flagged() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: warp_drive
      url: https://upstream.example.com
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-action-type")
            .collect();
        assert_eq!(unknown.len(), 1, "got findings: {findings:?}");
        assert_eq!(unknown[0].severity, Severity::Error);
    }

    #[test]
    fn unknown_policy_type_is_flagged() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: rate_limiting
        requests_per_second: 10
      - type: galactic_firewall
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-policy-type")
            .collect();
        assert_eq!(unknown.len(), 1, "got findings: {findings:?}");
        assert!(unknown[0].path.contains("policies[1]"));
        assert_eq!(unknown[0].severity, Severity::Error);
    }

    #[test]
    fn owasp_api_top10_pack_entry_is_not_flagged_unknown() {
        // WOR-2491 task 4: `owasp_api_top10` compiles cleanly as a real
        // origin policy (it's a pseudo-policy consumed by
        // `owasp_api_pack::expand_owasp_pack`, not dispatched by
        // `compile_policy`); plan-time validation must not flag it as
        // an unknown policy type.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: owasp_api_top10
        enable: all
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-policy-type")
            .collect();
        assert!(unknown.is_empty(), "got findings: {findings:?}");
    }

    #[test]
    fn malformed_owasp_api_pack_config_is_a_real_plan_finding() {
        // WOR-2491 review round, M2: `sbproxy plan`'s text preview
        // silently drops an expander error; `validate()` must not.
        // `api11` is not one of the ten items.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: owasp_api_top10
        enable: [api11]
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let pack_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "invalid-owasp-api-pack-config")
            .collect();
        assert_eq!(pack_findings.len(), 1, "got findings: {findings:?}");
        assert_eq!(pack_findings[0].severity, Severity::Error);
        assert_eq!(pack_findings[0].path, "origins.api.example.com.policies");
        assert!(
            pack_findings[0].message.contains("api11"),
            "{}",
            pack_findings[0].message
        );
    }

    #[test]
    fn well_formed_owasp_api_pack_config_produces_no_pack_finding() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: owasp_api_top10
        enable: all
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "invalid-owasp-api-pack-config"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn unknown_transform_type_is_flagged() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    transforms:
      - type: galactic_compression
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-transform-type")
            .collect();
        assert_eq!(unknown.len(), 1, "got findings: {findings:?}");
        assert_eq!(unknown[0].severity, Severity::Error);
    }

    #[test]
    fn unknown_auth_is_warn_not_error() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: saml
      idp_url: https://idp.example.com
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-auth-type")
            .collect();
        assert_eq!(unknown.len(), 1, "got findings: {findings:?}");
        assert_eq!(unknown[0].severity, Severity::Warn);
    }

    #[test]
    fn ldap_auth_and_its_alias_validate_clean() {
        // `ldap_auth` / `ldap` shipped missing from KNOWN_AUTH_TYPES, so
        // `sbproxy validate` told operators the type "will fail at
        // runtime" for a provider `compile_auth` builds happily. The
        // repo's own examples/auth-ldap/sb.yml drew the warning.
        for type_name in ["ldap_auth", "ldap"] {
            let yaml = format!(
                r#"
origins:
  intranet.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: {type_name}
      url: ldaps://directory.internal:636
      base_dn: ou=users,dc=example,dc=org
"#
            );
            let cfg = parse(&yaml);
            let findings = validate(&cfg, &ValidationOptions::default());
            let unknown: Vec<_> = findings
                .iter()
                .filter(|f| f.rule_id == "unknown-auth-type")
                .collect();
            assert!(
                unknown.is_empty(),
                "`{type_name}` is a built-in auth type and must validate clean; \
                 got findings: {findings:?}"
            );
        }
    }

    #[test]
    fn unknown_auth_inside_a_composition_list_is_flagged_at_its_index() {
        // WOR-2517: a list-form `authentication:` block checks each
        // entry; only the unknown one warns, at its indexed path.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      - type: api_key
        api_keys:
          - key-one
      - type: saml
        idp_url: https://idp.example.com
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-auth-type")
            .collect();
        assert_eq!(unknown.len(), 1, "got findings: {findings:?}");
        assert_eq!(unknown[0].severity, Severity::Warn);
        assert_eq!(unknown[0].path, "origins.api.example.com.authentication[1]");
    }

    #[test]
    fn extra_types_in_options_are_treated_as_known() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: enterprise_l7
      url: https://upstream.example.com
"#;
        let cfg = parse(yaml);
        let mut opts = ValidationOptions::default();
        opts.extra_action_types.push("enterprise_l7".to_string());
        let findings = validate(&cfg, &opts);
        assert!(
            findings.iter().all(|f| f.rule_id != "unknown-action-type"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn runtime_builtins_are_known_to_plan_validation() {
        let cases = [
            (
                "oidc",
                "unknown-auth-type",
                r#"
origins:
  app.example.com:
    action:
      type: static
      body: ok
    authentication:
      type: oidc
      authorization_endpoint: https://idp.example.com/authorize
      token_endpoint: https://idp.example.com/oauth/token
      jwks_uri: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com
      client_id: sbproxy
      client_secret: super-secret-client-secret-of-arbitrary-length
      cookie_secret: operator-supplied-32-plus-byte-cookie-secret
"#,
            ),
            (
                "rate_limit_budget",
                "unknown-policy-type",
                r#"
origins:
  api.example.com:
    action:
      type: static
      body: ok
    policies:
      - type: rate_limit_budget
"#,
            ),
            (
                "content_digest",
                "unknown-policy-type",
                r#"
origins:
  webhook.example.com:
    action:
      type: static
      body: ok
    policies:
      - type: content_digest
"#,
            ),
            (
                "agent_budget",
                "unknown-policy-type",
                r#"
origins:
  ai.example.com:
    action:
      type: static
      body: ok
    policies:
      - type: agent_budget
        requests_per_minute: 60
        tokens_per_hour: 100000
        burst: 10
        on_exceed: deny
"#,
            ),
            (
                "a2a_agent_card_rewrite",
                "unknown-transform-type",
                r#"
origins:
  agent.example.com:
    action:
      type: static
      body: ok
    transforms:
      - type: a2a_agent_card_rewrite
"#,
            ),
        ];

        let mut rejected_builtins = Vec::new();
        for (type_name, unknown_rule, yaml) in cases {
            let cfg = parse(yaml);
            let findings = validate(&cfg, &ValidationOptions::default());
            if findings
                .iter()
                .any(|finding| finding.rule_id == unknown_rule)
            {
                rejected_builtins.push(type_name);
            }
        }
        assert!(
            rejected_builtins.is_empty(),
            "runtime built-ins rejected by plan validation: {rejected_builtins:?}"
        );
    }

    #[test]
    fn known_builtins_produce_no_findings() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: hardcoded-not-a-ref
    policies:
      - type: rate_limiting
        requests_per_second: 10
    transforms:
      - type: gzip
        # Note: 'gzip' is intentionally not in KNOWN_TRANSFORM_TYPES
        # to keep this test honest. Replace with `noop` to assert
        # zero findings.
"#;
        // Replace "gzip" with a known type so we expect zero findings.
        let yaml = yaml.replace("type: gzip", "type: noop");
        let cfg = parse(&yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        assert!(findings.is_empty(), "got findings: {findings:?}");
    }
}
