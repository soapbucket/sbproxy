//! Plan-time semantic validation. Implements step 3 of the WOR-131
//! ADR (`docs/adr-config-plan-apply.md`): a sync library API that
//! walks a parsed [`ConfigFile`] and produces a list of
//! [`PlanFinding`]s the CLI surfaces under the diff.
//!
//! Three rule families are enforced today:
//!
//! * [`orphan-ref`](validate#orphan-references): a `fallback_origin`
//!   or forward-rule action target names a hostname that is not
//!   present under `origins.*` in the same proposed config.
//! * [`missing-secret`](validate#missing-secrets): a `secret:` /
//!   `secret://` / `vault://` template reference whose logical name
//!   does not appear under `proxy.secrets.map` in the proposed
//!   config. Backends that resolve from the OS env (`backend: env`)
//!   skip this check because the validator cannot inspect process
//!   env safely at plan time.
//! * [`unknown-type`](validate#unknown-types): an `action`,
//!   `authentication`, `policies[*]`, or `transforms[*]` `type:`
//!   discriminator that names a module not registered in the OSS
//!   built-in catalogs (`KNOWN_ACTION_TYPES`, ...). Operators
//!   running enterprise builds with extra plugins can extend the
//!   catalogs through [`ValidationOptions`].
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
    "forward_auth",
    "forward",
    "bot_auth",
    "web_bot_auth",
    "cap",
    "noop",
];

/// Built-in OSS policy `type:` names. Mirrors `sbproxy_modules::compile_policy`.
pub const KNOWN_POLICY_TYPES: &[&str] = &[
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
    "concurrent_limit",
    "concurrent_limiting",
    "ai_crawl_control",
    "pay_per_crawl",
    "exposed_credentials",
    "leaked_credentials",
    "page_shield",
    "dlp",
    "openapi_validation",
    "prompt_injection_v2",
    "http_framing",
    "agent_class",
    "a2a",
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
    "lua_json",
    "javascript",
    "js_json",
    "wasm",
    "boilerplate",
    "citation_block",
    "json_envelope",
    "cel",
    "noop",
];

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

    findings
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

/// Walk a JSON value tree and emit a finding for each `secret:` /
/// `secret://` / `vault://` reference whose logical name is not in
/// `secret_keys`. References embedded in arbitrary string fields
/// (e.g. `auth.secret: "secret:my_jwt"`) are caught.
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

/// Pull every `secret:`, `secret://`, or `vault://` reference out
/// of a free-form string. Returns the bare logical name (the part
/// after the prefix) for each match. Multiple references in one
/// string (e.g. an interpolated template) are all returned.
fn extract_secret_refs(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["secret://", "vault://", "secret:"] {
        let mut start = 0;
        while let Some(idx) = input[start..].find(prefix) {
            let abs = start + idx;
            let after = &input[abs + prefix.len()..];
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
            start = abs + prefix.len() + end;
        }
        if !out.is_empty() {
            return out;
        }
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
        if let Some(t) = type_of(auth) {
            if !known_auth(t, opts) {
                out.push(PlanFinding {
                    // `Warn` because compile_auth falls through to
                    // the inventory plugin registry at runtime; an
                    // unknown name here may resolve in an enterprise
                    // build with extra plugins linked in.
                    severity: Severity::Warn,
                    rule_id: "unknown-auth-type".to_string(),
                    path: format!("origins.{host}.authentication"),
                    message: format!(
                        "origin '{host}' uses auth type '{t}' which is not in the OSS catalog (will fail at runtime if no plugin registers it)"
                    ),
                });
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

    #[test]
    fn vault_url_style_reference_is_flagged() {
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
      secret: "vault://missing_key"
"#;
        let cfg = parse(yaml);
        let findings = validate(&cfg, &ValidationOptions::default());
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "missing-vault-key")
            .collect();
        assert_eq!(missing.len(), 1, "got findings: {findings:?}");
        assert!(missing[0].message.contains("missing_key"));
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
