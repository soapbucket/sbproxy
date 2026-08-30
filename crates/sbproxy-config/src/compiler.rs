//! Config compilation: transforms raw YAML into optimized `CompiledConfig`.
//!
//! The compilation step converts user-facing `ConfigFile` into the
//! performance-optimized `CompiledConfig` / `CompiledOrigin` types that
//! the proxy runtime works with.

use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use anyhow::{Context, Result};
use compact_str::CompactString;
use sbproxy_platform::storage::{
    KVStore, RedisConfig, RedisKVStore, RedisTlsConfig, ValidatedRedisConnection,
};
use smallvec::SmallVec;

use sbproxy_security::egress::{EgressAuthorizer, EgressConfig, EgressPurpose, PurposeAllowlist};

use crate::snapshot::{CompiledConfig, CompiledEgressGates, CompiledOrigin};
use crate::types::{
    AttestationBillableConfig, AttestationConfig, AttestationLedgerConfig,
    AttestationMeasuredConfig, AttestationOriginHeaderConfig, AttestationQueueConfig,
    AttestationRole, AttestationRouteWeightConfig, AuditConfig, AuditSinkKind, CompressionConfig,
    ConfigFile, ConnectionPoolConfig, CorsConfig, EgressPurposeConfig, EgressTopLevelConfig,
    EnforcementMode, EventSinkKind, EventsConfig, FailureMode, L2CacheConfig, L2CacheParams,
    OriginAttestationConfig, RawOriginConfig, UpstreamTimeouts, UpstreamTimeoutsConfig,
    WebBotAuthConfig, ATTESTATION_SIGN_WITH_WEB_BOT_AUTH, COMPRESSION_ALGORITHM_TOKENS,
    DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS, DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS,
    DEFAULT_UPSTREAM_READ_TIMEOUT_MS, DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS,
    DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS, MAX_ATTESTATION_QUEUE_ENTRIES,
};

const MAX_REDIS_TLS_FILE_BYTES: u64 = 1_048_576;

fn read_redis_tls_file(path: &str, error: &'static str) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| anyhow::anyhow!(error))?;
    let mut bytes = Vec::new();
    file.take(MAX_REDIS_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!(error))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REDIS_TLS_FILE_BYTES {
        return Err(anyhow::anyhow!(error));
    }
    Ok(bytes)
}

fn read_optional_redis_tls_file(
    path: Option<&str>,
    error: &'static str,
) -> Result<Option<Vec<u8>>> {
    path.map(|path| read_redis_tls_file(path, error))
        .transpose()
}

/// Compile the Redis connection shared by the blocking L2 store and async
/// compression state without opening a network connection.
///
/// # Errors
///
/// Returns a static, redacted error when the DSN, TLS field combination, file
/// contents, or client identity is invalid.
pub fn build_l2_redis_connection(params: &L2CacheParams) -> Result<ValidatedRedisConnection> {
    let tls = RedisTlsConfig {
        root_cert: read_optional_redis_tls_file(
            params.ca_file.as_deref(),
            "invalid Redis ca_file configuration",
        )?,
        client_cert: read_optional_redis_tls_file(
            params.cert_file.as_deref(),
            "invalid Redis cert_file configuration",
        )?,
        client_key: read_optional_redis_tls_file(
            params.key_file.as_deref(),
            "invalid Redis key_file configuration",
        )?,
    };
    ValidatedRedisConnection::new(&params.dsn, tls)
}

/// Build a concrete `KVStore` for the given L2 cache config.
///
/// # Errors
///
/// Returns an error if the configured `driver` is not recognized or if the
/// Redis connection and TLS configuration is invalid.
pub fn build_l2_store(cfg: &L2CacheConfig) -> Result<Arc<dyn KVStore>> {
    match cfg.driver.as_str() {
        "redis" => {
            let connection = build_l2_redis_connection(&cfg.params)?;
            Ok(Arc::new(RedisKVStore::new(RedisConfig::new(connection))))
        }
        other => anyhow::bail!("unsupported l2_cache driver: '{}'", other),
    }
}

/// Extract the `type` field from a JSON value.
///
/// Most plugin configs (actions, policies, etc.) use a `type` discriminator
/// to select which implementation to use.
///
/// # Errors
///
/// Returns an error if `value` has no `type` field or its `type` is not
/// a string.
pub fn extract_type(value: &serde_json::Value) -> Result<String> {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing or empty 'type' field"))
}

/// The access-log `custom_fields` DOTTED interpolation vocabulary, the
/// prefixes `sbproxy-core`'s `custom_log::resolve_var` answers from the
/// per-request context rather than from the process environment
/// (`crates/sbproxy-core/src/server/custom_log.rs:274-286`, documented
/// in docs/access-log.md).
///
/// Same reasoning as [`ACCESS_LOG_BARE_VARS`], which covered only the
/// bare names: substituting a process variable would bake a boot-time
/// constant into a per-request log field, and reporting one as
/// unresolved would make a config authority refuse a whole bundle over
/// a documented form. Missing these two cost the confined fragment pass
/// a false refusal against a `fields:` block written exactly as
/// documented (WOR-2433 review).
///
/// `env.` is deliberately absent: `resolve_var` answers `${env.NAME}`
/// from `std::env::var`, so it is a real environment reference on both
/// sides. Prefixes are matched exactly as `resolve_var` matches them,
/// `request.header.` and not the wider `request.`, so the carve-out
/// cannot be wider than the runtime resolver it mirrors.
const ACCESS_LOG_DOTTED_PREFIXES: &[&str] = &["request.header.", "attribution."];

/// The access-log `custom_fields` bare-name interpolation vocabulary,
/// resolved per request by `sbproxy-core`'s `custom_log::resolve_var`
/// and documented in docs/access-log.md. Like the dotted runtime
/// vocabulary, a placeholder naming one of these is not an env
/// reference: substituting a process variable would bake a boot-time
/// constant into a per-request log field, and reporting it as
/// unresolved would make a config authority refuse the whole bundle
/// over a documented form. Exact names only - a `:-` default is not
/// part of `resolve_var`'s syntax, so `${method:-GET}` keeps its env
/// treatment.
const ACCESS_LOG_BARE_VARS: &[&str] = &[
    "method",
    "path",
    "host",
    "query",
    "status",
    "tenant_id",
    "provider",
    "model",
];

/// True when a `${...}` placeholder's name (the part before an optional
/// `:-` default) is an environment reference this pre-parse pass owns.
///
/// The one carve-out is the MCP local-tool interpolation vocabulary
/// (docs/mcp-compose.md), whose engine defines exactly two roots:
/// `args.` (the tool call's JSON-RPC arguments) and `steps.` (prior
/// step outputs). Those placeholders belong to the executor at call
/// time, so the substitution pass leaves them byte-for-byte literal
/// even when a same-named process variable exists, and the hazard scan
/// does not report them as unresolved (reporting one would tell the
/// operator to export a variable that would break the tool if they
/// did, and the config-authority subscriber would refuse the whole
/// bundle over it).
///
/// Every other name, dotted or not, gets the full env treatment:
/// attempted resolution, `:-` default support, and the
/// unresolved-reference report that the config-authority path upgrades
/// to a refusal. A broader "any name containing a dot" carve-out
/// shipped briefly and silently disabled that fail-closed gate for
/// forms like `${secret.OPENAI_KEY}` while also breaking
/// `${dotted.name:-default}` resolution; the allowlist keeps the
/// detector exactly as wide as the enforcer.
/// The bare access-log names in [`ACCESS_LOG_BARE_VARS`] are excluded
/// by exact match for the same reason: they are per-request vocabulary
/// resolved by `custom_log.rs`, never env references.
pub(crate) fn placeholder_is_env_reference(var_name: &str) -> bool {
    // `${}` names nothing. `interpolate_env_vars` guards on
    // `!var_name.is_empty()` and never looks it up, so calling it an
    // environment reference is a false positive in both directions: the
    // hazard scan told an operator to export a variable with no name,
    // and a config authority subscriber refuses a whole bundle over a
    // literal `${}` that could never have resolved. Excluded so this
    // predicate is exactly as wide as the pass it describes, which is
    // what the confined pass's biconditional test asserts
    // (WOR-2433 review).
    if var_name.is_empty() {
        return false;
    }
    if ACCESS_LOG_BARE_VARS.contains(&var_name) {
        return false;
    }
    let name = var_name.split_once(":-").map_or(var_name, |(name, _)| name);
    if ACCESS_LOG_DOTTED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return false;
    }
    !(name.starts_with("args.") || name.starts_with("steps."))
}

/// Interpolate `${VAR_NAME}` patterns in a string with environment variables.
///
/// This is the pass `compile_config` runs over the raw document text
/// before anything parses it, and it is public so the CLI paths that
/// read a config without compiling it (`sbproxy config print`,
/// `sbproxy mcp lock`) resolve `${VAR}` identically instead of carrying
/// a near-copy that drifts (WOR-2433).
///
/// It reads the process environment without restriction, which is
/// correct for a document the operator who runs the proxy wrote and
/// wrong for one composed from somewhere else. An externally authored
/// fragment goes through [`crate::confined_template`] instead, which
/// resolves only the inputs its caller binds.
///
/// `${VAR:-default}` takes the shell meaning: the variable's value when it
/// is set and non-empty, the literal default otherwise. Unresolvable
/// variables without a default are left as-is (literal `${...}` in the
/// output), which `scan_yaml_hazards` reports after parsing. A
/// placeholder whose name is not a possible environment variable name
/// (an MCP `args.` / `steps.` runtime path, or an access-log bare name;
/// see `placeholder_is_env_reference`) is not touched at all.
///
/// `$$` escapes: `$${VAR}` is never substituted (docs/mcp-compose.md
/// documents it as rendering the literal text `${VAR}`). This pass
/// consumes `$` in pairs, greedily from the left, so an odd run leaves
/// a live placeholder (`$$${VAR}` is one escaped pair, then a real
/// substitution) -- the same rule the MCP engine's scanner applies. The
/// pass strips nothing: the `$$` bytes stay in the output for the
/// runtime consumer that owns the unescape.
pub fn interpolate_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            if chars.peek() == Some(&'$') {
                // `$$` escape: consume the pair so a `${` right after
                // it never opens a placeholder here, but emit the
                // bytes untouched -- the downstream consumer (the MCP
                // local-tool engine) owns the unescape.
                chars.next();
                result.push_str("$$");
                continue;
            }
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                let mut found_close = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        found_close = true;
                        break;
                    }
                    var_name.push(c);
                }
                if found_close && !var_name.is_empty() {
                    // Not an env reference (an MCP `args.`/`steps.`
                    // runtime path): keep the placeholder byte-for-byte,
                    // even when a colliding process variable exists.
                    if !placeholder_is_env_reference(&var_name) {
                        result.push_str("${");
                        result.push_str(&var_name);
                        result.push('}');
                        continue;
                    }
                    // `${VAR:-default}`: shell semantics, default wins
                    // when the variable is unset or empty.
                    let (name, default) = match var_name.split_once(":-") {
                        Some((n, d)) => (n, Some(d)),
                        None => (var_name.as_str(), None),
                    };
                    match std::env::var(name) {
                        Ok(val) if !val.is_empty() => result.push_str(&val),
                        _ => match default {
                            Some(d) => result.push_str(d),
                            None => {
                                // Leave unresolved variable as literal.
                                result.push_str("${");
                                result.push_str(&var_name);
                                result.push('}');
                            }
                        },
                    }
                } else {
                    // Either an empty name (`${}`) or an unterminated
                    // `${`. Both are left literal, byte for byte: the
                    // closing brace is re-emitted when the input had
                    // one, so `${}` round-trips instead of coming back
                    // as `${`. The CLI's deleted private copy got this
                    // right and this one did not, and `sbproxy config
                    // print` is the command an operator runs precisely
                    // to see the value the box will actually use
                    // (WOR-2433 review).
                    result.push_str("${");
                    result.push_str(&var_name);
                    if found_close {
                        result.push('}');
                    }
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Every live `${VAR}` env placeholder in `s`, as full `${...}` slices.
///
/// The one scanner both the fleet-wide hazard report
/// ([`scan_yaml_hazards`]) and the confined fragment pass
/// ([`crate::confined_template`]) run, so the detector cannot drift
/// narrower than [`interpolate_env_vars`], the enforcer. A placeholder
/// is live here exactly when that function would resolve it from the
/// process environment: unescaped by the `$$` pair-parity rule, and a
/// name [`placeholder_is_env_reference`] owns.
pub(crate) fn env_references_in(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        let tail = &rest[start..];
        match tail.find('}') {
            Some(end) => {
                // `$${...}` is the documented escape: the placeholder
                // never opens, so it is not a live reference. An
                // odd-length `$` run before the placeholder's own `$`
                // escapes it; an even run leaves it live (`$$${VAR}` is
                // one escaped pair, then a real reference) -- the same
                // pair-parity rule `interpolate_env_vars` and the MCP
                // engine's scanner apply.
                let escaping_dollars = rest[..start]
                    .chars()
                    .rev()
                    .take_while(|&c| c == '$')
                    .count();
                let escaped = escaping_dollars % 2 == 1;
                // A placeholder in the MCP local-tool vocabulary
                // (`${args.id}`, `${steps.x.y}`) is left for its own
                // consumer and never reported here; every other
                // unescaped name is an environment reference.
                if !escaped && placeholder_is_env_reference(&tail[2..end]) {
                    out.push(&tail[..=end]);
                }
                rest = &tail[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// Pre-parse hazard scan: reject custom YAML tags, report unresolved
/// `${VAR}` references.
///
/// Tags: serde_yaml resolves standard tags and silently strips unknown
/// ones, keeping the bare scalar. `password: !env ADMIN_PASSWORD`
/// therefore parses to the LITERAL string `ADMIN_PASSWORD`: the operator
/// believes the value comes from the environment while it is actually a
/// constant, which for credential fields is a published-password bug. No
/// supported config form uses tags, so any tag fails the compile with a
/// pointer at the `${VAR}` interpolation form.
///
/// Unresolved references: env interpolation leaves an unset `${VAR}` as
/// the literal text (WOR-1818). The scan runs over the PARSED value tree
/// (comments are gone by then) and returns `path: ${VAR}` pairs for the
/// caller to warn about; credential fields upgrade the warning to a hard
/// error at their typed checks.
fn scan_yaml_hazards(yaml: &str) -> Result<Vec<String>> {
    fn walk(
        value: &serde_yaml::Value,
        path: &str,
        tags: &mut Vec<String>,
        unresolved: &mut Vec<String>,
    ) {
        match value {
            serde_yaml::Value::Tagged(tagged) => {
                let shown = if path.is_empty() { "<root>" } else { path };
                tags.push(format!("{shown}: {}", tagged.tag));
                walk(&tagged.value, path, tags, unresolved);
            }
            serde_yaml::Value::String(s) => {
                for r in env_references_in(s) {
                    unresolved.push(format!("{path}: {r}"));
                }
            }
            serde_yaml::Value::Mapping(map) => {
                for (k, v) in map {
                    let key = k.as_str().map(str::to_owned).unwrap_or_else(|| "?".into());
                    let child = if path.is_empty() {
                        key
                    } else {
                        format!("{path}.{key}")
                    };
                    walk(v, &child, tags, unresolved);
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                for (i, v) in seq.iter().enumerate() {
                    walk(v, &format!("{path}.{i}"), tags, unresolved);
                }
            }
            _ => {}
        }
    }
    // A file that fails to parse at all is reported by the main typed
    // parse with better context; only inspect hazards when parsing works.
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return Ok(Vec::new());
    };
    let mut tags = Vec::new();
    let mut unresolved = Vec::new();
    walk(&root, "", &mut tags, &mut unresolved);
    if !tags.is_empty() {
        anyhow::bail!(
            "config compile: unsupported YAML tag(s): {}. Tags are silently stripped by \
             the parser, so the value would be the literal text after the tag (for \
             `password: !env ADMIN_PASSWORD` the password becomes the string \
             \"ADMIN_PASSWORD\"). Use `${{VAR}}` interpolation instead.",
            tags.join(", ")
        );
    }
    Ok(unresolved)
}

/// Every `${VAR}` reference in `yaml` that survives interpolation on this
/// host, as `path: ${VAR}` pairs.
///
/// [`compile_config`] only warns about these and leaves them as literal
/// text, because a hand-edited config is edited by someone watching the
/// log. An authority-supplied document has no such reader: a bundle
/// naming a variable one subscriber does not export would take effect
/// fleet-wide as the literal string `${VAR}`. Callers that apply a
/// document nobody proofread use this to refuse it instead.
///
/// Returns an empty vector for a document that does not parse, or one
/// carrying an unsupported YAML tag; [`compile_config`] rejects both with
/// a better message than this scan could give.
#[must_use]
pub fn unresolved_env_references(yaml: &str) -> Vec<String> {
    scan_yaml_hazards(&interpolate_env_vars(yaml)).unwrap_or_default()
}

/// Recursively walk a JSON value and replace `{{vars.X}}` and `{{env.X}}`
/// template patterns in all string values.
///
/// - `{{vars.X}}` is resolved from the `variables` map.
/// - `{{env.X}}` is resolved from the process environment via `std::env::var`.
///
/// Unresolvable patterns are left as-is (literal `{{...}}` in the output).
/// Lua script values (keys named `lua_script`) are NOT interpolated, since
/// those are executed at runtime by the Lua engine.
pub fn interpolate_config_vars(
    value: &mut serde_json::Value,
    variables: &std::collections::HashMap<String, serde_json::Value>,
) {
    match value {
        serde_json::Value::String(s) if s.contains("{{") => {
            *s = resolve_template_string(s, variables);
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                interpolate_config_vars(item, variables);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                // Skip Lua, JavaScript, and Rego script bodies - they
                // are executed (Lua/JS) or evaluated (Rego) at runtime,
                // not templated. WOR-2482: without this, a forward-rule
                // modifier's script reaches here through the whole-rule
                // JSON round-trip in `compile_origin`, and a literal
                // `{{` inside the script (a string or comment) would be
                // corrupted by var substitution. `js_script` was missing
                // from this list until a review caught it: a
                // forward-rule `js_script` containing a literal
                // `{{vars.X}}` (e.g. building a header value with a
                // template-looking string) was silently rewritten with
                // the variable's value instead of reaching the engine
                // as authored.
                if key == "lua_script" || key == "js_script" || key == "rego_module" {
                    continue;
                }
                interpolate_config_vars(val, variables);
            }
        }
        _ => {}
    }
}

/// Look up a possibly-dotted variable path (`api_version`,
/// `feature_flags.beta_api`) in the origin's variables map. The first
/// segment indexes the map; the rest walk nested JSON objects.
pub(crate) fn lookup_variable_path<'a>(
    variables: &'a std::collections::HashMap<String, serde_json::Value>,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut segments = path.split('.');
    let mut current = variables.get(segments.next()?)?;
    for segment in segments {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Resolve `{{vars.X}}` and `{{env.X}}` patterns in a single string.
fn resolve_template_string(
    input: &str,
    variables: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        if let Some(end) = after_open.find("}}") {
            let key = after_open[..end].trim();
            // WOR-1828: `variables.` is the long form of `vars.`; the
            // published variables-template example wrote it for months
            // while nothing resolved it, so its headers shipped as
            // literal template text. Accept both spellings.
            if let Some(var_name) = key
                .strip_prefix("vars.")
                .or_else(|| key.strip_prefix("variables."))
            {
                // Resolve {{vars.X}} from origin variables. A dotted
                // tail (`vars.feature_flags.beta_api`) walks nested
                // objects, so a grouped variables: block interpolates
                // without flattening.
                if let Some(val) = lookup_variable_path(variables, var_name) {
                    match val {
                        serde_json::Value::String(s) => result.push_str(s),
                        other => result.push_str(&other.to_string()),
                    }
                } else {
                    tracing::warn!(
                        template = %key,
                        "config: template names a variable that is not defined on the \
                         origin; the value ships as literal text"
                    );
                    // Leave unresolved variable as-is.
                    result.push_str("{{");
                    result.push_str(&after_open[..end]);
                    result.push_str("}}");
                }
            } else if let Some(env_name) = key.strip_prefix("env.") {
                // Resolve {{env.X}} from environment variables.
                match std::env::var(env_name) {
                    Ok(val) => result.push_str(&val),
                    Err(_) => {
                        result.push_str("{{");
                        result.push_str(&after_open[..end]);
                        result.push_str("}}");
                    }
                }
            } else {
                // Leave `request.*` for runtime resolution (the modifier
                // context binds it per request). Any other prefix resolves
                // nowhere, at compile or at runtime, so the literal braces
                // would reach the upstream; warn instead of staying silent
                // (WOR-1828).
                if !key.starts_with("request.") {
                    tracing::warn!(
                        template = %key,
                        "config: unknown template prefix; the value ships as literal \
                         text. Known prefixes: vars. (alias variables.), env., request."
                    );
                }
                result.push_str("{{");
                result.push_str(&after_open[..end]);
                result.push_str("}}");
            }
            rest = &after_open[end + 2..];
        } else {
            // No closing }}, push the rest as-is.
            result.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    result.push_str(rest);
    result
}

/// Resolve a request/response modifier's `rego_module_path` into
/// `rego_module`, mirroring `policy: rego`'s `module` / `module_path`
/// split (WOR-2482; Task 1 established the convention on
/// `transforms[] type: wasm`'s `module_path`): read once here, when the
/// config compiles, and again on every reload. Downstream code
/// (`sbproxy-core`, which does the actual Rego evaluation) reads only
/// `rego_module`; a modifier entry with neither field set has no Rego
/// form and is left untouched.
///
/// Also validates `rego_budget_ms`, the Rego evaluation budget: not
/// module resolution, but the same per-modifier Rego validation this
/// function already performs at the same three call sites, so it lives
/// here rather than as a fourth near-duplicate loop.
///
/// # Errors
///
/// Returns an error naming the origin and the modifier field when both
/// `rego_module` and `rego_module_path` are set, when `rego_module_path`
/// cannot be read, or when `rego_budget_ms` is `Some(0)`.
fn resolve_rego_modifier_module(
    hostname: &str,
    field: &str,
    module: &mut Option<String>,
    module_path: &mut Option<String>,
    budget_ms: Option<u64>,
) -> Result<()> {
    if module.is_some() && module_path.is_some() {
        anyhow::bail!(
            "origin {hostname}: {field} sets both rego_module and rego_module_path; use \
             `rego_module` for an inline Rego source or `rego_module_path` for a path to a \
             .rego file, not both"
        );
    }
    // Same invariant `policy: rego` and `ai_routing_policy` hold: a zero
    // budget reads as "no budget" but is an instantly expired timer, so
    // it would abort every evaluation before the rule ran rather than
    // disabling the limit.
    if budget_ms == Some(0) {
        anyhow::bail!(
            "origin {hostname}: {field} rego_budget_ms must be greater than zero; a zero \
             budget would abort every evaluation before the rule ran, silently dropping every \
             header the module would have set"
        );
    }
    if let Some(path) = module_path.take() {
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            anyhow::anyhow!(
                "origin {hostname}: {field}: loading rego_module_path from {path}: {error}"
            )
        })?;
        *module = Some(contents);
    }
    Ok(())
}

// --- features.* -> proxy.extensions[...] migration ---

/// Names of legacy `features.*` blocks lifted into
/// `proxy.extensions[...]`. The canonical shape is the extensions
/// map; the legacy shape stays accepted for one release with a
/// deprecation log.
const MIGRATED_FEATURE_KEYS: &[(&str, &str)] = &[
    ("anomaly_detection", "anomaly"),
    ("reputation_updater", "reputation"),
    ("reputation", "reputation"),
    ("tls_fingerprint", "tls_fingerprint"),
];

/// Lift legacy `features.<key>` blocks into `proxy.extensions[<key>]`.
///
/// This is a pre-parse YAML rewrite: parse to `serde_yaml::Value`,
/// move recognised keys, and serialise back out. Operators that
/// accidentally configure both shapes simultaneously get a hard
/// error so the proxy never silently honours one block over the
/// other.
///
/// Idempotent: a config that already uses `proxy.extensions[...]`
/// passes through unchanged. Configs without a `features:` block
/// likewise round-trip with no rewrites.
/// Detect the legacy `virtual_keys:` YAML key. The check is a simple
/// substring scan rather than a full parse so the diagnostic surfaces
/// before the typed-error path; an operator with the old shape sees
/// the migration pointer immediately.
///
/// Word-boundary regex check rather than a raw `contains("virtual_keys:")`
/// so a comment like `# virtual_keys: was deprecated` does not trip the
/// guard. The pattern matches the YAML key shape: start of line, any
/// whitespace, the literal `virtual_keys:`, end of token.
/// Lower `proxy.credentials` + `tenants[].credentials` +
/// `origins[].credentials` of type `ai_provider` into JSON entries
/// appended to each origin's `action.virtual_keys` array. Honours
/// the most-specific-wins rule: origin -> tenant -> proxy. Duplicate
/// names at a more specific scope replace the less specific entry.
///
/// Lowering at compile time means the runtime AI dispatch keeps
/// using the existing `VirtualKeyConfig` registry without knowing
/// about the new credentials block; the credentials epic is purely
/// a configuration-time refactor of the operator surface.
///
/// `attrs.tags`, `attrs.metadata`, `attrs.project`, `attrs.user`
/// fan out onto the lowered `VirtualKeyConfig` field of the same
/// name so the per-credential attribution metric and access-log
/// columns continue to populate from the unified principal write.
fn lower_credentials_into_origin_virtual_keys(file: &mut crate::types::ConfigFile) -> Result<()> {
    use crate::types::{CredentialBlock, CredentialPolicy};
    use serde_json::json;

    validate_credential_principal_selectors("proxy", &file.proxy.credentials)?;
    for tenant in &file.proxy.tenants {
        validate_credential_principal_selectors(
            &format!("tenant `{}`", tenant.id),
            &tenant.credentials,
        )?;
    }
    for (hostname, origin) in &file.origins {
        validate_credential_principal_selectors(
            &format!("origin `{hostname}`"),
            &origin.credentials,
        )?;
    }

    // Walk the origins; for each origin's resolved tenant, build the
    // ordered scope list (origin -> tenant -> proxy) and merge the
    // ai_provider credentials by name.
    for (hostname, origin) in file.origins.iter_mut() {
        // Resolve tenant_id once per origin so the loop body does
        // not re-string-compare.
        let tenant_id = origin
            .tenant_id
            .clone()
            .unwrap_or_else(|| "__default__".to_string());

        // Pull the relevant tenant block; missing == no tenant scope
        // (single-tenant configs land here).
        let tenant_creds: Vec<&CredentialBlock> = file
            .proxy
            .tenants
            .iter()
            .find(|t| t.id == tenant_id)
            .map(|t| t.credentials.iter().collect())
            .unwrap_or_default();
        let proxy_creds: Vec<&CredentialBlock> = file.proxy.credentials.iter().collect();
        let origin_creds: Vec<&CredentialBlock> = origin.credentials.iter().collect();

        // Most-specific-wins merge by name. Walk in reverse order
        // (proxy first, tenant, then origin) so origin entries
        // replace tenant entries which replace proxy entries.
        let mut by_name: std::collections::BTreeMap<String, &CredentialBlock> =
            std::collections::BTreeMap::new();
        for c in proxy_creds
            .iter()
            .chain(tenant_creds.iter())
            .chain(origin_creds.iter())
        {
            if c.kind == "ai_provider" {
                by_name.insert(c.name.clone(), c);
            }
        }
        if by_name.is_empty() {
            continue;
        }

        // Materialise each ai_provider credential as a virtual-key
        // JSON entry on the origin's action block. The shape mirrors
        // `sbproxy_ai::identity::VirtualKeyConfig`; missing fields
        // default per serde.
        let action = origin.action.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "origin `{hostname}` action block must be an object to receive credentials"
            )
        })?;

        if action.get("type").and_then(|t| t.as_str()) == Some("ai_proxy") {
            let governed = action
                .get("require_governed_key")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !governed {
                anyhow::bail!(
                    "origin `{hostname}` declares credentials: but require_governed_key is not true; \
                     requests presenting no credential, or any credential, would dispatch ungoverned. \
                     Set `action.require_governed_key: true` on this origin. See docs/migration-credentials.md."
                );
            }
        }

        let entries: Vec<serde_json::Value> = by_name
            .values()
            .map(|cred| {
                // Convert the per-credential attrs to the legacy
                // ai_project / ai_user / tags / metadata shape.
                let mut metadata: serde_json::Map<String, serde_json::Value> = cred
                    .attrs
                    .metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                if let Some(cost_center) = &cred.attrs.cost_center {
                    metadata.insert(
                        "cost_center".to_string(),
                        serde_json::Value::String(cost_center.clone()),
                    );
                }
                let key = cred.key.clone().unwrap_or_default();
                let key_id = format!(
                    "cfg:{}:{}:{}:{}:{}",
                    tenant_id.len(),
                    tenant_id,
                    hostname.len(),
                    hostname,
                    cred.name
                );
                let mut vk = json!({
                    "key": key,
                    "key_id": key_id,
                    "name": cred.name.clone(),
                    "enabled": true,
                    "tags": cred.attrs.tags.clone(),
                    "metadata": metadata,
                });
                if let Some(p) = &cred.attrs.project {
                    vk["project"] = json!(p);
                }
                if let Some(u) = &cred.attrs.user {
                    vk["user"] = json!(u);
                }
                if let Some(t) = &cred.attrs.team {
                    vk["team"] = json!(t);
                }
                if let Some(provider) = &cred.provider {
                    vk["allowed_providers"] = json!([provider]);
                }
                if !cred.principals.is_empty() {
                    vk["principal_selectors"] = json!(cred.principals.clone());
                }
                if let Some(models) = &cred.models {
                    if !models.allow.is_empty() {
                        vk["allowed_models"] = json!(models.allow.clone());
                    }
                    if !models.deny.is_empty() {
                        vk["blocked_models"] = json!(models.deny.clone());
                    }
                }
                if let Some(budget) = cred.attrs.budget.as_ref() {
                    let mut b = serde_json::Map::new();
                    if let Some(max_tokens) = budget.max_tokens {
                        b.insert("max_tokens".to_string(), json!(max_tokens));
                    }
                    if let Some(max_cost) = budget.max_cost_usd {
                        b.insert("max_cost_usd".to_string(), json!(max_cost));
                    }
                    if !b.is_empty() {
                        vk["budget"] = serde_json::Value::Object(b);
                    }
                }
                // Per-credential rate_limit lowers onto the legacy
                // `max_requests_per_minute` field. `require_pii_redaction`
                // lowers onto the runtime key so dispatch can reject the
                // request before provider selection when request redaction
                // is inactive.
                let mut required_pii_redaction = Vec::new();
                for policy in &cred.policies {
                    match policy {
                        CredentialPolicy::RateLimit { rpm } => {
                            if let Some(r) = rpm {
                                vk["max_requests_per_minute"] = json!(r);
                            }
                        }
                        CredentialPolicy::RequirePiiRedaction { rules } => {
                            required_pii_redaction.extend(rules.iter().cloned());
                        }
                    }
                }
                if !required_pii_redaction.is_empty() {
                    vk["require_pii_redaction"] = json!(required_pii_redaction);
                }
                // `route_to_model` and `inject_tools` mirror the
                // identically-named fields on the underlying
                // `VirtualKeyConfig`; pass them through so the AI
                // dispatch's model-pin + tool-injection paths fire.
                // Empty `inject_tools` is dropped to keep the JSON
                // shape compact and match the lowering above.
                if let Some(m) = &cred.route_to_model {
                    vk["route_to_model"] = json!(m);
                }
                if let Some(selector) = &cred.compression_profile {
                    vk["compression_profile"] = json!(selector);
                }
                if !cred.inject_tools.is_empty() {
                    vk["inject_tools"] = json!(cred.inject_tools.clone());
                }
                if let Some(allowed_tools) = &cred.allowed_tools {
                    vk["allowed_tools"] = json!(allowed_tools);
                }
                // WOR-1646: pass through the federation-injection ref
                // so the AI dispatch resolves the referenced gateway's
                // live catalogue at request time.
                if let Some(m) = &cred.inject_mcp {
                    vk["inject_mcp"] = m.clone();
                }
                vk
            })
            .collect();

        // Merge into the existing virtual_keys array on the action
        // block. The compile-time lowering APPENDS; an operator who
        // hand-wrote `virtual_keys:` would have hit the legacy-key
        // rejection above, so the array is guaranteed empty here
        // for any config that compiled to this point.
        let action_existing = action
            .entry("virtual_keys".to_string())
            .or_insert_with(|| json!([]));
        if let serde_json::Value::Array(arr) = action_existing {
            arr.extend(entries);
        }
    }
    Ok(())
}

fn validate_credential_principal_selectors(
    scope: &str,
    credentials: &[crate::types::CredentialBlock],
) -> Result<()> {
    for credential in credentials {
        for (idx, selector) in credential.principals.iter().enumerate() {
            if principal_selector_is_empty(selector) {
                anyhow::bail!(
                    "credential `{}` at {scope} has empty principals[{idx}] selector; \
                     omit `principals` or use `principals: []` to match every principal",
                    credential.name
                );
            }
        }
    }
    Ok(())
}

fn principal_selector_is_empty(selector: &crate::types::PrincipalSelector) -> bool {
    selector.virtual_key.is_none()
        && selector.team.is_none()
        && selector.project.is_none()
        && selector.user.is_none()
        && selector.role.is_none()
        && selector.claim.is_empty()
}

/// Hostname of the first origin still carrying the removed
/// `rate_limit_headers:` key, if any.
///
/// The origin-level block parsed for years and never did anything: the
/// runtime emits rate-limit headers from the rate-limiting policy's own
/// `headers` block. Detected on the raw YAML, before the typed parse, so
/// the operator gets a pointer at the live surface instead of the generic
/// unknown-key diagnostic.
fn yaml_origin_with_removed_rate_limit_headers(yaml: &str) -> Option<String> {
    let root: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let origins = root.get("origins")?.as_mapping()?;
    for (hostname, origin) in origins {
        if origin.get("rate_limit_headers").is_some() {
            return Some(hostname.as_str().unwrap_or("<unnamed origin>").to_string());
        }
    }
    None
}

/// Whether the document sets `model_aliases:` at the top level.
///
/// The AI gateway reads model aliases from the `ai_proxy` action, next to
/// the providers they name, and the root of the file ignores unknown keys.
/// A root-level block would therefore parse and do nothing, which the
/// gateway documentation once showed as the intended shape. Detected on
/// the raw YAML so the operator gets the live path rather than silence.
fn yaml_uses_top_level_model_aliases(yaml: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .ok()
        .is_some_and(|root| root.get("model_aliases").is_some())
}

/// Whether the document sets `model_groups:` at the top level.
///
/// Same shape and same reason as
/// [`yaml_uses_top_level_model_aliases`]: named model groups are read
/// from the `ai_proxy` action, next to the providers their members
/// name, and the root of the file ignores unknown keys, so a root-level
/// block would parse and silently do nothing.
fn yaml_uses_top_level_model_groups(yaml: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .ok()
        .is_some_and(|root| root.get("model_groups").is_some())
}

/// The legacy `proxy.secrets` keys this document authors, in schema order.
///
/// Read off the raw YAML rather than off the typed block because presence
/// is the thing being refused and two of the five carry serde defaults:
/// after the typed parse an operator who wrote `backend: env` and one who
/// wrote nothing at all are the same value, and only the first of the two
/// has a belief about secret resolution to correct. Same reason
/// `yaml_uses_top_level_model_aliases` reads the raw document.
///
/// `map` and `rotation` are not collected here. `map` is live (a non-empty
/// map installs the process resolver, and its keys suppress the
/// `missing-vault-key` finding in `sbproxy plan`), and `rotation` is
/// reserved surface.
fn yaml_legacy_secrets_keys(yaml: &str) -> Vec<&'static str> {
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return Vec::new();
    };
    let Some(secrets) = root.get("proxy").and_then(|proxy| proxy.get("secrets")) else {
        return Vec::new();
    };
    let mut authored: Vec<&'static str> = Vec::new();
    for (field, path) in [
        ("backend", "proxy.secrets.backend"),
        ("fallback", "proxy.secrets.fallback"),
    ] {
        if secrets.get(field).is_some() {
            authored.push(path);
        }
    }
    if let Some(hashicorp) = secrets.get("hashicorp") {
        for (field, path) in [
            ("addr", "proxy.secrets.hashicorp.addr"),
            ("mount", "proxy.secrets.hashicorp.mount"),
            ("token", "proxy.secrets.hashicorp.token"),
        ] {
            if hashicorp.get(field).is_some() {
                authored.push(path);
            }
        }
    }
    authored
}

fn yaml_uses_legacy_virtual_keys(yaml: &str) -> bool {
    for line in yaml.lines() {
        // Strip any inline comment that starts AFTER the YAML value;
        // a leading `#` is the comment-only case and is already
        // ignored by the trim_start below.
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("virtual_keys:") || trimmed.starts_with("virtual_keys :") {
            return true;
        }
    }
    false
}

fn migrate_features_to_extensions(yaml: &str) -> Result<String> {
    use serde_yaml::Value as YamlValue;

    let mut root: YamlValue = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => {
            // Defer parse errors to the typed `compile_config` path so
            // operators see a single canonical error message.
            return Ok(yaml.to_string());
        }
    };
    let Some(map) = root.as_mapping_mut() else {
        return Ok(yaml.to_string());
    };

    let features_key = YamlValue::String("features".to_string());
    let proxy_key = YamlValue::String("proxy".to_string());

    // Take ownership of `features:` so we can drain its keys without
    // re-borrowing root. When absent, no migration to do.
    let Some(features_val) = map.remove(&features_key) else {
        return Ok(yaml.to_string());
    };
    let Some(features_map) = features_val.as_mapping().cloned() else {
        // Non-map `features:` value is a config error the typed parse
        // will surface; pass through.
        map.insert(features_key, features_val);
        return Ok(yaml.to_string());
    };

    let mut remaining_features = serde_yaml::Mapping::new();
    let mut migrated: Vec<(String, YamlValue)> = Vec::new();

    for (k, v) in features_map.into_iter() {
        let Some(name) = k.as_str() else {
            // Non-string key; preserve in place so the typed parser
            // can complain about it.
            remaining_features.insert(k, v);
            continue;
        };
        match MIGRATED_FEATURE_KEYS
            .iter()
            .find(|(legacy, _)| *legacy == name)
        {
            Some((legacy, canonical)) => {
                // Route through tracing so the warning lands in the
                // same structured-log stream operators already watch
                // alongside the `proxy.extensions[...]` bootstrap block.
                // Legacy and canonical names are emitted as fields so
                // they survive any log formatter.
                tracing::warn!(
                    legacy = legacy,
                    canonical = canonical,
                    "deprecated config: features.{} is deprecated; \
                     lifting into proxy.extensions.{}",
                    legacy,
                    canonical,
                );
                migrated.push(((*canonical).to_string(), v));
            }
            None => {
                remaining_features.insert(k, v);
            }
        }
    }

    if !remaining_features.is_empty() {
        // Preserve any features.* keys we did not migrate so the rest
        // of the parser sees them unchanged.
        map.insert(features_key, YamlValue::Mapping(remaining_features));
    }

    if migrated.is_empty() {
        return serde_yaml::to_string(&root)
            .context("failed to re-serialise YAML during migration");
    }

    // Splice the migrated blocks into proxy.extensions. Create proxy
    // and proxy.extensions if missing.
    let proxy_val = map
        .entry(proxy_key)
        .or_insert_with(|| YamlValue::Mapping(serde_yaml::Mapping::new()));
    let proxy_map = match proxy_val.as_mapping_mut() {
        Some(m) => m,
        None => anyhow::bail!("`proxy:` must be a mapping when migrating legacy features.* blocks"),
    };
    let extensions_key = YamlValue::String("extensions".to_string());
    let extensions_val = proxy_map
        .entry(extensions_key)
        .or_insert_with(|| YamlValue::Mapping(serde_yaml::Mapping::new()));
    let extensions_map = match extensions_val.as_mapping_mut() {
        Some(m) => m,
        None => {
            anyhow::bail!("`proxy.extensions:` must be a mapping when migrating legacy features.*");
        }
    };

    for (canonical, value) in migrated {
        let key = YamlValue::String(canonical.clone());
        if extensions_map.contains_key(&key) {
            anyhow::bail!(
                "config conflict: both `features.{}` and `proxy.extensions.{}` are set; \
                 remove the legacy `features.*` block",
                MIGRATED_FEATURE_KEYS
                    .iter()
                    .find(|(_, c)| *c == canonical)
                    .map(|(l, _)| *l)
                    .unwrap_or(canonical.as_str()),
                canonical,
            );
        }
        extensions_map.insert(key, value);
    }

    serde_yaml::to_string(&root).context("failed to re-serialise YAML during migration")
}

/// Lift a schema-v1 (Go v0.1.x) flat single-origin file into
/// `origins: { <hostname>: { ... } }` (WOR-2706).
///
/// The archived Go schema put `hostname`, `action`, `authentication`,
/// and the rest of an origin's behaviour at the document root. The
/// current `ConfigFile` only stores origin behaviour under `origins:`,
/// so without this rewrite those keys warn as unknown and the compiled
/// proxy has no origins.
///
/// A file that already has a non-empty `origins:` map is left alone:
/// that is the current schema, and a hybrid document that staples
/// leftover metadata onto a real origin map must not have its origin
/// fields stolen out from under it. A document with no `hostname` or
/// no `action` is not a flat origin file.
fn migrate_flat_v1_origin(yaml: &str) -> Result<String> {
    use serde_yaml::Value as YamlValue;

    let mut root: YamlValue = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => {
            // Defer parse errors to the typed `compile_config` path so
            // operators see a single canonical error message.
            return Ok(yaml.to_string());
        }
    };
    let Some(map) = root.as_mapping_mut() else {
        return Ok(yaml.to_string());
    };

    // Keys that already live on `ConfigFile` stay at the root.
    const CONFIG_FILE_KEYS: &[&str] = &[
        "source",
        "extensions",
        "proxy",
        "origins",
        "access_log",
        "agent_classes",
        "rate_limits",
        "audit",
        "egress",
        "session_ledger",
        "request_events",
        "events",
        "flags",
        "update",
        "origin_defaults",
        "origin_sources",
    ];
    // Go-era document metadata. These have no current `ConfigFile`
    // field; leaving them at the root keeps the existing warn-on-
    // unknown-top-level behaviour rather than failing as nested
    // unknowns under the new origin.
    const V1_METADATA_KEYS: &[&str] = &[
        "config_version",
        "id",
        "hostname",
        "workspace_id",
        "version",
        "environment",
        "tags",
        "debug",
    ];

    let hostname_key = YamlValue::String("hostname".to_string());
    let action_key = YamlValue::String("action".to_string());
    let origins_key = YamlValue::String("origins".to_string());

    let hostname = match map.get(&hostname_key).and_then(YamlValue::as_str) {
        Some(host) if !host.is_empty() => host.to_string(),
        _ => return Ok(yaml.to_string()),
    };
    if map.get(&action_key).is_none() {
        return Ok(yaml.to_string());
    }
    let origins_occupied = match map.get(&origins_key) {
        None | Some(YamlValue::Null) => false,
        Some(YamlValue::Mapping(existing)) => !existing.is_empty(),
        Some(_) => true,
    };
    if origins_occupied {
        return Ok(yaml.to_string());
    }

    let mut origin = serde_yaml::Mapping::new();
    let keys: Vec<YamlValue> = map.keys().cloned().collect();
    for key in keys {
        let Some(name) = key.as_str() else {
            continue;
        };
        if CONFIG_FILE_KEYS.contains(&name) || V1_METADATA_KEYS.contains(&name) {
            continue;
        }
        if let Some(value) = map.remove(&key) {
            origin.insert(key, value);
        }
    }
    if origin.is_empty() {
        return Ok(yaml.to_string());
    }

    rewrite_v1_origin_fields(&mut origin);

    tracing::warn!(
        hostname = %hostname,
        "config: lifting a schema-v1 flat origin into `origins`"
    );

    let mut origins = match map.remove(&origins_key) {
        Some(YamlValue::Mapping(existing)) => existing,
        _ => serde_yaml::Mapping::new(),
    };
    origins.insert(YamlValue::String(hostname), YamlValue::Mapping(origin));
    map.insert(origins_key, YamlValue::Mapping(origins));
    map.remove(&hostname_key);

    serde_yaml::to_string(&root).context("failed to re-serialise YAML during v1 origin migration")
}

/// Translate Go-era origin field spellings that the current typed
/// structs would otherwise refuse as nested unknowns.
fn rewrite_v1_origin_fields(origin: &mut serde_yaml::Mapping) {
    use serde_yaml::Value as YamlValue;

    let Some(YamlValue::Sequence(rules)) =
        origin.get_mut(YamlValue::String("forward_rules".to_string()))
    else {
        return;
    };
    for rule in rules.iter_mut() {
        let Some(map) = rule.as_mapping_mut() else {
            continue;
        };
        let Some(prefix) = map.remove(YamlValue::String("path_prefix".to_string())) else {
            continue;
        };
        if map.contains_key(YamlValue::String("rules".to_string())) {
            continue;
        }
        let mut matcher = serde_yaml::Mapping::new();
        matcher.insert(YamlValue::String("match".to_string()), prefix);
        map.insert(
            YamlValue::String("rules".to_string()),
            YamlValue::Sequence(vec![YamlValue::Mapping(matcher)]),
        );
    }
}

/// Validate one `cache.key` / `cache.admit` decision script.
///
/// Same `source` + `engine` shape as `custom_fields`, deliberately: one
/// surface with the engine as an operator choice rather than a second
/// mechanism with its own rules. The accepted set is narrower, because
/// these events return documents and `custom_fields` returns a scalar.
///
/// Refusing at load rather than per request matters more here than for a
/// log field: a cache event that fails every evaluation degrades
/// silently to the static config, and the only symptom is a hit rate
/// that never improves.
pub(crate) fn validate_decision_script(
    what: &str,
    script: &crate::types::DecisionScriptConfig,
) -> anyhow::Result<()> {
    if script.source.trim().is_empty() {
        anyhow::bail!("{what}: `source` is empty");
    }
    match script.engine.as_str() {
        "lua" | "js" => Ok(()),
        // CEL is refused here on the design's own terms rather than by
        // omission. These events return a *document*: `cache.key` a list
        // of dimensions, `cache.admit` a `{store, ttl_secs, reason}`
        // object. CEL evaluates to one scalar, so supporting it would
        // mean inventing a token grammar to pack a document into a
        // string, which is exactly the mistake `route_to:gpt-4o-mini`
        // already made once and this epic exists to stop repeating.
        //
        // CEL keeps every surface where a scalar *is* the answer: policy
        // expressions, rate-limit and WAF keys, custom log fields, and
        // the transform's header rules.
        "cel" => anyhow::bail!(
            "{what}: engine `cel` cannot answer this event: it returns a single scalar and this \
             event returns a document (a list of key dimensions, or `store` plus `ttl_secs`). \
             Use `lua` or `js`, which return documents natively."
        ),
        "wasm" => anyhow::bail!(
            "{what}: engine `wasm` is not supported here: WASM is a compiled module, not inline \
             source. Attach a WASM hook through an extension bundle, or use `lua` or `js`."
        ),
        other => {
            anyhow::bail!("{what}: unknown engine `{other}` (expected `lua` or `js`)")
        }
    }
}

/// Validate one origin's `comp:` block (WOR-2673).
///
/// Every refusal here is a catalog an operator would otherwise publish
/// and then watch fail one buyer at a time: a tier nobody can redeem, a
/// price that does not apply to its own pricing model, a buyer key that
/// is not a key. The bridge itself is built at pipeline construction
/// and needs secrets to do it; this runs on a machine that has none.
fn validate_comp_marketplace(
    comp: &crate::types::CompMarketplaceConfig,
    olp: Option<&crate::types::OlpConfig>,
) -> Result<()> {
    // The bridge has no issuer of its own. It signs the license token it
    // returns with the origin's OLP key so that the origin's own
    // `/.well-known/olp/introspect` verifies it; without that block
    // there is nothing to sign with and nothing to verify against.
    if !olp.is_some_and(|olp| olp.enabled) {
        anyhow::bail!(
            "config compile: comp.enabled needs olp.enabled on the same origin. The bridge \
             mints its license tokens with olp.signing_key so this origin's own \
             /.well-known/olp/introspect verifies them"
        );
    }
    if comp.master_key.trim().is_empty() {
        anyhow::bail!("config compile: comp.master_key must not be empty");
    }
    if comp.rotation_id.trim().is_empty() {
        anyhow::bail!("config compile: comp.rotation_id must not be empty");
    }
    if comp.publisher.name.trim().is_empty() || comp.publisher.contact.trim().is_empty() {
        anyhow::bail!(
            "config compile: comp.publisher.name and comp.publisher.contact are required"
        );
    }
    if comp.tiers.is_empty() {
        anyhow::bail!(
            "config compile: comp.tiers must not be empty; a manifest with no tiers publishes \
             nothing a buyer can quote"
        );
    }
    let mut seen: Vec<&str> = Vec::with_capacity(comp.tiers.len());
    for tier in &comp.tiers {
        if tier.id.trim().is_empty() {
            anyhow::bail!("config compile: comp.tiers[].id must not be empty");
        }
        if seen.contains(&tier.id.as_str()) {
            anyhow::bail!(
                "config compile: comp.tiers[].id '{}' appears twice; a quote request names a \
                 tier by id and would resolve to whichever came first",
                tier.id
            );
        }
        seen.push(tier.id.as_str());
        if tier.license.trim().is_empty() {
            anyhow::bail!(
                "config compile: comp.tiers[{}].license must name the license URN the minted \
                 token grants",
                tier.id
            );
        }
        match tier.authorization.as_str() {
            "public" | "cap" | "olp" => {}
            other => anyhow::bail!(
                "config compile: comp.tiers[{}].authorization '{other}' is not one of public, \
                 cap, olp",
                tier.id
            ),
        }
        match tier.shape.as_str() {
            "html" | "json-envelope" | "bulk-archive" => {}
            other => anyhow::bail!(
                "config compile: comp.tiers[{}].shape '{other}' is not one of html, \
                 json-envelope, bulk-archive",
                tier.id
            ),
        }
        match tier.pricing.model.as_str() {
            "free" => {}
            "per_request" => {
                if tier.pricing.amount_micros.is_none() {
                    anyhow::bail!(
                        "config compile: comp.tiers[{}].pricing.model is per_request, which \
                         prices from amount_micros; set it or the tier quotes at zero",
                        tier.id
                    );
                }
            }
            "flat_rate" => {
                if tier.pricing.amount.is_none() {
                    anyhow::bail!(
                        "config compile: comp.tiers[{}].pricing.model is flat_rate, which \
                         prices from amount; set it or the tier quotes at zero",
                        tier.id
                    );
                }
            }
            other => anyhow::bail!(
                "config compile: comp.tiers[{}].pricing.model '{other}' is not one of free, \
                 per_request, flat_rate",
                tier.id
            ),
        }
        if tier.pricing.currency.trim().len() != 3 {
            anyhow::bail!(
                "config compile: comp.tiers[{}].pricing.currency must be a three-letter ISO 4217 \
                 code",
                tier.id
            );
        }
    }
    // `redeem` only mints for OLP-authorized tiers, and it mints for
    // exactly one. Nothing in a redeem request names a tier: the buyer
    // sends a `quote_id`, and this bridge keeps no durable
    // quote-to-tier mapping. So zero redeemable tiers is an endpoint
    // that refuses everything, and two is an endpoint that hands a
    // buyer whichever one the manifest lists first.
    //
    // The second half is the same hazard as the duplicate-tier-id
    // refusal above, and it is refused here for the same reason: a
    // documented limit an operator can configure their way into is an
    // invariant held by prose (WOR-2673 review B2).
    let olp_tiers: Vec<&str> = comp
        .tiers
        .iter()
        .filter(|tier| tier.authorization == "olp")
        .map(|tier| tier.id.as_str())
        .collect();
    match olp_tiers.as_slice() {
        [] => anyhow::bail!(
            "config compile: comp.tiers has no tier with authorization: olp, and redeem can \
             only mint a license token for an OLP tier"
        ),
        [_one] => {}
        [first, second, ..] => anyhow::bail!(
            "config compile: comp.tiers carries more than one tier with authorization: olp \
             ('{first}' and '{second}'). A redeem request names a quote_id and no tier, and \
             this bridge keeps no quote-to-tier store, so it would mint '{first}' for a buyer \
             who quoted '{second}'. Advertise the others as authorization: cap or public, or \
             split them across origins"
        ),
    }
    if comp.buyer_keys.is_empty() {
        anyhow::bail!(
            "config compile: comp.buyer_keys must not be empty; a redeem request is refused \
             unless its signing kid resolves here, so an empty list refuses every redeem"
        );
    }
    let mut seen_kids: Vec<&str> = Vec::with_capacity(comp.buyer_keys.len());
    for key in &comp.buyer_keys {
        if key.kid.trim().is_empty() {
            anyhow::bail!("config compile: comp.buyer_keys[].kid must not be empty");
        }
        if seen_kids.contains(&key.kid.as_str()) {
            anyhow::bail!(
                "config compile: comp.buyer_keys[].kid '{}' appears twice",
                key.kid
            );
        }
        seen_kids.push(key.kid.as_str());
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            key.public_key.trim(),
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "config compile: comp.buyer_keys[{}].public_key is not base64url without \
                 padding: {error}",
                key.kid
            )
        })?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "config compile: comp.buyer_keys[{}].public_key decoded to {} bytes; an Ed25519 \
                 public key is 32",
                key.kid,
                decoded.len()
            );
        }
    }
    if let Some(hash) = comp.manifest_hash.as_deref() {
        if !hash.starts_with("sha256:") {
            anyhow::bail!(
                "config compile: comp.manifest_hash must be `sha256:<hex>`; leave it unset to \
                 have the proxy compute it over the manifest it publishes"
            );
        }
    }
    Ok(())
}

/// Validate `observability.log.custom_fields:` at config-load time.
///
/// Each field must declare exactly one value source (`value`, or
/// `source` + `engine`), have a non-empty unique name, and name a
/// supported engine. WASM is rejected with a pointer to the reason:
/// inline `source` is text, and a WASM log field would need a compiled
/// module path instead.
fn validate_custom_log_fields(fields: &[crate::CustomLogFieldConfig]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for field in fields {
        if field.name.trim().is_empty() {
            anyhow::bail!("observability.log.custom_fields: a field has an empty `name`");
        }
        if !seen.insert(field.name.as_str()) {
            anyhow::bail!(
                "observability.log.custom_fields: duplicate field name `{}`",
                field.name
            );
        }
        let has_value = field.value.is_some();
        let has_source = field.source.is_some();
        if has_value && has_source {
            anyhow::bail!(
                "observability.log.custom_fields: field `{}` sets both `value` and `source`; pick one",
                field.name
            );
        }
        if !has_value && !has_source {
            anyhow::bail!(
                "observability.log.custom_fields: field `{}` sets neither `value` nor `source`",
                field.name
            );
        }
        if has_source {
            match field.engine.as_deref() {
                Some("cel") | Some("lua") | Some("js") => {}
                Some("wasm") => anyhow::bail!(
                    "observability.log.custom_fields: field `{}` uses engine `wasm`, which is not \
                     supported for log fields: WASM is a compiled module, not inline source. Use \
                     `cel`, `lua`, or `js`.",
                    field.name
                ),
                Some(other) => anyhow::bail!(
                    "observability.log.custom_fields: field `{}` uses unknown engine `{other}` \
                     (expected `cel`, `lua`, or `js`)",
                    field.name
                ),
                None => anyhow::bail!(
                    "observability.log.custom_fields: field `{}` sets `source` but no `engine`",
                    field.name
                ),
            }
        }
    }
    Ok(())
}

/// Validate `observability.log.decision_audit:` at config-load time.
///
/// Two refusals, both landing on the same property: a misconfigured
/// audit feed is silent, and silence is indistinguishable from a feed
/// that is working and quiet. Neither mistake can be found by looking
/// at the proxy afterwards, so both are found here.
///
/// 1. An event label naming no decision this proxy makes. Accepting it
///    would leave an operator believing they had an audit trail.
/// 2. `ai.stream.event: true`. That event fires once per streamed
///    chunk, so a per-event audit record is an ingest bill rather than
///    a control. `ai.close` carries the stream's summary instead.
///    Writing `ai.stream.event: false` stays legal: saying out loud
///    that a feed is off is a reasonable thing for an operator to do.
///
/// The second refusal is deliberately not the only defense.
/// [`crate::DecisionAuditConfig::publishes`] answers `false` for that
/// label whatever the config says, because this function iterates
/// `events` and so cannot see the config that reaches the same feed
/// through the master switch (`enabled: true` with no `events:` map).
/// Both are kept: the type makes the feed unreachable, and this
/// refusal means a config that asked for it fails loudly instead of
/// being silently ignored.
fn validate_decision_audit(audit: &crate::DecisionAuditConfig) -> Result<()> {
    use sbproxy_observe::decision::DecisionEvent;

    for (label, enabled) in &audit.events {
        let Some(event) = DecisionEvent::from_label(label) else {
            let accepted = DecisionEvent::ALL
                .iter()
                .map(|event| event.as_label())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "observability.log.decision_audit.events names `{label}`, which is not a \
                 decision this proxy makes. A label that matches nothing turns nothing on, and \
                 an audit feed that emits nothing looks exactly like one with nothing to say. \
                 Accepted values: {accepted}."
            );
        };
        if *enabled && event == DecisionEvent::AiStreamEvent {
            anyhow::bail!(
                "observability.log.decision_audit.events sets `ai.stream.event: true`, and that is \
                 the one event that cannot be turned on: it fires once per streamed chunk, so a \
                 per-event audit record is an ingest bill rather than a control. Enable \
                 `ai.close` instead, which carries the stream's summary once the response \
                 finishes."
            );
        }
    }
    Ok(())
}

/// Reject a `proxy.admin.bind` value that is not an IP address.
///
/// The admin server used to fall back to `127.0.0.1` when the bind
/// string failed to parse, so `bind: 0.0.0..1` (or a hostname, which is
/// also not accepted) looked like it worked while quietly serving
/// somewhere else than asked. An operator who typed a wide bind and got
/// loopback would have drawn exactly the wrong conclusion about what is
/// exposed, so a typo fails the compile instead.
fn validate_admin_bind(bind: Option<&str>) -> Result<()> {
    let Some(bind) = bind else {
        return Ok(());
    };
    let trimmed = bind.trim();
    if trimmed.parse::<std::net::IpAddr>().is_err() {
        anyhow::bail!(
            "proxy.admin.bind is `{bind}`, which is not an IP address. Use an address \
             literal such as `127.0.0.1`, `::1`, or `0.0.0.0` (hostnames are not \
             resolved). Startup used to fall back to loopback on a value it could not \
             parse, which hid the typo behind an admin server bound somewhere other \
             than the one you asked for."
        );
    }
    Ok(())
}

/// True when `entry` (an exact IP or a CIDR from `proxy.admin.allow_ips`)
/// admits nothing but loopback peers.
///
/// Both `127.0.0.1` and `127.0.0.0/8` are loopback-only; `10.0.0.0/8` is
/// not, and neither is `127.0.0.0/7`, which spans `126.0.0.0` upward. An
/// entry that parses as neither an address nor a CIDR cannot be proven
/// loopback-only, so it counts as reachable: the point of the check is to
/// be sure, not to be lenient.
///
/// Parsed by hand rather than with a CIDR crate because `sbproxy-config`
/// deliberately carries no network-address dependency; the runtime filter
/// in `sbproxy-core` does the real matching.
fn admin_allow_entry_is_loopback_only(entry: &str) -> bool {
    let trimmed = entry.trim();
    let (addr_part, prefix_part) = match trimmed.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (trimmed, None),
    };
    let Ok(addr) = addr_part.parse::<std::net::IpAddr>() else {
        return false;
    };
    // `::ffff:127.0.0.1` is a loopback peer wearing IPv6 clothing;
    // canonicalising first means it is judged as the v4 address it is.
    let canonical = addr.to_canonical();
    if !canonical.is_loopback() {
        return false;
    }
    let Some(prefix) = prefix_part else {
        return true;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    // The whole network has to sit inside the loopback space: 127.0.0.0/8
    // for v4, and only the single `::1` for v6.
    match canonical {
        std::net::IpAddr::V4(_) => prefix >= 8,
        std::net::IpAddr::V6(_) => prefix >= 128,
    }
}

/// Refuse the shipped default admin credentials on an admin surface that
/// is reachable from off the local machine.
///
/// `admin` / `changeme` is a published constant, so a reachable admin
/// server carrying it is effectively unauthenticated, and the admin API
/// mints API keys, reads and rewrites the config, and drives the model
/// host. The surface counts as reachable when either `bind` is not a
/// loopback address or `allow_ips` admits a peer outside loopback. The
/// error names whichever of the two tripped.
///
/// Loopback-only with the defaults stays valid on purpose: that is the
/// first-run and local-development path, where the credentials guard
/// nothing that the local user does not already have.
fn validate_admin_reachable_credentials(admin: &crate::types::AdminConfig) -> Result<()> {
    if admin.password != crate::types::DEFAULT_ADMIN_PASSWORD {
        return Ok(());
    }
    let mut reasons: Vec<String> = Vec::new();
    if let Some(bind) = admin.bind.as_deref() {
        // A bind that does not parse is already rejected by
        // `validate_admin_bind`; treat it as reachable here so the two
        // checks cannot disagree about what an unparseable value means.
        let loopback = bind
            .trim()
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.to_canonical().is_loopback());
        if !loopback {
            reasons.push(format!(
                "proxy.admin.bind is `{bind}`, which is not a loopback address"
            ));
        }
    }
    let off_loopback: Vec<&str> = admin
        .allow_ips
        .iter()
        .map(String::as_str)
        .filter(|entry| !admin_allow_entry_is_loopback_only(entry))
        .collect();
    if !off_loopback.is_empty() {
        reasons.push(format!(
            "proxy.admin.allow_ips admits peers outside loopback ({})",
            off_loopback.join(", ")
        ));
    }
    if reasons.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "proxy.admin.password is still the shipped default `{}`, and the admin surface is \
         reachable off loopback: {}. Set a real password (`password: ${{ADMIN_PASSWORD}}` \
         with the variable exported, or a secret reference), or keep the admin server on \
         loopback. The default is a published constant, so a reachable admin server using \
         it is open to anyone who can route to the port, and the admin API mints API keys \
         and rewrites config.",
        crate::types::DEFAULT_ADMIN_PASSWORD,
        reasons.join("; ")
    );
}

/// Refuse the shipped default admin credentials on a node that publishes
/// configuration bundles, whatever its admin server is bound to.
///
/// The reachability test in [`validate_admin_reachable_credentials`] is the
/// right one for an ordinary node: loopback with the defaults is the
/// first-run path and guards nothing the local user does not already have.
/// A publishing node is different. Its admin API is where a fleet's
/// configuration is authored and signed, so `admin` / `changeme` there is
/// not "a local convenience", it is a published constant standing between
/// anyone who reaches the port and every subscriber's running config. The
/// blast radius is the fleet, not the box, so the bind does not enter into
/// it.
fn validate_publishing_node_admin_credentials(
    admin: Option<&crate::types::AdminConfig>,
) -> Result<()> {
    let Some(admin) = admin.filter(|admin| admin.enabled) else {
        // No admin server means no publish route and no status route, so
        // there is no credential to be weak. The node can still serve the
        // bundle listener from a config an operator publishes some other
        // way, which is an odd but coherent deployment.
        return Ok(());
    };
    if admin.password != crate::types::DEFAULT_ADMIN_PASSWORD {
        return Ok(());
    }
    anyhow::bail!(
        "proxy.config_authority.publish is set and proxy.admin.password is still the shipped \
         default `{}`. A publishing node's admin API validates, signs, and publishes the \
         configuration every subscriber then applies, so the default password there is not a \
         local-development convenience: it is a published constant guarding a fleet-wide \
         write. Set a real password (`password: ${{ADMIN_PASSWORD}}` with the variable \
         exported, or a secret reference) before this node publishes anything. Unlike \
         proxy.admin on an ordinary node, binding to loopback does not make this acceptable.",
        crate::types::DEFAULT_ADMIN_PASSWORD
    )
}

/// Refuse a publishing node whose signing key cannot be loaded.
///
/// An authority that cannot sign cannot serve. Checked here rather than at
/// the first publication so the failure lands at boot, or in `sbproxy
/// validate`, instead of in the middle of a change window when an operator
/// is trying to push a fix. Loads through the same constructor the running
/// authority uses, so "readable" means readable in the way that matters:
/// present, bounded, owner-only, and a valid Ed25519 seed.
fn validate_publish_signing_key(
    publish: &crate::types::ConfigAuthorityPublishConfig,
) -> Result<()> {
    crate::config_bundle::ConfigBundleSigner::ed25519_from_seed_file(
        publish.key_id.as_str(),
        &publish.signing_key_file,
    )
    .map(|_| ())
    .map_err(|error| {
        anyhow::anyhow!(
            "proxy.config_authority.publish.signing_key_file '{}' is not a usable signing key: \
             {error}. Generate one with `head -c 32 /dev/urandom | base64 > {}` and \
             `chmod 600` it, then publish the matching verifying key to subscribers with \
             `GET /admin/config-authority/status`. An authority that cannot sign cannot serve, \
             so this is refused at startup rather than at the first publish attempt.",
            publish.signing_key_file,
            publish.signing_key_file,
        )
    })
}

fn validate_compression_state_local_path(path: &str) -> Result<()> {
    const MAX_PATH_BYTES: usize = 4_096;
    let field = "proxy.compression_state.local_path";

    if path.trim().is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    if path.len() > MAX_PATH_BYTES {
        anyhow::bail!("{field} must not exceed {MAX_PATH_BYTES} bytes");
    }
    if path.chars().any(char::is_control) {
        anyhow::bail!("{field} must not contain control characters");
    }
    if !std::path::Path::new(path).is_absolute() {
        anyhow::bail!("{field} must be an absolute path");
    }
    Ok(())
}

/// Compile a raw YAML config string into a `CompiledConfig`.
///
/// # Errors
///
/// Returns an error if the YAML fails to parse, if a config mixes the
/// legacy `features.*` blocks with the canonical `extensions` shape, if
/// any origin or L2 cache backend fails to compile, or if the config
/// sets `proxy.messenger_settings`, which this build refuses (WOR-2166).
///
/// Also refuses the keys that parse and govern nothing (WOR-2310):
/// `proxy.device_parser_file`, `origins.*.traffic_capture`,
/// `origins.*.sessions.ttl_seconds`, and `max_connections` /
/// `max_lifetime_secs` under `origins.*.connection_pool`. Each error
/// names a working surface to move to. `connection_pool.idle_timeout_secs`
/// is not among them: it is live.
///
/// WOR-2325 continues that sweep. The legacy single-backend secrets
/// surface is refused whenever it is authored: `proxy.secrets.backend`,
/// `proxy.secrets.fallback`, and `addr` / `mount` / `token` under
/// `proxy.secrets.hashicorp`. Resolution walks the named entries under
/// `proxy.secrets.backends` and reads no other field on the block, so a
/// Vault credential authored on the legacy shape bought no Vault access.
/// `proxy.secrets.map` and `proxy.secrets.rotation` are deliberately not
/// among them: the map is read, and rotation is reserved surface.
///
/// Three more are value-scoped, refused only for the value that
/// misdescribed the build rather than for the key's presence:
/// `proxy.key_management.governance.key_introspection: true` (no
/// caller-facing introspection route is installed),
/// `proxy.key_management.store.redis_source_of_truth: true` (the store
/// backend already decides the system of record), and
/// `origins.*.cors.enable: false` (CORS is gated on the presence of the
/// `cors:` block, so `false` left it fully on). `enable: true` stays
/// accepted because it agrees with what the block already does.
///
/// The per-origin refusals are applied while each origin compiles, and
/// they also cover the inline forward-origin metadata
/// (`origins.*.forward_rules[].origin.hostname` / `.workspace_id` /
/// `.version`), none of which reaches the compiled child origin.
pub fn compile_config(yaml: &str) -> Result<CompiledConfig> {
    // Interpolate environment variables before parsing YAML.
    let yaml = interpolate_env_vars(yaml);
    // Custom YAML tags are stripped by the parser, turning `!env VAR`
    // into the literal string `VAR`; reject them before anything else
    // reads the file. Unresolved `${VAR}` references are collected here
    // and reported after the typed parse below.
    let unresolved_env_refs = scan_yaml_hazards(&yaml)?;
    // Wave 5 day-6 Item 2: lift legacy `features.anomaly_detection`,
    // `features.reputation`, and `features.tls_fingerprint` blocks
    // into the canonical `proxy.extensions[...]` shape the bootstrap
    // expects. Pure-YAML rewrite so the rest of compile_config sees a
    // single source of truth. Returns an error when the legacy and
    // new shapes coexist (operator must pick one).
    let yaml = migrate_features_to_extensions(&yaml)?;
    // WOR-2706: a Go v0.1.x flat single-origin file has no `origins:`
    // map; rewrite it in memory so the rest of compile sees the current
    // nested shape. A file that already has `origins:` is unchanged.
    let yaml = migrate_flat_v1_origin(&yaml)?;

    // WOR-1976: make every explicitly configured compatibility-only key
    // visible at boot. Inspect the raw YAML so omitted serde-defaulted fields
    // stay quiet; the same registry is enforced against the generated schema
    // by the build-time reader guard.
    if let Ok(raw_yaml) = serde_yaml::from_str::<serde_yaml::Value>(&yaml) {
        for key in crate::key_registry::configured_config_only_keys(&raw_yaml) {
            tracing::warn!(
                config_key = key.path,
                reason = key.note.unwrap_or("no live OSS consumer"),
                "config-only key is set and does not activate runtime behavior"
            );
        }
    }

    // Reject the legacy `virtual_keys:` YAML key with a pointer to
    // the migration guide. The credentials epic replaces it with the
    // canonical `credentials:` block; an operator with the old shape
    // sees a hard compile error rather than a silent ignore.
    if yaml_uses_legacy_virtual_keys(&yaml) {
        anyhow::bail!(
            "config compile: the legacy `virtual_keys:` YAML key is no longer supported. \
             Rewrite the block as `credentials: - type: ai_provider ...` per \
             `docs/migration-credentials.md`."
        );
    }

    // WOR-2311: reject the removed origin-level `rate_limit_headers:` key.
    // It parsed for years and did nothing; the runtime emits
    // `X-RateLimit-*` and `Retry-After` from the rate-limiting policy's
    // own `headers` block. A key that parses and does not govern is a
    // defect, so it is refused with a pointer rather than silently
    // dropped or bounced as a generic unknown key.
    if let Some(hostname) = yaml_origin_with_removed_rate_limit_headers(&yaml) {
        anyhow::bail!(
            "config compile: origin `{hostname}` sets `rate_limit_headers:`, which has been \
             removed. The origin-level block was never consumed: `X-RateLimit-*` and \
             `Retry-After` are emitted by the rate-limiting policy itself. Delete the block \
             and configure the policy instead, as \
             `policies: - type: rate_limiting ... headers: {{ enabled: true, \
             include_retry_after: true }}`. See the `Rate limit headers` section of \
             `docs/configuration.md`."
        );
    }

    // WOR-2312: reject a top-level `model_aliases:` block. Aliases are an
    // AI-gateway key and are read from the `ai_proxy` action, where the
    // providers they name live. At the root they would parse and do
    // nothing, and the shape was documented that way, so it is refused
    // with the live path rather than silently ignored.
    if yaml_uses_top_level_model_aliases(&yaml) {
        anyhow::bail!(
            "config compile: `model_aliases:` is set at the top level, where nothing reads it. \
             Model aliases belong to the AI gateway action that serves them: move the block to \
             `origins.<hostname>.action.model_aliases` alongside that action's `providers:`. \
             See the `Model aliases` section of `docs/ai-gateway.md`."
        );
    }

    // WOR-2657: the same refusal for a top-level `model_groups:` block.
    // A group's members name providers on one action, so the block is
    // meaningless anywhere else, and at the root it would parse and be
    // dropped.
    if yaml_uses_top_level_model_groups(&yaml) {
        anyhow::bail!(
            "config compile: `model_groups:` is set at the top level, where nothing reads it. \
             Model groups belong to the AI gateway action whose providers serve their members: \
             move the block to `origins.<hostname>.action.model_groups` alongside that action's \
             `providers:`. See the `Model groups` section of `docs/ai-gateway.md`."
        );
    }

    // WOR-2325: refuse the legacy single-backend secrets surface. Every one
    // of these parsed, validated, and selected nothing: secret resolution
    // walks the named entries under `proxy.secrets.backends` and reads no
    // other field on the block. The Vault three are why this is a refusal
    // rather than one more boot warning, because an operator who set
    // `proxy.secrets.hashicorp.token` had every reason to believe the proxy
    // was authenticating to Vault with it and the proxy never opened a
    // connection.
    //
    // Read off the raw YAML for two reasons. Presence is what is being
    // refused and two of the five carry serde defaults, and `hashicorp.addr`
    // is a required field, so a half-authored legacy block would otherwise
    // die on `missing field addr` instead of on the migration.
    //
    // The message names the keys and never their values: one of the three
    // is a credential.
    let legacy_secrets_keys = yaml_legacy_secrets_keys(&yaml);
    if !legacy_secrets_keys.is_empty() {
        anyhow::bail!(
            "config compile: legacy `proxy.secrets` key(s) that nothing reads: {}. Secret \
             resolution walks the named entries under `proxy.secrets.backends` and consults no \
             other field on the block, so an address, a mount, or a token authored on the legacy \
             shape bought no access to anything: no connection was ever opened with it. Rewrite \
             the block as a named backend, `proxy.secrets.backends: - type: hashicorp, name: \
             primary, addr: https://vault.example/v1, mount: secret, auth: {{ type: token, \
             token: ${{VAULT_TOKEN}} }}`, and reference it from each consumer as \
             `vault://primary/<path>`. `proxy.secrets.map` is unaffected and stays supported. \
             See the `Secrets` section of `docs/configuration.md`.",
            legacy_secrets_keys.join(", ")
        );
    }

    // WOR-1140: two layers reject misspelled keys, so a typo is a hard
    // boot error rather than a silent drop that takes the field's
    // (often protection-disabling) default.
    //
    // The first layer is `#[serde(deny_unknown_fields)]` on every
    // struct in the config schema below the root: an unknown nested key
    // fails the typed parse itself, including inside tagged enums
    // (`credentials[].policies[]`, `secrets.backends[]`, ...) whose
    // buffered content `serde_ignored` cannot see into. The root
    // `ConfigFile` deliberately stays permissive because the archived
    // Go v0.1.x schema was a flat single-origin file whose keys all sit
    // at the top level; those fall through to the second layer.
    //
    // The second layer is this `serde_ignored` pass, which reports the
    // top-level leftovers so they can warn (v1 compat) below. The
    // schema's deliberate arbitrary-key blocks (`proxy.extensions` /
    // origin `extensions` are `HashMap<String, Value>`, and `action` /
    // `policies` / `transforms` / `authentication` / `variables` are
    // opaque `serde_json::Value` handed to the module layer) accept any
    // key under either layer. The `sbproxy serve` boot path runs
    // `compile_config`, so both gates fire on boot and reload, not just
    // the `validate` subcommand.
    let mut unknown_keys: Vec<String> = Vec::new();
    let mut config_file: ConfigFile = {
        let de = serde_yaml::Deserializer::from_str(&yaml);
        serde_ignored::deserialize(de, |path| {
            unknown_keys.push(path.to_string());
        })
        .context("failed to parse config YAML")?
    };
    // Split unknown keys by nesting. The archived Go `v0.1.x` schema was
    // a flat single-origin file (`config_version`, `id`, `hostname`,
    // `action`, ...) whose keys all sit at the TOP level; the
    // schema-v1 compatibility promise tolerates those, so a top-level
    // unknown only warns. A NESTED unknown (`proxy.*`, `origins.*.*`) in
    // the schema-v2 shape is a real typo in a server / security / origin
    // block - e.g. `mtls`->`mtsl`, `trusted_proxies`->`trusted_proxy`,
    // `force_ssl`->`forced_ssl` - which silently disables the intended
    // protection, so that fails the compile (and thus boot / reload).
    let (nested_unknowns, top_unknowns): (Vec<String>, Vec<String>) =
        unknown_keys.into_iter().partition(|k| k.contains('.'));
    if !top_unknowns.is_empty() {
        tracing::warn!(
            keys = %top_unknowns.join(", "),
            "config: ignored unknown/misspelled top-level key(s); each is dropped and \
             takes its default. Check for typos, or move an out-of-tree block under \
             `proxy.extensions:`."
        );
    }
    if !nested_unknowns.is_empty() {
        anyhow::bail!(
            "config compile: unknown or misspelled config key(s): {}. A typo in a nested \
             server / security / origin key is silently dropped and the setting takes its \
             default (often disabling the protection you intended), so boot is rejected. \
             Fix the spelling, or nest an out-of-tree block under `proxy.extensions:` (or \
             the origin's `extensions:`).",
            nested_unknowns.join(", ")
        );
    }

    // WOR-2227: a secret reference whose authority is not declared under
    // `proxy.secrets.backends` used to compile, validate, and plan clean,
    // then die at boot inside whichever module first tried to resolve it.
    // Three shipped examples were broken that way. Checked here rather
    // than at resolve time so `sbproxy validate`, `sbproxy plan`, and the
    // example sweeps all inherit it without touching a backend.
    crate::secret_refs::check_secret_backend_references(&yaml, config_file.proxy.secrets.as_ref())?;

    if let Some(classifier_hooks) = config_file.proxy.classifier_hooks.as_ref() {
        classifier_hooks
            .validate()
            .context("config compile: proxy.classifier_hooks")?;
    }
    validate_ai_toolkit_config(&config_file)?;

    {
        let mut names = std::collections::HashSet::with_capacity(config_file.flags.len());
        for flag in &config_file.flags {
            if flag.name.trim().is_empty() {
                anyhow::bail!("config compile: flags[].name must not be empty");
            }
            if !names.insert(flag.name.as_str()) {
                anyhow::bail!(
                    "config compile: duplicate top-level feature flag name `{}`",
                    flag.name
                );
            }
            if flag.rules.rollout_percent > 100 {
                anyhow::bail!(
                    "config compile: flag `{}` has rollout_percent {}; expected 0..=100",
                    flag.name,
                    flag.rules.rollout_percent
                );
            }
        }
    }

    // WOR-2436: both composition blocks are checked here rather than in
    // the aggregator, so `sbproxy validate`, `sbproxy plan` and boot all
    // inherit the same refusals. An operator learns that a production
    // entry follows a branch, or that two project repositories claim the
    // same hostname, before anything has been fetched.
    // A document that declares an extension bundle source may name a
    // policy or transform type this build cannot resolve from here; see
    // `origin_profile::UnknownTypes`.
    let declares_extension_bundles = config_file.extensions.declares_any_source();
    if let Some(defaults) = config_file.origin_defaults.as_ref() {
        crate::origin_profile::validate_origin_defaults_with(defaults, declares_extension_bundles)
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;
    }
    if let Some(sources) = config_file.origin_sources.as_ref() {
        crate::origin_profile::validate_origin_sources_with(sources, declares_extension_bundles)
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;
        let hand_written: std::collections::BTreeSet<String> =
            config_file.origins.keys().cloned().collect();
        let claims = crate::origin_profile::claimed_hosts(&sources.entries, &hand_written)
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;
        let pinned = sources
            .entries
            .iter()
            .filter(|entry| {
                entry
                    .revision
                    .as_deref()
                    .is_some_and(crate::origin_profile::revision_is_immutable)
            })
            .count();
        tracing::info!(
            tier = sources.tier.as_str(),
            entries = sources.entries.len(),
            pinned,
            unpinned = sources.entries.len().saturating_sub(pinned),
            claimed_hosts = claims.len(),
            "origin_sources declared; composition runs in the aggregator, not on this node"
        );
    }
    // The counts ride on the compiled config rather than being written
    // here: this function also compiles candidate documents. See
    // `origin_profile::origin_source_entry_counts`.
    let origin_source_entries =
        crate::origin_profile::origin_source_entry_counts(config_file.origin_sources.as_ref());

    if config_file
        .proxy
        .http3
        .as_ref()
        .is_some_and(|http3| http3.enabled)
    {
        anyhow::bail!(
            "config compile: proxy.http3.enabled=true is not supported because HTTP/3 is not \
             served by this build. Set `enabled: false` or remove the `http3` block. Native \
             HTTP/3 support is tracked in WOR-2310."
        );
    }

    if let Some(key_management) = config_file.proxy.key_management.as_ref() {
        key_management
            .inbound
            .validate()
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;

        // WOR-2573: the quorum's own field doc promises this refusal, and
        // both ends of the range are reachable and bad. `quorum: 0` makes
        // `approvals.len() >= quorum` true on the first approval and the
        // admin surface then reports the grant as legitimately quorate, so
        // a two-person rule silently becomes a zero-person one. A quorum
        // above the roster can never be met, and an operator discovers that
        // during the incident the grant exists for.
        let break_glass = &key_management.break_glass;
        if break_glass.enabled {
            if break_glass.quorum == 0 {
                anyhow::bail!(
                    "config compile: proxy.key_management.break_glass.quorum is 0, so a grant \
                     would activate on its first approval and the admin surface would report it \
                     as quorate. Set it to at least 1."
                );
            }
            if break_glass.quorum > break_glass.approvers.len() {
                anyhow::bail!(
                    "config compile: proxy.key_management.break_glass.quorum is {} but only {} \
                     approver(s) are configured, so no grant can ever activate. Add approvers or \
                     lower the quorum.",
                    break_glass.quorum,
                    break_glass.approvers.len()
                );
            }
        }

        // WOR-2325: two booleans on this block parse and govern nothing.
        // Both are refused on `true` only, the value that misdescribes the
        // build. `false` is the default and is what the build actually
        // does, so an operator who wrote it has nothing to fix and no
        // reason to be stopped at boot.
        if key_management.governance.key_introspection {
            anyhow::bail!(
                "config compile: proxy.key_management.governance.key_introspection is true, but \
                 this build installs no caller-facing introspection route. There is no \
                 `GET /api/v1/key` handler for the holder of a minted key to call, so the flag \
                 admitted nothing and a caller asking about its own key got the same 404 it \
                 would have without the flag. Remove it, or set it to false. To read a key's \
                 policy and usage today, use `GET /admin/keys/{{id}}` and \
                 `GET /admin/keys/{{id}}/usage` on the admin API, which are \
                 operator-authenticated rather than caller-authenticated."
            );
        }
        if key_management.store.redis_source_of_truth {
            anyhow::bail!(
                "config compile: proxy.key_management.store.redis_source_of_truth is true, but \
                 nothing reads it. The key plane picks its system of record from \
                 `key_management.store.backend` and from nothing else, so selecting `backend: \
                 redis` already makes Redis authoritative and this flag offered a choice that \
                 does not exist: it could neither promote Redis under another backend nor demote \
                 it under its own. Remove it, or set it to false. For a Redis-backed key store, \
                 set `backend: redis` with a `store.url`; otherwise keep the default `embedded` \
                 backend, which is the local redb file."
            );
        }

        let correlation = &config_file.proxy.correlation_id;
        if correlation.enabled
            && key_management
                .inbound
                .is_credential_carrier(&correlation.header)
        {
            anyhow::bail!(
                "config compile: proxy.correlation_id.header {:?} may not also be a primary \
                 credential carrier because correlation IDs are logged, forwarded, and echoed",
                correlation.header
            );
        }
    }

    if let Some(local_path) = config_file
        .proxy
        .compression_state
        .as_ref()
        .and_then(|state| state.local_path.as_deref())
    {
        validate_compression_state_local_path(local_path)?;
    }

    if let Some(config_history) = config_file.proxy.config_history.as_ref() {
        config_history
            .validate()
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;
    }

    // WOR-1818: report interpolation leftovers. An unset `${VAR}` stays
    // literal, which for most fields degrades into a confusing runtime
    // failure. Warn once, listing every remaining reference with its
    // path; the admin credentials upgrade to a hard error because a
    // literal `${ADMIN_PASSWORD}` login string defeats the operator's
    // intent while still "working".
    if !unresolved_env_refs.is_empty() {
        tracing::warn!(
            refs = %unresolved_env_refs.join(", "),
            "config: unresolved ${{VAR}} reference(s) left as literal text; export the \
             variable(s) before starting, or remove the reference"
        );
    }
    if let Some(admin) = &config_file.proxy.admin {
        if admin.enabled {
            for (field, value) in [("password", &admin.password), ("username", &admin.username)] {
                if value.contains("${") {
                    anyhow::bail!(
                        "proxy.admin.{field} contains the unresolved reference `{value}`; \
                         export the environment variable before starting (admin \
                         credentials must never fall back to literal placeholder text)"
                    );
                }
            }
            validate_admin_bind(admin.bind.as_deref())?;
            validate_admin_reachable_credentials(admin)?;
        }
        // 0 is rejected rather than treated as "off": the admin rate
        // limiter is a DDoS bound on an authenticated control surface
        // and cannot be disabled through config.
        if admin.rate_limit_per_minute == 0 || admin.rate_limit_per_minute > 100_000 {
            anyhow::bail!(
                "proxy.admin.rate_limit_per_minute is {}; it must be between 1 and \
                 100000 requests per client IP per minute (the admin rate limiter \
                 cannot be turned off)",
                admin.rate_limit_per_minute
            );
        }
    }

    if let Some(log) = config_file
        .proxy
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
    {
        validate_custom_log_fields(&log.custom_fields)?;
        // Proxy scope only, because that is the only scope carrying the
        // block today. Tenant and origin `decision_audit:` land with the
        // scope composition, and this call grows a sibling per scope the
        // way `validate_custom_log_fields` already has.
        if let Some(audit) = log.decision_audit.as_ref() {
            validate_decision_audit(audit)?;
        }
    }
    // Every scope gets the same validation. A refusal that only covered
    // proxy scope would let a tenant write the typo the proxy block is
    // refused for, which is the shape of gap this guard exists to close.
    for tenant in &config_file.proxy.tenants {
        if let Some(audit) = tenant
            .observability
            .as_ref()
            .and_then(|obs| obs.log.decision_audit.as_ref())
        {
            validate_decision_audit(audit)
                .with_context(|| format!("tenant `{}` observability.log", tenant.id))?;
        }
    }
    for (host, origin) in &config_file.origins {
        if let Some(audit) = origin
            .observability
            .as_ref()
            .and_then(|obs| obs.log.decision_audit.as_ref())
        {
            validate_decision_audit(audit)
                .with_context(|| format!("origin `{host}` observability.log"))?;
        }
    }
    // Tenant- and origin-scope custom_fields use the same validation.
    for tenant in &config_file.proxy.tenants {
        if let Some(obs) = tenant.observability.as_ref() {
            validate_custom_log_fields(&obs.log.custom_fields)
                .with_context(|| format!("tenant `{}` observability.log", tenant.id))?;
        }
    }
    for (host, origin) in &config_file.origins {
        if let Some(obs) = origin.observability.as_ref() {
            validate_custom_log_fields(&obs.log.custom_fields)
                .with_context(|| format!("origin `{host}` observability.log"))?;
        }
    }

    // WOR-2673: the OLP token endpoint's per-source budget. Zero is a
    // refusal rather than "unlimited": that endpoint is unauthenticated,
    // mints an Ed25519 bearer license token per call, and answers ahead
    // of authentication and the policy chain where an origin's own rate
    // limits live, so this value is the only bound on it. A bound one
    // typo away from being off is not a bound.
    for (host, origin) in &config_file.origins {
        if let Some(olp) = origin.olp.as_ref().filter(|olp| olp.enabled) {
            if olp.token_rate_limit_per_minute == 0 {
                anyhow::bail!(
                    "config compile: origin `{host}` olp.token_rate_limit_per_minute is 0, which \
                     is not a way to say unlimited. POST /.well-known/olp/token is \
                     unauthenticated and mints a bearer license token per call, so it always \
                     carries a budget. Remove the key for the default of 60 per minute, or set \
                     the number you want"
                );
            }
        }
    }

    // WOR-2673: the CoMP marketplace bridge. Validated here rather than
    // at pipeline build so `sbproxy validate` catches a catalog nobody
    // can buy from, on a machine that holds none of the secrets.
    for (host, origin) in &config_file.origins {
        if let Some(comp) = origin.comp.as_ref().filter(|comp| comp.enabled) {
            validate_comp_marketplace(comp, origin.olp.as_ref())
                .with_context(|| format!("origin `{host}` comp"))?;
        }
    }

    // Config-authority participation. Validated here rather than at first
    // fetch so `sbproxy validate` catches an unusable authority URL, an
    // inline credential, or a `replace` subscriber that has told itself it
    // may boot without a bundle.
    if let Some(authority) = config_file.proxy.config_authority.as_ref() {
        authority
            .validate()
            .context("config compile: proxy.config_authority")?;
        if let Some(publish) = authority.publish.as_ref() {
            validate_publishing_node_admin_credentials(config_file.proxy.admin.as_ref())?;
            validate_publish_signing_key(publish)?;
        }
    }

    // Payment settlement. Every rule here is structural or cross-field,
    // so it holds on a machine that has none of the credentials: no
    // secret is resolved, no SQLite file is opened, no provider object
    // is created, and no worker starts. A configured rail whose Cargo
    // feature is missing is caught later, at runtime assembly, where
    // the compiled feature set is actually known.
    if let Some(payments) = config_file.proxy.payments.as_ref() {
        payments
            .validate()
            .context("config compile: proxy.payments")?;
    }

    if let Some(cluster) = crate::cluster::resolve_effective_cluster(&config_file.proxy)
        .context("config compile: proxy cluster")?
    {
        for diagnostic in cluster.diagnostics {
            tracing::warn!(
                code = diagnostic.code,
                message = %diagnostic.message,
                "cluster configuration migration"
            );
        }
    }

    // Lower `proxy.credentials` + `tenant.credentials` + per-origin
    // `credentials:` of type `ai_provider` into the existing
    // `action.virtual_keys` array on each origin's AI handler config
    // so the runtime AI dispatch keeps working unchanged. Resolution
    // order at this stage matches request-time: origin scope first,
    // then tenant scope (when the origin's tenant_id matches), then
    // proxy scope. Duplicate-name credentials at a more specific
    // scope shadow the less specific one.
    lower_credentials_into_origin_virtual_keys(&mut config_file)?;

    let mut origins = Vec::with_capacity(config_file.origins.len());
    let mut host_map = std::collections::HashMap::new();

    // Collected before the loop below consumes `config_file.origins`.
    // Keyed by the origin's config key, which is what the resolver
    // expects and what a non-wildcard request's hostname carries.
    let origin_decision_audit: std::collections::BTreeMap<
        String,
        crate::types::DecisionAuditConfig,
    > = config_file
        .origins
        .iter()
        .filter_map(|(host, origin)| {
            origin
                .observability
                .as_ref()
                .and_then(|obs| obs.log.decision_audit.clone())
                .map(|cfg| (host.clone(), cfg))
        })
        .collect();

    // Sorted by config key before anything is assigned a position.
    //
    // `RawConfigFile::origins` is a `HashMap`, so iterating it directly
    // hands out `idx` values in whatever order that map's per-process
    // seed produced. Those indices are not private bookkeeping: they
    // are what `host_map` stores, they set the order of the `origins`
    // vector every later stage indexes into, and they reach the hashed
    // view behind `config_revision`. WOR-2602: three boots of one
    // unchanged two-origin file reported two different revisions,
    // alternating, because of exactly this. Sorting here makes every
    // index a function of the config's content rather than of the
    // process that read it.
    let mut ordered_origins: Vec<(String, RawOriginConfig)> =
        config_file.origins.into_iter().collect();
    ordered_origins.sort_by(|left, right| left.0.cmp(&right.0));

    for (hostname, raw_config) in ordered_origins {
        // Wildcard keys (`*.example.com`) are validated here and stored
        // under their literal spelling; `CompiledConfig::resolve_origin`
        // and the core `HostRouter` give them suffix-match semantics.
        validate_origin_host_key(&hostname)?;
        let origin = compile_origin(&hostname, raw_config)?;
        let idx = origins.len();
        host_map.insert(CompactString::new(&hostname), idx);
        origins.push(origin);
    }

    // WOR-1053: validate that every `origin.tenant_id` references a
    // declared `proxy.tenants[].id`. `__default__` is the synthetic
    // tenant for single-tenant configs and is never declared by the
    // operator; it falls through the validation. An operator that
    // explicitly declares a `__default__` tenant gets a compile
    // error so the reserved name stays unambiguous.
    {
        let declared: std::collections::HashSet<&str> = config_file
            .proxy
            .tenants
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        if declared.contains("__default__") {
            anyhow::bail!(
                "proxy.tenants[].id `__default__` is reserved for the synthetic single-tenant fallback; pick a different id"
            );
        }
        for tenant in &config_file.proxy.tenants {
            if tenant.id.is_empty() {
                anyhow::bail!("proxy.tenants[].id must not be empty");
            }
            if tenant.id.len() > 256 {
                anyhow::bail!(
                    "proxy.tenants[].id `{}` exceeds 256 character cap",
                    &tenant.id[..tenant.id.len().min(64)]
                );
            }
        }
        for origin in &origins {
            let tid = origin.tenant_id.as_str();
            if tid == "__default__" {
                continue;
            }
            if !declared.contains(tid) {
                anyhow::bail!(
                    "origin `{}` references tenant_id `{}` which is not declared under proxy.tenants",
                    origin.hostname,
                    tid,
                );
            }
        }
    }

    // Instantiate the L2 cache backend (Redis) if configured. DSN semantics,
    // TLS field combinations, and local PEM material are validated here at
    // startup. Only the network connection is lazy; reachability, TLS handshake,
    // authentication, and database-selection failures surface on first use.
    let l2_store = match &config_file.proxy.l2_cache {
        Some(cfg) => Some(build_l2_store(cfg)?),
        None => None,
    };

    // WOR-2166: refuse the shared message bus. The block used to compile a
    // memory, Redis, SQS, or GCP Pub/Sub messenger and hang it off the
    // compiled snapshot, and nothing in the request path, the reload path,
    // or the admin path ever subscribed to a topic or published on one. An
    // operator who configured a cluster bus got a valid snapshot and not a
    // single cross-replica event, for the life of the process. A knob that
    // parses, validates, and does not govern is a defect, so the config is
    // rejected instead of accepted into a snapshot where it does nothing.
    // WOR-2310 deleted the four bus backends from `sbproxy-platform`, so this
    // gate is permanent rather than a placeholder waiting on a first consumer.
    // WOR-2192: those backends acknowledged before yield (a crash lost the
    // message), treated any error as a clean end-of-stream, and could not
    // stop when the owner dropped. A future consumer has to ship an async
    // Stream with an explicit cancellation contract before any of them
    // return. The block still parses so the failure below is an explanatory
    // diagnostic instead of an unknown-key error.
    if let Some(settings) = &config_file.proxy.messenger_settings {
        anyhow::bail!(
            "config compile: proxy.messenger_settings is set (driver '{}'), but this build has \
             no runtime consumer for the message bus. Nothing subscribes to a topic and nothing \
             publishes on one, so the block would validate at boot and then move no events \
             between replicas for the life of the process. The GCP and SQS adapters were also \
             deleted because they acknowledged before yield, treated errors as end-of-stream, \
             and could not stop on drop (WOR-2192); do not restore them without an async Stream \
             and an explicit cancellation contract. Remove the block. Both uses this block was \
             documented for have a working surface today: config distribution across replicas \
             is `proxy.config_authority`, where one node publishes a signed bundle and the \
             others pull and verify it, and cache invalidation is `POST /admin/cache/purge` on \
             the admin API, which reaches every replica when `proxy.l2_cache` puts the response \
             cache on a shared Redis tier. See `docs/configuration.md`.",
            settings.driver,
        );
    }

    // WOR-2310: refuse the device-parser catalog override. The device
    // parser in this build matches on compiled-in rules and has no code
    // path that opens a catalog file, so this named a path the proxy never
    // read: a missing file, an unreadable file, and a carefully maintained
    // one all behaved identically. That is worse than an unsupported key,
    // because an operator maintaining the catalog had every reason to
    // believe the rules in it were live. The field still parses so the
    // failure below explains itself instead of reading as an unknown key.
    if let Some(path) = &config_file.proxy.device_parser_file {
        anyhow::bail!(
            "config compile: proxy.device_parser_file is set ('{path}'), but this build's device \
             parser matches on compiled-in rules and never opens a catalog file. The path was \
             not read at startup or on reload, so whatever it points at has no effect on how a \
             user agent is classified. Remove it. The neighboring \
             `proxy.ai_providers_file` is the override that does work, and it applies to the AI \
             provider catalog rather than to device detection."
        );
    }

    // WOR-2311: prefix purge is a silent no-op on stores whose keys are
    // hashed. The `file` backend names entries by the SHA-256 of the cache
    // key and memcached offers no key scan, so `delete_prefix` returns 0
    // without scanning anything. `invalidate_on_mutation` (on by default)
    // is the feature that issues those prefix purges: on these backends a
    // POST/PUT/PATCH/DELETE evicts nothing and cached GET variants only
    // fall out by TTL. Warn rather than reject, matching the
    // body-reading-policy-on-`static` precedent (WOR-2136): the cache
    // still serves reads correctly, and the combination has always
    // compiled.
    if let Some(store) = &config_file.proxy.response_cache_store {
        let hashed_backend = match &store.backend {
            crate::types::ResponseCacheBackendConfig::File { .. } => Some("file"),
            crate::types::ResponseCacheBackendConfig::Memcached { .. } => Some("memcached"),
            crate::types::ResponseCacheBackendConfig::Memory
            | crate::types::ResponseCacheBackendConfig::Redis => None,
        };
        if let Some(backend) = hashed_backend {
            for origin in &origins {
                if origin
                    .response_cache
                    .as_ref()
                    .is_some_and(|cache| cache.enabled && cache.invalidate_on_mutation)
                {
                    tracing::warn!(
                        hostname = %origin.hostname,
                        backend,
                        "response_cache.invalidate_on_mutation cannot purge by prefix on \
                         this response_cache_store backend: its cache keys are hashed, so \
                         mutation requests evict nothing and entries fall out by TTL only. \
                         Use the `memory` or `redis` backend for mutation-driven \
                         invalidation, or set `invalidate_on_mutation: false` to accept \
                         TTL-based expiry"
                    );
                }
            }
        }
    }

    // WOR-805: validate the Web Bot Auth signing identity up front so a
    // malformed seed fails config load rather than silently disabling
    // the hosted directory at runtime. The seed must be 64 hex chars
    // (32 bytes); the actual key derivation happens in the data plane.
    if let Some(wba) = &config_file.proxy.web_bot_auth {
        if wba.key_id.trim().is_empty() {
            anyhow::bail!("proxy.web_bot_auth.key_id must be non-empty");
        }
        let seed = &wba.ed25519_seed_hex;
        if seed.len() != 64 || !seed.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!(
                "proxy.web_bot_auth.ed25519_seed_hex must be 64 hex characters (a 32-byte Ed25519 seed)"
            );
        }
    }

    // WOR-2318: the audit trail's durable form. Validated immediately
    // after the identity it borrows, and here rather than at boot for the
    // same reason attestation is: `sbproxy validate` has to reject a chain
    // that could never be signed without creating a file to discover it.
    if let Some(audit) = &config_file.audit {
        validate_audit(audit, config_file.proxy.web_bot_auth.as_ref())?;
    }

    // WOR-2318: the `events:` egress. Same reasoning as `audit:`: an
    // `sbproxy validate` run has to reject a sink that could never
    // deliver without opening a file or a socket to find out.
    if let Some(events) = &config_file.events {
        validate_events(events)?;
    }

    // WOR-2127: consumption attestation. Validated here rather than in
    // the pipeline because `sbproxy validate` has to reject a broken
    // block without touching the filesystem, and because a proxy that
    // announces a metering role it cannot honour should not start.
    if let Some(attestation) = &config_file.proxy.attestation {
        validate_attestation(attestation, config_file.proxy.web_bot_auth.as_ref())?;
        for origin in &origins {
            if let Some(origin_attestation) = &origin.attestation {
                validate_origin_attestation(&origin.hostname, attestation, origin_attestation)?;
            }
        }
    } else {
        for origin in &origins {
            if origin.attestation.is_some() {
                anyhow::bail!(
                    "origin `{}` declares an `attestation:` block but `proxy.attestation` is \
                     absent. A per-origin role has no queue, no ledger, and no billing table \
                     behind it, so it could never produce a record.",
                    origin.hostname,
                );
            }
        }
    }

    // A clustered node whose keystore is node-local mints keys its peers may
    // not resolve. How bad that is depends on whether a shared cache tier
    // propagates records, so classify rather than blanket-reject.
    if let Some(cluster) = &config_file.proxy.cluster {
        let km = config_file.proxy.key_management.as_ref();
        match crate::cluster::classify_clustered_keystore(
            &cluster.seeds,
            km.map(|k| k.enabled).unwrap_or(false),
            km.map(|k| k.store.backend).unwrap_or_default(),
            km.map(|k| k.cache.tier).unwrap_or_default(),
        ) {
            crate::cluster::ClusteredKeystoreVerdict::Fine => {}
            crate::cluster::ClusteredKeystoreVerdict::NotDurable(message) => {
                tracing::warn!("{message}");
            }
            crate::cluster::ClusteredKeystoreVerdict::Broken(message) => {
                anyhow::bail!("config compile: {message}");
            }
        }
    }

    // WOR-2064: the mesh keystore stores its records on the cluster's
    // replicated state substrate, so it needs a cluster and that
    // cluster's replication block. Checked here so `sbproxy validate`
    // rejects the combination without booting anything.
    if let Some(km) = config_file.proxy.key_management.as_ref() {
        if km.enabled && km.store.backend == crate::types::KeyStoreBackend::Mesh {
            match &config_file.proxy.cluster {
                None => anyhow::bail!(
                    "config compile: proxy.key_management.store.backend is 'mesh' but \
                     proxy.cluster is not configured. A mesh keystore on a node with no mesh is \
                     an embedded keystore with extra steps. Configure proxy.cluster with a \
                     replication block, or use the embedded backend."
                ),
                Some(cluster) if cluster.replication.is_none() => anyhow::bail!(
                    "config compile: proxy.key_management.store.backend is 'mesh' but \
                     proxy.cluster has no replication block. The mesh keystore stores its \
                     records on the cluster's replicated state substrate and takes its \
                     replication factor from proxy.cluster.replication; add that block (an \
                     empty 'replication:' mapping uses the defaults)."
                ),
                Some(_) => {}
            }
        }
    }

    // WOR-2673: the AWS-SDK cache-reserve backend was retired in favor
    // of the object-storage one, which reaches the same buckets plus
    // GCS, Azure, a local directory, and every S3-compatible store.
    // A refusal rather than a silent migration: `type: s3` carried
    // `kms_key_id`, and an alias would have moved an operator from
    // KMS-wrapped per-object data keys to local sealing without saying
    // so. `CacheReserveBackendConfig` also carries `#[serde(other)]`,
    // so with no refusal here the old block parses as an out-of-tree
    // backend and the reserve silently disappears.
    if let Some(reserve) = config_file.proxy.cache_reserve.as_ref() {
        if let Some(crate::types::CacheReserveBackendConfig::S3 {
            bucket,
            region,
            kms_key_id,
            prefix,
            ..
        }) = reserve.backend.as_ref()
        {
            let bucket = bucket
                .as_deref()
                .map(str::trim)
                .filter(|bucket| !bucket.is_empty())
                .unwrap_or("your-bucket");
            let region_line = region
                .as_deref()
                .map(|region| format!("\n        region: {region}"))
                .unwrap_or_default();
            let prefix_line = prefix
                .as_deref()
                .map(|prefix| format!("\n        prefix: {prefix}"))
                .unwrap_or_default();
            let kms_note = if kms_key_id.is_some() {
                "Your kms_key_id has no equivalent: the replacement seals entries \
                 locally with AES-256-GCM under cache_reserve.backend.encryption, or \
                 leaves encryption to the bucket's own SSE-KMS setting, which is \
                 configured on the bucket and composes with either choice."
            } else {
                "kms_key_id has no equivalent: the replacement seals entries locally \
                 with AES-256-GCM under cache_reserve.backend.encryption, or leaves \
                 encryption to the bucket's own SSE-KMS setting."
            };
            anyhow::bail!(
                "config compile: proxy.cache_reserve.backend type: s3 was retired. \
                 Write this instead:\n      backend:\n        type: object_store\n        \
                 backend: s3\n        bucket: {bucket}{region_line}{prefix_line}\n\
                 {kms_note} See docs/cache-reserve.md for the full migration."
            );
        }
    }

    // WOR-2199: a bind address the operator cannot express is a bind
    // address they cannot restrict, and one they misspell must not fall
    // back to every interface.
    if let Some(federation) = config_file
        .proxy
        .federation
        .as_ref()
        .filter(|cfg| cfg.enabled)
    {
        if !federation.entity_id.starts_with("https://") {
            anyhow::bail!("config compile: proxy.federation.entity_id must use https");
        }
        if federation.signing_key.pem_file.trim().is_empty()
            || federation.signing_key.kid.trim().is_empty()
        {
            anyhow::bail!(
                "config compile: proxy.federation.signing_key pem_file and kid must not be empty"
            );
        }
        if !matches!(
            federation.signing_key.algorithm.as_str(),
            "ES256" | "ES384" | "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "EdDSA"
        ) {
            anyhow::bail!("config compile: proxy.federation.signing_key.algorithm is not allowed");
        }
        if federation
            .published_jwks
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            anyhow::bail!("config compile: proxy.federation.published_jwks.keys must not be empty");
        }
        if federation.lifetime_secs == 0
            || federation.refresh_margin_secs >= federation.lifetime_secs
        {
            anyhow::bail!(
                "config compile: proxy.federation.refresh_margin_secs must be less than lifetime_secs"
            );
        }
        for hint in &federation.authority_hints {
            if !hint.starts_with("https://") {
                anyhow::bail!(
                    "config compile: proxy.federation.authority_hints entries must use https"
                );
            }
        }
        if let Some(peer_trust) = federation.peer_trust.as_ref() {
            if peer_trust.trust_anchors.is_empty() {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.trust_anchors must not be empty; \
                     a peer chain verified against no pinned anchor verifies nothing"
                );
            }
            for anchor in &peer_trust.trust_anchors {
                if !anchor.entity_id.starts_with("https://") {
                    anyhow::bail!(
                        "config compile: proxy.federation.peer_trust.trust_anchors[].entity_id must use https"
                    );
                }
                if anchor
                    .jwks
                    .get("keys")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(Vec::is_empty)
                {
                    anyhow::bail!(
                        "config compile: proxy.federation.peer_trust.trust_anchors[].jwks.keys must not be empty"
                    );
                }
            }
            if peer_trust.header.trim().is_empty()
                || peer_trust
                    .header
                    .bytes()
                    .any(|byte| !byte.is_ascii_graphic() || byte == b':')
            {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.header must be a header name"
                );
            }
            if peer_trust.max_chain_depth == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.max_chain_depth must be greater than zero"
                );
            }
            if peer_trust.max_chain_fetches == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.max_chain_fetches must be \
                     greater than zero; a walk with no fetch budget is the unbounded walk \
                     this key exists to stop"
                );
            }
            if peer_trust.max_chain_bytes == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.max_chain_bytes must be greater than zero"
                );
            }
            if peer_trust.max_chain_duration_ms == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.max_chain_duration_ms must be greater than zero"
                );
            }
            if peer_trust.max_authority_hints == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.max_authority_hints must be greater than zero"
                );
            }
            if peer_trust.walks_per_minute == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.walks_per_minute must be \
                     greater than zero; the per-source rate limit is what stops a caller \
                     that rotates the entity id it claims from driving one chain walk per request"
                );
            }
            if peer_trust.cache_ttl_secs == 0 {
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.cache_ttl_secs must be greater than zero"
                );
            }
            if peer_trust.required && federation.authority_hints.is_empty() {
                // Not fatal to the peer check itself, but it means this
                // proxy demands a chain from every caller while
                // publishing a statement no caller can chain. Refusing
                // is cheaper than the asymmetry.
                anyhow::bail!(
                    "config compile: proxy.federation.peer_trust.required needs \
                     proxy.federation.authority_hints, or peers cannot chain this entity back"
                );
            }
        }
    }

    config_file.proxy.validate_bind_address()?;

    config_file
        .extensions
        .validate()
        .context("config compile: invalid extension bundle source")?;

    // Lift the decision-audit block onto the snapshot so a decision point
    // asks one `Option` on the compiled config instead of walking
    // `proxy.observability.log` per request. Proxy scope only, matching
    // the validation above: that is the only scope carrying the block
    // today, and when tenant and origin `decision_audit:` land this
    // becomes a compose the way `custom_fields` already is.
    //
    // Cloned rather than moved because `config_file.proxy` is handed to
    // the snapshot whole as `server` below.
    let decision_audit = crate::types::DecisionAuditScopes {
        proxy: config_file
            .proxy
            .observability
            .as_ref()
            .and_then(|obs| obs.log.as_ref())
            .and_then(|log| log.decision_audit.clone()),
        tenants: config_file
            .proxy
            .tenants
            .iter()
            .filter_map(|tenant| {
                tenant
                    .observability
                    .as_ref()
                    .and_then(|obs| obs.log.decision_audit.clone())
                    .map(|cfg| (tenant.id.clone(), cfg))
            })
            .collect(),
        origins: origin_decision_audit,
    };

    Ok(CompiledConfig {
        extension_bundles: config_file.extensions,
        origin_source_entries,
        origins,
        host_map,
        server: config_file.proxy,
        l2_store,
        // A pipeline lifecycle extension builds the mesh node when configured,
        // so compilation always yields `None` here.
        mesh: None,
        // Access-log emission settings ride through unchanged. `None`
        // (the default) keeps the logging hook a no-op.
        access_log: config_file.access_log,
        // WOR-2405: which decision events publish an audit record.
        // `None` keeps every decision point's publish check a single
        // `Option` test that fails fast.
        decision_audit,
        // G1.4 wire: hand the parsed `agent_classes:` block to the
        // binary startup code. The resolver itself is constructed in
        // `sbproxy-core` (which depends on the classifier crate); this
        // crate stays ignorant of the typed resolver.
        agent_classes: config_file.agent_classes,
        // WOR-1130: top-level workspace rate-limit budget plus the
        // compatibility-only audit selector.
        rate_limits: config_file.rate_limits,
        audit: config_file.audit,
        // WOR-1186: session-ledger emission config.
        session_ledger: config_file.session_ledger,
        // WOR-2318: request-event egress config.
        request_events: config_file.request_events,
        // WOR-2318: typed-proxy-event egress config.
        events: config_file.events,
        // WOR-1971: hand the complete top-level flag set to the binary.
        flags: config_file.flags,
        // WOR-2476/WOR-2481: compile the top-level `egress:` block into
        // one authorizer per configured purpose. Absent, this is
        // `CompiledEgressGates::default()`, which arms nothing.
        egress: compile_egress_gates(config_file.egress.as_ref())?,
    })
}

/// Async wrapper that honours a [`crate::ConfigSource`] before compiling.
///
/// `inline_text` is the YAML the operator handed the binary. The
/// function parses the file far enough to see whether a `source:`
/// discriminator is set, then resolves it via
/// [`crate::source::load_from_source`] and feeds the resolved text
/// back through [`compile_config`].
///
/// `ConfigSource::Local` (or no `source:` field at all) preserves
/// the historical behaviour: `inline_text` is the config.
///
/// # Errors
///
/// Returns an error if the top-level `source:` block cannot be parsed,
/// if resolving a non-local config source fails, or if the resolved
/// config fails to compile (see [`compile_config`]).
pub async fn compile_config_from_source(
    inline_text: &str,
    fetch_ctx: &crate::source::FetchContext,
) -> Result<CompiledConfig> {
    compile_config_from_source_blocking(inline_text, fetch_ctx)
}

/// [`compile_config_from_source`] without the async wrapper.
///
/// The boot path and the reload transaction are both synchronous and run
/// outside any tokio runtime, and the resolution itself never awaits
/// anything: it shells out to `git` with a hard timeout and reads a
/// file. So the production call sites use this and the async function
/// above stays as a convenience for callers already in an async context.
///
/// # Errors
///
/// Returns an error if the top-level `source:` block cannot be parsed,
/// if resolving a non-local config source fails, or if the resolved
/// config fails to compile (see [`compile_config`]).
pub fn compile_config_from_source_blocking(
    inline_text: &str,
    fetch_ctx: &crate::source::FetchContext,
) -> Result<CompiledConfig> {
    let resolved = crate::source::resolve_document(inline_text, fetch_ctx)
        .map_err(|e| anyhow::anyhow!("config source: {e}"))?;
    if resolved.is_remote() {
        ensure_node_local_refs_resolved(&resolved.text)?;
    }
    compile_config(&resolved.text)
}

/// Config paths whose value identifies *this* node and therefore must
/// never be left as literal `${VAR}` text.
///
/// A shared repository carries `node_id: ${SB_NODE_ID}` and each host
/// supplies its own value, which is the documented way one document
/// serves a whole fleet. The failure mode without this check is quiet
/// and bad: an unresolved reference is otherwise only a warning, so a
/// host that forgot to export the variable would take the literal string
/// `${SB_NODE_ID}` as its node id, join the cluster under it, and
/// collide with every other host that forgot.
///
/// Scoped to `proxy.cluster` because that is the block
/// `ClusterRestartFingerprint` covers: any change to it rejects a reload
/// outright, so a wrong value there is not something a later reload can
/// repair.
pub const NODE_LOCAL_PATH_PREFIXES: &[&str] = &["proxy.cluster"];

/// Refuse a resolved remote document that leaves a node-local value as
/// literal `${VAR}` text.
///
/// Apply this to a document that came from a `source:` block, never to a
/// hand-edited local file: the local file's operator is watching the log,
/// the existing warning is enough for them, and tightening it would break
/// configs that work today.
///
/// Called from both entry points that turn a resolved source into a
/// running configuration, because they are separate paths:
/// [`compile_config_from_source_blocking`] is what the CLI and the tests
/// use, and the server's boot and reload paths resolve and compile in two
/// steps so they can publish the resolved document for the
/// config-authority merge base.
///
/// # Errors
///
/// Returns an error naming every offending path.
pub fn ensure_node_local_refs_resolved(resolved_text: &str) -> Result<()> {
    let unresolved = unresolved_env_references(resolved_text);
    let offending: Vec<&String> = unresolved
        .iter()
        .filter(|entry| {
            let path = entry.split(':').next().unwrap_or_default().trim();
            NODE_LOCAL_PATH_PREFIXES
                .iter()
                .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}.")))
        })
        .collect();
    if offending.is_empty() {
        return Ok(());
    }
    let listed = offending
        .iter()
        .map(|entry| entry.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "the resolved config source leaves node-local reference(s) unresolved: {listed}. These \
         identify this node, so the literal placeholder text cannot be used as a value: export \
         the environment variable(s) on this host, or move the value into a node-local overlay"
    )
}

/// Lexically normalize an audit chain path for the pairwise-distinctness
/// comparison in [`validate_audit`] (WOR-2478 M11).
///
/// Splits on `/`, drops empty segments (so a repeated or trailing slash
/// collapses) and `.` segments, and rejoins, restoring a leading slash
/// when the input had one. `/a/b.jsonl` and `/a/./b.jsonl` normalize to
/// the same string, so a config that merely spells one chain path with a
/// redundant `.` segment cannot slip past the check that exists to catch
/// two channels sharing one file.
///
/// Deliberately does not resolve `..` (a `..` segment's target depends
/// on what its parent actually resolves to on disk, which this function
/// cannot know without touching the filesystem, and the paths being
/// compared here may not exist yet) or symlinks. An operator who wants
/// that guarantee should not need a `..` or a symlink to bypass a check
/// that is trying to protect them from themselves; this closes the
/// purely lexical gap, not every gap.
fn normalize_chain_path(path: &str) -> String {
    let leading_slash = path.starts_with('/');
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let joined = segments.join("/");
    if leading_slash {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Validate the top-level `audit:` block (WOR-2318, WOR-2478).
///
/// Each rule exists because the alternative is a deployment that
/// believes it has an audit trail.
///
/// `sink: tracing` is refused. Emission to the `security_audit`,
/// `config_audit`, and `key_audit` targets is unconditional and always
/// was, so the value never selected anything: it was the documented key
/// that did nothing which this whole change is about. Refusing rather
/// than quietly aliasing it to `memory` follows the same call
/// `load_balancer`'s `sticky:` and the AI router's
/// `routing.strategy: token_rate` both took.
///
/// `path` and `sign_with` are required by `chain` and refused without it.
/// A chain with no file has nothing to append to; a `path` under
/// `sink: memory` describes a file nothing will ever write, which is the
/// more dangerous of the two because it looks configured.
///
/// `sign_with` must name an identity this build can resolve, and that
/// block must exist. An unsigned chain is tamper-evident to somebody
/// holding an earlier copy of the file and to nobody else: whoever can
/// rewrite the file can re-link it. The one accepted value is
/// [`ATTESTATION_SIGN_WITH_WEB_BOT_AUTH`], which is the same identity
/// `proxy.attestation.sign_with` names, deliberately, so a deployment
/// that already publishes a key does not acquire a second key
/// distribution problem by turning this on.
///
/// `config_path` follows `path`: it is refused without `sink: chain`,
/// but `sink: chain` does not require it in return, because chaining
/// `config_audit` is opt-in (WOR-2478). It must also differ from
/// `path`, because the config channel and the security chain verify
/// two different payload types independently; letting one file answer
/// for both would make a verification failure on one look like a
/// failure of the other.
///
/// `key_path` and `admin_path` follow the identical pattern (WOR-2478):
/// each is opt-in, each requires `sink: chain`, and each must differ from
/// every other chain path this config names. Four channels means six
/// pairwise checks rather than one; each is written out rather than
/// looped, matching `config_path`'s check above, so the refusal message
/// always names the two keys actually in conflict. Every comparison runs
/// against [`normalize_chain_path`]'s output rather than the raw string
/// (WOR-2478 M11), so `/a/b.jsonl` and `/a/./b.jsonl` are caught as the
/// same file even though they differ byte for byte.
fn validate_audit(audit: &AuditConfig, web_bot_auth: Option<&WebBotAuthConfig>) -> Result<()> {
    if audit.sink == AuditSinkKind::Tracing {
        anyhow::bail!(
            "audit.sink `tracing` was removed: it never selected anything. Every audit channel \
             has always emitted to its tracing target unconditionally, so `tracing` and `memory` \
             described the same proxy. Use `memory` for that behavior under an honest name, or \
             `chain` with a `path` and a `sign_with` for a trail that survives a restart and \
             cannot be edited without the edit showing."
        );
    }

    if audit.sink != AuditSinkKind::Chain {
        if audit.path.is_some() {
            anyhow::bail!(
                "audit.path is set but audit.sink is not `chain`, so nothing would ever be \
                 written to it. Set `sink: chain` or remove the path."
            );
        }
        if audit.sign_with.is_some() {
            anyhow::bail!(
                "audit.sign_with is set but audit.sink is not `chain`, so nothing would ever be \
                 signed. Set `sink: chain` or remove the identity."
            );
        }
        if audit.config_path.is_some() {
            anyhow::bail!(
                "audit.config_path is set but audit.sink is not `chain`, so nothing would ever \
                 be written to it. audit.config_path requires `audit.sink: chain`. Set `sink: \
                 chain` or remove the path."
            );
        }
        if audit.key_path.is_some() {
            anyhow::bail!(
                "audit.key_path is set but audit.sink is not `chain`, so nothing would ever be \
                 written to it. audit.key_path requires `audit.sink: chain`. Set `sink: chain` \
                 or remove the path."
            );
        }
        if audit.admin_path.is_some() {
            anyhow::bail!(
                "audit.admin_path is set but audit.sink is not `chain`, so nothing would ever \
                 be written to it. audit.admin_path requires `audit.sink: chain`. Set `sink: \
                 chain` or remove the path."
            );
        }
        return Ok(());
    }

    match audit.path.as_deref().map(str::trim) {
        None | Some("") => anyhow::bail!(
            "audit.sink is `chain` but audit.path is missing, so there is no file to chain \
             into. Point it at a path on durable storage, for example \
             `/var/lib/sbproxy/security-audit.jsonl`."
        ),
        Some(_) => {}
    }

    if let Some(config_path) = audit.config_path.as_deref().map(str::trim) {
        if Some(normalize_chain_path(config_path))
            == audit
                .path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the config channel cannot share the security chain file; the two payload \
                 types verify separately"
            );
        }
    }

    if let Some(key_path) = audit.key_path.as_deref().map(str::trim) {
        if Some(normalize_chain_path(key_path))
            == audit
                .path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the key channel cannot share the security chain file; the two payload types \
                 verify separately"
            );
        }
        if Some(normalize_chain_path(key_path))
            == audit
                .config_path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the key channel cannot share the config chain file; the two payload types \
                 verify separately"
            );
        }
    }

    if let Some(admin_path) = audit.admin_path.as_deref().map(str::trim) {
        if Some(normalize_chain_path(admin_path))
            == audit
                .path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the admin channel cannot share the security chain file; the two payload types \
                 verify separately"
            );
        }
        if Some(normalize_chain_path(admin_path))
            == audit
                .config_path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the admin channel cannot share the config chain file; the two payload types \
                 verify separately"
            );
        }
        if Some(normalize_chain_path(admin_path))
            == audit
                .key_path
                .as_deref()
                .map(|p| normalize_chain_path(p.trim()))
        {
            anyhow::bail!(
                "the admin channel cannot share the key chain file; the two payload types \
                 verify separately"
            );
        }
    }

    match audit.sign_with.as_deref().map(str::trim) {
        None => anyhow::bail!(
            "audit.sink is `chain` but audit.sign_with is missing, so every entry would be \
             unsigned. An unsigned chain only detects an edit for somebody who already holds an \
             earlier copy of the file; whoever can rewrite it can re-link it. Set it to \
             `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`."
        ),
        Some(identity) if identity == ATTESTATION_SIGN_WITH_WEB_BOT_AUTH => {
            if web_bot_auth.is_none() {
                anyhow::bail!(
                    "audit.sign_with names `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`, but that \
                     block is not configured, so there is no key to sign the audit chain with."
                );
            }
        }
        Some(other) => anyhow::bail!(
            "audit.sign_with `{other}` is not a signing identity this build can resolve; the \
             only accepted value is `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`"
        ),
    }

    Ok(())
}

/// Compile the top-level `egress:` section into one
/// [`sbproxy_security::egress::EgressAuthorizer`] per configured purpose
/// (WOR-2476, WOR-2481). `cfg` absent yields a default
/// [`CompiledEgressGates`] (every field `None`), which arms nothing.
///
/// `Err` when any sub-block's `ports:` is present but empty, or names
/// port `0`; see [`compile_egress_purpose`].
fn compile_egress_gates(cfg: Option<&EgressTopLevelConfig>) -> Result<CompiledEgressGates> {
    let Some(cfg) = cfg else {
        return Ok(CompiledEgressGates::default());
    };
    Ok(CompiledEgressGates {
        ai_providers: compile_egress_purpose(
            &[EgressPurpose::AiProvider],
            cfg.ai_providers.as_ref(),
            "ai_providers",
        )?,
        agent_orchestration: compile_egress_purpose(
            &[EgressPurpose::AgentOrchestration],
            cfg.agent_orchestration.as_ref(),
            "agent_orchestration",
        )?,
        classifier_hooks: compile_egress_purpose(
            &[EgressPurpose::ClassifierHook],
            cfg.classifier_hooks.as_ref(),
            "classifier_hooks",
        )?,
        // WOR-2476 fix: `usage_sinks:` has to arm the Webhook sink too,
        // not just the three sinks that already share
        // `EgressPurpose::UsageSink` internally (Langfuse, Datadog,
        // ObjectStore).
        // `WebhookSink::record` authorizes under its own, separate,
        // pre-existing `EgressPurpose::Webhook` (see
        // `crates/sbproxy-ai/src/usage_sink.rs`); an authorizer whose
        // internal purpose map only has a `UsageSink` entry denies every
        // Webhook dispatch with `UnlistedPurpose` regardless of `hosts`,
        // because `EgressAuthorizer::authorize` looks the purpose up by
        // exact key. Compiling one authorizer keyed under both purposes,
        // sharing the same allowlist, is what actually arms every
        // consumer `UsageSinkConfig::build` attaches this to.
        usage_sinks: compile_egress_purpose(
            &[EgressPurpose::UsageSink, EgressPurpose::Webhook],
            cfg.usage_sinks.as_ref(),
            "usage_sinks",
        )?,
        model_artifacts: compile_egress_purpose(
            &[EgressPurpose::ModelArtifact],
            cfg.model_artifacts.as_ref(),
            "model_artifacts",
        )?,
        token_exchange: compile_egress_purpose(
            &[EgressPurpose::TokenExchange],
            cfg.token_exchange.as_ref(),
            "token_exchange",
        )?,
        federation: compile_egress_purpose(
            &[EgressPurpose::Federation],
            cfg.federation.as_ref(),
            "federation",
        )?,
        telemetry: compile_egress_purpose(
            &[EgressPurpose::Telemetry],
            cfg.telemetry.as_ref(),
            "telemetry",
        )?,
    })
}

/// Validate the security properties the config compiler owns without
/// resolving a secret or constructing the runtime candidate.
fn validate_ai_toolkit_config(config_file: &ConfigFile) -> Result<()> {
    const DEFAULT_MAX_SECRET_BYTES: usize = 256;

    let Some(cfg) = config_file.proxy.ai_toolkit.as_ref() else {
        return Ok(());
    };
    let max_secret_bytes = cfg
        .limits
        .max_secret_bytes
        .unwrap_or(DEFAULT_MAX_SECRET_BYTES);
    for (index, agent) in cfg.agents.iter().enumerate() {
        let endpoint = agent.endpoint.trim().parse::<http::Uri>().map_err(|_| {
            anyhow::anyhow!(
                "config compile: proxy.ai_toolkit.agents[{index}].endpoint must be an absolute \
                 http:// or https:// URI"
            )
        })?;
        let scheme = endpoint.scheme_str().ok_or_else(|| {
            anyhow::anyhow!(
                "config compile: proxy.ai_toolkit.agents[{index}].endpoint must include an \
                 http:// or https:// scheme"
            )
        })?;
        if !matches!(scheme, "http" | "https") {
            anyhow::bail!(
                "config compile: proxy.ai_toolkit.agents[{index}].endpoint must use http:// or \
                 https://"
            );
        }
        let host = endpoint.host().ok_or_else(|| {
            anyhow::anyhow!(
                "config compile: proxy.ai_toolkit.agents[{index}].endpoint must include a host"
            )
        })?;
        if scheme == "http" && !crate::types::endpoint_host_is_local(host) {
            anyhow::bail!(
                "config compile: proxy.ai_toolkit.agents[{index}].endpoint must use https:// for \
                 nonlocal destinations"
            );
        }
        if agent.auth.shared_secret.len() > max_secret_bytes {
            anyhow::bail!(
                "config compile: proxy.ai_toolkit.agents[{index}].auth.shared_secret exceeds the \
                 configured {max_secret_bytes}-byte reference limit"
            );
        }
        if !crate::types::is_secret_reference(&agent.auth.shared_secret) {
            anyhow::bail!(
                "config compile: proxy.ai_toolkit.agents[{index}].auth.shared_secret must be a \
                 secret reference (`env:NAME`, `${{NAME}}`, `file:/path`, or \
                 `secret://backend/name`), not inline material"
            );
        }
    }
    if !cfg.agents.is_empty()
        && !config_file
            .egress
            .as_ref()
            .and_then(|egress| egress.agent_orchestration.as_ref())
            .is_some_and(|purpose| purpose.mode.is_enforce())
    {
        anyhow::bail!(
            "config compile: proxy.ai_toolkit.agents requires \
             egress.agent_orchestration.mode: deny_by_default so every agent invocation is \
             governed by an explicit destination allowlist"
        );
    }
    let validate_origin = |resource: &str, index: usize, origin: &str| -> Result<()> {
        if !config_file.origins.contains_key(origin) {
            let bounded: String = origin.chars().take(128).collect();
            anyhow::bail!(
                "config compile: proxy.ai_toolkit.{resource}[{index}].origin references unknown \
                 configured origin {bounded:?}"
            );
        }
        Ok(())
    };
    for (index, agent) in cfg.agents.iter().enumerate() {
        validate_origin("agents", index, &agent.origin)?;
    }
    for (index, workflow) in cfg.workflows.iter().enumerate() {
        validate_origin("workflows", index, &workflow.origin)?;
    }
    for (index, dataset) in cfg.datasets.iter().enumerate() {
        validate_origin("datasets", index, &dataset.origin)?;
    }
    for (index, rollout) in cfg.prompt_rollouts.iter().enumerate() {
        validate_origin("prompt_rollouts", index, &rollout.origin)?;
    }
    Ok(())
}

/// Compile one sub-block into a real authorizer keyed under every purpose
/// in `purposes`, all sharing the same allowlist. `section_key` names the
/// sub-block for the two refusal messages (e.g. `"telemetry"`).
///
/// `Ok(None)` when the sub-block is omitted, or when its `mode` is the
/// inert `allow_by_default` default: either way every named purpose
/// stays legacy ungated, exactly the contract every consumer already
/// honors for an absent authorizer. `deny_by_default` builds a real
/// allowlist scoped to `hosts` (exact match, case-insensitive) and
/// `ports` (default `[80, 443]`; see `EgressPurposeConfig`'s own field
/// doc for why a purpose that dials a non-standard port, like
/// `telemetry`'s OTLP endpoint, must override it).
///
/// `Err` when `ports` is present but empty, or names port `0`. Checked
/// unconditionally, even under `allow_by_default`, because an operator
/// who wrote either explicitly almost certainly meant something else,
/// and `allow_by_default` being inert today does not mean a later `mode`
/// flip should be the first thing to notice.
///
/// Most sub-blocks arm exactly one [`EgressPurpose`]; `usage_sinks` arms
/// two (`UsageSink` and `Webhook`, see the call site's comment) because
/// the sink implementations underneath it authorize under two different,
/// pre-existing purposes. `purposes` must be non-empty; every call site
/// in this file passes a literal slice.
fn compile_egress_purpose(
    purposes: &[EgressPurpose],
    cfg: Option<&EgressPurposeConfig>,
    section_key: &str,
) -> Result<Option<EgressAuthorizer>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    if cfg.ports.is_empty() {
        anyhow::bail!(
            "egress.{section_key}.ports is empty, which would refuse every destination this \
             purpose reaches with no host list fix able to recover it. Omit `ports:` to use \
             the default [80, 443], or name at least one port."
        );
    }
    if cfg.ports.contains(&0) {
        anyhow::bail!(
            "egress.{section_key}.ports names port 0, which is never a valid destination \
             port. Remove it."
        );
    }
    if !cfg.mode.is_enforce() {
        return Ok(None);
    }
    let mut allow = PurposeAllowlist {
        hosts: cfg
            .hosts
            .iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .collect(),
        allow_private: cfg.allow_private,
        ..Default::default()
    };
    allow.schemes.insert("https".to_string());
    allow.schemes.insert("http".to_string());
    for port in &cfg.ports {
        allow.ports.insert(*port);
    }
    let mut purposes_map = std::collections::HashMap::new();
    for purpose in purposes {
        purposes_map.insert(*purpose, allow.clone());
    }
    Ok(Some(EgressAuthorizer::new(EgressConfig {
        purposes: purposes_map,
    })))
}

/// Validate the top-level `events:` block (WOR-2318).
///
/// Every rule here refuses a config that would compile, boot, serve
/// traffic, and deliver nothing, which is the failure an event sink is
/// uniquely bad at surfacing: the operator's evidence that it works is
/// events arriving, and the evidence that it is misconfigured is
/// identical to the evidence that nothing happened.
///
/// Options that belong to a sink other than the selected one are refused
/// rather than ignored, following `audit.path` under `sink: memory`. An
/// ignored `url:` under `sink: file` is the more dangerous half of that
/// pair, because it reads as configured.
///
/// `types:` is checked against the closed enum rather than passed
/// through. A misspelled `policy_denial` would otherwise select no
/// events and present as a healthy sink on a quiet proxy.
///
/// Kafka, NATS, and EventBridge never reach this function: they are not
/// [`EventSinkKind`] variants, so serde refuses the name and names the
/// three that are accepted. That is deliberate rather than an oversight
/// to be papered over with a friendlier message here, because a variant
/// that exists only to be rejected is a config surface that lies about
/// what the build can do.
fn validate_events(events: &EventsConfig) -> Result<()> {
    let sink = events.sink;

    if sink != EventSinkKind::File && events.path.is_some() {
        anyhow::bail!(
            "events.path is set but events.sink is not `file`, so nothing would ever be written \
             to it. Set `sink: file` or remove the path."
        );
    }
    if sink != EventSinkKind::Webhook {
        if events.url.is_some() {
            anyhow::bail!(
                "events.url is set but events.sink is not `webhook`, so nothing would ever be \
                 posted to it. Set `sink: webhook` or remove the url."
            );
        }
        if events.signing_secret.is_some() {
            anyhow::bail!(
                "events.signing_secret is set but events.sink is not `webhook`, so nothing would \
                 ever be signed with it. Set `sink: webhook` or remove the secret."
            );
        }
    }

    if sink == EventSinkKind::None {
        if !events.types.is_empty() {
            anyhow::bail!(
                "events.types selects event types but events.sink is `none`, so none of them \
                 would be delivered. Choose `file` or `webhook`, or remove the block."
            );
        }
        if events.queue_capacity.is_some() {
            anyhow::bail!(
                "events.queue_capacity is set but events.sink is `none`, so there is no queue. \
                 Choose `file` or `webhook`, or remove the capacity."
            );
        }
        return Ok(());
    }

    match sink {
        EventSinkKind::File => match events.path.as_deref().map(str::trim) {
            None | Some("") => anyhow::bail!(
                "events.sink is `file` but events.path is missing, so there is no file to append \
                 to. Point it at a path on writable storage, for example \
                 `/var/log/sbproxy/events.ndjson`."
            ),
            Some(_) => {}
        },
        EventSinkKind::Webhook => match events.url.as_deref().map(str::trim) {
            None | Some("") => anyhow::bail!(
                "events.sink is `webhook` but events.url is missing, so there is nowhere to post. \
                 Point it at your collector, for example `https://siem.example.com/sbproxy`."
            ),
            Some(url) if !(url.starts_with("http://") || url.starts_with("https://")) => {
                anyhow::bail!(
                    "events.url `{url}` is not an http(s) URL. The webhook sink posts over HTTP \
                     and the SSRF guard refuses every other scheme."
                )
            }
            Some(_) => {}
        },
        EventSinkKind::None => {}
    }

    if events.queue_capacity == Some(0) {
        anyhow::bail!(
            "events.queue_capacity is 0, so every event would be dropped the moment it was \
             published while the sink looked configured. Leave it unset for the default of \
             {default}, or give it a real depth.",
            default = sbproxy_observe::event_sink::DEFAULT_QUEUE_CAPACITY,
        );
    }

    for name in &events.types {
        if sbproxy_observe::EventType::from_name(name).is_none() {
            let accepted = sbproxy_observe::ALL_EVENT_TYPES
                .iter()
                .map(|event_type| event_type.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "events.types names `{name}`, which is not an event this proxy emits. A name \
                 that matches nothing selects nothing, and a sink that delivers nothing looks \
                 exactly like a quiet proxy. Accepted values: {accepted}."
            );
        }
    }

    // WOR-2384: `fail_closed` draws from the exact same closed set as
    // `types`, checked the same way and refused with the same accepted
    // list, so a typo here fails the same way a typo in `types` does
    // rather than silently naming a type that can never be fail-closed.
    for name in &events.fail_closed {
        if sbproxy_observe::EventType::from_name(name).is_none() {
            let accepted = sbproxy_observe::ALL_EVENT_TYPES
                .iter()
                .map(|event_type| event_type.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "events.fail_closed names `{name}`, which is not an event this proxy emits. \
                 Accepted values: {accepted}."
            );
        }
    }

    Ok(())
}

/// The YAML spelling of an attestation role.
///
/// A refusal has to name the value the operator wrote rather than the
/// Rust variant, and an exhaustive match with no wildcard arm means
/// adding a fifth role stops the build here, where the refusals that
/// have to decide about it live.
fn attestation_role_label(role: AttestationRole) -> &'static str {
    match role {
        AttestationRole::Off => "off",
        AttestationRole::Claim => "claim",
        AttestationRole::Receipt => "receipt",
        AttestationRole::Both => "both",
    }
}

/// Refuse a role that promises the claim half of attestation.
///
/// WOR-2623: `claim` and `both` parse, validate, and produce nothing.
/// Nothing in the request path writes a claim before a call is served,
/// nothing ever reads `proxy.attestation.queue`, and no ceiling is
/// computed for `proxy.attestation.enforcement_mode` to act on, so a
/// config declaring either role compiled clean and served traffic
/// producing neither a claim nor a receipt. That is worse than not
/// offering the role at all: the operator believes their spend is
/// bounded. Both roles stay in the vocabulary so the refusal can say
/// what is missing instead of reporting an unknown value, and the
/// message names the half that is complete.
///
/// Written once and called from both the proxy-wide check and the
/// per-origin one, because an origin that widens `receipt` to `both`
/// reaches exactly the same nothing. `subject` is the clause the
/// spelling attaches to, so each caller can name the key the operator
/// actually edited.
fn refuse_claim_role(subject: &str, role: AttestationRole) -> anyhow::Error {
    anyhow::anyhow!(
        "{subject} `{}`, which promises the claim half of attestation, and this build does \
         not implement it: no claim is written before a call is served, nothing ever reads \
         proxy.attestation.queue, and proxy.attestation.enforcement_mode acts on a verdict \
         that is never reached because no ceiling is computed to reach it. A proxy that \
         announces a metering posture it cannot honor is worse than one that announces \
         none, so this is refused at load rather than at the moment somebody disputes an \
         invoice. Set `role: receipt` for the half that is complete: a signed, hash-chained \
         record of what each call actually consumed, written after it is served. See the \
         `role` section of `docs/metering.md`.",
        attestation_role_label(role)
    )
}

/// Validate `proxy.attestation` before anything is built from it.
///
/// Runs on every compile, including the one behind `sbproxy validate`,
/// which is why it lives here and not in the pipeline: the pipeline is
/// allowed to touch the filesystem and this is not, and an operator
/// checking a candidate config deserves the same answer the server
/// would give them.
///
/// The rule the whole block turns on is that a declared role has to be
/// honorable. A role this build cannot perform at all is the first
/// case of that rule and is refused before anything else is read; see
/// [`refuse_claim_role`]. After that, a role with no queue drops
/// unsettled claims on restart, a role with no ledger cannot prove a
/// gap, a role with an incomplete billing table charges by accident,
/// and a receipt with no signing identity is a log line. Each of those
/// fails here rather than at the moment somebody disputes an invoice.
fn validate_attestation(
    attestation: &AttestationConfig,
    web_bot_auth: Option<&WebBotAuthConfig>,
) -> Result<()> {
    let role: AttestationRole = attestation.role;
    let failure_mode: FailureMode = attestation.failure_mode;
    let enforcement_mode: EnforcementMode = attestation.enforcement_mode;

    // First, and before the keys a claim role would need: the operator
    // is owed the reason their whole posture is refused, not a demand
    // for a queue that would never be read either way.
    if role.makes_claims() {
        return Err(refuse_claim_role("proxy.attestation.role is", role));
    }

    // Every claim-making role is refused above, so the only role left
    // that engages the block is one that writes receipts. Spelled that
    // way rather than as the old disjunction, so a reader does not go
    // looking for a claim branch below that can no longer be reached.
    let engaged = role.writes_receipts();

    if engaged && !failure_mode.admits() {
        tracing::warn!(
            failure_mode = failure_mode.as_label(),
            "proxy.attestation.failure_mode refuses traffic when metering itself breaks. \
             That is the right call for an operator who cannot serve unbilled traffic, and \
             the wrong one for everybody else: a full ledger disk then takes the API down."
        );
    }
    if engaged && !enforcement_mode.blocks() {
        tracing::info!(
            enforcement_mode = enforcement_mode.as_label(),
            "proxy.attestation records attestation verdicts without acting on them"
        );
    }

    match attestation.sign_with.as_deref() {
        None if role.writes_receipts() => anyhow::bail!(
            "proxy.attestation.role writes receipts, so proxy.attestation.sign_with is \
             required: an unsigned receipt is a log line, not evidence. Set it to \
             `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`."
        ),
        None => {}
        Some(identity)
            if identity == ATTESTATION_SIGN_WITH_WEB_BOT_AUTH && web_bot_auth.is_none() =>
        {
            anyhow::bail!(
                "proxy.attestation.sign_with names `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`, \
                 but that block is not configured, so there is no key to sign with"
            )
        }
        Some(identity) if identity == ATTESTATION_SIGN_WITH_WEB_BOT_AUTH => {}
        Some(other) => anyhow::bail!(
            "proxy.attestation.sign_with `{other}` is not a signing identity this build can \
             resolve; the only accepted value is `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`"
        ),
    }

    match &attestation.queue {
        Some(queue) => validate_attestation_queue(queue)?,
        None if engaged => anyhow::bail!(
            "proxy.attestation declares a role, so proxy.attestation.queue is required: a \
             claim is written when a call starts and settled when it finishes, and with \
             nowhere to hold the gap a restart loses every claim in flight"
        ),
        None => {}
    }

    match &attestation.ledger {
        Some(ledger) => validate_attestation_ledger(ledger)?,
        None if engaged => anyhow::bail!(
            "proxy.attestation declares a role, so proxy.attestation.ledger is required: a \
             signature on each record says nothing about records that were never written, \
             and the chain is what makes a gap visible"
        ),
        None => {}
    }

    match &attestation.billable {
        Some(billable) => validate_attestation_billable(billable)?,
        None if engaged => anyhow::bail!(
            "proxy.attestation declares a role, so proxy.attestation.billable is required, \
             with an answer for all eight outcomes. There is no default, on purpose: an \
             unstated billing rule still runs, it just runs as whatever the code happened \
             to do."
        ),
        None => {}
    }

    validate_attestation_unit_resolvers(
        &attestation.measured,
        &attestation.route_weights,
        &attestation.origin_headers,
    )?;

    if engaged
        && attestation.measured.is_empty()
        && attestation.route_weights.is_empty()
        && attestation.origin_headers.is_empty()
    {
        // Not an error. A deployment can legitimately want the record
        // without the arithmetic: an event per call, an outcome, and a
        // chain that proves none went missing. It is worth saying out
        // loud all the same, because an operator who meant to price
        // something and mistyped the key gets a proxy that meters
        // diligently and bills nothing, and the receipts look fine.
        tracing::warn!(
            "proxy.attestation declares a role but no unit resolvers, so every receipt will \
             record an outcome with an empty units list. Declare proxy.attestation.measured, \
             proxy.attestation.route_weights, or proxy.attestation.origin_headers to price \
             the calls."
        );
    }

    Ok(())
}

/// Reject unit resolver declarations that could not produce a readable
/// invoice.
///
/// The cross-cutting check is the one worth having here: a unit name has
/// to identify one invoice line, across all three lists rather than
/// within each one. Route weights may repeat a name on purpose, because
/// several routes priced differently are still one line, and the most
/// specific match wins. Everything else that repeats a name produces two
/// entries on one receipt that a buyer cannot tell apart, and worse,
/// whose provenance differs, which defeats the reason the units are
/// broken out by source in the first place.
fn validate_attestation_unit_resolvers(
    measured: &[AttestationMeasuredConfig],
    route_weights: &[AttestationRouteWeightConfig],
    origin_headers: &[AttestationOriginHeaderConfig],
) -> Result<()> {
    let mut measured_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (index, entry) in measured.iter().enumerate() {
        validate_attestation_measured(index, entry)?;
        let name: &str = entry.name.trim();
        if !measured_names.insert(name) {
            anyhow::bail!(
                "proxy.attestation.measured: `{name}` is declared twice. One unit name is one \
                 invoice line, and two quantities filling the same line would produce a receipt \
                 nobody can read."
            );
        }
    }

    let mut route_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut seen_routes: std::collections::HashSet<(String, Option<String>, String)> =
        std::collections::HashSet::new();

    for entry in route_weights {
        validate_attestation_route_weight(entry)?;
        let name: &str = entry.name.trim();
        let method: Option<String> = entry
            .method
            .as_deref()
            .map(|method| method.trim().to_ascii_uppercase());
        let path: &str = entry.path.trim();
        if !seen_routes.insert((name.to_string(), method, path.to_string())) {
            anyhow::bail!(
                "proxy.attestation.route_weights: `{name}` prices `{path}` twice. Two weights \
                 for one route on one invoice line have no defensible order, so pick the one \
                 you meant."
            );
        }
        if measured_names.contains(name) {
            return Err(unit_name_claimed_twice(
                name,
                "a measured unit",
                "a route weight",
            ));
        }
        route_names.insert(name);
    }

    let mut header_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for entry in origin_headers {
        validate_attestation_origin_header(entry)?;
        let name: &str = entry.name.trim();
        if !header_names.insert(name) {
            anyhow::bail!(
                "proxy.attestation.origin_headers: `{name}` is declared twice. One unit name is \
                 one invoice line, and two headers filling the same line would produce a \
                 receipt nobody can read."
            );
        }
        if measured_names.contains(name) {
            return Err(unit_name_claimed_twice(
                name,
                "a measured unit",
                "an origin header",
            ));
        }
        if route_names.contains(name) {
            return Err(unit_name_claimed_twice(
                name,
                "a route weight",
                "an origin header",
            ));
        }
    }

    Ok(())
}

/// The error for one unit name claimed by two different resolvers.
///
/// Written once rather than three times so the three pairings cannot
/// drift apart in wording; the reason is identical in every one of them.
fn unit_name_claimed_twice(name: &str, first: &str, second: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "proxy.attestation: `{name}` is declared as both {first} and {second}. One name has to \
         mean one thing on a receipt: a buyer reading two `{name}` lines with different \
         provenance cannot tell which number came from where, which is the whole reason units \
         carry a source."
    )
}

/// Reject a measured entry that names nothing or divides by nothing.
fn validate_attestation_measured(index: usize, entry: &AttestationMeasuredConfig) -> Result<()> {
    let name: &str = entry.name.trim();
    if name.is_empty() {
        anyhow::bail!(
            "proxy.attestation.measured[{index}].name is empty; every entry needs a non-empty \
             `name`, because it is the invoice line the count is billed on"
        );
    }

    if entry.per == 0 {
        anyhow::bail!(
            "proxy.attestation.measured[{index}].per is 0. `per` is a divisor: it says how much \
             of the raw quantity makes one unit, so a divisor of zero cannot produce a unit \
             count for `{name}`. Use 1 to bill one unit per observed item, or 1024 to bill \
             kibibytes."
        );
    }

    Ok(())
}

/// Reject a route weight that names nothing or matches nothing.
fn validate_attestation_route_weight(entry: &AttestationRouteWeightConfig) -> Result<()> {
    let name: &str = entry.name.trim();
    if name.is_empty() {
        anyhow::bail!(
            "proxy.attestation.route_weights: every entry needs a non-empty `name`; it is the \
             invoice line the weight is billed on"
        );
    }

    let path: &str = entry.path.trim();
    if !path.starts_with('/') {
        anyhow::bail!(
            "proxy.attestation.route_weights: `{name}` has path {path:?}, which does not start \
             with `/` and so can never match a request path"
        );
    }
    // A `*` anywhere but the documented suffix is the shape of somebody
    // expecting glob matching. It would silently match nothing, which is
    // a route that quietly stops being priced.
    let stars = path.matches('*').count();
    if stars > 1 || (stars == 1 && !path.ends_with("/*")) {
        anyhow::bail!(
            "proxy.attestation.route_weights: `{name}` has path {path:?}. The only wildcard is \
             a trailing `/*`, which matches everything below that segment; anywhere else a `*` \
             is matched literally and the route would silently go unpriced."
        );
    }

    if let Some(method) = entry.method.as_deref() {
        let method: &str = method.trim();
        if method.is_empty() {
            anyhow::bail!(
                "proxy.attestation.route_weights: `{name}` has an empty `method`. Omit the key \
                 to price every method."
            );
        }
        if !method.bytes().all(|byte| byte.is_ascii_graphic()) {
            anyhow::bail!(
                "proxy.attestation.route_weights: `{name}` has method {method:?}, which is not \
                 an HTTP method token"
            );
        }
    }

    // `weight` is deliberately unchecked. Zero is a real answer (metered
    // and free) and there is no upper bound worth inventing for a number
    // the operator is charging themselves against.
    Ok(())
}

/// Reject an origin-header rule that names nothing or names a header
/// that cannot exist.
fn validate_attestation_origin_header(entry: &AttestationOriginHeaderConfig) -> Result<()> {
    let name: &str = entry.name.trim();
    if name.is_empty() {
        anyhow::bail!(
            "proxy.attestation.origin_headers: every entry needs a non-empty `name`; it is the \
             invoice line the origin's count is billed on"
        );
    }

    let header: &str = entry.header.trim();
    if header.is_empty()
        || http::header::HeaderName::from_bytes(header.to_ascii_lowercase().as_bytes()).is_err()
    {
        anyhow::bail!(
            "proxy.attestation.origin_headers: `{name}` reads {header:?}, which is not a valid \
             HTTP header name, so no response could ever carry it"
        );
    }
    Ok(())
}

/// Reject a claim queue that could not hold a claim.
fn validate_attestation_queue(queue: &AttestationQueueConfig) -> Result<()> {
    if queue.path.trim().is_empty() {
        anyhow::bail!("proxy.attestation.queue.path must be non-empty");
    }
    let max_entries: usize = queue.max_entries;
    if max_entries == 0 {
        anyhow::bail!(
            "proxy.attestation.queue.max_entries must be at least 1; a queue of zero drops \
             every claim at the moment it is made, which is silently not metering"
        );
    }
    if max_entries > MAX_ATTESTATION_QUEUE_ENTRIES {
        anyhow::bail!(
            "proxy.attestation.queue.max_entries {max_entries} exceeds the cap of \
             {MAX_ATTESTATION_QUEUE_ENTRIES}; past that an operator is describing a \
             database rather than a hold buffer, and an extra zero should not be the way \
             they find out"
        );
    }
    Ok(())
}

/// Reject a ledger path that names nothing.
fn validate_attestation_ledger(ledger: &AttestationLedgerConfig) -> Result<()> {
    if ledger.path.trim().is_empty() {
        anyhow::bail!("proxy.attestation.ledger.path must be non-empty");
    }
    Ok(())
}

/// Refuse a billing table that leaves any outcome unanswered, naming
/// every one that is missing rather than the first.
///
/// Serde would reject a missing required field on its own, one field per
/// compile. That is the wrong shape for this block: an operator who left
/// three outcomes blank should see all three, because the point of the
/// exercise is to make them decide, not to make them guess.
fn validate_attestation_billable(billable: &AttestationBillableConfig) -> Result<()> {
    let missing: Vec<&'static str> = billable.missing_outcomes();
    if !missing.is_empty() {
        anyhow::bail!(
            "proxy.attestation.billable has no answer for {}. Every outcome needs one, \
             because a billing rule left implicit is a billing rule nobody agreed to. Each \
             takes one of yes, no, partial, collapse.",
            missing.join(", "),
        );
    }
    Ok(())
}

/// Validate one origin's attestation override against the proxy block
/// it inherits from.
///
/// The checks worth having are the widening ones. `proxy.attestation`
/// only has to declare a signing identity when the proxy-wide role
/// writes receipts, so an origin that widens `off` to `receipt` can
/// reach a receipt with nothing to sign it. And the proxy-wide refusal
/// of the claim half only sees the proxy-wide role, so an origin that
/// widens `receipt` to `both` would otherwise walk straight past it.
/// Both holes are invisible in either block on its own, which is why
/// this runs where both are in scope.
fn validate_origin_attestation(
    hostname: &str,
    proxy: &AttestationConfig,
    attestation: &OriginAttestationConfig,
) -> Result<()> {
    let role: Option<AttestationRole> = attestation.role;
    let agreement_id: Option<&str> = attestation.agreement_id.as_deref();
    let resolved: AttestationRole = role.unwrap_or(proxy.role);

    // WOR-2623: the resolved role, not the authored one. An origin
    // inheriting a refused proxy-wide role never gets here, because the
    // proxy-wide check runs first; what this catches is the override
    // that introduces the claim half one origin at a time.
    if resolved.makes_claims() {
        return Err(refuse_claim_role(
            &format!("origin `{hostname}`: attestation.role resolves to"),
            resolved,
        ));
    }

    if resolved.writes_receipts() && proxy.sign_with.is_none() {
        anyhow::bail!(
            "origin `{hostname}`: attestation.role writes receipts, but \
             proxy.attestation.sign_with is unset, so nothing could sign them. An unsigned \
             receipt is a log line, not evidence."
        );
    }
    if resolved.writes_receipts() && agreement_id.is_none() {
        tracing::warn!(
            hostname = %hostname,
            "origin writes receipts but names no attestation.agreement_id, so its receipts \
             will record how much was consumed without naming the contract that prices it"
        );
    }
    Ok(())
}

/// Resolve an origin's upstream timeouts into concrete durations.
///
/// Absent fields fall back to the `DEFAULT_UPSTREAM_*` constants so the
/// request path never sees an `Option`. The idle deadline has one extra
/// input: the legacy `connection_pool.idle_timeout_secs` spelling feeds the
/// same resolved value when `timeouts.idle_ms` is unset, and authoring both
/// (a non-default legacy value next to `idle_ms`) fails the compile so the
/// two keys cannot silently disagree.
///
/// # Errors
///
/// Returns an error when any configured deadline is `0`: a zero deadline
/// fails the operation the moment it starts and is never what an operator
/// meant, so it is rejected here rather than shipped.
fn resolve_upstream_timeouts(
    hostname: &str,
    timeouts: Option<&UpstreamTimeoutsConfig>,
    connection_pool: Option<&ConnectionPoolConfig>,
) -> Result<UpstreamTimeouts> {
    // An explicitly typed local (all fields `None` when the block is
    // absent) keeps the field reads below visible to the build-time
    // config-reader guard, which cannot type closure parameters.
    let authored: UpstreamTimeoutsConfig = timeouts.cloned().unwrap_or_default();

    let configured = [
        ("timeouts.connect_ms", authored.connect_ms),
        ("timeouts.total_connect_ms", authored.total_connect_ms),
        ("timeouts.read_ms", authored.read_ms),
        ("timeouts.write_ms", authored.write_ms),
        ("timeouts.idle_ms", authored.idle_ms),
    ];
    for (key, value) in configured {
        if value == Some(0) {
            anyhow::bail!(
                "origin {hostname}: {key} is 0. A zero deadline fails the upstream operation \
                 the moment it starts; omit the key to keep the built-in default instead."
            );
        }
    }

    let pool_idle_secs = connection_pool.map(|pool| pool.idle_timeout_secs);
    let idle_ms = match (authored.idle_ms, pool_idle_secs) {
        // The legacy key's serde default (90 s) is indistinguishable from an
        // authored 90, so only a non-default legacy value can conflict.
        (Some(_), Some(pool_secs))
            if pool_secs != ConnectionPoolConfig::default().idle_timeout_secs =>
        {
            anyhow::bail!(
                "origin {hostname}: config conflict: both `timeouts.idle_ms` and \
                 `connection_pool.idle_timeout_secs` are set. They name the same upstream \
                 idle deadline; remove the legacy `connection_pool.idle_timeout_secs` and \
                 keep `timeouts.idle_ms`."
            );
        }
        (Some(idle_ms), _) => idle_ms,
        (None, Some(pool_secs)) => {
            if pool_secs == 0 {
                anyhow::bail!(
                    "origin {hostname}: connection_pool.idle_timeout_secs is 0. A zero idle \
                     deadline closes every pooled upstream connection the moment it goes \
                     idle; omit the key to keep the built-in default instead."
                );
            }
            u64::from(pool_secs).saturating_mul(1000)
        }
        (None, None) => DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS,
    };

    let ms = std::time::Duration::from_millis;
    Ok(UpstreamTimeouts {
        connect: ms(authored
            .connect_ms
            .unwrap_or(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS)),
        total_connect: ms(authored
            .total_connect_ms
            .unwrap_or(DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS)),
        read: ms(authored.read_ms.unwrap_or(DEFAULT_UPSTREAM_READ_TIMEOUT_MS)),
        write: ms(authored
            .write_ms
            .unwrap_or(DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS)),
        idle: ms(idle_ms),
    })
}

/// Refuse the per-origin keys that parse and govern nothing (WOR-2310).
///
/// Each of these was accepted, warned about once at compile as
/// `config_only`, and then ignored for the life of the process. A warning
/// is the right call for a key whose behavior is merely narrower than its
/// name suggests; it is the wrong call for a key with no implementation at
/// all, because the config keeps claiming a property the proxy does not
/// have. These are the second kind, so they are refused outright, the same
/// call `load_balancer`'s `sticky:` and `audit.sink: tracing` took.
///
/// Every message names a surface that works, because an operator who set
/// one of these wanted something real.
///
/// WOR-2325 added the inline forward-origin metadata
/// (`forward_rules[].origin.hostname` / `.workspace_id` / `.version`) on
/// the same grounds, and `cors.enable` on stronger ones: that boolean did
/// not merely fail to govern, it governed backwards, so it is refused for
/// the one value that lied rather than for its presence.
///
/// # Errors
///
/// Returns an error naming the key when any of them is authored. An
/// omitted key is `None` and compiles.
fn refuse_inert_origin_keys(hostname: &str, config: &RawOriginConfig) -> Result<()> {
    if let Some(pool) = config.connection_pool.as_ref() {
        if let Some(max) = pool.max_connections {
            anyhow::bail!(
                "origin {hostname}: connection_pool.max_connections is set ({max}), but this \
                 build never applied it. Pingora sizes the upstream keepalive pool once per \
                 connector, not per origin, so there is no per-origin limit for the value to \
                 become and upstream connections were never capped at it. Remove it. To bound \
                 how many requests this origin has in flight, add a `concurrent_limit` policy \
                 with `max: {max}`, which is enforced per request and rejects over the cap \
                 instead of queueing."
            );
        }
        if let Some(secs) = pool.max_lifetime_secs {
            anyhow::bail!(
                "origin {hostname}: connection_pool.max_lifetime_secs is set ({secs}), but this \
                 build never applied it. Pingora's connection pool has no age-based eviction, \
                 so no pooled upstream connection was ever retired for being old and a \
                 long-lived connection outlived this deadline indefinitely. Remove it. The \
                 deadline that does retire pooled connections is the idle one, \
                 `timeouts.idle_ms`, which closes a connection after it has gone unused for \
                 that long."
            );
        }
    }

    if config.traffic_capture.is_some() {
        anyhow::bail!(
            "origin {hostname}: traffic_capture is set, but this build has no traffic-capture \
             consumer. Nothing read the block, and because it was accepted as an untyped value \
             nothing validated it either, so a misspelled field inside it looked exactly like a \
             working setting. Remove it. To send a copy of each request somewhere for \
             inspection, use `mirror`, which forwards a fire-and-forget duplicate to a second \
             upstream and does not delay or fail the real request."
        );
    }

    if let Some(ttl) = config.sessions.as_ref().and_then(|s| s.ttl_seconds) {
        anyhow::bail!(
            "origin {hostname}: sessions.ttl_seconds is set ({ttl}), but this build has no \
             sessions index to retain. Sessions appear in the admin recent-request ring, which \
             is bounded by entry count and evicts the oldest entry when it is full, so a \
             session aged out on request volume and never on this deadline. Remove it. To bound \
             how many sessions are minted, use `sessions.budget.max_per_window` with \
             `sessions.budget.window_seconds`, both of which are enforced."
        );
    }

    // WOR-2325: the inline forward-origin metadata. The forward-origin
    // runtime reads `origin.action` and `origin.request_modifiers`, and
    // OpenAPI emission reads `origin.id`. These three are read by nobody:
    // the parent origin's hostname is what routes the request, and the
    // compiled child origin carries neither a version nor a workspace
    // label for the other two to become. Each is refused on its own so the
    // operator is told which line to delete and why that particular one
    // never mattered.
    for (index, rule) in config.forward_rules.iter().enumerate() {
        // `origin.id` is the rule's own identifier and the one metadata
        // field that is read, so it names the rule when it is present and
        // the index stands in when it is not.
        let rule_label = match rule.origin.id.as_deref() {
            Some(id) => format!("forward_rules[{index}] (origin id `{id}`)"),
            None => format!("forward_rules[{index}]"),
        };
        if let Some(value) = rule.origin.hostname.as_deref() {
            anyhow::bail!(
                "origin {hostname}: {rule_label} sets origin.hostname (`{value}`), but a forward \
                 rule never routes on it. The request has already been matched to `{hostname}` \
                 by the time the rule fires, so this tag selected no upstream and changed no \
                 header. Delete the line. To send the matched request to a different host, put \
                 that host in the rule's own `origin.action.url`; to label the rule in metrics \
                 and in the emitted OpenAPI document, use `origin.id`, which is read."
            );
        }
        if let Some(value) = rule.origin.workspace_id.as_deref() {
            anyhow::bail!(
                "origin {hostname}: {rule_label} sets origin.workspace_id (`{value}`), but \
                 nothing reads it. The compiled child origin has no workspace field, so the \
                 value never reached routing, logs, metrics, or cost attribution. Delete the \
                 line. Multi-tenant attribution is `origins.{hostname}.tenant_id` naming a \
                 declared `proxy.tenants[].id`, which is checked at compile and labels the \
                 request everywhere downstream."
            );
        }
        if let Some(value) = rule.origin.version.as_deref() {
            anyhow::bail!(
                "origin {hostname}: {rule_label} sets origin.version (`{value}`), but nothing \
                 reads it. The compiled child origin carries no version label, so the value \
                 never reached routing, logs, metrics, or the emitted OpenAPI document. Delete \
                 the line. To version the surface a caller sees, match the version in the path \
                 (`rules: - path: {{ prefix: /v2/ }}`); to version the rule for your own \
                 records, fold it into `origin.id`, which is read."
            );
        }
    }

    // WOR-2325: `cors.enable: false` is the one value on this block that
    // did not merely fail to govern, it governed backwards. Both runtime
    // entry points gate on the PRESENCE of the `cors:` block and neither
    // one looks at the boolean, so an operator who wrote `false` to turn
    // CORS off ran with CORS fully on. `true` is left accepted because it
    // agrees with what the block already does, which also keeps the
    // archived schema-v1 fixtures compiling unmodified. The alias spelling
    // `enabled` deserializes into this same field, so both spellings are
    // covered by the one check.
    if config
        .cors
        .as_ref()
        .is_some_and(|cors| cors.enable == Some(false))
    {
        anyhow::bail!(
            "origin {hostname}: cors.enable is false, but this build never read it and CORS has \
             been fully active on this origin the whole time. Both entry points, the preflight \
             responder and the response header pass, gate on the presence of the `cors:` block \
             rather than on this boolean, so every matching request was answered with \
             `Access-Control-Allow-Origin` despite the false. The only way to turn CORS off is \
             to delete the whole `cors:` block. If you meant to leave CORS on, delete just the \
             `enable` line (or set it to true, which is accepted because it describes what the \
             block already does) and narrow `allowed_origins` instead."
        );
    }

    Ok(())
}

/// Validate an `origins:` map key at config compile.
///
/// Exact hostnames pass through untouched. A key starting with `*.`
/// declares a wildcard origin that matches one or more leading labels:
/// `*.example.com` matches `a.example.com` and `a.b.example.com`, never
/// `example.com` itself. Exact keys always beat wildcards at request
/// time, and between wildcards the longest matching suffix wins, so a
/// wildcard duplicating an exact key is legal rather than a conflict.
///
/// The `*` must be the complete first label. Mid-label forms
/// (`a*.example.com`), inner labels (`api.*.example.com`), and a bare
/// `*` are rejected here so a typo fails boot instead of becoming an
/// exact key no request will ever match.
fn validate_origin_host_key(hostname: &str) -> Result<()> {
    if !hostname.contains('*') {
        return Ok(());
    }
    if hostname == "*" || hostname == "*." {
        anyhow::bail!(
            "origin `{hostname}`: a bare catch-all wildcard is not supported; use a \
             leading `*.` label with a non-empty suffix, e.g. `*.example.com`"
        );
    }
    let Some(suffix) = hostname.strip_prefix("*.") else {
        anyhow::bail!(
            "origin `{hostname}`: `*` is only supported as the complete first label \
             (`*.example.com`); mid-label wildcards are not supported"
        );
    };
    if suffix.contains('*') {
        anyhow::bail!(
            "origin `{hostname}`: `*` may appear only once, as the complete first \
             label (`*.example.com`)"
        );
    }
    if suffix.split('.').any(|label| label.is_empty()) {
        anyhow::bail!("origin `{hostname}`: wildcard suffix `{suffix}` contains an empty label");
    }
    Ok(())
}

/// Refuse a `cors:` block the CORS middleware would answer with silence.
///
/// `allowed_origins: ["*"]` plus `allow_credentials: true` is the pair
/// browsers reject outright. The middleware has always refused to emit any
/// header for it, but only at request time, which turned a config mistake
/// into a browser app that fails with no server-side error and a warn line
/// per request. The predicate is
/// [`CorsConfig::wildcard_with_credentials`], shared with the runtime
/// guard so this refusal cannot drift narrower than that one.
fn validate_origin_cors(hostname: &str, cors: &CorsConfig) -> Result<()> {
    if cors.wildcard_with_credentials() {
        anyhow::bail!(
            "origin {hostname}: cors.allowed_origins contains `*` and cors.allow_credentials is \
             true. Browsers refuse that pair per the Fetch standard, so the proxy emits no CORS \
             headers at all for it and the browser app breaks with nothing in the response \
             saying why. Pick one: list the origins you mean in `allowed_origins`, or drop \
             `allow_credentials`."
        );
    }
    Ok(())
}

/// Refuse a `compression.algorithms` entry that names no codec.
///
/// An unrecognized name used to make every codec unnegotiable for the
/// origin, so `algorithms: [deflate]` served every response uncompressed
/// with no load-time error and nothing in the logs or metrics separating
/// it from a client that advertised no encodings at all.
fn validate_origin_compression(hostname: &str, compression: &CompressionConfig) -> Result<()> {
    for entry in &compression.algorithms {
        let token = entry.trim().to_ascii_lowercase();
        if !COMPRESSION_ALGORITHM_TOKENS.contains(&token.as_str()) {
            let supported = COMPRESSION_ALGORITHM_TOKENS.join(", ");
            anyhow::bail!(
                "origin {hostname}: compression.algorithms contains `{entry}`, which names no \
                 codec this proxy can produce. Supported entries are: {supported}. The list is \
                 a priority order, so the first entry the client accepts is the one served."
            );
        }
    }
    Ok(())
}

/// Compile a single origin from its raw config.
///
/// # Errors
///
/// Returns an error if any of the origin's configured modules (action,
/// auth, policy, or transform) names an unknown type or has invalid
/// parameters, if a referenced module cannot be built, or if its `cors:`
/// or `compression:` block carries a setting the runtime would have to
/// ignore.
pub fn compile_origin(hostname: &str, mut config: RawOriginConfig) -> Result<CompiledOrigin> {
    // Before any work: reject the keys that would otherwise be accepted
    // into a snapshot that does not honor them (WOR-2310).
    refuse_inert_origin_keys(hostname, &config)?;

    let allowed_methods: SmallVec<[http::Method; 4]> = config
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse::<http::Method>().ok())
        .collect();

    if let Some(properties) = config.properties.as_mut() {
        properties
            .validate_and_normalize_rollup_keys()
            .map_err(|message| anyhow::anyhow!("origin {hostname}: {message}"))?;
    }

    // Interpolate {{vars.X}} and {{env.X}} in all JSON value fields.
    // This resolves template patterns in action URLs, error pages, etc.
    // Header modifier values are also resolved at runtime by TemplateContext.
    interpolate_config_vars(&mut config.action, &config.variables);
    if let Some(ref mut auth) = config.authentication {
        interpolate_config_vars(auth, &config.variables);
    }
    for policy in &mut config.policies {
        interpolate_config_vars(policy, &config.variables);
    }
    for transform in &mut config.transforms {
        interpolate_config_vars(transform, &config.variables);
    }
    for filter in &mut config.filters {
        interpolate_config_vars(&mut filter.config, &config.variables);
    }
    for fwd_rule in &mut config.forward_rules {
        // Forward rules are typed in `RawOriginConfig` but the interpolator
        // walks `serde_json::Value` recursively. Round-trip through JSON so
        // `{{vars.X}}` placeholders inside action bodies and modifier headers
        // still get substituted.
        if let Ok(mut value) = serde_json::to_value(&*fwd_rule) {
            interpolate_config_vars(&mut value, &config.variables);
            if let Ok(updated) = serde_json::from_value(value) {
                *fwd_rule = updated;
            }
        }
    }
    if let Some(ref mut fallback) = config.fallback_origin {
        interpolate_config_vars(fallback, &config.variables);
    }
    if let Some(ref mut pages) = config.error_pages {
        for entry in pages.iter_mut() {
            if entry.body.contains("{{") {
                entry.body = resolve_template_string(&entry.body, &config.variables);
            }
            if entry.content_type.contains("{{") {
                entry.content_type =
                    resolve_template_string(&entry.content_type, &config.variables);
            }
        }
    }
    // Interpolate request/response modifier header values.
    for modifier in &mut config.request_modifiers {
        if let Some(ref mut hm) = modifier.headers {
            for value in hm.set.values_mut() {
                if value.contains("{{") {
                    *value = resolve_template_string(value, &config.variables);
                }
            }
            for value in hm.add.values_mut() {
                if value.contains("{{") {
                    *value = resolve_template_string(value, &config.variables);
                }
            }
        }
    }
    for modifier in &mut config.response_modifiers {
        if let Some(ref mut hm) = modifier.headers {
            for value in hm.set.values_mut() {
                if value.contains("{{") {
                    *value = resolve_template_string(value, &config.variables);
                }
            }
            for value in hm.add.values_mut() {
                if value.contains("{{") {
                    *value = resolve_template_string(value, &config.variables);
                }
            }
        }
    }

    // WOR-2482: resolve a Rego modifier's `rego_module_path` into
    // `rego_module` once, here, mirroring `policy: rego`'s `module` /
    // `module_path` split (see Task 1). Downstream code (sbproxy-core,
    // which does the actual evaluation) reads only `rego_module`.
    for modifier in &mut config.request_modifiers {
        resolve_rego_modifier_module(
            hostname,
            "request_modifiers[]",
            &mut modifier.rego_module,
            &mut modifier.rego_module_path,
            modifier.rego_budget_ms,
        )?;
    }
    for modifier in &mut config.response_modifiers {
        resolve_rego_modifier_module(
            hostname,
            "response_modifiers[]",
            &mut modifier.rego_module,
            &mut modifier.rego_module_path,
            modifier.rego_budget_ms,
        )?;
    }
    for fwd_rule in &mut config.forward_rules {
        for modifier in &mut fwd_rule.origin.request_modifiers {
            resolve_rego_modifier_module(
                hostname,
                "forward_rules[].origin.request_modifiers[]",
                &mut modifier.rego_module,
                &mut modifier.rego_module_path,
                modifier.rego_budget_ms,
            )?;
        }
    }

    let variables = if config.variables.is_empty() {
        None
    } else {
        Some(Box::new(
            config
                .variables
                .iter()
                .map(|(k, v)| (CompactString::new(k), v.clone()))
                .collect(),
        ))
    };

    // Deserialize the raw `response_cache` JSON (if any) into a typed struct.
    //
    // WOR-1140: a parse failure here is a hard compile error. This block
    // used to downgrade to "no cache" with a warning, but with
    // `deny_unknown_fields` on `ResponseCacheConfig` a misspelled key
    // would have turned into a silently disabled cache, which is the
    // exact silent-drop failure mode this ticket removes. An operator
    // who authored a `response_cache:` block gets the block they wrote
    // or an error naming what is wrong with it.
    let response_cache: Option<crate::types::ResponseCacheConfig> = match &config.response_cache {
        Some(v) => match serde_json::from_value::<crate::types::ResponseCacheConfig>(v.clone()) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                anyhow::bail!(
                    "origin '{hostname}': response_cache block failed to parse: {e}. Fix the \
                     block (or remove it); a malformed cache config is rejected rather than \
                     silently ignored."
                );
            }
        },
        None => None,
    };

    // WOR-2367: refuse a malformed decision script at load. A cache
    // event that fails every evaluation degrades silently to the static
    // config, and the only symptom is a hit rate that never improves,
    // so the engine name is checked here rather than per request.
    if let Some(cache) = response_cache.as_ref() {
        if let Some(script) = cache.key_event.as_ref() {
            validate_decision_script(
                &format!("origin '{hostname}': response_cache.key_event"),
                script,
            )?;
        }
        if let Some(script) = cache.admit_event.as_ref() {
            validate_decision_script(
                &format!("origin '{hostname}': response_cache.admit_event"),
                script,
            )?;
        }
    }

    // WOR-2342: refuse a cacheable method that carries a request body.
    //
    // `compute_cache_key` builds
    // `<workspace>:<hostname>:<method>:<path>:<query>:<vary>` and takes no
    // body parameter at all. For GET and HEAD that is complete, because
    // the request is fully described by its target and headers. For a
    // method whose body carries the request, it is not: every POST to one
    // URL collapses to a single key.
    //
    // So `methods: [GET, POST]` on an AI origin serves the first cached
    // completion to every later prompt at that path. Not a stale answer,
    // someone else's answer, returned as a cache hit with no indication
    // anything is wrong. The default is GET-only, which is the only
    // reason this has not caused damage.
    //
    // Refused rather than fixed by hashing the body, for two reasons. The
    // lookup happens in `request_filter`, before the body is buffered, so
    // keying on it would mean buffering every request body on the hot
    // path before knowing whether the route caches at all. And AI traffic
    // already has a purpose-built answer: the semantic cache keys on
    // prompt content by design, with a similarity threshold and per-scope
    // isolation this cache has no notion of.
    //
    // nginx takes the same position from the other direction:
    // `proxy_cache_methods` accepts POST, but the operator must add
    // `$request_body` to `proxy_cache_key` themselves. Accepting the
    // method without the key is the combination that is never right.
    if let Some(cache) = &response_cache {
        const BODY_SAFE_METHODS: &[&str] = &["GET", "HEAD"];
        for method in &cache.cacheable_methods {
            if !BODY_SAFE_METHODS
                .iter()
                .any(|safe| safe.eq_ignore_ascii_case(method))
            {
                anyhow::bail!(
                    "origin '{hostname}': response_cache cannot cache `{method}`. The cache key \
                     is built from method, path, query, and Vary headers only, so every \
                     `{method}` to one path shares a single entry and the first response is \
                     served to every later request regardless of its body. Only GET and HEAD \
                     are safe here. To cache AI completions, use the semantic cache \
                     (`origins.<host>.action.semantic_cache`), which keys on prompt content."
                );
            }
        }
    }

    // --- Wave 4 day-4: auto-prepend the content-shaping chain ---
    //
    // When the origin authors an `ai_crawl_control` policy or one of
    // the new content-shaping transforms (`boilerplate`,
    // `citation_block`, `json_envelope`), the compile step synthesises
    // a default `content_negotiate` action and (when no transforms
    // were authored) prepends the four-transform default chain.
    // Operators can override either by explicitly authoring
    // `transforms:` with at least one entry, in which case the
    // auto-wire backs off and uses what the operator wrote verbatim.
    //
    // G4.1 carries the resolver contract; A4.2 places the JSON
    // envelope in the chain.
    let has_ai_crawl_control = config
        .policies
        .iter()
        .any(|p| policy_type_is(p, "ai_crawl_control") || policy_type_is(p, "pay_per_crawl"));
    let has_wave4_transform = config.transforms.iter().any(|t| {
        transform_type_is(t, "boilerplate")
            || transform_type_is(t, "citation_block")
            || transform_type_is(t, "json_envelope")
    });
    let needs_content_negotiate = has_ai_crawl_control || has_wave4_transform;

    let auto_content_negotiate = if needs_content_negotiate {
        // Wave 4 day-5 G4.2 wire: thread the per-origin
        // `default_content_shape:` YAML key into the synthesised
        // content_negotiate config. Operators who set
        // `default_content_shape: markdown` get that value as the
        // wildcard `*/*` fallback. Unset falls back to `html` inside
        // the resolver per G4.1's contract.
        match config.default_content_shape.as_deref() {
            Some(shape) => Some(serde_json::json!({
                "type": "content_negotiate",
                "default_content_shape": shape,
            })),
            None => Some(serde_json::json!({"type": "content_negotiate"})),
        }
    } else {
        None
    };

    // Auto-wire the four-transform default chain when:
    //  - `ai_crawl_control` is configured, AND
    //  - the operator authored an empty `transforms:` list.
    //
    // The default chain order matters (G4.10 / G4.4):
    //   boilerplate -> html_to_markdown -> citation_block -> json_envelope.
    // boilerplate strips before Markdown projection so the projection
    // sees mainly the article body; citation_block prepends to the
    // Markdown body; json_envelope wraps the whole thing for the
    // ContentShape::Json branch and is a no-op otherwise.
    //
    // Operators who author a non-empty `transforms:` list keep full
    // control; the auto-wire stays out of their way.
    //
    // Wave 4 / A4.2 follow-up: when the operator set
    // `token_bytes_ratio:` at the origin level, thread it onto the
    // synthesised `html_to_markdown` config so the projection's
    // `token_estimate` field honours the override. Operators who
    // authored their own `transforms:` list set the ratio inside
    // their `html_to_markdown` entry directly.
    if has_ai_crawl_control && config.transforms.is_empty() {
        let html_to_markdown = match config.token_bytes_ratio {
            Some(ratio) => serde_json::json!({
                "type": "html_to_markdown",
                "token_bytes_ratio": ratio,
            }),
            None => serde_json::json!({"type": "html_to_markdown"}),
        };
        config.transforms = vec![
            serde_json::json!({"type": "boilerplate"}),
            html_to_markdown,
            serde_json::json!({"type": "citation_block"}),
            serde_json::json!({"type": "json_envelope"}),
        ];
    }

    // --- WOR-2136: refuse the dead tag + body-aware combination ---
    //
    // `action: tag` stamps the score / label headers onto the upstream
    // request, and the upstream request is already assembled by the
    // time the request body is read. On anything but an `ai_proxy`
    // origin a body-aware hit therefore has nowhere to write: the
    // combination reads as enforcing and enforces nothing. `ai_proxy`
    // is exempt because that path reads the body before dispatch and
    // can tag. Rejecting at compile keeps the dead combination out of
    // running configs.
    let origin_action_type = config
        .action
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    for policy in &config.policies {
        if !policy_type_is(policy, "prompt_injection_v2") {
            continue;
        }
        if !policy
            .get("enable_body_aware")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let action_key = policy.get("action").and_then(|v| v.as_str());
        // `enforcement: block` (WOR-2121) forces every hit to refuse,
        // so the tag flavor never manifests and the combination is
        // live: refusing it would make this compile-time detector
        // narrower than the runtime it guards. `observe` keeps the tag
        // flavor, so the dead combination stays dead there.
        let enforcement_key = policy.get("enforcement").and_then(|v| v.as_str());
        if action_key.unwrap_or("tag") == "tag"
            && enforcement_key != Some("block")
            && origin_action_type != "ai_proxy"
        {
            let default_note = if action_key.is_none() {
                " (the default)"
            } else {
                ""
            };
            anyhow::bail!(
                "origin {hostname}: prompt_injection_v2 sets `enable_body_aware: true` \
                 with `action: tag`{default_note} on a `{origin_action_type}` origin. \
                 A body hit cannot stamp the tag headers because the upstream request \
                 is already assembled by the time the body is read, so this combination \
                 enforces nothing. Use `action: block` or `action: log` for body-aware \
                 scanning here; tagging on a body hit works only on `ai_proxy` origins, \
                 which read the body before dispatch."
            );
        }
    }

    // --- WOR-2136: warn about body-reading policies on `static` ---
    //
    // A `static` action answers at the request phase and never
    // forwards, so `request_body_filter` never runs and a policy that
    // inspects the request body inspects nothing there. Warn rather
    // than reject: the origin still serves, and the combination has
    // shipped before as a copy-paste artifact (fixed in #861).
    if origin_action_type == "static" {
        for policy in &config.policies {
            let policy_type = policy.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let reads_body = matches!(
                policy_type,
                "openapi_validation" | "content_digest" | "request_validator"
            ) || (policy_type == "prompt_injection_v2"
                && policy
                    .get("enable_body_aware")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false));
            if reads_body {
                tracing::warn!(
                    hostname = %hostname,
                    policy = %policy_type,
                    "policy reads the request body, but a `static` action never \
                     forwards a request, so request_body_filter never runs and the \
                     policy validates nothing on this origin"
                );
            }
        }
    }

    // --- WOR-2316: warn about header-sourced object_authz ownership ---
    //
    // `object_authz` compares a path segment against the caller's owner
    // identity. With `principal.owner_from: sub` that identity is the
    // verified auth subject and the comparison means something. With
    // `owner_from: header` it is whatever the request said, so any
    // client that can reach the proxy directly can name itself the
    // owner of any object and the BOLA rule passes. That is a valid
    // deployment behind an ingress that strips the header on the way
    // in, and an authorization bypass without one, and the config
    // cannot tell which it is. Warn loudly and name the origin; do not
    // reject, because the trusted-ingress shape is real.
    for policy in &config.policies {
        if !policy_type_is(policy, "object_authz") && !policy_type_is(policy, "bola") {
            continue;
        }
        let principal = policy.get("principal");
        let owner_from = principal
            .and_then(|p| p.get("owner_from"))
            .and_then(|v| v.as_str());
        if owner_from != Some("header") {
            continue;
        }
        let owner_header = principal
            .and_then(|p| p.get("owner_header"))
            .and_then(|v| v.as_str())
            .unwrap_or("x-owner-id");
        tracing::warn!(
            hostname = %hostname,
            owner_header = %owner_header,
            "object_authz reads the object owner from the `{owner_header}` request header \
             instead of the verified auth subject. Any client that can reach this origin \
             directly can set that header and assert ownership of any object, so the BOLA \
             rules on origin `{hostname}` enforce nothing unless an ingress in front of the \
             proxy strips `{owner_header}` from every inbound request. Use \
             `principal.owner_from: sub` unless that ingress exists."
        );
    }

    // --- Wave 4 / G4.5: validate and intern the Content-Signal value ---
    //
    // The closed enum is `{ai-train, search, ai-input}` per A4.1's
    // value table. Any other value (including unknown casing) fails
    // config compilation hard so a typo in YAML does not silently
    // suppress the response header. The interned `&'static str` form
    // lets the response_filter stamp the header without re-formatting
    // on every request.
    let content_signal: Option<&'static str> = match config.content_signal.as_deref() {
        None => None,
        Some("ai-train") => Some("ai-train"),
        Some("search") => Some("search"),
        Some("ai-input") => Some("ai-input"),
        Some(other) => {
            anyhow::bail!(
                "invalid content_signal value {:?} for origin {}: must be one of ai-train, search, ai-input",
                other,
                hostname
            );
        }
    };

    let token_bytes_ratio = config.token_bytes_ratio;

    // --- WOR-2565: compile the deprecation announcement blocks ---
    //
    // The origin-scope block compiles onto the snapshot; each forward
    // rule's block is compiled here for validation only (an unparseable
    // date, a sunset before the deprecation instant, or a `gone`
    // posture with no sunset refuses the whole config now rather than
    // at first request), and the runtime pipeline compiler re-runs the
    // same function on the rule JSON to build the per-rule form.
    let deprecation = config
        .deprecation
        .as_ref()
        .map(|raw| {
            let scope = format!("origin {hostname}");
            crate::types::warn_dateless_deprecated(raw, &scope);
            crate::types::compile_deprecation(raw, &scope)
        })
        .transpose()?;
    for (rule_idx, rule) in config.forward_rules.iter().enumerate() {
        if let Some(raw) = rule.deprecation.as_ref() {
            let scope = format!("forward rule {rule_idx} on origin {hostname}");
            crate::types::warn_dateless_deprecated(raw, &scope);
            crate::types::compile_deprecation(raw, &scope)?;
        }
    }

    // --- WOR-193: validate agent_skills entries at config-load ---
    //
    // Reject unknown `type:` discriminators eagerly so a typo cannot
    // silently turn a `skill-md` entry into an unhandled bucket. The
    // closed enum is `{skill-md, archive}` per the v0.2.0 spec.
    // Visibility is `{public, authenticated}`; absent (or any other
    // value) falls back to public at the call site.
    for skill in &config.agent_skills {
        match skill.kind.as_str() {
            "skill-md" | "archive" => {}
            other => {
                anyhow::bail!(
                    "invalid agent_skills entry {:?} for origin {}: type must be one of skill-md, archive (got {:?})",
                    skill.name,
                    hostname,
                    other
                );
            }
        }
        match skill.visibility.as_str() {
            "public" | "authenticated" => {}
            other => {
                anyhow::bail!(
                    "invalid agent_skills visibility {:?} for origin {} entry {:?}: must be public or authenticated",
                    other,
                    hostname,
                    skill.name
                );
            }
        }
    }

    // WOR-2127: shape-check the per-origin attestation override. An
    // empty `agreement_id` is worse than an absent one: it parses, it
    // reaches a receipt, and it names no contract, so the buyer holds a
    // signed document that cannot be priced.
    if let Some(attestation) = &config.attestation {
        if let Some(agreement_id) = &attestation.agreement_id {
            if agreement_id.trim().is_empty() {
                anyhow::bail!(
                    "origin {hostname}: attestation.agreement_id must be non-empty when set; \
                     omit the key to name no agreement"
                );
            }
        }
    }

    // WOR-1053: resolve the origin's declared tenant against the
    // `proxy.tenants[]` list. Absent declarations fall back to the
    // synthetic `__default__` tenant so existing single-tenant
    // configs keep working without a YAML change. The validator is
    // declared at the compile boundary so a typo at the operator's
    // YAML surfaces as a compile error rather than a silent
    // `__default__` stamp at request time.
    let tenant_id = config
        .tenant_id
        .as_ref()
        .map(|s| CompactString::new(s.as_str()))
        .unwrap_or_else(|| CompactString::const_new("__default__"));

    // Resolve the upstream transport deadlines to concrete durations here,
    // once, so `upstream_peer` reads plain `Duration`s off the compiled
    // origin instead of re-deriving defaults per request. Zero values and
    // the legacy-key conflict are rejected inside the resolver.
    let timeouts = resolve_upstream_timeouts(
        hostname,
        config.timeouts.as_ref(),
        config.connection_pool.as_ref(),
    )?;

    // WOR-2491: expand the `owasp_api_top10` pseudo-policy, if the
    // origin has one, into concrete synthesized policy entries, and
    // (task 3: api3's response half) transform entries, and (task 3:
    // api9) the origin-level `expose_openapi` flag. This mutates
    // `config.policies`/`config.transforms`/`config.expose_openapi` in
    // place: the pack entry itself is removed from `policies` (so it
    // never reaches `sbproxy-modules::compile.rs`'s type-string match
    // arms below), and any items with synthesis wired append to the
    // relevant list. Must run before `policy_configs`/`transform_configs`/
    // `expose_openapi` move or copy these fields into the compiled
    // origin below.
    //
    // Review round (WOR-2491, M1): read `config.action`'s own `type`
    // string here, before it moves into `action_config` below, so the
    // expander can tell whether this origin's action applies
    // response-phase policies. `api8`'s `security_headers` piece only
    // takes effect where that surface runs: Pingora's response filter
    // for proxied actions, and (WOR-2496) the generated-response
    // application in `action_dispatch.rs::handle_action` for
    // `static`/`mock`/`echo`/`beacon`/`redirect`. Actions with their
    // own protocol write paths (`mcp`, `noop`, `ai_proxy`, `storage`,
    // any plugin action) take neither, so synthesizing the piece
    // there would claim coverage nothing enforces. The allowlist is
    // `owasp_api_pack.rs::action_applies_response_phase_policies`,
    // pinned by its own drift-tie test.
    let action_type = config
        .action
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let owasp_pack_manifest = crate::owasp_api_pack::expand_owasp_pack(
        hostname,
        &mut config.policies,
        &mut config.transforms,
        &mut config.expose_openapi,
        action_type,
    )?;

    // Middleware blocks whose only previous defense was a runtime no-op.
    // Both run here, on the way into the compiled origin, so a broken
    // setting is a load-time error rather than a silently disabled
    // feature nothing reports.
    if let Some(cors) = config.cors.as_ref() {
        validate_origin_cors(hostname, cors)?;
    }
    if let Some(compression) = config.compression.as_ref() {
        validate_origin_compression(hostname, compression)?;
    }

    let mut compiled = CompiledOrigin {
        hostname: CompactString::new(hostname),
        origin_id: CompactString::new(hostname),
        // Filled in below, once every field the projection reads is in
        // place. Deriving it here would mean listing those fields
        // twice and letting the two copies drift.
        cache_config_fingerprint: CompactString::default(),
        workspace_id: CompactString::default(),
        tenant_id,
        action_config: config.action,
        auth_config: config.authentication,
        policy_configs: config.policies,
        transform_configs: config.transforms,
        filters: config.filters,
        cors: config.cors,
        hsts: config.hsts,
        compression: config.compression,
        session: config.session,
        properties: config.properties,
        sessions: config.sessions,
        user: config.user,
        force_ssl: config.force_ssl,
        allowed_methods,
        request_modifiers: config.request_modifiers.into_iter().collect(),
        response_modifiers: config.response_modifiers.into_iter().collect(),
        variables,
        // Snapshot stores forward rules as JSON because the runtime compiler
        // in sbproxy-core consumes the raw shape directly. Each `RawForwardRule`
        // round-trips cleanly because every field implements `Serialize`.
        forward_rules: config
            .forward_rules
            .into_iter()
            .map(|r| serde_json::to_value(r).expect("RawForwardRule serializes"))
            .collect(),
        fallback_origin: config.fallback_origin,
        error_pages: config.error_pages,
        problem_details: config.problem_details,
        proxy_status: config.proxy_status,
        // WOR-2565: compiled origin-scope deprecation announcement.
        deprecation,
        message_signatures: config.message_signatures,
        olp: config.olp,
        comp: config.comp,
        web_bot_auth_publish: config.web_bot_auth_publish,
        idempotency: config.idempotency,
        // Resolved upstream transport deadlines; see
        // `resolve_upstream_timeouts` above.
        timeouts,
        bot_detection: config.bot_detection,
        threat_protection: config.threat_protection,
        on_request: config.on_request,
        on_response: config.on_response,
        response_cache,
        mirror: config.mirror,
        extensions: config.extensions,
        expose_openapi: config.expose_openapi,
        stream_safety: config.stream_safety,
        // Wave 4 day-4 wire: synthesised `content_negotiate` config,
        // populated above when the origin has an `ai_crawl_control`
        // policy or one of the new content-shaping transforms.
        auto_content_negotiate,
        // Wave 4 / G4.5: validated content_signal interned to
        // &'static str so the response stamp path is allocation-free.
        content_signal,
        // Wave 4 / A4.2: per-origin token-bytes ratio for the Markdown
        // projection. None falls back to DEFAULT_TOKEN_BYTES_RATIO at
        // the call site.
        token_bytes_ratio,
        // WOR-193: per-origin Agent Skills v0.2.0 advertisement.
        agent_skills: config.agent_skills,
        // WOR-809: agent-web emission bodies served verbatim.
        agents_md: config.agents_md,
        ai_txt: config.ai_txt,
        // WOR-820: agents.json manifest config.
        agents_json: config.agents_json,
        // WOR-802: outbound credential resolver config (JSON; compiled
        // in sbproxy-core).
        outbound_credential: config.outbound_credential,
        // WOR-805: opt-in for outbound Web Bot Auth signing.
        outbound_web_bot_auth: config.outbound_web_bot_auth,
        // WOR-2127: per-origin attestation role override + agreement id.
        // Shape-checked above; the cross-block requirement (there has to
        // be a `proxy.attestation` for this to mean anything) is checked
        // in `compile_config`, which can see both.
        attestation: config.attestation,
        // WOR-1043 PR3: origin-scope observability overrides.
        observability: config.observability,
        // WOR-2491: computed above, before `config.policies` moved
        // into `policy_configs`.
        owasp_pack_manifest,
    };

    // WOR-2407: name the config this origin's cached entries belong to,
    // so a shared store cannot hand them to a node running a different
    // one. Computed once, here; the request path only reads it.
    compiled.cache_config_fingerprint = crate::cache_identity::origin_cache_fingerprint(&compiled);

    Ok(compiled)
}

/// Returns true when the JSON value's `type` field equals `wanted`.
///
/// Used by [`compile_origin`] to walk anonymous policy / transform
/// configs without compiling them first. Keeps the auto-prepend
/// detection cheap (no full deserialise).
fn config_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s == wanted)
        .unwrap_or(false)
}

fn policy_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    config_type_is(value, wanted)
}

fn transform_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    config_type_is(value, wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn compile_rejects_invalid_inbound_key_config_even_when_disabled() {
        for carrier_yaml in [
            "headers:\n        - name: x-sb-property-credential",
            "headers: []\n      provider_hints:\n        - provider: custom\n          header: x-sb-user-id",
        ] {
            let yaml = format!(
                "proxy:\n  key_management:\n    enabled: false\n    inbound:\n      {carrier_yaml}\n"
            );
            let error = compile_config(&yaml)
                .err()
                .expect("compile must run inbound credential validation");
            assert!(
                format!("{error:#}").contains("may not carry a key"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn compile_rejects_a_config_history_keep_below_one() {
        let yaml = "proxy:\n  config_history:\n    keep: 0\n";
        let error = compile_config(yaml)
            .err()
            .expect("compile must run config_history validation");
        assert!(
            format!("{error:#}").contains("proxy.config_history.keep must be at least 1"),
            "{error:#}"
        );
    }

    #[test]
    fn compile_rejects_primary_carriers_that_collide_with_correlation_ids() {
        for (correlation_yaml, inbound_yaml) in [
            (
                "",
                "headers:\n        - name: X-Request-Id\n          scheme: ''\n      provider_hints: []",
            ),
            (
                "  correlation_id:\n    header: X-Custom-Correlation\n",
                "headers: []\n      provider_hints:\n        - provider: custom\n          header: x-custom-correlation",
            ),
        ] {
            let yaml = format!(
                "proxy:\n{correlation_yaml}  key_management:\n    enabled: false\n    inbound:\n      {inbound_yaml}\n"
            );
            let error = compile_config(&yaml)
                .err()
                .expect("correlation IDs must not carry credentials");
            let message = format!("{error:#}");
            assert!(message.contains("correlation_id"), "{message}");
            assert!(message.contains("credential"), "{message}");
        }
    }

    #[test]
    fn compile_allows_reserved_match_metadata_and_disabled_correlation() {
        let yaml = r#"
proxy:
  correlation_id:
    enabled: false
    header: X-Custom-Correlation
  key_management:
    enabled: false
    inbound:
      headers:
        - name: X-Custom-Correlation
          scheme: ""
      provider_hints:
        - provider: custom
          header: X-Opaque-Credential
          also_header: X-Sb-User-Id
"#;
        compile_config(yaml)
            .expect("disabled correlation and non-carrier metadata must remain valid");
    }

    // --- WOR-2136: the dead tag + body-aware combination ---

    #[test]
    fn compile_rejects_tag_with_body_aware_on_a_plain_proxy_origin() {
        let yaml = r#"
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        action: tag
        enable_body_aware: true
"#;
        let error = compile_config(yaml)
            .err()
            .expect("tag + body-aware on a proxy origin must not compile");
        let message = format!("{error:#}");
        assert!(message.contains("enable_body_aware"), "{message}");
        assert!(
            message.contains("already assembled by the time the body is read"),
            "{message}"
        );
        assert!(
            message.contains("`action: block` or `action: log`"),
            "{message}"
        );
    }

    #[test]
    fn compile_rejects_the_default_tag_with_body_aware_too() {
        // `tag` is the default action, so omitting the key is the same
        // dead combination; the message names the default explicitly.
        let yaml = r#"
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        enable_body_aware: true
"#;
        let error = compile_config(yaml)
            .err()
            .expect("the default action is tag, so this must not compile either");
        assert!(format!("{error:#}").contains("(the default)"), "{error:#}");
    }

    #[test]
    fn compile_allows_the_live_prompt_injection_combinations() {
        // tag without body-aware: the URI + header scan can stamp.
        // block with body-aware: a body hit rejects, which works.
        for policy_yaml in [
            "action: tag",
            "action: block\n        enable_body_aware: true",
            "action: log\n        enable_body_aware: true",
        ] {
            let yaml = format!(
                r#"
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        {policy_yaml}
"#
            );
            compile_config(&yaml)
                .unwrap_or_else(|error| panic!("`{policy_yaml}` must stay compilable: {error:#}"));
        }
    }

    #[test]
    fn compile_allows_tag_with_body_aware_on_an_ai_proxy_origin() {
        // The ai_proxy path reads the body before dispatch and can tag,
        // so the combination is live there and must keep compiling.
        let yaml = r#"
origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        action: tag
        enable_body_aware: true
"#;
        compile_config(yaml).expect("tag + body-aware is live on ai_proxy origins");
    }

    #[test]
    fn compile_allows_tag_with_body_aware_when_enforcement_block_overrides_the_flavor() {
        // `enforcement: block` forces every hit to refuse, so the tag
        // flavor never manifests and the combination is not dead.
        // Refusing it would be a compile-time detector narrower than
        // the runtime it guards.
        let yaml = r#"
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        action: tag
        enforcement: block
        enable_body_aware: true
"#;
        compile_config(yaml)
            .expect("enforcement: block makes the tag + body-aware combination live");
    }

    #[test]
    fn compile_still_rejects_tag_with_body_aware_under_enforcement_observe() {
        // Under `enforcement: observe` the tag flavor is exactly what a
        // hit resolves to, so the dead combination is still dead.
        let yaml = r#"
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: prompt_injection_v2
        detector: heuristic-v1
        action: tag
        enforcement: observe
        enable_body_aware: true
"#;
        let error = compile_config(yaml)
            .err()
            .expect("observe keeps the tag flavor, so this must not compile");
        assert!(
            format!("{error:#}").contains("enable_body_aware"),
            "{error:#}"
        );
    }

    #[test]
    fn a_body_reading_policy_on_a_static_origin_warns_at_compile() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // Counts compile-time warnings that name the request_body_filter
        // gap, so the assertion cannot pass on an unrelated warning.
        struct WarnCounter(Arc<AtomicUsize>);

        impl tracing::Subscriber for WarnCounter {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                metadata.target().starts_with("sbproxy_config")
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                struct SeenGapMessage(bool);
                impl tracing::field::Visit for SeenGapMessage {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message"
                            && format!("{value:?}").contains("request_body_filter never runs")
                        {
                            self.0 = true;
                        }
                    }
                }
                if *event.metadata().level() == tracing::Level::WARN {
                    let mut visitor = SeenGapMessage(false);
                    event.record(&mut visitor);
                    if visitor.0 {
                        self.0.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let yaml = r#"
origins:
  "static.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_validator
        schema:
          type: object
"#;
        let warnings = Arc::new(AtomicUsize::new(0));
        let compiled =
            tracing::subscriber::with_default(WarnCounter(Arc::clone(&warnings)), || {
                compile_config(yaml)
            });
        compiled.expect("a body-reading policy on a static origin compiles; it only warns");
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            1,
            "the static + body-reading combination must warn exactly once"
        );
    }

    /// Counts compile-time warnings that name the header-sourced
    /// `object_authz` owner, so the assertion cannot pass on an
    /// unrelated warning (WOR-2316).
    fn object_authz_header_warnings_for(yaml: &str) -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct OwnerHeaderWarnCounter(Arc<AtomicUsize>);

        impl tracing::Subscriber for OwnerHeaderWarnCounter {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                metadata.target().starts_with("sbproxy_config")
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                struct SeenOwnerHeaderMessage(bool);
                impl tracing::field::Visit for SeenOwnerHeaderMessage {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            let text = format!("{value:?}");
                            if text.contains("object_authz reads the object owner from")
                                && text.contains("assert ownership")
                            {
                                self.0 = true;
                            }
                        }
                    }
                }
                if *event.metadata().level() == tracing::Level::WARN {
                    let mut visitor = SeenOwnerHeaderMessage(false);
                    event.record(&mut visitor);
                    if visitor.0 {
                        self.0.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let warnings = Arc::new(AtomicUsize::new(0));
        let compiled = tracing::subscriber::with_default(
            OwnerHeaderWarnCounter(Arc::clone(&warnings)),
            || compile_config(yaml),
        );
        compiled.expect("object_authz compiles either way; the header source only warns");
        warnings.load(Ordering::Relaxed)
    }

    /// WOR-2316: sourcing the owner from a request header is an
    /// authorization bypass unless an ingress strips that header, and
    /// the config cannot tell whether one exists. It stays legal and
    /// gets one loud warning naming the origin.
    #[test]
    fn header_sourced_object_authz_owner_warns_once_at_compile() {
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    policies:
      - type: object_authz
        principal:
          owner_from: header
          owner_header: x-owner-id
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
"#;
        assert_eq!(
            object_authz_header_warnings_for(yaml),
            1,
            "a header-sourced owner must warn exactly once"
        );
    }

    /// The secure default must stay quiet, or the warning becomes noise
    /// operators learn to skip past (WOR-2316).
    #[test]
    fn subject_sourced_object_authz_owner_does_not_warn() {
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    policies:
      - type: object_authz
        principal:
          owner_from: sub
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
"#;
        assert_eq!(
            object_authz_header_warnings_for(yaml),
            0,
            "the verified-subject default must not warn"
        );

        let omitted = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    policies:
      - type: object_authz
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
"#;
        assert_eq!(
            object_authz_header_warnings_for(omitted),
            0,
            "an omitted principal block is the secure default and must not warn"
        );
    }

    #[test]
    fn top_level_feature_flags_compile_into_the_runtime_snapshot() {
        let compiled = compile_config(
            r#"
flags:
  - name: new-checkout
    default: false
    rules:
      allow_list: [alice]
      block_list: [mallory]
      rollout_percent: 25
"#,
        )
        .expect("top-level flags should compile");

        assert_eq!(compiled.flags.len(), 1);
        let flag = &compiled.flags[0];
        assert_eq!(flag.name, "new-checkout");
        assert!(!flag.default);
        assert_eq!(flag.rules.allow_list, ["alice"]);
        assert_eq!(flag.rules.block_list, ["mallory"]);
        assert_eq!(flag.rules.rollout_percent, 25);
    }

    #[test]
    fn duplicate_top_level_feature_flag_names_fail_compile() {
        let error = compile_config(
            r#"
flags:
  - name: new-checkout
    default: true
  - name: new-checkout
    default: false
"#,
        )
        .err()
        .expect("duplicate flag names must be rejected");

        let message = format!("{error:#}");
        assert!(message.contains("duplicate"), "{message}");
        assert!(message.contains("new-checkout"), "{message}");
    }

    #[test]
    fn feature_flag_rollout_percent_must_be_at_most_one_hundred() {
        let error = compile_config(
            r#"
flags:
  - name: impossible-rollout
    rules:
      rollout_percent: 101
"#,
        )
        .err()
        .expect("an out-of-range rollout must be rejected");

        let message = format!("{error:#}");
        assert!(message.contains("impossible-rollout"), "{message}");
        assert!(message.contains("0..=100"), "{message}");
    }

    #[test]
    fn feature_flag_segments_are_rejected_until_cel_accepts_a_segment() {
        let error = compile_config(
            r#"
flags:
  - name: segment-only
    rules:
      segments: [beta]
"#,
        )
        .err()
        .expect("an unread segment rule must be rejected");

        let message = format!("{error:#}");
        assert!(message.contains("segments"), "{message}");
        assert!(message.contains("unknown field"), "{message}");
    }

    fn custom_field(
        name: &str,
        value: Option<&str>,
        engine: Option<&str>,
        source: Option<&str>,
    ) -> crate::CustomLogFieldConfig {
        crate::CustomLogFieldConfig {
            name: name.to_string(),
            value: value.map(str::to_string),
            engine: engine.map(str::to_string),
            source: source.map(str::to_string),
        }
    }

    // WOR-1818: `${VAR:-default}` resolves with shell semantics.
    #[test]
    fn env_interpolation_supports_shell_defaults() {
        let _env = crate::test_env::EnvVarGuard::set(&[
            ("SBPROXY_TEST_UNSET_XYZ", None),
            ("SBPROXY_TEST_SET_XYZ", Some("live")),
        ]);
        assert_eq!(
            interpolate_env_vars("a ${SBPROXY_TEST_UNSET_XYZ:-fallback} b"),
            "a fallback b"
        );
        assert_eq!(
            interpolate_env_vars("a ${SBPROXY_TEST_SET_XYZ:-fallback} b"),
            "a live b"
        );
        // No default: unresolved stays literal for the hazard scan.
        assert_eq!(
            interpolate_env_vars("a ${SBPROXY_TEST_UNSET_XYZ} b"),
            "a ${SBPROXY_TEST_UNSET_XYZ} b"
        );
    }

    // WOR-2489: an `args.`/`steps.` placeholder is MCP runtime
    // interpolation vocabulary (`${args.id}`, `${steps.fetch.body.x}`),
    // not an env reference. It must survive the pre-parse substitution
    // byte-for-byte even when a same-named process variable exists.
    #[test]
    fn mcp_vocabulary_placeholder_survives_interpolation_even_with_a_colliding_env_var() {
        let _env = crate::test_env::EnvVarGuard::set(&[
            ("args.user_id", Some("spliced-from-env-would-be-a-bug")),
            ("SBPROXY_TEST_SET_XYZ", Some("live")),
        ]);
        assert_eq!(interpolate_env_vars("${args.user_id}"), "${args.user_id}");
        // A dotted name with a `:-` default is still not an env
        // reference; the whole placeholder, default included, stays.
        assert_eq!(
            interpolate_env_vars("${steps.fetch.body.x:-fallback}"),
            "${steps.fetch.body.x:-fallback}"
        );
        // A real env reference in the same string still resolves.
        assert_eq!(
            interpolate_env_vars("${SBPROXY_TEST_SET_XYZ}/${args.user_id}"),
            "live/${args.user_id}"
        );
    }

    // WOR-2489: the hazard scan must not report an `args.`/`steps.`
    // placeholder as an unresolved env reference. Before the carve-out,
    // a `type: local` MCP tool carrying `${args.user_id}` in its
    // `http.url` produced a misleading boot warning, and the
    // config-authority subscriber refused any bundle carrying it
    // fleet-wide (config_subscriber.rs's hard-refusal path).
    #[test]
    fn mcp_vocabulary_placeholders_are_not_reported_as_unresolved_env_references() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      server_info: {name: dotted-fixture, version: "1.0.0"}
      federated_servers:
        - type: local
          origin: local.internal
          prefix: dotted-local
          egress: {mode: enforce, hosts: [api.internal]}
          tools:
            - name: fetch
              description: dotted placeholder fixture
              input_schema: {type: object, properties: {}}
              http:
                method: GET
                url: "https://api.internal/items/${args.user_id}?v=${steps.fetch.body.x}"
"#;
        assert_eq!(
            unresolved_env_references(yaml),
            Vec::<String>::new(),
            "args./steps. placeholders are MCP runtime vocabulary, not env references"
        );
        // The config also compiles (the executor, not the env layer,
        // owns those placeholders from here on).
        compile_config(yaml).expect("a local tool with dotted placeholders compiles");

        // A genuine `${VAR}` miss is still reported exactly as before.
        let missing = r#"
proxy:
  http_bind_port: 8080
origins:
  "mcp.example.com":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "${SBPROXY_TEST_UNSET_REVIEW_TOKEN}"
"#;
        let refs = unresolved_env_references(missing);
        assert_eq!(refs.len(), 1, "got: {refs:?}");
        assert!(
            refs[0].contains("${SBPROXY_TEST_UNSET_REVIEW_TOKEN}"),
            "got: {refs:?}"
        );
    }

    // Phase-2 review: the access-log `custom_fields` bare-name
    // vocabulary (docs/access-log.md; `custom_log.rs`'s `resolve_var`)
    // is per-request interpolation, not env references. Before this
    // fix, the shipped example `value: "${tenant_id}"` was reported as
    // an unresolved env reference, so a config authority refused the
    // bundle fleet-wide - and exporting the named variable made it
    // worse by baking a boot-time constant into a per-request field.
    #[test]
    fn access_log_bare_names_survive_interpolation_and_are_not_reported() {
        let _env = crate::test_env::EnvVarGuard::set(&[
            ("tenant_id", Some("spliced-from-env-would-be-a-bug")),
            ("path", Some("also-a-bug")),
            ("method", None),
        ]);
        for name in ACCESS_LOG_BARE_VARS {
            let placeholder = format!("${{{name}}}");
            assert_eq!(
                interpolate_env_vars(&placeholder),
                placeholder,
                "bare access-log name {name} must survive pre-parse interpolation"
            );
        }
        // The hazard scan does not report them either, so a config
        // authority no longer refuses the documented example.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      custom_fields:
        - name: tenant
          value: "${tenant_id}"
        - name: m
          value: "${method}"
"#;
        assert_eq!(
            unresolved_env_references(yaml),
            Vec::<String>::new(),
            "access-log bare names are per-request vocabulary, not env references"
        );
        // A `:-` default keeps env semantics: `resolve_var` has no
        // default syntax, so this form was never access-log vocabulary
        // and its v1.12 shell-default treatment is preserved.
        assert_eq!(interpolate_env_vars("${method:-GET}"), "GET");
    }

    // v1.13.0 phase-2 review: the WOR-2489 carve-out must be scoped to
    // the MCP local-tool vocabulary (an `args.` or `steps.` root), not
    // to "any name containing a dot". A dotted name outside that
    // vocabulary is a plain env reference: resolution is attempted,
    // `:-` defaults work, and a miss stays literal for the hazard scan.
    #[test]
    fn non_mcp_dotted_placeholder_gets_env_resolution_and_defaults() {
        let _env = crate::test_env::EnvVarGuard::set(&[
            ("dotted.name", None),
            ("otel.endpoint", Some("https://collector.internal:4317")),
        ]);
        // `${dotted.name:-default}` keeps its v1.12 shell semantics.
        assert_eq!(interpolate_env_vars("${dotted.name:-default}"), "default");
        // A set dotted variable resolves; the pass attempts the lookup
        // rather than skipping the placeholder.
        assert_eq!(
            interpolate_env_vars("${otel.endpoint}"),
            "https://collector.internal:4317"
        );
        // Unset with no default: literal, so the hazard scan reports it.
        assert_eq!(interpolate_env_vars("${dotted.name}"), "${dotted.name}");
    }

    // v1.13.0 phase-2 review: a dotted name outside the MCP vocabulary
    // must be REPORTED unresolved, because `unresolved_env_references`
    // is the predicate the config-authority subscriber uses to refuse a
    // bundle. With the global dotted carve-out, `${secret.OPENAI_KEY}`
    // applied fleet-wide as literal text with nothing logged.
    #[test]
    fn non_mcp_dotted_placeholder_is_reported_as_unresolved() {
        let _env = crate::test_env::EnvVarGuard::set(&[("secret.OPENAI_KEY", None)]);
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "${secret.OPENAI_KEY}"
"#;
        let refs = unresolved_env_references(yaml);
        assert_eq!(refs.len(), 1, "got: {refs:?}");
        assert!(refs[0].contains("${secret.OPENAI_KEY}"), "got: {refs:?}");
    }

    // docs/mcp-compose.md documents `$$` as the escape that renders a
    // literal `${...}` at MCP call time. The pre-parse env layer must
    // honor it: before this fix, `$${OPENAI_API_KEY}` had the live
    // value spliced into the config text at compile time -- the exact
    // leak the escape exists to prevent. The env layer strips nothing;
    // the MCP engine (mcp_interpolate.rs) owns the `$$` unescape.
    #[test]
    fn escaped_placeholder_survives_env_interpolation() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "OPENAI_API_KEY",
            Some("sk-live-splice-would-leak"),
        )]);
        // `$${...}`: escaped. Byte-for-byte untouched, value never read.
        assert_eq!(
            interpolate_env_vars("$${OPENAI_API_KEY}"),
            "$${OPENAI_API_KEY}"
        );
        // `$$$...`: one escaped `$` pair, then a LIVE placeholder --
        // the same greedy pair-parity rule the MCP engine's scanner
        // applies.
        assert_eq!(
            interpolate_env_vars("$$${OPENAI_API_KEY}"),
            "$$sk-live-splice-would-leak"
        );
        // `$$` not followed by `{` stays what it always was.
        assert_eq!(interpolate_env_vars("cost: $$5"), "cost: $$5");
    }

    // The escape must also silence the hazard scan (an escaped
    // placeholder never opens, so there is nothing unresolved), and the
    // untouched bytes must reach the compiled config for the runtime
    // consumer to unescape.
    #[test]
    fn escaped_placeholder_reaches_the_compiled_config_and_is_not_reported() {
        let _env = crate::test_env::EnvVarGuard::set(&[
            ("OPENAI_API_KEY", Some("sk-live-splice-would-leak")),
            ("SBPROXY_TEST_UNSET_ESCAPED", None),
        ]);
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "key=$${OPENAI_API_KEY} other=$${SBPROXY_TEST_UNSET_ESCAPED}"
"#;
        // Neither the set-variable nor the unset-variable escape is an
        // unresolved reference, so a config authority does not refuse
        // the bundle over the escape.
        assert_eq!(
            unresolved_env_references(yaml),
            Vec::<String>::new(),
            "escaped placeholders are not env references"
        );
        let compiled = compile_config(yaml).expect("escaped placeholders compile");
        assert_eq!(
            compiled.origins[0].action_config["body"],
            serde_json::json!("key=$${OPENAI_API_KEY} other=$${SBPROXY_TEST_UNSET_ESCAPED}"),
            "the escape bytes reach the compiled config untouched"
        );
    }

    // WOR-1817: custom YAML tags are stripped by the parser, so
    // `password: !env ADMIN_PASSWORD` silently becomes the literal
    // string "ADMIN_PASSWORD". Any tag must fail the compile with a
    // pointer at ${VAR} interpolation.
    #[test]
    fn unknown_yaml_tag_fails_compile() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    username: admin
    password: !env ADMIN_PASSWORD
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let err = compile_config(yaml)
            .err()
            .expect("custom YAML tag must fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("!env") && msg.contains("${VAR}"),
            "error must name the tag and point at interpolation: {msg}"
        );
        assert!(
            msg.contains("proxy.admin.password"),
            "error must locate the tagged value: {msg}"
        );
    }

    #[test]
    fn admin_rate_limit_defaults_to_60() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    username: admin
    password: secret
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let admin = compiled.server.admin.as_ref().expect("admin block");
        assert_eq!(admin.rate_limit_per_minute, 240);
    }

    #[test]
    fn admin_rate_limit_out_of_range_is_rejected() {
        for bad in ["0", "100001"] {
            let yaml = format!(
                r#"
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    username: admin
    password: secret
    rate_limit_per_minute: {bad}
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#
            );
            let err = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("rate_limit_per_minute {bad} must fail compile"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("rate_limit_per_minute") && msg.contains("between 1 and"),
                "error must name the field and its range: {msg}"
            );
        }
    }

    #[test]
    fn admin_rate_limit_in_range_value_is_kept() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    username: admin
    password: secret
    rate_limit_per_minute: 500
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let admin = compiled.server.admin.as_ref().expect("admin block");
        assert_eq!(admin.rate_limit_per_minute, 500);
    }

    /// Build a config with an admin block whose body is `body`, so the
    /// default-credential tests differ only in the lines under test.
    fn admin_config_yaml(body: &str) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
{body}
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#
        )
    }

    #[test]
    fn default_admin_credentials_off_loopback_bind_are_refused() {
        let yaml =
            admin_config_yaml("    bind: 0.0.0.0\n    username: admin\n    password: changeme");
        let err = compile_config(&yaml)
            .err()
            .expect("default credentials on a wide bind must fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("proxy.admin.password") && msg.contains("shipped default"),
            "error must name the credential: {msg}"
        );
        assert!(
            msg.contains("proxy.admin.bind is `0.0.0.0`"),
            "error must name the condition that tripped: {msg}"
        );
        assert!(
            msg.contains("Set a real password"),
            "error must say what to do: {msg}"
        );
    }

    #[test]
    fn default_admin_credentials_with_wide_allow_ips_are_refused() {
        // Loopback bind, but the allowlist admits a whole private range,
        // so the surface is reachable from other hosts on that network.
        let yaml = admin_config_yaml(
            "    bind: 127.0.0.1\n    password: changeme\n    allow_ips: [\"127.0.0.1\", \"10.0.0.0/8\"]",
        );
        let err = compile_config(&yaml)
            .err()
            .expect("default credentials with a wide allow_ips must fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("proxy.admin.allow_ips admits peers outside loopback (10.0.0.0/8)"),
            "error must name the offending entry, and only that entry: {msg}"
        );
        assert!(
            msg.contains("Set a real password"),
            "error must say what to do: {msg}"
        );
    }

    #[test]
    fn default_admin_credentials_on_loopback_still_compile() {
        // The local-development path. Both the implicit default bind and
        // an explicit loopback bind (with a loopback-only allowlist) stay
        // valid with the shipped credentials.
        for body in [
            "    username: admin\n    password: changeme",
            "    bind: 127.0.0.1\n    password: changeme",
            "    bind: \"::1\"\n    password: changeme",
            "    password: changeme\n    allow_ips: [\"127.0.0.0/8\", \"::1\"]",
        ] {
            let yaml = admin_config_yaml(body);
            compile_config(&yaml)
                .unwrap_or_else(|e| panic!("loopback default credentials must compile: {e:#}"));
        }
    }

    #[test]
    fn real_admin_password_off_loopback_compiles() {
        let yaml = admin_config_yaml(
            "    bind: 0.0.0.0\n    username: admin\n    password: not-the-default\n    allow_ips: [\"10.0.0.0/8\"]",
        );
        let compiled = compile_config(&yaml)
            .unwrap_or_else(|e| panic!("a real password off loopback must compile: {e:#}"));
        let admin = compiled.server.admin.as_ref().expect("admin block");
        assert_eq!(admin.bind.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn unparseable_admin_bind_is_refused() {
        for bad in ["0.0.0..1", "localhost", "127.0.0.1:9090", ""] {
            let yaml = admin_config_yaml(&format!(
                "    bind: \"{bad}\"\n    password: not-the-default"
            ));
            let err = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("bind `{bad}` must fail compile"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("proxy.admin.bind") && msg.contains("not an IP address"),
                "error must name the field and the reason: {msg}"
            );
        }
    }

    #[test]
    fn admin_allow_entry_loopback_classification() {
        for loopback in [
            "127.0.0.1",
            " 127.0.0.1 ",
            "127.0.0.1/32",
            "127.0.0.0/8",
            "::1",
            "::1/128",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                admin_allow_entry_is_loopback_only(loopback),
                "{loopback} is loopback-only"
            );
        }
        for reachable in [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "192.168.1.50",
            // Spans 126.0.0.0 upward, so it is not inside 127.0.0.0/8.
            "127.0.0.0/7",
            "::/0",
            "not-an-address",
        ] {
            assert!(
                !admin_allow_entry_is_loopback_only(reachable),
                "{reachable} reaches beyond loopback"
            );
        }
    }

    #[test]
    fn http3_enabled_is_rejected_because_it_is_not_served() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  http3:
    enabled: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;

        let error = compile_config(yaml)
            .err()
            .expect("proxy.http3.enabled=true must fail config compilation");
        let message = format!("{error:#}");
        assert!(
            message.contains("proxy.http3.enabled")
                && message.contains("not served")
                && message.contains("WOR-2310"),
            "error must name the unsupported setting, explain that it is not served, and point \
             to the implementation ticket: {message}"
        );
    }

    #[test]
    fn http3_explicitly_disabled_remains_valid() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  http3:
    enabled: false
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;

        let compiled = compile_config(yaml).expect("disabled HTTP/3 config remains valid");
        assert_eq!(
            compiled.server.http3.as_ref().map(|config| config.enabled),
            Some(false)
        );
    }

    #[test]
    fn http3_omitted_remains_valid() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;

        let compiled = compile_config(yaml).expect("omitted HTTP/3 config remains valid");
        assert!(compiled.server.http3.is_none());
    }

    /// Minimal `tracing::Subscriber` that records the `config_key` field
    /// of every event, regardless of level or target. Proves the boot
    /// warning in `compile_config` (above) actually fires as a `tracing`
    /// event, not just that `key_registry::configured_config_only_keys`
    /// returns the right entries in isolation.
    struct ConfigOnlyWarningCapture {
        keys: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for ConfigOnlyWarningCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        /// Deliberately `sometimes`, never `always`: `tracing` caches one
        /// `Interest` per callsite for the whole process, and the boot
        /// warning's callsite is shared with every other `compile_config`
        /// test running in parallel on other threads. `sometimes` forces
        /// `tracing` to call `enabled` on the *emitting* thread for every
        /// event, so this capture answers only for its own thread and the
        /// cached value can never go stale in either direction.
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        /// Keeps the process-wide max-level hint at `TRACE` while this
        /// subscriber is registered, so `tracing::warn!`'s static level
        /// fast path (`LevelFilter::current()`) cannot filter the event
        /// before interest is even consulted.
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Visitor<'a>(&'a mut Option<String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "config_key" {
                        *self.0 = Some(value.to_string());
                    }
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "config_key" {
                        *self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut key = None;
            event.record(&mut Visitor(&mut key));
            if let Some(key) = key {
                self.keys.lock().unwrap().push(key);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// A registered-but-silent subscriber whose only job is to keep
    /// `tracing`'s global callsite-interest cache honest for the capture
    /// above. It is never installed as anyone's default; it exists purely
    /// as a second entry in the process-wide dispatcher list.
    ///
    /// Why this is needed (tracing-core 0.1.36):
    ///
    /// * `Dispatchers::rebuilder` takes a "just one dispatcher" fast path
    ///   whenever at most one dispatcher is registered
    ///   (`callsite.rs:544-549`), and that path computes a callsite's
    ///   interest from *the calling thread's* default subscriber
    ///   (`callsite.rs:561-573`). On any sibling test thread that default
    ///   is `NoSubscriber`, whose `register_callsite` returns
    ///   `Interest::never()` (`subscriber.rs:676-678`). The result is
    ///   written to the one process-wide cache slot
    ///   (`callsite.rs:505-506`), and a callsite registers exactly once
    ///   (`callsite.rs:308-321`), so the first sibling thread to reach the
    ///   boot warning wins and disables it for *every* thread, this test
    ///   included. Registering a second dispatcher turns the fast path off
    ///   and forces interest to be computed from the live dispatcher list,
    ///   which contains the capture above.
    /// * The pin hints `LevelFilter::OFF`, which matters for ordering:
    ///   `MAX_LEVEL` starts at `OFF` (`metadata.rs:245`) so no thread can
    ///   reach a callsite at all until some dispatcher raises it. Because
    ///   the pin keeps it at `OFF`, the door stays shut until the capture
    ///   registers, and `register_dispatch` clears `has_just_one` before
    ///   `rebuild_interest` raises the max level (`callsite.rs:484-488`,
    ///   `551-557`, `407-421`) -- so there is no window in which a sibling
    ///   thread can poison the cache.
    struct InterestPin;

    impl tracing::Subscriber for InterestPin {
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::never()
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::OFF)
        }
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            false
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, _event: &tracing::Event<'_>) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// This exemplar has now been promoted out from under the test twice:
    /// first `proxy.device_parser_file`, then `cors.enable`, each of which
    /// became a compile error once someone looked at what it did. That is
    /// the sweep working, but it means the exemplar has to be a key that is
    /// inert **and** harmless, not merely inert.
    ///
    /// `proxy.observability.log.sampling.debug` qualifies. The process
    /// logger has no sampling call site at all, so the rate changes
    /// nothing, but a rate that fails open emits more lines rather than
    /// fewer. Nobody is misled about a security property, so a warning is
    /// proportionate and the key stays accepted. Refusal is reserved for
    /// keys that describe the build wrongly, which is why the previous two
    /// exemplars left.
    #[test]
    fn compile_config_warns_when_an_operator_sets_a_config_only_key() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      sampling:
        debug: 0.5
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        // Register the pin BEFORE the capture and keep it alive for the
        // whole test: with two dispatchers registered, `tracing` computes
        // this callsite's interest from the dispatcher list (which holds
        // the capture) instead of from whichever thread happens to hit the
        // callsite first. See `InterestPin` for the file:line evidence.
        // Dropping the pin early would re-arm the fast path, so it must
        // outlive the `with_default` scope below (hence the explicit
        // `drop` after it, rather than an `_`-bound temporary).
        let pin = tracing::dispatcher::Dispatch::new(InterestPin);

        let keys = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = ConfigOnlyWarningCapture { keys: keys.clone() };
        tracing::subscriber::with_default(subscriber, || {
            // Repair, don't rely: if some other dispatcher elsewhere in the
            // process had already cached this callsite as `never` before the
            // pin existed, this recomputes it. With the pin registered the
            // rebuild reads the live dispatcher list, so the recomputed
            // value is honest regardless of which thread runs it.
            tracing::callsite::rebuild_interest_cache();
            compile_config(yaml).expect("log sampling is config-only, not a compile error");
        });
        drop(pin);

        assert_eq!(
            keys.lock().unwrap().as_slice(),
            ["proxy.observability.log.sampling.debug"],
            "compile_config must warn once for the explicitly-set config-only key"
        );
    }

    /// A typo'd event label has to fail the compile. Dropping it leaves
    /// an operator believing they have an audit trail, and an audit feed
    /// that emits nothing looks exactly like one with nothing to report,
    /// so nothing downstream can find the mistake either.
    #[test]
    fn decision_audit_refuses_an_unknown_event_label() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
        events:
          cache.admision: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let error = compile_config(yaml)
            .err()
            .expect("an unknown decision event label must fail the compile");
        let message = format!("{error:#}");
        assert!(message.contains("`cache.admision`"), "{message}");
        // The accepted set is listed, so the operator does not have to
        // guess which spelling was wanted.
        assert!(message.contains("cache.admit"), "{message}");
        assert!(message.contains("route.decide"), "{message}");
        assert!(message.contains("payment.lifecycle"), "{message}");
    }

    /// `ai.stream.event` fires once per streamed chunk, so a per-event
    /// audit record on it is an ingest bill rather than a control. The
    /// refusal names `ai.close`, which carries the same stream's summary
    /// once, so the operator gets the record they were after.
    #[test]
    fn decision_audit_refuses_the_per_chunk_stream_event() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
        events:
          ai.stream.event: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let error = compile_config(yaml)
            .err()
            .expect("ai.stream.event must not be enable-able as a per-event audit feed");
        let message = format!("{error:#}");
        assert!(message.contains("ai.stream.event"), "{message}");
        assert!(message.contains("per streamed chunk"), "{message}");
        assert!(message.contains("ai.close"), "{message}");
    }

    /// The valid shape compiles: a known label turned on, and the
    /// per-chunk event turned explicitly off. Writing a feed's `false`
    /// down is a reasonable thing for an operator to do, so only the
    /// `true` is refused.
    #[test]
    fn decision_audit_accepts_a_known_event_and_an_explicit_off() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
        events:
          cache.admit: true
          ai.stream.event: false
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        compile_config(yaml).expect("a known event label with a boolean toggle must compile");
    }

    #[test]
    fn a_tenant_scope_decision_audit_is_validated_too() {
        // The proxy-scope guard alone would let a tenant write the typo
        // the proxy block is refused for.
        let err = compile_config(
            r#"
proxy:
  http_bind_port: 8080
  tenants:
    - id: acme-corp
      observability:
        log:
          decision_audit:
            events:
              cache.admitt: true
origins:
  "api.example.test":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#,
        )
        .err()
        .expect("a tenant-scope typo must fail the load");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("acme-corp") && msg.contains("cache.admitt"),
            "the refusal names the tenant and the bad label: {msg}"
        );
    }

    #[test]
    fn an_origin_scope_decision_audit_composes_and_is_validated() {
        let compiled = compile_config(
            r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        events:
          cache.admit: true
origins:
  "api.example.test":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    observability:
      log:
        decision_audit:
          events:
            route.decide: true
"#,
        )
        .unwrap_or_else(|e| panic!("scoped blocks must compile: {e:#}"));
        let scopes = &compiled.decision_audit;
        assert!(
            scopes.publishes("route.decide", None, Some("api.example.test")),
            "the origin's own entry applies to it"
        );
        assert!(
            scopes.publishes("cache.admit", None, Some("api.example.test")),
            "and it inherits the proxy entry it said nothing about"
        );
    }

    /// Validating the block is not the same as delivering it. The
    /// request path reads `CompiledConfig.decision_audit`, so a config
    /// that parses and validates but never reaches the snapshot is a
    /// feed the operator configured and no decision point can see.
    #[test]
    fn decision_audit_reaches_the_compiled_snapshot() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        events:
          cache.admit: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("a per-event decision audit toggle compiles");
        let audit = compiled
            .decision_audit
            .proxy
            .as_ref()
            .expect("an authored decision_audit block must reach the snapshot");
        // The per-event entry carries this on its own: the master switch
        // is unset, so anything re-deriving the precedence off `enabled`
        // alone would read this as off.
        assert!(
            audit.publishes("cache.admit"),
            "an event the operator turned on must publish"
        );
        assert!(
            !audit.publishes("route.decide"),
            "an event the operator never named must stay off under an unset master switch"
        );
    }

    /// The refusal above is a refusal of one `events:` key, and the
    /// master switch does not go through that key. `enabled: true` with
    /// no `events:` map names nothing, so it compiles clean, and a
    /// `publishes` that only consulted the map and the switch would hand
    /// the operator the per-chunk feed the refusal exists to prevent as
    /// soon as an emitter lands. This walks the whole path (compile,
    /// snapshot, read) rather than calling the method directly, because
    /// the bypass is a property of the two halves together.
    #[test]
    fn a_bare_master_switch_does_not_turn_on_the_per_chunk_stream_event() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("a bare master switch compiles");
        let audit = compiled
            .decision_audit
            .proxy
            .as_ref()
            .expect("an authored decision_audit block must reach the snapshot");
        assert!(
            audit.publishes("cache.admit"),
            "the master switch turns on the events it is meant to"
        );
        assert!(
            !audit.publishes("ai.stream.event"),
            "the master switch must not reach the per-chunk stream event; `ai.close` carries \
             the stream's summary instead"
        );
    }

    /// No block means no feed, and the snapshot has to say so with
    /// `None` rather than a default-constructed block. A `Some` holding
    /// empty defaults would answer the same way today and stop doing so
    /// the moment any default turns permissive.
    #[test]
    fn no_decision_audit_block_compiles_to_none() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled =
            compile_config(yaml).expect("a config with no decision_audit block compiles");
        assert!(
            compiled.decision_audit.is_empty(),
            "a config that never mentions decision_audit must not synthesize a block"
        );
    }

    // WOR-1140: unknown-config-key handling.
    #[test]
    fn nested_unknown_key_fails_compile() {
        // A typo in a nested server/security key (here `proxy.mtsl`
        // instead of the real block) must fail the compile rather than
        // be silently dropped.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  mtsl:
    require_client_cert: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let err = compile_config(yaml)
            .err()
            .expect("nested typo must fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mtsl"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn nested_origin_unknown_key_fails_compile() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    forced_ssl: true
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let err = compile_config(yaml)
            .err()
            .expect("origin typo must fail compile");
        assert!(format!("{err:#}").contains("forced_ssl"));
    }

    #[test]
    fn top_level_unknown_key_compiles_for_v1_compat() {
        // The archived Go v0.1.x flat schema puts metadata at the top
        // level; schema-v1 compat tolerates those (they only warn), so
        // the config still compiles.
        let yaml = r#"
config_version: 2
id: "legacy-1"
hostname: "api.example.com"
version: "1.0"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        assert!(
            compile_config(yaml).is_ok(),
            "top-level v1-compat metadata keys must still compile"
        );
    }

    #[test]
    fn flat_v1_origin_without_origins_map_compiles_into_that_hostname() {
        let yaml = r#"
config_version: 2
id: "legacy-flat"
hostname: "api.example.com"
action:
  type: proxy
  url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("flat schema-v1 file must compile");
        assert_eq!(
            compiled.origins.len(),
            1,
            "WOR-2706: origin must not be dropped"
        );
        assert!(
            compiled
                .host_map
                .keys()
                .any(|host| host.as_str() == "api.example.com"),
            "declared hostname must be present in the compiled host map"
        );
    }

    #[test]
    fn ai_toolkit_config_is_preserved_under_proxy() {
        let yaml = r#"
proxy:
  ai_toolkit:
    limits:
      max_agents: 8
      max_dataset_versions_total: 24
      max_dataset_bytes_total: 1048576
      max_request_bytes: 4096
    agents:
      - origin: ai.example.test
        id: researcher
        endpoint: https://agents.example.test/invoke
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities:
          - name: research
            description: bounded research
            input_schema: {type: object}
            output_schema: {type: object}
    prompt_rollouts:
      - origin: ai.example.test
        name: system
        salt: stable-salt
        versions:
          - version: 1
            content: concise system prompt
            weight: 1.0
    workflows:
      - origin: ai.example.test
        name: research-flow
        initial_state: collect
        max_steps: 4
        timeout_ms: 2000
        states:
          - name: collect
            action: research
            transitions: {}
    datasets:
      - origin: ai.example.test
        name: quality
        version: 1
        entries:
          - input: hello
            expected_output: world
            metadata: {source: fixture}
origins:
  ai.example.test:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
egress:
  agent_orchestration:
    mode: deny_by_default
    hosts: ["agents.example.test"]
"#;
        let compiled = compile_config(yaml).expect("toolkit config compiles");
        let toolkit = compiled
            .server
            .ai_toolkit
            .as_ref()
            .expect("compiled server keeps the toolkit declaration");
        assert_eq!(toolkit.agents[0].id, "researcher");
        assert_eq!(toolkit.limits.max_dataset_versions_total, Some(24));
        assert_eq!(toolkit.limits.max_dataset_bytes_total, Some(1_048_576));
        assert_eq!(toolkit.workflows[0].states[0].action, "research");
        assert_eq!(toolkit.datasets[0].version, 1);
        assert_eq!(toolkit.prompt_rollouts[0].versions[0].version, 1);
    }

    #[test]
    fn ai_toolkit_agents_require_deny_by_default_agent_egress() {
        let yaml = r#"
proxy:
  ai_toolkit:
    agents:
      - origin: ai.example.test
        id: researcher
        endpoint: https://agents.example.test/invoke
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities: []
origins:
  ai.example.test:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
        let error = compile_config(yaml)
            .err()
            .expect("agent endpoints without an explicit egress gate must be refused");
        let message = format!("{error:#}");
        assert!(message.contains("egress.agent_orchestration"), "{message}");
        assert!(message.contains("deny_by_default"), "{message}");
    }

    #[test]
    fn ai_toolkit_config_rejects_plaintext_agents_off_loopback() {
        let yaml = r#"
proxy:
  ai_toolkit:
    agents:
      - origin: ai.example.test
        id: researcher
        endpoint: http://agents.example.test/invoke
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities: []
origins:
  ai.example.test:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
egress:
  agent_orchestration:
    mode: deny_by_default
    hosts: ["agents.example.test"]
"#;

        let error = compile_config(yaml)
            .err()
            .expect("plaintext agent credentials must not leave loopback");
        let message = format!("{error:#}");
        assert!(
            message.contains("endpoint must use https:// for nonlocal destinations"),
            "{message}"
        );
        assert!(!message.contains("agents.example.test"), "{message}");
    }

    #[test]
    fn ai_toolkit_config_allows_https_and_plaintext_loopback_agents() {
        for endpoint in [
            "http://127.0.0.1/invoke",
            "http://[::1]/invoke",
            "http://localhost/invoke",
            "https://agents.example.test/invoke",
        ] {
            let yaml = format!(
                r#"
proxy:
  ai_toolkit:
    agents:
      - origin: ai.example.test
        id: researcher
        endpoint: "{endpoint}"
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities: []
origins:
  ai.example.test:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
egress:
  agent_orchestration:
    mode: deny_by_default
    hosts: ["127.0.0.1", "::1", "localhost", "agents.example.test"]
    allow_private: true
"#
            );
            compile_config(&yaml)
                .unwrap_or_else(|error| panic!("{endpoint} must remain valid: {error:#}"));
        }
    }

    #[test]
    fn ai_toolkit_rejects_inline_agent_shared_secret() {
        let yaml = r#"
proxy:
  ai_toolkit:
    agents:
      - origin: ai-origin
        id: researcher
        endpoint: https://agents.example.test/invoke
        auth:
          shared_secret: plaintext-is-not-a-reference
        capabilities: []
"#;
        let error = compile_config(yaml)
            .err()
            .expect("inline agent credential must be refused");
        let message = format!("{error:#}");
        assert!(message.contains("proxy.ai_toolkit.agents[0].auth.shared_secret"));
        assert!(message.contains("secret reference"));
        assert!(!message.contains("plaintext-is-not-a-reference"));
    }

    #[test]
    fn ai_toolkit_bounds_agent_secret_reference_before_resolution() {
        let yaml = r#"
proxy:
  ai_toolkit:
    limits:
      max_secret_bytes: 8
    agents:
      - origin: ai-origin
        id: researcher
        endpoint: https://agents.example.test/invoke
        auth:
          shared_secret: env:VERY_LONG_SECRET_REFERENCE
        capabilities: []
"#;
        let error = compile_config(yaml)
            .err()
            .expect("an oversized secret reference must be refused before resolution");
        let message = format!("{error:#}");
        assert!(message.contains("8-byte reference limit"), "{message}");
        assert!(!message.contains("VERY_LONG_SECRET_REFERENCE"));
    }

    // WOR-2476/WOR-2481: the top-level `egress:` section.

    #[test]
    fn egress_section_rejects_an_unknown_sub_key() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
    bogus_key: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let err = compile_config(yaml)
            .err()
            .expect("unknown egress sub-key must fail compile");
        assert!(
            format!("{err:#}").contains("bogus_key"),
            "error must name the offending key: {err:#}"
        );
    }

    #[test]
    fn egress_section_rejects_an_unknown_top_level_purpose() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  mcp_upstream:
    mode: deny_by_default
    hosts: ["mcp.example.com"]
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let err = compile_config(yaml)
            .err()
            .expect("a purpose this section does not expose must fail compile");
        assert!(
            format!("{err:#}").contains("mcp_upstream"),
            "error must name the offending key: {err:#}"
        );
    }

    #[test]
    fn omitted_egress_section_arms_nothing() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config with no egress: block compiles");
        assert!(compiled.egress.ai_providers.is_none());
        assert!(compiled.egress.agent_orchestration.is_none());
        assert!(compiled.egress.classifier_hooks.is_none());
        assert!(compiled.egress.usage_sinks.is_none());
        assert!(compiled.egress.model_artifacts.is_none());
        assert!(compiled.egress.token_exchange.is_none());
        assert!(compiled.egress.telemetry.is_none());
    }

    #[test]
    fn egress_purpose_omitted_from_the_section_stays_ungated() {
        // Only `ai_providers` is configured; the other five sub-blocks must
        // still compile to `None` even though `egress:` itself is present.
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        assert!(compiled.egress.ai_providers.is_some());
        assert!(compiled.egress.agent_orchestration.is_none());
        assert!(compiled.egress.classifier_hooks.is_none());
        assert!(compiled.egress.usage_sinks.is_none());
        assert!(compiled.egress.model_artifacts.is_none());
        assert!(compiled.egress.token_exchange.is_none());
        assert!(compiled.egress.telemetry.is_none());
    }

    #[test]
    fn egress_allow_by_default_mode_stays_ungated_even_with_hosts_set() {
        // The default `mode` is inert on purpose (WOR-2476): a `hosts`
        // list with no explicit `deny_by_default` must not silently start
        // gating a purpose an operator has not opted into.
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  ai_providers:
    hosts: ["api.openai.com"]
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        assert!(
            compiled.egress.ai_providers.is_none(),
            "allow_by_default (the default) must compile to no authorizer"
        );
    }

    #[test]
    fn egress_classifier_hooks_preserves_legacy_ungated_default() {
        let yaml = r#"
proxy: {}
egress:
  classifier_hooks:
    hosts: ["127.0.0.1"]
    ports: [50051]
    allow_private: true
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        assert!(
            compiled.egress.classifier_hooks.is_none(),
            "an omitted classifier_hooks mode must remain legacy ungated"
        );
    }

    #[test]
    fn egress_classifier_hooks_compiles_an_exact_purpose_authorizer() {
        let yaml = r#"
proxy: {}
egress:
  classifier_hooks:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    ports: [50051]
    allow_private: true
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .classifier_hooks
            .expect("deny_by_default must compile a classifier-hook authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert!(
            authorizer
                .authorize(
                    EgressPurpose::ClassifierHook,
                    "http://127.0.0.1:50051",
                    &SystemHostResolver,
                )
                .is_ok(),
            "the configured destination must authorize under ClassifierHook"
        );
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::AiProvider,
                    "http://127.0.0.1:50051",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedPurpose,
            "the classifier-hooks block must not grant another purpose"
        );
    }

    #[test]
    fn egress_agent_orchestration_compiles_an_exact_purpose_authorizer() {
        let yaml = r#"
proxy: {}
egress:
  agent_orchestration:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    ports: [18777]
    allow_private: true
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .agent_orchestration
            .expect("deny_by_default must compile an agent-workflow authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert!(authorizer
            .authorize(
                EgressPurpose::AgentOrchestration,
                "http://127.0.0.1:18777/invoke",
                &SystemHostResolver,
            )
            .is_ok());
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::AiProvider,
                    "http://127.0.0.1:18777/invoke",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedPurpose,
            "the agent-orchestration block must not grant another purpose"
        );
    }

    #[test]
    fn egress_deny_by_default_compiles_a_real_authorizer() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  usage_sinks:
    mode: deny_by_default
    hosts: ["collector.example.com"]
    allow_private: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .usage_sinks
            .expect("deny_by_default must compile a real authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::UsageSink,
                    "https://attacker.test/collect",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedHost,
            "a host outside the configured allowlist must be denied"
        );
    }

    #[test]
    fn egress_usage_sinks_authorizer_also_arms_the_webhook_purpose() {
        // Regression test (WOR-2476): `WebhookSink::record` authorizes
        // under `EgressPurpose::Webhook`, a separate, pre-existing
        // purpose from `EgressPurpose::UsageSink` that Langfuse/Datadog/
        // ObjectStore share. An authorizer compiled from `usage_sinks:`
        // that only covered `UsageSink` denied every Webhook dispatch
        // with `UnlistedPurpose` regardless of `hosts`, because
        // `EgressAuthorizer::authorize` looks the purpose up by exact
        // key. Proves the compiled authorizer covers both: an allowed
        // host authorizes under either purpose, and an unlisted host is
        // denied by host, not by purpose, under either.
        // `allow_private` + a loopback IP literal so the positive case
        // below resolves with no real DNS lookup (an IP literal needs
        // none) and stays hermetic.
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  usage_sinks:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    allow_private: true
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .usage_sinks
            .expect("deny_by_default must compile a real authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};

        // Not `UnlistedPurpose`: the Webhook purpose key exists. An
        // unlisted host is denied by host, which only happens after the
        // purpose lookup already succeeded.
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::Webhook,
                    "https://attacker.test/ingest",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedHost,
            "an unlisted host must be denied by host, not by a missing Webhook purpose entry"
        );

        // The allowlisted host authorizes under the Webhook purpose too,
        // not just UsageSink.
        assert!(
            authorizer
                .authorize(
                    EgressPurpose::Webhook,
                    "https://127.0.0.1/ingest",
                    &SystemHostResolver,
                )
                .is_ok(),
            "the configured host must authorize under EgressPurpose::Webhook, not just UsageSink"
        );
    }

    #[test]
    fn egress_deny_by_default_with_empty_hosts_denies_everything() {
        // Proves the acceptance shape the brief calls out directly: an
        // empty `hosts:` list under `deny_by_default` refuses every
        // destination, not just unlisted ones (there is nothing listed).
        let yaml = r#"
proxy:
  http_bind_port: 8080
egress:
  ai_providers:
    mode: deny_by_default
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .ai_providers
            .expect("deny_by_default must compile a real authorizer even with empty hosts");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::AiProvider,
                    "https://api.openai.com/v1/chat/completions",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedHost,
        );
    }

    #[test]
    fn egress_telemetry_with_an_explicit_port_authorizes_the_default_otlp_endpoint() {
        // C1 regression: `compile_egress_purpose` used to hardcode
        // `{80, 443}` regardless of the sub-block's own `ports:`, which
        // meant `egress.telemetry:` could never be armed at all --
        // `DEFAULT_OTLP_ENDPOINT` is `http://localhost:4327`, and every
        // other OTLP default (4317 gRPC, 4318 HTTP) is non-standard too.
        // An operator following the docs' advice to add the host to
        // `hosts:` would still get `DisallowedPort` on every dial, with
        // no config fix available.
        let yaml = r#"
proxy: {}
egress:
  telemetry:
    mode: deny_by_default
    hosts: ["localhost"]
    ports: [4327]
    allow_private: true
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .telemetry
            .expect("deny_by_default must compile a real authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert!(
            authorizer
                .authorize(
                    EgressPurpose::Telemetry,
                    "http://localhost:4327",
                    &SystemHostResolver,
                )
                .is_ok(),
            "an explicit ports: override must authorize the default OTLP endpoint \
             (allow_private: true is required too, since localhost resolves to a \
             loopback address and authorize_inner denies PrivateAddress otherwise, \
             matching docs/configuration.md's own worked example)"
        );

        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::Telemetry,
                    "http://localhost:8080",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::DisallowedPort,
            "a port outside the explicit override must still be refused"
        );
    }

    #[test]
    fn egress_telemetry_without_ports_refuses_the_default_otlp_endpoint() {
        // The other half of the C1 regression: the default port set
        // ([80, 443]) does not cover OTLP, so an operator who arms
        // `egress.telemetry:` without an explicit `ports:` override
        // gets `DisallowedPort` on the default endpoint, not a working
        // gate. This is the exact boot failure C1 described: "boot
        // fails with advice that cannot work" until `ports:` is added.
        let yaml = r#"
proxy: {}
egress:
  telemetry:
    mode: deny_by_default
    hosts: ["localhost"]
"#;
        let compiled = compile_config(yaml).expect("config compiles");
        let authorizer = compiled
            .egress
            .telemetry
            .expect("deny_by_default must compile a real authorizer");

        use sbproxy_security::egress::{EgressDenied, EgressPurpose, SystemHostResolver};
        assert_eq!(
            authorizer
                .authorize(
                    EgressPurpose::Telemetry,
                    "http://localhost:4327",
                    &SystemHostResolver,
                )
                .unwrap_err(),
            EgressDenied::DisallowedPort,
            "the default port set [80, 443] does not cover OTLP's default port"
        );
    }

    #[test]
    fn egress_section_refuses_an_empty_ports_list() {
        let yaml = r#"
proxy: {}
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
    ports: []
"#;
        let err = compile_config(yaml)
            .err()
            .expect("an empty ports: list must fail compile");
        assert!(
            format!("{err:#}").contains("egress.ai_providers.ports"),
            "error must name the offending key: {err:#}"
        );
    }

    #[test]
    fn egress_section_refuses_port_zero() {
        let yaml = r#"
proxy: {}
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
    ports: [443, 0]
"#;
        let err = compile_config(yaml)
            .err()
            .expect("port 0 must fail compile");
        assert!(
            format!("{err:#}").contains("egress.ai_providers.ports"),
            "error must name the offending key: {err:#}"
        );
    }

    #[test]
    fn extensions_block_accepts_arbitrary_keys() {
        // `proxy.extensions` is an opaque arbitrary-key block; unknown
        // keys there must NOT trip the unknown-key gate.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    my_out_of_tree_block:
      anything: 1
      goes: here
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        assert!(
            compile_config(yaml).is_ok(),
            "arbitrary keys under proxy.extensions must compile"
        );
    }

    #[test]
    fn custom_log_fields_accept_valid_shapes() {
        let fields = vec![
            custom_field("region", Some("${env.REGION}"), None, None),
            custom_field("tier", None, Some("cel"), Some("\"gold\"")),
            custom_field("rc", None, Some("lua"), Some("return 1")),
            custom_field("um", None, Some("js"), Some("1")),
        ];
        assert!(validate_custom_log_fields(&fields).is_ok());
    }

    #[test]
    fn custom_log_fields_reject_wasm_and_bad_shapes() {
        // WASM is rejected with a clear message.
        let wasm = vec![custom_field("x", None, Some("wasm"), Some("..."))];
        let err = validate_custom_log_fields(&wasm).unwrap_err().to_string();
        assert!(err.contains("wasm"), "got: {err}");

        // Both value and source set.
        let both = vec![custom_field("x", Some("a"), Some("cel"), Some("1"))];
        assert!(validate_custom_log_fields(&both).is_err());

        // Neither set.
        let neither = vec![custom_field("x", None, None, None)];
        assert!(validate_custom_log_fields(&neither).is_err());

        // Unknown engine.
        let unknown = vec![custom_field("x", None, Some("ruby"), Some("1"))];
        assert!(validate_custom_log_fields(&unknown).is_err());

        // Duplicate names.
        let dup = vec![
            custom_field("x", Some("a"), None, None),
            custom_field("x", Some("b"), None, None),
        ];
        assert!(validate_custom_log_fields(&dup).is_err());
    }

    // --- extract_type tests ---

    #[test]
    fn extract_type_from_valid_json() {
        let val = serde_json::json!({"type": "proxy", "url": "http://example.com"});
        assert_eq!(extract_type(&val).unwrap(), "proxy");
    }

    #[test]
    fn extract_type_missing_field() {
        let val = serde_json::json!({"url": "http://example.com"});
        assert!(extract_type(&val).is_err());
    }

    #[test]
    fn extract_type_non_string() {
        let val = serde_json::json!({"type": 42});
        assert!(extract_type(&val).is_err());
    }

    // --- YAML parsing tests ---

    #[test]
    fn parse_minimal_yaml() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.origins.len(), 1);
        assert!(config.origins.contains_key("api.example.com"));

        let origin = &config.origins["api.example.com"];
        assert_eq!(
            origin.action.get("type").unwrap().as_str().unwrap(),
            "proxy"
        );
    }

    #[test]
    fn parse_yaml_with_server_config() {
        let yaml = r#"
proxy:
  http_bind_port: 9090
origins:
  example.com:
    action:
      type: proxy
      url: http://backend:8080
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxy.http_bind_port, 9090);
    }

    #[test]
    fn parse_yaml_default_port() {
        let yaml = r#"
origins:
  example.com:
    action:
      type: proxy
      url: http://backend:8080
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxy.http_bind_port, 8080);
    }

    #[test]
    fn parse_yaml_with_auth_and_policies() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    authentication:
      type: api_keys
      keys:
        - name: test-key
          key: abc123
    policies:
      - type: rate_limit
        requests_per_second: 10
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let origin = &config.origins["api.example.com"];
        assert!(origin.authentication.is_some());
        assert_eq!(origin.policies.len(), 1);
    }

    #[test]
    fn parse_yaml_with_cors_and_hsts() {
        let yaml = r#"
origins:
  app.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    cors:
      allowed_origins:
        - "https://example.com"
      allow_credentials: true
    hsts:
      max_age: 86400
      include_subdomains: true
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let origin = &config.origins["app.example.com"];
        let cors = origin.cors.as_ref().unwrap();
        assert_eq!(cors.allowed_origins, vec!["https://example.com"]);
        assert!(cors.allow_credentials);

        let hsts = origin.hsts.as_ref().unwrap();
        assert_eq!(hsts.max_age, 86400);
        assert!(hsts.include_subdomains);
    }

    // --- compile_config tests ---

    #[test]
    fn compile_basic_config() {
        let yaml = r#"
proxy:
  http_bind_port: 9090
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    force_ssl: true
    allowed_methods:
      - GET
      - POST
"#;
        let compiled = compile_config(yaml).unwrap();
        assert_eq!(compiled.server.http_bind_port, 9090);
        assert_eq!(compiled.origins.len(), 1);

        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(origin.hostname.as_str(), "api.example.com");
        assert!(origin.force_ssl);
        assert_eq!(origin.allowed_methods.len(), 2);
        assert!(origin.allowed_methods.contains(&http::Method::GET));
        assert!(origin.allowed_methods.contains(&http::Method::POST));
    }

    #[test]
    fn a_malformed_bind_address_fails_config_load() {
        // WOR-2199. Rejected at compile, not at bind: a proxy that
        // starts and then cannot listen has already told the operator
        // it was fine, and one that silently falls back to every
        // interface is the bug this field exists to prevent.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  bind_address: "127.0.0.999"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("a malformed bind address must not compile");
        let msg = format!("{err:#}");
        assert!(msg.contains("bind_address"), "{msg}");
        assert!(msg.contains("127.0.0.999"), "{msg}");
    }

    #[test]
    fn an_absent_bind_address_still_binds_every_interface() {
        // The compatibility half of the same change. Every config
        // written before this field existed must keep the reach it had.
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let compiled = compile_config(yaml).expect("config without the field compiles");
        assert_eq!(compiled.server.effective_bind_address(), "0.0.0.0");
    }

    #[test]
    fn compile_origin_normalizes_promoted_property_keys() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    properties:
      rollup_keys: [Feature, CUSTOMER-TIER]
"#;
        let compiled = compile_config(yaml).expect("property rollup keys should compile");
        let properties = compiled
            .resolve_origin("api.example.com")
            .unwrap()
            .properties
            .as_ref()
            .unwrap();
        assert_eq!(properties.rollup_keys, ["feature", "customer-tier"]);
    }

    #[test]
    fn compile_origin_rejects_invalid_promoted_property_keys() {
        for rollup_keys in [
            "[Feature, feature]",
            "['bad.key']",
            "[one, two, three, four, five, six]",
        ] {
            let yaml = format!(
                r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    properties:
      rollup_keys: {rollup_keys}
"#
            );
            let error = compile_config(&yaml)
                .err()
                .expect("invalid property rollup keys must fail");
            assert!(
                error.to_string().contains("properties.rollup_keys"),
                "unhelpful error: {error}"
            );
        }
    }

    /// WOR-1053 PR1: an origin with no `tenant_id:` resolves to the
    /// synthetic `__default__` tenant so existing single-tenant
    /// configs keep working unchanged.
    #[test]
    fn compile_origin_defaults_to_default_tenant() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(origin.tenant_id.as_str(), "__default__");
    }

    /// WOR-1053 PR1: an origin's explicit `tenant_id` resolves to the
    /// declared tenant when the id matches a `proxy.tenants[]` entry.
    #[test]
    fn compile_origin_resolves_declared_tenant() {
        let yaml = r#"
proxy:
  tenants:
    - id: acme-corp
origins:
  api.acme.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    tenant_id: acme-corp
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.acme.example.com").unwrap();
        assert_eq!(origin.tenant_id.as_str(), "acme-corp");
    }

    /// WOR-1053 PR1: an origin that references an undeclared tenant
    /// fails config compile with an actionable error so an operator's
    /// typo surfaces at startup rather than at request time.
    #[test]
    fn compile_origin_rejects_undeclared_tenant() {
        let yaml = r#"
proxy:
  tenants:
    - id: acme-corp
origins:
  api.bogus.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    tenant_id: typo-corp
"#;
        let err = compile_config(yaml)
            .err()
            .expect("undeclared tenant should fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("typo-corp") && msg.contains("not declared"),
            "unhelpful error: {msg}"
        );
    }

    /// `allowed_origins: ["*"]` with `allow_credentials: true` used to
    /// pass `sbproxy validate` and then emit zero CORS headers plus one
    /// warn line per request, forever. It fails the load now.
    #[test]
    fn compile_origin_rejects_cors_wildcard_with_credentials() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    cors:
      allowed_origins:
        - "*"
      allow_credentials: true
"#;
        let err = compile_config(yaml)
            .err()
            .expect("wildcard plus credentials must fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("allow_credentials") && msg.contains("api.example.com"),
            "unhelpful error: {msg}"
        );
    }

    /// The same wildcard without credentials is a legitimate public API
    /// and still compiles, so the refusal is no wider than its claim.
    #[test]
    fn compile_origin_accepts_cors_wildcard_without_credentials() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    cors:
      allowed_origins:
        - "*"
"#;
        compile_config(yaml).expect("wildcard alone is a valid public-API CORS policy");
    }

    /// An algorithm name naming no codec used to disable compression for
    /// the whole origin in silence.
    #[test]
    fn compile_origin_rejects_unknown_compression_algorithm() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    compression:
      enabled: true
      algorithms:
        - deflate
"#;
        let err = compile_config(yaml)
            .err()
            .expect("an unknown codec name must fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("deflate") && msg.contains("gzip"),
            "the error must name the bad entry and the supported set: {msg}"
        );
    }

    /// Every supported token, in any case, still compiles.
    #[test]
    fn compile_origin_accepts_every_supported_compression_algorithm() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    compression:
      enabled: true
      algorithms:
        - GZIP
        - br
        - zstd
"#;
        compile_config(yaml).expect("the documented codec tokens must compile");
    }

    /// A `timeouts:` block resolves onto the compiled origin as concrete
    /// durations, so the request path reads them without Option juggling.
    #[test]
    fn compile_origin_resolves_custom_upstream_timeouts() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    timeouts:
      connect_ms: 1500
      total_connect_ms: 4000
      read_ms: 120000
      write_ms: 45000
      idle_ms: 20000
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let ms = std::time::Duration::from_millis;
        assert_eq!(origin.timeouts.connect, ms(1500));
        assert_eq!(origin.timeouts.total_connect, ms(4000));
        assert_eq!(origin.timeouts.read, ms(120_000));
        assert_eq!(origin.timeouts.write, ms(45_000));
        assert_eq!(origin.timeouts.idle, ms(20_000));
    }

    /// Absent fields resolve to the `DEFAULT_UPSTREAM_*` constants, both
    /// with no `timeouts:` block at all and with a partial one.
    #[test]
    fn compile_origin_upstream_timeouts_default_to_the_consts() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
  partial.example.com:
    action:
      type: proxy
      url: http://localhost:3001
    timeouts:
      read_ms: 120000
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(origin.timeouts, UpstreamTimeouts::default());
        let ms = std::time::Duration::from_millis;
        assert_eq!(
            origin.timeouts.connect,
            ms(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            origin.timeouts.total_connect,
            ms(DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(origin.timeouts.read, ms(DEFAULT_UPSTREAM_READ_TIMEOUT_MS));
        assert_eq!(origin.timeouts.write, ms(DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS));
        assert_eq!(origin.timeouts.idle, ms(DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS));

        let partial = compiled.resolve_origin("partial.example.com").unwrap();
        assert_eq!(partial.timeouts.read, ms(120_000));
        assert_eq!(
            partial.timeouts.connect,
            ms(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(partial.timeouts.idle, ms(DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS));
    }

    /// A zero deadline means instant failure and is never intended, so
    /// every `timeouts.*_ms` key rejects `0` at compile with an error
    /// that names the offending key.
    #[test]
    fn compile_origin_rejects_zero_upstream_timeouts() {
        for key in [
            "connect_ms",
            "total_connect_ms",
            "read_ms",
            "write_ms",
            "idle_ms",
        ] {
            let yaml = format!(
                r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    timeouts:
      {key}: 0
"#
            );
            let err = compile_config(&yaml)
                .err()
                .expect("zero timeout should fail compile");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(&format!("timeouts.{key} is 0")),
                "error for {key} must name the key: {msg}"
            );
        }
    }

    /// The legacy `connection_pool.idle_timeout_secs` feeds the same
    /// resolved idle deadline when `timeouts.idle_ms` is unset, so the
    /// previously inert key becomes live rather than staying a trap.
    #[test]
    fn compile_origin_legacy_pool_idle_feeds_resolved_idle() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    connection_pool:
      idle_timeout_secs: 45
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(origin.timeouts.idle, std::time::Duration::from_secs(45));
    }

    /// Authoring a non-default legacy idle next to `timeouts.idle_ms`
    /// fails compile: two spellings of one deadline must not disagree
    /// silently.
    #[test]
    fn compile_origin_rejects_conflicting_idle_spellings() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    connection_pool:
      idle_timeout_secs: 45
    timeouts:
      idle_ms: 20000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("conflicting idle spellings should fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("config conflict")
                && msg.contains("connection_pool.idle_timeout_secs")
                && msg.contains("timeouts.idle_ms"),
            "unhelpful error: {msg}"
        );
    }

    /// A present but empty `connection_pool` block does not count as
    /// authoring the legacy idle: `timeouts.idle_ms` wins and the compile
    /// stays green.
    ///
    /// This used to reach the same state by setting `max_connections: 64`,
    /// which is now refused, so the block is empty instead. What is being
    /// pinned is the same either way: `idle_timeout_secs` at its serde
    /// default must read as absent rather than as an authored 90.
    #[test]
    fn compile_origin_idle_ms_wins_over_defaulted_pool_idle() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    connection_pool: {}
    timeouts:
      idle_ms: 20000
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(
            origin.timeouts.idle,
            std::time::Duration::from_millis(20_000)
        );
    }

    /// The legacy idle spelling is held to the same zero rejection as
    /// `timeouts.idle_ms` now that it is live.
    #[test]
    fn compile_origin_rejects_zero_legacy_pool_idle() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    connection_pool:
      idle_timeout_secs: 0
"#;
        let err = compile_config(yaml)
            .err()
            .expect("zero legacy idle should fail compile");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("connection_pool.idle_timeout_secs is 0"),
            "unhelpful error: {msg}"
        );
    }

    /// Legacy `virtual_keys:` YAML at any scope is rejected at
    /// compile with a pointer to the migration guide. The credentials
    /// block replaces it.
    #[test]
    fn compile_rejects_legacy_virtual_keys_key() {
        let yaml = r#"
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
      virtual_keys:
        - key: vk-1
          name: test
"#;
        let err = compile_config(yaml)
            .err()
            .expect("legacy virtual_keys: should be rejected at compile");
        let msg = err.to_string();
        assert!(
            msg.contains("virtual_keys") && msg.contains("migration"),
            "unhelpful error: {msg}"
        );
    }

    /// A top-level `model_aliases:` block is refused with the live path.
    /// The root ignores unknown keys, so before this it parsed and did
    /// nothing, which is the shape the gateway guide used to show.
    #[test]
    fn compile_rejects_top_level_model_aliases() {
        let yaml = r#"
model_aliases:
  - alias: fast
    provider: openai
    model_id: gpt-4o-mini
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
"#;
        let err = compile_config(yaml)
            .err()
            .expect("a top-level model_aliases: block should be rejected at compile");
        let msg = err.to_string();
        assert!(
            msg.contains("model_aliases") && msg.contains("action.model_aliases"),
            "unhelpful error: {msg}"
        );
    }

    /// The same aliases on the AI action compile, and reach the handler.
    #[test]
    fn compile_accepts_model_aliases_on_the_ai_action() {
        let yaml = r#"
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
          models: [gpt-4o-mini]
      model_aliases:
        - alias: fast
          provider: openai
          model_id: gpt-4o-mini
"#;
        compile_config(yaml).expect("aliases on the AI action compile");
    }

    /// A top-level `model_groups:` block is refused with the live path,
    /// for the same reason the alias block above is: the root ignores
    /// unknown keys, so it would parse and load-balance nothing.
    #[test]
    fn compile_rejects_top_level_model_groups() {
        let yaml = r#"
model_groups:
  - name: pool
    members:
      - provider: openai
        model: gpt-4o-mini
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
          models: [gpt-4o-mini]
"#;
        let err = compile_config(yaml)
            .err()
            .expect("a top-level model_groups: block should be rejected at compile");
        let msg = err.to_string();
        assert!(
            msg.contains("model_groups") && msg.contains("action.model_groups"),
            "unhelpful error: {msg}"
        );
    }

    /// The same group on the AI action compiles. `compile_config` parses
    /// the action body without building its handler, so this pins the key
    /// as accepted here and nothing more; the group validator itself runs
    /// where the action is compiled, which
    /// `a_group_two_members_on_one_provider_is_refused_at_pipeline_build`
    /// in `sbproxy-core` covers.
    #[test]
    fn compile_accepts_model_groups_on_the_ai_action() {
        let yaml = r#"
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
          models: [gpt-4o-mini]
        - name: azure
          api_key: dummy
          models: [gpt-4o-mini-deployment]
      model_groups:
        - name: pool
          routing: weighted
          members:
            - provider: openai
              model: gpt-4o-mini
              weight: 9
            - provider: azure
              model: gpt-4o-mini-deployment
              weight: 1
"#;
        compile_config(yaml).expect("groups on the AI action compile");
    }

    /// An `ai_provider` credential at proxy scope lowers onto every
    /// origin's `action.virtual_keys` array.
    #[test]
    fn proxy_ai_provider_credential_lowers_into_origin_vks() {
        let yaml = r#"
proxy:
  credentials:
    - name: openai-shared
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
      attrs:
        project: shared
        cost_center: research
        tags: [tier-shared]
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let action = &origin.action_config;
        let vks = action
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");
        assert_eq!(vks.len(), 1);
        assert_eq!(vks[0]["name"], "openai-shared");
        assert_eq!(
            vks[0]["key_id"],
            "cfg:11:__default__:8:ai.local:openai-shared"
        );
        assert_eq!(vks[0]["project"], "shared");
        assert_eq!(vks[0]["allowed_providers"][0], "openai");
        assert_eq!(vks[0]["tags"][0], "tier-shared");
        assert_eq!(
            vks[0]["metadata"]["cost_center"], "research",
            "cost_center must be lifted into the runtime metadata map"
        );
    }

    /// `route_to_model` and `inject_tools` set on a credentials-block
    /// entry must reach the lowered virtual_keys entry verbatim; the
    /// AI dispatch consumes the same field names on the underlying
    /// `VirtualKeyConfig`. The legacy `action.virtual_keys:` shape
    /// accepted these, and the credentials block has to as well or
    /// the migration silently drops behaviour.
    #[test]
    fn credential_route_to_model_and_inject_tools_pass_through() {
        let yaml = r#"
proxy:
  credentials:
    - name: pinned
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
      route_to_model: gpt-4o-mini
      compression_profile: coding-agent
      allowed_tools: []
      inject_tools:
        - type: function
          function:
            name: search_docs
            description: search the documentation
            parameters:
              type: object
              properties:
                query: { type: string }
              required: [query]
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");
        assert_eq!(vks.len(), 1);
        assert_eq!(
            vks[0]["route_to_model"], "gpt-4o-mini",
            "route_to_model must reach the lowered VK; got: {}",
            vks[0]
        );
        assert_eq!(
            vks[0]["compression_profile"], "coding-agent",
            "compression_profile must reach the lowered VK; got: {}",
            vks[0]
        );
        let tools = vks[0]["inject_tools"]
            .as_array()
            .expect("inject_tools array");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["function"]["name"], "search_docs");
        assert_eq!(
            vks[0]["allowed_tools"],
            serde_json::json!([]),
            "an explicit empty tool list must remain deny-all"
        );
    }

    #[test]
    fn credential_principals_and_pii_requirement_pass_through() {
        let yaml = r#"
proxy:
  credentials:
    - name: secure-openai
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
      principals:
        - team: frontend
          role: admin
      policies:
        - type: require_pii_redaction
          rules: [email, credit_card]
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");

        assert_eq!(vks.len(), 1);
        assert_eq!(vks[0]["principal_selectors"][0]["team"], "frontend");
        assert_eq!(vks[0]["principal_selectors"][0]["role"], "admin");
        assert_eq!(vks[0]["require_pii_redaction"][0], "email");
        assert_eq!(vks[0]["require_pii_redaction"][1], "credit_card");
    }

    #[test]
    fn credential_empty_principal_selector_is_rejected() {
        let yaml = r#"
proxy:
  credentials:
    - name: bad-openai
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
      principals:
        - {}
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
"#;
        let err = compile_config(yaml)
            .err()
            .expect("empty principal selector should fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("bad-openai") && msg.contains("empty principals[0] selector"),
            "unhelpful error: {msg}"
        );
    }

    /// WOR-2299: an `ai_proxy` origin that declares `credentials:` but
    /// does not also set `action.require_governed_key: true` must fail
    /// compile. Without the flag the credential is materialised but
    /// never checked, so the origin would keep accepting any bearer
    /// token, or none, and dispatch every request ungoverned.
    #[test]
    fn credentials_without_require_governed_key_is_rejected() {
        let yaml = r#"
proxy:
  credentials:
    - name: ungoverned-openai
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
"#;
        let err = compile_config(yaml)
            .err()
            .expect("credentials without require_governed_key should fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("ai.local") && msg.contains("require_governed_key"),
            "unhelpful error: {msg}"
        );
    }

    /// Regression guard for the check above: the same shape WITH
    /// `require_governed_key: true` set must keep compiling. This
    /// pins the check to `credentials:` presence, not to the origin
    /// merely being an `ai_proxy`.
    #[test]
    fn credentials_with_require_governed_key_still_compiles() {
        let yaml = r#"
proxy:
  credentials:
    - name: governed-openai
      type: ai_provider
      provider: openai
      key: ${OPENAI_API_KEY}
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled =
            compile_config(yaml).expect("credentials with require_governed_key: true must compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");
        assert_eq!(vks.len(), 1);
        assert_eq!(vks[0]["name"], "governed-openai");
    }

    /// An origin-scope credential with the same name as a
    /// proxy-scope credential shadows the proxy entry; the merged
    /// virtual_keys array carries only the origin variant.
    #[test]
    fn origin_credential_shadows_proxy_credential_of_same_name() {
        let yaml = r#"
proxy:
  credentials:
    - name: openai
      type: ai_provider
      provider: openai
      key: ${OPENAI_PROXY}
      attrs: { project: proxy-default }
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
    credentials:
      - name: openai
        type: ai_provider
        provider: openai
        key: ${OPENAI_LOCAL}
        attrs: { project: local-override }
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");
        assert_eq!(vks.len(), 1);
        assert_eq!(vks[0]["project"], "local-override");
        assert_eq!(vks[0]["key"], "${OPENAI_LOCAL}");
    }

    /// A tenant-scope credential applies only to origins that resolve
    /// to that tenant. Other origins (default tenant) see only the
    /// proxy-scope credential.
    #[test]
    fn tenant_credential_applies_only_to_matching_origins() {
        let yaml = r#"
proxy:
  tenants:
    - id: acme-corp
      credentials:
        - name: openai-acme
          type: ai_provider
          provider: openai
          attrs: { project: acme }
origins:
  api.acme.local:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
  api.shared.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let acme = compiled.resolve_origin("api.acme.local").unwrap();
        let acme_vks = acme
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("acme origin gets the tenant credential");
        assert_eq!(acme_vks.len(), 1);
        assert_eq!(acme_vks[0]["project"], "acme");

        let shared = compiled.resolve_origin("api.shared.local").unwrap();
        let shared_vks = shared
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array());
        // Shared origin resolves to __default__ tenant; the acme
        // tenant block does not apply. virtual_keys may be absent
        // or empty; both encode "no credentials".
        assert!(shared_vks.map(|v| v.is_empty()).unwrap_or(true));
    }

    /// `attrs.team` lowers onto the virtual key from all three
    /// credential scopes, the same way `project` and `user` do. The
    /// three scopes merge through one closure, so a regression in any
    /// of them is a regression in all three; asserting each separately
    /// is what makes that visible rather than assumed.
    #[test]
    fn credential_team_lowers_from_every_credential_scope() {
        let yaml = r#"
proxy:
  credentials:
    - name: shared
      type: ai_provider
      provider: openai
      attrs: { team: platform }
  tenants:
    - id: acme-corp
      credentials:
        - name: tenant-scoped
          type: ai_provider
          provider: openai
          attrs: { team: acme-ml }
origins:
  api.acme.local:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
    credentials:
      - name: origin-scoped
        type: ai_provider
        provider: openai
        attrs: { team: research }
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled
            .resolve_origin("api.acme.local")
            .expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");

        let teams: std::collections::BTreeMap<&str, &str> = vks
            .iter()
            .filter_map(|vk| Some((vk["name"].as_str()?, vk["team"].as_str()?)))
            .collect();

        assert_eq!(teams.get("shared").copied(), Some("platform"));
        assert_eq!(teams.get("tenant-scoped").copied(), Some("acme-ml"));
        assert_eq!(teams.get("origin-scoped").copied(), Some("research"));
    }

    /// A credential that authors no team lowers no `team` key at all,
    /// matching how `project` and `user` are omitted rather than
    /// emitted as null.
    #[test]
    fn credential_without_a_team_lowers_no_team_key() {
        let yaml = r#"
proxy:
  credentials:
    - name: plain
      type: ai_provider
      provider: openai
      attrs: { project: shared }
origins:
  ai.local:
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: dummy
"#;
        let compiled = compile_config(yaml).expect("should compile");
        let origin = compiled.resolve_origin("ai.local").expect("origin exists");
        let vks = origin
            .action_config
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .expect("virtual_keys array materialised");

        assert_eq!(vks.len(), 1);
        assert!(vks[0].get("team").is_none());
    }

    /// WOR-1053 PR1: declaring a tenant named `__default__` clashes
    /// with the reserved single-tenant fallback name and fails
    /// compile.
    #[test]
    fn compile_rejects_reserved_default_tenant_name() {
        let yaml = r#"
proxy:
  tenants:
    - id: __default__
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("declaring __default__ should fail compile");
        let msg = err.to_string();
        assert!(
            msg.contains("__default__") && msg.contains("reserved"),
            "unhelpful error: {msg}"
        );
    }

    #[test]
    fn compile_config_with_variables() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    variables:
      api_version: "v2"
      timeout: 30
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let vars = origin.variables.as_ref().unwrap();
        assert_eq!(vars.get("api_version").unwrap().as_str().unwrap(), "v2");
        assert_eq!(vars.get("timeout").unwrap().as_i64().unwrap(), 30);
    }

    #[test]
    fn compile_config_empty_variables_are_none() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(origin.variables.is_none());
    }

    // --- resolve_origin tests ---

    #[test]
    fn resolve_origin_found() {
        let yaml = r#"
origins:
  a.example.com:
    action:
      type: proxy
      url: http://a:3000
  b.example.com:
    action:
      type: proxy
      url: http://b:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        assert!(compiled.resolve_origin("a.example.com").is_some());
        assert!(compiled.resolve_origin("b.example.com").is_some());
    }

    #[test]
    fn resolve_origin_not_found() {
        let yaml = r#"
origins:
  a.example.com:
    action:
      type: proxy
      url: http://a:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        assert!(compiled.resolve_origin("nonexistent.com").is_none());
    }

    // --- wildcard origin keys ---

    #[test]
    fn wildcard_origin_matches_one_or_more_labels() {
        let yaml = r#"
origins:
  "*.example.com":
    action:
      type: proxy
      url: http://wild:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        assert!(compiled.resolve_origin("a.example.com").is_some());
        assert!(compiled.resolve_origin("a.b.example.com").is_some());
        // The bare suffix is not covered: `*.` requires at least one label.
        assert!(compiled.resolve_origin("example.com").is_none());
        assert!(compiled.resolve_origin("other.com").is_none());
    }

    #[test]
    fn wildcard_origin_exact_key_wins() {
        let yaml = r#"
origins:
  "*.example.com":
    action:
      type: proxy
      url: http://wild:3000
  api.example.com:
    action:
      type: proxy
      url: http://exact:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        let exact = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(exact.hostname.as_str(), "api.example.com");
        let wild = compiled.resolve_origin("web.example.com").unwrap();
        assert_eq!(wild.hostname.as_str(), "*.example.com");
    }

    #[test]
    fn wildcard_origin_longest_suffix_wins() {
        let yaml = r#"
origins:
  "*.example.com":
    action:
      type: proxy
      url: http://broad:3000
  "*.tenant.example.com":
    action:
      type: proxy
      url: http://narrow:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        let narrow = compiled.resolve_origin("a.tenant.example.com").unwrap();
        assert_eq!(narrow.hostname.as_str(), "*.tenant.example.com");
        // `tenant.example.com` itself only matches the broader wildcard.
        let broad = compiled.resolve_origin("tenant.example.com").unwrap();
        assert_eq!(broad.hostname.as_str(), "*.example.com");
    }

    #[test]
    fn wildcard_origin_literal_key_still_resolves() {
        // Admin surfaces look origins up by their configured key; the
        // literal spelling must keep resolving even though no wire
        // hostname ever contains `*`.
        let yaml = r#"
origins:
  "*.example.com":
    action:
      type: proxy
      url: http://wild:3000
"#;
        let compiled = compile_config(yaml).unwrap();
        assert!(compiled.resolve_origin("*.example.com").is_some());
    }

    #[test]
    fn wildcard_origin_mid_label_rejected() {
        let yaml = r#"
origins:
  "a*.example.com":
    action:
      type: proxy
      url: http://bad:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("the wildcard host key must be rejected at compile")
            .to_string();
        assert!(
            err.contains("complete first label"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wildcard_origin_inner_label_rejected() {
        let yaml = r#"
origins:
  "api.*.example.com":
    action:
      type: proxy
      url: http://bad:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("the wildcard host key must be rejected at compile")
            .to_string();
        assert!(
            err.contains("complete first label"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wildcard_origin_bare_star_rejected() {
        let yaml = r#"
origins:
  "*":
    action:
      type: proxy
      url: http://bad:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("the wildcard host key must be rejected at compile")
            .to_string();
        assert!(err.contains("catch-all"), "unexpected error: {err}");
    }

    #[test]
    fn wildcard_origin_second_star_rejected() {
        let yaml = r#"
origins:
  "*.a*.example.com":
    action:
      type: proxy
      url: http://bad:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("the wildcard host key must be rejected at compile")
            .to_string();
        assert!(err.contains("only once"), "unexpected error: {err}");
    }

    #[test]
    fn wildcard_origin_empty_suffix_label_rejected() {
        let yaml = r#"
origins:
  "*..example.com":
    action:
      type: proxy
      url: http://bad:3000
"#;
        let err = compile_config(yaml)
            .err()
            .expect("the wildcard host key must be rejected at compile")
            .to_string();
        assert!(err.contains("empty label"), "unexpected error: {err}");
    }

    #[test]
    fn compile_invalid_yaml_returns_error() {
        let yaml = "not: valid: yaml: [[[";
        assert!(compile_config(yaml).is_err());
    }

    #[test]
    fn compile_config_with_lua_request_modifiers() {
        let yaml = r#"
origins:
  "lua-reqmod.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            local result = {}
            result.set_headers = {}
            result.set_headers["X-Lua-Modified"] = "true"
            result.set_headers["X-Lua-Method"] = req.method
            result.set_headers["X-Lua-Path"] = req.path
            return result
          end
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("lua-reqmod.test").unwrap();
        assert_eq!(origin.request_modifiers.len(), 1);
        assert!(origin.request_modifiers[0].headers.is_none());
        assert!(origin.request_modifiers[0].lua_script.is_some());
        let script = origin.request_modifiers[0].lua_script.as_ref().unwrap();
        assert!(script.contains("modify_request"));
        assert!(script.contains("X-Lua-Modified"));
    }

    #[test]
    fn compile_config_with_lua_and_header_request_modifiers() {
        let yaml = r#"
origins:
  "lua-chain.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            return {
              set_headers = {
                ["X-Lua-Stage"] = "request",
                ["X-Lua-Original-Path"] = req.path
              }
            }
          end
    response_modifiers:
      - lua_script: |
          function modify_response(resp, ctx)
            return {
              set_headers = {
                ["X-Lua-Stage"] = "response",
                ["X-Lua-Processed"] = "true"
              }
            }
          end
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("lua-chain.test").unwrap();
        assert_eq!(origin.request_modifiers.len(), 1);
        assert!(origin.request_modifiers[0].lua_script.is_some());
        assert_eq!(origin.response_modifiers.len(), 1);
        assert!(origin.response_modifiers[0].lua_script.is_some());
    }

    // --- WOR-2482: Rego request/response modifiers ---

    #[test]
    fn compile_config_with_rego_request_modifiers() {
        let yaml = r#"
origins:
  "rego-reqmod.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - rego_module: |
          package sbproxy

          modify_request := {"set_headers": {"x-rego-modified": "true"}}
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("rego-reqmod.test").unwrap();
        assert_eq!(origin.request_modifiers.len(), 1);
        assert!(origin.request_modifiers[0].lua_script.is_none());
        assert!(origin.request_modifiers[0].rego_module.is_some());
        let module = origin.request_modifiers[0].rego_module.as_ref().unwrap();
        assert!(module.contains("modify_request"));
        assert!(module.contains("x-rego-modified"));
        assert!(origin.request_modifiers[0].rego_module_path.is_none());
    }

    #[test]
    fn compile_config_with_rego_response_modifiers() {
        let yaml = r#"
origins:
  "rego-respmod.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    response_modifiers:
      - rego_module: |
          package sbproxy

          modify_response := {"set_headers": {"x-rego-stage": "response"}}
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("rego-respmod.test").unwrap();
        assert_eq!(origin.response_modifiers.len(), 1);
        assert!(origin.response_modifiers[0].rego_module.is_some());
        let module = origin.response_modifiers[0].rego_module.as_ref().unwrap();
        assert!(module.contains("modify_response"));
    }

    #[test]
    fn rego_module_path_on_a_modifier_is_loaded_and_the_path_field_is_cleared() {
        let directory = tempfile::TempDir::new().expect("tempdir");
        let path = directory.path().join("modify.rego");
        std::fs::write(
            &path,
            "package sbproxy\n\nmodify_request := {\"set_headers\": {}}\n",
        )
        .expect("write fixture module");

        let yaml = format!(
            r#"
origins:
  "rego-path.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - rego_module_path: "{}"
"#,
            path.display()
        );
        let compiled = compile_config(&yaml).unwrap();
        let origin = compiled.resolve_origin("rego-path.test").unwrap();
        let modifier = &origin.request_modifiers[0];
        assert!(
            modifier.rego_module_path.is_none(),
            "module_path is resolved into module at compile time, mirroring policy: rego"
        );
        let module = modifier
            .rego_module
            .as_ref()
            .expect("module loaded from path");
        assert!(module.contains("modify_request"));
    }

    #[test]
    fn rego_module_and_rego_module_path_together_on_one_modifier_is_refused() {
        let yaml = r#"
origins:
  "rego-both.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - rego_module: |
          package sbproxy
          modify_request := {"set_headers": {}}
        rego_module_path: /etc/sbproxy/modify.rego
"#;
        let error = compile_config(yaml)
            .err()
            .expect("setting both rego_module and rego_module_path must be refused");
        assert!(
            error.to_string().contains("rego_module")
                && error.to_string().contains("rego_module_path"),
            "unexpected error: {error}"
        );
    }

    /// `rego_budget_ms: 0` on a modifier, mirroring `policy: rego`'s
    /// `budget_ms` refusal: a zero budget is an instantly expired timer,
    /// not "no limit", so it is refused at config compile rather than
    /// silently aborting every evaluation at request time.
    #[test]
    fn rego_budget_ms_of_zero_on_a_modifier_is_refused() {
        let yaml = r#"
origins:
  "rego-zero-budget.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - rego_module: |
          package sbproxy
          modify_request := {"set_headers": {}}
        rego_budget_ms: 0
"#;
        let error = compile_config(yaml)
            .err()
            .expect("rego_budget_ms: 0 on a modifier must be refused");
        assert!(
            error.to_string().contains("rego_budget_ms"),
            "unexpected error: {error}"
        );
    }

    /// The multi-engine "both set" case is a different question from the
    /// mutual-exclusion case above: this is `rego_module` alongside
    /// `lua_script`, two *different* engines on one modifier entry.
    ///
    /// `lua_script` and `js_script` set together on one modifier are not
    /// refused today (`sbproxy_core::server::proxy_http` runs Lua then
    /// JavaScript, and the later engine's headers win on a shared key,
    /// by design - see the comment at that call site). `rego_module`
    /// mirrors that: it is not refused either, so it must survive
    /// compilation with both fields intact for the runtime to run all
    /// three.
    #[test]
    fn rego_module_alongside_lua_script_on_one_modifier_is_not_refused() {
        let yaml = r#"
origins:
  "rego-and-lua.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            return { set_headers = { ["x-engine"] = "lua" } }
          end
        rego_module: |
          package sbproxy
          modify_request := {"set_headers": {"x-engine": "rego"}}
"#;
        let compiled = compile_config(yaml).expect("both engines on one modifier compiles");
        let origin = compiled.resolve_origin("rego-and-lua.test").unwrap();
        assert!(origin.request_modifiers[0].lua_script.is_some());
        assert!(origin.request_modifiers[0].rego_module.is_some());
    }

    #[test]
    fn compile_config_with_template_variables() {
        let yaml = r#"
origins:
  "templates.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    variables:
      app_name: "sbproxy-test"
      app_version: "1.0.0"
      environment: "testing"
    request_modifiers:
      - headers:
          set:
            X-App-Name: "{{vars.app_name}}"
            X-App-Version: "{{vars.app_version}}"
            X-Env: "{{vars.environment}}"
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("templates.test").unwrap();
        let vars = origin.variables.as_ref().unwrap();
        assert_eq!(
            vars.get("app_name").unwrap().as_str().unwrap(),
            "sbproxy-test"
        );
        assert_eq!(vars.get("app_version").unwrap().as_str().unwrap(), "1.0.0");
        assert_eq!(
            vars.get("environment").unwrap().as_str().unwrap(),
            "testing"
        );
        assert_eq!(origin.request_modifiers.len(), 1);
        let headers = origin.request_modifiers[0].headers.as_ref().unwrap();
        // Template patterns with {{vars.X}} are resolved at compile time.
        assert_eq!(headers.set.get("X-App-Name").unwrap(), "sbproxy-test");
        assert_eq!(headers.set.get("X-App-Version").unwrap(), "1.0.0");
        assert_eq!(headers.set.get("X-Env").unwrap(), "testing");
    }

    #[test]
    fn compile_config_with_env_variables() {
        // Set a test environment variable.
        let _env =
            crate::test_env::EnvVarGuard::set(&[("TEST_ENV_VALUE_COMPILE", Some("from-env-42"))]);
        let yaml = r#"
origins:
  "envvar.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    variables:
      test_value: "${TEST_ENV_VALUE_COMPILE}"
    request_modifiers:
      - headers:
          set:
            X-Env-Test: "${TEST_ENV_VALUE_COMPILE}"
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("envvar.test").unwrap();
        let vars = origin.variables.as_ref().unwrap();
        // ${...} is resolved at compile time by interpolate_env_vars.
        assert_eq!(
            vars.get("test_value").unwrap().as_str().unwrap(),
            "from-env-42"
        );
        let headers = origin.request_modifiers[0].headers.as_ref().unwrap();
        assert_eq!(headers.set.get("X-Env-Test").unwrap(), "from-env-42");
    }

    #[test]
    fn compile_config_with_request_modifiers() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    request_modifiers:
      - headers:
          set:
            X-Custom: "value"
          remove:
            - X-Unwanted
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert_eq!(origin.request_modifiers.len(), 1);
        let headers = origin.request_modifiers[0].headers.as_ref().unwrap();
        assert_eq!(headers.set.get("X-Custom").unwrap(), "value");
        assert_eq!(headers.remove, vec!["X-Unwanted"]);
    }

    #[test]
    fn compiled_config_default_is_empty() {
        let config = CompiledConfig::default();
        assert!(config.origins.is_empty());
        assert!(config.host_map.is_empty());
        assert_eq!(config.server.http_bind_port, 8080);
    }

    // --- Go e2e config compatibility tests ---

    #[test]
    fn parse_go_static_echo_config() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "static.test":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        message: "Hello from static"
        version: "1.0"
  "echo.test":
    action:
      type: echo
"#;
        let compiled = compile_config(yaml).unwrap();
        assert_eq!(compiled.origins.len(), 2);
        assert!(compiled.resolve_origin("static.test").is_some());
        assert!(compiled.resolve_origin("echo.test").is_some());
    }

    #[test]
    fn parse_go_cors_with_allow_origins() {
        let yaml = r#"
origins:
  "cors.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    cors:
      enable: true
      allow_origins:
        - https://app.example.com
      allow_methods:
        - GET
        - POST
      allow_headers:
        - Content-Type
      max_age: 3600
      allow_credentials: true
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("cors.test").unwrap();
        let cors = origin.cors.as_ref().unwrap();
        assert_eq!(cors.allowed_origins, vec!["https://app.example.com"]);
        assert_eq!(cors.allowed_methods, vec!["GET", "POST"]);
        assert_eq!(cors.allowed_headers, vec!["Content-Type"]);
        assert!(cors.allow_credentials);
    }

    #[test]
    fn parse_go_redirect_with_status_code() {
        let yaml = r#"
origins:
  "redirect.test":
    action:
      type: redirect
      url: http://example.com
      status_code: 301
"#;
        let compiled = compile_config(yaml).unwrap();
        assert!(compiled.resolve_origin("redirect.test").is_some());
    }

    #[test]
    fn parse_go_modifiers_with_delete() {
        let yaml = r#"
origins:
  "mod.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    request_modifiers:
      - headers:
          set:
            X-Custom: hello
          delete:
            - X-Remove-Me
    response_modifiers:
      - headers:
          set:
            X-Powered-By: test
          delete:
            - Server
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("mod.test").unwrap();
        assert_eq!(origin.request_modifiers.len(), 1);
        let headers = origin.request_modifiers[0].headers.as_ref().unwrap();
        assert_eq!(headers.remove, vec!["X-Remove-Me"]);
    }

    #[test]
    fn parse_go_auth_field_alias() {
        let yaml = r#"
origins:
  "auth.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    auth:
      type: api_key
      api_keys:
        - test-key
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("auth.test").unwrap();
        assert!(origin.auth_config.is_some());
    }

    // --- Wave 5 / G5.1 KYA auth.type tests ---
    //
    // The OSS config compiler stores `authentication` as an opaque
    // `serde_json::Value`; runtime dispatch happens later in
    // `sbproxy-modules::compile_auth`. The OSS compiler keeps the
    // `kya` provider name reachable so an `sb.yml` carrying
    // `authentication.type: kya` compiles unchanged when a third-party
    // verifier plugin is wired through the `sbproxy-plugin` registry;
    // when no plugin is registered the runtime returns a clear
    // "no auth provider for type 'kya'" error.
    #[test]
    fn parse_kya_authentication_compiles() {
        let yaml = r#"
origins:
  "kya.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    authentication:
      type: kya
      issuers:
        - url: https://api.skyfire.io
          jwks_refresh_interval_secs: 3600
          negative_cache_ttl_secs: 300
          stale_grace_secs: 86400
          audience_check: hostname
      cache_ttl_secs: 3600
      fail_open: false
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("kya.test").unwrap();
        let auth = origin
            .auth_config
            .as_ref()
            .expect("kya authentication block must be preserved");
        assert_eq!(
            auth.get("type").and_then(|v| v.as_str()),
            Some("kya"),
            "authentication.type must round-trip to the snapshot"
        );
        let issuers = auth
            .get("issuers")
            .and_then(|v| v.as_array())
            .expect("issuers must round-trip");
        assert_eq!(issuers.len(), 1, "single issuer must round-trip");
        assert_eq!(
            issuers[0].get("url").and_then(|v| v.as_str()),
            Some("https://api.skyfire.io")
        );
    }

    #[test]
    fn parse_kya_authentication_minimal_compiles() {
        // Minimal config: only the required `type` and `issuers` array.
        // Defaults are filled in by the verifier at
        // `KyaConfig::validate` time, not by the OSS compiler.
        let yaml = r#"
origins:
  "kya-min.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    authentication:
      type: kya
      issuers:
        - url: https://issuer.example.com
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("kya-min.test").unwrap();
        assert!(origin.auth_config.is_some());
    }

    #[test]
    fn parse_kya_authentication_preserves_extra_fields() {
        // Operators may add forward-compat fields (e.g. `audit_sample_rate`)
        // that the OSS compiler does not type-check. The opaque-value
        // contract requires those fields to round-trip unchanged into
        // the snapshot so the verifier sees them.
        let yaml = r#"
origins:
  "kya-extra.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    authentication:
      type: kya
      issuers:
        - url: https://issuer.example.com
          audience_check: hostname
      cache_ttl_secs: 7200
      fail_open: true
      audit_sample_rate: 50
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("kya-extra.test").unwrap();
        let auth = origin.auth_config.as_ref().unwrap();
        assert_eq!(
            auth.get("audit_sample_rate").and_then(|v| v.as_u64()),
            Some(50),
            "forward-compat fields must round-trip to the verifier"
        );
        assert_eq!(auth.get("fail_open").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn parse_kya_authentication_under_go_auth_alias() {
        // The Go-compat `auth:` alias for `authentication:` must accept
        // `type: kya` the same way it accepts `type: api_key`.
        let yaml = r#"
origins:
  "kya-alias.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    auth:
      type: kya
      issuers:
        - url: https://issuer.example.com
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("kya-alias.test").unwrap();
        let auth = origin.auth_config.as_ref().unwrap();
        assert_eq!(auth.get("type").and_then(|v| v.as_str()), Some("kya"));
    }

    #[test]
    fn parse_auth_composition_list_round_trips_to_snapshot() {
        // WOR-2517: a list-form `authentication:` block is stored
        // opaque like the scalar form; the modules crate compiles it
        // into the OR composition at pipeline build. Entry order is
        // load-bearing (first success wins), so it must survive the
        // round trip.
        let yaml = r#"
origins:
  "composed.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    authentication:
      - type: api_key
        api_keys:
          - key-one
      - type: bearer
        tokens:
          - tok-one
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("composed.test").unwrap();
        let auth = origin.auth_config.as_ref().unwrap();
        let entries = auth.as_array().expect("list form must stay a list");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].get("type").and_then(|v| v.as_str()),
            Some("api_key")
        );
        assert_eq!(
            entries[1].get("type").and_then(|v| v.as_str()),
            Some("bearer")
        );
    }

    #[test]
    fn parse_go_compression_with_enable() {
        let yaml = r#"
origins:
  "comp.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    compression:
      enable: true
      algorithms:
        - gzip
        - br
      min_size: 64
      level: 6
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("comp.test").unwrap();
        let comp = origin.compression.as_ref().unwrap();
        assert!(comp.enabled);
        assert_eq!(comp.level, Some(6));
    }

    #[test]
    fn parse_go_session_config() {
        // Legacy key `session_config` still works via serde alias.
        let yaml = r#"
origins:
  "session.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    session_config:
      cookie_name: sbproxy_sid
      cookie_max_age: 3600
      cookie_same_site: Lax
      allow_non_ssl: true
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("session.test").unwrap();
        let session = origin.session.as_ref().unwrap();
        assert_eq!(session.cookie_name.as_deref(), Some("sbproxy_sid"));
        assert_eq!(session.max_age, Some(3600));
        assert_eq!(session.same_site.as_deref(), Some("Lax"));
        assert!(session.allow_non_ssl);
    }

    #[test]
    fn parse_canonical_session_key() {
        // New canonical key `session` works.
        let yaml = r#"
origins:
  "session.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    session:
      cookie_name: sbproxy_sid
      max_age: 3600
      same_site: Lax
      allow_non_ssl: true
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("session.test").unwrap();
        let session = origin.session.as_ref().unwrap();
        assert_eq!(session.cookie_name.as_deref(), Some("sbproxy_sid"));
        assert_eq!(session.max_age, Some(3600));
        assert_eq!(session.same_site.as_deref(), Some("Lax"));
        assert!(session.allow_non_ssl);
    }

    #[test]
    fn parse_forward_rules_and_fallback() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "routing.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-backend
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
          request_modifiers:
            - headers:
                set:
                  X-Routed-To: api-backend
      - rules:
          - path:
              exact: /health
        origin:
          id: health-static
          action:
            type: static
            status_code: 200
            content_type: application/json
            json_body:
              status: healthy
    fallback_origin:
      on_error: true
      add_debug_header: true
      origin:
        id: fb-fallback
        action:
          type: static
          status_code: 200
          json_body:
            source: fallback
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("routing.test").unwrap();
        assert_eq!(origin.forward_rules.len(), 2);
        assert!(origin.fallback_origin.is_some());

        // First forward rule has prefix /api/
        let rule0 = &origin.forward_rules[0];
        let rules_arr = rule0.get("rules").unwrap().as_array().unwrap();
        let path_obj = rules_arr[0].get("path").unwrap();
        assert_eq!(path_obj.get("prefix").unwrap().as_str().unwrap(), "/api/");

        // Second forward rule has exact /health
        let rule1 = &origin.forward_rules[1];
        let rules_arr = rule1.get("rules").unwrap().as_array().unwrap();
        let path_obj = rules_arr[0].get("path").unwrap();
        assert_eq!(path_obj.get("exact").unwrap().as_str().unwrap(), "/health");

        // Fallback has on_error: true
        let fb = origin.fallback_origin.as_ref().unwrap();
        assert!(fb.get("on_error").unwrap().as_bool().unwrap());
    }

    /// WOR-2482 review finding: a forward-rule modifier's `js_script`
    /// reaches `interpolate_config_vars` through the whole-rule JSON
    /// round-trip this function performs on every `forward_rules[]`
    /// entry. Before the fix, a `{{vars.X}}`-shaped literal inside the
    /// script body (naming a variable the origin actually defines) was
    /// silently rewritten with the variable's value rather than
    /// reaching the JS engine as authored, the same corruption
    /// `interpolate_skips_lua_script_keys` already pins for
    /// `lua_script`. End to end through `compile_config`, not the
    /// lower-level `interpolate_config_vars` unit test
    /// (`interpolate_skips_js_script_keys`, in the section below), so
    /// this proves the fix survives the forward-rule round-trip
    /// specifically.
    #[test]
    fn forward_rule_js_script_with_a_vars_pattern_is_not_interpolated() {
        let yaml = r#"
origins:
  "js-braces.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    variables:
      literal_marker: "SUBSTITUTED"
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          action:
            type: proxy
            url: http://127.0.0.1:18888
          request_modifiers:
            - js_script: |
                function modify_request(req, ctx) {
                  return { set_headers: { "x-literal": "{{vars.literal_marker}}" } };
                }
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("js-braces.test").unwrap();
        let script = origin.forward_rules[0]["origin"]["request_modifiers"][0]["js_script"]
            .as_str()
            .expect("js_script survives as a string");
        assert!(
            script.contains("{{vars.literal_marker}}"),
            "a js_script's {{{{vars.X}}}} pattern must stay literal, matching lua_script and \
             rego_module, not be resolved at compile time: {script}"
        );
        assert!(
            !script.contains("SUBSTITUTED"),
            "the script must not have been silently rewritten with the variable's value: {script}"
        );
    }

    // --- interpolate_config_vars tests ---

    #[test]
    fn interpolate_vars_in_json_string() {
        let vars: HashMap<String, serde_json::Value> = [
            ("service_name".to_string(), serde_json::json!("my-api")),
            ("version".to_string(), serde_json::json!("2.5.0")),
        ]
        .into_iter()
        .collect();
        let mut val = serde_json::json!("Service: {{vars.service_name}} v{{vars.version}}");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "Service: my-api v2.5.0");
    }

    #[test]
    fn interpolate_vars_in_nested_object() {
        let vars: HashMap<String, serde_json::Value> =
            [("host".to_string(), serde_json::json!("backend.local"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!({
            "url": "http://{{vars.host}}:8080",
            "nested": {
                "label": "{{vars.host}}"
            }
        });
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val["url"].as_str().unwrap(), "http://backend.local:8080");
        assert_eq!(val["nested"]["label"].as_str().unwrap(), "backend.local");
    }

    // WOR-1828: `variables.` is an accepted alias of `vars.`, and a
    // dotted tail walks nested objects, matching what the published
    // variables-template example has always written.
    #[test]
    fn interpolate_accepts_variables_alias_and_dotted_paths() {
        let vars: HashMap<String, serde_json::Value> = [
            ("api_version".to_string(), serde_json::json!("v2")),
            (
                "feature_flags".to_string(),
                serde_json::json!({"beta_api": false}),
            ),
        ]
        .into_iter()
        .collect();
        let mut val = serde_json::json!({
            "X-Api-Version": "{{ variables.api_version }}",
            "X-Beta-Api": "{{ variables.feature_flags.beta_api }}",
            "X-Short": "{{ vars.feature_flags.beta_api }}"
        });
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val["X-Api-Version"].as_str().unwrap(), "v2");
        assert_eq!(val["X-Beta-Api"].as_str().unwrap(), "false");
        assert_eq!(val["X-Short"].as_str().unwrap(), "false");
    }

    #[test]
    fn interpolate_env_in_json_string() {
        let _env = crate::test_env::EnvVarGuard::set(&[("SBPROXY_TEST_HOST", Some("env-backend"))]);
        let vars: HashMap<String, serde_json::Value> = HashMap::new();
        let mut val = serde_json::json!("http://{{env.SBPROXY_TEST_HOST}}:8080");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "http://env-backend:8080");
    }

    #[test]
    fn interpolate_skips_lua_script_keys() {
        let vars: HashMap<String, serde_json::Value> =
            [("name".to_string(), serde_json::json!("test"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!({
            "headers": {"X-Name": "{{vars.name}}"},
            "lua_script": "result.set_headers['X-Name'] = '{{vars.name}}'"
        });
        interpolate_config_vars(&mut val, &vars);
        // headers value should be interpolated
        assert_eq!(val["headers"]["X-Name"].as_str().unwrap(), "test");
        // lua_script should NOT be interpolated
        assert_eq!(
            val["lua_script"].as_str().unwrap(),
            "result.set_headers['X-Name'] = '{{vars.name}}'"
        );
    }

    /// WOR-2482 review finding: `js_script` was missing from the skip
    /// list `interpolate_skips_lua_script_keys` above pins for
    /// `lua_script`, so a forward-rule `js_script` containing a literal
    /// `{{vars.X}}` (a template-looking string the author meant to reach
    /// the JS engine verbatim, not a real template reference) was
    /// silently rewritten with the variable's value.
    #[test]
    fn interpolate_skips_js_script_keys() {
        let vars: HashMap<String, serde_json::Value> =
            [("name".to_string(), serde_json::json!("test"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!({
            "headers": {"X-Name": "{{vars.name}}"},
            "js_script": "result.set_headers['X-Name'] = '{{vars.name}}'"
        });
        interpolate_config_vars(&mut val, &vars);
        // headers value should be interpolated
        assert_eq!(val["headers"]["X-Name"].as_str().unwrap(), "test");
        // js_script should NOT be interpolated
        assert_eq!(
            val["js_script"].as_str().unwrap(),
            "result.set_headers['X-Name'] = '{{vars.name}}'"
        );
    }

    #[test]
    fn interpolate_unresolved_vars_left_as_is() {
        let vars: HashMap<String, serde_json::Value> = HashMap::new();
        let mut val = serde_json::json!("{{vars.unknown}}");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "{{vars.unknown}}");
    }

    #[test]
    fn interpolate_mixed_vars_and_env() {
        let _env = crate::test_env::EnvVarGuard::set(&[("SBPROXY_MIX_PORT", Some("9090"))]);
        let vars: HashMap<String, serde_json::Value> =
            [("host".to_string(), serde_json::json!("api.local"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!("http://{{vars.host}}:{{env.SBPROXY_MIX_PORT}}/api");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "http://api.local:9090/api");
    }

    #[test]
    fn interpolate_in_array_values() {
        let vars: HashMap<String, serde_json::Value> =
            [("tag".to_string(), serde_json::json!("v1"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!(["{{vars.tag}}", "literal", "{{vars.tag}}-latest"]);
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val[0].as_str().unwrap(), "v1");
        assert_eq!(val[1].as_str().unwrap(), "literal");
        assert_eq!(val[2].as_str().unwrap(), "v1-latest");
    }

    #[test]
    fn interpolate_in_error_page_body() {
        let vars: HashMap<String, serde_json::Value> = [
            ("service_name".to_string(), serde_json::json!("my-api")),
            ("version".to_string(), serde_json::json!("2.5.0")),
        ]
        .into_iter()
        .collect();
        let mut val = serde_json::json!({
            "status": [500, 502, 503],
            "content_type": "application/json",
            "template": true,
            "body": "{\"error\": true, \"service\": \"{{vars.service_name}}\", \"version\": \"{{vars.version}}\"}"
        });
        interpolate_config_vars(&mut val, &vars);
        assert!(val["body"].as_str().unwrap().contains("my-api"));
        assert!(val["body"].as_str().unwrap().contains("2.5.0"));
    }

    #[test]
    fn compile_config_propagates_origin_extensions() {
        // Opaque per-origin extensions must round-trip from the raw YAML
        // into the compiled snapshot so an extension can read its own
        // keys. The map stays generic: nothing in this workspace
        // interprets it.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    extensions:
      custom_metadata:
        enabled: true
        ttl_secs: 600
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("api.example.com").expect("origin");
        let custom = origin
            .extensions
            .get("custom_metadata")
            .expect("custom_metadata extension present after compile");
        assert!(custom.get("enabled").unwrap().as_bool().unwrap());
        assert_eq!(custom.get("ttl_secs").unwrap().as_u64().unwrap(), 600);
    }

    #[test]
    fn compile_config_interpolates_vars_in_modifiers() {
        let yaml = r#"
origins:
  "varmod.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    variables:
      service_name: "my-api"
      version: "2.5.0"
      team: "platform"
    request_modifiers:
      - headers:
          set:
            X-Service: "{{vars.service_name}}"
            X-Version: "{{vars.version}}"
            X-Team: "{{vars.team}}"
"#;
        let compiled = compile_config(yaml).unwrap();
        let origin = compiled.resolve_origin("varmod.test").unwrap();
        let headers = origin.request_modifiers[0].headers.as_ref().unwrap();
        assert_eq!(headers.set.get("X-Service").unwrap(), "my-api");
        assert_eq!(headers.set.get("X-Version").unwrap(), "2.5.0");
        assert_eq!(headers.set.get("X-Team").unwrap(), "platform");
    }

    // --- WOR-2166: messenger_settings is rejected, not compiled ---

    /// Every driver the block used to accept is refused, and the error
    /// explains why rather than just naming the key. The block used to
    /// build a live bus and attach it to the snapshot; nothing ever
    /// subscribed or published, so an operator who set this got a valid
    /// config and zero cross-replica events.
    #[test]
    fn messenger_settings_is_rejected_for_every_driver() {
        for driver in ["memory", "redis", "sqs", "gcp_pubsub", "invalid_backend"] {
            let yaml = format!(
                r#"
proxy:
  messenger_settings:
    driver: {driver}
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#
            );
            let err = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("driver {driver} must be refused"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("proxy.messenger_settings"),
                "error must name the key: {msg}"
            );
            assert!(
                msg.contains(driver),
                "error must name the configured driver: {msg}"
            );
            assert!(
                msg.contains("no runtime consumer"),
                "error must say the bus has no consumer in this build: {msg}"
            );
            assert!(
                msg.contains("WOR-2192"),
                "error must name the delivery defects that forbid restoring the drivers: {msg}"
            );
        }
    }

    /// The diagnostic has to leave the operator somewhere to go. Both
    /// documented uses of the bus have a working surface today, and the
    /// error names each one.
    #[test]
    fn messenger_rejection_names_the_surfaces_that_do_work() {
        let yaml = r#"
proxy:
  messenger_settings:
    driver: redis
    params:
      dsn: redis://127.0.0.1:6379
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let msg = format!(
            "{:#}",
            compile_config(yaml)
                .err()
                .expect("a configured bus must be refused")
        );
        assert!(
            msg.contains("proxy.config_authority"),
            "config distribution has a working surface and the error must name it: {msg}"
        );
        assert!(
            msg.contains("/admin/cache/purge"),
            "cache invalidation has a working surface and the error must name it: {msg}"
        );
        assert!(
            msg.contains("WOR-2192"),
            "the diagnostic must name the deleted-backend defects so they cannot return unnoticed: {msg}"
        );
    }

    #[test]
    fn compile_config_parses_agent_classes_top_level_block() {
        // G1.4 wire: the top-level `agent_classes:` block must
        // round-trip onto `CompiledConfig::agent_classes`.
        let yaml = r#"
agent_classes:
  catalog: merged
  hosted_feed:
    url: https://feed.sbproxy.dev/agents/v1.json
    bootstrap_keys:
      - "key1-base64"
  resolver:
    rdns_enabled: false
    cache_size: 5000
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        let ac = compiled
            .agent_classes
            .as_ref()
            .expect("agent_classes parsed");
        assert_eq!(ac.catalog, "merged");
        let feed = ac.hosted_feed.as_ref().expect("hosted_feed parsed");
        assert_eq!(feed.url, "https://feed.sbproxy.dev/agents/v1.json");
        assert_eq!(feed.bootstrap_keys, vec!["key1-base64".to_string()]);
        assert!(!ac.resolver.rdns_enabled);
        assert!(ac.resolver.bot_auth_keyid_enabled);
        assert_eq!(ac.resolver.cache_size, 5000);
    }

    #[test]
    fn compile_config_no_agent_classes_when_block_absent() {
        // Backwards compat: missing top-level block lands `None` and
        // the binary uses defaults.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        assert!(compiled.agent_classes.is_none());
    }

    #[test]
    fn compile_config_parses_inline_agent_class_entries() {
        let yaml = r#"
agent_classes:
  catalog: inline
  entries:
    - id: conformance-bot
      vendor: Conformance
      purpose: training
      expected_user_agent_pattern: "(?i)\\bConformanceBot/\\d"
      expected_reverse_dns_suffixes: []
      expected_keyids:
        - conformance-key
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        let ac = compiled
            .agent_classes
            .as_ref()
            .expect("agent_classes parsed");
        assert_eq!(ac.catalog, "inline");
        assert_eq!(ac.entries.len(), 1);
        assert_eq!(ac.entries[0]["id"], "conformance-bot");
        assert_eq!(ac.entries[0]["expected_keyids"][0], "conformance-key");
    }

    /// The rejection is scoped to configs that actually author the block.
    /// A config without `messenger_settings` is the overwhelming majority
    /// and must be untouched by WOR-2166.
    #[test]
    fn a_config_without_messenger_settings_still_compiles() {
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        assert!(compiled.resolve_origin("api.example.com").is_some());
    }

    // --- WOR-2310: the inert config-only keys are refused, not warned ---

    /// Wrap an origin body in a compilable document.
    fn origin_doc(body: &str) -> String {
        format!(
            r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
{body}
"#
        )
    }

    /// Each key used to compile with a warning. The warning was not
    /// enough: the snapshot still claimed a property the proxy did not
    /// have, and every one of these describes a resource limit or a
    /// retention window an operator would reasonably assume was enforced.
    ///
    /// The assertion checks the authored value appears in the message
    /// too. A refusal that names the key but not the value leaves an
    /// operator with several origins guessing which one to edit.
    #[test]
    fn inert_per_origin_keys_are_refused_and_the_error_names_the_value() {
        let cases = [
            (
                "    connection_pool:\n      max_connections: 64",
                "connection_pool.max_connections",
                "64",
                "concurrent_limit",
            ),
            (
                "    connection_pool:\n      max_lifetime_secs: 120",
                "connection_pool.max_lifetime_secs",
                "120",
                "timeouts.idle_ms",
            ),
            (
                "    sessions:\n      ttl_seconds: 3600",
                "sessions.ttl_seconds",
                "3600",
                "sessions.budget.max_per_window",
            ),
        ];

        for (body, key, value, replacement) in cases {
            let yaml = origin_doc(body);
            let err = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("{key} must be refused"));
            let msg = format!("{err:#}");
            assert!(msg.contains(key), "error must name the key: {msg}");
            assert!(
                msg.contains(value),
                "error must quote the authored value: {msg}"
            );
            assert!(
                msg.contains(replacement),
                "error must name the surface that works: {msg}"
            );
            assert!(
                msg.contains("api.example.com"),
                "error must name the origin: {msg}"
            );
        }
    }

    /// `traffic_capture` is untyped, so it has no value worth quoting.
    /// The message has to carry the replacement instead.
    #[test]
    fn traffic_capture_is_refused_and_points_at_mirror() {
        let yaml = origin_doc("    traffic_capture:\n      sample_rate: 0.1");
        let msg = format!(
            "{:#}",
            compile_config(&yaml)
                .err()
                .expect("traffic_capture must be refused")
        );
        assert!(
            msg.contains("traffic_capture"),
            "error must name the key: {msg}"
        );
        assert!(
            msg.contains("mirror"),
            "error must name the working surface: {msg}"
        );
    }

    /// The one live field on the block keeps working. Refusing the whole
    /// of `connection_pool` would take the legacy idle spelling with it,
    /// and that one does feed the resolved upstream deadline.
    #[test]
    fn connection_pool_idle_timeout_still_compiles_on_its_own() {
        let yaml = origin_doc("    connection_pool:\n      idle_timeout_secs: 30");
        let compiled = compile_config(&yaml).expect("the legacy idle spelling stays supported");
        let origin = compiled
            .resolve_origin("api.example.com")
            .expect("origin compiles");
        assert_eq!(
            origin.timeouts.idle,
            std::time::Duration::from_secs(30),
            "the legacy key must still feed the resolved idle deadline"
        );
    }

    /// A sessions block without the refused field is untouched: capture
    /// and the budget gate are both live and must keep compiling.
    #[test]
    fn sessions_without_ttl_still_compiles() {
        let yaml = origin_doc("    sessions:\n      capture: true");
        compile_config(&yaml).expect("sessions capture stays supported");
    }

    /// The proxy-level twin of the origin keys above. It named a file the
    /// proxy never opened, so a maintained catalog and a missing one
    /// behaved identically.
    #[test]
    fn device_parser_file_is_refused_and_points_at_the_override_that_works() {
        let yaml = r#"
proxy:
  device_parser_file: "/etc/sbproxy/devices.yaml"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let msg = format!(
            "{:#}",
            compile_config(yaml)
                .err()
                .expect("device_parser_file must be refused")
        );
        assert!(
            msg.contains("proxy.device_parser_file"),
            "error must name the key: {msg}"
        );
        assert!(
            msg.contains("/etc/sbproxy/devices.yaml"),
            "error must quote the path that was never read: {msg}"
        );
        assert!(
            msg.contains("ai_providers_file"),
            "error must name the override that does work: {msg}"
        );
    }

    // --- WOR-2325: the rest of the keys that parse and govern nothing ---

    /// The refusal text for a document that must not compile.
    ///
    /// `compile_config` returns a `CompiledConfig`, which is not `Debug`,
    /// so `expect_err` does not compile against it. A `let ... else`
    /// binding gets the error out without asking `Debug` of the success
    /// type. The rendering is `{:#}` so the whole `anyhow` context chain
    /// is searched, not just the outermost message.
    fn refusal_message(yaml: &str, what: &str) -> String {
        let Err(error) = compile_config(yaml) else {
            panic!("{what} must not compile");
        };
        format!("{error:#}")
    }

    /// Wrap a `proxy:` body in a compilable document.
    fn proxy_doc(body: &str) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 8080
{body}
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#
        )
    }

    /// All five legacy secrets keys used to parse, validate, and select
    /// nothing: `install_secret_resolver` walks `proxy.secrets.backends`
    /// and reads no other field on the block. Each case here compiled
    /// silently before this refusal existed.
    ///
    /// The Vault three are the reason this is an error rather than one
    /// more boot warning. An operator who authored an address, a mount,
    /// and a token believed the proxy held a Vault session, and it had
    /// never opened a connection.
    #[test]
    fn legacy_secrets_keys_are_refused_with_the_named_backend_migration() {
        // `hashicorp.addr` has no serde default, so every case on that
        // block has to carry it or the typed parse fails first and the
        // case proves nothing about the refusal.
        let cases = [
            ("    backend: hashicorp", "proxy.secrets.backend"),
            ("    fallback: env", "proxy.secrets.fallback"),
            (
                "    hashicorp:\n      addr: https://vault.example/v1",
                "proxy.secrets.hashicorp.addr",
            ),
            (
                "    hashicorp:\n      addr: https://vault.example/v1\n      mount: secret/prod",
                "proxy.secrets.hashicorp.mount",
            ),
            (
                "    hashicorp:\n      addr: https://vault.example/v1\n      token: t0ken",
                "proxy.secrets.hashicorp.token",
            ),
        ];

        for (body, key) in cases {
            let yaml = proxy_doc(&format!("  secrets:\n{body}"));
            let msg = refusal_message(&yaml, key);
            assert!(msg.contains(key), "error must name the key: {msg}");
            assert!(
                msg.contains("proxy.secrets.backends"),
                "error must name the replacement surface: {msg}"
            );
            assert!(
                msg.contains("vault://primary/"),
                "error must show the reference shape the migration produces: {msg}"
            );
        }
    }

    /// The refusal must not echo the credential it is refusing. An error
    /// string lands in logs, in CI output, and in bug reports, so naming
    /// the key is the whole job and quoting the value would be a leak.
    #[test]
    fn the_legacy_vault_token_refusal_does_not_echo_the_token() {
        let yaml = proxy_doc(
            "  secrets:\n    hashicorp:\n      addr: https://vault.example/v1\n      \
             token: hvs.SUPERSECRETVALUE",
        );
        let msg = refusal_message(&yaml, "proxy.secrets.hashicorp.token");
        assert!(
            !msg.contains("hvs.SUPERSECRETVALUE"),
            "the refusal must name the key and never its value: {msg}"
        );
    }

    /// `map` is live: a non-empty map installs the process secret
    /// resolver, and its keys suppress the `missing-vault-key` finding
    /// that exits `sbproxy plan` with 3. Refusing it alongside its legacy
    /// neighbors would break both. `rotation` is reserved surface.
    #[test]
    fn the_live_and_reserved_secrets_keys_are_not_swept_up() {
        let yaml = proxy_doc(
            "  secrets:\n    map:\n      jwt_signing_key: KV_JWT_KEY\n    \
             rotation:\n      grace_period_secs: 300\n      re_resolve_interval_secs: 60",
        );
        compile_config(&yaml).expect("proxy.secrets.map and .rotation stay supported");
    }

    /// A config on the current shape must not be caught by the scan that
    /// finds the legacy one, or the migration the error asks for lands the
    /// operator on a second error.
    #[test]
    fn the_named_backend_shape_the_refusal_asks_for_compiles() {
        let yaml = proxy_doc(
            "  secrets:\n    backends:\n      - type: local\n        name: primary\n        \
             entries:\n          api_key: value",
        );
        compile_config(&yaml).expect("the migration target must compile");
    }

    /// The route this flag gates is not installed: there is no
    /// `GET /api/v1/key` handler anywhere in the tree, and the field's
    /// only readers are `#[cfg(test)]`. Setting it used to compile.
    #[test]
    fn key_introspection_is_refused_because_no_such_route_is_installed() {
        let yaml = proxy_doc(
            "  key_management:\n    enabled: true\n    governance:\n      \
             key_introspection: true",
        );
        let msg = refusal_message(&yaml, "key_introspection: true");
        assert!(
            msg.contains("proxy.key_management.governance.key_introspection"),
            "error must name the key: {msg}"
        );
        assert!(
            msg.contains("/admin/keys/"),
            "error must name the surface that does answer: {msg}"
        );
    }

    /// The store backend alone decides the system of record, so this
    /// boolean offered a choice that does not exist. Zero reads.
    #[test]
    fn redis_source_of_truth_is_refused_because_the_backend_already_decides() {
        let yaml = proxy_doc(
            "  key_management:\n    enabled: true\n    store:\n      backend: redis\n      \
             url: redis://127.0.0.1:6379\n      redis_source_of_truth: true",
        );
        let msg = refusal_message(&yaml, "redis_source_of_truth: true");
        assert!(
            msg.contains("proxy.key_management.store.redis_source_of_truth"),
            "error must name the key: {msg}"
        );
        assert!(
            msg.contains("backend"),
            "error must name the setting that actually decides: {msg}"
        );
    }

    /// Both booleans default to false and false is what this build does,
    /// so the operator who wrote it has nothing to fix. Refusing on
    /// presence would stop a boot for a config that is already honest.
    #[test]
    fn the_key_management_booleans_set_to_false_still_compile() {
        let yaml = proxy_doc(
            "  key_management:\n    enabled: true\n    governance:\n      \
             key_introspection: false\n    store:\n      redis_source_of_truth: false",
        );
        compile_config(&yaml).expect("false describes the build and stays accepted");
    }

    /// Wrap a single forward rule around the caller's `origin:` body.
    fn forward_rule_doc(origin_body: &str) -> String {
        format!(
            r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
{origin_body}
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
"#
        )
    }

    /// The inline forward-origin runtime reads `origin.action` and
    /// `origin.request_modifiers`; OpenAPI emission reads `origin.id`.
    /// These three are read by nobody, and all three used to compile.
    ///
    /// Every message must name the rule as well as the origin: a config
    /// with several forward rules leaves the operator guessing otherwise.
    #[test]
    fn informational_forward_origin_fields_are_refused_one_by_one() {
        let cases = [
            ("          hostname: api-b", "origin.hostname", "action.url"),
            (
                "          workspace_id: acme",
                "origin.workspace_id",
                "tenant_id",
            ),
            ("          version: v2", "origin.version", "origin.id"),
        ];

        for (line, key, replacement) in cases {
            let yaml = forward_rule_doc(line);
            let msg = refusal_message(&yaml, key);
            assert!(msg.contains(key), "error must name the key: {msg}");
            assert!(
                msg.contains("forward_rules[0]"),
                "error must name the rule that carries it: {msg}"
            );
            assert!(
                msg.contains("api.example.com"),
                "error must name the origin: {msg}"
            );
            assert!(
                msg.contains(replacement),
                "error must name a surface that is read: {msg}"
            );
        }
    }

    /// With `origin.id` set, the rule has a name of its own and the error
    /// should use it rather than making the operator count list entries.
    #[test]
    fn a_forward_rule_refusal_names_the_rule_by_its_origin_id() {
        let yaml = forward_rule_doc("          id: api-backend\n          hostname: api-backend");
        let msg = refusal_message(&yaml, "origin.hostname");
        assert!(
            msg.contains("origin id `api-backend`"),
            "error must identify the rule by the identifier that is read: {msg}"
        );
    }

    /// `id`, `action`, and `request_modifiers` are the three fields the
    /// forward-origin path actually reads. Refusing their neighbors must
    /// not touch them.
    #[test]
    fn the_forward_origin_fields_that_are_read_still_compile() {
        let yaml = forward_rule_doc(
            r#"          id: api-backend
          request_modifiers:
            - headers:
                set:
                  X-Route: api"#,
        );
        compile_config(&yaml).expect("the read forward-origin fields stay supported");
    }

    /// The most serious of the sweep. Both runtime entry points gate on
    /// the presence of the `cors:` block and neither reads this boolean,
    /// so `enable: false` compiled cleanly and served CORS to everyone the
    /// operator had just tried to shut out.
    #[test]
    fn cors_enable_false_is_refused_because_it_did_not_disable_cors() {
        let yaml = origin_doc(
            "    cors:\n      enable: false\n      \
             allowed_origins: [\"https://app.example.com\"]",
        );
        let msg = refusal_message(&yaml, "cors.enable: false");
        assert!(
            msg.contains("cors.enable"),
            "error must name the key: {msg}"
        );
        assert!(
            msg.contains("api.example.com"),
            "error must name the origin: {msg}"
        );
        assert!(
            msg.contains("delete the whole `cors:` block"),
            "error must say that removing the block is the only way to disable CORS: {msg}"
        );
    }

    /// The alias spelling deserializes into the same field, so the
    /// operator who wrote `enabled: false` was misled in exactly the same
    /// way and gets exactly the same refusal.
    #[test]
    fn the_cors_enabled_alias_spelling_is_refused_the_same_way() {
        let yaml = origin_doc(
            "    cors:\n      enabled: false\n      \
             allowed_origins: [\"https://app.example.com\"]",
        );
        let msg = refusal_message(&yaml, "cors.enabled: false");
        assert!(
            msg.contains("cors.enable"),
            "the alias must reach the same refusal: {msg}"
        );
    }

    /// The asymmetry is deliberate. `true` describes what the block
    /// already does, so the operator who wrote it was not misled and has
    /// nothing to fix, and the archived schema-v1 fixtures that carry it
    /// must keep compiling unmodified.
    #[test]
    fn cors_enable_true_still_compiles_because_it_describes_the_build() {
        let yaml = origin_doc(
            "    cors:\n      enable: true\n      \
             allowed_origins: [\"https://app.example.com\"]",
        );
        let compiled = compile_config(&yaml).expect("`enable: true` agrees with the runtime");
        let origin = compiled
            .resolve_origin("api.example.com")
            .expect("origin compiles");
        assert_eq!(
            origin
                .cors
                .as_ref()
                .expect("cors block survives compilation")
                .allowed_origins,
            vec!["https://app.example.com"]
        );
    }

    /// A `cors:` block with no `enable` at all is the shape the refusal
    /// asks for, so it has to compile.
    #[test]
    fn a_cors_block_without_the_legacy_flag_compiles() {
        let yaml = origin_doc("    cors:\n      allowed_origins: [\"https://app.example.com\"]");
        compile_config(&yaml).expect("the shape the refusal asks for must compile");
    }

    // --- WOR-2311: origin-level rate_limit_headers is removed ---

    /// The block parsed for years and was never consumed; header emission
    /// lives on the rate-limiting policy. The rejection must name the
    /// origin and point the operator at the policy-level `headers` block
    /// rather than bouncing the key as a generic unknown field.
    #[test]
    fn removed_rate_limit_headers_key_is_rejected_with_a_pointer_at_the_policy() {
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    rate_limit_headers:
      enabled: true
"#;
        let msg = format!(
            "{:#}",
            compile_config(yaml)
                .err()
                .expect("the removed origin-level key must be refused")
        );
        assert!(
            msg.contains("rate_limit_headers"),
            "error must name the removed key: {msg}"
        );
        assert!(
            msg.contains("api.example.com"),
            "error must name the offending origin: {msg}"
        );
        assert!(
            msg.contains("type: rate_limiting"),
            "error must point at the policy-level configuration: {msg}"
        );
    }

    /// The migration target named by the rejection has to compile, or the
    /// diagnostic points at a dead end.
    #[test]
    fn the_policy_level_rate_limit_headers_block_still_compiles() {
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    policies:
      - type: rate_limiting
        requests_per_minute: 600
        headers:
          enabled: true
          include_retry_after: true
"#;
        let compiled = compile_config(yaml).expect("the policy-level headers block is live");
        assert!(compiled.resolve_origin("api.example.com").is_some());
    }

    // --- WOR-2311: prefix purge is a no-op on hashed cache backends ---

    /// Counts compile-time warnings that name the hashed-backend purge
    /// gap, so the assertions cannot pass on an unrelated warning.
    struct PurgeWarnCounter(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for PurgeWarnCounter {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target().starts_with("sbproxy_config")
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct SeenGapMessage(bool);
            impl tracing::field::Visit for SeenGapMessage {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message"
                        && format!("{value:?}").contains("mutation requests evict nothing")
                    {
                        self.0 = true;
                    }
                }
            }
            if *event.metadata().level() == tracing::Level::WARN {
                let mut visitor = SeenGapMessage(false);
                event.record(&mut visitor);
                if visitor.0 {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn purge_gap_warnings_for(yaml: &str) -> usize {
        let warnings = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compiled = tracing::subscriber::with_default(
            PurgeWarnCounter(std::sync::Arc::clone(&warnings)),
            || compile_config(yaml),
        );
        compiled.expect("the backend + invalidate_on_mutation combination compiles; it only warns");
        warnings.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The `file` backend names entries by the SHA-256 of the cache key,
    /// so `invalidate_on_mutation` (on by default) has nothing to scan and
    /// evicts nothing. The operator hears that at config compile, once per
    /// affected origin.
    #[test]
    fn invalidate_on_mutation_on_the_file_backend_warns_at_compile() {
        let yaml = r#"
proxy:
  response_cache_store:
    backend:
      type: file
      path: /var/cache/sbproxy/responses
origins:
  "cache.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    response_cache:
      enabled: true
"#;
        assert_eq!(
            purge_gap_warnings_for(yaml),
            1,
            "the file backend + default invalidate_on_mutation must warn exactly once"
        );
    }

    #[test]
    fn invalidate_on_mutation_on_the_memcached_backend_warns_at_compile() {
        let yaml = r#"
proxy:
  response_cache_store:
    backend:
      type: memcached
origins:
  "cache.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    response_cache:
      enabled: true
"#;
        assert_eq!(
            purge_gap_warnings_for(yaml),
            1,
            "memcached offers no key scan, so the combination must warn exactly once"
        );
    }

    /// The warning is scoped to the gap. A scannable backend, a disabled
    /// cache, or an explicit opt-out of mutation invalidation stays quiet.
    #[test]
    fn scannable_backends_and_opted_out_origins_do_not_warn() {
        let memory_backend = r#"
proxy:
  response_cache_store:
    backend:
      type: memory
origins:
  "cache.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    response_cache:
      enabled: true
"#;
        assert_eq!(purge_gap_warnings_for(memory_backend), 0);

        let opted_out = r#"
proxy:
  response_cache_store:
    backend:
      type: file
      path: /var/cache/sbproxy/responses
origins:
  "cache.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    response_cache:
      enabled: true
      invalidate_on_mutation: false
"#;
        assert_eq!(purge_gap_warnings_for(opted_out), 0);

        let cache_disabled = r#"
proxy:
  response_cache_store:
    backend:
      type: file
      path: /var/cache/sbproxy/responses
origins:
  "cache.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        assert_eq!(purge_gap_warnings_for(cache_disabled), 0);
    }

    // --- Wave 4 day-4 auto-wire tests (G4.1 + G4.10 + G4.4) ---

    // --- Wave 4 day-4 auto-wire tests: content_negotiate ---

    #[test]
    fn auto_wire_skips_origins_without_ai_crawl_or_wave4_transforms() {
        // Plain proxy origin: no ai_crawl_control, no wave4 transforms.
        // The auto-prepend must stay out of the way.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(
            origin.auto_content_negotiate.is_none(),
            "non-content-shaped origin gets no synthesised content_negotiate"
        );
        assert!(
            origin.transform_configs.is_empty(),
            "non-content-shaped origin keeps an empty transforms list"
        );
    }

    #[test]
    fn auto_wire_prepends_content_negotiate_when_ai_crawl_control_present() {
        // ai_crawl_control on its own: the synthesised
        // `content_negotiate` config rides through to CompiledOrigin
        // so the runtime can mount the resolver.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        let auto = origin
            .auto_content_negotiate
            .as_ref()
            .expect("ai_crawl_control => synthesised content_negotiate");
        assert_eq!(
            auto.get("type").and_then(|v| v.as_str()),
            Some("content_negotiate"),
            "auto config has the right type discriminator"
        );
    }

    #[test]
    fn auto_wire_recognises_pay_per_crawl_alias() {
        // `pay_per_crawl` is the legacy alias for `ai_crawl_control`.
        // The auto-wire must recognise both spellings.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    policies:
      - type: pay_per_crawl
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        assert!(
            origin.auto_content_negotiate.is_some(),
            "pay_per_crawl alias also triggers the auto-wire"
        );
    }

    #[test]
    fn auto_wire_fires_when_only_a_wave4_transform_is_authored() {
        // No ai_crawl_control on this origin, but the operator authors
        // a wave4 transform. The synthesised content_negotiate still
        // appears so the resolver can stamp ctx fields.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    transforms:
      - type: json_envelope
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        assert!(origin.auto_content_negotiate.is_some());
    }

    // --- Wave 4 day-4 transform-chain auto-wire tests (G4.10 / G4.4) ---

    #[test]
    fn auto_wire_prepends_default_transform_chain_when_ai_crawl_control_present() {
        // The four-transform default chain in declared order:
        //   boilerplate -> html_to_markdown -> citation_block -> json_envelope.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        let names: Vec<&str> = origin
            .transform_configs
            .iter()
            .map(|t| t.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec![
                "boilerplate",
                "html_to_markdown",
                "citation_block",
                "json_envelope",
            ],
            "default chain is auto-prepended when ai_crawl_control is configured and no transforms are authored"
        );
    }

    #[test]
    fn auto_wire_keeps_operator_authored_transforms_intact() {
        // When the operator authors a `transforms:` list, the auto-wire
        // backs off entirely. The operator's list is preserved as-is.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
    transforms:
      - type: html_to_markdown
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        // Auto-content-negotiate still fires (operator may have wired
        // their own transforms but still wants the resolver to stamp
        // ctx). The transform list, however, is left alone.
        assert!(origin.auto_content_negotiate.is_some());
        assert_eq!(
            origin.transform_configs.len(),
            1,
            "operator's authored transform list survives the auto-wire"
        );
        assert_eq!(
            origin.transform_configs[0]
                .get("type")
                .and_then(|v| v.as_str()),
            Some("html_to_markdown")
        );
    }

    #[test]
    fn auto_wire_pay_per_crawl_alias_also_prepends_default_chain() {
        // Confirm the legacy policy alias triggers the same default chain.
        let yaml = r#"
origins:
  shaped.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>x</h1>"
    policies:
      - type: pay_per_crawl
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("shaped.example.com").unwrap();
        assert_eq!(
            origin.transform_configs.len(),
            4,
            "default chain still fires under the legacy policy name"
        );
    }

    // --- WOR-2565: deprecation block compilation ---

    fn dep_yaml(block: &str) -> String {
        format!(
            r#"
origins:
  dep.example.com:
    deprecation:
{block}
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#
        )
    }

    #[test]
    fn deprecation_full_block_compiles_with_precomputed_headers() {
        let yaml = dep_yaml(
            "      deprecated: 2026-09-01\n      sunset: 2026-12-31T23:59:59Z\n      successor: https://api.example.com/v2/\n      link: https://developer.example.com/deprecation\n",
        );
        let compiled = compile_config(&yaml).expect("compile");
        let origin = compiled.resolve_origin("dep.example.com").unwrap();
        let dep = origin.deprecation.as_ref().expect("block compiles");
        assert_eq!(dep.deprecation_header.as_deref(), Some("@1788220800"));
        assert_eq!(
            dep.sunset_header.as_deref(),
            Some("Thu, 31 Dec 2026 23:59:59 GMT")
        );
        assert_eq!(
            dep.successor.as_deref(),
            Some("https://api.example.com/v2/")
        );
        assert!(!dep.gone_after_sunset, "serve is the default posture");
    }

    #[test]
    fn deprecation_sunset_before_deprecated_fails_config_load() {
        // RFC 9745 section 3: the Sunset timestamp MUST NOT be earlier
        // than the Deprecation one.
        let yaml = dep_yaml("      deprecated: 2026-09-01\n      sunset: 2026-08-31\n");
        let err = match compile_config(&yaml) {
            Ok(_) => panic!("compile must reject sunset earlier than deprecated"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("RFC 9745") && err.contains("dep.example.com"),
            "error must name the rule and the origin; got: {err}"
        );
    }

    #[test]
    fn deprecation_unparseable_date_fails_config_load() {
        let yaml = dep_yaml("      deprecated: next tuesday\n");
        let err = match compile_config(&yaml) {
            Ok(_) => panic!("compile must reject an unparseable date"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("RFC 3339") && err.contains("next tuesday"),
            "error must name the accepted formats and the bad value; got: {err}"
        );
    }

    #[test]
    fn deprecation_bare_true_compiles_and_emits_no_deprecation_header() {
        // RFC 9745 requires a Date value; the draft-era literal `true`
        // did not survive into the RFC. The flag still compiles (it
        // drives spec emission and metrics), announces no instant, and
        // a configured sunset still emits.
        let yaml = dep_yaml("      deprecated: true\n      sunset: 2027-01-01\n");
        let compiled = compile_config(&yaml).expect("bare `true` must compile");
        let origin = compiled.resolve_origin("dep.example.com").unwrap();
        let dep = origin.deprecation.as_ref().expect("block compiles");
        assert_eq!(dep.deprecation_header, None);
        assert_eq!(dep.deprecated_at, None);
        assert_eq!(
            dep.sunset_header.as_deref(),
            Some("Fri, 01 Jan 2027 00:00:00 GMT")
        );
    }

    #[test]
    fn deprecation_false_fails_config_load() {
        let yaml = dep_yaml("      deprecated: false\n");
        let err = match compile_config(&yaml) {
            Ok(_) => panic!("compile must reject `deprecated: false`"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("remove the `deprecation:` block"),
            "error must say what to do instead; got: {err}"
        );
    }

    #[test]
    fn deprecation_gone_without_sunset_fails_config_load() {
        let yaml = dep_yaml("      deprecated: 2026-09-01\n      after_sunset: gone\n");
        let err = match compile_config(&yaml) {
            Ok(_) => panic!("compile must reject `gone` with no sunset"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("after_sunset") && err.contains("never take effect"),
            "error must explain the dead posture; got: {err}"
        );
    }

    #[test]
    fn deprecation_empty_block_fails_config_load() {
        let yaml = dep_yaml("      successor: https://api.example.com/v2/\n");
        let err = match compile_config(&yaml) {
            Ok(_) => panic!("compile must reject a block announcing nothing"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("neither `deprecated` nor `sunset`"),
            "error must name the missing fields; got: {err}"
        );
    }

    #[test]
    fn forward_rule_deprecation_is_validated_at_config_compile() {
        // The per-rule block must refuse at compile time too, not at
        // first request through the runtime pipeline compiler.
        let yaml = r#"
origins:
  dep.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    forward_rules:
      - rules:
          - path:
              prefix: /v1/
        deprecation:
          deprecated: 2026-09-01
          sunset: 2020-01-01
        origin:
          action:
            type: static
            status_code: 200
            content_type: text/plain
            body: "v1"
"#;
        let err = match compile_config(yaml) {
            Ok(_) => panic!("compile must reject the rule's bad sunset"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("forward rule 0") && err.contains("RFC 9745"),
            "error must name the rule and the reason; got: {err}"
        );
    }

    // --- Wave 4 / G4.5: Content-Signal closed-enum validation ---

    #[test]
    fn content_signal_valid_value_compiles_to_static_str() {
        let yaml = r#"
origins:
  signal.example.com:
    content_signal: ai-train
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("signal.example.com").unwrap();
        assert_eq!(origin.content_signal, Some("ai-train"));
    }

    #[test]
    fn content_signal_invalid_value_fails_config_load() {
        // Closed-enum check: any value outside {ai-train, search,
        // ai-input} must error out so the proxy never silently
        // suppresses the response header on a typo.
        let yaml = r#"
origins:
  signal.example.com:
    content_signal: junk
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
"#;
        let result = compile_config(yaml);
        let err = match result {
            Ok(_) => panic!("compile must reject content_signal: junk (closed enum)"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("content_signal"),
            "error message must reference content_signal; got: {err}"
        );
    }

    #[test]
    fn content_signal_absent_compiles_with_none() {
        let yaml = r#"
origins:
  signal.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("signal.example.com").unwrap();
        assert!(origin.content_signal.is_none());
    }

    // --- WOR-805: Web Bot Auth signing identity validation ---

    #[test]
    fn web_bot_auth_valid_seed_compiles() {
        let yaml = r#"
proxy:
  web_bot_auth:
    key_id: sbproxy-2026
    ed25519_seed_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
origins:
  a.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        let compiled = compile_config(yaml).expect("compile");
        let wba = compiled.server.web_bot_auth.expect("web_bot_auth present");
        assert_eq!(wba.key_id, "sbproxy-2026");
    }

    #[test]
    fn web_bot_auth_bad_seed_length_fails_config_load() {
        let yaml = r#"
proxy:
  web_bot_auth:
    key_id: sbproxy-2026
    ed25519_seed_hex: "deadbeef"
origins:
  a.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        match compile_config(yaml) {
            Ok(_) => panic!("short seed must fail config load"),
            Err(e) => assert!(
                e.to_string().contains("ed25519_seed_hex"),
                "error must reference the seed field; got: {e}"
            ),
        }
    }

    #[test]
    fn web_bot_auth_non_hex_seed_fails_config_load() {
        let yaml = r#"
proxy:
  web_bot_auth:
    key_id: sbproxy-2026
    ed25519_seed_hex: "zzzz456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
origins:
  a.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        assert!(compile_config(yaml).is_err(), "non-hex seed must fail");
    }

    #[test]
    fn web_bot_auth_empty_key_id_fails_config_load() {
        let yaml = r#"
proxy:
  web_bot_auth:
    key_id: ""
    ed25519_seed_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
origins:
  a.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        match compile_config(yaml) {
            Ok(_) => panic!("empty key_id must fail config load"),
            Err(e) => assert!(e.to_string().contains("key_id"), "got: {e}"),
        }
    }

    // --- WOR-2318: the audit trail's durable form ---

    /// Wrap an `audit:` block in the smallest document that compiles.
    /// `extra_proxy` is spliced under `proxy:`.
    fn audit_yaml(audit: &str, extra_proxy: &str) -> String {
        format!(
            r#"
proxy:{extra_proxy}
audit:
{audit}
origins:
  a.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#
        )
    }

    /// A `proxy:` body carrying the one signing identity `sign_with`
    /// resolves.
    const AUDIT_SIGNER: &str = r#"
  web_bot_auth:
    key_id: sbproxy-audit
    ed25519_seed_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#;

    #[test]
    fn audit_sink_memory_compiles_and_asks_for_nothing_else() {
        let compiled = compile_config(&audit_yaml("  sink: memory", " {}")).expect("compile");
        let audit = compiled.audit.expect("audit block survives compilation");
        assert_eq!(audit.sink, AuditSinkKind::Memory);
        assert!(audit.path.is_none());
        assert!(audit.sign_with.is_none());
    }

    #[test]
    fn audit_sink_tracing_is_refused_with_a_migration_path() {
        let error = compile_config(&audit_yaml("  sink: tracing", " {}"))
            .err()
            .expect("a value that selects nothing must not compile");
        let message = error.to_string();
        assert!(
            message.contains("tracing"),
            "the refusal names the removed value: {message}"
        );
        assert!(
            message.contains("memory") && message.contains("chain"),
            "and names both replacements: {message}"
        );
    }

    #[test]
    fn audit_chain_compiles_with_a_path_and_a_resolvable_identity() {
        let yaml = audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        );
        let compiled = compile_config(&yaml).expect("compile");
        let audit = compiled.audit.expect("audit block survives compilation");
        assert_eq!(audit.sink, AuditSinkKind::Chain);
        assert_eq!(
            audit.path.as_deref(),
            Some("/var/lib/sbproxy/security-audit.jsonl")
        );
    }

    #[test]
    fn audit_chain_without_a_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("a chain with no file must not compile");
        assert!(
            error.to_string().contains("audit.path"),
            "the refusal names the missing key: {error}"
        );
    }

    #[test]
    fn audit_chain_without_a_signing_identity_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("an unsigned chain must not compile");
        assert!(
            error.to_string().contains("audit.sign_with"),
            "the refusal names the missing key: {error}"
        );
    }

    #[test]
    fn audit_chain_signing_identity_must_exist() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            " {}",
        ))
        .err()
        .expect("naming an absent identity must not compile");
        assert!(
            error.to_string().contains("not configured"),
            "the refusal says the identity is absent: {error}"
        );
    }

    #[test]
    fn audit_chain_rejects_an_unknown_signing_identity() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.some_future_key",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("an unresolvable identity must not compile");
        assert!(
            error.to_string().contains("proxy.web_bot_auth"),
            "the refusal names what is on offer: {error}"
        );
    }

    #[test]
    fn a_path_under_the_memory_sink_is_refused_rather_than_ignored() {
        // The dangerous shape: it looks configured and writes nothing.
        let error = compile_config(&audit_yaml(
            "  sink: memory\n  path: /var/lib/sbproxy/security-audit.jsonl",
            " {}",
        ))
        .err()
        .expect("a path nothing writes to must not compile");
        assert!(
            error.to_string().contains("audit.path"),
            "the refusal names the key that would be ignored: {error}"
        );
    }

    // --- WOR-2478: the `config_path` channel ---

    #[test]
    fn a_config_path_under_the_memory_sink_is_refused_rather_than_ignored() {
        // The dangerous shape, same as `audit.path` under `sink: memory`:
        // it reads as configured and chains nothing.
        let error = compile_config(&audit_yaml(
            "  sink: memory\n  config_path: /var/lib/sbproxy/config-audit.jsonl",
            " {}",
        ))
        .err()
        .expect("a config_path nothing writes to must not compile");
        assert!(
            error.to_string().contains("audit.config_path"),
            "the refusal names the key that would be ignored: {error}"
        );
        assert!(
            error.to_string().contains("audit.sink: chain"),
            "the refusal names what config_path requires: {error}"
        );
    }

    #[test]
    fn a_config_path_equal_to_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             config_path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("a config_path that shares the chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the config channel cannot share the security chain file; the two payload types \
             verify separately"
        );
    }

    #[test]
    fn audit_chain_compiles_with_a_path_sign_with_and_a_distinct_config_path() {
        let yaml = audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             config_path: /var/lib/sbproxy/config-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        );
        let compiled = compile_config(&yaml).expect("compile");
        let audit = compiled.audit.expect("audit block survives compilation");
        assert_eq!(audit.sink, AuditSinkKind::Chain);
        assert_eq!(
            audit.path.as_deref(),
            Some("/var/lib/sbproxy/security-audit.jsonl")
        );
        assert_eq!(
            audit.config_path.as_deref(),
            Some("/var/lib/sbproxy/config-audit.jsonl")
        );
    }

    // --- WOR-2478: the `key_path` and `admin_path` channels ---

    #[test]
    fn a_key_path_under_the_memory_sink_is_refused_rather_than_ignored() {
        let error = compile_config(&audit_yaml(
            "  sink: memory\n  key_path: /var/lib/sbproxy/key-audit.jsonl",
            " {}",
        ))
        .err()
        .expect("a key_path nothing writes to must not compile");
        assert!(
            error.to_string().contains("audit.key_path"),
            "the refusal names the key that would be ignored: {error}"
        );
        assert!(
            error.to_string().contains("audit.sink: chain"),
            "the refusal names what key_path requires: {error}"
        );
    }

    #[test]
    fn an_admin_path_under_the_memory_sink_is_refused_rather_than_ignored() {
        let error = compile_config(&audit_yaml(
            "  sink: memory\n  admin_path: /var/lib/sbproxy/admin-audit.jsonl",
            " {}",
        ))
        .err()
        .expect("an admin_path nothing writes to must not compile");
        assert!(
            error.to_string().contains("audit.admin_path"),
            "the refusal names the key that would be ignored: {error}"
        );
        assert!(
            error.to_string().contains("audit.sink: chain"),
            "the refusal names what admin_path requires: {error}"
        );
    }

    #[test]
    fn a_key_path_equal_to_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             key_path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("a key_path that shares the security chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the key channel cannot share the security chain file; the two payload types \
             verify separately"
        );
    }

    #[test]
    fn a_key_path_equal_to_config_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             config_path: /var/lib/sbproxy/config-audit.jsonl\n  \
             key_path: /var/lib/sbproxy/config-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("a key_path that shares the config chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the key channel cannot share the config chain file; the two payload types verify \
             separately"
        );
    }

    #[test]
    fn an_admin_path_equal_to_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             admin_path: /var/lib/sbproxy/security-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("an admin_path that shares the security chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the admin channel cannot share the security chain file; the two payload types \
             verify separately"
        );
    }

    #[test]
    fn an_admin_path_equal_to_config_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             config_path: /var/lib/sbproxy/config-audit.jsonl\n  \
             admin_path: /var/lib/sbproxy/config-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("an admin_path that shares the config chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the admin channel cannot share the config chain file; the two payload types \
             verify separately"
        );
    }

    #[test]
    fn an_admin_path_equal_to_key_path_is_refused() {
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             key_path: /var/lib/sbproxy/key-audit.jsonl\n  \
             admin_path: /var/lib/sbproxy/key-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("an admin_path that shares the key chain file must not compile");
        assert_eq!(
            error.to_string(),
            "the admin channel cannot share the key chain file; the two payload types verify \
             separately"
        );
    }

    #[test]
    fn audit_chain_compiles_with_all_four_distinct_paths() {
        let yaml = audit_yaml(
            "  sink: chain\n  path: /var/lib/sbproxy/security-audit.jsonl\n  \
             config_path: /var/lib/sbproxy/config-audit.jsonl\n  \
             key_path: /var/lib/sbproxy/key-audit.jsonl\n  \
             admin_path: /var/lib/sbproxy/admin-audit.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        );
        let compiled = compile_config(&yaml).expect("compile");
        let audit = compiled.audit.expect("audit block survives compilation");
        assert_eq!(audit.sink, AuditSinkKind::Chain);
        assert_eq!(
            audit.path.as_deref(),
            Some("/var/lib/sbproxy/security-audit.jsonl")
        );
        assert_eq!(
            audit.config_path.as_deref(),
            Some("/var/lib/sbproxy/config-audit.jsonl")
        );
        assert_eq!(
            audit.key_path.as_deref(),
            Some("/var/lib/sbproxy/key-audit.jsonl")
        );
        assert_eq!(
            audit.admin_path.as_deref(),
            Some("/var/lib/sbproxy/admin-audit.jsonl")
        );
    }

    #[test]
    fn chain_paths_are_compared_after_normalizing_dot_segments() {
        // WOR-2478 M11: `/a/./b.jsonl` and `/a/b.jsonl` name the same
        // file lexically, so the pairwise check must catch this collision
        // even though the two strings differ byte for byte.
        let error = compile_config(&audit_yaml(
            "  sink: chain\n  path: /a/b.jsonl\n  \
             config_path: /a/./b.jsonl\n  sign_with: proxy.web_bot_auth",
            AUDIT_SIGNER,
        ))
        .err()
        .expect("a config_path that normalizes to the same file as path must not compile");
        assert_eq!(
            error.to_string(),
            "the config channel cannot share the security chain file; the two payload types \
             verify separately"
        );
    }

    // --- WOR-2318: the `events:` egress ---

    /// A config whose `events:` body is the caller's.
    fn events_yaml(body: &str) -> String {
        format!("proxy: {{}}\nevents:\n{body}\n")
    }

    /// The full refusal text for an `events:` block that must not
    /// compile.
    ///
    /// Two details are load bearing. `compile_config` returns a
    /// `CompiledConfig`, which is not `Debug`, so `expect_err` will not
    /// compile against it; `.err().expect(..)` is the form that does.
    /// And the rendering is `{:?}` rather than `to_string()`, because a
    /// serde failure arrives wrapped in
    /// `.context("failed to parse config YAML")` and `Display` on an
    /// `anyhow::Error` prints only the outermost message, hiding the
    /// part that names the offending key.
    fn events_refusal(body: &str) -> String {
        let error = compile_config(&events_yaml(body))
            .err()
            .expect("this events: block must not compile");
        format!("{error:?}")
    }

    #[test]
    fn events_sink_none_compiles_and_asks_for_nothing_else() {
        let compiled = compile_config(&events_yaml("  sink: none")).expect("compile");
        let events = compiled.events.expect("events block survives compilation");
        assert_eq!(events.sink, EventSinkKind::None);
        assert!(events.path.is_none());
        assert!(events.url.is_none());
        assert!(events.types.is_empty());
    }

    #[test]
    fn events_file_sink_compiles_with_a_path() {
        let compiled = compile_config(&events_yaml(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson",
        ))
        .expect("compile");
        let events = compiled.events.expect("events block survives compilation");
        assert_eq!(events.sink, EventSinkKind::File);
        assert_eq!(
            events.path.as_deref(),
            Some("/var/log/sbproxy/events.ndjson")
        );
    }

    #[test]
    fn events_webhook_sink_compiles_with_a_url_and_a_type_filter() {
        let compiled = compile_config(&events_yaml(
            "  sink: webhook\n  url: https://siem.example.com/sbproxy\n  \
             signing_secret: ${SIEM_HMAC}\n  types:\n    - policy_denied\n    \
             - auth_denied",
        ))
        .expect("compile");
        let events = compiled.events.expect("events block survives compilation");
        assert_eq!(events.sink, EventSinkKind::Webhook);
        assert_eq!(events.types, vec!["policy_denied", "auth_denied"]);
    }

    #[test]
    fn events_file_sink_without_a_path_is_refused() {
        let message = events_refusal("  sink: file");
        assert!(
            message.contains("events.path"),
            "the refusal names the missing key: {message}"
        );
    }

    #[test]
    fn events_webhook_sink_without_a_url_is_refused() {
        let message = events_refusal("  sink: webhook");
        assert!(
            message.contains("events.url"),
            "the refusal names the missing key: {message}"
        );
    }

    #[test]
    fn a_url_under_the_file_sink_is_refused_rather_than_ignored() {
        // The dangerous shape, same as `audit.path` under `sink: memory`:
        // it reads as configured and posts nothing.
        let message = events_refusal(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  \
             url: https://siem.example.com/sbproxy",
        );
        assert!(
            message.contains("events.url"),
            "the refusal names the key that would be ignored: {message}"
        );
    }

    #[test]
    fn a_path_under_the_webhook_sink_is_refused_rather_than_ignored() {
        let message = events_refusal(
            "  sink: webhook\n  url: https://siem.example.com/sbproxy\n  \
             path: /var/log/sbproxy/events.ndjson",
        );
        assert!(
            message.contains("events.path"),
            "the refusal names the key that would be ignored: {message}"
        );
    }

    #[test]
    fn a_signing_secret_with_no_webhook_is_refused_rather_than_ignored() {
        let message = events_refusal(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  \
             signing_secret: ${SIEM_HMAC}",
        );
        assert!(
            message.contains("events.signing_secret"),
            "the refusal names the key that would be ignored: {message}"
        );
    }

    #[test]
    fn types_and_queue_capacity_under_sink_none_are_refused() {
        let types = events_refusal("  sink: none\n  types:\n    - policy_denied");
        assert!(
            types.contains("events.types"),
            "the refusal names the inert key: {types}"
        );
        let capacity = events_refusal("  sink: none\n  queue_capacity: 512");
        assert!(
            capacity.contains("events.queue_capacity"),
            "the refusal names the inert key: {capacity}"
        );
    }

    #[test]
    fn a_zero_queue_capacity_is_refused() {
        let message = events_refusal(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  queue_capacity: 0",
        );
        assert!(
            message.contains("events.queue_capacity"),
            "the refusal names the key: {message}"
        );
    }

    #[test]
    fn an_unknown_event_type_is_refused_with_the_accepted_list() {
        // The failure this prevents: a misspelling selects no events,
        // and a sink that delivers nothing is indistinguishable from a
        // quiet proxy.
        let message = events_refusal(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  types:\n    - policy_denial",
        );
        assert!(
            message.contains("policy_denial"),
            "the refusal quotes the offending name: {message}"
        );
        assert!(
            message.contains("policy_denied") && message.contains("guardrail_triggered"),
            "and lists what is accepted: {message}"
        );
    }

    #[test]
    fn a_non_http_webhook_url_is_refused() {
        let message = events_refusal("  sink: webhook\n  url: file:///tmp/events");
        assert!(
            message.contains("http"),
            "the refusal says which schemes are allowed: {message}"
        );
    }

    #[test]
    fn kafka_nats_and_eventbridge_are_refused_by_name() {
        // Not `EventSinkKind` variants, so serde refuses them and names
        // the three that exist. A variant declared only to be rejected
        // would be a config surface that lies about what the build does.
        for absent in ["kafka", "nats", "eventbridge"] {
            let message = events_refusal(&format!("  sink: {absent}"));
            assert!(
                message.contains("webhook") && message.contains("file"),
                "refusing `{absent}` must name the sinks that do exist: {message}"
            );
        }
    }

    // --- WOR-2384: `events.fail_closed` ---

    #[test]
    fn events_fail_closed_defaults_to_empty() {
        let compiled = compile_config(&events_yaml(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson",
        ))
        .expect("compile");
        let events = compiled.events.expect("events block survives compilation");
        assert!(events.fail_closed.is_empty());
    }

    #[test]
    fn events_fail_closed_compiles_with_a_known_type() {
        let compiled = compile_config(&events_yaml(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  fail_closed:\n    \
             - mcp_governance_decision",
        ))
        .expect("compile");
        let events = compiled.events.expect("events block survives compilation");
        assert_eq!(events.fail_closed, vec!["mcp_governance_decision"]);
    }

    #[test]
    fn an_unknown_fail_closed_type_is_refused_with_the_accepted_list() {
        // Mirrors `an_unknown_event_type_is_refused_with_the_accepted_list`:
        // `fail_closed` draws from the exact same closed set as `types`
        // and is refused the same way, so a typo cannot silently name a
        // type that is never actually enforced.
        let message = events_refusal(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  fail_closed:\n    \
             - mcp_governance_decisionn",
        );
        assert!(
            message.contains("mcp_governance_decisionn"),
            "the refusal quotes the offending name: {message}"
        );
        assert!(
            message.contains("mcp_governance_decision") && message.contains("policy_denied"),
            "and lists what is accepted: {message}"
        );
    }

    /// WOR-2571: the five key-lifecycle kinds resolve through the same
    /// `EventType::from_name` path as every other name, so this pins
    /// the config boundary accepting them rather than trusting the
    /// enum change alone. A regression here would refuse a correct
    /// `events.types:` at compile time, which is the loudest possible
    /// failure, but only if someone has a config that names them; this
    /// test is that config.
    #[test]
    fn events_types_accept_the_key_lifecycle_kinds() {
        let compiled = compile_config(&events_yaml(
            "  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  types:\n    \
             - key_minted\n    - key_revoked\n    - key_rotated\n    - key_blocked\n    \
             - credential_resolved",
        ))
        .expect("the key-lifecycle event names must be accepted");
        let events = compiled.events.expect("events block survives compilation");
        assert_eq!(
            events.types,
            vec![
                "key_minted",
                "key_revoked",
                "key_rotated",
                "key_blocked",
                "credential_resolved"
            ]
        );
    }

    #[test]
    fn an_unknown_events_key_is_refused() {
        // `deny_unknown_fields`, so a `batch_size:` or a `retries:` an
        // operator hoped for fails rather than being dropped.
        let message =
            events_refusal("  sink: file\n  path: /var/log/sbproxy/events.ndjson\n  retries: 3");
        assert!(
            message.contains("retries"),
            "the refusal names the unknown key: {message}"
        );
    }

    // --- WOR-2127: consumption attestation ---

    /// The signing identity every attestation fixture below points at.
    const ATTESTATION_SIGNER: &str = r#"
  web_bot_auth:
    key_id: sbproxy-2026
    ed25519_seed_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#;

    /// A complete billing table, indented to sit under `attestation:`.
    const ATTESTATION_BILLABLE: &str = r#"
    billable:
      delivered: yes
      client_disconnected: partial
      origin_4xx: no
      origin_5xx: no
      policy_blocked: no
      rate_limited: no
      cache_hit: yes
      retry: collapse"#;

    /// One static origin, so a fixture only has to say what it is
    /// testing.
    const ATTESTATION_ORIGIN: &str = r#"
origins:
  api.partner.example:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;

    /// A config whose `attestation:` body is the caller's, with the
    /// signer, queue, ledger, and billing table already in place.
    fn attestation_yaml(body: &str) -> String {
        format!(
            "proxy:{ATTESTATION_SIGNER}\n  attestation:{body}\n    sign_with: proxy.web_bot_auth\
             \n    queue:\n      path: /tmp/sbproxy-attestation/claims.q\n      max_entries: 100000\
             \n    ledger:\n      path: /tmp/sbproxy-attestation/receipts.ndjson\
             {ATTESTATION_BILLABLE}\n{ATTESTATION_ORIGIN}"
        )
    }

    /// WOR-2623: `claim` and `both` compiled clean and served traffic
    /// that produced neither a claim nor a receipt. Nothing in the
    /// request path writes a pre-call claim, nothing reads
    /// `proxy.attestation.queue`, and no ceiling is computed for
    /// `enforcement_mode` to act on, so the operator who set a ceiling
    /// and a bounded queue got an unmetered proxy and no signal at all.
    /// A posture the build cannot perform is refused at load.
    #[test]
    fn attestation_claim_roles_are_refused_because_the_claim_half_is_not_implemented() {
        for spelling in ["claim", "both"] {
            let yaml = attestation_yaml(&format!("\n    role: {spelling}"));
            let error = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("`role: {spelling}` must not compile"));
            let rendered = error.to_string();

            assert!(
                rendered.contains(&format!("`{spelling}`")),
                "the refusal names the value the operator wrote: {rendered}"
            );
            assert!(
                rendered.contains("proxy.attestation.queue"),
                "the refusal names the surface that is never read: {rendered}"
            );
            assert!(
                rendered.contains("enforcement_mode"),
                "the refusal names the ceiling that is never computed: {rendered}"
            );
            assert!(
                rendered.contains("role: receipt"),
                "the refusal points at the half that is complete: {rendered}"
            );
        }
    }

    /// The proxy-wide refusal reads the proxy-wide role, so an origin
    /// that widens `receipt` into `both` would walk straight past it and
    /// reach the same unimplemented half one host at a time.
    #[test]
    fn attestation_origin_widening_into_the_claim_half_is_refused() {
        let yaml = attestation_yaml("\n    role: receipt").replace(
            "      body: \"ok\"\n",
            "      body: \"ok\"\n    attestation:\n      role: both\n",
        );

        let error = compile_config(&yaml)
            .err()
            .expect("an origin cannot widen into a half the build does not have");
        let rendered = error.to_string();

        assert!(
            rendered.contains("api.partner.example"),
            "the refusal names the origin the operator has to fix: {rendered}"
        );
        assert!(rendered.contains("`both`"), "{rendered}");
        assert!(rendered.contains("role: receipt"), "{rendered}");
    }

    #[test]
    fn attestation_valid_config_compiles() {
        let compiled = compile_config(&attestation_yaml("\n    role: receipt")).expect("compile");
        let attestation = compiled
            .server
            .attestation
            .expect("the attestation block survives compilation");

        assert_eq!(attestation.role, AttestationRole::Receipt);
        // The whole reason this key departs from the surface-wide
        // `closed`: billing is not a security boundary, so an unwritable
        // ledger must not take the API down.
        assert_eq!(attestation.failure_mode, FailureMode::Degraded);
        assert_eq!(attestation.enforcement_mode, EnforcementMode::Block);
        assert_eq!(
            attestation.sign_with.as_deref(),
            Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH)
        );
        let queue = attestation.queue.expect("queue present");
        assert_eq!(queue.max_entries, 100_000);
        assert!(attestation.ledger.is_some());
        assert!(attestation
            .billable
            .expect("billable present")
            .missing_outcomes()
            .is_empty());
    }

    #[test]
    fn attestation_absent_block_still_compiles() {
        let yaml = r#"
origins:
  api.partner.example:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        let compiled = compile_config(yaml).expect("a config with no attestation block compiles");
        assert!(compiled.server.attestation.is_none());
        assert!(compiled
            .resolve_origin("api.partner.example")
            .expect("origin compiled")
            .attestation
            .is_none());
    }

    #[test]
    fn attestation_every_failure_mode_parses() {
        for (spelling, expected) in [
            ("closed", FailureMode::Closed),
            ("open", FailureMode::Open),
            ("degraded", FailureMode::Degraded),
            ("observe", FailureMode::Observe),
        ] {
            let yaml = attestation_yaml(&format!(
                "\n    role: receipt\n    failure_mode: {spelling}"
            ));
            let compiled =
                compile_config(&yaml).unwrap_or_else(|e| panic!("{spelling} must compile: {e}"));
            assert_eq!(
                compiled
                    .server
                    .attestation
                    .expect("attestation present")
                    .failure_mode,
                expected,
                "failure_mode: {spelling}"
            );
        }
    }

    #[test]
    fn attestation_incomplete_billable_names_every_missing_outcome() {
        let yaml = format!(
            "proxy:{ATTESTATION_SIGNER}\n  attestation:\n    role: receipt\
             \n    sign_with: proxy.web_bot_auth\
             \n    queue:\n      path: /tmp/sbproxy-attestation/claims.q\
             \n    ledger:\n      path: /tmp/sbproxy-attestation/receipts.ndjson\
             \n    billable:\n      delivered: yes\n      client_disconnected: partial\
             \n      origin_4xx: no\n      origin_5xx: no\n      policy_blocked: no\
             \n      rate_limited: no\n{ATTESTATION_ORIGIN}"
        );

        let error = compile_config(&yaml)
            .err()
            .expect("an incomplete billing table is not a table");
        let rendered = error.to_string();

        // Both, in one message. An operator who left two outcomes blank
        // should not have to compile twice to find that out.
        assert!(rendered.contains("cache_hit"), "{rendered}");
        assert!(rendered.contains("retry"), "{rendered}");
    }

    #[test]
    fn attestation_role_without_a_billing_table_fails_config_load() {
        let yaml = format!(
            "proxy:{ATTESTATION_SIGNER}\n  attestation:\n    role: receipt\
             \n    sign_with: proxy.web_bot_auth\
             \n    queue:\n      path: /tmp/sbproxy-attestation/claims.q\
             \n    ledger:\n      path: /tmp/sbproxy-attestation/receipts.ndjson\
             \n{ATTESTATION_ORIGIN}"
        );

        let error = compile_config(&yaml)
            .err()
            .expect("a role with no billing table must fail");
        assert!(
            error.to_string().contains("billable"),
            "the error names the key the operator has to author: {error}"
        );
    }

    #[test]
    fn attestation_role_without_a_queue_fails_config_load() {
        let yaml = format!(
            "proxy:{ATTESTATION_SIGNER}\n  attestation:\n    role: receipt\
             \n    sign_with: proxy.web_bot_auth\
             \n    ledger:\n      path: /tmp/sbproxy-attestation/receipts.ndjson\
             {ATTESTATION_BILLABLE}\n{ATTESTATION_ORIGIN}"
        );

        let error = compile_config(&yaml)
            .err()
            .expect("a role with nowhere to hold claims fails");
        assert!(error.to_string().contains("queue"), "got: {error}");
    }

    #[test]
    fn attestation_zero_queue_capacity_fails_config_load() {
        let yaml = attestation_yaml("\n    role: receipt")
            .replace("max_entries: 100000", "max_entries: 0");

        let error = compile_config(&yaml)
            .err()
            .expect("a queue of zero is not a queue");
        assert!(error.to_string().contains("max_entries"), "got: {error}");
    }

    #[test]
    fn attestation_unknown_signing_identity_fails_config_load() {
        let yaml = attestation_yaml("\n    role: receipt")
            .replace("sign_with: proxy.web_bot_auth", "sign_with: proxy.mtls");

        let error = compile_config(&yaml)
            .err()
            .expect("an unresolvable signer must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("sign_with"), "{rendered}");
        assert!(
            rendered.contains(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH),
            "the error tells the operator what is on offer: {rendered}"
        );
    }

    #[test]
    fn attestation_receipt_role_without_a_signer_fails_config_load() {
        let yaml = attestation_yaml("\n    role: receipt")
            .replace("\n    sign_with: proxy.web_bot_auth", "");

        let error = compile_config(&yaml)
            .err()
            .expect("an unsigned receipt is not evidence");
        assert!(error.to_string().contains("sign_with"), "got: {error}");
    }

    #[test]
    fn attestation_origin_override_survives_compilation() {
        // A narrowing override: the proxy meters, this one origin does
        // not. Narrowing is the only direction left now that widening
        // into the claim half is refused.
        let override_block =
            "      body: \"ok\"\n    attestation:\n      role: off\n      agreement_id: acme-2026\n";
        let yaml =
            attestation_yaml("\n    role: receipt").replace("      body: \"ok\"\n", override_block);

        let compiled = compile_config(&yaml).expect("a per-origin override compiles");
        let origin = compiled
            .resolve_origin("api.partner.example")
            .expect("origin compiled");
        let attestation = origin
            .attestation
            .as_ref()
            .expect("the override survives compilation");

        assert_eq!(attestation.role, Some(AttestationRole::Off));
        assert_eq!(attestation.agreement_id.as_deref(), Some("acme-2026"));
    }

    #[test]
    fn attestation_origin_block_without_a_proxy_block_fails_config_load() {
        let yaml = r#"
origins:
  api.partner.example:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    attestation:
      role: receipt
      agreement_id: acme-2026
"#;
        let error = compile_config(yaml)
            .err()
            .expect("a per-origin role with nothing behind it must fail");
        assert!(
            error.to_string().contains("proxy.attestation"),
            "the error points at the block the operator is missing: {error}"
        );
    }

    #[test]
    fn attestation_origin_widening_past_the_signer_fails_config_load() {
        // `proxy.attestation` only has to name a signer when the
        // proxy-wide role writes receipts. An origin that widens `off`
        // to `receipt` reaches a receipt with nothing to sign it, and
        // that hole is invisible in either block on its own.
        let yaml = attestation_yaml("\n    role: off")
            .replace("\n    sign_with: proxy.web_bot_auth", "")
            .replace(
                "      body: \"ok\"\n",
                "      body: \"ok\"\n    attestation:\n      role: receipt\n",
            );

        let error = compile_config(&yaml)
            .err()
            .expect("widening past the signer must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("sign_with"), "{rendered}");
        assert!(rendered.contains("api.partner.example"), "{rendered}");
    }

    #[test]
    fn attestation_empty_agreement_id_fails_config_load() {
        let yaml = attestation_yaml("\n    role: receipt").replace(
            "      body: \"ok\"\n",
            "      body: \"ok\"\n    attestation:\n      agreement_id: \"\"\n",
        );

        let error = compile_config(&yaml)
            .err()
            .expect("an empty agreement names no contract");
        assert!(error.to_string().contains("agreement_id"), "got: {error}");
    }

    // --- WOR-2128: unit resolvers ---

    #[test]
    fn attestation_resolvers_survive_compilation_in_the_operators_spelling() {
        let compiled = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    route_weights:\
             \n      - name: search_call\
             \n        method: POST\
             \n        path: /v1/search\
             \n        weight: 5\
             \n      - name: search_call\
             \n        path: /v1/search/*\
             \n        weight: 1\
             \n    origin_headers:\
             \n      - name: result_row\
             \n        header: X-Rows-Returned",
        ))
        .expect("a complete block with resolvers compiles");

        let attestation = compiled
            .server
            .attestation
            .expect("the attestation block survives compilation");

        assert_eq!(attestation.route_weights.len(), 2);
        assert_eq!(attestation.route_weights[0].name, "search_call");
        assert_eq!(attestation.route_weights[0].method.as_deref(), Some("POST"));
        assert_eq!(attestation.route_weights[0].path, "/v1/search");
        assert_eq!(attestation.route_weights[0].weight, 5);
        assert_eq!(
            attestation.route_weights[1].method, None,
            "an omitted method prices every method"
        );
        assert_eq!(attestation.origin_headers.len(), 1);
        assert_eq!(
            attestation.origin_headers[0].header, "X-Rows-Returned",
            "the receipt quotes this back, so the operator's casing is kept"
        );
    }

    #[test]
    fn attestation_one_unit_name_may_not_come_from_two_provenances() {
        // The check the units-carry-a-source design depends on. Two
        // `search_call` lines on one receipt, one priced by config and
        // one asserted by the origin, cannot be told apart by whoever
        // reads it, which is exactly what the source field is for.
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    route_weights:\
             \n      - name: search_call\
             \n        path: /v1/search\
             \n        weight: 5\
             \n    origin_headers:\
             \n      - name: search_call\
             \n        header: X-Rows-Returned",
        ))
        .err()
        .expect("a name shared across resolvers is not compilable");

        let rendered = error.to_string();
        assert!(rendered.contains("search_call"), "{rendered}");
        assert!(rendered.contains("provenance"), "{rendered}");
    }

    #[test]
    fn attestation_route_priced_twice_on_one_line_fails_config_load() {
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    route_weights:\
             \n      - name: search_call\
             \n        method: post\
             \n        path: /v1/search\
             \n        weight: 5\
             \n      - name: search_call\
             \n        method: POST\
             \n        path: /v1/search\
             \n        weight: 9",
        ))
        .err()
        .expect("two weights for one route have no defensible order");

        assert!(
            error.to_string().contains("twice"),
            "the method is matched case-insensitively, so these are one route: {error}"
        );
    }

    #[test]
    fn attestation_wildcard_outside_the_documented_suffix_fails_config_load() {
        for path in ["/v1/*/search", "/v1/search*", "/*/x", "/v1/*/*"] {
            let error = compile_config(&attestation_yaml(&format!(
                "\n    role: receipt\
                 \n    route_weights:\
                 \n      - name: search_call\
                 \n        path: \"{path}\"\
                 \n        weight: 5"
            )))
            .err()
            .unwrap_or_else(|| panic!("{path:?} looks like a glob and is not one"));

            assert!(
                error.to_string().contains("wildcard"),
                "{path:?}: a `*` that matches literally leaves a route silently unpriced: {error}"
            );
        }
    }

    #[test]
    fn attestation_relative_route_path_fails_config_load() {
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    route_weights:\
             \n      - name: search_call\
             \n        path: v1/search\
             \n        weight: 5",
        ))
        .err()
        .expect("a path that can never match a request path is a typo, not a rule");

        assert!(
            error.to_string().contains("does not start with"),
            "got: {error}"
        );
    }

    #[test]
    fn attestation_unreachable_origin_header_fails_config_load() {
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    origin_headers:\
             \n      - name: result_row\
             \n        header: \"X Rows Returned\"",
        ))
        .err()
        .expect("a header name with spaces cannot arrive on a response");

        assert!(
            error.to_string().contains("valid HTTP header name"),
            "got: {error}"
        );
    }

    #[test]
    fn attestation_zero_weight_is_a_metered_free_route() {
        let compiled = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    route_weights:\
             \n      - name: health_call\
             \n        path: /healthz\
             \n        weight: 0",
        ))
        .expect("metered and free is a position an operator is allowed to hold");

        assert_eq!(
            compiled
                .server
                .attestation
                .expect("attestation present")
                .route_weights[0]
                .weight,
            0
        );
    }

    #[test]
    fn attestation_role_without_resolvers_still_compiles() {
        // Recording every call and pricing none of it is a legitimate
        // posture: the chain still proves no call went missing. The
        // compiler warns and does not refuse.
        let compiled = compile_config(&attestation_yaml("\n    role: receipt"))
            .expect("a role without unit resolvers is not an error");
        let attestation = compiled.server.attestation.expect("attestation present");
        assert!(attestation.measured.is_empty());
        assert!(attestation.route_weights.is_empty());
        assert!(attestation.origin_headers.is_empty());
    }

    // --- WOR-2145: the measured unit resolver ---

    #[test]
    fn attestation_measured_units_survive_compilation_with_per_defaulted() {
        let compiled = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    measured:\
             \n      - name: api_call\
             \n        quantity: requests\
             \n      - name: egress_kib\
             \n        quantity: bytes_out\
             \n        per: 1024",
        ))
        .expect("a complete block with measured units compiles");

        let attestation = compiled
            .server
            .attestation
            .expect("the attestation block survives compilation");

        assert_eq!(attestation.measured.len(), 2);
        assert_eq!(attestation.measured[0].name, "api_call");
        assert_eq!(
            attestation.measured[0].quantity,
            crate::types::AttestationMeasuredQuantity::Requests
        );
        assert_eq!(
            attestation.measured[0].per, 1,
            "an omitted `per` bills one unit per observed item"
        );
        assert_eq!(
            attestation.measured[1].per, 1024,
            "1024 against bytes_out is what turns bytes into kibibytes"
        );
    }

    #[test]
    fn attestation_every_measured_quantity_spelling_parses() {
        use crate::types::AttestationMeasuredQuantity as Quantity;

        let compiled = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    measured:\
             \n      - name: api_call\
             \n        quantity: requests\
             \n      - name: ingress_kib\
             \n        quantity: bytes_in\
             \n        per: 1024\
             \n      - name: egress_kib\
             \n        quantity: bytes_out\
             \n        per: 1024\
             \n      - name: compute_second\
             \n        quantity: duration_ms\
             \n        per: 1000",
        ))
        .expect("every quantity the meter counts is spellable in config");

        let quantities: Vec<Quantity> = compiled
            .server
            .attestation
            .expect("attestation present")
            .measured
            .iter()
            .map(|entry| entry.quantity)
            .collect();

        assert_eq!(
            quantities,
            vec![
                Quantity::Requests,
                Quantity::BytesIn,
                Quantity::BytesOut,
                Quantity::DurationMs,
            ],
            "the config spelling and the metering spelling are the same snake_case"
        );
    }

    #[test]
    fn attestation_measured_divisor_of_zero_fails_config_load() {
        // `per` reaches the request path as a divisor. Catching zero
        // here is the difference between a config error and a panic
        // while a response is being written.
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    measured:\
             \n      - name: egress_kib\
             \n        quantity: bytes_out\
             \n        per: 0",
        ))
        .err()
        .expect("a divisor of zero cannot produce a unit count");

        let rendered = error.to_string();
        assert!(
            rendered.contains("proxy.attestation.measured[0].per"),
            "the error names the key the operator has to fix: {rendered}"
        );
        assert!(rendered.contains("divisor"), "{rendered}");
    }

    #[test]
    fn attestation_measured_without_a_name_fails_config_load() {
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    measured:\
             \n      - name: \"\"\
             \n        quantity: requests",
        ))
        .err()
        .expect("a unit with no name has no invoice line to be billed on");

        assert!(
            error
                .to_string()
                .contains("proxy.attestation.measured[0].name"),
            "got: {error}"
        );
    }

    #[test]
    fn attestation_measured_name_may_not_be_claimed_by_another_resolver() {
        // Same rule as the route-weight/origin-header collision, and
        // for the same reason: two `api_call` lines with different
        // provenance is a receipt nobody can read.
        let error = compile_config(&attestation_yaml(
            "\n    role: receipt\
             \n    measured:\
             \n      - name: api_call\
             \n        quantity: requests\
             \n    route_weights:\
             \n      - name: api_call\
             \n        path: /v1/search\
             \n        weight: 5",
        ))
        .err()
        .expect("a name shared across resolvers is not compilable");

        let rendered = error.to_string();
        assert!(rendered.contains("api_call"), "{rendered}");
        assert!(rendered.contains("provenance"), "{rendered}");
    }

    // --- WOR-193: agent_skills schema validation ---

    #[test]
    fn agent_skills_invalid_type_fails_config_load() {
        let yaml = r#"
origins:
  skills.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
    agent_skills:
      - name: bad
        type: not-a-real-kind
        description: nope
        url: /skills/foo.md
        body: "x"
"#;
        let result = compile_config(yaml);
        let err = match result {
            Ok(_) => panic!("compile must reject unknown agent_skills type"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("agent_skills") && err.contains("type"),
            "error must reference agent_skills type; got: {err}"
        );
    }

    #[test]
    fn agent_skills_invalid_visibility_fails_config_load() {
        let yaml = r#"
origins:
  skills.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
    agent_skills:
      - name: ok
        type: skill-md
        description: nope
        url: /skills/foo.md
        body: "x"
        visibility: secret
"#;
        let result = compile_config(yaml);
        let err = match result {
            Ok(_) => panic!("compile must reject unknown visibility"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("visibility"),
            "error must reference visibility; got: {err}"
        );
    }

    #[test]
    fn agent_skills_absent_compiles_with_empty_list() {
        // v1-compat: existing configs without `agent_skills:` keep
        // working unchanged (the field defaults to an empty Vec).
        let yaml = r#"
origins:
  noskills.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("noskills.example.com").unwrap();
        assert!(origin.agent_skills.is_empty());
    }

    #[test]
    fn agent_skills_skill_md_compiles_cleanly() {
        let yaml = r##"
origins:
  skills.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
    agent_skills:
      - name: deploy-via-pr
        type: skill-md
        description: "Open a PR"
        url: /skills/deploy-via-pr.md
        body: "# deploy-via-pr"
"##;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("skills.example.com").unwrap();
        assert_eq!(origin.agent_skills.len(), 1);
        assert_eq!(origin.agent_skills[0].name, "deploy-via-pr");
        assert_eq!(origin.agent_skills[0].kind, "skill-md");
        assert_eq!(origin.agent_skills[0].visibility, "public");
    }

    // --- Wave 4 / A4.2 follow-up: token_bytes_ratio override ---

    #[test]
    fn token_bytes_ratio_override_threads_into_html_to_markdown_transform() {
        let yaml = r#"
origins:
  ratio.example.com:
    token_bytes_ratio: 0.5
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "ok"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens: [tok-1]
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("ratio.example.com").unwrap();
        // The compiled origin carries the override.
        assert_eq!(origin.token_bytes_ratio, Some(0.5));
        // The auto-wired html_to_markdown transform reads the same
        // value so the projection's token_estimate honours it.
        let html_to_md = origin
            .transform_configs
            .iter()
            .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("html_to_markdown"))
            .expect("html_to_markdown auto-wired");
        let ratio = html_to_md
            .get("token_bytes_ratio")
            .and_then(|v| v.as_f64())
            .expect("token_bytes_ratio threaded into transform");
        assert!((ratio - 0.5).abs() < f64::EPSILON);
    }

    // --- Wave 5 day-6 Item 2: features.* -> proxy.extensions migration ---

    #[test]
    fn migrate_features_anomaly_lifts_to_proxy_extensions() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
features:
  anomaly_detection:
    enabled: true
    window_days: 28
origins: {}
"#;
        let migrated = migrate_features_to_extensions(yaml).expect("migration must succeed");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        let block = parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .and_then(|e| e.get("anomaly"))
            .expect("anomaly block must land under proxy.extensions");
        assert_eq!(block.get("enabled").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(block.get("window_days").and_then(|v| v.as_i64()), Some(28));
        // The legacy `features:` block should be gone.
        assert!(parsed.get("features").is_none());
    }

    #[test]
    fn migrate_features_reputation_aliases_lift_to_extensions() {
        // Both `reputation` and the longer `reputation_updater` should
        // land at `proxy.extensions.reputation`.
        let yaml_a = r#"
features:
  reputation:
    enabled: true
"#;
        let migrated = migrate_features_to_extensions(yaml_a).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        assert!(parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .and_then(|e| e.get("reputation"))
            .is_some());

        let yaml_b = r#"
features:
  reputation_updater:
    enabled: true
"#;
        let migrated = migrate_features_to_extensions(yaml_b).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        assert!(parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .and_then(|e| e.get("reputation"))
            .is_some());
    }

    #[test]
    fn migrate_features_passthrough_when_no_features_block() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins: {}
"#;
        let migrated = migrate_features_to_extensions(yaml).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        // No mention of extensions added when nothing to migrate.
        assert!(parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .is_none());
    }

    #[test]
    fn migrate_features_preserves_unknown_features_keys() {
        let yaml = r#"
features:
  anomaly_detection:
    enabled: true
  some_future_feature:
    enabled: true
"#;
        let migrated = migrate_features_to_extensions(yaml).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        assert!(parsed
            .get("features")
            .and_then(|f| f.get("some_future_feature"))
            .is_some());
        assert!(parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .and_then(|e| e.get("anomaly"))
            .is_some());
    }

    #[test]
    fn migrate_features_errors_on_dual_shape() {
        // Operator who set both forms simultaneously must get a hard
        // error so they make a deliberate choice.
        let yaml = r#"
proxy:
  extensions:
    anomaly:
      tenant_id: "ext-from-canonical"
features:
  anomaly_detection:
    tenant_id: "ext-from-legacy"
"#;
        let err = migrate_features_to_extensions(yaml).expect_err("dual shape must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("config conflict") && msg.contains("anomaly"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn migrate_features_tls_fingerprint_lifts_to_extensions() {
        let yaml = r#"
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
"#;
        let migrated = migrate_features_to_extensions(yaml).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&migrated).unwrap();
        let block = parsed
            .get("proxy")
            .and_then(|p| p.get("extensions"))
            .and_then(|e| e.get("tls_fingerprint"))
            .expect("tls_fingerprint must land under proxy.extensions");
        assert_eq!(block.get("enabled").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn compile_config_round_trips_legacy_anomaly_block_into_extensions() {
        // Black-box: a config that uses the legacy shape must compile
        // and the bootstrap-visible `server.extensions["anomaly"]` slot
        // must carry the values.
        let yaml = r#"
proxy:
  http_bind_port: 8080
features:
  anomaly_detection:
    tenant_id: "tenant-legacy"
origins: {}
"#;
        let cfg = compile_config(yaml).expect("compile");
        let block = cfg
            .server
            .extensions
            .get("anomaly")
            .expect("legacy block must round-trip into proxy.extensions[anomaly]");
        assert_eq!(
            block.get("tenant_id").and_then(|v| v.as_str()),
            Some("tenant-legacy")
        );
    }

    // --- compile_config_from_source: inline (no source) path ----------

    #[tokio::test]
    async fn compile_config_from_source_without_source_field_keeps_inline_behaviour() {
        // When `source:` is omitted, `compile_config_from_source` must
        // behave identically to `compile_config(inline)`.
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  app.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let ctx = crate::source::FetchContext::with_git_binary();
        let cfg = compile_config_from_source(yaml, &ctx)
            .await
            .expect("compile from inline");
        assert!(cfg.host_map.contains_key("app.example.com"));
    }

    #[tokio::test]
    async fn compile_config_from_source_local_kind_keeps_inline_behaviour() {
        // Explicit `source: { kind: local }` is the same as no source.
        let yaml = r#"
source:
  kind: local
proxy:
  http_bind_port: 8080
origins:
  app.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let ctx = crate::source::FetchContext::with_git_binary();
        let cfg = compile_config_from_source(yaml, &ctx)
            .await
            .expect("compile from local kind");
        assert!(cfg.host_map.contains_key("app.example.com"));
    }

    // --- WOR-2602: origin indices are content, not load order ---

    /// Repeated compiles of one file assign the same origin indices.
    ///
    /// `RawConfigFile::origins` is a `HashMap`, and the compile loop
    /// used to walk it directly, so `idx` fell out of that map's
    /// per-process seed. Those indices are not internal bookkeeping:
    /// `host_map` stores them, `CompiledConfig::origins` is ordered by
    /// them, and the `config_revision` hash consumed them, which is how
    /// one unchanged two-origin file came to report two revisions
    /// across three boots.
    ///
    /// Four origins for 24 possible index assignments rather than two,
    /// and 128 compiles because `RandomState` reseeds per map instance
    /// inside a thread, so these are 128 independent draws and not one
    /// draw read 128 times. Both counts match the sibling assertion in
    /// `sbproxy-core`'s `one_unchanged_multi_origin_config_hashes_to_one_revision`,
    /// which covers the same defect one layer up.
    #[test]
    fn repeated_compiles_assign_the_same_origin_indices() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  alpha.example.com:
    action:
      type: proxy
      url: http://localhost:3001
  bravo.example.com:
    action:
      type: proxy
      url: http://localhost:3002
  charlie.example.com:
    action:
      type: proxy
      url: http://localhost:3003
  delta.example.com:
    action:
      type: proxy
      url: http://localhost:3004
"#;

        let mut assignments: std::collections::BTreeSet<Vec<(String, usize)>> =
            std::collections::BTreeSet::new();
        for _ in 0..128 {
            let cfg = compile_config(yaml).expect("multi-origin fixture compiles");
            let mut pairs: Vec<(String, usize)> = cfg
                .host_map
                .iter()
                .map(|(host, idx)| (host.to_string(), *idx))
                .collect();
            pairs.sort();
            assignments.insert(pairs);
        }

        assert_eq!(
            assignments.len(),
            1,
            "one unchanged config must assign one set of origin indices, saw {assignments:?}"
        );
        // Which assignment, not just how many. Sorted by config key, so
        // the index a hostname gets is readable off the file. Stability
        // alone would also be satisfied by sorting descending, or by
        // any other total order someone later found tidier, and the
        // order is what `CompiledConfig::origins` is in and what the
        // emitted OpenAPI `servers` array is ordered by.
        assert_eq!(
            assignments.iter().next().map(Vec::as_slice),
            Some(
                [
                    ("alpha.example.com".to_string(), 0),
                    ("bravo.example.com".to_string(), 1),
                    ("charlie.example.com".to_string(), 2),
                    ("delta.example.com".to_string(), 3),
                ]
                .as_slice()
            )
        );
    }

    // --- WOR-2342: response_cache method allowlist ---

    fn response_cache_yaml(methods: &str) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    response_cache:
      enabled: true
      ttl_secs: 60
      cacheable_methods: [{methods}]
"#
        )
    }

    #[test]
    fn caching_a_body_bearing_method_is_refused() {
        // The cache key is method, path, query, and Vary headers. It
        // carries no body, so every POST to one path collapses to a
        // single entry and the first response is served to every later
        // prompt. Refused at compile rather than documented, because the
        // failure is silent and returns someone else's answer.
        for method in ["POST", "PUT", "PATCH", "DELETE", "post"] {
            let err = compile_config(&response_cache_yaml(method))
                .err()
                .unwrap_or_else(|| panic!("{method} must be refused"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("response_cache cannot cache"),
                "error must name the refusal: {msg}"
            );
            assert!(
                msg.contains("regardless of its body"),
                "error must say why, not just that: {msg}"
            );
            assert!(
                msg.contains("semantic_cache"),
                "error must point at the surface that does key on content: {msg}"
            );
        }
    }

    #[test]
    fn get_and_head_still_compile() {
        // The other half. Both are fully described by their target and
        // headers, so the existing key is complete for them, and every
        // shipped example and conformance case uses one of the two.
        for methods in ["GET", "HEAD", "GET, HEAD"] {
            compile_config(&response_cache_yaml(methods))
                .unwrap_or_else(|e| panic!("{methods} must compile: {e:#}"));
        }
    }

    #[test]
    fn an_unset_method_list_still_compiles() {
        // Defaults to GET-only in the request path; an operator who never
        // wrote the key must not be asked about it.
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    response_cache:
      enabled: true
      ttl_secs: 60
"#;
        compile_config(yaml).expect("a cache block without methods must compile");
    }

    // --- WOR-2491: owasp_api_top10 pack expansion, wired at compile time ---

    #[test]
    fn owasp_pack_pseudo_type_never_reaches_module_compilation() {
        // The pack entry must be consumed during expansion, never
        // handed to `sbproxy-modules::compile.rs`'s type-string match
        // arms. Proven here by compiling a full origin and checking
        // the compiled chain: it holds the synthesized `object_authz`
        // policy and no `owasp_api_top10` entry at all.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();

        let types: Vec<&str> = origin
            .policy_configs
            .iter()
            .map(|p| p.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(
            types.contains(&"object_authz"),
            "compiled chain must hold the synthesized policy: {types:?}"
        );
        assert!(
            !types.contains(&"owasp_api_top10"),
            "the pseudo-policy must not reach the compiled chain: {types:?}"
        );

        let manifest = origin
            .owasp_pack_manifest
            .as_ref()
            .expect("owasp_pack_manifest is populated when the origin has a pack entry");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api1)
            .expect("api1 entry present");
        // Plan-ledger ruling: api1's state is always needs_operator_input
        // (empty object_rules means no real ownership check runs),
        // not enforced/report_only.
        assert_eq!(
            entry.state,
            crate::owasp_api_pack::PackItemState::NeedsOperatorInput
        );
    }

    #[test]
    fn owasp_pack_backs_off_when_operator_already_authors_object_authz() {
        // An origin that already authors `object_authz` explicitly
        // gets no second synthesized entry, and the manifest records
        // why: `operator_authored`, not `report_only`/`enforced`.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1]
      - type: object_authz
        test_mode: false
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
            object_param: order_id
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();

        let object_authz_count = origin
            .policy_configs
            .iter()
            .filter(|p| p.get("type").and_then(|v| v.as_str()) == Some("object_authz"))
            .count();
        assert_eq!(
            object_authz_count, 1,
            "the operator's own object_authz survives; the pack adds no second one"
        );

        let manifest = origin
            .owasp_pack_manifest
            .as_ref()
            .expect("manifest present");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api1)
            .expect("api1 entry present");
        assert_eq!(
            entry.state,
            crate::owasp_api_pack::PackItemState::OperatorAuthored
        );
    }

    #[test]
    fn owasp_pack_posture_report_only_threads_into_object_authz_test_mode() {
        // `posture: report_only` must thread into `object_authz`'s own
        // `test_mode` switch, the module's real report-only knob.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1]
        posture: report_only
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let synthesized = origin
            .policy_configs
            .iter()
            .find(|p| p.get("type").and_then(|v| v.as_str()) == Some("object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized.get("test_mode").and_then(|v| v.as_bool()),
            Some(true),
            "report_only posture must set object_authz's own test_mode: true"
        );
    }

    #[test]
    fn owasp_pack_posture_enforce_threads_into_object_authz_test_mode() {
        // The other direction of the same knob: `posture: enforce`
        // sets `test_mode: false`, so this is a real threaded switch
        // and not a value the synthesis hard-codes.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1]
        posture: enforce
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let synthesized = origin
            .policy_configs
            .iter()
            .find(|p| p.get("type").and_then(|v| v.as_str()) == Some("object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized.get("test_mode").and_then(|v| v.as_bool()),
            Some(false),
            "enforce posture must set object_authz's own test_mode: false"
        );
    }

    #[test]
    fn owasp_pack_unknown_item_name_fails_compilation() {
        // Validation errors from `expand_owasp_pack` must surface as a
        // real `compile_config` error, not get swallowed on the way
        // out of `compile_origin`.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1, api99]
"#;
        // `Result::expect_err` requires the `Ok` type to implement
        // `Debug`; `CompiledConfig` deliberately does not (WOR-2491
        // task 2 fix: this pre-existing call site never compiled under
        // `cargo check --tests`, only under the plain `cargo check`
        // task 1 verified with). Match instead.
        let err = match compile_config(yaml) {
            Ok(_) => panic!("unknown item name must be refused"),
            Err(e) => e,
        };
        let message = format!("{err:#}");
        assert!(message.contains("api99"), "{message}");
        assert!(
            message.contains("api1, api2"),
            "accepted list present: {message}"
        );
    }

    #[test]
    fn origin_without_owasp_pack_entry_has_no_manifest() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
        let compiled = compile_config(yaml).expect("plain origin must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(
            origin.owasp_pack_manifest.is_none(),
            "an origin with no owasp_api_top10 policy gets no manifest"
        );
    }

    // --- WOR-2491 task 2: api4, api5, api7, api8 wired at compile time ---

    #[test]
    fn owasp_pack_api4_synthesizes_only_the_ip_safe_policies_without_rps() {
        // WOR-2491 review round, B1: rate_limiting and ddos_protection
        // both key on caller IP by default and are no longer
        // synthesized without an operator-supplied per_item.api4.rps
        // budget - see owasp_api_pack.rs's own unit tests for the
        // outage class this avoids.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api4]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let types: Vec<&str> = origin
            .policy_configs
            .iter()
            .map(|p| p.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(types.contains(&"request_limit"), "{types:?}");
        assert!(types.contains(&"concurrent_limit"), "{types:?}");
        assert!(!types.contains(&"rate_limiting"), "{types:?}");
        assert!(!types.contains(&"ddos_protection"), "{types:?}");
        assert!(!types.contains(&"owasp_api_top10"), "{types:?}");

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api4)
            .expect("api4 entry");
        assert_eq!(
            entry.state,
            crate::owasp_api_pack::PackItemState::NeedsOperatorInput
        );
        assert_eq!(entry.synthesized_types.len(), 2);
    }

    #[test]
    fn owasp_pack_api4_synthesizes_all_four_policies_when_rps_configured() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api4]
        per_item:
          api4:
            rps: 25
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let types: Vec<&str> = origin
            .policy_configs
            .iter()
            .map(|p| p.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(types.contains(&"request_limit"), "{types:?}");
        assert!(types.contains(&"rate_limiting"), "{types:?}");
        assert!(types.contains(&"concurrent_limit"), "{types:?}");
        assert!(types.contains(&"ddos_protection"), "{types:?}");

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api4)
            .expect("api4 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
        assert_eq!(entry.synthesized_types.len(), 4);
    }

    #[test]
    fn owasp_pack_api5_alone_needs_operator_input_and_adds_no_enumeration() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api5]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let synthesized = origin
            .policy_configs
            .iter()
            .find(|p| p.get("type").and_then(|v| v.as_str()) == Some("object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized
                .get("function_rules")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(0)
        );
        assert!(
            synthesized.get("enumeration").is_none(),
            "api5 alone must not also add api1's enumeration block"
        );

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api5)
            .expect("api5 entry");
        assert_eq!(
            entry.state,
            crate::owasp_api_pack::PackItemState::NeedsOperatorInput
        );
    }

    #[test]
    fn owasp_pack_api1_and_api5_together_compile_one_shared_object_authz() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api1, api5]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let object_authz_count = origin
            .policy_configs
            .iter()
            .filter(|p| p.get("type").and_then(|v| v.as_str()) == Some("object_authz"))
            .count();
        assert_eq!(
            object_authz_count, 1,
            "api1 and api5 must compile to one shared object_authz entry"
        );
    }

    #[test]
    fn owasp_pack_api7_adds_nothing_but_reports_enforced() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api7]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(
            origin.policy_configs.is_empty(),
            "api7 is not policy-gated; nothing is added: {:?}",
            origin.policy_configs
        );
        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api7)
            .expect("api7 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
    }

    #[test]
    fn owasp_pack_api8_synthesizes_security_headers_and_http_framing() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api8]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let types: Vec<&str> = origin
            .policy_configs
            .iter()
            .map(|p| p.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(types.contains(&"security_headers"), "{types:?}");
        assert!(types.contains(&"http_framing"), "{types:?}");

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api8)
            .expect("api8 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
    }

    #[test]
    fn owasp_pack_api8_synthesizes_security_headers_on_a_static_action() {
        // WOR-2496: a static action's generated response runs the
        // response-phase policy surface, so security_headers is
        // synthesized on the compiled origin alongside http_framing
        // (request-phase, action agnostic) when the pack entry
        // enables api8.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: static
      status: 200
      content_type: application/json
      json_body:
        ok: true
    policies:
      - type: owasp_api_top10
        enable: [api8]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        let types: Vec<&str> = origin
            .policy_configs
            .iter()
            .map(|p| p.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(
            types.contains(&"security_headers"),
            "security_headers must be synthesized on a static action: {types:?}"
        );
        assert!(types.contains(&"http_framing"), "{types:?}");

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api8)
            .expect("api8 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
        assert_eq!(
            entry.synthesized_types,
            vec!["security_headers", "http_framing"]
        );
    }

    // --- WOR-2491 task 3: api3, api9 wired at compile time ---

    #[test]
    fn owasp_pack_api3_synthesizes_response_projection_into_compiled_transform_chain() {
        // The ledger's 2026-08-18 correction, proven at the compiled
        // origin: `per_item.api3.response_exclude_fields` produces a
        // real `transforms:` entry, not a policy, so it must show up
        // on `transform_configs`.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api3]
        per_item:
          api3:
            response_exclude_fields: [ssn, internal_notes]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();

        assert!(
            origin.policy_configs.is_empty(),
            "api3's response half is a transform, not a policy: {:?}",
            origin.policy_configs
        );
        let projection = origin
            .transform_configs
            .iter()
            .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("json_projection"))
            .expect("synthesized json_projection present on transform_configs");
        assert_eq!(
            projection.get("exclude").and_then(|v| v.as_bool()),
            Some(true)
        );

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api3)
            .expect("api3 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
        assert_eq!(entry.synthesized_types, vec!["json_projection"]);
    }

    #[test]
    fn owasp_pack_api3_request_side_backs_off_when_operator_authors_openapi_validation() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api3]
      - type: openapi_validation
        spec:
          openapi: "3.0.0"
          info:
            title: test
            version: "1"
          paths: {}
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();

        let openapi_validation_count = origin
            .policy_configs
            .iter()
            .filter(|p| p.get("type").and_then(|v| v.as_str()) == Some("openapi_validation"))
            .count();
        assert_eq!(
            openapi_validation_count, 1,
            "the operator's own openapi_validation survives untouched"
        );
        assert!(
            origin.transform_configs.is_empty(),
            "no response_exclude_fields supplied, so no transform is synthesized: {:?}",
            origin.transform_configs
        );

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api3)
            .expect("api3 entry");
        // Response half is still uncovered (no exclude_fields), so the
        // item as a whole still needs operator input even though the
        // request half backed off cleanly.
        assert_eq!(
            entry.state,
            crate::owasp_api_pack::PackItemState::NeedsOperatorInput
        );
        assert!(
            entry
                .reason
                .contains("origin already authors openapi_validation"),
            "{}",
            entry.reason
        );
    }

    #[test]
    fn owasp_pack_api9_sets_expose_openapi_true_on_compiled_origin() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: owasp_api_top10
        enable: [api9]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(
            origin.expose_openapi,
            "api9 must flip expose_openapi to true on the compiled origin"
        );

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api9)
            .expect("api9 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
        assert!(
            entry.reason.contains("set expose_openapi: true"),
            "{}",
            entry.reason
        );
    }

    #[test]
    fn owasp_pack_api9_leaves_operator_authored_expose_openapi_true_alone() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    expose_openapi: true
    policies:
      - type: owasp_api_top10
        enable: [api9]
"#;
        let compiled = compile_config(yaml).expect("owasp pack config must compile");
        let origin = compiled.resolve_origin("api.example.com").unwrap();
        assert!(origin.expose_openapi, "must stay true");

        let manifest = origin.owasp_pack_manifest.as_ref().expect("manifest");
        let entry = manifest
            .entry_for(crate::owasp_api_pack::PackItem::Api9)
            .expect("api9 entry");
        assert_eq!(entry.state, crate::owasp_api_pack::PackItemState::Enforced);
        assert!(
            entry
                .reason
                .contains("origin already sets expose_openapi: true"),
            "{}",
            entry.reason
        );
    }
}

#[cfg(test)]
mod cache_decision_event_tests {
    use super::*;

    fn origin_with_cache(cache_yaml: &str) -> String {
        format!(
            "proxy:\n  http_bind_port: 8080\norigins:\n  \"api.local\":\n    action:\n      \
             type: static\n      status_code: 200\n      content_type: text/plain\n      \
             body: \"ok\"\n    response_cache:\n{cache_yaml}"
        )
    }

    #[test]
    fn cel_is_refused_for_a_document_returning_cache_event() {
        // The refusal has to name why, or an operator reads "unsupported"
        // and assumes it is unimplemented rather than wrong-shaped.
        for key in ["key_event", "admit_event"] {
            let yaml = origin_with_cache(&format!(
                "      enabled: true\n      {key}:\n        engine: cel\n        source: \"true\"\n"
            ));
            let error = compile_config(&yaml)
                .err()
                .unwrap_or_else(|| panic!("{key} with engine cel must not compile"));
            let message = format!("{error:#}");
            assert!(message.contains("cel"), "must name the engine: {message}");
            assert!(
                message.contains("scalar") && message.contains("document"),
                "must say why a scalar engine cannot answer a document event: {message}"
            );
            assert!(
                message.contains("lua") && message.contains("js"),
                "must name what does work: {message}"
            );
            assert!(
                message.contains("api.local"),
                "must name the origin: {message}"
            );
        }
    }

    #[test]
    fn wasm_is_refused_because_it_is_not_inline_source() {
        let yaml = origin_with_cache(
            "      enabled: true\n      admit_event:\n        engine: wasm\n        source: \"x\"\n",
        );
        let error = compile_config(&yaml).err().expect("wasm must not compile");
        let message = format!("{error:#}");
        assert!(message.contains("compiled module"), "{message}");
        assert!(
            message.contains("bundle"),
            "must point at the bundle path: {message}"
        );
    }

    #[test]
    fn an_unknown_engine_names_the_ones_that_work() {
        let yaml = origin_with_cache(
            "      enabled: true\n      key_event:\n        engine: rego\n        source: \"x\"\n",
        );
        let message = format!(
            "{:#}",
            compile_config(&yaml)
                .err()
                .expect("unknown engine must not compile")
        );
        assert!(message.contains("rego"), "{message}");
        assert!(
            message.contains("lua") && message.contains("js"),
            "{message}"
        );
    }

    #[test]
    fn an_empty_source_is_refused() {
        let yaml = origin_with_cache(
            "      enabled: true\n      admit_event:\n        engine: lua\n        source: \"   \"\n",
        );
        assert!(
            compile_config(&yaml).is_err(),
            "an empty script would decline on every request while looking configured"
        );
    }

    #[test]
    fn admit_event_and_stale_while_revalidate_compose() {
        // These two were refused together until WOR-2367, because the
        // revalidation refresh had no way to evaluate the event and
        // would write back with the static `ttl_secs`, reverting both
        // the override and any refusal. The refresh now runs the event
        // against the response it fetched, so the pair is legal.
        compile_config(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    response_cache:
      enabled: true
      ttl_secs: 60
      stale_while_revalidate: 30
      admit_event:
        engine: lua
        source: "return {store = true, reason = 'ok'}"
"#,
        )
        .map(|_| ())
        .expect("admit_event and stale_while_revalidate compose now");
    }

    #[test]
    fn a_valid_pair_still_compiles() {
        // The refusals above must not be satisfiable by refusing
        // everything.
        let yaml = origin_with_cache(
            "      enabled: true\n      key_event:\n        engine: lua\n        source: \"return \
             {vary = {'tenant'}}\"\n      admit_event:\n        engine: js\n        source: \
             \"({store: true})\"\n",
        );
        compile_config(&yaml).expect("lua and js decision events must compile");
    }

    #[test]
    fn classifier_hooks_are_a_validated_stock_proxy_config_surface() {
        let valid = r#"
proxy:
  http_bind_port: 8080
  classifier_hooks:
    endpoint: http://127.0.0.1:9440
    timeout_ms: 250
    intent:
      model: intent-v1
    quality:
      minimum_score: 0.8
      provider_models:
        primary:
          model: quality-primary-v1
          label: preferred
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: primary
          provider_type: openai
          api_key: test
"#;
        compile_config(valid).expect("classifier-backed hooks compile from stock config");

        for invalid_block in [
            "timeout_ms: 0\n    intent: {}",
            "timeout_ms: 250\n    quality:\n      minimum_score: 1.1\n      provider_models:\n        primary: { model: q, label: preferred }",
            "timeout_ms: 250\n    quality:\n      minimum_score: 0.8\n      provider_models: {}",
        ] {
            let yaml = format!(
                "proxy:\n  http_bind_port: 8080\n  classifier_hooks:\n    endpoint: http://127.0.0.1:9440\n    {invalid_block}\norigins:\n  x.example.com:\n    action:\n      type: static\n      status_code: 200\n      content_type: text/plain\n      body: ok\n"
            );
            assert!(
                compile_config(&yaml).is_err(),
                "invalid classifier hook block compiled: {invalid_block}"
            );
        }
    }

    #[test]
    fn classifier_hooks_reject_nonlocal_plaintext_and_inline_credentials() {
        let insecure_plaintext = r#"
proxy:
  http_bind_port: 8080
  classifier_hooks:
    endpoint: http://classifier.example:9440
    intent:
      model: intent-v1
origins:
  x.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
        assert!(
            compile_config(insecure_plaintext).is_err(),
            "nonlocal classifier hooks must not allow plaintext transport"
        );

        let inline_bearer = r#"
proxy:
  http_bind_port: 8080
  classifier_hooks:
    endpoint: https://classifier.example:9440
    authentication:
      type: bearer
      credential: inline-token
    intent:
      model: intent-v1
origins:
  x.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
        assert!(
            compile_config(inline_bearer).is_err(),
            "nonlocal classifier hooks must not accept inline bearer material"
        );

        let valid_secret_backed = r#"
proxy:
  http_bind_port: 8080
  classifier_hooks:
    endpoint: https://classifier.example:9440
    authentication:
      type: bearer
      credential: env:SB_CLASSIFIER_TOKEN
    tls:
      ca_pem: file:/etc/sbproxy/classifier-ca.pem
    intent:
      model: intent-v1
origins:
  x.example.com:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
        compile_config(valid_secret_backed)
            .expect("secret-backed nonlocal classifier hook transport must compile");
    }
}
