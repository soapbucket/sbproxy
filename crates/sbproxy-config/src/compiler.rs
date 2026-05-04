//! Config compilation: transforms raw YAML into optimized `CompiledConfig`.
//!
//! The compilation step converts user-facing `ConfigFile` into the
//! performance-optimized `CompiledConfig` / `CompiledOrigin` types that
//! the proxy runtime works with.

use std::sync::Arc;

use anyhow::{Context, Result};
use compact_str::CompactString;
use sbproxy_platform::messenger::aws_sqs::SqsConfig;
use sbproxy_platform::messenger::gcp_pubsub::GcpPubSubConfig;
use sbproxy_platform::messenger::redis::RedisMessengerConfig;
use sbproxy_platform::messenger::{
    GcpPubSubMessenger, MemoryMessenger, Messenger, RedisMessenger, SqsMessenger,
};
use sbproxy_platform::storage::{KVStore, RedisConfig, RedisKVStore};
use smallvec::SmallVec;

use crate::snapshot::{CompiledConfig, CompiledOrigin};
use crate::types::{ConfigFile, L2CacheConfig, MessengerSettings, RawOriginConfig};

/// Extract the Redis host:port pair from a DSN like `redis://host:6379/0`.
///
/// Accepts either a bare `host:port` form (as used by the raw RESP client)
/// or a `redis://[user[:pass]@]host:port[/db]` URL. The database index is
/// ignored since the single-connection RESP client does not issue SELECT.
fn parse_redis_addr(dsn: &str) -> Result<String> {
    let s = dsn.trim();
    let without_scheme = s
        .strip_prefix("redis://")
        .or_else(|| s.strip_prefix("rediss://"))
        .unwrap_or(s);

    // Drop any auth prefix (`user:pass@`).
    let without_auth = without_scheme
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(without_scheme);

    // Drop any trailing /db path and query string.
    let host_port = without_auth
        .split(['/', '?'])
        .next()
        .unwrap_or(without_auth);

    if host_port.is_empty() {
        anyhow::bail!("redis DSN missing host:port");
    }

    // If no port specified, default to 6379.
    if host_port.contains(':') {
        Ok(host_port.to_string())
    } else {
        Ok(format!("{}:6379", host_port))
    }
}

/// Build a concrete `KVStore` for the given L2 cache config.
pub fn build_l2_store(cfg: &L2CacheConfig) -> Result<Arc<dyn KVStore>> {
    match cfg.driver.as_str() {
        "redis" => {
            let addr = parse_redis_addr(&cfg.params.dsn)
                .with_context(|| format!("invalid redis DSN '{}'", cfg.params.dsn))?;
            Ok(Arc::new(RedisKVStore::new(RedisConfig {
                addr,
                ..RedisConfig::default()
            })))
        }
        other => anyhow::bail!("unsupported l2_cache driver: '{}'", other),
    }
}

// --- Messenger factory ---

/// Default bound on per-subscriber queue depth for the in-process memory
/// messenger. Chosen to match the admin-endpoint / purge-subscriber fan-out
/// scale without risking unbounded memory growth if a subscriber stalls.
const DEFAULT_MEMORY_MESSENGER_CAPACITY: usize = 1024;

/// Build a concrete `Messenger` for the given settings block.
///
/// This is the single entry point that maps YAML-level driver strings to
/// concrete platform-crate messenger implementations. Unknown drivers
/// produce an `Err` so the caller can decide whether to degrade to no-bus
/// semantics (the recommended posture: log + continue) or to hard-fail.
///
/// Each driver accepts a small set of string parameters under
/// `messenger_settings.params`:
///
/// * `memory`     - no params. (`capacity` is hardcoded to a sane default.)
/// * `redis`      - `dsn` (default `redis://127.0.0.1:6379`).
/// * `sqs`        - `queue_url`, `region`, `api_key` (all required).
/// * `gcp_pubsub` - `project`, `topic`, `subscription`, `access_token` (all required).
pub fn build_messenger(settings: &MessengerSettings) -> Result<Arc<dyn Messenger>> {
    match settings.driver.as_str() {
        "memory" => Ok(Arc::new(MemoryMessenger::new(
            DEFAULT_MEMORY_MESSENGER_CAPACITY,
        ))),
        "redis" => {
            let dsn = settings
                .params
                .get("dsn")
                .cloned()
                .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
            let addr = parse_redis_addr(&dsn)
                .with_context(|| format!("invalid redis messenger DSN '{}'", dsn))?;
            Ok(Arc::new(RedisMessenger::new(RedisMessengerConfig { addr })))
        }
        "sqs" => {
            let queue_url = settings
                .params
                .get("queue_url")
                .cloned()
                .context("sqs messenger: missing 'queue_url' param")?;
            let region = settings
                .params
                .get("region")
                .cloned()
                .context("sqs messenger: missing 'region' param")?;
            let api_key = settings
                .params
                .get("api_key")
                .cloned()
                .context("sqs messenger: missing 'api_key' param")?;
            Ok(Arc::new(SqsMessenger::new(SqsConfig {
                queue_url,
                region,
                api_key,
            })))
        }
        "gcp_pubsub" => {
            let project = settings
                .params
                .get("project")
                .cloned()
                .context("gcp_pubsub messenger: missing 'project' param")?;
            let topic = settings
                .params
                .get("topic")
                .cloned()
                .context("gcp_pubsub messenger: missing 'topic' param")?;
            let subscription = settings
                .params
                .get("subscription")
                .cloned()
                .context("gcp_pubsub messenger: missing 'subscription' param")?;
            let access_token = settings
                .params
                .get("access_token")
                .cloned()
                .context("gcp_pubsub messenger: missing 'access_token' param")?;
            Ok(Arc::new(GcpPubSubMessenger::new(GcpPubSubConfig {
                project,
                topic,
                subscription,
                access_token,
            })))
        }
        other => anyhow::bail!("unsupported messenger driver: '{}'", other),
    }
}

/// Extract the `type` field from a JSON value.
///
/// Most plugin configs (actions, policies, etc.) use a `type` discriminator
/// to select which implementation to use.
pub fn extract_type(value: &serde_json::Value) -> Result<String> {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing or empty 'type' field"))
}

/// Interpolate `${VAR_NAME}` patterns in a string with environment variables.
///
/// Unresolvable variables are left as-is (literal `${...}` in the output).
fn interpolate_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
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
                    match std::env::var(&var_name) {
                        Ok(val) => result.push_str(&val),
                        Err(_) => {
                            // Leave unresolved variable as literal.
                            result.push_str("${");
                            result.push_str(&var_name);
                            result.push('}');
                        }
                    }
                } else {
                    result.push_str("${");
                    result.push_str(&var_name);
                    if !found_close {
                        // Unterminated ${, just push what we have
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
                // Skip Lua scripts - they are executed at runtime.
                if key == "lua_script" {
                    continue;
                }
                interpolate_config_vars(val, variables);
            }
        }
        _ => {}
    }
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
            if let Some(var_name) = key.strip_prefix("vars.") {
                // Resolve {{vars.X}} from origin variables.
                if let Some(val) = variables.get(var_name) {
                    match val {
                        serde_json::Value::String(s) => result.push_str(s),
                        other => result.push_str(&other.to_string()),
                    }
                } else {
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
                // Leave other patterns (request.*, etc.) for runtime resolution.
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
                // Stay dependency-light: write straight to stderr.
                // Operators relying on structured logs already get
                // the `proxy.extensions[...]` block on the typed
                // bootstrap so the only audience for this line is
                // the engineer running `sbproxy --config foo.yml`.
                eprintln!(
                    "warning: deprecated config: features.{} is deprecated; \
                     lifting into proxy.extensions.{}",
                    legacy, canonical,
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

/// Compile a raw YAML config string into a `CompiledConfig`.
pub fn compile_config(yaml: &str) -> Result<CompiledConfig> {
    // Interpolate environment variables before parsing YAML.
    let yaml = interpolate_env_vars(yaml);
    // Wave 5 day-6 Item 2: lift legacy `features.anomaly_detection`,
    // `features.reputation`, and `features.tls_fingerprint` blocks
    // into the canonical `proxy.extensions[...]` shape the bootstrap
    // expects. Pure-YAML rewrite so the rest of compile_config sees a
    // single source of truth. Returns an error when the legacy and
    // new shapes coexist (operator must pick one).
    let yaml = migrate_features_to_extensions(&yaml)?;
    let config_file: ConfigFile =
        serde_yaml::from_str(&yaml).context("failed to parse config YAML")?;

    let mut origins = Vec::with_capacity(config_file.origins.len());
    let mut host_map = std::collections::HashMap::new();

    for (hostname, raw_config) in config_file.origins {
        let origin = compile_origin(&hostname, raw_config)?;
        let idx = origins.len();
        host_map.insert(CompactString::new(&hostname), idx);
        origins.push(origin);
    }

    // Instantiate the L2 cache backend (Redis) if configured. The store is
    // created lazily, so this call just records the target address without
    // opening a connection yet. Any concrete failure surfaces the first
    // time a request tries to use it.
    let l2_store = match &config_file.proxy.l2_cache {
        Some(cfg) => Some(build_l2_store(cfg)?),
        None => None,
    };

    // Instantiate the shared message bus if configured. An invalid driver
    // here surfaces as a compile-time error so operators see the misconfig
    // at startup (not only when the bus is first published to). A missing
    // block is the graceful "no bus" path and simply yields `None`.
    let messenger = match &config_file.proxy.messenger_settings {
        Some(cfg) => Some(build_messenger(cfg)?),
        None => None,
    };

    Ok(CompiledConfig {
        origins,
        host_map,
        server: config_file.proxy,
        l2_store,
        messenger,
        // The mesh node is built by the enterprise startup hook (not OSS),
        // so compilation always yields `None` here.
        mesh: None,
        // Access-log emission settings ride through unchanged. `None`
        // (the default) keeps the logging hook a no-op.
        access_log: config_file.access_log,
        // G1.4 wire: hand the parsed `agent_classes:` block to the
        // binary startup code. The resolver itself is constructed in
        // `sbproxy-core` (which depends on the classifier crate); this
        // crate stays ignorant of the typed resolver.
        agent_classes: config_file.agent_classes,
    })
}

/// Compile a single origin from its raw config.
pub fn compile_origin(hostname: &str, mut config: RawOriginConfig) -> Result<CompiledOrigin> {
    let allowed_methods: SmallVec<[http::Method; 4]> = config
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse::<http::Method>().ok())
        .collect();

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
    if let Some(ref mut error_pages) = config.error_pages {
        interpolate_config_vars(error_pages, &config.variables);
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
    // Parse errors are downgraded to "no cache" with a warning so that a
    // malformed block does not break the whole pipeline.
    let response_cache: Option<crate::types::ResponseCacheConfig> = match &config.response_cache {
        Some(v) => match serde_json::from_value::<crate::types::ResponseCacheConfig>(v.clone()) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                eprintln!(
                    "[sbproxy-config] ignoring response_cache for {}: {}",
                    hostname, e
                );
                None
            }
        },
        None => None,
    };

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
    // See `docs/adr-content-negotiation-and-pricing.md` (G4.1) for
    // the resolver contract and `docs/adr-json-envelope-schema.md`
    // (A4.2) for the envelope's place in the chain.
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

    Ok(CompiledOrigin {
        hostname: CompactString::new(hostname),
        origin_id: CompactString::new(hostname),
        workspace_id: CompactString::default(),
        action_config: config.action,
        auth_config: config.authentication,
        policy_configs: config.policies,
        transform_configs: config.transforms,
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
        bot_detection: config.bot_detection,
        threat_protection: config.threat_protection,
        on_request: config.on_request,
        on_response: config.on_response,
        response_cache,
        mirror: config.mirror,
        extensions: config.extensions,
        expose_openapi: config.expose_openapi,
        stream_safety: config.stream_safety,
        // R2.3 wire: ride the parsed `rate_limits:` block onto the
        // compiled snapshot. The handler-chain mount lives in a
        // follow-up; this commit just makes the YAML schema land.
        rate_limits: config.rate_limits,
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
    })
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
        std::env::set_var("TEST_ENV_VALUE_COMPILE", "from-env-42");
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
        std::env::remove_var("TEST_ENV_VALUE_COMPILE");
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
    // `sbproxy-modules::compile_auth`. The enterprise binary registers
    // the `kya` provider via inventory so the runtime path resolves;
    // the tests below pin the OSS parse-and-pass-through contract so
    // that an `sb.yml` carrying `authentication.type: kya` compiles
    // unchanged on the OSS side. The verifier itself lives in
    // `sbproxy-enterprise-modules::auth::kya` (out of this crate's
    // dependency tree).
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
        // Defaults are filled in by the enterprise verifier at
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
        // the snapshot so the enterprise verifier sees them.
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
            "forward-compat fields must round-trip to the enterprise verifier"
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

    #[test]
    fn interpolate_env_in_json_string() {
        std::env::set_var("SBPROXY_TEST_HOST", "env-backend");
        let vars: HashMap<String, serde_json::Value> = HashMap::new();
        let mut val = serde_json::json!("http://{{env.SBPROXY_TEST_HOST}}:8080");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "http://env-backend:8080");
        std::env::remove_var("SBPROXY_TEST_HOST");
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

    #[test]
    fn interpolate_unresolved_vars_left_as_is() {
        let vars: HashMap<String, serde_json::Value> = HashMap::new();
        let mut val = serde_json::json!("{{vars.unknown}}");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "{{vars.unknown}}");
    }

    #[test]
    fn interpolate_mixed_vars_and_env() {
        std::env::set_var("SBPROXY_MIX_PORT", "9090");
        let vars: HashMap<String, serde_json::Value> =
            [("host".to_string(), serde_json::json!("api.local"))]
                .into_iter()
                .collect();
        let mut val = serde_json::json!("http://{{vars.host}}:{{env.SBPROXY_MIX_PORT}}/api");
        interpolate_config_vars(&mut val, &vars);
        assert_eq!(val.as_str().unwrap(), "http://api.local:9090/api");
        std::env::remove_var("SBPROXY_MIX_PORT");
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
        // Opaque per-origin extensions must round-trip from the raw
        // YAML into the compiled snapshot so enterprise crates (e.g.
        // the semantic-cache hook) can read their own keys.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    extensions:
      semantic_cache:
        enabled: true
        ttl_secs: 600
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("api.example.com").expect("origin");
        let sc = origin
            .extensions
            .get("semantic_cache")
            .expect("semantic_cache extension present after compile");
        assert!(sc.get("enabled").unwrap().as_bool().unwrap());
        assert_eq!(sc.get("ttl_secs").unwrap().as_u64().unwrap(), 600);
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

    // --- build_messenger tests ---

    #[test]
    fn build_messenger_memory_driver() {
        // The in-process driver needs no params and must always succeed
        // so that the single-replica dev experience is never gated on
        // external dependencies.
        use crate::types::MessengerSettings;
        let settings = MessengerSettings {
            driver: "memory".to_string(),
            params: std::collections::HashMap::new(),
        };
        let bus = build_messenger(&settings).expect("memory messenger must build");
        // Publish -> subscribe roundtrip proves the Arc is a live instance.
        let mut sub = bus.subscribe("t").expect("subscribe");
        bus.publish(&sbproxy_platform::messenger::Message {
            topic: "t".into(),
            payload: serde_json::json!({"ok": true}),
            timestamp: 1,
        })
        .expect("publish");
        drop(bus);
        let msg = sub.next().expect("message");
        assert_eq!(msg.payload["ok"], serde_json::json!(true));
    }

    #[test]
    fn build_messenger_redis_driver_uses_default_dsn() {
        // No DSN supplied should not fail: the redis messenger only opens
        // its connection lazily, so construction is always cheap.
        use crate::types::MessengerSettings;
        let settings = MessengerSettings {
            driver: "redis".to_string(),
            params: std::collections::HashMap::new(),
        };
        let _bus = build_messenger(&settings).expect("redis messenger must build");
    }

    #[test]
    fn build_messenger_unknown_driver_errors() {
        // Unknown drivers must surface an error so misconfigured YAML is
        // caught at compile time rather than silently producing a no-op bus.
        use crate::types::MessengerSettings;
        let settings = MessengerSettings {
            driver: "invalid_backend".to_string(),
            params: std::collections::HashMap::new(),
        };
        assert!(build_messenger(&settings).is_err());
    }

    #[test]
    fn compile_config_attaches_messenger_when_settings_present() {
        // End-to-end: `messenger_settings: {driver: memory}` in YAML must
        // land on `CompiledConfig.messenger` as a live `Arc<dyn Messenger>`.
        let yaml = r#"
proxy:
  messenger_settings:
    driver: memory
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        assert!(
            compiled.messenger.is_some(),
            "messenger must be built from messenger_settings block"
        );
    }

    #[test]
    fn compile_config_parses_rate_limits_block_per_origin() {
        // R2.3 wire: the `rate_limits:` block on an origin must
        // round-trip onto `CompiledOrigin::rate_limits` so the
        // handler-chain mount has a typed source.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    rate_limits:
      tenant_burst: 2000
      tenant_sustained: 1000
      route_default: 100
      route_overrides:
        /search: 50
      soft_threshold_rps: 800
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("api.example.com").expect("origin");
        let rl = origin.rate_limits.as_ref().expect("rate_limits parsed");
        assert_eq!(rl.tenant_burst, 2000);
        assert_eq!(rl.tenant_sustained, 1000);
        assert_eq!(rl.route_default, 100);
        assert_eq!(rl.route_overrides.get("/search"), Some(&50));
        assert_eq!(rl.soft_threshold_rps, Some(800));
    }

    #[test]
    fn compile_config_no_rate_limits_when_block_absent() {
        // Backwards compat: an origin without the `rate_limits:`
        // block lands `rate_limits = None` so the middleware mount
        // skips it entirely.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        let origin = compiled.resolve_origin("api.example.com").expect("origin");
        assert!(origin.rate_limits.is_none());
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
    fn compile_config_no_messenger_when_settings_absent() {
        // Absent messenger_settings: `CompiledConfig.messenger` stays None
        // so consumers (e.g. the purge subscriber) cleanly skip spawning.
        let yaml = r#"
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
        let compiled = compile_config(yaml).expect("compile");
        assert!(compiled.messenger.is_none());
    }

    // --- Wave 4 day-4 auto-wire tests (G4.1 + G4.10 + G4.4) ---

    // --- Wave 4 day-4 auto-wire tests: content_negotiate (G4.1) ---

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
}
