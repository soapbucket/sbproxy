//! Pipeline reload and process lifecycle: config hot-reload
//! (`reload_from_config_path`), the file watcher, the SIGHUP handler,
//! graceful-shutdown config, the `run` entry point, and ARDP discovery.
//!
//! Extracted from `server.rs`. Behavior-preserving move;
//! `use super::*` re-imports the parent module's items. The public
//! `run`, `GraceConfig`, `reload_from_config_path`, and
//! `install_sighup_handler` stay public and are re-exported by the
//! parent so existing paths (incl. the binary's) are unchanged.

use super::*;

/// Start a file watcher that reloads the config on changes.
///
/// Spawns a background thread that watches the config file for modifications.
/// On change, it re-reads, re-compiles, and hot-swaps the pipeline via
/// [`reload::load_pipeline`]. Parse or compile errors are logged but do not
/// crash the proxy - the previous valid config continues to serve traffic.
/// Reload the proxy pipeline from a YAML config file at `config_path`.
///
/// The single source of truth for reload semantics shared by:
///
/// - The notify-based file watcher (auto-reload on `sb.yml` change).
/// - The SIGHUP signal handler (operator-driven reload
///   via `kill -HUP $(pgrep sbproxy)`).
///
/// Reads the file, runs `compile_config` (which also drives the
/// features.* migration), constructs a fresh
/// [`CompiledPipeline`], invokes the enterprise reload hook
/// (best-effort), and atomically swaps the live pipeline. Returns
/// `Ok(())` on success; logs and returns `Err` on any step's failure
/// so the caller can decide whether to retry.
///
/// Idempotent: invoking back-to-back yields the same effect as one
/// invocation. Safe to call from any thread; the global pipeline
/// `ArcSwap` handles the publish.
pub fn reload_from_config_path(config_path: &str) -> anyhow::Result<()> {
    // WOR-1101: stamp every reload outcome so operators can alert on
    // failures and watch the reload cadence from metrics, not just
    // logs. The inner function carries the original early-return body.
    let result = reload_from_config_path_inner(config_path);
    match &result {
        Ok(()) => sbproxy_observe::metrics::record_config_reload("success"),
        Err(_) => sbproxy_observe::metrics::record_config_reload("failure"),
    }
    result
}

fn reload_from_config_path_inner(config_path: &str) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{config_path}': {e}"))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;
    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }

    // WOR-594: refresh the operator-configured Lua sandbox limits on
    // reload so SIGHUP / hot-reload pick up changes to
    // `proxy.scripting.lua.sandbox:` without restarting the process.
    sbproxy_extension::lua::install_sandbox_config(sbproxy_extension::lua::SandboxConfig::from(
        &compiled.server.scripting.lua.sandbox,
    ));

    // Refresh the operator-extensible log redactor on reload so
    // SIGHUP picks up changes to `proxy.observability.log.redact:`
    // (proxy scope) as well as the tenant-scope and origin-scope
    // `observability.log.redact.pii:` overrides (WOR-1043 PR2 / PR3).
    install_op_redact_state(&compiled);

    // WOR-1067 PR2: refresh per-tenant cardinality caps on reload so
    // SIGHUP picks up changes to `tenants[].observability.cardinality.max_series`
    // without restarting the process. Tenants without an entry stay
    // on the proxy-wide cap.
    install_tenant_cardinality_state(&compiled.server);

    // WOR-1045 PR1 + PR2: validate the declared sinks block and (PR2)
    // build a SinkDispatcher from proxy + tenant + origin scopes so
    // every declared sink receives the matching records. When no
    // sinks block is declared, the dispatcher slot stays empty and
    // the legacy `tracing::*!` fallback continues to drive stdout.
    validate_sinks_config(&compiled.server);
    install_sink_dispatcher_from_config(&compiled);

    // WOR-173: refresh the AI provider catalog and rebuild the AI
    // client alongside the pipeline. Both globals live behind an
    // `ArcSwap`, so this is a lock-free atomic swap from the reload
    // thread's perspective. Failures fall back to the embedded
    // catalog with a warn-level log inside `reload_provider_registry`,
    // matching the startup behaviour. Note: `BUDGET_TRACKER` is
    // deliberately *not* refreshed - in-memory accumulators must
    // survive reload, see the doc comment on the static.
    {
        let override_path = compiled
            .server
            .ai_providers_file
            .as_deref()
            .map(std::path::Path::new);
        if let Err(e) = sbproxy_ai::reload_provider_registry(override_path) {
            tracing::error!(
                error = %e,
                "AI provider registry reload failed; serving with the previous catalog",
            );
        } else {
            reload_ai_client();
        }
    }

    let mut new_pipeline = CompiledPipeline::from_config(compiled)?;

    // WOR-196: pick up `listings/*.yaml` from the same Repo (the
    // directory the served `sb.yml` lives in) and stash the loaded
    // registry on the pipeline. The projection layer reads
    // `pipeline.listings` and renders the per-Listing Agent Skills
    // surface for the well-known endpoints. Load errors are logged
    // at warn level and the registry stays empty; the OSS surface
    // continues to serve the top-level `agent_skills:` block.
    {
        let repo_root = std::path::Path::new(config_path)
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let mut load_errors: Vec<sbproxy_config::ListingLoadError> = Vec::new();
        let loaded = sbproxy_config::load_listings_from_repo(&repo_root, &mut load_errors);
        for err in &load_errors {
            tracing::warn!(error = %err, "listings load error; skipping entry");
        }
        if !loaded.is_empty() {
            let mut findings: Vec<sbproxy_config::PlanFinding> = Vec::new();
            new_pipeline.listings =
                sbproxy_config::ListingRegistry::from_loaded(loaded, &mut findings);
            for finding in &findings {
                tracing::warn!(
                    rule_id = %finding.rule_id,
                    path = %finding.path,
                    message = %finding.message,
                    "listing registry finding"
                );
            }
        }
    }

    // Invoke the enterprise reload hook (best-effort): the OSS reload
    // path must continue to swap the pipeline even if a downstream
    // hook errors, otherwise a failing enterprise extension would
    // permanently pin the operator on the old config. We spin up a
    // current-thread runtime when no ambient tokio runtime exists so
    // the file-watcher thread (plain std thread) can also call this.
    if let Some(startup) = new_pipeline.hooks.startup.clone() {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Err(e) = startup.on_reload(&mut new_pipeline).await {
                        tracing::warn!(
                            error = %e,
                            "enterprise reload hook failed; serving with prior hook state",
                        );
                    }
                });
            });
        } else {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(hook_rt) => {
                    if let Err(e) = hook_rt.block_on(startup.on_reload(&mut new_pipeline)) {
                        tracing::warn!(
                            error = %e,
                            "enterprise reload hook failed; serving with prior hook state",
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to build reload-hook runtime; skipping reload hook",
                    );
                }
            }
        }
    }
    reload::load_pipeline(new_pipeline);
    tracing::info!("config reloaded successfully");
    Ok(())
}

pub(super) fn start_config_watcher(config_path: String) {
    use notify::{RecursiveMode, Watcher};

    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "failed to create config file watcher");
                return;
            }
        };

        if let Err(e) = watcher.watch(
            std::path::Path::new(&config_path),
            RecursiveMode::NonRecursive,
        ) {
            tracing::error!(error = %e, path = %config_path, "failed to watch config file");
            return;
        }

        tracing::info!(path = %config_path, "config file watcher started");

        for event in rx {
            match event {
                Ok(event) if event.kind.is_modify() => {
                    tracing::info!("config file changed, reloading...");
                    if let Err(e) = reload_from_config_path(&config_path) {
                        tracing::error!(error = %e, "reload failed; serving prior pipeline");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "config file watcher error");
                }
                _ => {}
            }
        }
    });
}

/// Install a SIGHUP signal handler that reloads the proxy pipeline
/// from `config_path`.
///
/// SIGHUP is the canonical "rerun bootstrap" signal in traditional
/// reverse proxies (nginx, haproxy). This function spawns a tokio
/// task that listens on the OS signal and calls
/// [`reload_from_config_path`] for each delivery. Multiple SIGHUPs
/// arriving back-to-back coalesce into multiple reloads (last write
/// wins on the `ArcSwap` inside `reload::load_pipeline`).
///
/// On non-Unix targets this is a no-op (Windows et al. have no
/// SIGHUP equivalent).
#[cfg(unix)]
pub fn install_sighup_handler(config_path: String) {
    use tokio::signal::unix::{signal, SignalKind};
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!(
            "no tokio runtime in scope; SIGHUP handler not installed (call from inside the tokio runtime)",
        );
        return;
    }
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        tracing::info!("SIGHUP handler installed; send `kill -HUP <pid>` to reload");
        while sig.recv().await.is_some() {
            tracing::info!("SIGHUP received; reloading config...");
            // WOR-618: `reload_from_config_path` does blocking config-file
            // reads, YAML parsing, pipeline rebuild, and projection refresh.
            // Run it on the blocking pool so the tokio worker that owns
            // the SIGHUP listener stays responsive to other signals.
            let path = config_path.clone();
            let result = tokio::task::spawn_blocking(move || reload_from_config_path(&path)).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "SIGHUP reload failed; serving prior pipeline");
                }
                Err(join_err) => {
                    tracing::error!(
                        error = %join_err,
                        "SIGHUP reload task panicked; serving prior pipeline",
                    );
                }
            }
        }
    });
}

/// SIGHUP handler is a no-op on non-Unix targets.
#[cfg(not(unix))]
pub fn install_sighup_handler(_config_path: String) {
    tracing::debug!("SIGHUP handler is unix-only; skipping on this target");
}

/// Resolve the graceful-shutdown grace period (in whole seconds) from
/// the two supported env vars. WOR-636.
///
/// Precedence (highest wins):
/// 1. `SBPROXY_SHUTDOWN_GRACE_MS` (milliseconds, current canonical
///    spelling)
/// 2. `SB_GRACE_TIME` (seconds, legacy)
/// 3. `0` (Pingora's instant-shutdown default; the binary wrapper
///    overlays a 30s default before this is called)
///
/// Pingora's `grace_period_seconds` is a whole-second field, so the
/// millisecond value rounds up to the next whole second when it does
/// not divide evenly. A value of `0` is preserved as `0`. A value
/// that fails to parse logs a warning and falls through to the next
/// source.
pub(crate) fn resolve_shutdown_grace_seconds(ms_var: Option<&str>, sec_var: Option<&str>) -> u64 {
    if let Some(v) = ms_var {
        match v.parse::<u64>() {
            Ok(ms) => {
                // Round milliseconds up to the next whole second so a
                // 500ms grace still gives an in-flight request a full
                // second to drain. Saturates at u64::MAX / 1000.
                let secs = ms.saturating_add(999) / 1000;
                return secs;
            }
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "SBPROXY_SHUTDOWN_GRACE_MS is not a non-negative integer; ignoring"
                );
            }
        }
    }
    if let Some(v) = sec_var {
        match v.parse::<u64>() {
            Ok(s) => return s,
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "SB_GRACE_TIME is not a non-negative integer; ignoring"
                );
            }
        }
    }
    0
}

/// Graceful-shutdown grace-period inputs for [`run`].
///
/// The binary (`crates/sbproxy/src/main.rs`) resolves these from its
/// CLI flags / env (`--shutdown-grace-ms` / `SBPROXY_SHUTDOWN_GRACE_MS`
/// and `--grace-time` / `SB_GRACE_TIME`) and passes them in explicitly,
/// rather than re-exporting them as process env vars for `run` to read
/// back. Both `None` means the in-process default of zero (instant
/// shutdown), which the Go e2e runner and dev loops rely on.
#[derive(Debug, Default, Clone, Copy)]
pub struct GraceConfig {
    /// Preferred source: shutdown grace in milliseconds.
    pub shutdown_grace_ms: Option<u64>,
    /// Legacy source: grace in whole seconds (`SB_GRACE_TIME`).
    pub grace_time_secs: Option<u64>,
}

/// Spawn a background thread that subscribes to the Pingora server's
/// `execution_phase_watch` broadcast and emits structured tracing
/// events at each transition. WOR-636.
///
/// Pingora handles SIGINT (fast shutdown) and SIGTERM (graceful
/// shutdown) inside [`pingora_core::server::Server::run_forever`].
/// The phase broadcast is the documented surface for observing those
/// transitions from outside the Pingora runtime; emitting our own
/// `tracing` events here means operators see a clear "shutdown
/// signal received" log line in the same stream as the request logs,
/// and the `shutdown.kind` / `shutdown.grace_seconds` fields make the
/// event filterable by structured-log consumers.
///
/// The subscriber must be acquired **before** `Server::run_forever`
/// consumes the `Server` value; this function is a no-op when called
/// after that point because the broadcast sender is dropped.
pub(super) fn spawn_shutdown_phase_logger(
    mut rx: tokio::sync::broadcast::Receiver<pingora_core::server::ExecutionPhase>,
    grace_seconds: u64,
) {
    std::thread::Builder::new()
        .name("sbproxy-shutdown-log".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to build shutdown-phase logger runtime; structured shutdown logs disabled"
                    );
                    return;
                }
            };
            rt.block_on(async move {
                loop {
                    match rx.recv().await {
                        Ok(pingora_core::server::ExecutionPhase::GracefulTerminate) => {
                            tracing::info!(
                                event = "shutdown_signal_received",
                                signal = "SIGTERM",
                                kind = "graceful",
                                grace_seconds = grace_seconds,
                                "SIGTERM received; draining in-flight requests"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownStarted) => {
                            tracing::info!(
                                event = "shutdown_started",
                                grace_seconds = grace_seconds,
                                "shutdown started"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownGracePeriod) => {
                            tracing::info!(
                                event = "shutdown_grace_period",
                                grace_seconds = grace_seconds,
                                "graceful shutdown grace period started"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownRuntimes) => {
                            tracing::info!(
                                event = "shutdown_runtimes",
                                "waiting for service runtimes to exit"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::Terminated) => {
                            tracing::info!(event = "shutdown_complete", "sbproxy has stopped");
                            break;
                        }
                        Ok(_) => {
                            // Earlier phases (Running, etc.) are not
                            // shutdown-related; skip them.
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped = skipped,
                                "shutdown-phase logger lagged behind Pingora's phase broadcast"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            // Sender dropped: the server is fully
                            // torn down. Nothing more to log.
                            break;
                        }
                    }
                }
            });
        })
        .ok();
}

/// Create and start a Pingora server with the given config file path.
///
/// This function:
/// 1. Reads and compiles the YAML config
/// 2. Compiles it into a pipeline with module instances
/// 3. Loads it into the hot-reload store
/// 4. Starts a file watcher for config hot-reload
/// 5. Creates a Pingora server with an HTTP proxy service
/// 6. Starts the server (blocks forever)
///
/// Pingora handles SIGTERM (graceful shutdown) and SIGINT (fast
/// shutdown) internally inside `Server::run_forever`. We subscribe
/// to Pingora's execution-phase broadcast (see
/// `spawn_shutdown_phase_logger`) so a structured tracing event is
/// emitted when a shutdown signal arrives; operators can grep for
/// `shutdown_signal_received` in the logs to see the drain start.
/// The grace period comes from the [`GraceConfig`] the binary passes
/// in (preferring `shutdown_grace_ms` over `grace_time_secs`), resolved
/// to seconds by `resolve_shutdown_grace_seconds`. The file watcher
/// handles config reload on file change,
/// which is equivalent to SIGHUP-based reload in traditional
/// servers.
pub fn run(config_path: &str, grace: GraceConfig) -> anyhow::Result<()> {
    use pingora_core::apps::HttpServerOptions;
    use pingora_core::server::configuration::ServerConf as PingoraServerConf;
    use pingora_core::server::Server;
    use pingora_proxy::http_proxy_service;

    // Load and compile the config.
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", config_path, e))?;
    let initial_content_hash = crate::identity::config_revision(yaml.as_bytes());
    let compiled = sbproxy_config::compile_config(&yaml)?;
    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }
    let port = compiled.server.http_bind_port;

    // Extract TLS-relevant fields before compiled is consumed by from_config.
    let server_config = compiled.server.clone();
    let hostnames: Vec<String> = compiled.host_map.keys().map(|k| k.to_string()).collect();

    if let Some(metrics_cfg) = server_config.metrics.as_ref() {
        let _ = sbproxy_observe::metrics::init_cardinality_limiter(
            sbproxy_observe::CardinalityConfig {
                max_per_label: metrics_cfg.max_cardinality_per_label,
                hostname_cap: metrics_cfg.cardinality.hostname_cap,
            },
        );
    }

    // Install operator-extensible redaction state into the global
    // log redactor. Compiled patterns + the extra field-key denylist
    // come from `proxy.observability.log.redact:`; an absent block
    // installs an empty state so the call site stays uniform across
    // single-tenant and multi-tenant deployments. The hook accepts
    // re-install so config reloads flow through. Tenant- and
    // origin-scope `observability.log.redact.pii:` overrides
    // (WOR-1043 PR2 / PR3) are composed off the proxy-scope rule set.
    install_op_redact_state(&compiled);
    install_tenant_cardinality_state(&server_config);
    validate_sinks_config(&server_config);
    install_sink_dispatcher_from_config(&compiled);

    // Walk the inventory-based plugin registry once at startup and
    // emit one `sbproxy_plugin_registered_total{kind, plugin}` row
    // per known registration. Subsequent reloads do not re-walk
    // because the inventory set is fixed at link time.
    report_plugin_registrations();

    // WOR-594: install the operator-configured Lua sandbox limits
    // into the extension crate's process-wide handle. Every
    // `LuaEngine::new()` after this point (request modifiers, response
    // modifiers, WAF custom rules, JSON transforms) picks up these
    // values; before this runs, the documented defaults are in
    // effect.
    sbproxy_extension::lua::install_sandbox_config(sbproxy_extension::lua::SandboxConfig::from(
        &server_config.scripting.lua.sandbox,
    ));

    // Initialise the AI provider catalog from the embedded YAML, with
    // an optional override path from `proxy.ai_providers_file`: use
    // the override file when readable, fall back to the embedded
    // gzipped catalog otherwise. The registry lives behind an
    // `ArcSwap` so SIGHUP / file-watcher / admin reload paths can
    // swap in a fresh catalog via `reload_provider_registry` without
    // restarting the process.
    {
        let override_path = server_config
            .ai_providers_file
            .as_deref()
            .map(std::path::Path::new);
        if let Err(e) = sbproxy_ai::providers::init_provider_registry(override_path) {
            tracing::error!(
                error = %e,
                "failed to initialise AI provider registry; falling back to embedded defaults on first lookup"
            );
        }
    }

    // --- Wave 3 / G1.4 wire: agent-class resolver startup ---
    //
    // Build the process-wide `AgentClassResolver` from the parsed
    // top-level `agent_classes:` block (or from defaults when the block
    // is absent), then install it in the global slot the request
    // pipeline reads in `request_filter`. The catalog source toggles
    // between the embedded `builtin` defaults, an external `hosted-feed`
    // (placeholder until G2.2 lands the registry fetcher), or the two
    // `merged` (currently equivalent to defaults; the registry overlay
    // arrives in G2.2). All paths are infallible: a malformed
    // `hosted_feed` block degrades gracefully to defaults so a startup
    // misconfiguration does not block serving.
    #[cfg(feature = "agent-class")]
    {
        install_agent_class_resolver(compiled.agent_classes.as_ref());
    }

    // --- Wave 5 / G5.4: install TLS-fingerprint catalogue ---
    //
    // The catalogue lives behind an arc-swap so SIGHUP reloads can
    // refresh it without dropping in-flight detector reads. The
    // embedded JSON ships with the seed entries from A5.1; the
    // builder task (B5.x) refreshes the file via a monthly PR.
    // Failures degrade gracefully: an empty catalogue means the
    // detector never matches, which is the safe default.
    #[cfg(feature = "tls-fingerprint")]
    {
        use std::sync::Arc as TlsFingerprintArc;
        match sbproxy_security::TlsFingerprintCatalog::default_embedded() {
            Ok(catalog) => {
                // Also install the CEL matcher adapter so
                // `tls_fingerprint_matches(ja4, agent_class_id)`
                // resolves against the same catalogue.
                struct CatalogAdapter(sbproxy_security::TlsFingerprintCatalog);
                impl sbproxy_extension::cel::TlsFingerprintMatcher for CatalogAdapter {
                    fn matches(&self, ja4: &str, agent_class_id: &str) -> bool {
                        self.0.matches(ja4, agent_class_id)
                    }
                }
                let adapter: TlsFingerprintArc<dyn sbproxy_extension::cel::TlsFingerprintMatcher> =
                    TlsFingerprintArc::new(CatalogAdapter(catalog.clone()));
                sbproxy_extension::cel::set_tls_fingerprint_matcher(adapter);
                reload::set_tls_fingerprint_catalog(catalog);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load embedded TLS fingerprint catalogue; headless detection disabled"
                );
            }
        }
    }

    // --- WOR-706: install agent-detect rule-pack loader ---
    //
    // When `proxy.extensions.agent_detect.enabled` is set with a
    // `rule_pack_path`, load the ADRF pack once and install the loader so
    // `request_filter` can run the scorer. A load failure (or a missing
    // path) degrades to no detection (the request_filter block
    // short-circuits when no loader is installed) rather than blocking
    // serving, matching the TLS-catalogue block above.
    {
        let agent_detect_cfg =
            crate::pipeline::AgentDetectConfig::from_extensions(&compiled.server.extensions);
        if agent_detect_cfg.enabled {
            match agent_detect_cfg.rule_pack_path.as_deref() {
                Some(path) => match sbproxy_agent_detect::RulePackLoader::open(path) {
                    Ok(loader) => reload::set_agent_detect_loader(loader),
                    Err(e) => tracing::warn!(
                        error = %e,
                        path = %path,
                        "failed to load agent-detect rule pack; agent detection disabled",
                    ),
                },
                None => tracing::warn!(
                    "agent_detect.enabled is set but rule_pack_path is unset; agent detection disabled",
                ),
            }
        }
    }

    // --- WOR-201 PR 1b: install policy verdict audit bus ---
    //
    // Construct a bounded mpsc channel and install the sender as the
    // process-wide audit bus before the pipeline is loaded. The
    // dispatcher emits a `PolicyVerdictEvent` for every policy
    // decision; the OSS drain stub on the receiver prints each event
    // to stderr as a JSON line. Enterprise replaces the consumer
    // with a NATS-backed audit-chain subscriber per
    // `docs/adr-policy-audit-binding.md`.
    //
    // Spawn the drain on a dedicated single-threaded runtime in a
    // background std thread so it lives independently of Pingora's
    // worker runtimes. This mirrors the SIGHUP handler pattern below
    // and keeps the audit consumer alive for the full process
    // lifetime.
    {
        let (tx, rx) = crate::policy_bus::channel(crate::policy_bus::DEFAULT_BUS_CAPACITY);
        let _ = crate::policy_bus::init_global_bus(tx);
        std::thread::Builder::new()
            .name("sbproxy-policy-bus-drain".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build policy-bus drain runtime");
                        return;
                    }
                };
                rt.block_on(async move {
                    crate::policy_bus::drain_to_stderr(rx).await;
                });
            })
            .ok();
    }

    // Compile config into a pipeline with action/auth/policy module instances.
    let mut pipeline = CompiledPipeline::from_config(compiled)?;

    // WOR-196: pick up `listings/*.yaml` from the same Repo (the
    // directory the served `sb.yml` lives in) and stash the loaded
    // registry on the pipeline so the projection layer can serve the
    // per-Listing and aggregated agent-skills endpoints. Mirrors the
    // same wiring in `reload_from_config_path` so SIGHUP and file-
    // watcher reloads pick up listing edits too.
    {
        let repo_root = std::path::Path::new(config_path)
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let mut load_errors: Vec<sbproxy_config::ListingLoadError> = Vec::new();
        let loaded = sbproxy_config::load_listings_from_repo(&repo_root, &mut load_errors);
        for err in &load_errors {
            tracing::warn!(error = %err, "listings load error; skipping entry");
        }
        if !loaded.is_empty() {
            let mut findings: Vec<sbproxy_config::PlanFinding> = Vec::new();
            pipeline.listings = sbproxy_config::ListingRegistry::from_loaded(loaded, &mut findings);
            for finding in &findings {
                tracing::warn!(
                    rule_id = %finding.rule_id,
                    path = %finding.path,
                    message = %finding.message,
                    "listing registry finding"
                );
            }
        }
    }

    // Give enterprise code a chance to wire its hooks, construct clients,
    // and register origins. Failures here do NOT block serving: they log
    // and return None-hooks, so request paths fall through to OSS behavior.
    //
    // `pub fn run` is sync (called from `main` before Pingora's runtime
    // starts), so we drive the async hook on a short-lived current-thread
    // runtime. The cloned Arc avoids holding a borrow of `pipeline.hooks`
    // across the await, which would conflict with the `&mut pipeline` arg.
    if pipeline.hooks.startup.is_none() {
        pipeline.hooks.startup = crate::hook_registry::collect_startup_hook();
    }
    if let Some(startup) = pipeline.hooks.startup.clone() {
        let hook_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build startup-hook runtime: {}", e))?;
        if let Err(e) = hook_rt.block_on(startup.on_startup(&mut pipeline)) {
            tracing::warn!(
                error = %e,
                "enterprise startup hook failed; continuing without enterprise features"
            );
        }
    }

    // Store in hot-reload slot.
    reload::load_pipeline(pipeline);

    // Start file watcher for config hot-reload.
    start_config_watcher(config_path.to_string());

    // --- Wave 5 day-6 Item 4: SIGHUP re-bootstrap handler ---
    //
    // Pingora's `Server::run_forever` owns its own tokio runtime, but
    // it neither installs a SIGHUP handler nor re-runs our bootstrap
    // on receipt. Spawn a dedicated single-threaded runtime on a
    // background std thread so an operator-driven `kill -HUP $(pgrep
    // sbproxy)` re-runs `reload_from_config_path` (which threads
    // through compile_config + the day-6 features.* migration + the
    // enterprise reload hook). Idempotent: each delivery atomically
    // swaps the live pipeline; multiple back-to-back SIGHUPs coalesce.
    {
        let cfg_path = config_path.to_string();
        std::thread::Builder::new()
            .name("sbproxy-sighup".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build SIGHUP runtime");
                        return;
                    }
                };
                rt.block_on(async {
                    install_sighup_handler(cfg_path);
                    // Park forever; the spawned task holds the runtime
                    // alive. A future shutdown signal will tear this
                    // down alongside Pingora's main runtime.
                    std::future::pending::<()>().await;
                });
            })
            .ok();
    }

    // --- TLS setup ---
    let tls_state = if server_config.https_bind_port.is_some()
        || server_config.tls_cert_file.is_some()
        || server_config.acme.as_ref().is_some_and(|a| a.enabled)
    {
        match sbproxy_tls::TlsState::init(&server_config, hostnames) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize TLS");
                return Err(e);
            }
        }
    } else {
        None
    };

    // Create Pingora server. The graceful-shutdown grace period is
    // resolved from three sources (preferred first):
    //
    //   1. `SBPROXY_SHUTDOWN_GRACE_MS` (milliseconds, WOR-636)
    //   2. `SB_GRACE_TIME` (seconds, legacy, kept for back-compat)
    //   3. zero (instant) for the Go e2e runner and dev loops
    //
    // The binary wrapper (`crates/sbproxy/src/main.rs`) overlays a 30s
    // default before calling in here so end users get a sane grace
    // period without setting any env var; the in-process default
    // stays zero so the Go e2e runner (which sends SIGTERM between
    // test cases and immediately tries to bind the same port for the
    // next case) does not pay a 30s port-busy penalty.
    //
    // Pingora handles SIGINT (fast shutdown) and SIGTERM (graceful
    // shutdown) inside `Server::run_forever`. We subscribe to the
    // execution-phase broadcast below so the structured shutdown log
    // line lands in operator-facing tracing output. See
    // `docs/manual.md` for the signal contract.
    //
    // Performance tuning (see sbproxy-bench/docs/TUNING.md):
    //   * threads: Pingora's default is 1 (single-threaded). Match Go's
    //     GOMAXPROCS behaviour by using all logical cores.
    //   * upstream_keepalive_pool_size: bump from 128 to 256 to match the
    //     Go http.Transport MaxIdleConnsPerHost we set on the Go side.
    // Offload upstream DNS + connect() onto a dedicated threadpool so worker
    // threads don't block on syscalls. Tier-2 tuning from
    // sbproxy-bench/docs/TUNING.md. Two pools is the Pingora-recommended
    // starting point for 8+ core machines.
    // WOR-646: grace inputs are passed in explicitly by the binary
    // rather than read back from process env. The string-taking helper
    // is reused as-is (it also tolerates malformed input from any other
    // caller); a resolved u64 always reparses cleanly.
    let grace_ms = grace.shutdown_grace_ms.map(|m| m.to_string());
    let grace_secs = grace.grace_time_secs.map(|s| s.to_string());
    let grace_seconds = resolve_shutdown_grace_seconds(grace_ms.as_deref(), grace_secs.as_deref());
    // Worker thread count. `SB_WORKER_THREADS` (when a positive
    // integer) overrides the auto-detected value; otherwise we use
    // `std::thread::available_parallelism()`, which honours cgroup
    // CPU quotas on Linux. Useful for benchmarks pinning to a known
    // worker count, or for containers where the operator wants to
    // cap the pool below the cgroup quota.
    let auto_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let threads = std::env::var("SB_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(auto_threads);
    let conf = PingoraServerConf {
        threads,
        upstream_keepalive_pool_size: 256,
        upstream_connect_offload_threadpools: Some(2),
        grace_period_seconds: Some(grace_seconds),
        graceful_shutdown_timeout_seconds: Some(grace_seconds),
        ..PingoraServerConf::default()
    };
    tracing::info!(
        threads = %conf.threads,
        upstream_pool = %conf.upstream_keepalive_pool_size,
        connect_offload = ?conf.upstream_connect_offload_threadpools,
        "pingora server config"
    );
    let mut server = Server::new_with_opt_and_conf(None, conf);

    // Create the HTTP proxy service.
    let mut proxy_service = http_proxy_service(&server.configuration, SbProxy);
    proxy_service.add_tcp(&format!("0.0.0.0:{port}"));

    // --- HTTP/2 cleartext (h2c) ---
    //
    // When the operator opts in via `proxy.http2_cleartext: true`,
    // enable Pingora's `HttpServerOptions::h2c` flag so the plain TCP
    // listener peeks for the HTTP/2 connection preface and upgrades
    // matching connections to h2 transparently. Plaintext gRPC
    // clients (and any tonic Channel that has not negotiated TLS+ALPN)
    // depend on this; without it the proxy parses the h2 preface as
    // an HTTP/1.1 request line and tears the connection down with
    // `FRAME_SIZE_ERROR`. TLS+ALPN h2 on `https_bind_port` is a
    // separate path and does not need this flag.
    if server_config.http2_cleartext {
        if let Some(app) = proxy_service.app_logic_mut() {
            // `HttpServerOptions` is `#[non_exhaustive]`, so build via
            // `Default::default()` and then flip the `h2c` flag.
            let mut opts = HttpServerOptions::default();
            opts.h2c = true;
            app.server_options = Some(opts);
            tracing::info!(port = %port, "h2c enabled on plain HTTP listener");
        }
    }

    tracing::info!(port = %port, "starting sbproxy on 0.0.0.0:{}", port);

    // Add HTTPS listener if TLS configured.
    if let Some(ref tls) = tls_state {
        if let Some(https_port) = server_config.https_bind_port {
            if let (Some(cert_path), Some(key_path)) =
                (&server_config.tls_cert_file, &server_config.tls_key_file)
            {
                // Manual cert files provided.
                if let Some(mtls_cfg) = server_config.mtls.as_ref() {
                    // mTLS path: build TlsSettings, configure the
                    // rustls ClientCertVerifier wrapper that captures
                    // CN+SAN into the process-wide cert cache, then
                    // delegate chain validation to WebPkiClientVerifier.
                    let cache = crate::identity::mtls_cert_cache();
                    match build_mtls_tls_settings(cert_path, key_path, mtls_cfg, cache) {
                        Ok(settings) => {
                            proxy_service.add_tls_with_settings(
                                &format!("0.0.0.0:{https_port}"),
                                None,
                                settings,
                            );
                            tracing::info!(
                                port = %https_port,
                                require = %mtls_cfg.require,
                                "HTTPS listener added (manual certs + mTLS)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "mTLS setup failed; falling back to non-mTLS HTTPS"
                            );
                            proxy_service
                                .add_tls(&format!("0.0.0.0:{https_port}"), cert_path, key_path)
                                .map_err(|e| {
                                    anyhow::anyhow!("failed to add TLS listener: {}", e)
                                })?;
                        }
                    }
                } else {
                    proxy_service
                        .add_tls(&format!("0.0.0.0:{https_port}"), cert_path, key_path)
                        .map_err(|e| anyhow::anyhow!("failed to add TLS listener: {}", e))?;
                    tracing::info!(port = %https_port, "HTTPS listener added (manual certs)");
                }
            } else if server_config.acme.as_ref().is_some_and(|a| a.enabled) {
                // ACME-only mode: generate a self-signed bootstrap cert so the
                // HTTPS listener can start immediately. ACME will replace it with
                // a real cert once issuance completes.
                match tls.generate_self_signed_bootstrap_cert() {
                    Ok((cert_path, key_path)) => {
                        // Wire mTLS through the ACME path too. Without
                        // this branch, an operator who configured mTLS
                        // alongside ACME would silently get plain TLS
                        // until they noticed clients reaching the
                        // upstream without the expected cert headers.
                        if let Some(mtls_cfg) = server_config.mtls.as_ref() {
                            let cache = crate::identity::mtls_cert_cache();
                            match build_mtls_tls_settings(&cert_path, &key_path, mtls_cfg, cache) {
                                Ok(settings) => {
                                    proxy_service.add_tls_with_settings(
                                        &format!("0.0.0.0:{https_port}"),
                                        None,
                                        settings,
                                    );
                                    tracing::info!(
                                        port = %https_port,
                                        require = %mtls_cfg.require,
                                        "HTTPS listener added (ACME bootstrap + mTLS; ACME will replace cert)"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "mTLS setup failed on ACME path; falling back to non-mTLS HTTPS"
                                    );
                                    proxy_service
                                        .add_tls(
                                            &format!("0.0.0.0:{https_port}"),
                                            &cert_path,
                                            &key_path,
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!("failed to add TLS listener: {}", e)
                                        })?;
                                }
                            }
                        } else {
                            proxy_service
                                .add_tls(&format!("0.0.0.0:{https_port}"), &cert_path, &key_path)
                                .map_err(|e| {
                                    anyhow::anyhow!("failed to add TLS listener: {}", e)
                                })?;
                            tracing::info!(
                                port = %https_port,
                                "HTTPS listener added (self-signed bootstrap, ACME will replace)"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to generate bootstrap cert, HTTPS listener not started"
                        );
                    }
                }
            }
        }
    }

    server.add_service(proxy_service);

    // Spawn the embedded admin HTTP server on `proxy.admin.port`
    // when `admin.enabled: true`. The admin server lives outside
    // Pingora's service tree because its routing semantics
    // (authoritative, basic-auth gated, no upstream forwarding)
    // do not fit Pingora's reverse-proxy shape. Pingora installs
    // its own tokio runtime; we hand the admin task to that
    // runtime when it starts via `tokio::spawn` below the run-loop
    // setup.
    if server_config.admin.as_ref().is_some_and(|a| a.enabled) {
        let admin_cfg = crate::admin::AdminConfig {
            enabled: true,
            port: server_config.admin.as_ref().map(|a| a.port).unwrap_or(9090),
            username: server_config
                .admin
                .as_ref()
                .map(|a| a.username.clone())
                .unwrap_or_else(|| "admin".to_string()),
            password: server_config
                .admin
                .as_ref()
                .map(|a| a.password.clone())
                .unwrap_or_else(|| "changeme".to_string()),
            max_log_entries: server_config
                .admin
                .as_ref()
                .map(|a| a.max_log_entries)
                .unwrap_or(1000),
        };
        // Pass the same on-disk config path the file watcher uses
        // so `POST /admin/reload` re-reads the same file. The two
        // reload paths share the in-process single-flight guard on
        // the AdminState so a manual reload during a watcher reload
        // serialises cleanly.
        // WOR-800 PR5: open the prompt persistence handle when the
        // operator configured a path. Hydrating reads the existing
        // file into the in-memory overlay; subsequent admin mutators
        // write through. A failure to open is logged but does NOT
        // abort startup: an unreadable persistence file should not
        // brick the proxy. PR3-style ephemeral mutations keep
        // working on the failed path.
        let prompt_persistence = server_config
            .admin
            .as_ref()
            .and_then(|a| a.prompt_persistence_path.as_ref())
            .and_then(|path| match crate::admin::PromptPersistence::open(path) {
                Ok(p) => {
                    tracing::info!(path = %path.display(), "opened prompt persistence");
                    Some(std::sync::Arc::new(p))
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to open prompt persistence; mutations will be ephemeral"
                    );
                    None
                }
            });
        let mut admin_state_inner = crate::admin::AdminState::new(admin_cfg)
            .with_config_path(config_path)
            .with_loaded_config_content_hash(initial_content_hash.clone());
        if let Some(p) = prompt_persistence {
            admin_state_inner = admin_state_inner.with_prompt_persistence(p);
        }

        // WOR-27: register the synthetic-pipeline probe and spawn its
        // driver loop when the operator opted in. Registration runs
        // sync; the driver loop calls `tokio::spawn` and therefore
        // must be invoked from inside the admin thread's runtime
        // (this `pub fn run` itself has no current tokio runtime).
        let synthetic_driver = match server_config.synthetic_probe.as_ref() {
            Some(synth_cfg) if synth_cfg.enabled => {
                let state = sbproxy_observe::SyntheticProbeState::new();
                let stale_after =
                    std::time::Duration::from_secs(synth_cfg.effective_stale_after_secs());
                let registration = sbproxy_observe::SyntheticProbeRegistration {
                    name: "synthetic_pipeline".to_string(),
                    state: state.clone(),
                    stale_after,
                };
                admin_state_inner
                    .health_registry
                    .register(registration.into_probe());
                Some((synth_cfg.clone(), state))
            }
            _ => None,
        };
        let admin_state = std::sync::Arc::new(admin_state_inner);
        // Pingora's `Server::run_forever` builds its own multi-thread
        // tokio runtime; spawning before run_forever installs the
        // task on that runtime via the global handle once Pingora
        // initialises it. We use a small bootstrap task that grabs
        // the runtime handle as soon as it is available.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("admin runtime");
            rt.block_on(async move {
                if let Some((synth_cfg, state)) = synthetic_driver {
                    crate::synthetic::spawn_loop(synth_cfg, state);
                }
                // The admin server's listener task lives forever;
                // run it inline on this dedicated thread.
                if let Some(handle) = crate::admin::spawn_admin_server(admin_state) {
                    let _ = handle.await;
                }
            });
        });
    }

    // Register ACME challenge store and Alt-Svc header globally.
    if let Some(ref tls) = tls_state {
        reload::set_challenge_store(std::sync::Arc::clone(&tls.challenge_store));
    }
    if server_config.http3.as_ref().is_some_and(|h| h.enabled) {
        if let Some(https_port) = server_config.https_bind_port {
            reload::set_alt_svc(sbproxy_tls::alt_svc::h3_alt_svc_value(https_port));
            tracing::info!(
                "Alt-Svc header will advertise HTTP/3 on port {}",
                https_port
            );
        }
    }

    // Start ACME renewal task if enabled.
    if let Some(ref tls) = tls_state {
        tls.start_acme_renewal_task();
        // Kick off OCSP stapling for the manual fallback cert.
        // No-op when no manual cert is loaded; otherwise the
        // task does an immediate fetch and refreshes every 12h,
        // calling back into the resolver to update the stapled
        // bytes on the cert.
        tls.start_ocsp_refresh_task();
    }

    // Start HTTP/3 listener if enabled.
    if let Some(ref tls) = tls_state {
        if server_config.http3.as_ref().is_some_and(|h| h.enabled) {
            // Wire the real pipeline dispatch into the H3 listener.
            let dispatch_fn: sbproxy_tls::h3_listener::DispatchFn =
                std::sync::Arc::new(|method, uri, headers, body, client_ip| {
                    Box::pin(crate::dispatch::dispatch_h3_request(
                        method, uri, headers, body, client_ip,
                    ))
                });
            match tls.start_h3_listener(&server_config, dispatch_fn) {
                Ok(Some(_handle)) => {
                    tracing::info!("HTTP/3 listener started");
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "failed to start HTTP/3 listener, continuing without it");
                }
            }
        }
    }

    server.bootstrap();

    // WOR-636: subscribe to Pingora's execution-phase broadcast
    // before `run_forever` consumes the server so an explicit
    // structured tracing event lands when SIGINT or SIGTERM is
    // received. Pingora handles the signal itself; this just makes
    // the shutdown visible to operator-facing logs.
    spawn_shutdown_phase_logger(server.watch_execution_phase(), grace_seconds);

    server.run_forever();
}

/// Render the ARDP (`/.well-known/sbproxy-agent`) capability
/// advertisement as a compact JSON string.
///
/// Pure helper so the JSON shape is unit-testable without booting the
/// Pingora pipeline. The advertised endpoint keys (`mcp`, `agent_skills`,
/// `openapi`) are emitted only when the corresponding capability is
/// actually configured on the origin; the `capabilities` array tracks the
/// same set so registry consumers can branch on a string list without
/// re-walking the endpoint map. The publisher block is constant and
/// names the project surface, not the operator.
///
/// Per draft-pioli-agent-discovery-01 §4. Wire format is JSON; this
/// function builds a `serde_json::Value` and renders it with the
/// canonical compact encoder so the body is stable across releases.
pub(super) fn render_ardp_discovery(
    agent_id: &str,
    scheme: &str,
    host_authority: Option<&str>,
    has_mcp: bool,
    has_agent_skills: bool,
    has_openapi: bool,
) -> String {
    let base = match host_authority {
        Some(auth) if !auth.is_empty() => format!("{scheme}://{auth}"),
        _ => String::new(),
    };

    let mut endpoints = serde_json::Map::new();
    let mut capabilities: Vec<&'static str> = Vec::new();
    if has_mcp {
        let url = if base.is_empty() {
            "/mcp".to_string()
        } else {
            format!("{base}/mcp")
        };
        endpoints.insert("mcp".to_string(), serde_json::Value::String(url));
        capabilities.push("mcp.tools");
    }
    if has_agent_skills {
        let url = if base.is_empty() {
            "/.well-known/agent-skills/index.json".to_string()
        } else {
            format!("{base}/.well-known/agent-skills/index.json")
        };
        endpoints.insert("agent_skills".to_string(), serde_json::Value::String(url));
        capabilities.push("agent_skills.v0_2");
    }
    if has_openapi {
        let url = if base.is_empty() {
            "/.well-known/openapi.json".to_string()
        } else {
            format!("{base}/.well-known/openapi.json")
        };
        endpoints.insert("openapi".to_string(), serde_json::Value::String(url));
        capabilities.push("openapi");
    }

    let value = serde_json::json!({
        "schema_version": "1",
        "agent_id": agent_id,
        "endpoints": endpoints,
        "capabilities": capabilities,
        "publisher": {
            "name": "sbproxy",
            "url": "https://sbproxy.dev"
        }
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Walk the inventory-based plugin registry and emit one
/// `sbproxy_plugin_registered_total{kind, plugin}` counter row per
/// known registration. Called once from `run` so an operator scraping
/// `/metrics` immediately after startup sees the registration set
/// without waiting for a request to flow.
fn report_plugin_registrations() {
    use sbproxy_plugin::{PluginKind, PluginRegistration};
    for reg in inventory::iter::<PluginRegistration>() {
        let kind = match reg.kind {
            PluginKind::Action => "action",
            PluginKind::Auth => "auth",
            PluginKind::Policy => "policy",
            PluginKind::Transform => "transform",
            PluginKind::Enricher => "enricher",
        };
        sbproxy_observe::metrics::record_plugin_registered(kind, reg.name);
    }
    // AuthPluginRegistration is the strongly-typed sibling channel
    // used by auth providers; report them under kind=auth too so
    // `kind=auth` matches what `build_auth_plugin` actually
    // dispatches against.
    for reg in inventory::iter::<sbproxy_plugin::AuthPluginRegistration>() {
        sbproxy_observe::metrics::record_plugin_registered("auth", reg.name);
    }
}

/// Shared process-global mutex any test that touches the global
/// `OP_REDACT_STATE` (directly via `install_op_redact_config` or
/// indirectly via `reload_from_config_path` -> `install_op_redact_state`)
/// must hold for the duration of its assertions. Without this guard
/// two tests in the same binary race on the global slot and one
/// clobbers the other's installed state mid-flight.
#[cfg(test)]
pub(crate) static OP_REDACT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// WOR-1067 PR2: walk `server.tenants` and install each tenant's
/// `observability.cardinality.max_series` cap on the global
/// [`sbproxy_observe::metrics::global_limiter`]. A tenant without an
/// `observability.cardinality:` block stays on the proxy-wide cap
/// (today's behaviour); a tenant that declares the block without a
/// `max_series:` value gets the
/// `TENANT_CARDINALITY_DEFAULT_MAX_SERIES` (10_000) fallback so an
/// operator can opt in to per-tenant tracking without picking a
/// number.
///
/// Called once at boot (from `run`) and on every config reload (from
/// `reload_from_config_path`) so SIGHUP picks up new tenant caps.
fn install_tenant_cardinality_state(server: &sbproxy_config::ProxyServerConfig) {
    use sbproxy_config::TENANT_CARDINALITY_DEFAULT_MAX_SERIES;
    let limiter = sbproxy_observe::metrics::global_limiter();
    for tenant in &server.tenants {
        if let Some(cardinality) = tenant
            .observability
            .as_ref()
            .and_then(|o| o.cardinality.as_ref())
        {
            let max_series = cardinality
                .max_series
                .unwrap_or(TENANT_CARDINALITY_DEFAULT_MAX_SERIES)
                as usize;
            limiter.set_tenant_cap(tenant.id.clone(), max_series);
        }
    }
}

/// Read `proxy.observability.log.redact:` (proxy scope) and walk
/// `compiled.server.tenants` + `compiled.origins` for tenant- and
/// origin-scope `observability.log.redact.pii:` overrides
/// (WOR-1043 PR2 / PR3). Install the composed redaction state into the
/// global op-redact slot. Empty when no scope authored a block so the
/// redactor short-circuits at zero allocation. An invalid regex at the
/// proxy scope is logged at `warn` and dropped; unknown rule names at
/// any scope are warn-logged and skipped; the rest of the block still
/// installs.
fn install_op_redact_state(compiled: &sbproxy_config::CompiledConfig) {
    let server = &compiled.server;

    // Proxy-scope `redact:` block.
    let proxy_redact = server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .and_then(|l| l.redact.as_ref());

    // Compose proxy-scope fields + regex patterns. Tenant- and
    // origin-scope blocks reuse the same `ObservabilityPiiConfig`
    // shape but only the `pii:` leaf is honoured at scopes below
    // proxy; the field-key and regex passes still walk the rendered
    // JSON, which is tenant-agnostic at the emitter.
    let fields: Vec<String> = match proxy_redact {
        Some(c) => c.fields.iter().map(|f| f.to_ascii_lowercase()).collect(),
        None => Vec::new(),
    };

    let mut patterns = Vec::new();
    if let Some(cfg) = proxy_redact {
        patterns.reserve(cfg.patterns.len());
        for p in &cfg.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
    }

    // Resolve the proxy-scope PII rule set first. We need both the
    // `enabled` decision and the composed rule set because tenant-
    // scope blocks compose against the proxy's resolved values, and
    // origin-scope blocks compose against the tenant's (or proxy's
    // when the origin has no tenant block).
    let (proxy_enabled, proxy_rules) = match proxy_redact.and_then(|r| r.pii.as_ref()) {
        Some(block) => compose_pii_rules(false, &std::collections::BTreeSet::new(), block),
        None => (false, std::collections::BTreeSet::new()),
    };
    let proxy_pii = if proxy_enabled {
        build_pii_from_rule_names(&proxy_rules, "proxy")
    } else {
        None
    };

    // Build the tenant map. A tenant without a `pii:` block has no
    // entry, so resolution falls through to proxy scope.
    let mut tenant_pii: std::collections::HashMap<
        String,
        Option<sbproxy_security::pii::PiiRedactor>,
    > = std::collections::HashMap::new();
    let mut tenant_resolved: std::collections::HashMap<
        String,
        (bool, std::collections::BTreeSet<String>),
    > = std::collections::HashMap::new();
    for tenant in &server.tenants {
        let block = match tenant
            .observability
            .as_ref()
            .and_then(|o| o.log.redact.pii.as_ref())
        {
            Some(b) => b,
            None => continue,
        };
        let (enabled, rules) = compose_pii_rules(proxy_enabled, &proxy_rules, block);
        tenant_resolved.insert(tenant.id.clone(), (enabled, rules.clone()));
        let slot = if enabled {
            build_pii_from_rule_names(&rules, &format!("tenant `{}`", tenant.id))
        } else {
            None
        };
        // Note: an `enabled: false` tenant stores `None` here so the
        // resolver treats the entry as an explicit opt-out. A tenant
        // whose composed rule set is empty but `enabled: true` also
        // stores `None` (build_pii_from_rule_names returns `None` on
        // empty input), which matches the proxy-scope behaviour of
        // not running a PII pass when no rules are selected.
        tenant_pii.insert(tenant.id.clone(), slot);
    }

    // Build the origin map. Origins without a `tenant_id` (or with
    // the synthetic `__default__` tenant) compose against the proxy
    // scope; origins with a declared tenant compose against the
    // tenant's resolved state when present, falling back to proxy
    // scope when the tenant has no block of its own.
    let mut origin_pii: std::collections::HashMap<
        String,
        Option<sbproxy_security::pii::PiiRedactor>,
    > = std::collections::HashMap::new();
    for origin in &compiled.origins {
        let block = match origin
            .observability
            .as_ref()
            .and_then(|o| o.log.redact.pii.as_ref())
        {
            Some(b) => b,
            None => continue,
        };
        let tenant_id_str = origin.tenant_id.as_str();
        let (parent_enabled, parent_rules) = match tenant_resolved.get(tenant_id_str) {
            Some((e, r)) => (*e, r.clone()),
            None => (proxy_enabled, proxy_rules.clone()),
        };
        let (enabled, rules) = compose_pii_rules(parent_enabled, &parent_rules, block);
        let slot = if enabled {
            build_pii_from_rule_names(&rules, &format!("origin `{}`", origin.hostname))
        } else {
            None
        };
        // Key the origin map on the hostname so `StructuredLog.route`
        // (today: the origin's hostname) resolves at emit time. When
        // a future request_phase change starts stamping `hostname +
        // path-prefix` on `route`, mirror the same string here.
        origin_pii.insert(origin.hostname.to_string(), slot);
    }

    // WOR-1042: compose per-tenant + per-origin field-key denylists
    // and regex pattern sets. `fields:` is additive only at every
    // scope; `patterns:` is additive with a per-scope `disable:` opt
    // out keyed on the pattern name (built-in denylist + proxy
    // patterns are never disable-able by tenant/origin scope).
    let mut tenant_fields: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut tenant_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>> =
        std::collections::HashMap::new();
    // Keep the parent compiled set keyed by name so child scope
    // `disable:` lookups are O(1). Parent (proxy) names + compiled
    // entries cached for re-use by the origin walk.
    let proxy_pattern_names: Vec<String> = proxy_redact
        .map(|c| c.patterns.iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    let proxy_compiled_by_name: std::collections::HashMap<String, (regex::Regex, String)> =
        proxy_pattern_names
            .iter()
            .cloned()
            .zip(patterns.iter().cloned())
            .collect();

    for tenant in &server.tenants {
        let redact = match tenant.observability.as_ref().map(|o| &o.log.redact) {
            Some(r) => r,
            None => continue,
        };
        // Fields: additive on top of the proxy set.
        let mut merged_fields = fields.clone();
        for f in &redact.fields {
            let lower = f.to_ascii_lowercase();
            if !merged_fields.contains(&lower) {
                merged_fields.push(lower);
            }
        }
        // Patterns: start from proxy minus this tenant's `disable:`
        // set, then add tenant patterns.
        let disable: std::collections::HashSet<&str> =
            redact.disable.iter().map(|s| s.as_str()).collect();
        let mut merged_patterns: Vec<(regex::Regex, String)> = proxy_pattern_names
            .iter()
            .filter_map(|name| {
                if disable.contains(name.as_str()) {
                    None
                } else {
                    proxy_compiled_by_name.get(name).cloned()
                }
            })
            .collect();
        for p in &redact.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    merged_patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        scope = %format!("tenant `{}`", tenant.id),
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
        tenant_fields.insert(tenant.id.clone(), merged_fields);
        tenant_patterns.insert(tenant.id.clone(), merged_patterns);
    }

    let mut origin_fields: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut origin_patterns_map: std::collections::HashMap<String, Vec<(regex::Regex, String)>> =
        std::collections::HashMap::new();
    for origin in &compiled.origins {
        let redact = match origin.observability.as_ref().map(|o| &o.log.redact) {
            Some(r) => r,
            None => continue,
        };
        let tenant_id_str = origin.tenant_id.as_str();
        // Parent fields: tenant if present, else proxy.
        let parent_fields = tenant_fields
            .get(tenant_id_str)
            .cloned()
            .unwrap_or_else(|| fields.clone());
        let mut merged_fields = parent_fields;
        for f in &redact.fields {
            let lower = f.to_ascii_lowercase();
            if !merged_fields.contains(&lower) {
                merged_fields.push(lower);
            }
        }
        // Parent patterns: tenant if present, else proxy. Build a
        // name-keyed map on the fly so this scope's `disable:` can
        // remove parent entries by name.
        let parent_compiled = tenant_patterns
            .get(tenant_id_str)
            .cloned()
            .unwrap_or_else(|| patterns.clone());
        let disable: std::collections::HashSet<&str> =
            redact.disable.iter().map(|s| s.as_str()).collect();
        // We do not carry pattern names through the compiled list,
        // so origin `disable:` can only remove patterns the operator
        // re-named at the proxy scope. Honour the disable list by
        // name against proxy + tenant-declared pattern names.
        let mut tenant_pattern_names: Vec<String> = proxy_pattern_names.clone();
        if let Some(t) = server.tenants.iter().find(|t| t.id == tenant_id_str) {
            if let Some(o) = t.observability.as_ref() {
                for p in &o.log.redact.patterns {
                    tenant_pattern_names.push(p.name.clone());
                }
            }
        }
        let mut merged_patterns: Vec<(regex::Regex, String)> = parent_compiled
            .into_iter()
            .zip(tenant_pattern_names.iter())
            .filter_map(|(entry, name)| {
                if disable.contains(name.as_str()) {
                    None
                } else {
                    Some(entry)
                }
            })
            .collect();
        for p in &redact.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    merged_patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        scope = %format!("origin `{}`", origin.hostname),
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
        origin_fields.insert(origin.hostname.to_string(), merged_fields);
        origin_patterns_map.insert(origin.hostname.to_string(), merged_patterns);
    }

    sbproxy_observe::logging::install_op_redact_config(sbproxy_observe::logging::OpRedactState {
        fields,
        patterns,
        tenant_fields,
        tenant_patterns,
        origin_fields,
        origin_patterns: origin_patterns_map,
        proxy_pii,
        tenant_pii,
        origin_pii,
    });
}

/// Compose a child scope's `(enabled, rules)` from the parent's
/// resolved values plus the child's add / disable lists. The child's
/// `enabled` overrides the parent when set; an unset `enabled` inherits
/// the parent's flag. The rules set is the parent's rules plus the
/// child's `rules:` minus the child's `disable:`.
fn compose_pii_rules(
    parent_enabled: bool,
    parent_rules: &std::collections::BTreeSet<String>,
    block: &sbproxy_config::ObservabilityPiiConfig,
) -> (bool, std::collections::BTreeSet<String>) {
    let enabled = block.enabled.unwrap_or(parent_enabled);
    let mut rules = parent_rules.clone();
    // Special case for the proxy scope: an empty `rules:` at the
    // proxy scope (no parent to inherit from) means "all defaults".
    // We model this by treating an empty parent + empty rules + no
    // disable as a sentinel and substituting the full default name
    // list. Tenant and origin scopes have a non-empty parent set
    // whenever the proxy scope enabled PII, so this branch only
    // applies at the proxy scope.
    if parent_rules.is_empty() && block.rules.is_empty() {
        for r in sbproxy_security::pii::default_rules() {
            rules.insert(r.name);
        }
    } else {
        for r in &block.rules {
            rules.insert(r.clone());
        }
    }
    for d in &block.disable {
        rules.remove(d);
    }
    (enabled, rules)
}

/// Build a `PiiRedactor` from a set of built-in rule names. Returns
/// `None` when the set is empty or every requested rule is unknown.
/// Unknown rule names are warn-logged with the `scope_label` so an
/// operator typo at any scope surfaces in the logs.
fn build_pii_from_rule_names(
    rule_names: &std::collections::BTreeSet<String>,
    scope_label: &str,
) -> Option<sbproxy_security::pii::PiiRedactor> {
    if rule_names.is_empty() {
        return None;
    }
    let defaults = sbproxy_security::pii::default_rules();
    let known: std::collections::HashSet<&str> = defaults.iter().map(|r| r.name.as_str()).collect();
    for want in rule_names {
        if !known.contains(want.as_str()) {
            tracing::warn!(
                scope = %scope_label,
                rule = %want,
                "unknown PII rule name; skipping (typo or removed default?)"
            );
        }
    }
    let selected: Vec<_> = defaults
        .into_iter()
        .filter(|r| rule_names.contains(&r.name))
        .collect();
    if selected.is_empty() {
        return None;
    }
    let pii_config = sbproxy_security::pii::PiiConfig {
        enabled: true,
        defaults: false,
        rules: selected,
        redact_request: false,
        redact_response: false,
    };
    match sbproxy_security::pii::PiiRedactor::from_config(&pii_config) {
        Ok(redactor) => Some(redactor),
        Err(e) => {
            tracing::warn!(
                scope = %scope_label,
                error = %e,
                "failed to build operator PII redactor; PII pass disabled at this scope"
            );
            None
        }
    }
}

/// WOR-1045 PR1: validate the declared `proxy.observability.log.sinks:`
/// block. PR1 does NOT wire dispatch; this is a soundness check so
/// operators see issues before PR2 lights up the fan-out.
///
/// Reports:
///
/// * Duplicate `name` within the scope (rejected by PR2; warned here).
/// * Unknown `target` (`access_log` / `error_log` / `audit_log` /
///   `trace_exporter` / `external_log`). PR2 will reject these.
/// * Unknown `profile` (`internal` / `external`). PR2 will reject these.
///
/// Per-tenant and per-origin sink scopes land alongside the
/// WOR-1051 credentials epic; this helper covers only the proxy scope
/// today.
fn validate_sinks_config(server: &sbproxy_config::ProxyServerConfig) {
    let sinks = match server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .map(|l| &l.sinks)
    {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };

    const KNOWN_TARGETS: &[&str] = &[
        "access_log",
        "error_log",
        "audit_log",
        "trace_exporter",
        "external_log",
    ];
    const KNOWN_PROFILES: &[&str] = &["internal", "external"];

    let mut seen: std::collections::HashSet<&str> =
        std::collections::HashSet::with_capacity(sinks.len());
    for sink in sinks {
        if !seen.insert(sink.name.as_str()) {
            tracing::warn!(
                sink = %sink.name,
                "duplicate sink name at proxy scope; PR2 will reject (PR1 only warns)"
            );
        }
        if !KNOWN_TARGETS.contains(&sink.target.as_str()) {
            tracing::warn!(
                sink = %sink.name,
                target = %sink.target,
                "unknown sink target; PR2 will reject (PR1 only warns)"
            );
        }
        if let Some(profile) = sink.profile.as_deref() {
            if !KNOWN_PROFILES.contains(&profile) {
                tracing::warn!(
                    sink = %sink.name,
                    profile = %profile,
                    "unknown sink profile; PR2 will reject (PR1 only warns)"
                );
            }
        }
    }

    tracing::info!(
        count = sinks.len(),
        "WOR-1045 PR1: parsed sinks block; dispatch wiring lands in PR2"
    );
}

/// WOR-1045 PR2: build a [`sbproxy_observe::SinkDispatcher`] from the
/// compiled config and install it process-wide. The dispatcher walks
/// three scope lists:
///
/// * `proxy.observability.log.sinks:` (proxy scope, receives every record).
/// * `tenants[].observability.log.sinks:` (tenant scope, filtered by
///   `record.tenant_id`).
/// * `origins[].observability.log.sinks:` (origin scope, filtered by
///   `record.route`).
///
/// When zero sinks are declared the dispatcher installs an empty
/// snapshot so `current_sink_dispatcher()` returns `None`; the
/// `emit()` path then falls back to the legacy single `tracing::*!`
/// subscriber and stdout behaviour is preserved.
fn install_sink_dispatcher_from_config(compiled: &sbproxy_config::CompiledConfig) {
    use sbproxy_observe::sink_dispatcher::{
        install_sink_dispatcher, CompiledSink, SinkDispatcher, SinkScope,
    };

    // Resolve the top-level telemetry block once so OTLP sinks
    // inherit `transport`, `service_name`, `resource_attrs` without
    // re-deriving the defaults per sink.
    let telemetry_defaults = compiled
        .server
        .observability
        .as_ref()
        .and_then(|o| o.telemetry.as_ref());

    let mut compiled_sinks: Vec<CompiledSink> = Vec::new();

    // Proxy scope.
    let proxy_sinks: &[sbproxy_config::ObservabilitySinkConfig] = compiled
        .server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .map(|l| l.sinks.as_slice())
        .unwrap_or(&[]);
    for raw in proxy_sinks {
        if let Some(sink) = compile_one_sink(raw, SinkScope::Proxy, false, telemetry_defaults) {
            compiled_sinks.push(sink);
        }
    }

    // Tenant scope.
    for tenant in &compiled.server.tenants {
        let Some(obs) = tenant.observability.as_ref() else {
            continue;
        };
        for raw in &obs.log.sinks {
            if let Some(sink) = compile_one_sink(
                raw,
                SinkScope::Tenant(tenant.id.clone()),
                true,
                telemetry_defaults,
            ) {
                compiled_sinks.push(sink);
            }
        }
    }

    // Origin scope.
    for origin in &compiled.origins {
        let Some(obs) = origin.observability.as_ref() else {
            continue;
        };
        for raw in &obs.log.sinks {
            if let Some(sink) = compile_one_sink(
                raw,
                SinkScope::Origin(origin.hostname.to_string()),
                true,
                telemetry_defaults,
            ) {
                compiled_sinks.push(sink);
            }
        }
    }

    let count = compiled_sinks.len();
    // WOR-1099: a failed install (poisoned dispatcher lock) leaves the
    // proxy serving traffic with no log/event export. Surface it
    // instead of discarding the result bool.
    if !install_sink_dispatcher(SinkDispatcher::new(compiled_sinks)) {
        sbproxy_observe::metrics::record_sink_install_failure();
        tracing::error!(
            count,
            "failed to install sink dispatcher (dispatcher lock poisoned); telemetry export may be unavailable"
        );
    }
    if count > 0 {
        tracing::info!(
            count,
            "WOR-1045 PR2: installed sink dispatcher with declared sinks"
        );
    } else {
        tracing::debug!(
            "WOR-1045 PR2: no sinks declared; emit() falls back to the legacy tracing subscriber"
        );
    }
}

/// Compile a single declared sink. Returns `None` when the YAML
/// declared an unknown target or output type the dispatcher cannot
/// honour; we keep this lenient (warn + skip) rather than abort the
/// whole reload because a single misconfigured sink should not take
/// down the proxy.
fn compile_one_sink(
    raw: &sbproxy_config::ObservabilitySinkConfig,
    scope: sbproxy_observe::sink_dispatcher::SinkScope,
    default_external_profile: bool,
    telemetry: Option<&sbproxy_config::ObservabilityTelemetryConfig>,
) -> Option<sbproxy_observe::sink_dispatcher::CompiledSink> {
    use sbproxy_observe::sink_dispatcher::{
        CompiledSink, FileSink, Profile, SinkFormat, SinkOutput, StderrSink, StdoutSink,
    };
    use sbproxy_observe::Sink;

    let target = match raw.target.as_str() {
        "access_log" => Sink::AccessLog,
        "error_log" => Sink::ErrorLog,
        "audit_log" => Sink::AuditLog,
        "trace_exporter" => Sink::TraceExporter,
        "external_log" => Sink::External,
        other => {
            tracing::warn!(
                sink = %raw.name,
                target = %other,
                "unknown sink target; skipping sink"
            );
            return None;
        }
    };

    let format = match raw.format.as_deref().unwrap_or("compact") {
        "pretty" => SinkFormat::Pretty,
        "json" => SinkFormat::Json,
        _ => SinkFormat::Compact,
    };

    let profile = match raw.profile.as_deref() {
        Some("external") => Profile::External,
        Some("internal") => Profile::Internal,
        Some(other) => {
            tracing::warn!(
                sink = %raw.name,
                profile = %other,
                "unknown sink profile; defaulting to scope's default"
            );
            if default_external_profile {
                Profile::External
            } else {
                Profile::Internal
            }
        }
        None => {
            if default_external_profile {
                Profile::External
            } else {
                Profile::Internal
            }
        }
    };

    let output: Box<dyn SinkOutput> = match &raw.output {
        sbproxy_config::ObservabilitySinkOutput::Stdout => Box::new(StdoutSink),
        sbproxy_config::ObservabilitySinkOutput::Stderr => Box::new(StderrSink),
        sbproxy_config::ObservabilitySinkOutput::File {
            path,
            max_size_mb,
            max_backups,
            compress,
        } => {
            let mut fs = FileSink::new(std::path::PathBuf::from(path));
            if let Some(mb) = *max_size_mb {
                fs.max_size_bytes = mb.saturating_mul(1024 * 1024);
            }
            if let Some(b) = *max_backups {
                fs.max_backups = b as usize;
            }
            if let Some(c) = *compress {
                fs.compress = c;
            }
            Box::new(fs)
        }
        sbproxy_config::ObservabilitySinkOutput::Otlp {
            endpoint,
            transport,
            timeout_secs,
        } => {
            // The OTel BatchLogProcessor spawns a worker via
            // `tokio::spawn`, which requires an ambient runtime. The
            // first-boot install path runs before Pingora installs its
            // runtime, so we skip with a warn there; the SIGHUP and
            // file-watcher reload paths execute inside the running
            // runtime and pick the sink up. Operators who want OTLP
            // logs from the very first request can SIGHUP after boot.
            if tokio::runtime::Handle::try_current().is_err() {
                // WOR-1100: count the skip so operators can see from
                // metrics (not just a boot-time warn) that OTLP logs
                // are not exporting until the first reload.
                sbproxy_observe::metrics::record_telemetry_dropped("otlp_log", "no_runtime");
                tracing::warn!(
                    sink = %raw.name,
                    "OTLP log sink declared but no tokio runtime is active; the sink will activate after the first SIGHUP / hot reload",
                );
                return None;
            }
            let transport_default = telemetry
                .and_then(|t| t.transport.as_deref())
                .unwrap_or("grpc");
            let transport_str = transport.as_deref().unwrap_or(transport_default);
            let transport = match transport_str {
                "http" => sbproxy_observe::telemetry::OtlpTransport::Http,
                _ => sbproxy_observe::telemetry::OtlpTransport::Grpc,
            };
            let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(10).max(1));
            let service_name = telemetry
                .and_then(|t| t.service_name.clone())
                .unwrap_or_else(|| "sbproxy".to_string());
            let resource_attrs = telemetry
                .map(|t| t.resource_attrs.clone())
                .unwrap_or_default();
            let opts = sbproxy_observe::OtlpLogSinkOptions {
                endpoint: endpoint.clone(),
                transport,
                service_name,
                timeout,
                resource_attrs,
            };
            match sbproxy_observe::OtlpLogSink::new(opts) {
                Ok(s) => Box::new(s),
                Err(e) => {
                    tracing::warn!(
                        sink = %raw.name,
                        error = %e,
                        "failed to build OTLP log sink; skipping"
                    );
                    return None;
                }
            }
        }
    };

    Some(CompiledSink {
        name: raw.name.clone(),
        scope,
        target,
        format,
        profile,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WOR-1043 PR2 / PR3: installing the redact state from a compiled
    /// config that carries a proxy-scope PII block plus a tenant-scope
    /// override plus an origin-scope extension yields a tri-level
    /// `OpRedactState` the resolver can pick from. Verifies through
    /// `apply_redaction_for` because the state is process-global and
    /// the `OpRedactState` fields are exposed for inspection.
    #[test]
    fn install_op_redact_state_builds_tenant_and_origin_pii() {
        // Build a CompiledConfig with proxy + 1 tenant + 1 origin and
        // run the install. We assert against the resolver behaviour
        // because that is the user-visible contract; spying on the
        // private map would couple to representation details.
        use sbproxy_config::{
            CompiledConfig, CompiledOrigin, ObservabilityConfig, ObservabilityLogConfig,
            ObservabilityPiiConfig, ObservabilityRedactConfig, OriginObservabilityConfig,
            OriginObservabilityLogConfig, OriginObservabilityRedactConfig, ProxyServerConfig,
            ProxyTenantConfig, TenantObservabilityConfig, TenantObservabilityLogConfig,
            TenantObservabilityRedactConfig,
        };

        // Serialise the test against every other sbproxy-core test
        // that touches the process-global `OP_REDACT_STATE` (directly
        // or via `reload_from_config_path`). Without this guard,
        // `reload_from_config_path_is_idempotent_under_repeat_invocation`
        // races with us and clobbers the installed state mid-flight.
        let _guard = super::OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut server = ProxyServerConfig {
            http_bind_port: 8080,
            ..Default::default()
        };
        // Build the log block via Default and then spread the redact
        // leaf so we do not have to spell every unrelated knob
        // (level, format, sampling, sinks) by hand.
        let log_cfg = ObservabilityLogConfig {
            redact: Some(ObservabilityRedactConfig {
                fields: Vec::new(),
                patterns: Vec::new(),
                pii: Some(ObservabilityPiiConfig {
                    enabled: Some(true),
                    rules: vec!["email".to_string()],
                    disable: Vec::new(),
                }),
            }),
            ..Default::default()
        };
        server.observability = Some(ObservabilityConfig {
            log: Some(log_cfg),
            telemetry: None,
        });
        server.tenants = vec![ProxyTenantConfig {
            id: "acme".to_string(),
            credentials: Vec::new(),
            observability: Some(TenantObservabilityConfig {
                cardinality: None,
                log: TenantObservabilityLogConfig {
                    sinks: Vec::new(),
                    custom_fields: Vec::new(),
                    redact: TenantObservabilityRedactConfig {
                        fields: Vec::new(),
                        patterns: Vec::new(),
                        disable: Vec::new(),
                        pii: Some(ObservabilityPiiConfig {
                            enabled: Some(true),
                            rules: vec!["us_ssn".to_string()],
                            disable: Vec::new(),
                        }),
                    },
                },
            }),
        }];

        // Mint a minimal CompiledOrigin by hand. We only populate the
        // fields the install path actually reads (`hostname`,
        // `tenant_id`, `observability`); every other field uses Default
        // where Default is implemented, or an empty value otherwise.
        let origin = CompiledOrigin {
            hostname: compact_str::CompactString::new("api.acme.example.com"),
            origin_id: compact_str::CompactString::new("api-acme"),
            workspace_id: compact_str::CompactString::default(),
            tenant_id: compact_str::CompactString::new("acme"),
            action_config: serde_json::Value::Null,
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::SmallVec::new(),
            request_modifiers: smallvec::SmallVec::new(),
            response_modifiers: smallvec::SmallVec::new(),
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            message_signatures: None,
            olp: None,
            web_bot_auth_publish: None,
            idempotency: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: std::collections::HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits: None,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
            observability: Some(OriginObservabilityConfig {
                log: OriginObservabilityLogConfig {
                    sinks: Vec::new(),
                    custom_fields: Vec::new(),
                    redact: OriginObservabilityRedactConfig {
                        fields: Vec::new(),
                        patterns: Vec::new(),
                        disable: Vec::new(),
                        pii: Some(ObservabilityPiiConfig {
                            enabled: Some(true),
                            rules: vec!["credit_card".to_string()],
                            disable: Vec::new(),
                        }),
                    },
                },
            }),
        };

        let compiled = CompiledConfig {
            origins: vec![origin],
            host_map: std::collections::HashMap::new(),
            server,
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        };

        install_op_redact_state(&compiled);

        // Proxy scope: email rule fires; ssn / card do not.
        let json_email = r#"{"freeform":"ping alice@example.com please"}"#;
        let json_ssn = r#"{"freeform":"the ssn is 123-45-6789 today"}"#;
        let json_card = r#"{"freeform":"paid 4111 1111 1111 1111 yesterday"}"#;

        let proxy_email = sbproxy_observe::logging::apply_redaction_for(
            json_email,
            sbproxy_observe::logging::Sink::AccessLog,
            None,
            None,
        );
        assert!(
            proxy_email.contains("[REDACTED:EMAIL]"),
            "proxy scope should redact email: {proxy_email}"
        );

        // Tenant scope: composes email + us_ssn (tenant adds ssn).
        let tenant_ssn = sbproxy_observe::logging::apply_redaction_for(
            json_ssn,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            None,
        );
        assert!(
            tenant_ssn.contains("[REDACTED:SSN]") || tenant_ssn.contains("[REDACTED:US_SSN]"),
            "tenant scope should redact ssn (composed from proxy + tenant): {tenant_ssn}"
        );

        // Origin scope: composes email + us_ssn (from tenant) + credit_card.
        let origin_card = sbproxy_observe::logging::apply_redaction_for(
            json_card,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            Some("api.acme.example.com"),
        );
        assert!(
            origin_card.contains("[REDACTED:CARD]"),
            "origin scope should redact credit card (composed from tenant + origin): {origin_card}"
        );
        // Origin still inherits the email rule from proxy via the
        // tenant composition.
        let origin_email = sbproxy_observe::logging::apply_redaction_for(
            json_email,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            Some("api.acme.example.com"),
        );
        assert!(
            origin_email.contains("[REDACTED:EMAIL]"),
            "origin scope should still redact email via inherited rule set: {origin_email}"
        );

        // Reset the global slot so a sibling test does not see the
        // installed state.
        sbproxy_observe::logging::install_op_redact_config(
            sbproxy_observe::logging::OpRedactState::empty(),
        );
    }
}
