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
/// - The Wave 5 day-6 SIGHUP signal handler (operator-driven reload
///   via `kill -HUP $(pgrep sbproxy)`).
///
/// Reads the file, runs `compile_config` (which now also drives the
/// Wave 5 day-6 features.* migration in Item 2), constructs a fresh
/// [`CompiledPipeline`], invokes the enterprise reload hook
/// (best-effort), and atomically swaps the live pipeline. Returns
/// `Ok(())` on success; logs and returns `Err` on any step's failure
/// so the caller can decide whether to retry.
///
/// Idempotent: invoking back-to-back yields the same effect as one
/// invocation. Safe to call from any thread; the global pipeline
/// `ArcSwap` handles the publish.
pub fn reload_from_config_path(config_path: &str) -> anyhow::Result<()> {
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
/// from `config_path` (Wave 5 day-6 Item 4).
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
