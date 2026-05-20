//! sbproxy: AI Governance Gateway binary.
//!
//! Thin entrypoint that selects the rustls crypto provider, installs the
//! mimalloc allocator, parses CLI args, and hands the config path to
//! [`sbproxy_core::run`]. All real work happens in the workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// WOR-227 scaffold. Binary-side anchor for the admin UI + chat
// playground stub. The actual route handlers live in
// `sbproxy_core::admin_ui` and `sbproxy_core::admin_playground`;
// the modules here re-export so the file paths called out in the
// WOR-227 plan resolve and so future binary-only wiring has a
// home.
mod admin;

use std::env;

// mimalloc is Microsoft's high-performance allocator. Typically 5-10% faster
// than glibc malloc on server workloads; negligible on allocation-light
// paths. See sbproxy-bench/docs/RUST_OPTIMIZATIONS.md A2.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // rustls 0.23 requires the process to select a CryptoProvider before any
    // TLS machinery initialises. We install `ring` because `ring` is already
    // a workspace dependency (used by sbproxy-vault, sbproxy-tls, and
    // sbproxy-modules) so no new crate graph risk. Without this, every proxy
    // that touches TLS panics at startup.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args: Vec<String> = env::args().collect();

    // Resolve the effective log filter before tracing init so --log-level
    // and SB_LOG_LEVEL win over the default `info` and over RUST_LOG. A
    // separate request-log level appends an access_log target directive.
    // The priority is documented in docs/manual.md §13:
    //   1. `--log-level <level>` CLI flag
    //   2. `SB_LOG_LEVEL` env var
    //   3. `RUST_LOG` env var (rustc-style filter syntax)
    //   4. `info`
    let log_filter = resolve_log_filter(&args);
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_filter))
        .compact()
        .init();

    // Resolve --grace-time / SB_GRACE_TIME and stash it as an env var the
    // core picks up when constructing the Pingora server config. We pass
    // this through the environment rather than threading a new function
    // arg so existing callers of `sbproxy_core::run` keep working.
    if let Some(grace) = resolve_grace_time(&args) {
        env::set_var("SB_GRACE_TIME", grace.to_string());
    }

    // WOR-636: resolve `--shutdown-grace-ms` /
    // `SBPROXY_SHUTDOWN_GRACE_MS` and stash it in the environment so
    // `sbproxy_core::run` can pick it up. The binary overlays a 30s
    // default so orchestrators (kubelet, systemd, docker) get a sane
    // drain window without setting any env var; the in-process
    // default inside `sbproxy_core` stays at zero so the Go e2e
    // runner can rebind the listener between test cases.
    let resolved_ms = resolve_shutdown_grace_ms(&args).or_else(|| {
        // If the legacy `--grace-time` / `SB_GRACE_TIME` is set,
        // do not overlay the 30s default: respect what the
        // operator asked for.
        if resolve_grace_time(&args).is_some() {
            None
        } else {
            Some(DEFAULT_SHUTDOWN_GRACE_MS)
        }
    });
    if let Some(ms) = resolved_ms {
        env::set_var("SBPROXY_SHUTDOWN_GRACE_MS", ms.to_string());
    }

    // WOR-114: lock off the per-request feature-flag surface for
    // production hardening. CLI flag wins; otherwise honour
    // `SB_DISABLE_SB_FLAGS=1`.
    if resolve_disable_sb_flags(&args) {
        sbproxy_core::sb_flags::set_disabled(true);
    }

    // --- --version / -V short-circuit ---
    //
    // Output shape: `sbproxy <semver> (rev <sha>, built <yyyy-mm-dd>)`.
    // CARGO_PKG_VERSION comes from the workspace `version`. The git SHA
    // and build date are embedded by build.rs at compile time.
    //
    // The output shape is load-bearing: the marketing site (Hero.vue)
    // advertises it, and Homebrew's `test do` block asserts on it. If
    // you change the format, fix Hero.vue and the homebrew formula in
    // lockstep.
    if matches!(
        args.get(1).map(String::as_str),
        Some("--version") | Some("-V") | Some("version")
    ) {
        println!(
            "sbproxy {} (rev {}, built {})",
            env!("CARGO_PKG_VERSION"),
            env!("SBPROXY_GIT_SHA"),
            env!("SBPROXY_BUILD_DATE"),
        );
        return;
    }

    // --- --help / -h / help short-circuit ---
    //
    // Print usage and exit 0 (vs the no-args case, which exits 1).
    if matches!(
        args.get(1).map(String::as_str),
        Some("--help") | Some("-h") | Some("help")
    ) {
        println!("{}", general_usage_str());
        return;
    }

    // --- `sbproxy validate <path>` subcommand (alias: `--check`) ---
    //
    // Parse and compile the config without starting the proxy. Useful in
    // CI to fail fast on a bad sb.yml before deploying.
    //
    // The `--check` form is documented in SUPPLY-CHAIN.md as a CI-friendly
    // verification step (`./sbproxy --config /path --check`); it dispatches
    // to the same handler as `validate <path>`.
    if matches!(args.get(1).map(String::as_str), Some("validate"))
        || args.iter().any(|a| a == "--check")
    {
        // For the `--check` form, strip --check from the argv so the
        // existing parser sees only `--config <path>` (or `-f <path>`,
        // or a positional path).
        let filtered: Vec<String> = args
            .iter()
            .skip(1)
            .filter(|a| a.as_str() != "--check" && a.as_str() != "validate")
            .cloned()
            .collect();
        match handle_validate_subcommand(&filtered) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("validate: {e:#}");
                std::process::exit(2);
            }
        }
    }

    // --- Wave 4 / G4.5..G4.8 wire: `sbproxy projections render` ---
    //
    // Per A4.1 § "Operator preview via CLI": loads the YAML config,
    // runs `compile_config`, runs `render_projections`, writes the
    // named document for the named hostname (default the first
    // origin) to stdout. No proxy starts; this is a pure render.
    if matches!(args.get(1).map(String::as_str), Some("projections")) {
        match handle_projections_subcommand(&args[2..]) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(2);
            }
        }
    }

    // --- WOR-180 (steps 1+2): `sbproxy plan` and `sbproxy apply` ---
    //
    // `plan` runs `compile_config` on the proposed YAML (and optionally
    // a `--against` baseline YAML) for validation, parses both into
    // typed `ConfigFile` values, and calls `sbproxy_config::plan` to
    // emit a structured diff. Exit codes follow the ADR
    // (`docs/adr-config-plan-apply.md`): 0 no-op, 2 changes present.
    //
    // `apply` runs `compile_config` for validation and then calls into
    // `sbproxy_core::reload_from_config_path`, the same primitive the
    // SIGHUP handler and file watcher use. The `-p plan-file` form,
    // staleness check, and admin-socket `--running` baseline are
    // out-of-scope follow-ups (steps 3 through 5 of WOR-180).
    if matches!(args.get(1).map(String::as_str), Some("plan")) {
        match handle_plan_subcommand(&args[2..]) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("plan: {e:#}");
                std::process::exit(1);
            }
        }
    }
    if matches!(args.get(1).map(String::as_str), Some("apply")) {
        match handle_apply_subcommand(&args[2..]) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("apply: {e:#}");
                std::process::exit(1);
            }
        }
    }

    // CLI > SB_CONFIG_FILE env. The env fallback lets containerised
    // deployments set SB_CONFIG_FILE in the pod spec without templating
    // a CMD line.
    let config_path = parse_config_path(&args)
        .map(String::from)
        .or_else(|| env::var("SB_CONFIG_FILE").ok());

    match config_path {
        Some(path) => {
            if let Err(e) = sbproxy_core::run(&path) {
                eprintln!("Fatal: {e:#}");
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("Usage: sbproxy --config <path>");
            eprintln!("       sbproxy serve -f <path> [--log-level <level>]");
            eprintln!(
                "       sbproxy projections render --kind {{robots,llms,llms-full,licenses,tdmrep}} \\"
            );
            eprintln!("                                --config <path> [--hostname <h>]");
            eprintln!("       SB_CONFIG_FILE=<path> sbproxy");
            std::process::exit(1);
        }
    }
}

/// Resolve the effective log filter. CLI `--log-level <level>` wins;
/// otherwise `SB_LOG_LEVEL`, then `RUST_LOG`, then `info`. CLI
/// `--request-log-level <level>` / `SB_REQUEST_LOG_LEVEL` append an
/// `access_log=<level>` target directive.
///
/// Accepted values are anything `tracing_subscriber::EnvFilter` parses:
/// a bare level (`info`, `debug`, `trace`), a per-target filter
/// (`sbproxy=debug,h2=warn`), or any combination thereof.
fn resolve_log_filter(args: &[String]) -> String {
    let base = if let Some(v) = take_flag_value(args, "--log-level") {
        v
    } else if let Ok(v) = env::var("SB_LOG_LEVEL") {
        if !v.is_empty() {
            v
        } else if let Ok(v) = env::var("RUST_LOG") {
            if !v.is_empty() {
                v
            } else {
                "info".to_string()
            }
        } else {
            "info".to_string()
        }
    } else if let Ok(v) = env::var("RUST_LOG") {
        if !v.is_empty() {
            v
        } else {
            "info".to_string()
        }
    } else {
        "info".to_string()
    };

    if let Some(request_level) = resolve_request_log_level(args) {
        format!("{base},access_log={request_level}")
    } else {
        base
    }
}

fn resolve_request_log_level(args: &[String]) -> Option<String> {
    if let Some(v) = take_flag_value(args, "--request-log-level") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    match env::var("SB_REQUEST_LOG_LEVEL").ok() {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Default graceful-shutdown drain budget when no env var or CLI
/// flag is set. WOR-636. Matches the upstream client-go controller
/// default and the Kubernetes default `terminationGracePeriodSeconds`
/// so a pod eviction in a default-configured cluster drains cleanly.
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 30_000;

/// Resolve `--shutdown-grace-ms <ms>` / `SBPROXY_SHUTDOWN_GRACE_MS`.
/// Returns `None` when neither is set; the caller decides whether to
/// overlay the 30s default. The CLI value wins over the env value
/// when both are supplied.
fn resolve_shutdown_grace_ms(args: &[String]) -> Option<u64> {
    if let Some(v) = take_flag_value(args, "--shutdown-grace-ms") {
        if let Ok(n) = v.parse::<u64>() {
            return Some(n);
        }
        eprintln!("warning: --shutdown-grace-ms '{v}' is not a number; ignoring");
    }
    if let Ok(v) = env::var("SBPROXY_SHUTDOWN_GRACE_MS") {
        if let Ok(n) = v.parse::<u64>() {
            return Some(n);
        }
        eprintln!("warning: SBPROXY_SHUTDOWN_GRACE_MS '{v}' is not a number; ignoring");
    }
    None
}

/// Resolve `--grace-time <secs>` / `SB_GRACE_TIME`. Returns `None` when
/// neither is set, in which case the core uses its built-in default.
fn resolve_grace_time(args: &[String]) -> Option<u64> {
    if let Some(v) = take_flag_value(args, "--grace-time") {
        if let Ok(n) = v.parse::<u64>() {
            return Some(n);
        }
        eprintln!("warning: --grace-time '{v}' is not a number; ignoring");
    }
    if let Ok(v) = env::var("SB_GRACE_TIME") {
        if let Ok(n) = v.parse::<u64>() {
            return Some(n);
        }
        eprintln!("warning: SB_GRACE_TIME '{v}' is not a number; ignoring");
    }
    None
}

/// Resolve `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS`. Returns true
/// when the surface should be locked off. The CLI flag is a bare
/// boolean (presence = true); the env var accepts `1`, `true`,
/// `yes`, `on` (case-insensitive).
fn resolve_disable_sb_flags(args: &[String]) -> bool {
    if args.iter().any(|a| a == "--disable-sb-flags") {
        return true;
    }
    match env::var("SB_DISABLE_SB_FLAGS").ok().as_deref() {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

/// Look up the value for a `--flag <value>` pair in `args`. Returns
/// the first match. Used by [`resolve_log_filter`] and
/// [`resolve_grace_time`].
fn take_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

/// Parse config file path from CLI args.
///
/// Supports:
/// ```text
/// sbproxy --config <path>
/// sbproxy serve -f <path> [--log-level <level>]
/// sbproxy <path>  # positional
/// ```
fn parse_config_path(args: &[String]) -> Option<&str> {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-f" => {
                return args.get(i + 1).map(|s| s.as_str());
            }
            "serve" => {
                i += 1;
                continue;
            }
            "--log-level"
            | "--request-log-level"
            | "--log-format"
            | "--grace-time"
            | "--shutdown-grace-ms" => {
                i += 2; // skip flag + value
                continue;
            }
            "--disable-sb-flags" => {
                i += 1; // bare flag, no value
                continue;
            }
            arg if !arg.starts_with('-') => {
                return Some(arg);
            }
            _ => {
                i += 1;
                continue;
            }
        }
    }
    None
}

// --- `projections` subcommand handling ---

/// Dispatch the `projections render` subcommand.
///
/// `args` is the slice after `projections` (so `args[0]` is typically
/// `render`). Returns an error suitable for `eprintln!`-ing on the
/// CLI; the caller exits with status 2 on error so shell pipelines
/// can distinguish CLI errors from proxy runtime errors (status 1).
fn handle_projections_subcommand(args: &[String]) -> anyhow::Result<()> {
    let subcommand = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(usage_str()))?;
    match subcommand {
        "render" => handle_projections_render(&args[1..]),
        other => Err(anyhow::anyhow!(
            "unknown projections subcommand: {other}\n{}",
            usage_str()
        )),
    }
}

fn usage_str() -> &'static str {
    "usage: sbproxy projections render --kind {robots|llms|llms-full|licenses|tdmrep} \
     --config <path> [--hostname <h>]"
}

/// Top-level usage banner shown by `--help`/`-h`/`help` and by argument
/// errors. Distinct from `usage_str()` which is the projections-specific
/// help text.
fn general_usage_str() -> &'static str {
    "sbproxy: AI Governance Gateway
       One self-hostable runtime for AI traffic, APIs, MCP, and AI crawlers.

USAGE:
    sbproxy --config <path>
    sbproxy serve -f <path> [--log-level <level>] [--request-log-level <level>]
                            [--grace-time <secs>] [--shutdown-grace-ms <ms>]
    sbproxy validate <path>
    sbproxy --config <path> --check
    sbproxy plan -f <yaml> [--against <yaml>] [--format json|text] [--out <plan-file>]
    sbproxy apply -f <yaml>
    sbproxy apply -p <plan-file>
    sbproxy projections render --kind {robots|llms|llms-full|licenses|tdmrep} \\
                               --config <path> [--hostname <h>]
    sbproxy --version
    sbproxy --help

FLAGS:
    --config <path>, -f <path>   Path to sb.yml. Falls back to SB_CONFIG_FILE.
    --log-level <level>          tracing-subscriber filter. Wins over
                                 SB_LOG_LEVEL and RUST_LOG. Default: info.
    --request-log-level <level>  access_log target filter. Wins over
                                 SB_REQUEST_LOG_LEVEL. Default: unset.
    --grace-time <secs>          Graceful-shutdown timeout (seconds,
                                 legacy). Wins over SB_GRACE_TIME.
                                 Superseded by --shutdown-grace-ms.
    --shutdown-grace-ms <ms>     SIGINT/SIGTERM drain budget in
                                 milliseconds. Wins over
                                 SBPROXY_SHUTDOWN_GRACE_MS and over
                                 --grace-time. Default: 30000 (30s).
    --disable-sb-flags           Lock off the per-request feature-flag
                                 surface (`x-sb-flags` header and
                                 `?_sb.<k>` query params). Default: off.
    --check                      Validate config and exit; no listener.

ENV:
    SB_CONFIG_FILE               --config fallback.
    SB_LOG_LEVEL                 --log-level fallback.
    SB_REQUEST_LOG_LEVEL         --request-log-level fallback.
    SB_GRACE_TIME                --grace-time fallback (seconds).
    SBPROXY_SHUTDOWN_GRACE_MS    --shutdown-grace-ms fallback
                                 (milliseconds). Default: 30000.
    SB_DISABLE_SB_FLAGS          --disable-sb-flags fallback (1/true/yes/on).
    RUST_LOG                     tracing filter when --log-level and
                                 SB_LOG_LEVEL are unset.

DOCS:
    https://github.com/soapbucket/sbproxy/blob/main/docs/README.md"
}

/// Validate an `sb.yml` without starting the proxy. Returns Ok on a config
/// that loads and compiles cleanly; Err with a context-rich message
/// otherwise. Wired to the `sbproxy validate <path>` subcommand.
fn handle_validate_subcommand(args: &[String]) -> anyhow::Result<()> {
    let path = parse_validate_path(args).ok_or_else(|| {
        anyhow::anyhow!(
            "missing config path\n\nusage: sbproxy validate <path>\n   or: sbproxy validate --config <path>"
        )
    })?;
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path}': {e}"))?;
    sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path}' did not compile:\n{e:#}"))?;
    println!("ok: {path} is a valid sbproxy config");
    Ok(())
}

/// Pluck the config path out of `validate`'s argv. Mirrors `parse_config_path`
/// but operates on the args AFTER `validate` has already been consumed.
fn parse_validate_path(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-f" => return args.get(i + 1).map(|s| s.as_str()),
            arg if !arg.starts_with('-') => return Some(arg),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug)]
struct RenderArgs {
    kind: String,
    config: String,
    hostname: Option<String>,
}

fn parse_render_args(args: &[String]) -> anyhow::Result<RenderArgs> {
    let mut kind: Option<String> = None;
    let mut config: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" | "-k" => {
                kind = args.get(i + 1).cloned();
                i += 2;
            }
            "--config" | "-c" | "-f" => {
                config = args.get(i + 1).cloned();
                i += 2;
            }
            "--hostname" | "-H" => {
                hostname = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown flag {other} for projections render"
                ));
            }
        }
    }
    let kind = kind.ok_or_else(|| anyhow::anyhow!("missing --kind"))?;
    let config = config.ok_or_else(|| anyhow::anyhow!("missing --config"))?;
    Ok(RenderArgs {
        kind,
        config,
        hostname,
    })
}

fn handle_projections_render(args: &[String]) -> anyhow::Result<()> {
    let render = parse_render_args(args)?;
    let yaml = std::fs::read_to_string(&render.config)
        .map_err(|e| anyhow::anyhow!("failed to read config '{}': {e}", render.config))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;

    // The CLI uses a deterministic config_version of 0 so output is
    // reproducible across invocations, matching A4.1's "byte-for-byte
    // identical" preview contract for a given config.
    let docs = sbproxy_modules::projections::render_projections(&compiled, 0);

    // Pick the hostname: explicit flag wins; otherwise default to the
    // first origin in the compiled config so a single-origin config
    // works without extra arguments.
    let hostname = match render.hostname {
        Some(h) => h,
        None => compiled
            .origins
            .first()
            .map(|o| o.hostname.to_string())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no origins configured in '{}'; cannot pick a default hostname",
                    render.config
                )
            })?,
    };

    let body = lookup_projection(&docs, &render.kind, &hostname).ok_or_else(|| {
        anyhow::anyhow!(
            "no '{}' projection for hostname '{hostname}' (origin missing or has no \
             ai_crawl_control policy)",
            render.kind
        )
    })?;

    use std::io::Write as _;
    std::io::stdout().write_all(body.as_ref())?;
    std::io::stdout().flush()?;
    Ok(())
}

fn lookup_projection<'a>(
    docs: &'a sbproxy_modules::projections::ProjectionDocs,
    kind: &str,
    hostname: &str,
) -> Option<&'a bytes::Bytes> {
    match kind {
        "robots" => docs.robots_txt.get(hostname),
        "llms" => docs.llms_txt.get(hostname),
        "llms-full" => docs.llms_full_txt.get(hostname),
        "licenses" => docs.licenses_xml.get(hostname),
        "tdmrep" => docs.tdmrep_json.get(hostname),
        _ => None,
    }
}

// --- WOR-180 plan / apply handlers (steps 1+2 of `docs/adr-config-plan-apply.md`) ---

/// Output format for `sbproxy plan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanFormat {
    Text,
    Json,
}

/// Parsed argv for `sbproxy plan`.
#[derive(Debug)]
struct PlanArgs {
    config: String,
    against: Option<String>,
    format: PlanFormat,
    /// `--out <plan-file>` (WOR-180 step 5). When set, the JSON
    /// plan-file envelope (including `baseline_revision`) is written
    /// to disk for a later `apply -p` to consume.
    out: Option<String>,
}

/// Parsed argv for `sbproxy apply`. Either `config` (the `-f` flow)
/// or `plan_file` (the `-p` flow, WOR-180 step 5) is set; the parser
/// rejects both / neither.
#[derive(Debug)]
struct ApplyArgs {
    config: Option<String>,
    plan_file: Option<String>,
}

/// Help banner for `sbproxy plan`. Printed when invoked with `--help`
/// or `-h`; also referenced from argv-error messages.
const PLAN_HELP: &str = "sbproxy plan: diff a proposed config against a baseline.

USAGE:
    sbproxy plan -f <yaml> [--against <yaml>] [--format json|text] [--out <plan-file>]

FLAGS:
    -f, --config <yaml>   Proposed config file. Required.
    --against <yaml>      Baseline config file. Default: empty (every
                          origin in the proposed config surfaces as
                          'added'). The --running baseline is deferred.
    --format json|text    Output format. 'text' (default) is a
                          terraform-style diff for human consumption;
                          'json' is the stable plan envelope for
                          tooling.
    --out <plan-file>     Write the plan-file envelope (JSON, includes
                          baseline_revision for staleness detection)
                          to disk. Use with `apply -p <plan-file>`.
                          Atomic via temp-file + rename(2).
    -h, --help            Print this banner.

EXIT CODES:
    0   No changes between baseline and proposed.
    1   CLI / IO error.
    2   Changes present (informational, not an error).
    3   Semantic-validation errors present (orphan ref, missing
        secret, unknown module type). See the report's findings
        section for details.";

/// Help banner for `sbproxy apply`.
const APPLY_HELP: &str = "sbproxy apply: validate and reload an sbproxy config in place.

USAGE:
    sbproxy apply -f <yaml>
    sbproxy apply -p <plan-file>

FLAGS:
    -f, --config <yaml>   Proposed config file. Mutually exclusive
                          with -p.
    -p, --plan <file>     Plan file from a prior `plan --out`. Apply
                          recomputes the plan against the live
                          baseline and refuses (exit 5) if the
                          baseline_revision drifted. Mutually
                          exclusive with -f.
    -h, --help            Print this banner.

NOTES:
    apply runs `compile_config` on the proposed YAML, runs plan-time
    semantic validation, and then calls the same hot-reload primitive
    the SIGHUP handler and file watcher use. Apply refuses (exit 3)
    when any validation error is present. Apply takes an exclusive
    flock(2) on <yaml_path>.applylock for the duration of the run so
    two concurrent operators cannot race the same reload.

EXIT CODES:
    0   Reload applied cleanly.
    1   CLI / IO / reload error.
    3   Semantic-validation errors present; apply refused.
    5   Plan file is stale: the live baseline revision no longer
        matches the plan's baseline_revision. Operator must rerun
        `plan` and re-apply.
    6   Apply lock contention: another apply is in progress.";

fn parse_plan_args(args: &[String]) -> anyhow::Result<PlanArgs> {
    let mut config: Option<String> = None;
    let mut against: Option<String> = None;
    let mut format: PlanFormat = PlanFormat::Text;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{PLAN_HELP}");
                std::process::exit(0);
            }
            "--config" | "-f" => {
                config = args.get(i + 1).cloned();
                i += 2;
            }
            "--against" => {
                against = args.get(i + 1).cloned();
                i += 2;
            }
            "--format" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--format requires a value (json|text)"))?;
                format = match v.as_str() {
                    "json" => PlanFormat::Json,
                    "text" => PlanFormat::Text,
                    other => {
                        return Err(anyhow::anyhow!(
                            "invalid --format '{other}'; expected 'json' or 'text'"
                        ));
                    }
                };
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown flag '{other}' for plan\n\n{PLAN_HELP}"
                ));
            }
        }
    }
    let config = config.ok_or_else(|| anyhow::anyhow!("missing -f / --config\n\n{PLAN_HELP}"))?;
    Ok(PlanArgs {
        config,
        against,
        format,
        out,
    })
}

fn parse_apply_args(args: &[String]) -> anyhow::Result<ApplyArgs> {
    let mut config: Option<String> = None;
    let mut plan_file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{APPLY_HELP}");
                std::process::exit(0);
            }
            "--config" | "-f" => {
                config = args.get(i + 1).cloned();
                i += 2;
            }
            "--plan" | "-p" => {
                plan_file = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown flag '{other}' for apply\n\n{APPLY_HELP}"
                ));
            }
        }
    }
    match (&config, &plan_file) {
        (None, None) => Err(anyhow::anyhow!(
            "missing -f / --config or -p / --plan\n\n{APPLY_HELP}"
        )),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "-f and -p are mutually exclusive\n\n{APPLY_HELP}"
        )),
        _ => Ok(ApplyArgs { config, plan_file }),
    }
}

/// Validate a YAML config file by running it through `compile_config`,
/// then return the parsed `ConfigFile` for the diff walker.
///
/// `compile_config` runs env-var interpolation and the schema +
/// semantic checks the proxy already enforces at startup. The diff
/// itself runs over the parsed `ConfigFile` (per the ADR's
/// "diff operates over the raw `ConfigFile`" rule), so we re-parse the
/// file with `serde_yaml::from_str` after `compile_config` has signed
/// it off.
fn load_and_validate(path: &str) -> anyhow::Result<sbproxy_config::ConfigFile> {
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path}': {e}"))?;
    sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path}' did not compile:\n{e:#}"))?;
    serde_yaml::from_str::<sbproxy_config::ConfigFile>(&yaml)
        .map_err(|e| anyhow::anyhow!("failed to parse '{path}' as ConfigFile: {e}"))
}

/// Empty baseline used when `--against` is not supplied. Mirrors the
/// "no prior config" branch of the ADR's baseline-resolution table; the
/// proposed config's origins all surface as `Added`.
fn empty_config_file() -> sbproxy_config::ConfigFile {
    serde_yaml::from_str::<sbproxy_config::ConfigFile>("")
        .expect("empty YAML parses to default ConfigFile")
}

/// Run the `sbproxy plan` subcommand. Returns the desired process
/// exit code:
///
/// * `0` no changes and no validation errors,
/// * `2` changes present and no validation errors,
/// * `3` semantic-validation errors present (per the WOR-131 ADR).
///
/// Per-flavour CLI / IO errors short-circuit out of the caller via
/// `anyhow::Result::Err` and exit 1.
fn handle_plan_subcommand(args: &[String]) -> anyhow::Result<i32> {
    let parsed = parse_plan_args(args)?;
    let proposed = load_and_validate(&parsed.config)?;
    let baseline = match parsed.against.as_deref() {
        Some(p) => load_and_validate(p)?,
        None => empty_config_file(),
    };
    let mut report = sbproxy_config::plan(&baseline, &proposed);

    // WOR-136: pick up `listings/*.yaml` from the same Repo (the
    // directory the proposed `sb.yml` lives in) and fold the
    // plan-step validation findings into the existing stream. The
    // OSS revision resolver is the no-op resolver: existence checks
    // require a git-aware caller (the future k8s controller, the
    // hosted-Catalog surface).
    let repo_root = std::path::Path::new(&parsed.config)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut listing_load_errors: Vec<sbproxy_config::ListingLoadError> = Vec::new();
    let loaded = sbproxy_config::load_listings_from_repo(&repo_root, &mut listing_load_errors);
    for err in &listing_load_errors {
        report.findings.push(sbproxy_config::PlanFinding {
            severity: sbproxy_config::Severity::Error,
            rule_id: "listing-load-error".to_string(),
            path: "listings".to_string(),
            message: err.to_string(),
        });
    }
    if !loaded.is_empty() {
        let registry = sbproxy_config::ListingRegistry::from_loaded(loaded, &mut report.findings);
        // Emit a load summary on stderr in the same idiom the rest
        // of the CLI uses for plan / apply progress.  `sbproxy plan`
        // is the entry point a future hosted-Catalog surface and the
        // k8s controller will share, so logging the count here keeps
        // operator feedback consistent across surfaces.
        eprintln!(
            "plan: sbproxy.listings.loaded count={} root={}",
            registry.len(),
            repo_root.display()
        );
        sbproxy_config::validate_listings(
            &registry,
            &proposed,
            &sbproxy_config::NoopRevisionResolver,
            &mut report.findings,
        );
    }

    match parsed.format {
        PlanFormat::Json => {
            let body = serde_json::to_string_pretty(&report)
                .map_err(|e| anyhow::anyhow!("failed to serialise plan: {e}"))?;
            println!("{body}");
        }
        PlanFormat::Text => {
            print!("{}", sbproxy_config::render_text(&report));
        }
    }

    // WOR-180 step 5: when --out is set, write the plan-file envelope
    // (report + baseline_revision) atomically via temp-file +
    // rename(2). Apply -p will recompute the plan and reject on
    // baseline drift.
    if let Some(out_path) = parsed.out.as_deref() {
        let plan_file = sbproxy_config::PlanFile::new(&baseline, report.clone());
        plan_file
            .write_to_path(std::path::Path::new(out_path))
            .map_err(|e| anyhow::anyhow!("failed to write plan-file '{out_path}': {e}"))?;
        eprintln!("plan: wrote plan-file to {out_path}");
    }

    if report.has_errors() {
        Ok(3)
    } else if report.is_noop() {
        Ok(0)
    } else {
        Ok(2)
    }
}

/// Take an exclusive `flock(2)` on the apply lock for `yaml_path`.
/// The lock file is `<yaml_path>.applylock`. Returns the held file
/// handle (the lock releases on drop). When the lock cannot be
/// acquired immediately, we surface that as exit code 6 so the
/// operator can see they collided with another in-flight apply.
fn acquire_apply_lock(yaml_path: &str) -> anyhow::Result<std::fs::File> {
    use fs2::FileExt as _;
    let lock_path = format!("{yaml_path}.applylock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open apply-lock '{lock_path}': {e}"))?;
    file.try_lock_exclusive().map_err(|e| {
        anyhow::anyhow!("another apply is in progress (could not lock '{lock_path}': {e})")
    })?;
    Ok(file)
}

/// Run the `sbproxy apply` subcommand. Loads + validates the proposed
/// YAML, runs plan-time semantic validation, and calls into the
/// existing `reload_from_config_path` primitive (the same call the
/// file watcher and SIGHUP handler use). Refuses to apply when any
/// `Severity::Error` finding is present.
///
/// Two flows are supported:
///
/// * `apply -f <yaml>`: validate, plan against an empty baseline,
///   reload.
/// * `apply -p <plan-file>`: read the plan-file (which records the
///   original baseline_revision and proposed config bytes-by-name),
///   recompute the plan against the live baseline (the proposed
///   YAML referenced by the plan-file), and reject with exit 5 if
///   the live baseline hashes differently than the plan recorded.
///
/// Both flows take an exclusive `flock(2)` on
/// `<yaml_path>.applylock` so two operators running `apply` against
/// the same on-host config cannot race each other (per WOR-131 ADR
/// open question 3).
fn handle_apply_subcommand(args: &[String]) -> anyhow::Result<i32> {
    let parsed = parse_apply_args(args)?;
    if let Some(plan_path) = parsed.plan_file.as_deref() {
        return handle_apply_from_plan_file(plan_path);
    }
    let yaml_path = parsed
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    handle_apply_from_yaml(yaml_path)
}

/// `apply -f <yaml>` flow. Acquires the apply-lock, validates, and
/// calls `reload_from_config_path`. Refuses on validation errors
/// (exit 3) or lock contention (exit 6).
fn handle_apply_from_yaml(yaml_path: &str) -> anyhow::Result<i32> {
    let _lock = match acquire_apply_lock(yaml_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apply: {e:#}");
            return Ok(6);
        }
    };

    // Validate first so apply never half-commits a broken config.
    let proposed = load_and_validate(yaml_path)?;
    let baseline = empty_config_file();
    let report = sbproxy_config::plan(&baseline, &proposed);
    if report.has_errors() {
        eprintln!("apply: refusing to apply, semantic validation failed:");
        eprint!("{}", sbproxy_config::render_text(&report));
        return Ok(3);
    }

    sbproxy_core::server::reload_from_config_path(yaml_path)
        .map_err(|e| anyhow::anyhow!("reload failed: {e:#}"))?;
    println!("apply: reloaded config from {yaml_path}");
    Ok(0)
}

/// `apply -p <plan-file>` flow. Reads the plan-file, locates the
/// proposed YAML by reading the same file path the plan was generated
/// against (encoded as the apply target via the proposed config's
/// own structural identity), recomputes the plan, and rejects with
/// exit 5 if the baseline_revision drifted.
///
/// This flow takes the lock on the **proposed** config path's
/// `.applylock` companion. The plan-file does not itself own a
/// long-lived target path; the operator passes the same `-f` value
/// implicitly via the plan that was written from `plan -f X`.
fn handle_apply_from_plan_file(plan_path: &str) -> anyhow::Result<i32> {
    // Read the plan-file. Schema is the v1 envelope written by
    // `plan --out`.
    let plan_file = sbproxy_config::PlanFile::read_from_path(std::path::Path::new(plan_path))
        .map_err(|e| anyhow::anyhow!("failed to read plan-file '{plan_path}': {e}"))?;

    // The plan-file does not embed the YAML path (it embeds only the
    // diff body and the baseline_revision). The operator must supply
    // the YAML via env var SB_APPLY_CONFIG so apply knows which file
    // to recompute against. This mirrors the `SB_CONFIG_FILE`
    // pattern used elsewhere in the binary.
    let yaml_path = std::env::var("SB_APPLY_CONFIG").map_err(|_| {
        anyhow::anyhow!(
            "apply -p requires SB_APPLY_CONFIG to point at the proposed YAML path \
             (the plan-file does not embed the path itself)"
        )
    })?;

    let _lock = match acquire_apply_lock(&yaml_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apply: {e:#}");
            return Ok(6);
        }
    };

    let proposed = load_and_validate(&yaml_path)?;
    // Recompute the plan against the same baseline shape as plan
    // time. We do not yet have an admin-socket "live baseline"
    // surface (open question 4), so the on-disk baseline is "the
    // empty config" by default. The operator can override this with
    // SB_APPLY_BASELINE pointing at a YAML file.
    let baseline = match std::env::var("SB_APPLY_BASELINE").ok() {
        Some(b) => load_and_validate(&b)?,
        None => empty_config_file(),
    };

    let live_revision = sbproxy_config::compute_baseline_revision(&baseline);
    if live_revision != plan_file.baseline_revision {
        eprintln!(
            "apply: plan-file is stale.\n  recorded baseline_revision: {}\n  live baseline_revision:     {}",
            plan_file.baseline_revision, live_revision
        );
        eprintln!("apply: rerun `sbproxy plan -f <yaml> --out <plan-file>` and re-apply.");
        return Ok(5);
    }

    let report = sbproxy_config::plan(&baseline, &proposed);
    if report.has_errors() {
        eprintln!("apply: refusing to apply, semantic validation failed:");
        eprint!("{}", sbproxy_config::render_text(&report));
        return Ok(3);
    }

    sbproxy_core::server::reload_from_config_path(&yaml_path)
        .map_err(|e| anyhow::anyhow!("reload failed: {e:#}"))?;
    println!("apply: reloaded config from {yaml_path} (via plan-file {plan_path})");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // env::set_var / env::remove_var aren't safe to interleave across
    // threads. Serialize the env-var tests through this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn log_filter_cli_wins_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_LOG_LEVEL", "warn");
        env::set_var("RUST_LOG", "trace");
        let got = resolve_log_filter(&args(&["sbproxy", "--log-level", "debug"]));
        env::remove_var("SB_LOG_LEVEL");
        env::remove_var("RUST_LOG");
        assert_eq!(got, "debug");
    }

    #[test]
    fn log_filter_falls_through_to_sb_log_level() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("RUST_LOG");
        env::set_var("SB_LOG_LEVEL", "warn");
        let got = resolve_log_filter(&args(&["sbproxy"]));
        env::remove_var("SB_LOG_LEVEL");
        assert_eq!(got, "warn");
    }

    #[test]
    fn log_filter_falls_through_to_rust_log() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_LOG_LEVEL");
        env::set_var("RUST_LOG", "sbproxy=trace");
        let got = resolve_log_filter(&args(&["sbproxy"]));
        env::remove_var("RUST_LOG");
        assert_eq!(got, "sbproxy=trace");
    }

    #[test]
    fn log_filter_default_info() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_LOG_LEVEL");
        env::remove_var("SB_REQUEST_LOG_LEVEL");
        env::remove_var("RUST_LOG");
        assert_eq!(resolve_log_filter(&args(&["sbproxy"])), "info");
    }

    #[test]
    fn request_log_level_cli_appends_access_log_target() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_LOG_LEVEL");
        env::remove_var("SB_REQUEST_LOG_LEVEL");
        env::remove_var("RUST_LOG");
        let got = resolve_log_filter(&args(&[
            "sbproxy",
            "--log-level",
            "warn",
            "--request-log-level",
            "debug",
        ]));
        assert_eq!(got, "warn,access_log=debug");
    }

    #[test]
    fn request_log_level_env_appends_access_log_target() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_LOG_LEVEL");
        env::remove_var("RUST_LOG");
        env::set_var("SB_REQUEST_LOG_LEVEL", "trace");
        let got = resolve_log_filter(&args(&["sbproxy"]));
        env::remove_var("SB_REQUEST_LOG_LEVEL");
        assert_eq!(got, "info,access_log=trace");
    }

    #[test]
    fn request_log_level_cli_wins_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_REQUEST_LOG_LEVEL", "trace");
        let got = resolve_log_filter(&args(&["sbproxy", "--request-log-level", "debug"]));
        env::remove_var("SB_REQUEST_LOG_LEVEL");
        assert_eq!(got, "info,access_log=debug");
    }

    #[test]
    fn grace_time_cli_overrides_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_GRACE_TIME", "30");
        let got = resolve_grace_time(&args(&["sbproxy", "--grace-time", "5"]));
        env::remove_var("SB_GRACE_TIME");
        assert_eq!(got, Some(5));
    }

    #[test]
    fn grace_time_env_only() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_GRACE_TIME", "12");
        let got = resolve_grace_time(&args(&["sbproxy"]));
        env::remove_var("SB_GRACE_TIME");
        assert_eq!(got, Some(12));
    }

    #[test]
    fn grace_time_unset_returns_none() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_GRACE_TIME");
        assert_eq!(resolve_grace_time(&args(&["sbproxy"])), None);
    }

    #[test]
    fn parse_config_skips_grace_time_value() {
        let argv = args(&[
            "sbproxy",
            "--grace-time",
            "30",
            "--config",
            "/etc/sbproxy/sb.yml",
        ]);
        assert_eq!(parse_config_path(&argv), Some("/etc/sbproxy/sb.yml"));
    }

    #[test]
    fn parse_config_skips_request_log_level_value() {
        let argv = args(&[
            "sbproxy",
            "--request-log-level",
            "debug",
            "--config",
            "/etc/sbproxy/sb.yml",
        ]);
        assert_eq!(parse_config_path(&argv), Some("/etc/sbproxy/sb.yml"));
    }

    // --- WOR-636: SIGINT/SIGTERM grace-period parser ---

    #[test]
    fn shutdown_grace_ms_cli_overrides_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SBPROXY_SHUTDOWN_GRACE_MS", "5000");
        let got = resolve_shutdown_grace_ms(&args(&["sbproxy", "--shutdown-grace-ms", "12000"]));
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        assert_eq!(got, Some(12_000));
    }

    #[test]
    fn shutdown_grace_ms_env_only() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SBPROXY_SHUTDOWN_GRACE_MS", "45000");
        let got = resolve_shutdown_grace_ms(&args(&["sbproxy"]));
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        assert_eq!(got, Some(45_000));
    }

    #[test]
    fn shutdown_grace_ms_unset_returns_none() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        assert_eq!(resolve_shutdown_grace_ms(&args(&["sbproxy"])), None);
    }

    #[test]
    fn shutdown_grace_ms_malformed_cli_is_ignored() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        // CLI value cannot be parsed: function falls through to the
        // env (also unset), returning None. The warning lands on
        // stderr; the unit test does not capture stderr but the
        // contract is that an unparseable value is non-fatal.
        let got = resolve_shutdown_grace_ms(&args(&[
            "sbproxy",
            "--shutdown-grace-ms",
            "thirty seconds please",
        ]));
        assert_eq!(got, None);
    }

    #[test]
    fn parse_config_skips_shutdown_grace_ms_value() {
        let argv = args(&[
            "sbproxy",
            "--shutdown-grace-ms",
            "30000",
            "--config",
            "/etc/sbproxy/sb.yml",
        ]);
        assert_eq!(parse_config_path(&argv), Some("/etc/sbproxy/sb.yml"));
    }

    /// The 30s default tracks Kubernetes' default
    /// `terminationGracePeriodSeconds`. Any change here is a
    /// behaviour change for orchestrators that rely on the default.
    #[test]
    fn shutdown_grace_default_is_30_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_GRACE_MS, 30_000);
    }
}
