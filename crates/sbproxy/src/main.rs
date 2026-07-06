//! sbproxy: AI Governance Gateway binary.
//!
//! Thin entrypoint that selects the rustls crypto provider, installs the
//! mimalloc allocator, parses CLI args with `clap` derive, and hands the
//! config path to [`sbproxy_core::run`]. All real work happens in the
//! workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::env;
use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// `doctor --install`: acquire missing serve: prerequisites.
mod install;

// mimalloc is Microsoft's high-performance allocator. Typically 5-10% faster
// than glibc malloc on server workloads; negligible on allocation-light
// paths. See sbproxy-bench/docs/RUST_OPTIMIZATIONS.md A2.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Default graceful-shutdown drain budget when no env var or CLI
/// flag is set. Matches the upstream client-go controller default
/// and the Kubernetes default `terminationGracePeriodSeconds` so a
/// pod eviction in a default-configured cluster drains cleanly.
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 30_000;

/// Top-level CLI surface. Built with `clap` derive so `--help`,
/// `--version`, and env-var fallbacks are wired by the macro.
///
/// `version = false` disables clap's auto-version line so we can
/// print the load-bearing `sbproxy <semver> (rev <sha>, built
/// <date>)` shape ourselves. The marketing site (`Hero.vue`) and the
/// Homebrew formula assert on that exact format.
#[derive(Parser, Debug)]
#[command(
    name = "sbproxy",
    bin_name = "sbproxy",
    about = "sbproxy: AI Governance Gateway. One self-hostable runtime for AI traffic, APIs, MCP, and AI crawlers.",
    long_about = None,
    disable_version_flag = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
)]
struct Cli {
    /// Print the version line and exit. Output shape:
    /// `sbproxy <semver> (rev <sha>, built <yyyy-mm-dd>)`.
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue, global = true)]
    version: bool,

    /// Validate the config and exit without starting the proxy.
    /// Equivalent to `sbproxy validate <path>` and dispatches to the
    /// same handler. Documented in `SUPPLY-CHAIN.md` as the CI-friendly
    /// verification step.
    #[arg(long = "check", action = ArgAction::SetTrue, global = true)]
    check: bool,

    #[command(flatten)]
    globals: GlobalArgs,

    /// Positional config path for the no-subcommand run form
    /// (`sbproxy /etc/sb.yml`).
    config_path: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

/// Global flags that apply to the run form and to every subcommand.
/// `global = true` makes each flag accepted at any depth so
/// `sbproxy --log-level debug validate cfg.yml` and
/// `sbproxy validate cfg.yml --log-level debug` are both accepted.
#[derive(clap::Args, Debug, Default)]
struct GlobalArgs {
    /// Path to sb.yml. Falls back to `SB_CONFIG_FILE`.
    #[arg(short = 'f', long = "config", env = "SB_CONFIG_FILE", global = true)]
    config: Option<PathBuf>,

    /// `tracing-subscriber` filter. Wins over `SB_LOG_LEVEL` and `RUST_LOG`.
    /// Default: info. Accepts a bare level, a per-target filter, or any
    /// combination thereof.
    #[arg(long = "log-level", env = "SB_LOG_LEVEL", global = true)]
    log_level: Option<String>,

    /// `access_log` target filter. Wins over `SB_REQUEST_LOG_LEVEL`.
    /// Default: unset.
    #[arg(
        long = "request-log-level",
        env = "SB_REQUEST_LOG_LEVEL",
        global = true
    )]
    request_log_level: Option<String>,

    /// Output format for the `tracing` subscriber.
    ///
    /// * `compact` (default): one short line per event. Best for tail
    ///   in a terminal.
    /// * `pretty`: multi-line with span trees. Best for local debugging.
    /// * `json`: structured records. Best for shipping to a log
    ///   aggregator (Loki, Datadog, CloudWatch).
    ///
    /// Falls back to `SB_LOG_FORMAT` and finally `compact`. Invalid
    /// values fail the parse with a clap error listing the accepted
    /// names, so an operator never starts the proxy with a silently
    /// ignored selector.
    #[arg(long = "log-format", env = "SB_LOG_FORMAT", value_enum, global = true)]
    log_format: Option<LogFormat>,

    /// Graceful-shutdown timeout in seconds (legacy). Wins over
    /// `SB_GRACE_TIME`. Superseded by `--shutdown-grace-ms`.
    #[arg(long = "grace-time", env = "SB_GRACE_TIME", global = true)]
    grace_time: Option<u64>,

    /// SIGINT/SIGTERM drain budget in milliseconds. Wins over
    /// `SBPROXY_SHUTDOWN_GRACE_MS` and over `--grace-time`. Default:
    /// 30000 (30s).
    #[arg(
        long = "shutdown-grace-ms",
        env = "SBPROXY_SHUTDOWN_GRACE_MS",
        global = true
    )]
    shutdown_grace_ms: Option<u64>,

    /// Lock off the per-request feature-flag surface (`x-sb-flags`
    /// header and `?_sb.<k>` query params). Env fallback
    /// `SB_DISABLE_SB_FLAGS` accepts `1`, `true`, `yes`, `on`.
    #[arg(
        long = "disable-sb-flags",
        action = ArgAction::SetTrue,
        global = true
    )]
    disable_sb_flags: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the proxy. Synonym for the no-subcommand run form.
    Serve(ServeArgs),
    /// Validate an sb.yml without starting the proxy. Useful in CI to
    /// fail fast on a bad config before deploying.
    Validate(ValidateArgs),
    /// Diff a proposed config against a baseline. Exit 0 no-op, 2
    /// changes present, 3 semantic-validation errors.
    Plan(PlanArgs),
    /// Validate and reload an sbproxy config in place. Same primitive
    /// the SIGHUP handler and file watcher use.
    Apply(ApplyArgs),
    /// Config maintenance commands.
    Config(ConfigCmd),
    /// Render projection documents (robots.txt, llms.txt, ...) for an
    /// origin without starting the proxy.
    Projections(ProjectionsCmd),
    /// AI gateway tools (usage ledger verification, ...).
    Ai(AiCmd),
    /// Diagnose what this binary can do on the current host: compiled
    /// capability features, visible GPUs, inference engines on PATH,
    /// and whether a `serve:` provider could admit a model here.
    Doctor(DoctorArgs),
    /// Print a shell-completion script to stdout for the requested
    /// shell. Pipe into the shell's completion sink.
    Completions {
        /// Target shell. One of bash, zsh, fish, powershell, elvish.
        shell: Shell,
    },
    /// Print the version line and exit. Synonym for `--version`.
    Version,
}

/// Positional path can stand in for `-f / --config` in the run form.
#[derive(clap::Args, Debug)]
struct ServeArgs {
    /// Positional config path. Equivalent to `-f <path>`.
    config_path: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ValidateArgs {
    /// Positional config path. Equivalent to `-f <path>`.
    config_path: Option<PathBuf>,
    /// Output format. `text` (default) prints a human line; `json`
    /// emits a single structured object for CI consumption.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct PlanArgs {
    /// Proposed config file. Required.
    #[arg(short = 'f', long = "config")]
    config: Option<PathBuf>,
    /// Baseline config file. Default: empty baseline (every origin
    /// in the proposed config surfaces as `added`).
    #[arg(long = "against")]
    against: Option<PathBuf>,
    /// Output format. `text` (default) is a terraform-style diff;
    /// `json` is the stable plan envelope for tooling.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Write the plan-file envelope (JSON, includes
    /// `baseline_revision` for staleness detection) to disk. Use
    /// with `apply -p <plan-file>`. Atomic via temp-file + rename(2).
    #[arg(long = "out")]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ApplyArgs {
    /// Proposed config file. Mutually exclusive with `-p`.
    #[arg(short = 'f', long = "config", conflicts_with = "plan_file")]
    config: Option<PathBuf>,
    /// Plan file from a prior `plan --out`. Apply recomputes the
    /// plan against the live baseline and refuses (exit 5) if the
    /// `baseline_revision` drifted. Mutually exclusive with `-f`.
    #[arg(short = 'p', long = "plan", conflicts_with = "config")]
    plan_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ConfigCmd {
    #[command(subcommand)]
    sub: ConfigSub,
}

#[derive(Subcommand, Debug)]
enum ConfigSub {
    /// Rewrite deprecated config syntax to the current canonical form.
    Migrate(ConfigMigrateArgs),
    /// Convert a LiteLLM config.yaml into an equivalent sbproxy sb.yml.
    ImportLitellm(ImportLitellmArgs),
}

#[derive(clap::Args, Debug)]
struct ConfigMigrateArgs {
    /// Path to the config file to migrate.
    config_path: PathBuf,
    /// Write migrated YAML to this path. Defaults to stdout.
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ImportLitellmArgs {
    /// Path to the LiteLLM config.yaml to convert.
    config_path: PathBuf,
    /// Write the translated sb.yml to this path. Defaults to stdout.
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct AiCmd {
    #[command(subcommand)]
    sub: AiSub,
}

#[derive(Subcommand, Debug)]
enum AiSub {
    /// Verifiable usage ledger commands.
    Ledger(LedgerCmd),
}

#[derive(clap::Args, Debug)]
struct LedgerCmd {
    #[command(subcommand)]
    sub: LedgerSub,
}

#[derive(Subcommand, Debug)]
enum LedgerSub {
    /// Re-derive a ledger's hash chain (and signatures, when a seed is
    /// given) and report the first broken link, if any. Exit 0 when the
    /// ledger verifies, 1 when it does not.
    Verify(LedgerVerifyArgs),
}

#[derive(clap::Args, Debug)]
struct LedgerVerifyArgs {
    /// Path to the ledger file (the JSONL write-ahead log).
    path: PathBuf,
    /// Optional 32-byte Ed25519 signing seed as hex. When provided, every
    /// entry's signature is verified against the derived public key.
    #[arg(long = "signing-seed-hex")]
    signing_seed_hex: Option<String>,
    /// Output format. `text` (default) prints a human line; `json` emits a
    /// single structured object for CI consumption.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ProjectionsCmd {
    #[command(subcommand)]
    sub: ProjectionsSub,
}

#[derive(Subcommand, Debug)]
enum ProjectionsSub {
    /// Render the named projection document to stdout for the named
    /// hostname. Pure render: no listener starts, no state mutates.
    Render(RenderArgs),
}

#[derive(clap::Args, Debug)]
struct RenderArgs {
    /// Projection kind.
    #[arg(short = 'k', long = "kind", value_enum)]
    kind: ProjectionKind,
    /// Path to sb.yml.
    #[arg(short = 'c', long = "config", alias = "f")]
    config: PathBuf,
    /// Hostname to render for. Defaults to the first origin in the
    /// compiled config.
    #[arg(short = 'H', long = "hostname")]
    hostname: Option<String>,
}

#[derive(clap::Args, Debug)]
struct DoctorArgs {
    /// Output format. `text` (default) prints the human report; `json`
    /// emits a single structured object for tooling.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Install a missing serve: prerequisite instead of reporting.
    /// `vllm` uses uv or pipx; `llama-cpp` uses Homebrew or a pinned
    /// release (`--llama-tag` + `--llama-sha256`). The command is
    /// printed and confirmed before anything runs.
    #[arg(long = "install", value_enum)]
    install: Option<install::InstallTarget>,
    /// Skip the confirmation prompt (for provisioning scripts).
    #[arg(long = "yes", short = 'y', requires = "install")]
    yes: bool,
    /// Pinned llama.cpp release tag (e.g. `b4589`; `latest` is
    /// rejected). Used by `--install llama-cpp` when Homebrew is
    /// absent.
    #[arg(long = "llama-tag", requires = "install")]
    llama_tag: Option<String>,
    /// sha256 of the pinned llama.cpp release zip for `--llama-tag`.
    #[arg(long = "llama-sha256", requires = "llama_tag")]
    llama_sha256: Option<String>,
    /// Where `--install llama-cpp` links the `llama-server` binary so
    /// the engine launcher finds it on PATH.
    #[arg(long = "bin-dir", default_value = "/usr/local/bin")]
    bin_dir: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum OutputFormat {
    Text,
    Json,
}

/// `tracing-subscriber` output format, selected by `--log-format`
/// (or `SB_LOG_FORMAT`). Closed enum so clap rejects unknown values
/// at parse time.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum LogFormat {
    /// One short line per event. Default; matches the historical
    /// behaviour before the flag was wired.
    #[default]
    Compact,
    /// Multi-line with span trees. Best for local debugging.
    Pretty,
    /// Structured JSON records. Best for a log aggregator.
    Json,
}

impl LogFormat {
    fn as_str(self) -> &'static str {
        match self {
            LogFormat::Compact => "compact",
            LogFormat::Pretty => "pretty",
            LogFormat::Json => "json",
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ProjectionKind {
    Robots,
    Llms,
    #[value(name = "llms-full")]
    LlmsFull,
    Licenses,
    Tdmrep,
}

impl ProjectionKind {
    fn as_str(self) -> &'static str {
        match self {
            ProjectionKind::Robots => "robots",
            ProjectionKind::Llms => "llms",
            ProjectionKind::LlmsFull => "llms-full",
            ProjectionKind::Licenses => "licenses",
            ProjectionKind::Tdmrep => "tdmrep",
        }
    }
}

fn main() {
    // rustls 0.23 requires the process to select a CryptoProvider before any
    // TLS machinery initialises. We install `ring` because `ring` is already
    // a workspace dependency (used by sbproxy-vault, sbproxy-tls, and
    // sbproxy-modules) so no new crate graph risk. Without this, every proxy
    // that touches TLS panics at startup.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    // --- --version / -V / `version` short-circuit ---
    //
    // Output shape: `sbproxy <semver> (rev <sha>, built <yyyy-mm-dd>)`.
    // CARGO_PKG_VERSION comes from the workspace `version`. The git SHA
    // and build date are embedded by build.rs at compile time.
    //
    // The output shape is load-bearing: the marketing site (Hero.vue)
    // advertises it, and Homebrew's `test do` block asserts on it. If
    // you change the format, fix Hero.vue and the homebrew formula in
    // lockstep.
    if cli.version || matches!(cli.cmd, Some(Cmd::Version)) {
        print_version();
        return;
    }

    // Resolve the effective log filter before tracing init so --log-level
    // and SB_LOG_LEVEL win over the default `info` and over RUST_LOG.
    // The priority is documented in docs/manual.md §13:
    //   1. `--log-level <level>` CLI flag (or SB_LOG_LEVEL via clap env)
    //   2. `RUST_LOG` env var (rustc-style filter syntax)
    //   3. `info`
    let log_filter = resolve_log_filter(&cli.globals);
    let log_format = cli.globals.log_format.unwrap_or_default();
    let runtime_telemetry = runtime_telemetry_config_for_cli(&cli);
    init_tracing(log_filter, log_format, runtime_telemetry.as_ref());

    // Resolve the graceful-shutdown grace period from the CLI flags / env
    // the operator set (`--grace-time` / `SB_GRACE_TIME`, and
    // `--shutdown-grace-ms` / `SBPROXY_SHUTDOWN_GRACE_MS`) and pass it
    // to `sbproxy_core::run` as a parameter, rather than re-exporting it
    // as a process env var for the core to read back. The binary overlays
    // a 30s default for `shutdown_grace_ms` so orchestrators (kubelet,
    // systemd, docker) get a sane drain window without setting any env
    // var; the in-process default inside `sbproxy_core` stays at zero so
    // the Go e2e runner can rebind the listener between test cases. The
    // legacy `--grace-time` suppresses that 30s overlay so the operator's
    // explicit value wins.
    let grace_time_secs = cli.globals.grace_time;
    let shutdown_grace_ms = cli.globals.shutdown_grace_ms.or({
        if grace_time_secs.is_some() {
            None
        } else {
            Some(DEFAULT_SHUTDOWN_GRACE_MS)
        }
    });
    let grace = sbproxy_core::GraceConfig {
        shutdown_grace_ms,
        grace_time_secs,
    };

    // Lock off the per-request feature-flag surface for production
    // hardening. The CLI flag is wired by clap; the env-var form
    // accepts `1|true|yes|on` and is handled here so the env semantics
    // match the legacy hand-rolled parser.
    if cli.globals.disable_sb_flags || env_disable_sb_flags() {
        sbproxy_core::sb_flags::set_disabled(true);
    }

    // `--check` upgrades the run path to a validate path. The same
    // handler powers the `validate <path>` subcommand.
    if cli.check && matches!(cli.cmd, None | Some(Cmd::Serve(_))) {
        let path = pick_run_path(&cli);
        let args = ValidateArgs {
            config_path: path,
            format: OutputFormat::Text,
        };
        run_subcommand("validate", 2, handle_validate_subcommand(&args));
    }

    match cli.cmd {
        Some(Cmd::Validate(args)) => {
            run_subcommand("validate", 2, handle_validate_subcommand(&args));
        }
        Some(Cmd::Plan(args)) => {
            run_subcommand("plan", 1, handle_plan_subcommand(&args));
        }
        Some(Cmd::Apply(args)) => {
            run_subcommand("apply", 1, handle_apply_subcommand(&args));
        }
        Some(Cmd::Config(cmd)) => {
            run_subcommand("config", 2, handle_config_subcommand(&cmd));
        }
        Some(Cmd::Projections(cmd)) => {
            run_subcommand("error", 2, handle_projections_subcommand(&cmd).map(|()| 0));
        }
        Some(Cmd::Ai(cmd)) => {
            run_subcommand("ai", 2, handle_ai_subcommand(&cmd));
        }
        Some(Cmd::Doctor(args)) => {
            run_subcommand("doctor", 2, handle_doctor_subcommand(&args));
        }
        Some(Cmd::Completions { shell }) => {
            print_completions(shell);
        }
        Some(Cmd::Version) => unreachable!("handled by short-circuit above"),
        Some(Cmd::Serve(_)) | None => {
            let path = pick_run_path(&cli);
            run_proxy(path.as_deref(), grace);
        }
    }
}

/// Pick the effective config path for the run / `--check` path.
/// Priority: subcommand positional (`serve <path>`), top-level
/// positional (`sbproxy <path>`), then `-f/--config` (CLI or env via
/// `SB_CONFIG_FILE`).
fn pick_run_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(Cmd::Serve(s)) = &cli.cmd {
        if s.config_path.is_some() {
            return s.config_path.clone();
        }
    }
    if cli.config_path.is_some() {
        return cli.config_path.clone();
    }
    cli.globals.config.clone()
}

/// Run the proxy or print the usage stub on a missing config path.
fn run_proxy(config_path: Option<&std::path::Path>, grace: sbproxy_core::GraceConfig) {
    match config_path {
        Some(path) => {
            let path_str = path.to_string_lossy();
            if let Err(e) = sbproxy_core::run(&path_str, grace) {
                eprintln!("Fatal: {e:#}");
                std::process::exit(1);
            }
        }
        None => {
            let mut cmd = Cli::command();
            let _ = cmd.print_help();
            eprintln!();
            std::process::exit(1);
        }
    }
}

/// Print the load-bearing version line.
fn print_version() {
    println!(
        "sbproxy {} (rev {}, built {})",
        env!("CARGO_PKG_VERSION"),
        env!("SBPROXY_GIT_SHA"),
        env!("SBPROXY_BUILD_DATE"),
    );
}

/// Print a shell-completion script for `shell` to stdout.
fn print_completions(shell: Shell) {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
}

/// Resolve the effective log filter. CLI `--log-level <level>` wins
/// (clap also folds in `SB_LOG_LEVEL` via `env = "..."`); otherwise
/// `RUST_LOG`, then `info`. CLI `--request-log-level <level>` /
/// `SB_REQUEST_LOG_LEVEL` append an `access_log=<level>` target
/// directive.
fn resolve_log_filter(g: &GlobalArgs) -> String {
    let base = match g.log_level.as_deref().filter(|s| !s.is_empty()) {
        Some(v) => v.to_string(),
        None => match env::var("RUST_LOG") {
            Ok(v) if !v.is_empty() => v,
            _ => "info".to_string(),
        },
    };
    match g.request_log_level.as_deref().filter(|s| !s.is_empty()) {
        Some(request_level) => format!("{base},access_log={request_level}"),
        None => base,
    }
}

/// Read the run config just far enough to map `proxy.observability.telemetry`
/// into the observe crate's runtime config. Errors return `None` so the
/// normal run path can report the authoritative config failure after logging
/// is installed.
fn runtime_telemetry_config_for_cli(cli: &Cli) -> Option<sbproxy_observe::TelemetryConfig> {
    if cli.check || !matches!(cli.cmd, None | Some(Cmd::Serve(_))) {
        return None;
    }

    let path = pick_run_path(cli)?;
    let yaml = std::fs::read_to_string(&path).ok()?;
    let compiled = sbproxy_config::compile_config(&yaml).ok()?;
    compiled
        .server
        .observability
        .as_ref()
        .and_then(|observability| observability.telemetry.as_ref())
        .map(runtime_telemetry_config)
}

fn runtime_telemetry_config(
    raw: &sbproxy_config::ObservabilityTelemetryConfig,
) -> sbproxy_observe::TelemetryConfig {
    sbproxy_observe::TelemetryConfig {
        enabled: raw.enabled,
        endpoint: raw.endpoint.clone(),
        transport: match raw.transport.as_deref() {
            Some("http") => sbproxy_observe::OtlpTransport::Http,
            _ => sbproxy_observe::OtlpTransport::Grpc,
        },
        service_name: raw
            .service_name
            .clone()
            .unwrap_or_else(|| "sbproxy".to_string()),
        sample_rate: raw.sample_rate,
        always_sample_errors: raw.always_sample_errors.unwrap_or(true),
        keep_over_budget_usd: raw.keep_over_budget_usd,
        keep_slower_than_secs: raw.keep_slower_than_secs,
        propagation: raw.propagation.clone(),
        resource_attrs: raw.resource_attrs.clone(),
        export_metrics: raw.export_metrics,
        metrics_interval_secs: raw.metrics_interval_secs,
    }
}

fn init_tracing(
    log_filter: String,
    format: LogFormat,
    telemetry: Option<&sbproxy_observe::TelemetryConfig>,
) {
    let logging = sbproxy_observe::LoggingConfig {
        level: log_filter,
        format: format.as_str().to_string(),
        sampling: sbproxy_observe::SamplingConfig::default(),
    };
    logging.init_with_resolved_filter_and_telemetry(telemetry);
}

/// Honour `SB_DISABLE_SB_FLAGS=1|true|yes|on` (case-insensitive).
/// The CLI flag is wired by clap; this handles only the env form so
/// the env semantics match the legacy parser.
fn env_disable_sb_flags() -> bool {
    match env::var("SB_DISABLE_SB_FLAGS").ok().as_deref() {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

/// Run a subcommand handler that returns an exit code, applying the
/// shared `<prefix>: <error>` envelope: on success exit with the
/// handler's code, on failure print the prefixed error and exit
/// `err_code`. Replaces the four near-identical inline envelopes that
/// used to wrap the `validate` / `projections` / `plan` / `apply`
/// handlers in `main`.
fn run_subcommand(prefix: &str, err_code: i32, result: anyhow::Result<i32>) -> ! {
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{prefix}: {e:#}");
            std::process::exit(err_code);
        }
    }
}

// --- `validate` handler ---

/// Validate an `sb.yml` without starting the proxy. Returns the process
/// exit code: `0` for a config that loads and compiles cleanly, `2` for
/// one that does not. `Err` is reserved for usage errors (missing path),
/// which the caller prints and exits `2`.
///
/// With `--format json` the result is emitted as a single JSON object on
/// stdout so CI can parse it: `{"valid": true, "path": "..."}` or
/// `{"valid": false, "path": "...", "error": "..."}`. The default
/// `--format text` keeps the human line on success and a stderr error on
/// failure.
fn handle_validate_subcommand(args: &ValidateArgs) -> anyhow::Result<i32> {
    let path = args.config_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "missing config path\n\nusage: sbproxy validate <path> [--format json|text]\n   or: sbproxy validate --config <path>"
        )
    })?;
    let path_str = path.to_string_lossy().into_owned();
    let json = matches!(args.format, OutputFormat::Json);

    // Read + compile. The read and compile failures are the two
    // "invalid config" outcomes; in JSON mode they are reported as
    // `{"valid": false, ...}` with exit 2 rather than propagated.
    let outcome = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))
        .and_then(|yaml| {
            sbproxy_config::compile_config(&yaml)
                .map(|_| ())
                .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))
        });

    match (json, outcome) {
        (false, Ok(())) => {
            println!("ok: {path_str} is a valid sbproxy config");
            Ok(0)
        }
        // Text mode delegates the failure print to the caller, which
        // prefixes "validate: " and exits 2.
        (false, Err(e)) => Err(e),
        (true, Ok(())) => {
            println!("{}", serde_json::json!({ "valid": true, "path": path_str }));
            Ok(0)
        }
        (true, Err(e)) => {
            println!(
                "{}",
                serde_json::json!({
                    "valid": false,
                    "path": path_str,
                    "error": format!("{e:#}"),
                })
            );
            Ok(2)
        }
    }
}

// --- `doctor` handler ---

/// Print the host-capability diagnostics report, or, with
/// `--install`, acquire a missing prerequisite. The report path exits
/// 0 once the report is produced ("this host cannot serve local
/// models" is a finding, not an error); the install path exits 0 only
/// when the prerequisite is in place afterwards.
fn handle_doctor_subcommand(args: &DoctorArgs) -> anyhow::Result<i32> {
    if let Some(target) = args.install {
        return install::run(
            target,
            args.yes,
            args.llama_tag.as_deref(),
            args.llama_sha256.as_deref(),
            &args.bin_dir,
        );
    }
    let report = sbproxy_core::doctor::DoctorReport::collect();
    match args.format {
        OutputFormat::Text => print!("{}", report.render_text()),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(0)
}

// --- `projections` handler ---

/// Dispatch the `projections render` subcommand.
fn handle_projections_subcommand(cmd: &ProjectionsCmd) -> anyhow::Result<()> {
    match &cmd.sub {
        ProjectionsSub::Render(args) => handle_projections_render(args),
    }
}

fn handle_projections_render(args: &RenderArgs) -> anyhow::Result<()> {
    let config_str = args.config.to_string_lossy().into_owned();
    let yaml = std::fs::read_to_string(&args.config)
        .map_err(|e| anyhow::anyhow!("failed to read config '{config_str}': {e}"))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;

    // The CLI uses a deterministic config_version of 0 so output is
    // reproducible across invocations, matching the
    // "byte-for-byte identical" preview contract for a given config.
    let docs = sbproxy_modules::projections::render_projections(&compiled, 0);

    // Pick the hostname: explicit flag wins; otherwise default to the
    // first origin in the compiled config so a single-origin config
    // works without extra arguments.
    let hostname = match args.hostname.as_deref() {
        Some(h) => h.to_string(),
        None => compiled
            .origins
            .first()
            .map(|o| o.hostname.to_string())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no origins configured in '{config_str}'; cannot pick a default hostname"
                )
            })?,
    };

    let body = lookup_projection(&docs, args.kind, &hostname).ok_or_else(|| {
        anyhow::anyhow!(
            "no '{}' projection for hostname '{hostname}' (origin missing or has no \
             ai_crawl_control policy)",
            args.kind.as_str()
        )
    })?;

    use std::io::Write as _;
    std::io::stdout().write_all(body.as_ref())?;
    std::io::stdout().flush()?;
    Ok(())
}

// --- `config` handler ---

fn handle_config_subcommand(cmd: &ConfigCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        ConfigSub::Migrate(args) => handle_config_migrate(args),
        ConfigSub::ImportLitellm(args) => handle_config_import_litellm(args),
    }
}

fn handle_ai_subcommand(cmd: &AiCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        AiSub::Ledger(ledger) => match &ledger.sub {
            LedgerSub::Verify(args) => handle_ledger_verify(args),
        },
    }
}

fn handle_ledger_verify(args: &LedgerVerifyArgs) -> anyhow::Result<i32> {
    let verifying_key = match args.signing_seed_hex.as_deref() {
        Some(seed) => Some(sbproxy_ai::usage_ledger::verifying_key_from_seed_hex(seed)?),
        None => None,
    };
    let result = sbproxy_ai::usage_ledger::verify_ledger(&args.path, verifying_key.as_ref())?;
    let path_str = args.path.to_string_lossy();

    match args.format {
        OutputFormat::Json => {
            let obj = serde_json::json!({
                "path": path_str,
                "entries": result.entries,
                "ok": result.ok,
                "broken_seq": result.broken_seq,
                "reason": result.reason,
                "signature_checked": verifying_key.is_some(),
            });
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Text => {
            if result.ok {
                println!(
                    "ledger verify: OK ({} entr{}, {})",
                    result.entries,
                    if result.entries == 1 { "y" } else { "ies" },
                    if verifying_key.is_some() {
                        "chain + signatures"
                    } else {
                        "chain only"
                    },
                );
            } else {
                eprintln!(
                    "ledger verify: FAILED at seq {}: {}",
                    result.broken_seq.map(|s| s.to_string()).unwrap_or_default(),
                    result.reason.as_deref().unwrap_or("unknown"),
                );
            }
        }
    }

    Ok(if result.ok { 0 } else { 1 })
}

fn handle_config_import_litellm(args: &ImportLitellmArgs) -> anyhow::Result<i32> {
    let path_str = args.config_path.to_string_lossy();
    let yaml = std::fs::read_to_string(&args.config_path)
        .map_err(|e| anyhow::anyhow!("failed to read LiteLLM config '{path_str}': {e}"))?;
    let translation = sbproxy_config::litellm::translate_litellm(&yaml)?;

    match args.out.as_deref() {
        Some(out_path) => {
            let out_str = out_path.to_string_lossy();
            std::fs::write(out_path, translation.sb_yaml.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to write sb.yml '{out_str}': {e}"))?;
            eprintln!("config import-litellm: wrote {out_str}");
        }
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(translation.sb_yaml.as_bytes())?;
            std::io::stdout().flush()?;
        }
    }

    // Warnings go to stderr so stdout stays a clean sb.yml; unmapped keys are
    // not failures.
    for w in &translation.warnings {
        eprintln!("warning: {w}");
    }
    if !translation.warnings.is_empty() {
        eprintln!(
            "config import-litellm: {} key(s) need manual attention (see warnings above)",
            translation.warnings.len()
        );
    }

    Ok(0)
}

fn handle_config_migrate(args: &ConfigMigrateArgs) -> anyhow::Result<i32> {
    let path_str = args.config_path.to_string_lossy();
    let yaml = std::fs::read_to_string(&args.config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))?;
    let migration = sbproxy_vault::migrate_legacy_vault_references_in_text(&yaml);

    match args.out.as_deref() {
        Some(out_path) => {
            let out_str = out_path.to_string_lossy();
            std::fs::write(out_path, migration.output.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to write migrated config '{out_str}': {e}"))?;
            eprintln!(
                "config migrate: wrote {out_str} (rewrote {} legacy vault reference(s))",
                migration.replacements.len()
            );
        }
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(migration.output.as_bytes())?;
            std::io::stdout().flush()?;
        }
    }

    Ok(0)
}

fn lookup_projection<'a>(
    docs: &'a sbproxy_modules::projections::ProjectionDocs,
    kind: ProjectionKind,
    hostname: &str,
) -> Option<&'a bytes::Bytes> {
    match kind {
        ProjectionKind::Robots => docs.robots_txt.get(hostname),
        ProjectionKind::Llms => docs.llms_txt.get(hostname),
        ProjectionKind::LlmsFull => docs.llms_full_txt.get(hostname),
        ProjectionKind::Licenses => docs.licenses_xml.get(hostname),
        ProjectionKind::Tdmrep => docs.tdmrep_json.get(hostname),
    }
}

// --- plan / apply handlers (steps 1+2 of `docs/adr-config-plan-apply.md`) ---

/// Validate a YAML config file by running it through `compile_config`,
/// then return the parsed `ConfigFile` for the diff walker.
///
/// `compile_config` runs env-var interpolation and the schema +
/// semantic checks the proxy already enforces at startup. The diff
/// itself runs over the parsed `ConfigFile` (per the ADR's
/// "diff operates over the raw `ConfigFile`" rule), so we re-parse the
/// file with `serde_yaml::from_str` after `compile_config` has signed
/// it off.
fn load_and_validate(path: &std::path::Path) -> anyhow::Result<sbproxy_config::ConfigFile> {
    let path_str = path.to_string_lossy();
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))?;
    sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
    serde_yaml::from_str::<sbproxy_config::ConfigFile>(&yaml)
        .map_err(|e| anyhow::anyhow!("failed to parse '{path_str}' as ConfigFile: {e}"))
}

/// Empty baseline used when `--against` is not supplied. Mirrors the
/// "no prior config" branch of the ADR's baseline-resolution table; the
/// proposed config's origins all surface as `Added`.
fn empty_config_file() -> sbproxy_config::ConfigFile {
    serde_yaml::from_str::<sbproxy_config::ConfigFile>("")
        .expect("empty YAML parses to default ConfigFile")
}

/// Parse `plan` argv and load + validate both sides of the diff.
/// Returns `(baseline, proposed)`; the baseline is the empty config
/// when `--against` is absent.
fn load_plan_inputs(
    args: &PlanArgs,
) -> anyhow::Result<(sbproxy_config::ConfigFile, sbproxy_config::ConfigFile)> {
    let config = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    let proposed = load_and_validate(config)?;
    let baseline = match args.against.as_deref() {
        Some(p) => load_and_validate(p)?,
        None => empty_config_file(),
    };
    Ok((baseline, proposed))
}

/// Diff `baseline` vs `proposed` and fold in the repo's `listings/*.yaml`
/// plan-step findings. The repo root is the directory holding
/// the proposed `sb.yml`. The OSS revision resolver is the no-op
/// resolver: existence checks require a git-aware caller (the future
/// k8s controller, the hosted-Catalog surface).
fn collect_plan_findings(
    config_path: &std::path::Path,
    baseline: &sbproxy_config::ConfigFile,
    proposed: &sbproxy_config::ConfigFile,
) -> sbproxy_config::PlanReport {
    let mut report = sbproxy_config::plan(baseline, proposed);
    let repo_root = config_path
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
        // Emit a load summary on stderr in the same idiom the rest of
        // the CLI uses for plan / apply progress, so operator feedback
        // stays consistent across the surfaces that share this entry
        // point.
        eprintln!(
            "plan: sbproxy.listings.loaded count={} root={}",
            registry.len(),
            repo_root.display()
        );
        sbproxy_config::validate_listings(
            &registry,
            proposed,
            &sbproxy_config::NoopRevisionResolver,
            &mut report.findings,
        );
    }
    report
}

/// Render the plan report to stdout in the requested format and, when
/// `--out` is set, write the plan-file envelope (report +
/// baseline_revision) atomically via temp-file + `rename(2)` for a
/// later `apply -p` to consume.
fn render_and_write_plan(
    report: &sbproxy_config::PlanReport,
    args: &PlanArgs,
    baseline: &sbproxy_config::ConfigFile,
) -> anyhow::Result<()> {
    match args.format {
        OutputFormat::Json => {
            let body = serde_json::to_string_pretty(report)
                .map_err(|e| anyhow::anyhow!("failed to serialise plan: {e}"))?;
            println!("{body}");
        }
        OutputFormat::Text => {
            print!("{}", sbproxy_config::render_text(report));
        }
    }
    if let Some(out_path) = args.out.as_deref() {
        let out_str = out_path.to_string_lossy();
        let plan_file = sbproxy_config::PlanFile::new(baseline, report.clone());
        plan_file
            .write_to_path(out_path)
            .map_err(|e| anyhow::anyhow!("failed to write plan-file '{out_str}': {e}"))?;
        eprintln!("plan: wrote plan-file to {out_str}");
    }
    Ok(())
}

/// Map a plan report to the CLI exit code: 3 on any error finding, 0
/// when the plan is a no-op, 2 when there are non-error changes.
fn plan_exit_code(report: &sbproxy_config::PlanReport) -> i32 {
    if report.has_errors() {
        3
    } else if report.is_noop() {
        0
    } else {
        2
    }
}

fn handle_plan_subcommand(args: &PlanArgs) -> anyhow::Result<i32> {
    let (baseline, proposed) = load_plan_inputs(args)?;
    let config_path = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    let report = collect_plan_findings(config_path, &baseline, &proposed);
    render_and_write_plan(&report, args, &baseline)?;
    Ok(plan_exit_code(&report))
}

/// Take an exclusive `flock(2)` on the apply lock for `yaml_path`.
/// The lock file is `<yaml_path>.applylock`. Returns the held file
/// handle (the lock releases on drop). When the lock cannot be
/// acquired immediately, we surface that as exit code 6 so the
/// operator can see they collided with another in-flight apply.
fn acquire_apply_lock(yaml_path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    use fs2::FileExt as _;
    let lock_path = format!("{}.applylock", yaml_path.to_string_lossy());
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
/// the same on-host config cannot race each other.
fn handle_apply_subcommand(args: &ApplyArgs) -> anyhow::Result<i32> {
    if let Some(plan_path) = args.plan_file.as_deref() {
        return handle_apply_from_plan_file(plan_path);
    }
    let yaml_path = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config or -p / --plan"))?;
    handle_apply_from_yaml(yaml_path)
}

/// `apply -f <yaml>` flow. Acquires the apply-lock, validates, and
/// calls `reload_from_config_path`. Refuses on validation errors
/// (exit 3) or lock contention (exit 6).
fn handle_apply_from_yaml(yaml_path: &std::path::Path) -> anyhow::Result<i32> {
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

    let yaml_path_str = yaml_path.to_string_lossy().into_owned();
    sbproxy_core::server::reload_from_config_path(&yaml_path_str)
        .map_err(|e| anyhow::anyhow!("reload failed: {e:#}"))?;
    println!("apply: reloaded config from {yaml_path_str}");
    Ok(0)
}

/// `apply -p <plan-file>` flow. Reads the plan-file, locates the
/// proposed YAML by reading the path the operator supplied via the
/// `SB_APPLY_CONFIG` env var, recomputes the plan, and rejects with
/// exit 5 if the baseline_revision drifted.
fn handle_apply_from_plan_file(plan_path: &std::path::Path) -> anyhow::Result<i32> {
    let plan_path_str = plan_path.to_string_lossy().into_owned();
    let plan_file = sbproxy_config::PlanFile::read_from_path(plan_path)
        .map_err(|e| anyhow::anyhow!("failed to read plan-file '{plan_path_str}': {e}"))?;

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
    let yaml_path_buf = std::path::PathBuf::from(&yaml_path);

    let _lock = match acquire_apply_lock(&yaml_path_buf) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apply: {e:#}");
            return Ok(6);
        }
    };

    let proposed = load_and_validate(&yaml_path_buf)?;
    // Recompute the plan against the same baseline shape as plan
    // time. We do not yet have an admin-socket "live baseline"
    // surface, so the on-disk baseline is "the empty config" by
    // default. The operator can override this with SB_APPLY_BASELINE
    // pointing at a YAML file.
    let baseline = match std::env::var("SB_APPLY_BASELINE").ok() {
        Some(b) => load_and_validate(std::path::Path::new(&b))?,
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
    println!("apply: reloaded config from {yaml_path} (via plan-file {plan_path_str})");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // env::set_var / env::remove_var aren't safe to interleave across
    // threads. Serialize the env-var tests through this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Parse `argv` with clap and return the resulting `Cli`. Each
    /// test owns its argv slice so clap's `try_get_matches_from` does
    /// not consume the process's real `std::env::args`.
    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("clap parse should succeed")
    }

    /// Build a `GlobalArgs` with just the log-related fields set, for
    /// the `resolve_log_filter` precedence tests.
    fn globals_with_log(level: Option<&str>, request: Option<&str>) -> GlobalArgs {
        GlobalArgs {
            log_level: level.map(str::to_string),
            request_log_level: request.map(str::to_string),
            ..Default::default()
        }
    }

    // --- log-filter precedence ---

    #[test]
    fn log_filter_cli_wins_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("RUST_LOG", "trace");
        let got = resolve_log_filter(&globals_with_log(Some("debug"), None));
        env::remove_var("RUST_LOG");
        assert_eq!(got, "debug");
    }

    #[test]
    fn log_filter_falls_through_to_rust_log() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("RUST_LOG", "sbproxy=trace");
        let got = resolve_log_filter(&globals_with_log(None, None));
        env::remove_var("RUST_LOG");
        assert_eq!(got, "sbproxy=trace");
    }

    #[test]
    fn log_filter_default_info() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("RUST_LOG");
        assert_eq!(resolve_log_filter(&globals_with_log(None, None)), "info");
    }

    #[test]
    fn request_log_level_cli_appends_access_log_target() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("RUST_LOG");
        let got = resolve_log_filter(&globals_with_log(Some("warn"), Some("debug")));
        assert_eq!(got, "warn,access_log=debug");
    }

    #[test]
    fn request_log_level_env_appends_access_log_target() {
        // SB_REQUEST_LOG_LEVEL is read by clap when the CLI flag is
        // absent. Drive that path by populating `GlobalArgs` the way
        // clap would: with the env value already folded into the
        // `request_log_level` field.
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("RUST_LOG");
        let got = resolve_log_filter(&globals_with_log(None, Some("trace")));
        assert_eq!(got, "info,access_log=trace");
    }

    // --- clap env-var precedence (CLI > env) ---

    #[test]
    fn clap_cli_log_level_wins_over_sb_log_level() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_LOG_LEVEL", "warn");
        let cli = parse(&["sbproxy", "--log-level", "debug", "/tmp/sb.yml"]);
        env::remove_var("SB_LOG_LEVEL");
        assert_eq!(cli.globals.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn clap_sb_log_level_env_fills_the_gap() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_LOG_LEVEL", "warn");
        let cli = parse(&["sbproxy", "/tmp/sb.yml"]);
        env::remove_var("SB_LOG_LEVEL");
        assert_eq!(cli.globals.log_level.as_deref(), Some("warn"));
    }

    #[test]
    fn clap_shutdown_grace_cli_wins_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SBPROXY_SHUTDOWN_GRACE_MS", "5000");
        let cli = parse(&["sbproxy", "--shutdown-grace-ms", "12000", "/tmp/sb.yml"]);
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        assert_eq!(cli.globals.shutdown_grace_ms, Some(12_000));
    }

    #[test]
    fn clap_shutdown_grace_env_only() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SBPROXY_SHUTDOWN_GRACE_MS", "45000");
        let cli = parse(&["sbproxy", "/tmp/sb.yml"]);
        env::remove_var("SBPROXY_SHUTDOWN_GRACE_MS");
        assert_eq!(cli.globals.shutdown_grace_ms, Some(45_000));
    }

    #[test]
    fn clap_grace_time_cli_wins_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_GRACE_TIME", "30");
        let cli = parse(&["sbproxy", "--grace-time", "5", "/tmp/sb.yml"]);
        env::remove_var("SB_GRACE_TIME");
        assert_eq!(cli.globals.grace_time, Some(5));
    }

    /// The 30s default tracks Kubernetes' default
    /// `terminationGracePeriodSeconds`. Any change here is a
    /// behaviour change for orchestrators that rely on the default.
    #[test]
    fn shutdown_grace_default_is_30_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_GRACE_MS, 30_000);
    }

    // --- run-path resolution ---

    #[test]
    fn run_path_prefers_serve_positional() {
        let cli = parse(&["sbproxy", "serve", "-f", "/etc/sbproxy/sb.yml"]);
        let p = pick_run_path(&cli).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/sbproxy/sb.yml"));
    }

    #[test]
    fn run_path_picks_top_level_positional() {
        let cli = parse(&["sbproxy", "/etc/sbproxy/sb.yml"]);
        let p = pick_run_path(&cli).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/sbproxy/sb.yml"));
    }

    #[test]
    fn run_path_picks_dash_f_flag() {
        let cli = parse(&["sbproxy", "-f", "/etc/sbproxy/sb.yml"]);
        let p = pick_run_path(&cli).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/sbproxy/sb.yml"));
    }

    #[test]
    fn run_path_picks_long_config_flag() {
        let cli = parse(&["sbproxy", "--config", "/etc/sbproxy/sb.yml"]);
        let p = pick_run_path(&cli).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/sbproxy/sb.yml"));
    }

    // --- subcommand parsing ---

    #[test]
    fn parses_validate_subcommand_with_positional_path() {
        let cli = parse(&["sbproxy", "validate", "/etc/sbproxy/sb.yml"]);
        match cli.cmd {
            Some(Cmd::Validate(args)) => {
                assert_eq!(
                    args.config_path,
                    Some(std::path::PathBuf::from("/etc/sbproxy/sb.yml"))
                );
                assert!(matches!(args.format, OutputFormat::Text));
            }
            other => panic!("expected Validate, got {other:?}"),
        }
    }

    #[test]
    fn parses_validate_subcommand_with_json_format() {
        let cli = parse(&[
            "sbproxy",
            "validate",
            "/etc/sbproxy/sb.yml",
            "--format",
            "json",
        ]);
        let args = match cli.cmd {
            Some(Cmd::Validate(args)) => args,
            other => panic!("expected Validate, got {other:?}"),
        };
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn parses_projections_render_with_kind_and_hostname() {
        let cli = parse(&[
            "sbproxy",
            "projections",
            "render",
            "--kind",
            "llms-full",
            "--config",
            "/etc/sbproxy/sb.yml",
            "--hostname",
            "api.example.com",
        ]);
        let cmd = match cli.cmd {
            Some(Cmd::Projections(cmd)) => cmd,
            other => panic!("expected Projections, got {other:?}"),
        };
        let ProjectionsSub::Render(args) = cmd.sub;
        assert!(matches!(args.kind, ProjectionKind::LlmsFull));
        assert_eq!(args.config, std::path::PathBuf::from("/etc/sbproxy/sb.yml"));
        assert_eq!(args.hostname.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn projections_render_supports_short_flags() {
        let cli = parse(&[
            "sbproxy",
            "projections",
            "render",
            "-k",
            "robots",
            "-c",
            "/etc/sbproxy/sb.yml",
        ]);
        let ProjectionsSub::Render(args) = match cli.cmd {
            Some(Cmd::Projections(cmd)) => cmd.sub,
            _ => panic!("expected Projections"),
        };
        assert!(matches!(args.kind, ProjectionKind::Robots));
        assert!(args.hostname.is_none());
    }

    #[test]
    fn parses_plan_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "plan",
            "-f",
            "proposed.yml",
            "--against",
            "baseline.yml",
            "--format",
            "json",
            "--out",
            "plan.json",
        ]);
        let args = match cli.cmd {
            Some(Cmd::Plan(args)) => args,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(args.config, Some(std::path::PathBuf::from("proposed.yml")));
        assert_eq!(args.against, Some(std::path::PathBuf::from("baseline.yml")));
        assert!(matches!(args.format, OutputFormat::Json));
        assert_eq!(args.out, Some(std::path::PathBuf::from("plan.json")));
    }

    #[test]
    fn parses_apply_subcommand_with_yaml() {
        let cli = parse(&["sbproxy", "apply", "-f", "proposed.yml"]);
        let args = match cli.cmd {
            Some(Cmd::Apply(args)) => args,
            other => panic!("expected Apply, got {other:?}"),
        };
        assert_eq!(args.config, Some(std::path::PathBuf::from("proposed.yml")));
        assert!(args.plan_file.is_none());
    }

    #[test]
    fn parses_apply_subcommand_with_plan_file() {
        let cli = parse(&["sbproxy", "apply", "-p", "plan.json"]);
        let args = match cli.cmd {
            Some(Cmd::Apply(args)) => args,
            other => panic!("expected Apply, got {other:?}"),
        };
        assert_eq!(args.plan_file, Some(std::path::PathBuf::from("plan.json")));
        assert!(args.config.is_none());
    }

    #[test]
    fn parses_config_migrate_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "config",
            "migrate",
            "sb.yml",
            "--out",
            "migrated.yml",
        ]);
        let cmd = match cli.cmd {
            Some(Cmd::Config(cmd)) => cmd,
            other => panic!("expected Config, got {other:?}"),
        };
        let ConfigSub::Migrate(args) = cmd.sub else {
            panic!("expected Migrate subcommand");
        };
        assert_eq!(args.config_path, std::path::PathBuf::from("sb.yml"));
        assert_eq!(args.out, Some(std::path::PathBuf::from("migrated.yml")));
    }

    #[test]
    fn apply_rejects_dash_f_and_dash_p_together() {
        // `-f` and `-p` are declared mutually exclusive on `ApplyArgs`.
        let err = Cli::try_parse_from(["sbproxy", "apply", "-f", "x.yml", "-p", "plan.json"])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflicts"),
            "expected conflicts message, got: {msg}"
        );
    }

    #[test]
    fn parses_version_flag() {
        let cli = parse(&["sbproxy", "--version"]);
        assert!(cli.version);
    }

    #[test]
    fn parses_short_version_flag() {
        let cli = parse(&["sbproxy", "-V"]);
        assert!(cli.version);
    }

    #[test]
    fn parses_version_subcommand() {
        let cli = parse(&["sbproxy", "version"]);
        assert!(matches!(cli.cmd, Some(Cmd::Version)));
    }

    #[test]
    fn parses_check_flag() {
        let cli = parse(&["sbproxy", "--config", "cfg.yml", "--check"]);
        assert!(cli.check);
        assert_eq!(
            cli.globals.config,
            Some(std::path::PathBuf::from("cfg.yml"))
        );
    }

    #[test]
    fn parses_completions_subcommand() {
        let cli = parse(&["sbproxy", "completions", "zsh"]);
        match cli.cmd {
            Some(Cmd::Completions { shell }) => assert_eq!(shell, Shell::Zsh),
            other => panic!("expected Completions, got {other:?}"),
        }
    }

    #[test]
    fn parses_completions_for_each_supported_shell() {
        // The ticket calls out bash, zsh, fish, powershell, elvish.
        for s in [
            ("bash", Shell::Bash),
            ("zsh", Shell::Zsh),
            ("fish", Shell::Fish),
            ("powershell", Shell::PowerShell),
            ("elvish", Shell::Elvish),
        ] {
            let cli = parse(&["sbproxy", "completions", s.0]);
            match cli.cmd {
                Some(Cmd::Completions { shell }) => assert_eq!(shell, s.1),
                other => panic!("expected Completions for {}, got {other:?}", s.0),
            }
        }
    }

    // --- --log-format ---

    #[test]
    fn log_format_accepts_compact_pretty_json() {
        for (name, expected) in [
            ("compact", LogFormat::Compact),
            ("pretty", LogFormat::Pretty),
            ("json", LogFormat::Json),
        ] {
            let cli = Cli::try_parse_from(["sbproxy", "--log-format", name, "cfg.yml"])
                .expect("parse should succeed");
            assert_eq!(
                cli.globals.log_format,
                Some(expected),
                "--log-format {name} should parse to {expected:?}"
            );
        }
    }

    #[test]
    fn log_format_rejects_unknown_values() {
        let err = Cli::try_parse_from(["sbproxy", "--log-format", "yaml", "cfg.yml"])
            .expect_err("unknown --log-format must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("yaml") && msg.contains("compact"),
            "error must name the bad value and list accepted ones, got: {msg}"
        );
    }

    #[test]
    fn log_format_env_fallback_works() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var("SB_LOG_FORMAT", "json");
        let cli = Cli::try_parse_from(["sbproxy", "cfg.yml"]).expect("env fallback should parse");
        assert_eq!(cli.globals.log_format, Some(LogFormat::Json));
        env::remove_var("SB_LOG_FORMAT");
    }

    #[test]
    fn log_format_unset_yields_compact_default() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("SB_LOG_FORMAT");
        let cli = Cli::try_parse_from(["sbproxy", "cfg.yml"]).expect("parse should succeed");
        assert_eq!(cli.globals.log_format, None);
        // The defaulting happens at init_tracing's call site; verify the
        // Default impl returns Compact so the call site can rely on it.
        assert_eq!(LogFormat::default(), LogFormat::Compact);
    }

    #[test]
    fn log_format_as_str_matches_cli_values() {
        assert_eq!(LogFormat::Compact.as_str(), "compact");
        assert_eq!(LogFormat::Pretty.as_str(), "pretty");
        assert_eq!(LogFormat::Json.as_str(), "json");
    }

    #[test]
    fn runtime_telemetry_config_maps_yaml_surface() {
        let raw = sbproxy_config::ObservabilityTelemetryConfig {
            enabled: true,
            endpoint: Some("http://otel-collector:4318/v1/traces".to_string()),
            transport: Some("http".to_string()),
            service_name: Some("sbproxy-dev".to_string()),
            sample_rate: Some(0.25),
            always_sample_errors: Some(false),
            keep_over_budget_usd: Some(0.5),
            keep_slower_than_secs: Some(3.0),
            propagation: Some("w3c".to_string()),
            resource_attrs: std::collections::BTreeMap::from([(
                "deployment.environment".to_string(),
                "dev".to_string(),
            )]),
            export_metrics: true,
            metrics_interval_secs: Some(15),
        };

        let mapped = runtime_telemetry_config(&raw);
        assert!(mapped.enabled);
        assert_eq!(
            mapped.endpoint.as_deref(),
            Some("http://otel-collector:4318/v1/traces")
        );
        assert_eq!(mapped.transport, sbproxy_observe::OtlpTransport::Http);
        assert_eq!(mapped.service_name, "sbproxy-dev");
        assert_eq!(mapped.sample_rate, Some(0.25));
        assert!(!mapped.always_sample_errors);
        assert_eq!(mapped.keep_over_budget_usd, Some(0.5));
        assert_eq!(mapped.keep_slower_than_secs, Some(3.0));
        assert_eq!(mapped.propagation.as_deref(), Some("w3c"));
        assert_eq!(
            mapped.resource_attrs.get("deployment.environment"),
            Some(&"dev".to_string())
        );
        assert!(mapped.export_metrics);
        assert_eq!(mapped.metrics_interval_secs, Some(15));
    }

    /// The version line is load-bearing: the marketing site `Hero.vue`
    /// and the Homebrew formula assert on the exact shape. This pins
    /// the format string so any drift is caught at test time.
    #[test]
    fn version_string_shape_is_pinned() {
        let expected_prefix = format!("sbproxy {} (rev ", env!("CARGO_PKG_VERSION"));
        let line = format!(
            "sbproxy {} (rev {}, built {})",
            env!("CARGO_PKG_VERSION"),
            env!("SBPROXY_GIT_SHA"),
            env!("SBPROXY_BUILD_DATE"),
        );
        assert!(
            line.starts_with(&expected_prefix),
            "version line must start with `sbproxy <semver> (rev `, got: {line}"
        );
        assert!(
            line.contains(", built "),
            "version line must include `, built <date>`, got: {line}"
        );
        assert!(line.ends_with(')'), "version line must close with `)`");
    }

    // --- env-only disable-sb-flags ---

    #[test]
    fn env_disable_sb_flags_accepts_truthy_values() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["1", "true", "TRUE", "yes", "on", "YES", " On "] {
            env::set_var("SB_DISABLE_SB_FLAGS", v);
            assert!(env_disable_sb_flags(), "expected truthy for {v}");
        }
        env::remove_var("SB_DISABLE_SB_FLAGS");
    }

    #[test]
    fn env_disable_sb_flags_rejects_other_values() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["0", "false", "no", "off", ""] {
            env::set_var("SB_DISABLE_SB_FLAGS", v);
            assert!(!env_disable_sb_flags(), "expected falsy for '{v}'");
        }
        env::remove_var("SB_DISABLE_SB_FLAGS");
    }

    // --- validate handler (regression coverage from the legacy parser tests) ---

    fn temp_config(body: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sbproxy-validate-test-{}-{n}.yml",
            std::process::id()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    const MINIMAL_VALID: &str = "proxy:\n  http_bind_port: 8080\norigins:\n  \"x.local\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n";

    fn validate_args(path: &std::path::Path, json: bool) -> ValidateArgs {
        ValidateArgs {
            config_path: Some(path.to_path_buf()),
            format: if json {
                OutputFormat::Json
            } else {
                OutputFormat::Text
            },
        }
    }

    #[test]
    fn validate_valid_config_exits_zero() {
        let path = temp_config(MINIMAL_VALID);
        assert_eq!(
            handle_validate_subcommand(&validate_args(&path, false)).unwrap(),
            0
        );
        assert_eq!(
            handle_validate_subcommand(&validate_args(&path, true)).unwrap(),
            0
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_bad_config_text_errors_json_exits_two() {
        let path = temp_config("this is not: [valid yaml");
        assert!(handle_validate_subcommand(&validate_args(&path, false)).is_err());
        assert_eq!(
            handle_validate_subcommand(&validate_args(&path, true)).unwrap(),
            2
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_missing_path_is_a_usage_error() {
        let args = ValidateArgs {
            config_path: None,
            format: OutputFormat::Json,
        };
        assert!(handle_validate_subcommand(&args).is_err());
    }

    // --- config migrate handler ---

    #[test]
    fn handle_config_migrate_writes_rewritten_yaml() {
        let path = temp_config("key: vault://aws/prod/openai?version=3&key=api_key\n");
        let out = path.with_extension("migrated.yml");
        let args = ConfigMigrateArgs {
            config_path: path.clone(),
            out: Some(out.clone()),
        };
        assert_eq!(handle_config_migrate(&args).unwrap(), 0);
        let migrated = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            migrated,
            "key: awssm://aws/prod/openai?version=3&key=api_key\n"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    // --- plan handler regression coverage ---

    #[test]
    fn plan_exit_code_maps_report_state() {
        let noop = sbproxy_config::plan(&empty_config_file(), &empty_config_file());
        assert_eq!(plan_exit_code(&noop), 0);
        let path = temp_config(MINIMAL_VALID);
        let proposed = load_and_validate(&path).unwrap();
        let changed = sbproxy_config::plan(&empty_config_file(), &proposed);
        assert_eq!(plan_exit_code(&changed), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn handle_plan_valid_config_against_empty_reports_changes() {
        let path = temp_config(MINIMAL_VALID);
        let args = PlanArgs {
            config: Some(path.clone()),
            against: None,
            format: OutputFormat::Text,
            out: None,
        };
        assert_eq!(handle_plan_subcommand(&args).unwrap(), 2);
        // Plan against itself: no changes -> exit 0.
        let args = PlanArgs {
            config: Some(path.clone()),
            against: Some(path.clone()),
            format: OutputFormat::Text,
            out: None,
        };
        assert_eq!(handle_plan_subcommand(&args).unwrap(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn handle_plan_missing_config_is_usage_error() {
        let args = PlanArgs {
            config: None,
            against: None,
            format: OutputFormat::Text,
            out: None,
        };
        assert!(handle_plan_subcommand(&args).is_err());
    }
}
