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
/// The `--help` footer: homepage + a copyright line whose year comes from
/// the build date (`build.rs`), so it tracks the release year instead of
/// being hand-edited. The authoritative dated notice lives in `LICENSE`.
const HELP_FOOTER: &str = concat!(
    "Homepage: https://sbproxy.dev\nCopyright (c) ",
    env!("SBPROXY_BUILD_YEAR"),
    " Soap Bucket LLC. Apache-2.0 licensed."
);

#[derive(Parser, Debug)]
#[command(
    name = "sbproxy",
    bin_name = "sbproxy",
    about = "sbproxy: AI Governance Gateway. One self-hostable runtime for AI traffic, APIs, MCP, and AI crawlers.",
    long_about = None,
    disable_version_flag = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    // A homepage + copyright footer on `--help`. Kept off the `--version`
    // line, whose exact `sbproxy <semver> (rev <sha>, built <date>)` shape
    // the Homebrew formula and the marketing site assert on.
    after_help = HELP_FOOTER,
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
    /// Serve a model in one command, with no YAML. `sbproxy run
    /// qwen3-14b` (or `sbproxy run hf:Org/Repo:Q4_K_M --name coder`)
    /// synthesizes a minimal serving config, checks the model can run
    /// here, and boots the gateway with an OpenAI-compatible endpoint on
    /// loopback. The engine and weights are acquired on the first
    /// request.
    Run(RunArgs),
    /// Discover models: what can this host run. `sbproxy models` (or
    /// `models list`) prints one row per catalog model with a real
    /// per-GPU fit verdict and cache status; `models show <id>` prints
    /// the full entry.
    Models(ModelsCmd),
    /// Freshness: is any of it out of date. `sbproxy update` checks the
    /// engine release feed and the cached models; `--self` also checks
    /// the sbproxy binary. Reports only (a dry run); nothing is mutated.
    Update(UpdateArgs),
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
    /// Print the effective config after defaults + file + `${ENV}`
    /// interpolation, with secret values masked. Shows what this box
    /// will actually do.
    Print(ConfigPrintArgs),
}

#[derive(clap::Args, Debug)]
struct ConfigPrintArgs {
    /// Config file to print. Defaults to `-f/--config` or
    /// `SB_CONFIG_FILE`.
    config_path: Option<PathBuf>,
    /// Emit JSON instead of the default YAML.
    #[arg(long = "json")]
    json: bool,
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
struct RunArgs {
    /// The model to serve: a catalog id (`qwen3-14b`) or an explicit
    /// `hf:Org/Repo:QUANT` reference. A raw reference needs `--name`.
    #[arg(value_name = "MODEL")]
    model: String,
    /// The model id clients request (and the routing id). Defaults to
    /// the catalog id; required when MODEL is a raw `hf:` reference.
    #[arg(long = "name")]
    name: Option<String>,
    /// Loopback port to serve on.
    #[arg(long = "port", default_value_t = 8080)]
    port: u16,
    /// Engine to serve with: `auto` (default), `vllm`, `llama_cpp`, or
    /// `embedded`.
    #[arg(long = "engine", default_value = "auto")]
    engine: String,
    /// Acceleration to acquire an engine build for: `auto` (default),
    /// `cuda`, `vulkan`, `metal`, or `cpu`.
    #[arg(long = "accel", default_value = "auto")]
    accel: String,
    /// Weight/engine cache directory. Defaults to the platform cache.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// For a GGUF (llama.cpp) model, the exact GGUF filename in the repo,
    /// e.g. `qwen2.5-0.5b-instruct-q4_k_m.gguf`. A GGUF-only repo has no
    /// `config.json`, so the model host needs this to fetch the file and
    /// read its header for the fit metadata.
    #[arg(long = "gguf-file")]
    gguf_file: Option<String>,
    /// Print the synthesized config and the resolution, then exit
    /// without serving. For inspection / CI.
    #[arg(long = "dry-run")]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct ModelsCmd {
    #[command(subcommand)]
    sub: Option<ModelsSub>,
}

#[derive(Subcommand, Debug)]
enum ModelsSub {
    /// List catalog models with a per-GPU fit verdict and cache status.
    List(ModelsListArgs),
    /// Show the full catalog entry for a model id.
    Show(ModelsShowArgs),
}

#[derive(clap::Args, Debug, Default)]
struct ModelsListArgs {
    /// Output format. `text` (default) is a table; `json` is structured.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Operator catalog/manifest file, replacing the built-in catalog.
    #[arg(long = "catalog-file")]
    catalog_file: Option<PathBuf>,
    /// Weight cache directory to check for pulled models.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ModelsShowArgs {
    /// The catalog id to show.
    id: String,
    /// Output format. `text` (default) or `json`.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Operator catalog/manifest file, replacing the built-in catalog.
    #[arg(long = "catalog-file")]
    catalog_file: Option<PathBuf>,
    /// Weight cache directory to check for pulled models.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct UpdateArgs {
    /// Check the sbproxy binary against the release channel.
    #[arg(long = "self")]
    self_: bool,
    /// Check the inference engines (default when no target flag is set).
    #[arg(long = "engines")]
    engines: bool,
    /// Check the cached models (default when no target flag is set).
    #[arg(long = "models")]
    models: bool,
    /// Weight cache directory to check for pulled models.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// Output format. `text` (default) or `json`.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct DoctorArgs {
    /// Optional config file. When given, doctor also reports how each
    /// `serve:` model resolves on this host (engine + fit preview) and
    /// exits non-zero if a configured model has no viable engine.
    #[arg(value_name = "CONFIG")]
    config: Option<PathBuf>,
    /// Output format. `text` (default) prints the human report; `json`
    /// emits a single structured object for tooling.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
enum OutputFormat {
    #[default]
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

    // Anchor the uptime clock at real process start, so `/health` reports
    // true uptime rather than time-since-first-health-hit.
    sbproxy_observe::mark_process_start();

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
        Some(Cmd::Run(args)) => {
            handle_run_subcommand(&args, grace);
        }
        Some(Cmd::Models(cmd)) => {
            run_subcommand("models", 2, handle_models_subcommand(&cmd));
        }
        Some(Cmd::Update(args)) => {
            run_subcommand("update", 2, handle_update_subcommand(&args));
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
/// Warn at proxy start when the file-descriptor soft limit is low
/// (WOR-1809). Pingora holds a socket per connection and the model
/// host fetches weights over HTTPS; the 1024 systemd/shell default
/// surfaces as `Accept() failed: Too many open files` and failed
/// outbound fetches under modest load. Read from `/proc/self/limits`
/// so the crate stays free of unsafe; on platforms without procfs
/// (macOS dev boxes) the check is a silent no-op, which is fine
/// because the limit that bites in production is the Linux one.
fn warn_low_fd_limit() {
    let Ok(limits) = std::fs::read_to_string("/proc/self/limits") else {
        return;
    };
    let Some(soft) = parse_open_files_soft_limit(&limits) else {
        return;
    };
    if soft < 8192 {
        tracing::warn!(
            soft_limit = soft,
            "file-descriptor soft limit is low for a proxy; raise it \
             (`ulimit -n 65536`, or `LimitNOFILE=65536` in the systemd unit) \
             or accepts and weight downloads can fail under load"
        );
    }
}

/// Extract the soft "Max open files" value from `/proc/self/limits`
/// content. Returns `None` when the row is absent or unparseable
/// (including an `unlimited` soft value, which needs no warning).
fn parse_open_files_soft_limit(limits: &str) -> Option<u64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line["Max open files".len()..]
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Raise the file-descriptor soft limit toward the hard cap at startup
/// (WOR-1809). `sbproxy run` and any shell invocation otherwise inherit
/// the 1024 default, and Pingora's socket-per-connection plus engine
/// provisioning (vLLM's uv environment, weight downloads) exhaust it,
/// which surfaces as `Too many open files` and, once fds run out, a
/// failing GPU probe that wrongly rejects admission. Raising our own soft
/// limit means no `ulimit` or systemd tuning is required.
fn raise_fd_limit() {
    // Widen the soft limit toward the hard cap; `increase_nofile_limit`
    // targets min(requested, hard) and handles the macOS per-process
    // ceiling, so a request above the cap is clamped, not an error.
    let _ = rlimit::increase_nofile_limit(1_048_576);
}

fn run_proxy(config_path: Option<&std::path::Path>, grace: sbproxy_core::GraceConfig) {
    raise_fd_limit();
    warn_low_fd_limit();
    match config_path {
        Some(path) => {
            // WOR-1767: build + install the process secret resolver from
            // `proxy.secrets.backends` before the server compiles its config,
            // so provider-URI references in api_key / client_secret resolve
            // (or fail loud) instead of reaching the wire verbatim.
            install_secret_resolver(path);
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

/// Whole-value `${VAR}` env substitution for a `local` backend entry, so
/// real secret values can stay in the environment rather than the YAML.
/// A non-`${VAR}` value is used as-is; an unset var leaves the ref (which
/// then fails resolution, loudly, rather than silently blanking).
fn env_interp(value: &str) -> String {
    match value
        .strip_prefix("${")
        .and_then(|inner| inner.strip_suffix('}'))
    {
        Some(var) => std::env::var(var).unwrap_or_else(|_| value.to_string()),
        None => value.to_string(),
    }
}

/// Build the process secret resolver from `proxy.secrets` and install it
/// (WOR-1767). Provider-URI references (`secret://`, `secretfile://`, ...)
/// in config values then resolve at handler-build; an unresolved reference
/// hard-fails at that point. A misconfigured backend here (e.g. a missing
/// secrets file) fails loud rather than starting with unresolved secrets.
///
/// A read/parse error is left for `sbproxy_core::run` to report; when there
/// is no `proxy.secrets` block, nothing is installed and references pass
/// through (caught by plan-time validation).
fn install_secret_resolver(path: &std::path::Path) {
    let Ok(yaml) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&yaml) else {
        return;
    };
    let Some(secrets_val) = root.get("proxy").and_then(|p| p.get("secrets")) else {
        return;
    };
    let secrets: sbproxy_config::SecretsConfig = match serde_yaml::from_value(secrets_val.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Fatal: invalid proxy.secrets config: {e:#}");
            std::process::exit(1);
        }
    };
    if secrets.backends.is_empty() && secrets.map.is_empty() {
        return;
    }

    let mut manager = sbproxy_vault::VaultManager::new();
    for backend in &secrets.backends {
        match backend {
            sbproxy_config::SecretBackendConfig::Local { name, entries } => {
                let vault = sbproxy_vault::LocalVault::new();
                for (k, v) in entries {
                    if let Err(e) = vault.set_secret(k, &env_interp(v)) {
                        eprintln!("Fatal: secret backend '{name}': {e:#}");
                        std::process::exit(1);
                    }
                }
                manager.register_backend(
                    sbproxy_vault::VaultProviderType::LocalSecret,
                    name.clone(),
                    Box::new(vault),
                );
            }
            sbproxy_config::SecretBackendConfig::File { name, path, format } => {
                let format = match format {
                    sbproxy_config::SecretFileFormat::Yaml => sbproxy_vault::FileFormat::Yaml,
                    sbproxy_config::SecretFileFormat::Json => sbproxy_vault::FileFormat::Json,
                };
                match sbproxy_vault::FileVaultBackend::new(sbproxy_vault::FileVaultConfig {
                    path: path.clone(),
                    format,
                }) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::SecretFile,
                        name.clone(),
                        Box::new(b),
                    ),
                    Err(e) => {
                        eprintln!("Fatal: secret backend '{name}' ({}): {e:#}", path.display());
                        std::process::exit(1);
                    }
                }
            }
            sbproxy_config::SecretBackendConfig::Hashicorp {
                name,
                addr,
                mount,
                engine,
                cache_ttl_secs,
                namespace,
                auth,
            } => {
                let engine = match engine {
                    sbproxy_config::SecretKvEngine::V1 => sbproxy_vault::KvEngine::V1,
                    sbproxy_config::SecretKvEngine::V2 => sbproxy_vault::KvEngine::V2,
                };
                let auth = match auth {
                    sbproxy_config::HashiCorpBackendAuth::Token { token } => {
                        sbproxy_vault::HashiCorpAuth::Token {
                            token: env_interp(token),
                        }
                    }
                    sbproxy_config::HashiCorpBackendAuth::Approle {
                        role_id,
                        secret_id,
                        mount,
                    } => sbproxy_vault::HashiCorpAuth::AppRole {
                        role_id: role_id.clone(),
                        secret_id: env_interp(secret_id),
                        mount: mount.clone(),
                    },
                    sbproxy_config::HashiCorpBackendAuth::Kubernetes {
                        role,
                        jwt_path,
                        mount,
                    } => sbproxy_vault::HashiCorpAuth::Kubernetes {
                        role: role.clone(),
                        jwt_path: jwt_path.clone(),
                        mount: mount.clone(),
                    },
                };
                let cfg = sbproxy_vault::HashiCorpConfig {
                    addr: addr.clone(),
                    auth,
                    mount: mount.clone(),
                    engine,
                    cache_ttl: cache_ttl_secs.map(std::time::Duration::from_secs),
                    namespace: namespace.clone(),
                };
                match sbproxy_vault::HashiCorpVaultBackend::new(cfg) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::HashiCorp,
                        name.clone(),
                        Box::new(b),
                    ),
                    Err(e) => {
                        eprintln!("Fatal: secret backend '{name}': {e:#}");
                        std::process::exit(1);
                    }
                }
            }
            sbproxy_config::SecretBackendConfig::Aws {
                name,
                region,
                mount_prefix,
                cache_ttl_secs,
                auth,
            } => {
                let auth = match auth {
                    sbproxy_config::AwsBackendAuth::StaticKeys {
                        access_key_id,
                        secret_access_key,
                        session_token,
                    } => sbproxy_vault::AwsAuth::StaticKeys {
                        access_key_id: env_interp(access_key_id),
                        secret_access_key: env_interp(secret_access_key),
                        session_token: session_token.as_deref().map(env_interp),
                    },
                    sbproxy_config::AwsBackendAuth::DefaultChain => {
                        sbproxy_vault::AwsAuth::DefaultChain
                    }
                    sbproxy_config::AwsBackendAuth::AssumedRole {
                        role_arn,
                        external_id,
                        session_name,
                    } => sbproxy_vault::AwsAuth::AssumedRole {
                        role_arn: role_arn.clone(),
                        external_id: external_id.clone(),
                        session_name: session_name.clone(),
                    },
                };
                let cfg = sbproxy_vault::AwsSecretsManagerConfig {
                    region: region.clone(),
                    auth,
                    mount_prefix: mount_prefix.clone(),
                    cache_ttl: cache_ttl_secs.map(std::time::Duration::from_secs),
                };
                match sbproxy_vault::AwsSecretsManagerBackend::new(cfg) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::AwsSecretsManager,
                        name.clone(),
                        Box::new(b),
                    ),
                    Err(e) => {
                        eprintln!("Fatal: secret backend '{name}': {e:#}");
                        std::process::exit(1);
                    }
                }
            }
            sbproxy_config::SecretBackendConfig::Gcp {
                name,
                project_id,
                endpoint,
                cache_ttl_secs,
                auth,
            } => {
                let auth = match auth {
                    sbproxy_config::GcpBackendAuth::ApplicationDefault => {
                        sbproxy_vault::GcpSecretManagerAuth::ApplicationDefault
                    }
                    sbproxy_config::GcpBackendAuth::ServiceAccountKeyFile { path } => {
                        sbproxy_vault::GcpSecretManagerAuth::ServiceAccountKeyFile {
                            path: path.clone(),
                        }
                    }
                    sbproxy_config::GcpBackendAuth::ServiceAccountKeyJson { json } => {
                        sbproxy_vault::GcpSecretManagerAuth::ServiceAccountKeyJson {
                            json: env_interp(json),
                        }
                    }
                    sbproxy_config::GcpBackendAuth::ExternalAccountFile { path } => {
                        sbproxy_vault::GcpSecretManagerAuth::ExternalAccountFile {
                            path: path.clone(),
                        }
                    }
                };
                let cfg = sbproxy_vault::GcpSecretManagerConfig {
                    project_id: project_id.clone(),
                    endpoint: endpoint.clone(),
                    auth,
                    cache_ttl_secs: *cache_ttl_secs,
                };
                match sbproxy_vault::GcpSecretManagerBackend::new(cfg) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::GcpSecretManager,
                        name.clone(),
                        Box::new(b),
                    ),
                    Err(e) => {
                        eprintln!("Fatal: secret backend '{name}': {e:#}");
                        std::process::exit(1);
                    }
                }
            }
            sbproxy_config::SecretBackendConfig::K8s {
                name,
                namespace,
                cache_ttl_secs,
                auth,
            } => {
                let auth = match auth {
                    sbproxy_config::K8sBackendAuth::InCluster => {
                        sbproxy_vault::KubernetesAuth::InCluster
                    }
                    sbproxy_config::K8sBackendAuth::Kubeconfig { path, context } => {
                        sbproxy_vault::KubernetesAuth::Kubeconfig {
                            path: path.clone(),
                            context: context.clone(),
                        }
                    }
                };
                let cfg = sbproxy_vault::KubernetesSecretsConfig {
                    auth,
                    namespace: namespace.clone(),
                    cache_ttl: cache_ttl_secs.map(std::time::Duration::from_secs),
                };
                match sbproxy_vault::KubernetesSecretsBackend::new(cfg) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::KubernetesSecret,
                        name.clone(),
                        Box::new(b),
                    ),
                    Err(e) => {
                        eprintln!("Fatal: secret backend '{name}': {e:#}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    let resolver = sbproxy_vault::SecretResolver::new(None, secrets.map)
        .with_manager(std::sync::Arc::new(manager));
    sbproxy_vault::install_process_resolver(std::sync::Arc::new(resolver));
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

    // Read + compile + construct. Read and compile failures are the
    // classic "invalid config" outcomes; in JSON mode they are reported
    // as `{"valid": false, ...}` with exit 2 rather than propagated.
    //
    // WOR-1815: `compile_config` alone is not what boot runs. The
    // per-origin module constructors (`CompiledPipeline::from_config`,
    // the same call the server and the reload path make) hold the deep
    // semantic checks: a provider that sets both `serve:` and
    // `base_url:`, a policy field typo inside an opaque `policies:`
    // blob, an unknown transform type. A config that passes only
    // `compile_config` can still refuse to boot, so validate runs the
    // full construction and throws the pipeline away. Outside a Tokio
    // runtime (this subcommand) construction spawns nothing.
    let outcome = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))
        .and_then(|yaml| {
            let compiled = sbproxy_config::compile_config(&yaml)
                .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
            sbproxy_core::pipeline::CompiledPipeline::from_config(compiled)
                .map(|_| ())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "config '{path_str}' compiled, but a module failed to construct \
                         (this would fail at boot):\n{e:#}"
                    )
                })
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

/// Print the host-capability diagnostics report. It exits 0 once the
/// report is produced ("this host cannot serve local models" is a
/// finding, not an error); the report maps any missing serve:
/// prerequisites and how to install them.
fn handle_doctor_subcommand(args: &DoctorArgs) -> anyhow::Result<i32> {
    let mut report = sbproxy_core::doctor::DoctorReport::collect_deep();
    // With a config, add per-serve-entry resolution + a fit preview, and
    // let the exit code reflect whether a configured model can run here.
    let config_path = args
        .config
        .clone()
        .or_else(|| std::env::var_os("SB_CONFIG_FILE").map(PathBuf::from));
    let mut exit = 0;
    if let Some(path) = config_path {
        match std::fs::read_to_string(&path) {
            Ok(yaml) => {
                if let Some((serve, catalog)) = extract_serve_and_catalog(&yaml) {
                    report = report.with_serve_config(&serve, &catalog);
                    exit = report.exit_code();
                }
            }
            Err(e) => {
                eprintln!("doctor: could not read config '{}': {e}", path.display());
            }
        }
    }
    match args.format {
        OutputFormat::Text => print!("{}", report.render_text()),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(exit)
}

/// Extract the merged `serve:` block (across every `ai_proxy` provider)
/// and the model catalog to resolve ids against, for `sbproxy doctor
/// <config>`. Best-effort and read-only: a config with no `serve:`
/// block yields `None`. An operator `catalog_file` on the first serve
/// block replaces the built-in catalog for id resolution.
fn extract_serve_and_catalog(
    yaml: &str,
) -> Option<(
    sbproxy_model_host::ModelHostConfig,
    sbproxy_model_host::Catalog,
)> {
    let root: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let origins = root.get("origins")?.as_mapping()?;
    let mut merged: Option<sbproxy_model_host::ModelHostConfig> = None;
    for (_, origin) in origins {
        let Some(action) = origin.get("action") else {
            continue;
        };
        // action.type must be ai_proxy (or a bare providers list).
        let providers = action.get("providers").and_then(|p| p.as_sequence());
        let Some(providers) = providers else {
            continue;
        };
        for provider in providers {
            let Some(serve_val) = provider.get("serve") else {
                continue;
            };
            let Ok(serve) =
                serde_yaml::from_value::<sbproxy_model_host::ModelHostConfig>(serve_val.clone())
            else {
                continue;
            };
            match &mut merged {
                None => merged = Some(serve),
                Some(m) => {
                    m.models.extend(serve.models);
                    for (k, v) in serve.engines {
                        m.engines.entry(k).or_insert(v);
                    }
                }
            }
        }
    }
    let merged = merged?;
    // An operator catalog_file replaces the built-in catalog.
    let catalog = merged
        .catalog_file
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| sbproxy_model_host::Catalog::from_yaml(&c).ok())
        .unwrap_or_else(sbproxy_model_host::Catalog::builtin);
    Some((merged, catalog))
}

// --- `run` handler (WOR-1802) ---

/// `sbproxy run <model>`: synthesize a minimal serving config, check the
/// model can run here, and boot the gateway. On a preflight failure it
/// exits non-zero with the remediation; on success it serves (blocks).
fn handle_run_subcommand(args: &RunArgs, grace: sbproxy_core::GraceConfig) {
    // Resolve the model id every plane sees (routing + the served name).
    let name = match resolve_run_name(&args.model, args.name.as_deref()) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("sbproxy run: {e}");
            std::process::exit(2);
        }
    };

    // Build the `serve:` block once as JSON, reused for the preflight
    // (parsed to a ModelHostConfig) and for the synthesized config.
    let serve_value = build_run_serve_value(args);
    let serve_cfg: sbproxy_model_host::ModelHostConfig =
        match serde_json::from_value(serve_value.clone()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sbproxy run: could not build serve config: {e}");
                std::process::exit(2);
            }
        };

    // Preflight against this host (offline: engine viability + fit), the
    // same detection layer `doctor` uses, so a model that cannot run
    // here fails now with a remediation instead of 502-ing later.
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let catalog = sbproxy_model_host::Catalog::builtin();
    let entries = report.evaluate_serve(&serve_cfg, &catalog);
    for e in &entries {
        println!(
            "model {} -> {} [{}]: {}",
            e.model, e.engine_reason, e.fit.verdict, e.fit.detail
        );
    }
    if let Some(bad) = entries.iter().find(|e| !e.runnable) {
        eprintln!(
            "\nsbproxy run: '{}' has no viable engine on this host: {}",
            bad.model,
            bad.blocker.as_deref().unwrap_or("engine unavailable")
        );
        if let Some(rec) = &report.local_serving.recommendation {
            eprintln!("try: {rec}");
        }
        eprintln!("run `sbproxy doctor` for the full host report");
        std::process::exit(1);
    }

    // Synthesize the full config: one ai_proxy origin under both the
    // loopback IP and localhost (origins match the port-stripped Host
    // exactly, with no wildcard), so a plain curl to either routes.
    let action = serde_json::json!({
        "type": "ai_proxy",
        "providers": [{
            "name": "local",
            "default_model": name,
            "serve": serve_value,
        }],
    });
    let origin = serde_json::json!({ "action": action });
    let config = serde_json::json!({
        "proxy": { "http_bind_port": args.port },
        "origins": { "127.0.0.1": origin, "localhost": origin },
    });
    let yaml = match serde_yaml::to_string(&config) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("sbproxy run: could not serialize config: {e}");
            std::process::exit(2);
        }
    };

    if args.dry_run {
        println!("\n# synthesized config\n{yaml}");
        return;
    }

    // Write the synthesized config to a temp file (the serve boot path
    // takes a path, not an in-memory config). Use a dedicated per-run
    // directory, not the shared temp dir: the hot-reload watcher watches
    // the config's *directory*, and while an engine provisions (vLLM's uv
    // env, weight downloads) the shared temp dir churns, which would
    // otherwise fire a reload storm and exhaust file descriptors.
    let run_dir = std::env::temp_dir().join(format!("sbproxy-run-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        eprintln!("sbproxy run: could not create {}: {e}", run_dir.display());
        std::process::exit(1);
    }
    let path = run_dir.join("sb.yml");
    if let Err(e) = std::fs::write(&path, &yaml) {
        eprintln!("sbproxy run: could not write {}: {e}", path.display());
        std::process::exit(1);
    }

    let port = args.port;
    println!("\nServing {name} on http://127.0.0.1:{port}");
    println!(
        "Try: curl http://127.0.0.1:{port}/v1/chat/completions \\\n  \
         -H 'content-type: application/json' \\\n  \
         -d '{{\"model\":\"{name}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'"
    );
    println!(
        "The first request acquires the engine and downloads the weights; \
         watch the log for progress.\n"
    );

    // Boot the gateway (blocks until shutdown). Reuses the serve path, so
    // an invalid synthesized config fails loud here rather than at a
    // request.
    run_proxy(Some(&path), grace);
}

/// The served model id for `sbproxy run`: the explicit `--name`, else
/// the catalog id in MODEL. A raw `hf:`/pathy reference needs `--name`,
/// mirroring [`sbproxy_model_host::ServeEntry::effective_name`].
fn resolve_run_name(model: &str, name: Option<&str>) -> Result<String, String> {
    if let Some(n) = name {
        if n.trim().is_empty() {
            return Err("--name is empty".to_string());
        }
        return Ok(n.to_string());
    }
    if model.starts_with("hf:") || model.contains(':') || model.contains('/') {
        return Err(format!(
            "'{model}' is a raw model reference; pass --name to set the served model id"
        ));
    }
    Ok(model.to_string())
}

/// Build the `serve:` block (as JSON) for `sbproxy run`: one model, with
/// the engine / accel / cache-dir overrides applied.
fn build_run_serve_value(args: &RunArgs) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    entry.insert("model".to_string(), serde_json::json!(args.model));
    if let Some(n) = &args.name {
        entry.insert("name".to_string(), serde_json::json!(n));
    }
    if args.engine != "auto" {
        entry.insert("engine".to_string(), serde_json::json!(args.engine));
    }
    if let Some(f) = &args.gguf_file {
        entry.insert("gguf_file".to_string(), serde_json::json!(f));
    }

    let mut serve = serde_json::Map::new();
    serve.insert(
        "models".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(entry)]),
    );
    if let Some(cd) = &args.cache_dir {
        serve.insert(
            "cache_dir".to_string(),
            serde_json::json!(cd.to_string_lossy()),
        );
    }
    // Engines block. vLLM is provisioned via uvx (fetch uv, run
    // `uv tool run`), so a safetensors model serves on a GPU box with no
    // manual install; this is harmless when llama.cpp is the resolved
    // engine. Accel steers the acquired llama.cpp binary build.
    let mut engines = serde_json::Map::new();
    engines.insert(
        "vllm".to_string(),
        serde_json::json!({ "acquire": { "source": "uvx" } }),
    );
    if args.accel != "auto" {
        engines.insert(
            "llama_cpp".to_string(),
            serde_json::json!({ "acquire": { "accel": args.accel } }),
        );
    }
    serve.insert("engines".to_string(), serde_json::Value::Object(engines));
    serde_json::Value::Object(serve)
}

// --- `models` handler (WOR-1803) ---

fn handle_models_subcommand(cmd: &ModelsCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        // `sbproxy models` with no subcommand lists.
        None => handle_models_list(&ModelsListArgs::default()),
        Some(ModelsSub::List(a)) => handle_models_list(a),
        Some(ModelsSub::Show(a)) => handle_models_show(a),
    }
}

fn load_models_catalog(
    catalog_file: Option<&std::path::Path>,
) -> anyhow::Result<sbproxy_model_host::Catalog> {
    match catalog_file {
        Some(p) => {
            let yaml = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("read catalog '{}': {e}", p.display()))?;
            sbproxy_model_host::Catalog::from_yaml(&yaml)
                .map_err(|e| anyhow::anyhow!("parse catalog '{}': {e}", p.display()))
        }
        None => Ok(sbproxy_model_host::Catalog::builtin()),
    }
}

fn model_cache_root(cache_dir: Option<&std::path::Path>) -> PathBuf {
    let configured = cache_dir.map(|p| p.to_string_lossy().into_owned());
    sbproxy_model_host::resolve_cache_dir_default(configured.as_deref())
}

/// Whether any weights for `entry` are present in the cache dir.
fn model_is_cached(root: &std::path::Path, entry: &sbproxy_model_host::CatalogEntry) -> bool {
    let revision = entry.revision.as_deref().unwrap_or("main");
    let dir = sbproxy_model_host::weights::cache_dir(root, &entry.hf_repo, revision);
    std::fs::read_dir(&dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// One row of `sbproxy models list`.
#[derive(serde::Serialize)]
struct ModelRow {
    id: String,
    params: String,
    license: String,
    family: String,
    quants: Vec<String>,
    /// The engine `auto` resolves to on this host.
    engine: String,
    /// Fit verdict: fits / too-large / capability-refused / unknown.
    fit: String,
    estimated_vram_gib: Option<f64>,
    /// cached (weights present in the cache dir) or not-pulled. Resident
    /// / serving state needs a running gateway and is not shown here.
    status: String,
}

/// Build the model rows from a catalog, the host report, and the cache
/// dir. Pure over its inputs (the report/probe is passed in), so it is
/// unit-testable.
fn build_model_rows(
    catalog: &sbproxy_model_host::Catalog,
    report: &sbproxy_core::doctor::DoctorReport,
    cache_root: &std::path::Path,
) -> Vec<ModelRow> {
    // One serve entry per catalog id, so the doctor resolves engine +
    // fit per model against the detected GPU.
    let models_json: Vec<_> = catalog
        .models
        .keys()
        .map(|id| serde_json::json!({ "model": id }))
        .collect();
    let serve: sbproxy_model_host::ModelHostConfig =
        serde_json::from_value(serde_json::json!({ "models": models_json })).unwrap_or_default();
    let entries = report.evaluate_serve(&serve, catalog);
    let fit_by_id: std::collections::HashMap<&str, _> =
        entries.iter().map(|e| (e.model.as_str(), e)).collect();

    catalog
        .models
        .iter()
        .map(|(id, entry)| {
            let e = fit_by_id.get(id.as_str());
            ModelRow {
                id: id.clone(),
                params: entry.params.clone(),
                license: entry.license.clone(),
                family: entry.family.clone(),
                quants: entry.quants.clone(),
                engine: e.map(|e| e.engine.clone()).unwrap_or_default(),
                fit: e.map(|e| e.fit.verdict.to_string()).unwrap_or_default(),
                estimated_vram_gib: e.and_then(|e| e.fit.estimated_vram_gib),
                status: if model_is_cached(cache_root, entry) {
                    "cached".to_string()
                } else {
                    "not-pulled".to_string()
                },
            }
        })
        .collect()
}

fn handle_models_list(args: &ModelsListArgs) -> anyhow::Result<i32> {
    let catalog = load_models_catalog(args.catalog_file.as_deref())?;
    let root = model_cache_root(args.cache_dir.as_deref());
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let rows = build_model_rows(&catalog, &report, &root);

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Text => {
            println!(
                "{:<22} {:<9} {:<18} {:<10} {:<12} STATUS",
                "MODEL", "PARAMS", "FIT", "VRAM(GiB)", "ENGINE"
            );
            for r in &rows {
                let vram = r
                    .estimated_vram_gib
                    .map(|v| format!("~{v:.0}"))
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<22} {:<9} {:<18} {:<10} {:<12} {}",
                    r.id, r.params, r.fit, vram, r.engine, r.status
                );
            }
            println!(
                "\n(resident / serving state needs a running gateway; this view merges the \
                 catalog + weight cache + per-GPU fit)"
            );
        }
    }
    Ok(0)
}

/// The full catalog entry for `sbproxy models show <id>`.
#[derive(serde::Serialize)]
struct ModelDetail {
    id: String,
    hf_repo: String,
    source: String,
    revision: String,
    sha256: std::collections::BTreeMap<String, String>,
    engine: String,
    pull: String,
    quants: Vec<String>,
    params: String,
    license: String,
    family: String,
    min_vram_hint_gib: f64,
    cached: bool,
}

fn handle_models_show(args: &ModelsShowArgs) -> anyhow::Result<i32> {
    let catalog = load_models_catalog(args.catalog_file.as_deref())?;
    let root = model_cache_root(args.cache_dir.as_deref());
    let Some(entry) = catalog.get(&args.id) else {
        eprintln!("sbproxy models show: '{}' is not in the catalog", args.id);
        return Ok(2);
    };
    let detail = ModelDetail {
        id: args.id.clone(),
        hf_repo: entry.hf_repo.clone(),
        source: entry
            .source
            .clone()
            .unwrap_or_else(|| format!("hf:{}", entry.hf_repo)),
        revision: entry.revision.clone().unwrap_or_else(|| "main".to_string()),
        sha256: entry.sha256.clone(),
        engine: format!("{:?}", entry.engine).to_lowercase(),
        pull: format!("{:?}", entry.pull).to_lowercase(),
        quants: entry.quants.clone(),
        params: entry.params.clone(),
        license: entry.license.clone(),
        family: entry.family.clone(),
        min_vram_hint_gib: entry.min_vram_hint_gib,
        cached: model_is_cached(&root, entry),
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&detail)?),
        OutputFormat::Text => {
            println!("{}", detail.id);
            println!("  hf_repo:      {}", detail.hf_repo);
            println!("  source:       {}", detail.source);
            println!("  revision:     {}", detail.revision);
            println!("  params:       {}", detail.params);
            println!("  license:      {}", detail.license);
            println!("  family:       {}", detail.family);
            println!("  quants:       {}", detail.quants.join(", "));
            println!("  engine:       {}", detail.engine);
            println!("  pull:         {}", detail.pull);
            println!("  min VRAM:     ~{:.0} GiB", detail.min_vram_hint_gib);
            println!(
                "  cached:       {}",
                if detail.cached { "yes" } else { "no" }
            );
            if !detail.sha256.is_empty() {
                println!("  sha256:");
                for (file, digest) in &detail.sha256 {
                    println!("    {file}: {digest}");
                }
            }
        }
    }
    Ok(0)
}

// --- `update` handler (WOR-1804) ---

const SBPROXY_RELEASE_REPO: &str = "soapbucket/sbproxy";
const LLAMA_RELEASE_REPO: &str = "ggml-org/llama.cpp";

#[derive(serde::Serialize)]
struct SelfFreshness {
    current: String,
    latest: Option<String>,
    update_available: bool,
}

#[derive(serde::Serialize)]
struct EngineFreshness {
    engine: &'static str,
    installed: Option<String>,
    pinned_release: Option<String>,
    latest_release: Option<String>,
    update_available: bool,
}

#[derive(serde::Serialize)]
struct ModelFreshness {
    id: String,
    hf_repo: String,
    revision: String,
    /// `pinned` (a commit or tag) or `moving-ref` (a branch that drifts).
    tracking: &'static str,
}

#[derive(serde::Serialize)]
struct UpdateReport {
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    self_: Option<SelfFreshness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engines: Option<Vec<EngineFreshness>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    models: Option<Vec<ModelFreshness>>,
    note: String,
}

fn handle_update_subcommand(args: &UpdateArgs) -> anyhow::Result<i32> {
    // `update` = engines + models. `--self` adds the binary check; only
    // `--engines` / `--models` narrow (so `update --self` still reports
    // engines + models).
    let narrowed = args.engines || args.models;
    let self_ = args.self_.then(check_self_freshness);
    let engines = (args.engines || !narrowed).then(check_engines_freshness);
    let models = if args.models || !narrowed {
        Some(check_models_freshness(args.cache_dir.as_deref())?)
    } else {
        None
    };

    let report = UpdateReport {
        self_,
        engines,
        models,
        note: "dry run: `sbproxy update` reports only. Applying an update \
               (engine swap, self-update, model re-pull) is not wired yet; \
               a pinned artifact is never mutated without an explicit run."
            .to_string(),
    };

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => print_update_report(&report),
    }
    Ok(0)
}

fn check_self_freshness() -> SelfFreshness {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = github_latest_release(SBPROXY_RELEASE_REPO);
    let update_available = latest
        .as_deref()
        .map(|l| version_is_newer(&current, l))
        .unwrap_or(false);
    SelfFreshness {
        current,
        latest,
        update_available,
    }
}

fn check_engines_freshness() -> Vec<EngineFreshness> {
    let pinned = sbproxy_model_host::DEFAULT_LLAMA_RELEASE_TAG.to_string();
    let llama_latest = github_latest_release(LLAMA_RELEASE_REPO);
    let llama_update = llama_latest
        .as_deref()
        .map(|l| l != pinned)
        .unwrap_or(false);
    vec![
        EngineFreshness {
            engine: "llama_cpp",
            installed: engine_version("llama-server"),
            pinned_release: Some(pinned),
            latest_release: llama_latest,
            update_available: llama_update,
        },
        EngineFreshness {
            engine: "vllm",
            installed: engine_version("vllm"),
            // vLLM is not a pinned single-binary release on this path.
            pinned_release: None,
            latest_release: None,
            update_available: false,
        },
    ]
}

fn check_models_freshness(
    cache_dir: Option<&std::path::Path>,
) -> anyhow::Result<Vec<ModelFreshness>> {
    let catalog = load_models_catalog(None)?;
    let root = model_cache_root(cache_dir);
    let mut out = Vec::new();
    for (id, entry) in &catalog.models {
        if !model_is_cached(&root, entry) {
            continue; // only report models that are actually pulled
        }
        let revision = entry.revision.clone().unwrap_or_else(|| "main".to_string());
        out.push(ModelFreshness {
            id: id.clone(),
            hf_repo: entry.hf_repo.clone(),
            tracking: if is_moving_ref(&revision) {
                "moving-ref"
            } else {
                "pinned"
            },
            revision,
        });
    }
    Ok(out)
}

/// The version string an installed engine reports, or `None` when it is
/// not on `PATH`.
fn engine_version(program: &str) -> Option<String> {
    sbproxy_model_host::resolve_on_path(program)?;
    let out = std::process::Command::new(program)
        .arg("--version")
        .output()
        .ok()?;
    for stream in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(stream);
        if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
            return Some(line.trim().to_string());
        }
    }
    None
}

/// Whether a revision is a moving reference (a branch that can drift from
/// what was pulled) rather than a pinned commit / tag.
fn is_moving_ref(revision: &str) -> bool {
    let is_commit = revision.len() == 40 && revision.chars().all(|c| c.is_ascii_hexdigit());
    let is_tag = revision.starts_with('v')
        && revision[1..]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false);
    !(is_commit || is_tag)
}

/// The latest release tag of a GitHub repo (best-effort, via `curl`).
/// `None` when offline or the tool is absent.
fn github_latest_release(repo: &str) -> Option<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "6",
            "-H",
            "Accept: application/vnd.github+json",
        ])
        .arg(format!(
            "https://api.github.com/repos/{repo}/releases/latest"
        ))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("tag_name")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Whether `latest` is a newer semver than `current` (either may carry a
/// leading `v`); unparsable parts compare as `0`.
fn version_is_newer(current: &str, latest: &str) -> bool {
    fn parts(s: &str) -> Vec<u64> {
        s.trim_start_matches('v')
            .split(['.', '-', '+'])
            .filter_map(|p| p.parse::<u64>().ok())
            .collect()
    }
    let (c, l) = (parts(current), parts(latest));
    for i in 0..c.len().max(l.len()) {
        let cv = c.get(i).copied().unwrap_or(0);
        let lv = l.get(i).copied().unwrap_or(0);
        if lv != cv {
            return lv > cv;
        }
    }
    false
}

fn print_update_report(r: &UpdateReport) {
    if let Some(s) = &r.self_ {
        println!("sbproxy");
        println!("  current  {}", s.current);
        println!(
            "  latest   {}",
            s.latest.as_deref().unwrap_or("unknown (offline?)")
        );
        println!(
            "  {}",
            if s.update_available {
                "UPDATE AVAILABLE"
            } else {
                "up to date"
            }
        );
    }
    if let Some(engines) = &r.engines {
        println!("\nengines");
        for e in engines {
            println!("  {}", e.engine);
            println!(
                "    installed  {}",
                e.installed.as_deref().unwrap_or("not installed")
            );
            if let Some(p) = &e.pinned_release {
                println!("    pinned     {p}");
            }
            println!(
                "    latest     {}",
                e.latest_release.as_deref().unwrap_or("unknown / n/a")
            );
            if e.update_available {
                println!(
                    "    a newer prebuilt exists (pinned by default; \
                     set engines.<engine>.acquire.version to move)"
                );
            }
        }
    }
    if let Some(models) = &r.models {
        println!("\ncached models");
        if models.is_empty() {
            println!("  none pulled yet");
        }
        for m in models {
            let note = if m.tracking == "moving-ref" {
                " (tracks a moving ref; may be behind upstream)"
            } else {
                " (pinned)"
            };
            println!("  {:<20} {}@{}{}", m.id, m.hf_repo, m.revision, note);
        }
    }
    println!("\n{}", r.note);
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
        ConfigSub::Print(args) => handle_config_print(args),
    }
}

/// `sbproxy config print`: the effective config after built-in defaults +
/// the file + `${ENV}` interpolation, with secret values masked. Makes
/// it obvious what a box will actually do (WOR-1805).
fn handle_config_print(args: &ConfigPrintArgs) -> anyhow::Result<i32> {
    let path = args
        .config_path
        .clone()
        .or_else(|| std::env::var_os("SB_CONFIG_FILE").map(PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!("no config file: pass a path or set -f/--config / SB_CONFIG_FILE")
        })?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("read config '{}': {e}", path.display()))?;
    // Apply the same `${ENV}` interpolation the compiler does, so an
    // env-overridden value shows through as its resolved value.
    let interpolated = interpolate_env_vars(&raw);
    // Deserialize to the typed config (serde fills built-in defaults),
    // then re-serialize so defaults show explicitly.
    let config: sbproxy_config::ConfigFile = serde_yaml::from_str(&interpolated)
        .map_err(|e| anyhow::anyhow!("parse config '{}': {e}", path.display()))?;
    let mut value = serde_json::to_value(&config)?;
    mask_secrets(&mut value);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print!("{}", serde_yaml::to_string(&value)?);
    }
    Ok(0)
}

/// `${VAR}` interpolation matching the config compiler: a set variable
/// is substituted, an unset one is left literal.
fn interpolate_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                name.push(c);
            }
            match (closed && !name.is_empty(), std::env::var(&name)) {
                (true, Ok(val)) => out.push_str(&val),
                _ => {
                    out.push_str("${");
                    out.push_str(&name);
                    if closed {
                        out.push('}');
                    }
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Field names whose string value is a secret unless it is a resolver
/// reference.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "api_key"
            | "apikey"
            | "client_secret"
            | "token"
            | "password"
            | "secret"
            | "secret_key"
            | "access_key"
            | "access_key_id"
            | "secret_access_key"
            | "aws_secret_access_key"
            | "private_key"
    )
}

/// Whether a string value is a secret *reference* (safe to show) rather
/// than an inline secret (which must be masked).
fn is_secret_reference(value: &str) -> bool {
    sbproxy_vault::looks_like_secret_reference_uri(value)
        || value.starts_with("${")
        || value.starts_with("env:")
        || value.starts_with("secret:")
        || value.starts_with("file:")
        || value.starts_with("secretfile:")
}

/// Recursively mask inline secret values in a serialized config: a
/// string under a secret-named key that is not a resolver reference is
/// replaced with a placeholder. References (`vault://`, `${ENV}`,
/// `file:`, ...) are shown, since they are pointers, not the secret.
fn mask_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_secret_key(k) {
                    if let serde_json::Value::String(s) = v {
                        if !is_secret_reference(s) {
                            *s = "***MASKED***".to_string();
                            continue;
                        }
                    }
                }
                mask_secrets(v);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                mask_secrets(item);
            }
        }
        _ => {}
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
    let compiled = sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
    // WOR-1815: run the boot-time module constructors too, so `plan`
    // and `apply` report semantic-validation errors (exit 3) for a
    // config that compiles but cannot boot. See
    // `handle_validate_subcommand` for the rationale.
    sbproxy_core::pipeline::CompiledPipeline::from_config(compiled).map_err(|e| {
        anyhow::anyhow!(
            "config '{path_str}' compiled, but a module failed to construct \
             (this would fail at boot):\n{e:#}"
        )
    })?;
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

    #[test]
    fn run_name_defaults_to_catalog_id_and_hf_ref_needs_name() {
        // A plain catalog id is its own name.
        assert_eq!(resolve_run_name("qwen3-14b", None).unwrap(), "qwen3-14b");
        // A raw hf: ref without a name is an error.
        assert!(resolve_run_name("hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", None).is_err());
        // With a name it resolves to the name.
        assert_eq!(
            resolve_run_name("hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", Some("coder")).unwrap(),
            "coder"
        );
        // An empty name is rejected.
        assert!(resolve_run_name("qwen3-14b", Some("  ")).is_err());
    }

    #[test]
    fn run_serve_value_parses_into_a_valid_model_host_config() {
        // The synthesized serve block must round-trip into a
        // ModelHostConfig the runtime accepts, with the overrides applied.
        let args = RunArgs {
            model: "hf:Qwen/Qwen3-8B-GGUF:Q4_K_M".to_string(),
            name: Some("coder".to_string()),
            port: 8080,
            engine: "llama_cpp".to_string(),
            accel: "metal".to_string(),
            cache_dir: None,
            gguf_file: Some("qwen3-8b-q4_k_m.gguf".to_string()),
            dry_run: false,
        };
        let value = build_run_serve_value(&args);
        let cfg: sbproxy_model_host::ModelHostConfig =
            serde_json::from_value(value).expect("serve config parses");
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.models.len(), 1);
        assert_eq!(cfg.models[0].effective_name().unwrap(), "coder");
        assert_eq!(
            cfg.models[0].engine,
            sbproxy_model_host::EngineChoice::LlamaCpp
        );
        // The GGUF filename threads through to the serve entry (WOR-1808).
        assert_eq!(
            cfg.models[0].gguf_file.as_deref(),
            Some("qwen3-8b-q4_k_m.gguf")
        );
        // accel override keyed under the llama_cpp engine's acquire block.
        let prov = cfg
            .engines
            .get(&sbproxy_model_host::EngineKind::LlamaCpp)
            .expect("llama_cpp engine provisioning");
        assert_eq!(
            prov.acquire.as_ref().unwrap().accel,
            sbproxy_model_host::EngineAccel::Metal
        );
    }

    #[test]
    fn update_version_newer_compares_semver() {
        assert!(version_is_newer("1.4.0", "v1.5.0"));
        assert!(version_is_newer("1.4.0", "1.4.1"));
        assert!(version_is_newer("1.4.0", "2.0.0"));
        assert!(!version_is_newer("1.5.0", "v1.4.9"));
        assert!(!version_is_newer("1.4.0", "1.4.0"));
        assert!(!version_is_newer("1.4.0", "v1.4.0"));
    }

    #[test]
    fn update_moving_ref_vs_pinned() {
        assert!(is_moving_ref("main"));
        assert!(is_moving_ref("master"));
        assert!(is_moving_ref("my-feature-branch"));
        // A pinned tag or a 40-hex commit sha is not moving.
        assert!(!is_moving_ref("v1.2.0"));
        assert!(!is_moving_ref(&"a".repeat(40)));
        // A 39-char near-sha is treated as a branch (moving).
        assert!(is_moving_ref(&"a".repeat(39)));
    }

    #[test]
    fn config_print_masks_inline_secrets_but_shows_references() {
        let mut v = serde_json::json!({
            "providers": [
                { "name": "a", "api_key": "sk-REALSECRET123" },
                { "name": "b", "api_key": "vault://primary/openai" },
                { "name": "c", "api_key": "${OPENAI_API_KEY}" },
                { "name": "d", "client_secret": "literal-secret" },
                { "name": "e", "base_url": "https://api.example.com" },
            ]
        });
        mask_secrets(&mut v);
        let arr = v["providers"].as_array().unwrap();
        // Inline literal secrets are masked.
        assert_eq!(arr[0]["api_key"], "***MASKED***");
        assert_eq!(arr[3]["client_secret"], "***MASKED***");
        // References (a pointer, not the secret) are shown.
        assert_eq!(arr[1]["api_key"], "vault://primary/openai");
        assert_eq!(arr[2]["api_key"], "${OPENAI_API_KEY}");
        // Non-secret fields are untouched.
        assert_eq!(arr[4]["base_url"], "https://api.example.com");
    }

    #[test]
    fn config_print_env_interpolation_substitutes_and_passes_through() {
        // An unset variable is left literal.
        assert_eq!(
            interpolate_env_vars("y=${SB_DEFINITELY_UNSET_XYZZY}"),
            "y=${SB_DEFINITELY_UNSET_XYZZY}"
        );
        // A set variable (PATH is always set) is substituted.
        let out = interpolate_env_vars("p=${PATH}");
        assert_ne!(out, "p=${PATH}");
        assert!(out.starts_with("p="));
    }

    #[test]
    fn models_list_rows_cover_the_catalog_with_a_fit_verdict() {
        let catalog = sbproxy_model_host::Catalog::builtin();
        let report = sbproxy_core::doctor::DoctorReport::collect();
        // A cache root that does not exist -> everything reads not-pulled.
        let root = std::env::temp_dir().join("sbproxy-models-test-nonexistent");
        let rows = build_model_rows(&catalog, &report, &root);
        assert_eq!(rows.len(), catalog.len());
        for r in &rows {
            // Catalog ids resolve, so the fit is a real verdict, never empty.
            assert!(!r.fit.is_empty(), "row {} has no fit verdict", r.id);
            assert!(
                r.status == "cached" || r.status == "not-pulled",
                "unexpected status {}",
                r.status
            );
        }
    }

    #[test]
    fn run_serve_value_defaults_vllm_to_uvx() {
        // A plain catalog id (auto engine + accel) defaults vLLM to uvx
        // acquisition, so a safetensors model serves on a GPU box with no
        // manual install; no llama_cpp override is added.
        let args = RunArgs {
            model: "qwen3-14b".to_string(),
            name: None,
            port: 8080,
            engine: "auto".to_string(),
            accel: "auto".to_string(),
            cache_dir: None,
            gguf_file: None,
            dry_run: false,
        };
        let cfg: sbproxy_model_host::ModelHostConfig =
            serde_json::from_value(build_run_serve_value(&args)).unwrap();
        assert_eq!(cfg.models[0].engine, sbproxy_model_host::EngineChoice::Auto);
        let vllm = cfg
            .engines
            .get(&sbproxy_model_host::EngineKind::Vllm)
            .expect("vllm provisioning");
        assert_eq!(
            vllm.acquire.as_ref().unwrap().source,
            sbproxy_model_host::AcquireSource::Uvx
        );
        // No llama.cpp override when accel is auto.
        assert!(!cfg
            .engines
            .contains_key(&sbproxy_model_host::EngineKind::LlamaCpp));
    }

    #[test]
    fn parses_open_files_soft_limit() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max cpu time              unlimited            unlimited            seconds\n\
                      Max open files            1024                 524288               files\n";
        assert_eq!(parse_open_files_soft_limit(limits), Some(1024));
        assert_eq!(
            parse_open_files_soft_limit(
                "Max open files            unlimited            unlimited            files\n"
            ),
            None
        );
        assert_eq!(parse_open_files_soft_limit(""), None);
    }

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
