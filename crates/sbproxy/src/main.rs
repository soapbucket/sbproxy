//! sbproxy: AI Governance Gateway binary.
//!
//! Thin entrypoint that selects the rustls crypto provider, installs the
//! mimalloc allocator, parses CLI args with `clap` derive, and hands the
//! config path to [`sbproxy_core::run`]. All real work happens in the
//! workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
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
    /// Initialize and enroll nodes in a self-hosted cluster.
    Cluster(ClusterCmd),
    /// Render projection documents (robots.txt, llms.txt, ...) for an
    /// origin without starting the proxy.
    Projections(ProjectionsCmd),
    /// AI gateway tools (usage ledger verification, ...).
    Ai(AiCmd),
    /// Serve a certified catalog model in one command, with no YAML.
    /// Resolves an immutable artifact, generates local admin auth, warms
    /// the managed deployment, then advertises its OpenAI-compatible endpoint.
    Run(RunArgs),
    /// Discover, cache, remove, and operate managed local models.
    Models(ModelsCmd),
    /// Update the engines and cached models (add `--self` for the
    /// binary). `sbproxy update` checks the engine release feed and the
    /// cached models, then fetches, verifies, and swaps what is out of
    /// date, with confirmation. `--check` reports only. A pinned or
    /// `path`/`brew`/`apt`-managed artifact is reported, never replaced,
    /// unless a run explicitly targets it.
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
struct ClusterCmd {
    #[command(subcommand)]
    sub: ClusterSub,
}

#[derive(Subcommand, Debug)]
enum ClusterSub {
    /// Atomically create a CA, authority identity, gossip key, and token store.
    Init(ClusterInitArgs),
    /// Manage one-time enrollment tokens.
    Token(ClusterTokenCmd),
    /// Generate a local worker key, enroll it, and install returned material.
    Enroll(ClusterEnrollArgs),
    /// Show cluster membership, model eligibility, and unhealthy-node callouts.
    Status(ClusterStatusArgs),
}

#[derive(clap::Args, Debug)]
struct ClusterInitArgs {
    /// New authority directory. It must not already exist.
    #[arg(long = "dir")]
    directory: PathBuf,
    /// Logical cluster ID shared by every node.
    #[arg(long = "cluster-id")]
    cluster_id: String,
    /// Stable authority node ID.
    #[arg(long = "node-id")]
    node_id: String,
    /// Authority roles. Defaults to gateway plus authority.
    #[arg(long = "role", value_enum)]
    roles: Vec<ClusterRoleArg>,
    /// Exact identity label in `key=value` form. Repeatable.
    #[arg(long = "label")]
    labels: Vec<String>,
    /// DNS SAN expected on every peer certificate.
    #[arg(long = "server-name", default_value = "sbproxy-mesh")]
    server_name: String,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ClusterTokenCmd {
    #[command(subcommand)]
    sub: ClusterTokenSub,
}

#[derive(Subcommand, Debug)]
enum ClusterTokenSub {
    /// Create a hash-only, expiring, one-time enrollment token.
    Create(ClusterTokenCreateArgs),
}

#[derive(clap::Args, Debug)]
struct ClusterTokenCreateArgs {
    /// Existing authority directory.
    #[arg(long = "dir")]
    directory: PathBuf,
    /// Maximum role set. Defaults to worker.
    #[arg(long = "role", value_enum)]
    roles: Vec<ClusterRoleArg>,
    /// Exact labels granted to the enrolled identity in `key=value` form.
    #[arg(long = "label")]
    labels: Vec<String>,
    /// Token lifetime in seconds.
    #[arg(long = "ttl-secs", default_value_t = 900)]
    ttl_secs: u64,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args)]
struct ClusterEnrollArgs {
    /// Authority admin URL. The path is replaced with the enrollment endpoint.
    #[arg(long = "url")]
    url: String,
    /// One-time token. Prefer `SBPROXY_CLUSTER_TOKEN` over shell history.
    #[arg(long = "token", env = "SBPROXY_CLUSTER_TOKEN", hide_env_values = true)]
    token: String,
    /// Stable worker node ID.
    #[arg(long = "node-id")]
    node_id: String,
    /// Requested role subset. Defaults to worker.
    #[arg(long = "role", value_enum)]
    roles: Vec<ClusterRoleArg>,
    /// Exact token-granted label in `key=value` form. Repeatable.
    #[arg(long = "label")]
    labels: Vec<String>,
    /// New local identity directory. It must not already exist.
    #[arg(long = "out")]
    output: PathBuf,
    /// DNS SAN expected on every peer certificate.
    #[arg(long = "server-name", default_value = "sbproxy-mesh")]
    server_name: String,
    /// Additional PEM CA used to verify the authority HTTPS endpoint.
    #[arg(long = "ca-cert")]
    ca_cert: Option<PathBuf>,
    /// Permit plaintext HTTP for an explicitly development authority.
    #[arg(long = "allow-insecure-http", action = ArgAction::SetTrue)]
    allow_insecure_http: bool,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

impl std::fmt::Debug for ClusterEnrollArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClusterEnrollArgs")
            .field("url", &self.url)
            .field("token", &"<redacted>")
            .field("node_id", &self.node_id)
            .field("roles", &self.roles)
            .field("labels", &self.labels)
            .field("output", &self.output)
            .field("server_name", &self.server_name)
            .field("ca_cert", &self.ca_cert)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("format", &self.format)
            .finish()
    }
}

#[derive(clap::Args, Debug)]
struct ClusterStatusArgs {
    /// Admin endpoint and Basic Auth credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ClusterRoleArg {
    Gateway,
    Worker,
    Authority,
}

impl From<ClusterRoleArg> for sbproxy_mesh::ClusterNodeRole {
    fn from(value: ClusterRoleArg) -> Self {
        match value {
            ClusterRoleArg::Gateway => Self::Gateway,
            ClusterRoleArg::Worker => Self::Worker,
            ClusterRoleArg::Authority => Self::Authority,
        }
    }
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
    /// Certified catalog model ID to serve.
    #[arg(value_name = "MODEL")]
    model: String,
    /// Client-facing model alias. Defaults to the certified catalog ID.
    #[arg(long = "name")]
    name: Option<String>,
    /// Loopback port to serve on.
    #[arg(long = "port", default_value_t = 8080)]
    port: u16,
    /// Managed engine: `auto` (default), `vllm`, or `llama_cpp`.
    #[arg(long = "engine", default_value = "auto")]
    engine: String,
    /// Acceleration to acquire an engine build for: `auto` (default),
    /// `cuda`, `metal`, or `cpu`.
    #[arg(long = "accel", default_value = "auto")]
    accel: String,
    /// Weight/engine cache directory. Defaults to the platform cache.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// Exact certified artifact variant. Omission selects one compatible
    /// with the detected worker and engine.
    #[arg(long = "variant")]
    variant: Option<String>,
    /// Loopback admin port. Omission selects an available local port.
    #[arg(long = "admin-port")]
    admin_port: Option<u16>,
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
    /// Resolve, download, verify, and atomically cache exact artifacts.
    Pull(ModelsPullArgs),
    /// Remove one exact cached artifact when it is not configured or resident.
    Remove(ModelsRemoveArgs),
    /// List deployment lifecycle state from a running local gateway.
    Ps(ModelsPsArgs),
    /// Drain and stop one deployment on a running local gateway.
    Stop(ModelsStopArgs),
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ModelEngineArg {
    #[default]
    Auto,
    Vllm,
    #[value(name = "sglang")]
    SGLang,
    LlamaCpp,
    Embedded,
}

impl From<ModelEngineArg> for sbproxy_model_host::EngineChoice {
    fn from(value: ModelEngineArg) -> Self {
        match value {
            ModelEngineArg::Auto => Self::Auto,
            ModelEngineArg::Vllm => Self::Vllm,
            ModelEngineArg::SGLang => Self::SGLang,
            ModelEngineArg::LlamaCpp => Self::LlamaCpp,
            ModelEngineArg::Embedded => Self::Embedded,
        }
    }
}

#[derive(clap::Args, Debug)]
struct ModelsPullArgs {
    /// Catalog model IDs to pull. With no IDs, pulls the `on_boot` set.
    #[arg(value_name = "MODEL")]
    models: Vec<String>,
    /// Pull every catalog model compatible with this worker.
    #[arg(long = "all")]
    all: bool,
    /// Pin one exact variant. Valid only with one positional model.
    #[arg(long = "variant")]
    variant: Option<String>,
    /// Restrict resolution to one managed engine.
    #[arg(long = "engine", value_enum, default_value_t = ModelEngineArg::Auto)]
    engine: ModelEngineArg,
    /// Operator catalog file, replacing the built-in catalog.
    #[arg(long = "catalog-file")]
    catalog_file: Option<PathBuf>,
    /// Content-addressed artifact cache directory.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// Forbid network access. Verified hits and `file:` sources still work.
    #[arg(long = "offline")]
    offline: bool,
    /// Output format. Progress is always written to stderr.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
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

#[derive(clap::Args, Clone, Default)]
struct ModelsAdminArgs {
    /// Local admin API base URL. Defaults to `http://127.0.0.1:9090` for
    /// `ps` and `stop`; removal queries live protection only when supplied.
    #[arg(long = "admin-url", env = "SB_ADMIN_URL")]
    admin_url: Option<String>,
    /// Admin Basic Auth username.
    #[arg(long = "username", env = "SB_ADMIN_USERNAME")]
    username: Option<String>,
    /// Admin Basic Auth password. Never printed.
    #[arg(long = "password", env = "SB_ADMIN_PASSWORD")]
    password: Option<String>,
}

impl std::fmt::Debug for ModelsAdminArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelsAdminArgs")
            .field("admin_url", &self.admin_url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(clap::Args, Debug)]
struct ModelsRemoveArgs {
    /// Catalog model ID to remove from the verified cache.
    model: String,
    /// Exact artifact variant. Omission selects for the current worker.
    #[arg(long = "variant")]
    variant: Option<String>,
    /// Restrict resolution to one managed engine.
    #[arg(long = "engine", value_enum, default_value_t = ModelEngineArg::Auto)]
    engine: ModelEngineArg,
    /// Operator catalog file, replacing the built-in catalog.
    #[arg(long = "catalog-file")]
    catalog_file: Option<PathBuf>,
    /// Content-addressed artifact cache directory.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// Optional live admin endpoint and credentials for resident protection.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ModelsPsArgs {
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ModelsStopArgs {
    /// Canonical deployment ID to drain and stop.
    deployment: String,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct UpdateArgs {
    /// Include the sbproxy binary. It is only replaced when `--self` is
    /// given, since replacing the running binary is an explicit choice.
    #[arg(long = "self")]
    self_: bool,
    /// Include the inference engines (default when no target flag is set).
    /// Passing `--engines` explicitly targets them, so a pinned engine may
    /// be moved.
    #[arg(long = "engines")]
    engines: bool,
    /// Include the cached models (default when no target flag is set).
    /// Passing `--models` explicitly targets them.
    #[arg(long = "models")]
    models: bool,
    /// Assume yes to every confirmation prompt (for non-interactive runs).
    #[arg(long = "yes", short = 'y')]
    yes: bool,
    /// Weight cache directory to check for pulled models.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
    /// Output format. `text` (default) or `json`. `json` is always the
    /// freshness report (the acting path prints progress on the text path).
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

    // Resolve secret references in the alert channels and hand the finished set
    // to the boot-time dispatcher in sbproxy-core (WOR-1884). Done here, in the
    // binary, because secret resolution owns the vault backends and core does
    // not depend on them, mirroring how OTLP header secrets resolve above.
    install_alerting_channels_for_cli(&cli);

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

    let global_config_path = cli.globals.config.clone();
    // The global `--check` flag doubles as the update dry-run selector.
    let global_check = cli.check;
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
        Some(Cmd::Cluster(cmd)) => {
            run_subcommand("cluster", 2, handle_cluster_subcommand(&cmd));
        }
        Some(Cmd::Projections(cmd)) => {
            run_subcommand("error", 2, handle_projections_subcommand(&cmd).map(|()| 0));
        }
        Some(Cmd::Ai(cmd)) => {
            run_subcommand("ai", 2, handle_ai_subcommand(&cmd));
        }
        Some(Cmd::Run(args)) => {
            let code = handle_run_subcommand(&args, grace);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Some(Cmd::Models(cmd)) => {
            run_subcommand(
                "models",
                2,
                handle_models_subcommand(&cmd, global_config_path.as_deref()),
            );
        }
        Some(Cmd::Update(args)) => {
            run_subcommand(
                "update",
                2,
                handle_update_subcommand(&args, global_config_path.as_deref(), global_check),
            );
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

    // WOR-1785: the `secret:<name>` colon form (and the logical-name map
    // that served it) is gone. The config key still parses for
    // schema-v1 compatibility, so tell the operator it does nothing.
    if !secrets.map.is_empty() {
        tracing::warn!(
            entries = secrets.map.len(),
            "proxy.secrets.map has no effect: the `secret:<name>` form was removed. \
             Reference secrets as `secret://<backend>/<name>` with a backend declared \
             under proxy.secrets.backends (docs/secrets.md)"
        );
    }
    let resolver = sbproxy_vault::SecretResolver::new().with_manager(std::sync::Arc::new(manager));
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
    let telemetry = compiled
        .server
        .observability
        .as_ref()
        .and_then(|observability| observability.telemetry.as_ref())?;
    // WOR-1869: telemetry headers may hold provider-URI secret
    // references (vault://, secret://, ...), which need the backend
    // manager. Install the process resolver now; the call is
    // idempotent, so the serve path installing the same resolver
    // again later is a no-op.
    if telemetry
        .headers
        .values()
        .any(|v| sbproxy_vault::looks_like_secret_reference_uri(v))
    {
        install_secret_resolver(&path);
    }
    let mapped = runtime_telemetry_config(telemetry);
    if !mapped.headers.is_empty() {
        // Share the boot-resolved header set with the OTLP-logs sink,
        // which is built later inside sbproxy-core (it has no secret
        // resolution dependency of its own).
        sbproxy_observe::telemetry::install_resolved_otlp_headers(mapped.headers.clone());
    }
    Some(mapped)
}

/// Resolve secret references in `telemetry.headers` values at boot.
///
/// Follows the WOR-1767 fail-loud convention: a recognized reference
/// that cannot be resolved aborts startup rather than reaching the
/// collector verbatim as a bearer token. Literal values pass through
/// unchanged.
fn resolve_telemetry_headers(
    raw: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    if raw.is_empty() {
        return std::collections::BTreeMap::new();
    }
    let resolver = sbproxy_vault::process_resolver();
    raw.iter()
        .map(|(name, value)| {
            let resolved = match resolver.as_deref() {
                Some(r) => r.resolve(value),
                // No backends declared: `${VAR}` / `file:` still
                // resolve; provider URIs fail loud with a pointer at
                // proxy.secrets.backends.
                None => sbproxy_vault::SecretResolver::new().resolve(value),
            };
            match resolved {
                Ok(v) => (name.clone(), v),
                Err(e) => {
                    eprintln!("Fatal: telemetry header '{name}': {e:#}");
                    std::process::exit(1);
                }
            }
        })
        .collect()
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
        headers: resolve_telemetry_headers(&raw.headers),
    }
}

/// Resolve secret references in `proxy.alerting.channels` and install the
/// finished channel set for sbproxy-core's boot-time alert dispatcher (WOR-1884).
///
/// Runs only on the serve path. Follows the WOR-1767 fail-loud convention: a
/// recognized secret reference in `url` / `routing_key` that cannot be resolved
/// aborts startup rather than reaching PagerDuty or a webhook verbatim.
fn install_alerting_channels_for_cli(cli: &Cli) {
    if cli.check || !matches!(cli.cmd, None | Some(Cmd::Serve(_))) {
        return;
    }
    let Some(path) = pick_run_path(cli) else {
        return;
    };
    let Ok(yaml) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(compiled) = sbproxy_config::compile_config(&yaml) else {
        return;
    };
    let Some(alerting) = compiled.server.alerting.as_ref() else {
        return;
    };
    if alerting.channels.is_empty() {
        return;
    }

    // Install the process resolver when any channel carries a provider-URI
    // secret reference; the same idempotent installer telemetry headers use.
    let has_reference = alerting.channels.iter().any(|c| {
        [c.url.as_deref(), c.routing_key.as_deref()]
            .into_iter()
            .flatten()
            .any(sbproxy_vault::looks_like_secret_reference_uri)
    });
    if has_reference {
        install_secret_resolver(&path);
    }

    let channels = alerting
        .channels
        .iter()
        .map(map_alert_channel)
        .collect::<Vec<_>>();
    sbproxy_observe::alerting::install_channels(channels);
}

/// Map a config alert channel to the observe dispatcher shape, resolving any
/// secret references in `url` / `routing_key`.
fn map_alert_channel(
    channel: &sbproxy_config::AlertChannelConfig,
) -> sbproxy_observe::alerting::AlertChannelConfig {
    sbproxy_observe::alerting::AlertChannelConfig {
        channel_type: channel.channel_type.clone(),
        url: channel.url.as_deref().map(resolve_alerting_secret),
        headers: channel
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret: None,
        routing_key: channel.routing_key.as_deref().map(resolve_alerting_secret),
    }
}

/// Resolve a single alert-channel secret value, aborting on a reference that
/// cannot be resolved. Mirrors [`resolve_telemetry_headers`].
fn resolve_alerting_secret(value: &str) -> String {
    let resolver = sbproxy_vault::process_resolver();
    let resolved = match resolver.as_deref() {
        Some(r) => r.resolve(value),
        None => sbproxy_vault::SecretResolver::new().resolve(value),
    };
    match resolved {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Fatal: alerting channel secret: {e:#}");
            std::process::exit(1);
        }
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
            let pipeline = sbproxy_core::pipeline::CompiledPipeline::from_config(compiled)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "config '{path_str}' compiled, but a module failed to construct \
                         (this would fail at boot):\n{e:#}"
                    )
                })?;
            let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            sbproxy_core::model_runtime::validate_model_runtime(&pipeline, config_dir).map_err(
                |e| {
                    anyhow::anyhow!(
                        "config '{path_str}' has invalid model-host desired state \
                         (this would fail at boot):\n{e:#}"
                    )
                },
            )
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
                let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                match extract_serve_and_catalog(&yaml, config_dir) {
                    Ok(Some((serve, catalog))) => {
                        report = report.with_serve_config(&serve, &catalog);
                        exit = report.exit_code();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!("doctor: {error}");
                        exit = 2;
                    }
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
/// <config>`. Read-only: a config with no `serve:` block yields `None`.
/// An operator `catalog_file` on the first serve block replaces the
/// built-in catalog and resolves relative to the config directory.
fn extract_serve_and_catalog(
    yaml: &str,
    config_dir: &std::path::Path,
) -> anyhow::Result<
    Option<(
        sbproxy_model_host::ModelHostConfig,
        sbproxy_model_host::Catalog,
    )>,
> {
    let root: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    let Some(origins) = root.get("origins").and_then(serde_yaml::Value::as_mapping) else {
        return Ok(None);
    };
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
            let serve =
                serde_yaml::from_value::<sbproxy_model_host::ModelHostConfig>(serve_val.clone())?;
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
    let Some(merged) = merged else {
        return Ok(None);
    };
    // An operator catalog_file replaces the built-in catalog.
    let catalog = match merged.catalog_file.as_deref() {
        Some(configured) => {
            let configured = PathBuf::from(configured);
            let path = if configured.is_absolute() {
                configured
            } else {
                config_dir.join(configured)
            };
            let contents = std::fs::read_to_string(&path)
                .map_err(|error| anyhow::anyhow!("read catalog '{}': {error}", path.display()))?;
            sbproxy_model_host::Catalog::from_yaml(&contents)
                .map_err(|error| anyhow::anyhow!("parse catalog '{}': {error}", path.display()))?
        }
        None => sbproxy_model_host::Catalog::builtin(),
    };
    Ok(Some((merged, catalog)))
}

// --- `run` handler (WOR-1802) ---

struct PreparedRun {
    name: String,
    artifact: sbproxy_model_host::ResolvedArtifact,
    admin_port: u16,
    admin_password: String,
    yaml: String,
}

struct PrivateRunDirectory {
    path: PathBuf,
}

impl PrivateRunDirectory {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "sbproxy-run-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.path.join("sb.yml")
    }
}

impl Drop for PrivateRunDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `sbproxy run <model>`: resolve one certified artifact, synthesize the
/// canonical managed desired state, and wait for a warm deployment before
/// advertising the endpoint.
fn handle_run_subcommand(args: &RunArgs, grace: sbproxy_core::GraceConfig) -> i32 {
    use zeroize::Zeroize;

    let mut prepared = match prepare_run(args) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("sbproxy run: {error:#}");
            return 2;
        }
    };

    if args.dry_run {
        println!(
            "# resolved {}:{} with {}\n# generated admin credential is embedded below\n{}",
            prepared.artifact.logical_model,
            prepared.artifact.variant_id,
            engine_kind_name(prepared.artifact.engine),
            prepared.yaml,
        );
        prepared.admin_password.zeroize();
        prepared.yaml.zeroize();
        return 0;
    }

    raise_fd_limit();
    warn_low_fd_limit();
    let run_dir = PrivateRunDirectory::new();
    let path = run_dir.config_path();
    if let Err(error) = write_private_run_config(&path, prepared.yaml.as_bytes()) {
        prepared.admin_password.zeroize();
        prepared.yaml.zeroize();
        eprintln!("sbproxy run: {error:#}");
        return 1;
    }
    prepared.yaml.zeroize();

    eprintln!(
        "Preparing {}:{} with {}. Artifact and engine progress follows on stderr.",
        prepared.artifact.logical_model,
        prepared.artifact.variant_id,
        engine_kind_name(prepared.artifact.engine),
    );

    let path_string = path.to_string_lossy().into_owned();
    let server = match std::thread::Builder::new()
        .name("sbproxy-run-server".to_string())
        .spawn(move || sbproxy_core::run(&path_string, grace))
    {
        Ok(server) => server,
        Err(error) => {
            prepared.admin_password.zeroize();
            eprintln!("sbproxy run: start gateway thread: {error}");
            return 1;
        }
    };

    let admin_url = format!("http://127.0.0.1:{}", prepared.admin_port);
    let mut admin_args = ModelsAdminArgs {
        admin_url: Some(admin_url.clone()),
        username: Some("admin".to_string()),
        password: Some(prepared.admin_password.clone()),
    };
    loop {
        if server.is_finished() {
            let result = server.join();
            prepared.admin_password.zeroize();
            if let Some(password) = admin_args.password.as_mut() {
                password.zeroize();
            }
            match result {
                Ok(Ok(())) => eprintln!("sbproxy run: gateway exited before the model was ready"),
                Ok(Err(error)) => eprintln!("sbproxy run: gateway failed: {error:#}"),
                Err(_) => eprintln!("sbproxy run: gateway thread panicked"),
            }
            return 1;
        }

        if let Ok(status) = admin_request_json(
            &admin_args,
            None,
            reqwest::Method::GET,
            "/admin/model-host/status",
            None,
        ) {
            let deployment = status
                .get("deployments")
                .and_then(serde_json::Value::as_array)
                .and_then(|deployments| {
                    deployments.iter().find(|deployment| {
                        deployment
                            .get("deployment")
                            .and_then(serde_json::Value::as_str)
                            == Some("local")
                    })
                });
            match deployment
                .and_then(|deployment| deployment.get("state"))
                .and_then(serde_json::Value::as_str)
            {
                Some("ready") => break,
                Some("failed") => {
                    let reason = deployment
                        .and_then(|deployment| deployment.get("last_error"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("managed deployment preparation failed");
                    prepared.admin_password.zeroize();
                    if let Some(password) = admin_args.password.as_mut() {
                        password.zeroize();
                    }
                    eprintln!("sbproxy run: {reason}");
                    return 1;
                }
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    print!(
        "{}",
        run_ready_banner(
            &prepared.name,
            args.port,
            &admin_url,
            &prepared.admin_password,
        )
    );
    prepared.admin_password.zeroize();
    if let Some(password) = admin_args.password.as_mut() {
        password.zeroize();
    }

    let result = server.join();
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            eprintln!("sbproxy run: gateway failed: {error:#}");
            1
        }
        Err(_) => {
            eprintln!("sbproxy run: gateway thread panicked");
            1
        }
    }
}

fn run_ready_banner(name: &str, port: u16, admin_url: &str, admin_password: &str) -> String {
    format!(
        "\n{name} is ready on http://127.0.0.1:{port}\n\
         Admin: {admin_url}\n\
         Admin username: admin\n\
         Admin password: {admin_password}\n\
         export OPENAI_BASE_URL=http://127.0.0.1:{port}/v1\n\
         export OPENAI_API_KEY=local\n\
         Try: curl http://127.0.0.1:{port}/v1/chat/completions \\\n  \
           -H 'content-type: application/json' \\\n  \
           -d '{{\"model\":\"{name}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'\n"
    )
}

/// Resolve the public model name. One-command serving intentionally accepts
/// certified catalog IDs only; an optional name is a client-facing alias.
fn resolve_run_name(model: &str, name: Option<&str>) -> Result<String, String> {
    if model.starts_with("hf:") || model.contains(':') || model.contains('/') {
        return Err(format!(
            "'{model}' is a raw model reference; add it to a catalog before managed serving"
        ));
    }
    match name {
        Some(name) if name.trim().is_empty() => Err("--name is empty".to_string()),
        Some(name) => Ok(name.to_string()),
        None => Ok(model.to_string()),
    }
}

fn parse_run_engine(value: &str) -> anyhow::Result<sbproxy_model_host::EngineChoice> {
    match value {
        "auto" => Ok(sbproxy_model_host::EngineChoice::Auto),
        "vllm" => Ok(sbproxy_model_host::EngineChoice::Vllm),
        "sglang" => Ok(sbproxy_model_host::EngineChoice::SGLang),
        "llama_cpp" => Ok(sbproxy_model_host::EngineChoice::LlamaCpp),
        "embedded" => {
            anyhow::bail!(
                "embedded is not a managed process engine; use auto, vllm, sglang, or llama_cpp"
            )
        }
        other => {
            anyhow::bail!("unknown engine '{other}'; use auto, vllm, sglang, or llama_cpp")
        }
    }
}

fn run_acceleration(
    value: &str,
    worker: &sbproxy_model_host::WorkerProfile,
) -> anyhow::Result<&'static str> {
    let detected = match worker.accelerator {
        sbproxy_model_host::AcceleratorKind::Cpu => "cpu",
        sbproxy_model_host::AcceleratorKind::Metal => "metal",
        sbproxy_model_host::AcceleratorKind::Cuda => "cuda",
    };
    match value {
        "auto" => Ok(detected),
        "cpu" | "metal" | "cuda" if value == detected => Ok(detected),
        "cpu" | "metal" | "cuda" => {
            anyhow::bail!("requested {value} acceleration but the selected worker is {detected}")
        }
        "vulkan" => {
            anyhow::bail!("vulkan is not yet represented by the certified catalog worker contract")
        }
        other => anyhow::bail!("unknown acceleration '{other}'; use auto, cuda, metal, or cpu"),
    }
}

fn available_loopback_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn random_local_password() -> String {
    use rand::RngCore;
    use std::fmt::Write as _;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut password = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut password, "{byte:02x}").expect("writing to a String cannot fail");
    }
    password
}

fn prepare_run(args: &RunArgs) -> anyhow::Result<PreparedRun> {
    let name = resolve_run_name(&args.model, args.name.as_deref()).map_err(anyhow::Error::msg)?;
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let worker = sbproxy_model_host::WorkerProfile::from_descriptors(&report.gpus)
        .map_err(|error| anyhow::anyhow!("detect model worker: {error}"))?;
    let acceleration = run_acceleration(&args.accel, &worker)?;
    let catalog = sbproxy_model_host::Catalog::builtin();
    let artifact = catalog.resolve_artifact(
        &sbproxy_model_host::ResolveArtifactRequest {
            model: args.model.clone(),
            variant: args.variant.clone(),
            engine: parse_run_engine(&args.engine)?,
            replicas: 1,
            heterogeneous_variants: false,
        },
        &worker,
    )?;
    let admin_port = args.admin_port.unwrap_or(available_loopback_port()?);
    if admin_port == args.port {
        anyhow::bail!("--admin-port must differ from --port");
    }
    let admin_password = random_local_password();

    let mut cache = serde_json::Map::new();
    if let Some(cache_dir) = &args.cache_dir {
        cache.insert(
            "directory".to_string(),
            serde_json::json!(cache_dir.to_string_lossy()),
        );
    }
    let engine_name = engine_kind_name(artifact.engine);
    let engine_config = match artifact.engine {
        sbproxy_model_host::EngineKind::Vllm => serde_json::json!({
            "launch": "uv",
            "version": sbproxy_model_host::DEFAULT_VLLM_VERSION,
            "acceleration": acceleration,
        }),
        sbproxy_model_host::EngineKind::SGLang => serde_json::json!({
            "launch": "uv",
            "version": sbproxy_model_host::DEFAULT_SGLANG_VERSION,
            "acceleration": acceleration,
        }),
        sbproxy_model_host::EngineKind::LlamaCpp => serde_json::json!({
            "launch": "binary",
            "version": sbproxy_model_host::DEFAULT_LLAMA_RELEASE_TAG,
            "acceleration": acceleration,
        }),
        sbproxy_model_host::EngineKind::Embedded => {
            anyhow::bail!("catalog resolved the unsupported embedded managed engine")
        }
    };
    let action = serde_json::json!({
        "type": "ai_proxy",
        "providers": [{
            "name": "local",
            "provider_type": "managed_model",
            "deployment": "local",
            "models": [name.clone()],
            "default_model": name.clone(),
        }],
    });
    let origin = serde_json::json!({ "action": action });
    let config = serde_json::json!({
        "proxy": {
            "http_bind_port": args.port,
            "admin": {
                "enabled": true,
                "port": admin_port,
                "bind": "127.0.0.1",
                "username": "admin",
                "password": admin_password,
            },
            "model_host": {
                "cache": serde_json::Value::Object(cache),
                "engines": { engine_name: engine_config },
                "deployments": {
                    "local": {
                        "model": args.model,
                        "variant": artifact.variant_id,
                        "pull": "on_boot",
                        "warm": true,
                        "engine": engine_name,
                    },
                },
            },
        },
        "origins": {
            "127.0.0.1": origin.clone(),
            "localhost": origin,
        },
    });
    let yaml = serde_yaml::to_string(&config)?;
    sbproxy_config::compile_config(&yaml)
        .map_err(|error| anyhow::anyhow!("generated config is invalid: {error:#}"))?;
    Ok(PreparedRun {
        name,
        artifact,
        admin_port,
        admin_password,
        yaml,
    })
}

fn write_private_run_config(path: &std::path::Path, yaml: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("generated config has no parent directory"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", parent.display()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", path.display()))?;
    file.write_all(yaml)
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| anyhow::anyhow!("sync '{}': {error}", path.display()))?;
    Ok(())
}

// --- `models` handler (WOR-1803) ---

fn handle_models_subcommand(
    cmd: &ModelsCmd,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    match &cmd.sub {
        // `sbproxy models` with no subcommand lists.
        None => handle_models_list(&ModelsListArgs::default()),
        Some(ModelsSub::List(a)) => handle_models_list(a),
        Some(ModelsSub::Show(a)) => handle_models_show(a),
        Some(ModelsSub::Pull(a)) => handle_models_pull(a, config_path),
        Some(ModelsSub::Remove(a)) => handle_models_remove(a, config_path),
        Some(ModelsSub::Ps(a)) => handle_models_ps(a),
        Some(ModelsSub::Stop(a)) => handle_models_stop(a),
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

fn models_pull_transport(
) -> anyhow::Result<std::sync::Arc<dyn sbproxy_model_host::ArtifactTransport>> {
    #[cfg(feature = "model-weights")]
    {
        sbproxy_model_host::HttpArtifactTransport::new()
            .map(|transport| {
                std::sync::Arc::new(transport)
                    as std::sync::Arc<dyn sbproxy_model_host::ArtifactTransport>
            })
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
    #[cfg(not(feature = "model-weights"))]
    {
        Ok(std::sync::Arc::new(
            sbproxy_model_host::UnavailableArtifactTransport,
        ))
    }
}

fn models_pull_credential(
    reference: Option<&str>,
) -> anyhow::Result<Option<sbproxy_model_host::SourceCredential>> {
    use zeroize::Zeroize;

    let mut secret = match reference {
        Some(reference) => {
            let variable = reference
                .strip_prefix("${")
                .and_then(|value| value.strip_suffix('}'))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "catalog hf_token must be an environment reference like ${{HF_TOKEN}}"
                    )
                })?;
            Some(std::env::var(variable).map_err(|_| {
                anyhow::anyhow!("catalog hf_token environment variable '{variable}' is not set")
            })?)
        }
        None => std::env::var("HF_TOKEN")
            .ok()
            .or_else(|| std::env::var("HUGGING_FACE_HUB_TOKEN").ok()),
    };
    let Some(mut secret) = secret.take() else {
        return Ok(None);
    };
    let credential = sbproxy_model_host::SourceCredential::new(secret.as_bytes())
        .map_err(|error| anyhow::anyhow!(error.to_string()));
    secret.zeroize();
    credential.map(Some)
}

#[derive(Default)]
struct ModelsPullProgress;

impl sbproxy_model_host::ArtifactObserver for ModelsPullProgress {
    fn on_job(&self, job: &sbproxy_model_host::OperationJob) {
        let total = job.progress.total_bytes;
        if let Some(percent) = job
            .progress
            .completed_bytes
            .saturating_mul(100)
            .checked_div(total)
        {
            eprintln!(
                "{}: {:?} {} / {} bytes ({}%)",
                job.subject, job.state, job.progress.completed_bytes, total, percent
            );
        } else {
            eprintln!("{}: {:?}", job.subject, job.state);
        }
    }
}

#[derive(serde::Serialize)]
struct ModelsPullResult {
    model: String,
    variant: String,
    engine: String,
    artifact_digest: String,
    snapshot_path: PathBuf,
    verified_bytes: u64,
    job_id: String,
}

#[derive(serde::Serialize)]
struct ModelsPullOutput {
    schema_version: u32,
    command: &'static str,
    artifacts: Vec<ModelsPullResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gc: Option<sbproxy_model_host::GcReport>,
}

fn engine_kind_name(engine: sbproxy_model_host::EngineKind) -> &'static str {
    match engine {
        sbproxy_model_host::EngineKind::Vllm => "vllm",
        sbproxy_model_host::EngineKind::SGLang => "sglang",
        sbproxy_model_host::EngineKind::LlamaCpp => "llama_cpp",
        sbproxy_model_host::EngineKind::Embedded => "embedded",
    }
}

fn artifact_format_name(format: sbproxy_model_host::ArtifactFormat) -> &'static str {
    match format {
        sbproxy_model_host::ArtifactFormat::Safetensors => "safetensors",
        sbproxy_model_host::ArtifactFormat::Gguf => "gguf",
        sbproxy_model_host::ArtifactFormat::Pickle => "pickle",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullSelection {
    model: String,
    variant: Option<String>,
    engine: sbproxy_model_host::EngineChoice,
    replicas: u32,
    heterogeneous_variants: bool,
    configured: bool,
    pinned: bool,
}

impl PullSelection {
    fn catalog(model: String, args: &ModelsPullArgs) -> Self {
        Self {
            model,
            variant: args.variant.clone(),
            engine: args.engine.into(),
            replicas: 1,
            heterogeneous_variants: false,
            configured: false,
            pinned: false,
        }
    }
}

fn managed_engine_choice(
    engine: sbproxy_config::ManagedEngineChoice,
) -> sbproxy_model_host::EngineChoice {
    match engine {
        sbproxy_config::ManagedEngineChoice::Auto => sbproxy_model_host::EngineChoice::Auto,
        sbproxy_config::ManagedEngineChoice::Vllm => sbproxy_model_host::EngineChoice::Vllm,
        sbproxy_config::ManagedEngineChoice::SGLang => sbproxy_model_host::EngineChoice::SGLang,
        sbproxy_config::ManagedEngineChoice::LlamaCpp => sbproxy_model_host::EngineChoice::LlamaCpp,
    }
}

fn configured_pull_selections(
    serve: Option<&sbproxy_model_host::ModelHostConfig>,
    canonical: Option<&sbproxy_config::ModelHostControlConfig>,
) -> Vec<PullSelection> {
    let mut selections = Vec::new();
    if let Some(canonical) = canonical {
        selections.extend(
            canonical
                .deployments
                .values()
                .map(|deployment| PullSelection {
                    model: deployment.model.clone(),
                    variant: deployment.variant.clone(),
                    engine: managed_engine_choice(deployment.engine),
                    replicas: deployment.replicas,
                    heterogeneous_variants: deployment.heterogeneous_variants,
                    configured: true,
                    pinned: false,
                }),
        );
    }
    if let Some(serve) = serve {
        selections.extend(serve.models.iter().map(|entry| PullSelection {
            model: entry.model.clone(),
            variant: entry.variant.clone(),
            engine: entry.engine,
            replicas: 1,
            heterogeneous_variants: false,
            configured: true,
            pinned: entry.pinned,
        }));
    }
    selections
}

fn push_pull_selection(selections: &mut Vec<PullSelection>, candidate: PullSelection) {
    if let Some(existing) = selections.iter_mut().find(|existing| {
        existing.model == candidate.model
            && existing.variant == candidate.variant
            && existing.engine == candidate.engine
            && existing.replicas == candidate.replicas
            && existing.heterogeneous_variants == candidate.heterogeneous_variants
    }) {
        existing.configured |= candidate.configured;
        existing.pinned |= candidate.pinned;
    } else {
        selections.push(candidate);
    }
}

fn selected_pull_models(
    args: &ModelsPullArgs,
    catalog: &sbproxy_model_host::Catalog,
    serve: Option<&sbproxy_model_host::ModelHostConfig>,
    canonical: Option<&sbproxy_config::ModelHostControlConfig>,
) -> anyhow::Result<Vec<PullSelection>> {
    if args.all && !args.models.is_empty() {
        anyhow::bail!("--all cannot be combined with positional model IDs");
    }
    if args.variant.is_some() && (args.all || args.models.len() != 1) {
        anyhow::bail!("--variant requires exactly one positional model ID");
    }
    if args.all {
        return Ok(catalog
            .models
            .iter()
            .filter(|(_, entry)| !entry.variants.is_empty())
            .map(|(model, _)| PullSelection::catalog(model.clone(), args))
            .collect());
    }

    let configured = configured_pull_selections(serve, canonical);
    let mut selected = Vec::new();
    if !args.models.is_empty() {
        for model in &args.models {
            if args.variant.is_some() {
                push_pull_selection(&mut selected, PullSelection::catalog(model.clone(), args));
                continue;
            }
            let mut matched = false;
            for mut selection in configured
                .iter()
                .filter(|selection| selection.model == *model)
                .cloned()
            {
                if args.engine != ModelEngineArg::Auto {
                    selection.engine = args.engine.into();
                }
                push_pull_selection(&mut selected, selection);
                matched = true;
            }
            if !matched {
                push_pull_selection(&mut selected, PullSelection::catalog(model.clone(), args));
            }
        }
        return Ok(selected);
    }

    for selection in configured {
        push_pull_selection(&mut selected, selection);
    }
    for (model, entry) in &catalog.models {
        if !entry.variants.is_empty() && entry.pull == sbproxy_model_host::PullPolicy::OnBoot {
            push_pull_selection(&mut selected, PullSelection::catalog(model.clone(), args));
        }
    }
    Ok(selected)
}

fn handle_models_pull(
    args: &ModelsPullArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let (serve, canonical, catalog) = match config_path {
        Some(config_path) => {
            if args.catalog_file.is_some() {
                anyhow::bail!("--catalog-file cannot be combined with -f/--config");
            }
            let yaml = std::fs::read_to_string(config_path).map_err(|error| {
                anyhow::anyhow!("read config '{}': {error}", config_path.display())
            })?;
            let config_dir = config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let compiled = sbproxy_config::compile_config(&yaml)?;
            let canonical = compiled.server.model_host.clone();
            let legacy = extract_serve_and_catalog(&yaml, config_dir)?;
            if canonical.is_none() && legacy.is_none() {
                anyhow::bail!(
                    "config '{}' has no proxy.model_host or local serve block",
                    config_path.display()
                );
            }
            let (serve, catalog) = match legacy {
                Some((serve, catalog)) => (Some(serve), catalog),
                None => (None, sbproxy_model_host::Catalog::builtin()),
            };
            (serve, canonical, catalog)
        }
        None => (
            None,
            None,
            load_models_catalog(args.catalog_file.as_deref())?,
        ),
    };
    let selections = selected_pull_models(args, &catalog, serve.as_ref(), canonical.as_ref())?;
    if selections.is_empty() {
        eprintln!("sbproxy models pull: no catalog v2 artifacts selected");
        return Ok(0);
    }

    let report = sbproxy_core::doctor::DoctorReport::collect();
    let worker = sbproxy_model_host::WorkerProfile::from_descriptors(&report.gpus)
        .map_err(|error| anyhow::anyhow!("resolve pull worker: {error}"))?;
    let canonical_cache = canonical
        .as_ref()
        .and_then(|control| control.cache.directory.as_deref())
        .map(PathBuf::from);
    let legacy_cache = serve
        .as_ref()
        .and_then(|serve| serve.cache_dir.as_deref())
        .map(PathBuf::from);
    let configured_cache = canonical_cache.as_deref().or(legacy_cache.as_deref());
    let root = model_cache_root(args.cache_dir.as_deref().or(configured_cache));
    let manager = sbproxy_model_host::ArtifactManager::new(root, models_pull_transport()?)?
        .with_observer(std::sync::Arc::new(ModelsPullProgress));
    let network = if args.offline {
        sbproxy_model_host::NetworkPolicy::Denied
    } else {
        sbproxy_model_host::NetworkPolicy::Allowed
    };

    let configured_protection = match config_path {
        Some(path) => configured_artifact_protection(path, &catalog, &worker)?,
        None => sbproxy_model_host::CacheProtection::default(),
    };

    let mut requests: Vec<(
        sbproxy_model_host::ResolvedArtifact,
        sbproxy_model_host::PullPolicy,
        bool,
        Option<sbproxy_model_host::SourceCredential>,
    )> = Vec::with_capacity(selections.len());
    for selection in selections {
        let model = &selection.model;
        let entry = catalog
            .get(model)
            .ok_or_else(|| anyhow::anyhow!("model '{model}' is not in the catalog"))?;
        if entry.variants.is_empty() {
            anyhow::bail!(
                "model '{model}' has no exact catalog v2 variant; migrate its files, sizes, digests, and revision before pulling"
            );
        }
        let request = sbproxy_model_host::ResolveArtifactRequest {
            model: selection.model.clone(),
            variant: selection.variant,
            engine: selection.engine,
            replicas: selection.replicas,
            heterogeneous_variants: selection.heterogeneous_variants,
        };
        match catalog.resolve_artifact(&request, &worker) {
            Ok(artifact) => {
                if let Some(existing) = requests.iter().position(|(existing, _, _, _)| {
                    existing.artifact_digest == artifact.artifact_digest
                }) {
                    requests[existing].2 |= selection.pinned;
                } else {
                    requests.push((
                        artifact,
                        entry.pull,
                        selection.pinned,
                        models_pull_credential(entry.hf_token.as_deref())?,
                    ));
                }
            }
            Err(error) if args.all => {
                eprintln!("sbproxy models pull: skip {model}: {error}");
            }
            Err(error) => return Err(anyhow::anyhow!(error.to_string())),
        }
    }

    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("build models pull runtime: {error}"))?;
    let (results, protection) = executor.block_on(async {
        let mut results = Vec::with_capacity(requests.len());
        let mut protection = configured_protection;
        for (artifact, pull_policy, pinned, credential) in requests {
            let ready = manager
                .ensure(
                    &artifact,
                    sbproxy_model_host::AcquisitionContext {
                        intent: sbproxy_model_host::PullIntent::Explicit,
                        network,
                        pull_policy,
                        credential,
                    },
                )
                .await?;
            results.push(ModelsPullResult {
                model: artifact.logical_model,
                variant: artifact.variant_id,
                engine: engine_kind_name(artifact.engine).to_string(),
                artifact_digest: ready.artifact_digest,
                snapshot_path: ready.snapshot_path,
                verified_bytes: ready.metadata.total_size_bytes,
                job_id: ready.job.id,
            });
            if pinned {
                protection.pinned.insert(artifact.artifact_digest);
            }
        }
        Ok::<_, sbproxy_model_host::ArtifactError>((results, protection))
    })?;

    let budget_gib = canonical
        .as_ref()
        .and_then(|control| control.cache.budget_gib)
        .or_else(|| serve.as_ref().and_then(|serve| serve.cache_budget_gib));
    let gc = budget_gib
        .map(|gib| {
            if !gib.is_finite() || gib < 0.0 {
                anyhow::bail!("serve.cache_budget_gib must be a finite nonnegative number");
            }
            let bytes = (gib * 1024.0 * 1024.0 * 1024.0).floor();
            if bytes > u64::MAX as f64 {
                anyhow::bail!("serve.cache_budget_gib exceeds the supported byte range");
            }
            manager
                .enforce_budget(bytes as u64, &protection)
                .map_err(anyhow::Error::from)
        })
        .transpose()?;
    let output = ModelsPullOutput {
        schema_version: 1,
        command: "models.pull",
        artifacts: results,
        gc,
    };

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            for result in &output.artifacts {
                println!(
                    "{}:{} verified {} bytes at {} (sha256:{})",
                    result.model,
                    result.variant,
                    result.verified_bytes,
                    result.snapshot_path.display(),
                    result.artifact_digest
                );
            }
            if let Some(gc) = &output.gc {
                println!(
                    "cache GC: {} -> {} bytes ({} reclaimed, {} still above budget)",
                    gc.before_bytes,
                    gc.after_bytes,
                    gc.reclaimed_bytes,
                    gc.budget_unsatisfied_bytes
                );
            }
        }
    }
    Ok(0)
}

fn admin_request_json(
    args: &ModelsAdminArgs,
    default_url: Option<&str>,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    use zeroize::Zeroize;

    let base_url =
        args.admin_url.as_deref().or(default_url).ok_or_else(|| {
            anyhow::anyhow!("--admin-url is required for live runtime protection")
        })?;
    let username = args.username.as_deref().unwrap_or("admin");
    let mut password = args.password.clone().ok_or_else(|| {
        anyhow::anyhow!("admin password is required via --password or SB_ADMIN_PASSWORD")
    })?;
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut request = client
        .request(method, &url)
        .basic_auth(username, Some(password.as_str()));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let request = request.build();
    password.zeroize();
    let response = client.execute(request?)?;
    let status = response.status();
    let value: serde_json::Value = response
        .json()
        .map_err(|error| anyhow::anyhow!("admin endpoint returned invalid JSON: {error}"))?;
    if !status.is_success() {
        let reason = value
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("error").and_then(serde_json::Value::as_str))
            .unwrap_or("admin request failed");
        anyhow::bail!("admin request returned HTTP {}: {reason}", status.as_u16());
    }
    Ok(value)
}

fn models_command_envelope(command: &'static str, value: serde_json::Value) -> serde_json::Value {
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        value => serde_json::Map::from_iter([("result".to_string(), value)]),
    };
    object.insert("command".to_string(), serde_json::json!(command));
    object.insert("schema_version".to_string(), serde_json::json!(1));
    serde_json::Value::Object(object)
}

/// Render the worker-local device set for `models ps`: a single index for a
/// single-GPU deployment, or the tensor-parallel group with its degree for a
/// multi-GPU one ("0,1 tp2"). Empty (CPU or unplaced) renders "-".
fn format_device_set(value: Option<&serde_json::Value>) -> String {
    let indexes: Vec<String> = value
        .and_then(serde_json::Value::as_array)
        .map(|devices| {
            devices
                .iter()
                .filter_map(serde_json::Value::as_u64)
                .map(|index| index.to_string())
                .collect()
        })
        .unwrap_or_default();
    match indexes.len() {
        0 => "-".to_string(),
        1 => indexes[0].clone(),
        degree => format!("{} tp{degree}", indexes.join(",")),
    }
}

fn handle_models_ps(args: &ModelsPsArgs) -> anyhow::Result<i32> {
    let status = admin_request_json(
        &args.admin,
        Some("http://127.0.0.1:9090"),
        reqwest::Method::GET,
        "/admin/model-host/status",
        None,
    )?;
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&models_command_envelope("models.ps", status))?
        ),
        OutputFormat::Text => {
            let deployments = status
                .get("deployments")
                .and_then(serde_json::Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            println!(
                "{:<24} {:<12} {:<8} {:<8} {:<8} {:<14} REASON",
                "DEPLOYMENT", "STATE", "PORT", "ACTIVE", "QUEUED", "DEVICES"
            );
            for deployment in deployments {
                println!(
                    "{:<24} {:<12} {:<8} {:<8} {:<8} {:<14} {}",
                    deployment
                        .get("deployment")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("-"),
                    deployment
                        .get("state")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("-"),
                    deployment
                        .get("port")
                        .and_then(serde_json::Value::as_u64)
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    deployment
                        .get("active_requests")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                    deployment
                        .get("queued_requests")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                    format_device_set(deployment.get("selected_devices")),
                    deployment
                        .get("reason_code")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("-"),
                );
            }
        }
    }
    Ok(0)
}

fn handle_models_stop(args: &ModelsStopArgs) -> anyhow::Result<i32> {
    let stopped = admin_request_json(
        &args.admin,
        Some("http://127.0.0.1:9090"),
        reqwest::Method::POST,
        "/admin/model-host/stop",
        Some(serde_json::json!({ "deployment": args.deployment })),
    )?;
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&models_command_envelope("models.stop", stopped))?
        ),
        OutputFormat::Text => println!("{} stopped", args.deployment),
    }
    Ok(0)
}

fn configured_artifact_protection(
    config_path: &std::path::Path,
    catalog: &sbproxy_model_host::Catalog,
    worker: &sbproxy_model_host::WorkerProfile,
) -> anyhow::Result<sbproxy_model_host::CacheProtection> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", config_path.display()))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;
    let pipeline = sbproxy_core::pipeline::CompiledPipeline::from_config(compiled)?;
    let mut protection = sbproxy_model_host::CacheProtection::default();

    if let Some(control) = pipeline.config.server.model_host.as_ref() {
        for deployment in control.deployments.values() {
            let engine = match deployment.engine {
                sbproxy_config::ManagedEngineChoice::Auto => sbproxy_model_host::EngineChoice::Auto,
                sbproxy_config::ManagedEngineChoice::Vllm => sbproxy_model_host::EngineChoice::Vllm,
                sbproxy_config::ManagedEngineChoice::SGLang => {
                    sbproxy_model_host::EngineChoice::SGLang
                }
                sbproxy_config::ManagedEngineChoice::LlamaCpp => {
                    sbproxy_model_host::EngineChoice::LlamaCpp
                }
            };
            let artifact = catalog.resolve_artifact(
                &sbproxy_model_host::ResolveArtifactRequest {
                    model: deployment.model.clone(),
                    variant: deployment.variant.clone(),
                    engine,
                    replicas: deployment.replicas,
                    heterogeneous_variants: deployment.heterogeneous_variants,
                },
                worker,
            )?;
            protection.configured.insert(artifact.artifact_digest);
        }
    }
    for action in &pipeline.actions {
        let sbproxy_modules::Action::AiProxy(ai) = action else {
            continue;
        };
        for serve in ai
            .config
            .providers
            .iter()
            .filter_map(|provider| provider.serve.as_ref())
        {
            for configured in &serve.models {
                let artifact = catalog.resolve_artifact(
                    &sbproxy_model_host::ResolveArtifactRequest {
                        model: configured.model.clone(),
                        variant: configured.variant.clone(),
                        engine: configured.engine,
                        replicas: 1,
                        heterogeneous_variants: false,
                    },
                    worker,
                )?;
                protection
                    .configured
                    .insert(artifact.artifact_digest.clone());
                if configured.pinned {
                    protection.pinned.insert(artifact.artifact_digest);
                }
            }
        }
    }
    Ok(protection)
}

fn handle_models_remove(
    args: &ModelsRemoveArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let catalog = load_models_catalog(args.catalog_file.as_deref())?;
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let worker = sbproxy_model_host::WorkerProfile::from_descriptors(&report.gpus)
        .map_err(|error| anyhow::anyhow!("resolve removal worker: {error}"))?;
    let artifact = catalog.resolve_artifact(
        &sbproxy_model_host::ResolveArtifactRequest {
            model: args.model.clone(),
            variant: args.variant.clone(),
            engine: args.engine.into(),
            replicas: 1,
            heterogeneous_variants: false,
        },
        &worker,
    )?;
    let mut protection = match config_path {
        Some(path) => configured_artifact_protection(path, &catalog, &worker)?,
        None => sbproxy_model_host::CacheProtection::default(),
    };
    if args.admin.admin_url.is_some() {
        let live = admin_request_json(
            &args.admin,
            None,
            reqwest::Method::GET,
            "/admin/model-host/status",
            None,
        )?;
        if let Some(deployments) = live
            .get("deployments")
            .and_then(serde_json::Value::as_array)
        {
            for deployment in deployments {
                if let Some(digest) = deployment
                    .get("artifact_digest")
                    .and_then(serde_json::Value::as_str)
                {
                    protection.resident.insert(digest.to_string());
                }
            }
        }
    }

    let root = model_cache_root(args.cache_dir.as_deref());
    let manager = sbproxy_model_host::ArtifactManager::new(
        root,
        std::sync::Arc::new(sbproxy_model_host::UnavailableArtifactTransport),
    )?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("build models remove runtime: {error}"))?;
    let removed = executor.block_on(manager.remove(&artifact.artifact_digest, &protection))?;
    let output = models_command_envelope(
        "models.remove",
        serde_json::json!({
            "model": args.model,
            "variant": artifact.variant_id,
            "artifact_digest": removed.artifact_digest,
            "removed": removed.removed,
            "reclaimed_bytes": removed.reclaimed_bytes,
            "job_id": removed.job_id,
        }),
    );
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            if output["removed"].as_bool() == Some(true) {
                println!(
                    "{}:{} removed ({} bytes reclaimed)",
                    args.model,
                    output["variant"].as_str().unwrap_or("-"),
                    output["reclaimed_bytes"].as_u64().unwrap_or(0),
                );
            } else {
                println!("{} is not cached", args.model);
            }
        }
    }
    Ok(0)
}

fn model_cache_root(cache_dir: Option<&std::path::Path>) -> PathBuf {
    let configured = cache_dir.map(|p| p.to_string_lossy().into_owned());
    sbproxy_model_host::resolve_cache_dir_default(configured.as_deref())
}

/// Whether any weights for `entry` are present in the cache dir.
fn model_is_cached(
    root: &std::path::Path,
    model: &str,
    entry: &sbproxy_model_host::CatalogEntry,
) -> bool {
    if entry.variants.is_empty() {
        return false;
    }
    std::fs::read_dir(root.join("metadata"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| {
            serde_json::from_slice::<sbproxy_model_host::ArtifactCacheMetadata>(&bytes).ok()
        })
        .any(|metadata| {
            metadata.logical_model == model
                && root
                    .join("snapshots")
                    .join(metadata.artifact_digest)
                    .is_dir()
        })
}

/// One row of `sbproxy models list`.
#[derive(serde::Serialize)]
struct ModelRow {
    id: String,
    params: String,
    license: String,
    family: String,
    modality: String,
    quants: Vec<String>,
    selected_variant: Option<String>,
    format: Option<String>,
    stability: Option<String>,
    exact_size_bytes: Option<u64>,
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
    let worker = sbproxy_model_host::WorkerProfile::from_descriptors(&report.gpus).ok();

    catalog
        .models
        .iter()
        .map(|(id, entry)| {
            let e = fit_by_id.get(id.as_str());
            let resolved = worker.as_ref().and_then(|worker| {
                catalog
                    .resolve_artifact(
                        &sbproxy_model_host::ResolveArtifactRequest {
                            model: id.clone(),
                            variant: None,
                            engine: sbproxy_model_host::EngineChoice::Auto,
                            replicas: 1,
                            heterogeneous_variants: false,
                        },
                        worker,
                    )
                    .ok()
            });
            ModelRow {
                id: id.clone(),
                params: entry.params.clone(),
                license: entry.license.clone(),
                family: entry.family.clone(),
                modality: entry.modality.label().to_string(),
                quants: entry.quants.clone(),
                selected_variant: resolved
                    .as_ref()
                    .map(|artifact| artifact.variant_id.clone()),
                format: resolved
                    .as_ref()
                    .map(|artifact| artifact_format_name(artifact.format).to_string()),
                stability: resolved
                    .as_ref()
                    .map(|artifact| artifact.stability.as_str().to_string()),
                exact_size_bytes: resolved.as_ref().and_then(|artifact| {
                    artifact
                        .files
                        .iter()
                        .try_fold(0u64, |total, file| total.checked_add(file.size_bytes))
                }),
                engine: resolved
                    .as_ref()
                    .map(|artifact| engine_kind_name(artifact.engine).to_string())
                    .or_else(|| e.map(|entry| entry.engine.clone()))
                    .unwrap_or_default(),
                fit: e.map(|e| e.fit.verdict.to_string()).unwrap_or_default(),
                estimated_vram_gib: e.and_then(|e| e.fit.estimated_vram_gib),
                status: if entry.variants.is_empty() {
                    "preview-incomplete".to_string()
                } else if model_is_cached(cache_root, id, entry) {
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
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&models_command_envelope(
                "models.list",
                serde_json::json!({ "models": rows }),
            ))?
        ),
        OutputFormat::Text => {
            println!(
                "{:<27} {:<13} {:<12} {:<11} {:<10} {:<18} {:<10} {:<12} STATUS",
                "MODEL", "VARIANT", "FORMAT", "SIZE", "STABILITY", "FIT", "VRAM(GiB)", "ENGINE"
            );
            for r in &rows {
                let vram = r
                    .estimated_vram_gib
                    .map(|v| format!("~{v:.0}"))
                    .unwrap_or_else(|| "-".to_string());
                let size = r
                    .exact_size_bytes
                    .map(|bytes| format!("{:.1}MiB", bytes as f64 / (1024.0 * 1024.0)))
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<27} {:<13} {:<12} {:<11} {:<10} {:<18} {:<10} {:<12} {}",
                    r.id,
                    r.selected_variant.as_deref().unwrap_or("-"),
                    r.format.as_deref().unwrap_or("-"),
                    size,
                    r.stability.as_deref().unwrap_or("-"),
                    r.fit,
                    vram,
                    r.engine,
                    r.status
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
    catalog_revision: String,
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
    modality: String,
    context_length: u64,
    allow_pickle: bool,
    variants: Vec<sbproxy_model_host::ArtifactVariant>,
    min_vram_hint_gib: f64,
    cached: bool,
}

fn engine_choice_name(engine: sbproxy_model_host::EngineChoice) -> &'static str {
    match engine {
        sbproxy_model_host::EngineChoice::Auto => "auto",
        sbproxy_model_host::EngineChoice::Vllm => "vllm",
        sbproxy_model_host::EngineChoice::SGLang => "sglang",
        sbproxy_model_host::EngineChoice::LlamaCpp => "llama_cpp",
        sbproxy_model_host::EngineChoice::Embedded => "embedded",
    }
}

fn pull_policy_name(policy: sbproxy_model_host::PullPolicy) -> &'static str {
    match policy {
        sbproxy_model_host::PullPolicy::OnBoot => "on_boot",
        sbproxy_model_host::PullPolicy::OnDemand => "on_demand",
        sbproxy_model_host::PullPolicy::Manual => "manual",
    }
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
        catalog_revision: catalog.catalog_revision.clone(),
        hf_repo: entry.hf_repo.clone(),
        source: entry
            .source
            .clone()
            .unwrap_or_else(|| format!("hf:{}", entry.hf_repo)),
        revision: entry.revision.clone().unwrap_or_else(|| "main".to_string()),
        sha256: entry.sha256.clone(),
        engine: engine_choice_name(entry.engine).to_string(),
        pull: pull_policy_name(entry.pull).to_string(),
        quants: entry.quants.clone(),
        params: entry.params.clone(),
        license: entry.license.clone(),
        family: entry.family.clone(),
        modality: entry.modality.label().to_string(),
        context_length: entry.context_length,
        allow_pickle: entry.allow_pickle,
        variants: entry.variants.clone(),
        min_vram_hint_gib: entry.min_vram_hint_gib,
        cached: model_is_cached(&root, &args.id, entry),
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&models_command_envelope(
                "models.show",
                serde_json::to_value(&detail)?,
            ))?
        ),
        OutputFormat::Text => {
            println!("{}", detail.id);
            println!("  catalog:      {}", detail.catalog_revision);
            println!("  hf_repo:      {}", detail.hf_repo);
            println!("  source:       {}", detail.source);
            println!("  revision:     {}", detail.revision);
            println!("  params:       {}", detail.params);
            println!("  license:      {}", detail.license);
            println!("  family:       {}", detail.family);
            println!("  modality:     {}", detail.modality);
            println!("  context:      {}", detail.context_length);
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
            if !detail.variants.is_empty() {
                println!("  variants:");
                for variant in &detail.variants {
                    println!(
                        "    {}: {} {} [{}] via {} at {}",
                        variant.id,
                        artifact_format_name(variant.format),
                        variant.quant,
                        variant.stability.as_str(),
                        variant
                            .engines
                            .iter()
                            .map(|engine| engine_kind_name(*engine))
                            .collect::<Vec<_>>()
                            .join(","),
                        variant.revision
                    );
                    for file in &variant.files {
                        println!(
                            "      {}: {} bytes sha256:{}",
                            file.path, file.size_bytes, file.sha256
                        );
                    }
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

fn handle_update_subcommand(
    args: &UpdateArgs,
    config_path: Option<&std::path::Path>,
    check: bool,
) -> anyhow::Result<i32> {
    let update_cfg = load_update_config(config_path)?;

    // `update` = engines + models. `--self` adds the binary; only
    // `--engines` / `--models` narrow (so `update --self` still includes
    // engines + models).
    let narrowed = args.engines || args.models;
    let self_ = args.self_.then(check_self_freshness);
    let engines = (args.engines || !narrowed).then(check_engines_freshness);
    let models = if args.models || !narrowed {
        Some(check_models_freshness(args.cache_dir.as_deref())?)
    } else {
        None
    };

    // The acting path runs only on a `text`, non-`--check`, non-`auto`
    // run. `--check` and a background `update.auto` run report only, and
    // JSON is always the machine-readable freshness report (the acting
    // path prints progress on the human path).
    let is_json = matches!(args.format, OutputFormat::Json);
    let will_act = !check && !update_cfg.auto && !is_json;
    let note = if update_cfg.auto {
        "report only: update.auto is on, so this run reports and never \
         swaps. Run `sbproxy update` with auto off (or override the config) \
         to apply, and target an artifact to move a pinned one."
            .to_string()
    } else if check {
        "dry run (--check): reports only. Drop --check to apply, with \
         confirmation. A pinned or externally-managed artifact is never \
         replaced without an explicit targeted run."
            .to_string()
    } else if is_json {
        "freshness report only (json). Run `sbproxy update` on a terminal \
         to fetch, verify, and swap what is out of date, with confirmation."
            .to_string()
    } else {
        format!(
            "channel {}: applying with confirmation. A pinned or \
             externally-managed artifact is reported, never replaced, unless \
             you target it (e.g. `sbproxy update --engines`).",
            channel_label(update_cfg.channel)
        )
    };

    let report = UpdateReport {
        self_,
        engines,
        models,
        note,
    };

    if is_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    print_update_report(&report);
    if !will_act {
        return Ok(0);
    }

    let applier = RealUpdateApplier;
    apply_updates(
        &report,
        &UpdatePlanContext {
            channel: update_cfg.channel,
            targeted_self: args.self_,
            targeted_engines: args.engines,
            targeted_models: args.models,
            assume_yes: args.yes,
            cache_dir: args.cache_dir.clone(),
        },
        &applier,
    )
}

/// Load the `update:` block from a config file, or the defaults when no
/// `-f/--config` was given (or the file omits an `update:` block).
fn load_update_config(
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<sbproxy_config::UpdateConfig> {
    match config_path {
        Some(path) => {
            let yaml = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read config '{}': {e}", path.display()))?;
            let cfg: sbproxy_config::ConfigFile = serde_yaml::from_str(&yaml)
                .map_err(|e| anyhow::anyhow!("parse config '{}': {e}", path.display()))?;
            Ok(cfg.update)
        }
        None => Ok(sbproxy_config::UpdateConfig::default()),
    }
}

/// Short label for an update channel, for the report note.
fn channel_label(channel: sbproxy_config::UpdateChannel) -> &'static str {
    match channel {
        sbproxy_config::UpdateChannel::Stable => "stable",
        sbproxy_config::UpdateChannel::Latest => "latest",
        sbproxy_config::UpdateChannel::Pinned => "pinned",
    }
}

// --- `update` acting half: pinning gate + swap planners + apply seam ---

/// How an updatable artifact is currently obtained, which decides whether
/// `sbproxy update` is allowed to replace it (WOR-1804).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinState {
    /// Installed and owned by an external tool: a binary already on
    /// `PATH`, or a `brew` / `apt` package. Reported, never overwritten.
    ExternallyManaged,
    /// Pinned to an explicit version or digest. A blanket run holds it;
    /// only a run that explicitly targets this artifact may move it.
    Pinned,
    /// Tracks a moving reference on the configured channel. Swap-eligible.
    Tracking,
}

/// The outcome of the pinning gate: whether a swap may proceed, and why
/// not when it may not. Pure; drives both the report and the acting path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapDecision {
    /// A newer artifact exists and may be fetched and swapped in.
    Eligible,
    /// Already current; nothing to do.
    UpToDate,
    /// Owned by an external package manager; report only, never touch.
    ManagedElsewhere,
    /// Pinned and this run did not explicitly target it; hold.
    PinnedHold,
    /// A background / `update.auto` run only reports; it never swaps.
    AutoReportOnly,
}

/// Decide whether `sbproxy update` may replace one artifact. Pure:
/// pinning and external management always win over an available update,
/// an `auto` (background) run never swaps, and the `pinned` channel
/// freezes everything a targeted run did not name.
fn decide_swap(
    pin: PinState,
    update_available: bool,
    channel: sbproxy_config::UpdateChannel,
    targeted: bool,
    auto: bool,
) -> SwapDecision {
    if auto {
        return SwapDecision::AutoReportOnly;
    }
    if pin == PinState::ExternallyManaged {
        return SwapDecision::ManagedElsewhere;
    }
    let frozen = pin == PinState::Pinned || channel == sbproxy_config::UpdateChannel::Pinned;
    if frozen && !targeted {
        return SwapDecision::PinnedHold;
    }
    if !update_available {
        return SwapDecision::UpToDate;
    }
    SwapDecision::Eligible
}

/// Classify how the running `sbproxy` binary was installed, from its
/// path. Homebrew and distro package prefixes are externally managed (the
/// package manager owns the file); anything else (a `curl | sh` install
/// into `~/.local/bin`, `/usr/local/bin`, a container, or a dev build) is
/// treated as channel-tracking and swap-eligible.
fn classify_self_install(exe: &std::path::Path) -> PinState {
    let text = exe.to_string_lossy();
    // Homebrew (Intel + Apple Silicon) and Linuxbrew formula prefixes.
    let brew =
        text.contains("/Cellar/") || text.contains("/homebrew/") || text.contains("/linuxbrew/");
    // apt / dpkg install the binary into the distro-owned /usr (or /bin)
    // tree. /usr/local is operator-owned by the FHS, so it stays
    // swap-eligible.
    let distro = (text.starts_with("/usr/bin/") || text.starts_with("/bin/"))
        && !text.starts_with("/usr/local/");
    if brew || distro {
        PinState::ExternallyManaged
    } else {
        PinState::Tracking
    }
}

/// Classify how an engine binary is obtained on this host. A binary on
/// `PATH` is operator-installed (brew / apt / manual) and never
/// overwritten; otherwise the managed runtime falls back to the pinned
/// prebuilt release it fetches into the cache.
fn engine_pin_state(program: &str) -> PinState {
    if sbproxy_model_host::resolve_on_path(program).is_some() {
        PinState::ExternallyManaged
    } else {
        PinState::Pinned
    }
}

/// The PATH program name for an engine key.
fn engine_program(engine: &str) -> &'static str {
    match engine {
        "vllm" => "vllm",
        _ => "llama-server",
    }
}

/// Classify a cached model from its freshness `tracking` label: a pinned
/// revision is held, a moving ref is swap-eligible (a re-pull chases the
/// upstream head).
fn model_pin_state(tracking: &str) -> PinState {
    if tracking == "moving-ref" {
        PinState::Tracking
    } else {
        PinState::Pinned
    }
}

/// A planned engine prebuilt swap: which engine, the target release tag,
/// the expected sha256 when a digest is known for the tag, and the cache
/// root the binary is published under. The applier seam fetches, verifies,
/// and atomically publishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EngineSwapPlan {
    engine: String,
    program: String,
    tag: String,
    expected_sha256: Option<String>,
    cache_dir: PathBuf,
}

/// Plan an engine swap from a freshness row and a pinning decision, or
/// `None` when nothing should move. Only `llama_cpp` publishes a
/// single-binary prebuilt release the runtime manages; vLLM does not.
fn plan_engine_swap(
    freshness: &EngineFreshness,
    cache_dir: &std::path::Path,
    decision: SwapDecision,
) -> Option<EngineSwapPlan> {
    if decision != SwapDecision::Eligible || freshness.engine != "llama_cpp" {
        return None;
    }
    let tag = freshness.latest_release.clone()?;
    Some(EngineSwapPlan {
        engine: freshness.engine.to_string(),
        program: engine_program(freshness.engine).to_string(),
        // A vendored digest exists only for the default pinned tag; a
        // newer tag has no built-in digest, so it is fetched unverified
        // unless the operator supplies `engines.llama_cpp.acquire.sha256`.
        expected_sha256: None,
        tag,
        cache_dir: cache_dir.to_path_buf(),
    })
}

/// A planned binary self-update: the target version and the path of the
/// binary to replace. The release asset URL + digest are resolved by the
/// applier seam at apply time (they come from the GitHub release feed).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SelfUpdatePlan {
    target_version: String,
    dest: PathBuf,
}

/// Plan a self-update from the binary's freshness row and a pinning
/// decision, or `None` when the binary should not move.
fn plan_self_update(
    freshness: &SelfFreshness,
    dest: &std::path::Path,
    decision: SwapDecision,
) -> Option<SelfUpdatePlan> {
    if decision != SwapDecision::Eligible {
        return None;
    }
    let target_version = freshness.latest.clone()?;
    Some(SelfUpdatePlan {
        target_version,
        dest: dest.to_path_buf(),
    })
}

/// A planned model re-pull: the catalog id, HF repo, and revision to
/// re-fetch through the existing weight manager.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelRepullPlan {
    id: String,
    hf_repo: String,
    revision: String,
}

/// Plan a model re-pull from its freshness row and a pinning decision.
fn plan_model_repull(
    freshness: &ModelFreshness,
    decision: SwapDecision,
) -> Option<ModelRepullPlan> {
    if decision != SwapDecision::Eligible {
        return None;
    }
    Some(ModelRepullPlan {
        id: freshness.id.clone(),
        hf_repo: freshness.hf_repo.clone(),
        revision: freshness.revision.clone(),
    })
}

/// The release-archive base name for a host, matching the naming
/// `scripts/install.sh` uses: `sbproxy_<os>_<arch>.tar.gz` with `os` in
/// {linux, darwin} and `arch` in {amd64, arm64}. `Err` when the host is
/// one no prebuilt binary is published for (Intel macOS).
fn self_update_asset_name(os: &str, arch: &str) -> anyhow::Result<String> {
    let os_tag = match os {
        "linux" => "linux",
        "macos" => "darwin",
        other => anyhow::bail!("no prebuilt sbproxy binary for os '{other}'"),
    };
    let arch_tag = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => anyhow::bail!("no prebuilt sbproxy binary for arch '{other}'"),
    };
    if os_tag == "darwin" && arch_tag == "amd64" {
        anyhow::bail!(
            "no prebuilt sbproxy binary for darwin/amd64 (Intel Mac); build from source or run under Docker"
        );
    }
    Ok(format!("sbproxy_{os_tag}_{arch_tag}.tar.gz"))
}

/// The side-effecting half of `sbproxy update`: fetch, verify, and swap.
/// Split from the pure planners so the decision logic is unit-tested with
/// no network, and the real network + filesystem work is exercised only
/// on a live run (mirroring how the freshness report shipped ahead of the
/// acting half).
trait UpdateApplier {
    /// Fetch, verify, and publish an engine prebuilt swap. Returns the
    /// path to the newly published binary.
    fn apply_engine_swap(&self, plan: &EngineSwapPlan) -> anyhow::Result<PathBuf>;
    /// Fetch, verify, and atomically replace the running binary.
    fn apply_self_update(&self, plan: &SelfUpdatePlan) -> anyhow::Result<()>;
    /// Re-pull a model's weights through the existing weight manager.
    fn apply_model_repull(&self, plan: &ModelRepullPlan) -> anyhow::Result<()>;
}

/// The production applier: real network fetches, sha256 verification, and
/// atomic filesystem swaps.
struct RealUpdateApplier;

impl UpdateApplier for RealUpdateApplier {
    fn apply_engine_swap(&self, plan: &EngineSwapPlan) -> anyhow::Result<PathBuf> {
        #[cfg(feature = "model-weights")]
        {
            let path = sbproxy_model_host::ensure_llama_server_blocking(
                &plan.cache_dir,
                &plan.tag,
                sbproxy_model_host::EngineAccel::Auto,
                plan.expected_sha256.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("acquire {} {}: {e}", plan.engine, plan.tag))?;
            Ok(path)
        }
        #[cfg(not(feature = "model-weights"))]
        {
            let _ = plan;
            anyhow::bail!(
                "this build has no model-weights feature; rebuild with it to fetch engine prebuilts"
            )
        }
    }

    fn apply_self_update(&self, plan: &SelfUpdatePlan) -> anyhow::Result<()> {
        let asset = self_update_asset_name(std::env::consts::OS, std::env::consts::ARCH)?;
        let base = format!(
            "https://github.com/{SBPROXY_RELEASE_REPO}/releases/download/{}",
            plan.target_version
        );
        let archive_url = format!("{base}/{asset}");
        let sha_url = format!("{archive_url}.sha256");
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()?;
        // Stage under the destination directory so the final rename is a
        // same-filesystem atomic move.
        let dir = plan
            .dest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("binary path has no parent directory"))?;
        let staging = dir.join(format!(".sbproxy-update-{}", std::process::id()));
        std::fs::create_dir_all(&staging)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
        let result = self_update_into(&client, &archive_url, &sha_url, &staging, &plan.dest);
        let _ = std::fs::remove_dir_all(&staging);
        result
    }

    fn apply_model_repull(&self, plan: &ModelRepullPlan) -> anyhow::Result<()> {
        // Re-pull the exact catalog artifact for this model id through the
        // existing weight manager (the same path as `sbproxy models pull
        // <id>`), which re-resolves, fetches, and verifies it.
        let pull = ModelsPullArgs {
            models: vec![plan.id.clone()],
            all: false,
            variant: None,
            engine: ModelEngineArg::Auto,
            catalog_file: None,
            cache_dir: None,
            offline: false,
            format: OutputFormat::Text,
        };
        let code = handle_models_pull(&pull, None)?;
        if code != 0 {
            anyhow::bail!("re-pull of {} exited {code}", plan.id);
        }
        Ok(())
    }
}

/// Download the release archive + its published sha256, verify, extract
/// the `sbproxy` binary, and atomically replace `dest`.
fn self_update_into(
    client: &reqwest::blocking::Client,
    archive_url: &str,
    sha_url: &str,
    staging: &std::path::Path,
    dest: &std::path::Path,
) -> anyhow::Result<()> {
    let bytes = client
        .get(archive_url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| anyhow::anyhow!("download {archive_url}: {e}"))?
        .bytes()
        .map_err(|e| anyhow::anyhow!("read {archive_url}: {e}"))?;
    let archive_path = staging.join("sbproxy.tar.gz");
    std::fs::write(&archive_path, &bytes)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", archive_path.display()))?;

    // Fetch + verify the published checksum. Every release publishes it;
    // its absence is a hard failure (the same posture as install.sh).
    let sha_text = client
        .get(sha_url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| anyhow::anyhow!("fetch checksum {sha_url}: {e}"))?
        .text()
        .map_err(|e| anyhow::anyhow!("read checksum {sha_url}: {e}"))?;
    let expected = sha_text
        .split_whitespace()
        .next()
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("published checksum is malformed: '{sha_text}'"))?;
    sbproxy_model_host::weights::verify_sha256(&archive_path, &expected)
        .map_err(|e| anyhow::anyhow!("checksum verify failed: {e}"))?;

    // Extract (shell out to `tar`, as the engine release path does).
    let status = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(staging)
        .status()
        .map_err(|e| anyhow::anyhow!("tar: {e}"))?;
    if !status.success() {
        anyhow::bail!("tar extract of {} failed", archive_path.display());
    }
    let staged_binary = staging.join("sbproxy");
    if !staged_binary.is_file() {
        anyhow::bail!("sbproxy binary not found in the extracted release");
    }
    atomic_replace_binary(&staged_binary, dest)
}

/// Atomically replace `dest` with `src`: copy `src` to a temp file in the
/// destination directory, mark it executable, then rename over `dest`. On
/// unix a running binary can be replaced while it executes; on Windows a
/// rename over the running image fails, so a Windows self-update needs the
/// rename-self-aside dance this build does not implement.
fn atomic_replace_binary(src: &std::path::Path, dest: &std::path::Path) -> anyhow::Result<()> {
    let dir = dest
        .parent()
        .ok_or_else(|| anyhow::anyhow!("binary path has no parent directory"))?;
    let tmp = dir.join(format!(".sbproxy-new-{}", std::process::id()));
    std::fs::copy(src, &tmp).map_err(|e| anyhow::anyhow!("stage new binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow::anyhow!("chmod staged binary: {e}"))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("replace {}: {e}", dest.display())
    })?;
    Ok(())
}

/// Inputs to the acting half that the freshness report does not carry.
struct UpdatePlanContext {
    channel: sbproxy_config::UpdateChannel,
    targeted_self: bool,
    targeted_engines: bool,
    targeted_models: bool,
    assume_yes: bool,
    cache_dir: Option<PathBuf>,
}

/// Drive the acting half: for each artifact in the report run the pinning
/// gate, and when eligible confirm + apply through the seam. Never mutates
/// a pinned or externally-managed artifact without an explicit targeted
/// run. Returns exit code 1 when any apply failed.
fn apply_updates(
    report: &UpdateReport,
    ctx: &UpdatePlanContext,
    applier: &dyn UpdateApplier,
) -> anyhow::Result<i32> {
    println!("\napplying updates");
    let mut applied = 0u32;
    let mut failures = 0u32;

    if let Some(freshness) = &report.self_ {
        match std::env::current_exe() {
            Ok(exe) => {
                let decision = decide_swap(
                    classify_self_install(&exe),
                    freshness.update_available,
                    ctx.channel,
                    ctx.targeted_self,
                    false,
                );
                report_decision("sbproxy", decision);
                if let Some(plan) = plan_self_update(freshness, &exe, decision) {
                    if confirm_swap(
                        &format!("replace this binary with sbproxy {}", plan.target_version),
                        ctx.assume_yes,
                    ) {
                        match applier.apply_self_update(&plan) {
                            Ok(()) => {
                                applied += 1;
                                println!("  sbproxy -> {}", plan.target_version);
                            }
                            Err(e) => {
                                failures += 1;
                                eprintln!("  sbproxy self-update failed: {e}");
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("  sbproxy: cannot locate the running binary: {e}; skipping"),
        }
    }

    if let Some(engines) = &report.engines {
        let cache = model_cache_root(ctx.cache_dir.as_deref());
        for engine in engines {
            let decision = decide_swap(
                engine_pin_state(engine_program(engine.engine)),
                engine.update_available,
                ctx.channel,
                ctx.targeted_engines,
                false,
            );
            report_decision(engine.engine, decision);
            if let Some(plan) = plan_engine_swap(engine, &cache, decision) {
                if confirm_swap(
                    &format!("fetch and swap {} to {}", plan.engine, plan.tag),
                    ctx.assume_yes,
                ) {
                    match applier.apply_engine_swap(&plan) {
                        Ok(path) => {
                            applied += 1;
                            println!("  {} -> {} ({})", plan.engine, plan.tag, path.display());
                        }
                        Err(err) => {
                            failures += 1;
                            eprintln!("  {} swap failed: {err}", plan.engine);
                        }
                    }
                }
            }
        }
    }

    if let Some(models) = &report.models {
        for model in models {
            let pin = model_pin_state(model.tracking);
            // A moving-ref model is treated as potentially behind upstream
            // (the freshness classifies moving vs pinned; the upstream-head
            // comparison is a seam), so it is offered for re-pull.
            let update_available = pin == PinState::Tracking;
            let decision = decide_swap(
                pin,
                update_available,
                ctx.channel,
                ctx.targeted_models,
                false,
            );
            report_decision(&model.id, decision);
            if let Some(plan) = plan_model_repull(model, decision) {
                if confirm_swap(
                    &format!("re-pull {} ({}@{})", plan.id, plan.hf_repo, plan.revision),
                    ctx.assume_yes,
                ) {
                    match applier.apply_model_repull(&plan) {
                        Ok(()) => {
                            applied += 1;
                            println!("  re-pulled {}", plan.id);
                        }
                        Err(err) => {
                            failures += 1;
                            eprintln!("  {} re-pull failed: {err}", plan.id);
                        }
                    }
                }
            }
        }
    }

    println!("\n{applied} applied, {failures} failed");
    Ok(if failures > 0 { 1 } else { 0 })
}

/// Print a one-line reason for the pinning gate's non-eligible verdicts,
/// so a report-and-hold outcome is visible in the acting output.
fn report_decision(name: &str, decision: SwapDecision) {
    match decision {
        SwapDecision::Eligible => {}
        SwapDecision::UpToDate => println!("  {name}: up to date"),
        SwapDecision::ManagedElsewhere => {
            println!("  {name}: managed elsewhere (PATH / brew / apt); skipping")
        }
        SwapDecision::PinnedHold => {
            println!("  {name}: pinned; target it explicitly to move it, or set update.channel")
        }
        SwapDecision::AutoReportOnly => println!("  {name}: report only (update.auto)"),
    }
}

/// Interactive yes/no confirmation. Returns true immediately when
/// `assume_yes` (`--yes`) is set; otherwise prompts on stderr and reads a
/// line from stdin. A non-tty / EOF answer is treated as "no".
fn confirm_swap(action: &str, assume_yes: bool) -> bool {
    use std::io::Write;
    if assume_yes {
        return true;
    }
    eprint!("  {action}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
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
        if !model_is_cached(&root, id, entry) {
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

fn handle_cluster_subcommand(cmd: &ClusterCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        ClusterSub::Init(args) => handle_cluster_init(args),
        ClusterSub::Token(token) => match &token.sub {
            ClusterTokenSub::Create(args) => handle_cluster_token_create(args),
        },
        ClusterSub::Enroll(args) => handle_cluster_enroll(args),
        ClusterSub::Status(args) => handle_cluster_status(args),
    }
}

fn handle_cluster_init(args: &ClusterInitArgs) -> anyhow::Result<i32> {
    let roles = cluster_roles(
        &args.roles,
        &[ClusterRoleArg::Gateway, ClusterRoleArg::Authority],
    );
    let labels = parse_cluster_labels(&args.labels)?;
    let authority = sbproxy_mesh::enrollment::EnrollmentAuthority::initialize(
        &args.directory,
        sbproxy_mesh::enrollment::AuthorityInit {
            cluster_id: args.cluster_id.clone(),
            node_id: args.node_id.clone(),
            roles,
            labels,
            server_name: args.server_name.clone(),
        },
    )?;
    match args.format {
        OutputFormat::Text => {
            println!(
                "cluster authority initialized at {}",
                authority.directory().display()
            );
            println!("node id: {}", authority.identity().document.node_id);
            println!("CA: {}", authority.directory().join("ca.pem").display());
            println!(
                "gossip key: {}",
                authority.directory().join("gossip.key").display()
            );
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "command": "cluster.init",
                "directory": authority.directory(),
                "cluster_id": authority.identity().document.cluster_id,
                "node_id": authority.identity().document.node_id,
                "ca_file": authority.directory().join("ca.pem"),
                "node_cert_file": authority.directory().join("node.pem"),
                "node_key_file": authority.directory().join("node-key.pem"),
                "gossip_key_file": authority.directory().join("gossip.key"),
                "identity_file": authority.directory().join("identity.json"),
            }))?
        ),
    }
    Ok(0)
}

fn handle_cluster_token_create(args: &ClusterTokenCreateArgs) -> anyhow::Result<i32> {
    let authority = sbproxy_mesh::enrollment::EnrollmentAuthority::open(&args.directory)?;
    let roles = cluster_roles(&args.roles, &[ClusterRoleArg::Worker]);
    let labels = parse_cluster_labels(&args.labels)?;
    let issued = authority.create_token(
        sbproxy_mesh::enrollment::EnrollmentTokenConstraints {
            allowed_roles: roles,
            labels,
        },
        std::time::Duration::from_secs(args.ttl_secs),
    )?;
    match args.format {
        OutputFormat::Text => println!("{}", issued.token()),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "command": "cluster.token.create",
                "token": issued.token(),
                "token_id": issued.token_id(),
                "expires_at_unix_secs": issued.expires_at_unix_secs(),
                "constraints": issued.constraints(),
            }))?
        ),
    }
    Ok(0)
}

fn handle_cluster_enroll(args: &ClusterEnrollArgs) -> anyhow::Result<i32> {
    let mut endpoint = reqwest::Url::parse(&args.url)
        .map_err(|error| anyhow::anyhow!("invalid cluster authority URL: {error}"))?;
    match endpoint.scheme() {
        "https" => {}
        "http" if args.allow_insecure_http => {}
        "http" => anyhow::bail!(
            "plaintext enrollment requires --allow-insecure-http and a development authority"
        ),
        scheme => anyhow::bail!("cluster authority URL must use https, not {scheme:?}"),
    }
    endpoint.set_path(sbproxy_core::admin_cluster::ENROLL_PATH);
    endpoint.set_query(None);
    endpoint.set_fragment(None);

    let roles = cluster_roles(&args.roles, &[ClusterRoleArg::Worker]);
    let labels = parse_cluster_labels(&args.labels)?;
    let worker =
        sbproxy_mesh::enrollment::WorkerEnrollment::generate(&args.node_id, &args.server_name)?;
    let request = worker.request(args.token.clone(), roles, labels);
    let mut client = reqwest::Client::builder();
    if let Some(path) = args.ca_cert.as_ref() {
        let pem = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("read enrollment CA certificate {path:?}: {error}"))?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .map_err(|error| anyhow::anyhow!("parse enrollment CA certificate: {error}"))?;
        client = client.add_root_certificate(certificate);
    }
    let client = client.build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let response = client.post(endpoint).json(&request).send().await?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > 256 * 1024)
        {
            anyhow::bail!("cluster authority returned an oversized response");
        }
        let body = response.bytes().await?;
        if body.len() > 256 * 1024 {
            anyhow::bail!("cluster authority returned an oversized response");
        }
        if !status.is_success() {
            let code = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("code")
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "request_failed".to_string());
            anyhow::bail!("cluster enrollment failed with HTTP {status} ({code})");
        }
        serde_json::from_slice::<sbproxy_mesh::enrollment::EnrollmentResponse>(&body)
            .map_err(anyhow::Error::from)
    })?;
    let installed =
        sbproxy_mesh::enrollment::install_worker_enrollment(&args.output, worker, response)?;
    match args.format {
        OutputFormat::Text => {
            println!("cluster identity installed at {}", args.output.display());
            println!("node id: {}", installed.identity.node_id);
            println!("certificate: {}", installed.node_cert_file.display());
            println!("private key: {}", installed.node_key_file.display());
            println!("CA: {}", installed.ca_file.display());
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "command": "cluster.enroll",
                "directory": args.output,
                "cluster_id": installed.identity.cluster_id,
                "node_id": installed.identity.node_id,
                "roles": installed.identity.roles,
                "labels": installed.identity.labels,
                "node_cert_file": installed.node_cert_file,
                "node_key_file": installed.node_key_file,
                "ca_file": installed.ca_file,
                "gossip_key_file": installed.gossip_key_file,
                "identity_file": installed.identity_file,
                "authority_verifying_key_file": installed.authority_verifying_key_file,
            }))?
        ),
    }
    Ok(0)
}

fn handle_cluster_status(args: &ClusterStatusArgs) -> anyhow::Result<i32> {
    let status = admin_request_json(
        &args.admin,
        Some("http://127.0.0.1:9090"),
        reqwest::Method::GET,
        sbproxy_core::admin_cluster::STATUS_PATH,
        None,
    )?;
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Text => {
            let cluster_id = status
                .get("cluster_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let mode = status
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let summary = status.get("summary").unwrap_or(&serde_json::Value::Null);
            println!(
                "cluster {cluster_id} ({mode}): {} nodes, {} healthy, {} degraded, {} unhealthy, {} eligible workers",
                json_u64(summary, "total_nodes"),
                json_u64(summary, "healthy_nodes"),
                json_u64(summary, "degraded_nodes"),
                json_u64(summary, "unhealthy_nodes"),
                json_u64(summary, "eligible_workers"),
            );
            if let Some(nodes) = status.get("nodes").and_then(serde_json::Value::as_array) {
                for node in nodes {
                    let node_id = node
                        .get("node_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let health = node
                        .get("health")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let membership = node
                        .get("membership_state")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let eligibility = if node
                        .get("model_eligible")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        "eligible"
                    } else {
                        "excluded"
                    };
                    let reasons = node
                        .get("unhealthy_reasons")
                        .and_then(serde_json::Value::as_array)
                        .map(|reasons| {
                            reasons
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .filter(|reasons| !reasons.is_empty())
                        .map(|reasons| format!(" [{reasons}]"))
                        .unwrap_or_default();
                    println!(
                        "{node_id}\thealth={health}\tmembership={membership}\tmodel={eligibility}{reasons}"
                    );
                }
            }
        }
    }
    Ok(0)
}

fn json_u64(value: &serde_json::Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn cluster_roles(
    configured: &[ClusterRoleArg],
    defaults: &[ClusterRoleArg],
) -> BTreeSet<sbproxy_mesh::ClusterNodeRole> {
    let roles = if configured.is_empty() {
        defaults
    } else {
        configured
    };
    roles.iter().copied().map(Into::into).collect()
}

fn parse_cluster_labels(labels: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for label in labels {
        let (key, value) = label
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("cluster label {label:?} must use key=value form"))?;
        if key.is_empty() || value.is_empty() {
            anyhow::bail!("cluster label {label:?} must have a nonempty key and value");
        }
        if parsed.insert(key.to_string(), value.to_string()).is_some() {
            anyhow::bail!("cluster label key {key:?} was provided more than once");
        }
    }
    Ok(parsed)
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
                // WOR-1869: `headers` maps (telemetry export, alert
                // webhook channels) carry auth tokens under arbitrary
                // vendor names (x-honeycomb-team, x-scope-orgid), so a
                // key-name allowlist cannot catch them. Mask every
                // literal string directly under a `headers` map;
                // references stay visible as pointers.
                if k == "headers" {
                    if let serde_json::Value::Object(headers) = v {
                        for header_value in headers.values_mut() {
                            match header_value {
                                serde_json::Value::String(s) => {
                                    if !is_secret_reference(s) {
                                        *s = "***MASKED***".to_string();
                                    }
                                }
                                // Transform-style header blocks nest
                                // add / set maps; keep walking those.
                                other => mask_secrets(other),
                            }
                        }
                        continue;
                    }
                }
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
fn load_and_validate(
    path: &std::path::Path,
) -> anyhow::Result<(sbproxy_config::ConfigFile, Option<String>)> {
    let path_str = path.to_string_lossy();
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))?;
    let compiled = sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
    // WOR-1815: run the boot-time module constructors too, so `plan`
    // and `apply` catch a config that compiles but cannot boot. The
    // error is returned as data rather than an abort so the callers
    // can fold it into their findings report: `plan` renders it next
    // to the other semantic findings and exits 3, the same channel
    // the validate-rule findings use.
    let construction_error = sbproxy_core::pipeline::CompiledPipeline::from_config(compiled)
        .err()
        .map(|e| format!("{e:#}"));
    let config = serde_yaml::from_str::<sbproxy_config::ConfigFile>(&yaml)
        .map_err(|e| anyhow::anyhow!("failed to parse '{path_str}' as ConfigFile: {e}"))?;
    Ok((config, construction_error))
}

/// Fold a boot-time construction failure into a plan report as an
/// error-severity finding, so `plan` and `apply` surface it through
/// the same findings channel (and exit code 3) as the semantic
/// validation rules.
fn push_construction_finding(report: &mut sbproxy_config::PlanReport, message: &str) {
    report.findings.push(sbproxy_config::PlanFinding {
        severity: sbproxy_config::Severity::Error,
        rule_id: "module-construction".to_string(),
        path: "origins".to_string(),
        message: format!("a module failed to construct (this would fail at boot): {message}"),
    });
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
) -> anyhow::Result<(
    sbproxy_config::ConfigFile,
    sbproxy_config::ConfigFile,
    Option<String>,
)> {
    let config = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    let (proposed, construction_error) = load_and_validate(config)?;
    // The baseline is the operator's current state; only the proposed
    // side's construction result gates the plan.
    let baseline = match args.against.as_deref() {
        Some(p) => load_and_validate(p)?.0,
        None => empty_config_file(),
    };
    Ok((baseline, proposed, construction_error))
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
    let (baseline, proposed, construction_error) = load_plan_inputs(args)?;
    let config_path = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    let mut report = collect_plan_findings(config_path, &baseline, &proposed);
    if let Some(msg) = construction_error.as_deref() {
        push_construction_finding(&mut report, msg);
    }
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
    let (proposed, construction_error) = load_and_validate(yaml_path)?;
    let baseline = empty_config_file();
    let mut report = sbproxy_config::plan(&baseline, &proposed);
    if let Some(msg) = construction_error.as_deref() {
        push_construction_finding(&mut report, msg);
    }
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

    let (proposed, construction_error) = load_and_validate(&yaml_path_buf)?;
    // Recompute the plan against the same baseline shape as plan
    // time. We do not yet have an admin-socket "live baseline"
    // surface, so the on-disk baseline is "the empty config" by
    // default. The operator can override this with SB_APPLY_BASELINE
    // pointing at a YAML file.
    let baseline = match std::env::var("SB_APPLY_BASELINE").ok() {
        Some(b) => load_and_validate(std::path::Path::new(&b))?.0,
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

    let mut report = sbproxy_config::plan(&baseline, &proposed);
    if let Some(msg) = construction_error.as_deref() {
        push_construction_finding(&mut report, msg);
    }
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

    fn pull_catalog() -> sbproxy_model_host::Catalog {
        sbproxy_model_host::Catalog::from_yaml(
            "schema_version: 2\ncatalog_revision: cli-pull-fixture\nmodels:\n  boot:\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    context_length: 1024\n    pull: on_boot\n    variants:\n      - id: cpu\n        format: gguf\n        quant: Q4\n        engines: [llama_cpp]\n        source: file:/tmp/boot.gguf\n        revision: fixture\n        files:\n          - path: boot.gguf\n            sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n            size_bytes: 1\n        requirements:\n          accelerators: [cpu]\n        stability: preview\n        certification: cli-fixture\n  demand:\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    context_length: 1024\n    pull: on_demand\n    variants:\n      - id: cpu\n        format: gguf\n        quant: Q4\n        engines: [llama_cpp]\n        source: file:/tmp/demand.gguf\n        revision: fixture\n        files:\n          - path: demand.gguf\n            sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n            size_bytes: 1\n        requirements:\n          accelerators: [cpu]\n        stability: preview\n        certification: cli-fixture\n",
        )
        .unwrap()
    }

    fn pull_args() -> ModelsPullArgs {
        ModelsPullArgs {
            models: Vec::new(),
            all: false,
            variant: None,
            engine: ModelEngineArg::Auto,
            catalog_file: None,
            cache_dir: None,
            offline: false,
            format: OutputFormat::Text,
        }
    }

    fn selected_models(selections: Vec<PullSelection>) -> Vec<String> {
        selections
            .into_iter()
            .map(|selection| selection.model)
            .collect()
    }

    #[test]
    fn models_pull_defaults_to_boot_and_supports_explicit_or_all_selection() {
        let catalog = pull_catalog();
        assert_eq!(
            selected_models(selected_pull_models(&pull_args(), &catalog, None, None).unwrap()),
            ["boot"]
        );

        let mut explicit = pull_args();
        explicit.models = vec!["demand".to_string()];
        assert_eq!(
            selected_models(selected_pull_models(&explicit, &catalog, None, None).unwrap()),
            ["demand"]
        );

        let mut all = pull_args();
        all.all = true;
        assert_eq!(
            selected_models(selected_pull_models(&all, &catalog, None, None).unwrap()),
            ["boot", "demand"]
        );

        let configured: sbproxy_model_host::ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: demand\n").unwrap();
        assert_eq!(
            selected_models(
                selected_pull_models(&pull_args(), &catalog, Some(&configured), None).unwrap()
            ),
            ["demand", "boot"]
        );

        let canonical: sbproxy_config::ModelHostControlConfig = serde_yaml::from_str(
            "deployments:\n  coder:\n    model: demand\n    variant: cpu\n    engine: llama_cpp\n",
        )
        .unwrap();
        let selected = selected_pull_models(&pull_args(), &catalog, None, Some(&canonical))
            .expect("canonical deployment selection");
        assert_eq!(selected_models(selected.clone()), ["demand", "boot"]);
        assert_eq!(selected[0].variant.as_deref(), Some("cpu"));
        assert_eq!(
            selected[0].engine,
            sbproxy_model_host::EngineChoice::LlamaCpp
        );
        assert!(selected[0].configured);
    }

    #[test]
    fn models_pull_variant_requires_one_explicit_model() {
        let catalog = pull_catalog();
        let mut args = pull_args();
        args.variant = Some("cpu".to_string());
        assert!(selected_pull_models(&args, &catalog, None, None)
            .unwrap_err()
            .to_string()
            .contains("exactly one"));
    }

    #[test]
    fn models_pull_cli_surface_parses_exact_variant_and_offline_mode() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "models",
            "pull",
            "boot",
            "--variant",
            "cpu",
            "--engine",
            "llama-cpp",
            "--offline",
            "-f",
            "sb.yml",
        ])
        .unwrap();
        assert_eq!(cli.globals.config, Some(PathBuf::from("sb.yml")));
        let Some(Cmd::Models(ModelsCmd {
            sub: Some(ModelsSub::Pull(args)),
        })) = cli.cmd
        else {
            panic!("models pull parsed to the wrong command");
        };
        assert_eq!(args.models, ["boot"]);
        assert_eq!(args.variant.as_deref(), Some("cpu"));
        assert!(matches!(args.engine, ModelEngineArg::LlamaCpp));
        assert!(args.offline);
    }

    #[test]
    fn models_pull_offline_file_source_publishes_verified_snapshot() {
        let source = temp_config("demo weights\n");
        let cache = source.with_extension("model-cache");
        let catalog_path = temp_config(&format!(
            "schema_version: 2\ncatalog_revision: cli-offline-fixture\nmodels:\n  offline:\n    params: 0.000000013B\n    license: apache-2.0\n    family: fixture\n    context_length: 1024\n    pull: manual\n    variants:\n      - id: demo\n        format: gguf\n        quant: Q4_K_M\n        engines: [llama_cpp]\n        source: file:{}\n        revision: local-v1\n        files:\n          - path: model.gguf\n            sha256: 729590a45b549db7a1631f3d220b794a8cd7c9042a43064dd0dcc80c7cb98b5e\n            size_bytes: 13\n        requirements:\n          accelerators: [cpu, metal, cuda]\n          min_memory_bytes: 1\n        stability: preview\n        certification: cli-offline-fixture\n",
            source.display()
        ));
        let catalog_filename = catalog_path.file_name().unwrap().to_string_lossy();
        let config_path = temp_config(&format!(
            "origins:\n  ai.local:\n    action:\n      type: ai_proxy\n      providers:\n        - name: local\n          serve:\n            catalog_file: {catalog_filename}\n            cache_dir: {}\n            cache_budget_gib: 0\n            models:\n              - model: offline\n                variant: demo\n                engine: llama_cpp\n                pinned: true\n",
            cache.display()
        ));
        let args = ModelsPullArgs {
            models: Vec::new(),
            all: false,
            variant: None,
            engine: ModelEngineArg::Auto,
            catalog_file: None,
            cache_dir: None,
            offline: true,
            format: OutputFormat::Json,
        };

        assert_eq!(handle_models_pull(&args, Some(&config_path)).unwrap(), 0);
        let catalog = load_models_catalog(Some(&catalog_path)).unwrap();
        assert!(model_is_cached(
            &cache,
            "offline",
            catalog.get("offline").unwrap()
        ));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_dir_all(cache);
    }

    #[test]
    fn doctor_resolves_catalog_relative_to_config_directory() {
        let catalog_path = temp_config(
            "models:\n  exact:\n    hf_repo: Org/Exact\n    quants: [Q4_K_M]\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    min_vram_hint_gib: 1.0\n",
        );
        let filename = catalog_path.file_name().unwrap().to_string_lossy();
        let config = format!(
            "origins:\n  ai.local:\n    action:\n      providers:\n        - name: local\n          serve:\n            catalog_file: {filename}\n            models:\n              - model: exact\n"
        );

        let (_, catalog) = extract_serve_and_catalog(
            &config,
            catalog_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        )
        .unwrap()
        .unwrap();

        assert!(catalog.get("exact").is_some());
        let _ = std::fs::remove_file(catalog_path);
    }

    #[test]
    fn run_name_defaults_to_catalog_id_and_rejects_raw_refs() {
        // A plain catalog id is its own name.
        assert_eq!(resolve_run_name("qwen3-14b", None).unwrap(), "qwen3-14b");
        // Raw references bypass the certified artifact contract and are
        // rejected even when a client-facing alias is supplied.
        assert!(resolve_run_name("hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", None).is_err());
        assert!(resolve_run_name("hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", Some("coder")).is_err());
        assert_eq!(
            resolve_run_name("qwen2.5-0.5b-instruct", Some("coder")).unwrap(),
            "coder"
        );
        // An empty name is rejected.
        assert!(resolve_run_name("qwen3-14b", Some("  ")).is_err());
    }

    #[test]
    fn run_prepares_canonical_warm_managed_config() {
        let args = RunArgs {
            model: "qwen2.5-0.5b-instruct".to_string(),
            name: Some("coder".to_string()),
            port: 8080,
            engine: "auto".to_string(),
            accel: "auto".to_string(),
            cache_dir: None,
            variant: Some("q4_k_m".to_string()),
            admin_port: Some(9091),
            dry_run: false,
        };
        let prepared = prepare_run(&args).expect("prepare canonical run");
        let yaml: serde_yaml::Value = serde_yaml::from_str(&prepared.yaml).unwrap();
        assert_eq!(prepared.name, "coder");
        assert_eq!(prepared.artifact.variant_id, "q4_k_m");
        assert_eq!(
            yaml["proxy"]["model_host"]["deployments"]["local"]["warm"],
            true
        );
        assert_eq!(
            yaml["origins"]["localhost"]["action"]["providers"][0]["provider_type"],
            "managed_model"
        );
        assert_eq!(yaml["proxy"]["admin"]["port"], 9091);
        assert_eq!(prepared.admin_password.len(), 64);
        assert!(!prepared.yaml.contains("serve:"));
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
    fn update_pinned_never_swaps_moving_ref_is_eligible() {
        use sbproxy_config::UpdateChannel::Stable;
        // A moving-ref artifact on the stable channel with an available
        // update is swap-eligible.
        assert_eq!(
            decide_swap(PinState::Tracking, true, Stable, false, false),
            SwapDecision::Eligible
        );
        // The same artifact with nothing newer is up to date.
        assert_eq!(
            decide_swap(PinState::Tracking, false, Stable, false, false),
            SwapDecision::UpToDate
        );
        // A pinned artifact holds on a blanket run, even with an update
        // available, and is never swapped.
        assert_eq!(
            decide_swap(PinState::Pinned, true, Stable, false, false),
            SwapDecision::PinnedHold
        );
        // An explicit targeted run may move the pin.
        assert_eq!(
            decide_swap(PinState::Pinned, true, Stable, true, false),
            SwapDecision::Eligible
        );
        // Externally managed (PATH / brew / apt) is never touched, even
        // when targeted.
        assert_eq!(
            decide_swap(PinState::ExternallyManaged, true, Stable, true, false),
            SwapDecision::ManagedElsewhere
        );
    }

    #[test]
    fn update_pinned_channel_freezes_untargeted_tracking() {
        use sbproxy_config::UpdateChannel::{Pinned, Stable};
        // The `pinned` channel holds even a moving-ref artifact on a
        // blanket run...
        assert_eq!(
            decide_swap(PinState::Tracking, true, Pinned, false, false),
            SwapDecision::PinnedHold
        );
        // ...but a targeted run may still move it.
        assert_eq!(
            decide_swap(PinState::Tracking, true, Pinned, true, false),
            SwapDecision::Eligible
        );
        // On the stable channel the same untargeted moving-ref is eligible.
        assert_eq!(
            decide_swap(PinState::Tracking, true, Stable, false, false),
            SwapDecision::Eligible
        );
    }

    #[test]
    fn update_auto_run_only_reports() {
        use sbproxy_config::UpdateChannel::Stable;
        // A background / auto run never swaps anything, even an eligible
        // tracking artifact on a targeted run.
        assert_eq!(
            decide_swap(PinState::Tracking, true, Stable, true, true),
            SwapDecision::AutoReportOnly
        );
    }

    #[test]
    fn update_classify_self_install() {
        use std::path::Path;
        // Homebrew and Linuxbrew formula prefixes are externally managed.
        assert_eq!(
            classify_self_install(Path::new("/opt/homebrew/Cellar/sbproxy/1.4.0/bin/sbproxy")),
            PinState::ExternallyManaged
        );
        assert_eq!(
            classify_self_install(Path::new("/home/linuxbrew/.linuxbrew/bin/sbproxy")),
            PinState::ExternallyManaged
        );
        // A distro (apt) path under /usr/bin is externally managed.
        assert_eq!(
            classify_self_install(Path::new("/usr/bin/sbproxy")),
            PinState::ExternallyManaged
        );
        // A curl-installed / operator-owned path is channel-tracking.
        assert_eq!(
            classify_self_install(Path::new("/home/rick/.local/bin/sbproxy")),
            PinState::Tracking
        );
        assert_eq!(
            classify_self_install(Path::new("/usr/local/bin/sbproxy")),
            PinState::Tracking
        );
    }

    #[test]
    fn update_engine_swap_plan_only_for_llama_and_eligible() {
        let llama = EngineFreshness {
            engine: "llama_cpp",
            installed: None,
            pinned_release: Some("b9905".to_string()),
            latest_release: Some("b9999".to_string()),
            update_available: true,
        };
        let dir = std::path::Path::new("/cache");
        // Eligible llama_cpp yields a plan targeting the latest tag.
        let plan = plan_engine_swap(&llama, dir, SwapDecision::Eligible).unwrap();
        assert_eq!(plan.engine, "llama_cpp");
        assert_eq!(plan.program, "llama-server");
        assert_eq!(plan.tag, "b9999");
        // A newer tag carries no vendored digest.
        assert_eq!(plan.expected_sha256, None);
        // A non-eligible decision produces no plan.
        assert!(plan_engine_swap(&llama, dir, SwapDecision::PinnedHold).is_none());
        // vLLM has no single-binary prebuilt swap.
        let vllm = EngineFreshness {
            engine: "vllm",
            installed: None,
            pinned_release: None,
            latest_release: None,
            update_available: false,
        };
        assert!(plan_engine_swap(&vllm, dir, SwapDecision::Eligible).is_none());
    }

    #[test]
    fn update_self_update_asset_name_matches_installer() {
        assert_eq!(
            self_update_asset_name("linux", "x86_64").unwrap(),
            "sbproxy_linux_amd64.tar.gz"
        );
        assert_eq!(
            self_update_asset_name("linux", "aarch64").unwrap(),
            "sbproxy_linux_arm64.tar.gz"
        );
        assert_eq!(
            self_update_asset_name("macos", "aarch64").unwrap(),
            "sbproxy_darwin_arm64.tar.gz"
        );
        // Intel macOS and unknown hosts have no published binary.
        assert!(self_update_asset_name("macos", "x86_64").is_err());
        assert!(self_update_asset_name("freebsd", "x86_64").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn update_atomic_replace_binary_swaps_contents_and_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "sbproxy-update-replace-{}-{}",
            std::process::id(),
            random_local_password(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("sbproxy");
        std::fs::write(&dest, b"old-binary").unwrap();
        let src = dir.join("staged");
        std::fs::write(&src, b"new-binary").unwrap();

        atomic_replace_binary(&src, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new-binary");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "replacement is executable");
        // The temp file is renamed away, not left behind.
        assert!(!dir
            .join(format!(".sbproxy-new-{}", std::process::id()))
            .exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn update_acting_swaps_eligible_and_holds_pinned_via_seam() {
        use sbproxy_config::UpdateChannel::Stable;
        use std::cell::RefCell;

        #[derive(Default)]
        struct FakeApplier {
            engine_swaps: RefCell<Vec<String>>,
            self_updates: RefCell<Vec<String>>,
            model_repulls: RefCell<Vec<String>>,
        }
        impl UpdateApplier for FakeApplier {
            fn apply_engine_swap(&self, plan: &EngineSwapPlan) -> anyhow::Result<PathBuf> {
                self.engine_swaps.borrow_mut().push(plan.engine.clone());
                Ok(PathBuf::from("/fake/llama-server"))
            }
            fn apply_self_update(&self, plan: &SelfUpdatePlan) -> anyhow::Result<()> {
                self.self_updates
                    .borrow_mut()
                    .push(plan.target_version.clone());
                Ok(())
            }
            fn apply_model_repull(&self, plan: &ModelRepullPlan) -> anyhow::Result<()> {
                self.model_repulls.borrow_mut().push(plan.id.clone());
                Ok(())
            }
        }

        // A report with one moving-ref model and one pinned model. Only
        // the moving-ref one, on a targeted run, reaches the seam. This
        // path touches neither PATH nor the running-binary path (self and
        // engines are absent), so it is host-independent.
        let report = UpdateReport {
            self_: None,
            engines: None,
            models: Some(vec![
                ModelFreshness {
                    id: "moving".to_string(),
                    hf_repo: "Org/Moving".to_string(),
                    revision: "main".to_string(),
                    tracking: "moving-ref",
                },
                ModelFreshness {
                    id: "pinned".to_string(),
                    hf_repo: "Org/Pinned".to_string(),
                    revision: "v1.0".to_string(),
                    tracking: "pinned",
                },
            ]),
            note: String::new(),
        };
        let ctx = UpdatePlanContext {
            channel: Stable,
            targeted_self: false,
            targeted_engines: false,
            targeted_models: true,
            assume_yes: true,
            cache_dir: None,
        };
        let fake = FakeApplier::default();
        let code = apply_updates(&report, &ctx, &fake).unwrap();
        assert_eq!(code, 0);
        assert_eq!(*fake.model_repulls.borrow(), vec!["moving".to_string()]);
        assert!(fake.self_updates.borrow().is_empty());
        assert!(fake.engine_swaps.borrow().is_empty());
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
                r.status == "cached"
                    || r.status == "not-pulled"
                    || r.status == "preview-incomplete",
                "unexpected status {}",
                r.status
            );
        }
    }

    #[test]
    fn run_config_is_written_with_private_permissions() {
        let root = std::env::temp_dir().join(format!(
            "sbproxy-private-config-{}-{}",
            std::process::id(),
            random_local_password(),
        ));
        let path = root.join("sb.yml");
        write_private_run_config(&path, b"proxy: {}\norigins: {}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_run_directory_removes_credentials_when_the_handler_returns() {
        let root = std::env::temp_dir().join(format!(
            "sbproxy-private-run-dir-{}-{}",
            std::process::id(),
            random_local_password(),
        ));
        let run_dir = PrivateRunDirectory { path: root.clone() };
        let config = run_dir.config_path();
        write_private_run_config(&config, b"admin_password: fixture-secret\n").unwrap();
        assert!(config.exists());

        drop(run_dir);

        assert!(!root.exists());
    }

    #[test]
    fn run_ready_banner_contains_copyable_sdk_and_admin_settings() {
        let banner = run_ready_banner("coder", 8080, "http://127.0.0.1:9090", "fixture-secret");
        assert!(banner.contains("OPENAI_BASE_URL=http://127.0.0.1:8080/v1"));
        assert!(banner.contains("OPENAI_API_KEY=local"));
        assert!(banner.contains("Admin: http://127.0.0.1:9090"));
        assert!(banner.contains("Admin password: fixture-secret"));
        assert!(banner.contains("\"model\":\"coder\""));
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
    fn parses_cluster_init_token_and_enroll_commands() {
        let cli = parse(&[
            "sbproxy",
            "cluster",
            "init",
            "--dir",
            "/var/lib/sbproxy/cluster",
            "--cluster-id",
            "prod-a",
            "--node-id",
            "authority-a",
            "--role",
            "authority",
            "--label",
            "zone=a",
        ]);
        let Some(Cmd::Cluster(ClusterCmd {
            sub: ClusterSub::Init(init),
        })) = cli.cmd
        else {
            panic!("expected cluster init");
        };
        assert_eq!(init.cluster_id, "prod-a");
        assert_eq!(init.roles, vec![ClusterRoleArg::Authority]);

        let cli = parse(&[
            "sbproxy",
            "cluster",
            "token",
            "create",
            "--dir",
            "/var/lib/sbproxy/cluster",
            "--ttl-secs",
            "60",
        ]);
        let Some(Cmd::Cluster(ClusterCmd {
            sub:
                ClusterSub::Token(ClusterTokenCmd {
                    sub: ClusterTokenSub::Create(token),
                }),
        })) = cli.cmd
        else {
            panic!("expected cluster token create");
        };
        assert_eq!(token.ttl_secs, 60);

        let cli = parse(&[
            "sbproxy",
            "cluster",
            "enroll",
            "--url",
            "https://authority.example:9090",
            "--token",
            "secret-token",
            "--node-id",
            "worker-a",
            "--out",
            "/var/lib/sbproxy/cluster",
        ]);
        let Some(Cmd::Cluster(ClusterCmd {
            sub: ClusterSub::Enroll(enroll),
        })) = cli.cmd
        else {
            panic!("expected cluster enroll");
        };
        assert_eq!(enroll.node_id, "worker-a");
        assert!(!format!("{enroll:?}").contains("secret-token"));

        let cli = parse(&[
            "sbproxy",
            "cluster",
            "status",
            "--admin-url",
            "https://authority.example:9090",
            "--username",
            "operator",
            "--password",
            "secret-password",
            "--format",
            "json",
        ]);
        let Some(Cmd::Cluster(ClusterCmd {
            sub: ClusterSub::Status(status),
        })) = cli.cmd
        else {
            panic!("expected cluster status");
        };
        assert_eq!(status.admin.username.as_deref(), Some("operator"));
        assert!(matches!(status.format, OutputFormat::Json));
        assert!(!format!("{status:?}").contains("secret-password"));
    }

    #[test]
    fn cluster_labels_are_exact_and_duplicate_safe() {
        assert_eq!(
            parse_cluster_labels(&["zone=a".to_string(), "gpu=l4".to_string()])
                .unwrap()
                .len(),
            2
        );
        assert!(parse_cluster_labels(&["zone".to_string()]).is_err());
        assert!(parse_cluster_labels(&["zone=a".to_string(), "zone=b".to_string()]).is_err());
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
    fn update_accepts_global_check_and_local_yes() {
        // `--check` is the global flag; it is accepted after the `update`
        // subcommand and selects the dry-run report. `--yes` / `-y` is
        // local to `update`.
        let cli = parse(&["sbproxy", "update", "--check", "-y", "--engines"]);
        assert!(cli.check, "global --check is accepted after `update`");
        match cli.cmd {
            Some(Cmd::Update(args)) => {
                assert!(args.yes);
                assert!(args.engines);
            }
            other => panic!("expected Update, got {other:?}"),
        }
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
            headers: std::collections::BTreeMap::from([(
                "x-honeycomb-team".to_string(),
                "literal-token".to_string(),
            )]),
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
        // WOR-1869: literal header values pass through resolution
        // unchanged and land on the runtime config.
        assert_eq!(
            mapped.headers.get("x-honeycomb-team").map(String::as_str),
            Some("literal-token")
        );
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
    fn validate_rejects_model_host_semantics_that_boot_rejects() {
        let path = temp_config(
            "proxy:\n  http_bind_port: 8080\n  model_host:\n    max_parallel_prepares: 0\norigins:\n  x.local:\n    action:\n      type: static\n      status_code: 200\n      content_type: text/plain\n      body: ok\n",
        );
        assert!(handle_validate_subcommand(&validate_args(&path, false)).is_err());
        assert_eq!(
            handle_validate_subcommand(&validate_args(&path, true)).unwrap(),
            2
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_accepts_multi_replica_single_node_deployments() {
        // A single node may run several replicas; the device budget is enforced
        // at reconcile, so config validation accepts a multi-replica deployment
        // with a pinned variant.
        let path = temp_config(
            "proxy:\n  http_bind_port: 8080\n  model_host:\n    deployments:\n      coder:\n        model: qwen2.5-0.5b-instruct\n        variant: q4_k_m\n        replicas: 2\norigins:\n  x.local:\n    action:\n      type: static\n      status_code: 200\n      content_type: text/plain\n      body: ok\n",
        );
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
    fn validate_rejects_unsupported_legacy_managed_fields() {
        let path = temp_config(
            "origins:\n  ai.local:\n    action:\n      type: ai_proxy\n      providers:\n        - name: local\n          serve:\n            models:\n              - model: qwen3-14b\n                speculative: {}\n",
        );
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
        let (proposed, construction_error) = load_and_validate(&path).unwrap();
        assert!(construction_error.is_none(), "{construction_error:?}");
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
