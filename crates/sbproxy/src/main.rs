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

mod cedar_cli;

/// `sbproxy connect` / `sbproxy disconnect`: detect the coding agents on this
/// machine and point them at the gateway. Its own module because it is the
/// only verb here that writes files belonging to other programs, and the
/// reasoning about backups, atomic replacement, and what it deliberately
/// refuses to write belongs next to the code that does it.
mod connect;

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
    /// Keep this root-scoped: `ai evaluate --version <u32>` uses the same
    /// public spelling for an immutable dataset version.
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue)]
    version: bool,

    /// Validate the config and exit without starting the proxy.
    /// Equivalent to `sbproxy validate <path>` and dispatches to the
    /// same handler. Documented in `SUPPLY-CHAIN.md` as the CI-friendly
    /// verification step.
    #[arg(long = "check", action = ArgAction::SetTrue, global = true)]
    check: bool,

    /// Refuse to serve unless the model stack matches
    /// `sbproxy-models.lock` (WOR-1864). Before any listener starts,
    /// the lockfile next to the config is diffed against the verified
    /// weight cache and every configured serve/deployment entry must
    /// resolve to a locked artifact digest. Drift (or a missing
    /// lockfile) prints the per-model drift lines and exits 2 without
    /// serving. Honored by `serve` and the bare run form; other
    /// subcommands ignore it.
    #[arg(long = "locked", action = ArgAction::SetTrue, global = true)]
    locked: bool,

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

    /// What to do when the config this node was told to boot on does not
    /// work: `off` (exit, the default and today's behavior) or
    /// `last-known-good` (walk the config revision ring for a revision
    /// that boots). Beats `SB_CONFIG_FALLBACK` and
    /// `proxy.config_history.boot.fallback`, deliberately: a rescue boot
    /// must not depend on the file being right, and the file is what is
    /// broken. A node that boots on the fallback warns loudly, reports
    /// `sbproxy_config_fallback_active` as 1, and suspends its file
    /// watcher, SIGHUP, and `source:` poller until an operator clears
    /// the pin with `DELETE /admin/config/fallback`.
    ///
    /// `SB_CONFIG_FALLBACK` is deliberately **not** declared here.
    /// Letting clap consume it into this slot made the environment
    /// indistinguishable from the flag, which turned an unparseable
    /// value into `exit(2)` instead of the documented warn-and-fall-
    /// through, and left the environment branch in
    /// `sbproxy_core::config_boot::mode_from_flag_or_env` unreachable in
    /// production. That function reads the variable instead.
    #[arg(long = "config-fallback", global = true)]
    config_fallback: Option<String>,
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
    /// Fetch every project repository `origin_sources:` names, compose
    /// the `origins:` map, and either publish it through the config
    /// authority or write it to a file. Exit 0 published or unchanged,
    /// 1 CLI error, 2 `--dry-run` found changes, 3 the composition or
    /// the authority refused it.
    Aggregate(AggregateArgs),
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
    Ai(Box<AiCmd>),
    /// Audit-trail tools (verify the tamper-evident security or config
    /// audit chain).
    Audit(AuditCmd),
    /// Admin-account maintenance (password hashing, ...).
    Admin(AdminCliCmd),
    /// Serve a certified catalog model in one command, with no YAML.
    /// Resolves an immutable artifact, generates local admin auth, warms
    /// the managed deployment, then advertises its OpenAI-compatible endpoint.
    Run(RunArgs),
    /// Discover, cache, remove, and operate managed local models.
    Models(ModelsCmd),
    /// MCP gateway tools (pin the federated tool catalogue, check it).
    Mcp(McpCmd),
    /// Cedar policy tools (offline replay against a traffic sample).
    Cedar(CedarCmd),
    /// Rego policy tools (the offline `opa test` analogue).
    Rego(RegoCmd),
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
    /// Install, remove, or check a per-user launchd agent that keeps a
    /// certified catalog model running in the background (macOS only).
    /// Reuses the same secure config generation as `sbproxy run`.
    Service(ServiceCmd),
    /// Point the coding agents installed on this machine at this gateway.
    /// Detects each one, writes the config files it can write atomically
    /// (with a one-time backup), and prints the exact fields for the ones
    /// that only have a settings screen. `--dry-run` shows the diff and
    /// changes nothing. No credential is read or written: every client this
    /// touches takes its key from an environment variable, and this verb
    /// writes the variable's name.
    Connect(ConnectArgs),
    /// Undo `connect`: remove the profile it wrote and name what to clear by
    /// hand. The profile's current contents are copied to
    /// `<path>.sbproxy.removed` before it goes, so a hand edit survives the
    /// removal; the one-time `.sbproxy.bak`, which holds the file as it was
    /// before the first `connect`, is left exactly where it is.
    Disconnect(DisconnectArgs),
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
    /// Do not resolve a `source:` block. Validates the pointer file
    /// alone, which is what you want on a machine with no network or no
    /// credential for the repository, and a lie about a git-sourced
    /// config anywhere else.
    #[arg(long = "no-fetch")]
    no_fetch: bool,
}

#[derive(clap::Args, Debug)]
struct PlanArgs {
    /// Proposed config file. Required.
    #[arg(short = 'f', long = "config")]
    config: Option<PathBuf>,
    /// Do not resolve a `source:` block on either side of the diff.
    /// Without it, a git-sourced config is planned against the document
    /// the repository actually serves.
    #[arg(long = "no-fetch")]
    no_fetch: bool,
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
    /// Print the composition provenance for one composed host instead
    /// of a diff: which layer set each leaf of that origin, and which
    /// repository and commit it came from. Fetches every project
    /// repository `origin_sources:` names, so it is refused under
    /// `--no-fetch`.
    #[arg(long = "explain-origin", conflicts_with = "against")]
    explain_origin: Option<String>,
}

/// `sbproxy aggregate`: compose project-owned origin profiles into the
/// `origins:` map and publish or write the result.
#[derive(clap::Args)]
struct AggregateArgs {
    /// Positional runtime config path. Equivalent to `-f <path>`. This
    /// is the document carrying `origin_sources:` and `origin_defaults:`,
    /// not a project profile.
    config_path: Option<PathBuf>,
    /// Compose to this file instead of publishing. The offline path for
    /// a single node, a self-host, or a CI job that wants to review the
    /// composed output before it ships.
    #[arg(long = "out")]
    out: Option<PathBuf>,
    /// Print what `--out` would change against the file already there
    /// and write nothing. Exit 2 when there are changes.
    #[arg(long = "dry-run", action = ArgAction::SetTrue, requires = "out")]
    dry_run: bool,
    /// Print the composition provenance for one host and exit: which
    /// layer set each leaf, and which repository and commit it came
    /// from.
    #[arg(long = "explain")]
    explain: Option<String>,
    /// Keep running: poll each entry on the configured interval,
    /// coalesce a burst of movement into one composition, and publish
    /// when the composed document actually changed.
    ///
    /// Refuses to combine with the one-shot flags rather than ignoring
    /// them. `--watch --out f.yml` used to drop `--out` without a word
    /// and loop publishing to the admin API instead, which on a node
    /// with an admin listener is a fleet publish nobody asked for.
    #[arg(
        long = "watch",
        action = ArgAction::SetTrue,
        conflicts_with_all = ["dry_run", "out", "explain"]
    )]
    watch: bool,
    /// Stop after this many poll cycles in `--watch`. Zero means run
    /// until interrupted, which is the operational default; a positive
    /// value is what a cron-shaped invocation uses. Poll cycles rather
    /// than compositions, because a fleet where nothing moves composes
    /// nothing and a bound counting compositions would never be reached.
    #[arg(long = "polls", default_value_t = 0)]
    polls: u32,
    /// How subscribers apply the composed document. Must match the mode
    /// each subscriber is configured for, or they refuse the bundle.
    #[arg(long = "mode", value_enum, default_value_t = BundleModeArg::Overlay)]
    mode: BundleModeArg,
    /// Admin endpoint and Basic Auth credentials of the config
    /// authority this publishes through.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format. `text` (default) prints a human summary; `json`
    /// is the stable envelope for tooling.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

impl std::fmt::Debug for AggregateArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregateArgs")
            .field("config_path", &self.config_path)
            .field("out", &self.out)
            .field("dry_run", &self.dry_run)
            .field("explain", &self.explain)
            .field("watch", &self.watch)
            .field("polls", &self.polls)
            .field("admin", &self.admin)
            .finish_non_exhaustive()
    }
}

#[derive(clap::Args)]
struct ApplyArgs {
    /// Proposed config file. Mutually exclusive with `-p`.
    #[arg(short = 'f', long = "config", conflicts_with = "plan_file")]
    config: Option<PathBuf>,
    /// Plan file from a prior `plan --out`. Apply recomputes the
    /// plan against the live baseline and refuses (exit 5) if the
    /// `baseline_revision` drifted. Mutually exclusive with `-f`.
    #[arg(short = 'p', long = "plan", conflicts_with = "config")]
    plan_file: Option<PathBuf>,
    /// Admin API base URL of the proxy to apply to. Defaults to
    /// `http://127.0.0.1:9090`.
    #[arg(long = "admin-url", env = "SB_ADMIN_URL")]
    admin_url: Option<String>,
    /// Admin Basic Auth username. Defaults to `admin`.
    #[arg(long = "username", env = "SB_ADMIN_USERNAME")]
    username: Option<String>,
    /// Admin Basic Auth password. Never printed.
    #[arg(long = "password", env = "SB_ADMIN_PASSWORD")]
    password: Option<String>,
    /// Validate the config and stop. Contacts no proxy and changes
    /// nothing. Use this in CI, where there is no running proxy to
    /// apply to.
    #[arg(long = "validate-only")]
    validate_only: bool,
}

impl std::fmt::Debug for ApplyArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplyArgs")
            .field("config", &self.config)
            .field("plan_file", &self.plan_file)
            .field("admin_url", &self.admin_url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("validate_only", &self.validate_only)
            .finish()
    }
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
    /// Operate a config authority: generate its signing key, publish a
    /// configuration to the fleet, watch the rollout, roll back, and
    /// manage subscriber credentials.
    Authority(ConfigAuthorityCmd),
    /// Preview the configuration this node's authority would apply next,
    /// without applying it.
    Pull(ConfigPullArgs),
    /// List every config revision recorded in the running proxy's
    /// `proxy.config_history` ring (WOR-2456/2457), newest first.
    /// Requires `proxy.config_history.enabled` on that node.
    History(ConfigHistoryArgs),
    /// Print one recorded revision's stored document, selected by the
    /// revision number `config history` lists.
    Show(ConfigShowArgs),
    /// Roll the running proxy back to a config revision it already
    /// stored. Names the blast radius before it acts, refuses a stale
    /// `--expected-current`, and the restored document soaks like any
    /// other candidate.
    Rollback(ConfigRollbackArgs),
    /// Diff two stored config revisions, or one stored revision against
    /// what the proxy is running. Applies nothing.
    Diff(ConfigDiffArgs),
}

impl ConfigCmd {
    /// Whether this subcommand reports through `plan`'s exit-code
    /// convention, where 2 means "changes present" and is not an error.
    ///
    /// The older `config` subcommands exit 2 on a CLI error. The two that
    /// print a plan-style diff cannot, or a diff would be
    /// indistinguishable from a broken invocation, so their CLI-error code
    /// is 1 like `plan`'s.
    fn uses_plan_exit_codes(&self) -> bool {
        // `config diff` joins the two that already report this way: it
        // prints a plan, and a plan whose exit code doubled as a CLI
        // error code would make "these two revisions differ"
        // indistinguishable from "you typed the command wrong"
        // (WOR-2460).
        matches!(
            self.sub,
            ConfigSub::Authority(_) | ConfigSub::Pull(_) | ConfigSub::Diff(_)
        )
    }
}

#[derive(clap::Args, Debug)]
struct ConfigAuthorityCmd {
    #[command(subcommand)]
    sub: ConfigAuthoritySub,
}

#[derive(Subcommand, Debug)]
enum ConfigAuthoritySub {
    /// Generate an Ed25519 signing key and the verifying-key file
    /// subscribers install, then print what to copy where. Local: writes
    /// files, contacts nothing.
    Init(AuthorityInitArgs),
    /// Validate a payload locally, then publish it. Prints the revision
    /// and digest the authority assigned.
    Publish(AuthorityPublishArgs),
    /// Show the current revision, the signing key id, and the revision
    /// each subscriber was last seen holding.
    Status(AuthorityStatusArgs),
    /// Republish the previous revision's payload under a new revision
    /// number.
    Rollback(AuthorityRollbackArgs),
    /// Register, list, and revoke subscriber credentials.
    Subscriber(AuthoritySubscriberCmd),
}

/// `sbproxy config authority init`: generate this authority's key material.
#[derive(clap::Args, Debug)]
struct AuthorityInitArgs {
    /// Directory to write the key material into. Created when absent,
    /// owner-only.
    #[arg(long = "dir")]
    directory: PathBuf,
    /// Key id stamped into every bundle and keyed in the verifying-key
    /// file. Defaults to a name derived from the new public key, so a
    /// rotation never collides with the key it replaces.
    #[arg(long = "key-id")]
    key_id: Option<String>,
    /// Authority id shown in the printed config snippet. Does not affect
    /// the generated key material.
    #[arg(long = "authority-id", default_value = "control-plane")]
    authority_id: String,
    /// Replace an existing signing key. The new verifying key is added to
    /// the existing map rather than replacing it, so subscribers that
    /// still trust the old key keep verifying while they are updated.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config authority publish`: validate a payload, then publish it.
#[derive(clap::Args, Debug)]
struct AuthorityPublishArgs {
    /// The payload to publish: the document subscribers apply, not this
    /// node's own config file.
    #[arg(short = 'f', long = "config")]
    config: Option<PathBuf>,
    /// How subscribers apply it. Must match the `mode` each subscriber is
    /// configured for, or they refuse the bundle rather than guess.
    #[arg(long = "mode", value_enum, default_value_t = BundleModeArg::Overlay)]
    mode: BundleModeArg,
    /// Run every validation the authority runs and stop. Contacts no
    /// authority and publishes nothing. For CI.
    #[arg(long = "validate-only", action = ArgAction::SetTrue)]
    validate_only: bool,
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config authority status`: what is published, and who has it.
#[derive(clap::Args, Debug)]
struct AuthorityStatusArgs {
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config authority rollback`: republish the previous revision.
#[derive(clap::Args, Debug)]
struct AuthorityRollbackArgs {
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct AuthoritySubscriberCmd {
    #[command(subcommand)]
    sub: AuthoritySubscriberSub,
}

#[derive(Subcommand, Debug)]
enum AuthoritySubscriberSub {
    /// Register a subscriber and mint its credential. The credential is
    /// printed here, once, and is not recoverable afterwards.
    Add(AuthoritySubscriberAddArgs),
    /// List registered subscribers and the revision each last took.
    List(AuthoritySubscriberListArgs),
    /// Revoke one credential, or every credential one subscriber holds.
    Revoke(AuthoritySubscriberRevokeArgs),
}

/// `sbproxy config authority subscriber add`.
#[derive(clap::Args, Debug)]
struct AuthoritySubscriberAddArgs {
    /// Subscriber id, matching the `subscriber_id` that node sets under
    /// `proxy.config_authority.upstream`.
    subscriber_id: String,
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config authority subscriber list`.
#[derive(clap::Args, Debug)]
struct AuthoritySubscriberListArgs {
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config authority subscriber revoke`.
#[derive(clap::Args, Debug)]
struct AuthoritySubscriberRevokeArgs {
    /// Revoke exactly this credential, leaving any other credential the
    /// same subscriber holds alive. This is the half of a rotation that
    /// retires the old credential.
    #[arg(long = "credential-id", conflicts_with = "subscriber_id")]
    credential_id: Option<String>,
    /// Revoke every credential this subscriber holds. The node stops
    /// receiving updates; it keeps serving what it already applied.
    #[arg(long = "subscriber-id")]
    subscriber_id: Option<String>,
    /// Admin endpoint and Basic Auth credentials of the authority.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config pull`: preview what the next poll would apply.
#[derive(clap::Args, Debug)]
struct ConfigPullArgs {
    /// This node's config file, which is the merge base. Defaults to
    /// `-f/--config` or `SB_CONFIG_FILE`.
    config_path: Option<PathBuf>,
    /// Required. Fetch, verify, and merge, then print the diff. Applies
    /// nothing, writes no cache, advances no cursor, reloads nothing.
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config history`: list the running proxy's recorded config
/// revisions.
#[derive(clap::Args, Debug)]
struct ConfigHistoryArgs {
    /// Admin endpoint and Basic Auth credentials of the running proxy.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format. `text` (default) prints a table; `json` prints
    /// the admin API's response verbatim.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config rollback`: re-apply a stored config revision.
#[derive(clap::Args, Debug)]
struct ConfigRollbackArgs {
    /// Which revision to restore: a revision number from
    /// `sbproxy config history`, a content digest, or the default
    /// `last-known-good`.
    #[arg(long = "to", default_value = "last-known-good")]
    to: String,
    /// Refuse unless this is the revision the node is running right
    /// now. Two operators reaching for rollback during one incident is
    /// not hypothetical, and without this the second silently undoes
    /// the first. Read it from `sbproxy config history`.
    #[arg(long = "expected-current")]
    expected_current: Option<u64>,
    /// Confirm a restart-class or breaking rollback by naming the
    /// target revision again. Required for those two classes and
    /// ignored for the other two, the way a destructive action should
    /// be.
    #[arg(long = "confirm")]
    confirm: Option<u64>,
    /// Refuse unless the node's ring carries this lineage. A `source:`
    /// repoint preserves lineage; a node-identity change re-mints it,
    /// and a revision number from before that names a different
    /// history.
    #[arg(long = "lineage")]
    lineage: Option<String>,
    /// Roll back across a lineage break anyway.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
    /// Admin endpoint and Basic Auth credentials of the running proxy.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config diff`: plan between two stored revisions.
#[derive(clap::Args, Debug)]
struct ConfigDiffArgs {
    /// The revision to diff **to**: a revision number or
    /// `last-known-good`. Positional, so `sbproxy config diff 7` is the
    /// short form.
    to: Option<String>,
    /// Baseline revision. Defaults to what the proxy is running, which
    /// makes the one-argument form the question people actually ask
    /// mid-incident. Junos spells the two forms
    /// `show | compare rollback n` and
    /// `show system rollback 3 compare 1`; this is both.
    #[arg(long = "from")]
    from: Option<String>,
    /// Target revision, as a flag rather than the positional. Naming
    /// both is a usage error rather than a precedence rule.
    #[arg(long = "to")]
    to_flag: Option<String>,
    /// Admin endpoint and Basic Auth credentials of the running proxy.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format. `text` prints the plan; `json` prints the admin
    /// API's response verbatim.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// `sbproxy config show`: print one recorded revision's stored document.
#[derive(clap::Args, Debug)]
struct ConfigShowArgs {
    /// Revision number, from `sbproxy config history`'s `REVISION`
    /// column. Resolved to a content digest via that same listing, so
    /// the revision named here must still be in the ring (it has not
    /// aged out under `proxy.config_history.keep`).
    revision: u64,
    /// Admin endpoint and Basic Auth credentials of the running proxy.
    #[command(flatten)]
    admin: ModelsAdminArgs,
    /// Output format. `text` (default) prints just the stored
    /// document. `json` prints the admin API's full detail envelope
    /// (`entry`, `document`, `plan_text`).
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// How a published bundle declares subscribers should apply it.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum BundleModeArg {
    /// Merge over each subscriber's local document.
    Overlay,
    /// Become the whole document on each subscriber.
    Replace,
}

impl BundleModeArg {
    /// The wire value the `?mode=` query parameter takes.
    fn as_str(self) -> &'static str {
        match self {
            BundleModeArg::Overlay => "overlay",
            BundleModeArg::Replace => "replace",
        }
    }
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
    /// Versioned prompt tools.
    Prompt(Box<PromptCmd>),
    /// Validate or execute a bounded agent workflow.
    Workflow(WorkflowCmd),
    /// Register immutable evaluation datasets with the live toolkit runtime.
    Dataset(DatasetCmd),
    /// Run a bounded evaluation against an exact live dataset version.
    Evaluate(Box<EvaluateArgs>),
}

#[derive(clap::Args, Debug)]
struct PromptCmd {
    #[command(subcommand)]
    sub: PromptSub,
}

#[derive(Subcommand, Debug)]
enum PromptSub {
    /// Compile a shorter static system prompt against an evaluation set.
    Optimize(PromptOptimizeArgs),
    /// Select a weighted prompt version for a stable cohort.
    Select(PromptSelectArgs),
}

#[derive(clap::Args, Debug)]
struct WorkflowCmd {
    #[command(subcommand)]
    sub: WorkflowSub,
}

#[derive(Subcommand, Debug)]
enum WorkflowSub {
    /// Discover configured agents by capability through the admin API.
    Discover(WorkflowDiscoverArgs),
    /// Validate a YAML workflow graph through the live admin API.
    Validate(WorkflowValidateArgs),
    /// Execute a configured workflow through the live admin API.
    Run(WorkflowRunArgs),
}

#[derive(clap::Args, Debug)]
struct WorkflowDiscoverArgs {
    /// Configured proxy origin that owns the agent registry.
    #[arg(long)]
    origin: String,
    /// Optional capability used to filter the discovered agents.
    #[arg(long)]
    capability: Option<String>,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(clap::Args, Debug)]
struct WorkflowValidateArgs {
    /// YAML file containing the workflow graph.
    path: PathBuf,
    /// Configured proxy origin that will own the workflow.
    #[arg(long)]
    origin: String,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(clap::Args, Debug)]
struct WorkflowRunArgs {
    /// Configured proxy origin that owns the workflow.
    #[arg(long)]
    origin: String,
    /// Name of a configured workflow.
    #[arg(long)]
    workflow: String,
    /// JSON input passed to the workflow's initial capability.
    #[arg(long)]
    input: PathBuf,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(clap::Args, Debug)]
struct DatasetCmd {
    #[command(subcommand)]
    sub: DatasetSub,
}

#[derive(Subcommand, Debug)]
enum DatasetSub {
    /// Register one immutable, explicitly versioned JSON dataset.
    Register(DatasetRegisterArgs),
}

#[derive(clap::Args, Debug)]
struct DatasetRegisterArgs {
    /// Configured proxy origin that owns the dataset.
    #[arg(long)]
    origin: String,
    /// JSON file containing one explicitly versioned dataset.
    #[arg(long)]
    dataset: PathBuf,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(clap::Args, Debug)]
struct EvaluateArgs {
    /// Configured proxy origin that owns the dataset.
    #[arg(long)]
    origin: String,
    /// Exact registered dataset name.
    #[arg(long)]
    dataset: String,
    /// Exact immutable dataset version.
    #[arg(long)]
    version: u32,
    /// JSON array of model response strings, one per dataset entry.
    #[arg(long)]
    responses: PathBuf,
    /// Stable operator-supplied experiment identifier.
    #[arg(long = "experiment-id")]
    experiment_id: String,
    /// Human-readable experiment name.
    #[arg(long = "experiment-name")]
    experiment_name: String,
    /// Model label recorded with the evaluation summary.
    #[arg(long)]
    model: String,
    /// Optional concrete prompt version recorded with the evaluation.
    #[arg(long = "prompt-version")]
    prompt_version: Option<String>,
    /// Optional JSON object of bounded experiment parameters.
    #[arg(long)]
    parameters: Option<PathBuf>,
    /// Optional JSON array of offline judge responses, one per case.
    #[arg(long = "judge-responses")]
    judge_responses: Option<PathBuf>,
    /// Judge model label required with `--judge-responses`.
    #[arg(long = "judge-model")]
    judge_model: Option<String>,
    /// Judge criterion. Repeat to score several criteria.
    #[arg(long = "judge-criterion")]
    judge_criteria: Vec<String>,
    /// Keyword every response must contain. Repeat to require several.
    #[arg(long = "required-keyword")]
    required_keywords: Vec<String>,
    /// Optional JSON Schema that every response must satisfy.
    #[arg(long = "json-schema")]
    json_schema: Option<PathBuf>,
    /// Minimum response length in bytes. Setting either bound adds one
    /// inclusive length-range metric; leaving both unset adds none, so the
    /// reported metric pass rate reflects only the metrics you asked for.
    #[arg(long = "min-bytes")]
    min_bytes: Option<usize>,
    /// Maximum response length in bytes (defaults to 1 MiB when only
    /// `--min-bytes` is given).
    #[arg(long = "max-bytes")]
    max_bytes: Option<usize>,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(clap::Args, Debug)]
struct PromptSelectArgs {
    /// Configured proxy origin that owns the prompt rollout.
    #[arg(long)]
    origin: String,
    /// Prompt name to select.
    #[arg(long)]
    name: String,
    /// Stable dry-run cohort key. The authenticated admin scope is added
    /// server-side before selection.
    #[arg(long)]
    cohort: String,
    /// Admin endpoint and credentials.
    #[command(flatten)]
    admin: ModelsAdminArgs,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum PromptEvalMetricArg {
    ExactMatch,
    Contains,
    JsonExact,
}

impl From<PromptEvalMetricArg> for sbproxy_ai::prompt_optimizer::PromptEvalMetric {
    fn from(value: PromptEvalMetricArg) -> Self {
        match value {
            PromptEvalMetricArg::ExactMatch => Self::ExactMatch,
            PromptEvalMetricArg::Contains => Self::Contains,
            PromptEvalMetricArg::JsonExact => Self::JsonExact,
        }
    }
}

#[derive(clap::Args, Debug)]
struct PromptOptimizeArgs {
    /// UTF-8 file containing the source system prompt.
    #[arg(long)]
    prompt: PathBuf,
    /// Customer-owned JSONL evaluation set.
    #[arg(long = "eval-set")]
    eval_set: PathBuf,
    /// OpenAI-compatible base URL or full chat-completions endpoint.
    #[arg(long)]
    endpoint: String,
    /// Optional HTTP Host header when the endpoint uses a separate dial address.
    #[arg(long = "host-header")]
    host_header: Option<String>,
    /// Environment variable containing the endpoint API key.
    #[arg(long = "api-key-env")]
    api_key_env: Option<String>,
    /// Model used to evaluate the source and candidate prompts.
    #[arg(long = "task-model")]
    task_model: String,
    /// Model used once to propose shorter instructions. Defaults to task model.
    #[arg(long = "optimizer-model")]
    optimizer_model: Option<String>,
    /// Deterministic evaluation metric.
    #[arg(long, value_enum, default_value_t = PromptEvalMetricArg::ExactMatch)]
    metric: PromptEvalMetricArg,
    /// Maximum accepted aggregate quality drop.
    #[arg(long = "noise-tolerance", default_value_t = 0.02)]
    noise_tolerance: f64,
    /// Maximum candidate instructions evaluated.
    #[arg(long = "max-candidates", default_value_t = 8)]
    max_candidates: usize,
    /// Hard cap on all model requests in this run.
    #[arg(long = "max-requests", default_value_t = 256)]
    max_requests: usize,
    /// Per-request timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 60)]
    timeout_secs: u64,
    /// Prompt-store name written into the artifact.
    #[arg(long)]
    name: String,
    /// Prompt version label written into the artifact.
    #[arg(long = "prompt-version")]
    prompt_version: String,
    /// JSON artifact output path.
    #[arg(long)]
    output: PathBuf,
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
    /// Aggregate a value ledger into the per-model savings report the
    /// admin `GET /admin/model-host/value` route serves, reading the
    /// redb file directly with no server running. A missing file is
    /// reported as no value recorded yet, not an error. Exit 0.
    Report(LedgerReportArgs),
    /// Compare the local usage ledger against a provider's own usage
    /// export, per (day, model): usage the export shows that the ledger
    /// never recorded is evidence a call reached the provider without
    /// going through this gateway. Always verifies the ledger's hash
    /// chain first and refuses to reconcile an unverified one. Exit 0
    /// unless `--strict` is given and the export shows usage the ledger
    /// never saw, in which case exit 1.
    Reconcile(LedgerReconcileArgs),
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
struct LedgerReportArgs {
    /// Path to the value ledger file (the redb database the AI handler
    /// keeps at `<cache_dir>/value-ledger.redb`).
    path: PathBuf,
    /// Output format. `text` (default) prints per-model rows and totals;
    /// `json` emits the same object `GET /admin/model-host/value` serves.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// Provider usage export format for `sbproxy ai ledger reconcile`. A
/// closed set (clap rejects unknown values at parse time) with exactly
/// one member today: see `parse_openai_usage_export` in
/// `sbproxy_ai::usage_ledger` for why OpenAI's organization Usage API
/// export was picked as the format to support first, and what an
/// Anthropic Admin usage/cost format would need to add.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ProviderExportFormatArg {
    /// OpenAI organization Usage API completions export
    /// (`GET /v1/organization/usage/completions`, `bucket_width=1d`,
    /// ideally `group_by[]=model`).
    #[default]
    OpenaiUsage,
}

#[derive(clap::Args, Debug)]
struct LedgerReconcileArgs {
    /// Path to the local usage ledger file (the JSONL write-ahead log).
    path: PathBuf,
    /// Path to a downloaded provider usage export file.
    #[arg(long = "provider-export")]
    provider_export: PathBuf,
    /// Provider export format.
    #[arg(long = "format", value_enum, default_value_t = ProviderExportFormatArg::OpenaiUsage)]
    format: ProviderExportFormatArg,
    /// Optional 32-byte Ed25519 signing seed as hex, forwarded to the
    /// chain-integrity check that runs before reconciling.
    #[arg(long = "signing-seed-hex")]
    signing_seed_hex: Option<String>,
    /// Exit 1 when the export shows provider-side usage the ledger never
    /// recorded (the bypass evidence). Without this flag the command
    /// always exits 0 after printing the report, so a first run can be
    /// inspected before it is wired into a gate.
    #[arg(long)]
    strict: bool,
    /// Output format. `text` (default) prints the reconciled rows and
    /// the honesty caveats; `json` emits a structured object for
    /// tooling.
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct AuditCmd {
    #[command(subcommand)]
    sub: AuditSub,
}

#[derive(Subcommand, Debug)]
enum AuditSub {
    /// Re-derive an audit chain from genesis and report the first record
    /// that does not check out. `--channel security` (default) verifies
    /// the trail `audit.sink: chain` writes; `--channel config` verifies
    /// the config-authority decision trail; `--channel key` verifies the
    /// key/credential-mutation trail; `--channel admin` verifies the
    /// admin-console action trail. Exit 0 when the trail verifies, 1 when
    /// it does not.
    Verify(AuditVerifyArgs),
}

#[derive(clap::Args, Debug)]
struct AuditVerifyArgs {
    /// Path to the chain file, the one `audit.path` names.
    path: PathBuf,
    /// The 32-byte Ed25519 signing seed as hex. Without it only the hash
    /// chain is checked, which catches an edit made by somebody who could
    /// not re-link the file and misses one made by somebody who could.
    /// Pass it to also verify every signature.
    #[arg(long = "signing-seed-hex")]
    signing_seed_hex: Option<String>,
    /// Output format. `text` (default) prints a human line; `json` emits a
    /// single structured object for CI consumption.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Which chain to verify: `security` (default), the tamper-evident
    /// trail `audit.sink: chain` writes; `config`, the trail of
    /// config-authority decisions; `key`, the trail of key/credential
    /// mutations (metadata and fingerprints, never the raw diff); or
    /// `admin`, the trail of authenticated admin-console actions. Each
    /// channel writes a different payload shape to its own file, so pass
    /// the channel that matches the file at `path`.
    #[arg(
        long = "channel",
        value_parser = ["security", "config", "key", "admin"],
        default_value = "security"
    )]
    channel: String,
}

#[derive(clap::Args, Debug)]
struct AdminCliCmd {
    #[command(subcommand)]
    sub: AdminSub,
}

#[derive(Subcommand, Debug)]
enum AdminSub {
    /// Hash a password with the same HMAC-SHA256-plus-pepper primitive
    /// `proxy.admin.operators[].password_hash` is verified against, for
    /// pasting the result into config.
    HashPassword(HashPasswordArgs),
}

#[derive(clap::Args, Debug)]
struct HashPasswordArgs {
    /// Password to hash. Prefer `--password-stdin`: a literal value here
    /// stays in the shell history.
    #[arg(long = "password")]
    password: Option<String>,
    /// Read the password from stdin (first line, trailing newline
    /// trimmed) instead of `--password`.
    #[arg(long = "password-stdin", action = ArgAction::SetTrue)]
    password_stdin: bool,
}

/// Arguments to `sbproxy connect`.
///
/// There is no `--key` and no `--key-stdin`, so unlike `ApplyArgs` this
/// needs no hand-written redacting `Debug`: there is nothing here to redact.
/// Every client this verb configures reads its credential from an environment
/// variable, so the verb writes the variable's name and the operator exports
/// the value. See the module docs on `connect` for why that is a decision
/// rather than an omission.
#[derive(clap::Args, Debug)]
struct ConnectArgs {
    /// Clients to configure. Default: every client this verb knows
    /// (`codex`, `claude-code`, `cursor`, `cline`, `copilot`), skipping the
    /// ones that are not installed. Naming a client that is not installed is
    /// an error; the default sweep says so and exits clean.
    #[arg(value_name = "CLIENT")]
    clients: Vec<String>,
    /// Gateway base URL, with or without a trailing `/v1`.
    #[arg(long = "base-url", default_value = connect::DEFAULT_BASE_URL)]
    base_url: String,
    /// Model id or alias to select in the clients that take one. Left alone
    /// when absent, because writing a model nobody asked for is a behavior
    /// change wearing a convenience's clothes.
    #[arg(long = "model")]
    model: Option<String>,
    /// Print the diff and change nothing.
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,
    /// Output format. `text` (default) prints per-client blocks and a unified
    /// diff; `json` emits one structured object.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// Arguments to `sbproxy disconnect`. No base URL: reversing does not need to
/// know where the gateway was.
#[derive(clap::Args, Debug)]
struct DisconnectArgs {
    /// Clients to disconnect. Default: every client this verb knows.
    #[arg(value_name = "CLIENT")]
    clients: Vec<String>,
    /// Print the diff and change nothing.
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,
    /// Output format. `text` (default) or `json`.
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

#[derive(clap::Args, Debug)]
struct McpCmd {
    #[command(subcommand)]
    sub: McpSub,
}

#[derive(Subcommand, Debug)]
enum McpSub {
    /// Discover the configured federated servers and write a lockfile
    /// pinning every advertised tool at its current contract digest.
    Lock(McpLockArgs),
    /// Re-discover and diff against the committed baseline without
    /// starting a listener. Exits 2 on drift, for CI.
    VerifyLock(McpVerifyLockArgs),
}

#[derive(clap::Args, Debug)]
struct McpLockArgs {
    /// Lockfile path to write. Defaults to the mcp action's own
    /// `tool_versioning.lockfile`, which is the file the running gate
    /// reads. Only valid when the config has a single mcp action.
    #[arg(long = "out")]
    out: Option<PathBuf>,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct McpVerifyLockArgs {
    /// Lockfile path to check. Defaults to the mcp action's own
    /// `tool_versioning.lockfile`. Only valid when the config has a
    /// single mcp action.
    #[arg(long = "lockfile")]
    lockfile: Option<PathBuf>,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct CedarCmd {
    #[command(subcommand)]
    sub: CedarSub,
}

#[derive(Subcommand, Debug)]
enum CedarSub {
    /// Replay recorded MCP tool-call samples against Cedar source from
    /// an `sb.yml`. Exit 0 when every `expected` label holds and (with
    /// `--baseline`) no verdict moved; 1 when a sample missed or a
    /// verdict changed; 2 when the sample, the YAML, or the Cedar
    /// source could not be compiled.
    Replay(CedarReplayArgs),
}

#[derive(clap::Args, Debug)]
struct CedarReplayArgs {
    /// Proposed config whose `cedar_policies` block is evaluated.
    #[arg(short = 'f', long = "config")]
    config: Option<PathBuf>,
    /// JSONL traffic sample. Each line is
    /// `{principal, resource, expected?, action?, id?}`.
    #[arg(long = "against", required = true)]
    against: PathBuf,
    /// Optional baseline config. When set, the report diffs each
    /// sample's verdict against this file's Cedar source.
    #[arg(long = "baseline")]
    baseline: Option<PathBuf>,
    /// Restrict extraction to one origin hostname. Required when more
    /// than one origin has `cedar_policies`, so replay matches one live
    /// hook instead of mixing policy sets.
    #[arg(long = "origin")]
    origin: Option<String>,
    /// Output format. `text` (default) prints one line per sample;
    /// `json` emits a single object for CI.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct RegoCmd {
    #[command(subcommand)]
    sub: RegoSub,
}

#[derive(Subcommand, Debug)]
enum RegoSub {
    /// Run one or more Rego fixture files against the module(s) they
    /// name and print a coverage summary. The offline `opa test`
    /// analogue: every fixture compiles its module the same way a
    /// live `policy: rego` or `ai_routing_policy` does (`module_path`
    /// and `rego_v0` honored), so a fixture that passes here behaves
    /// identically pasted into config. Exit 0 when every case passes
    /// and (with `--min-coverage`) coverage clears the threshold; 1
    /// when a case fails or coverage falls short; 2 when a fixture
    /// itself is malformed.
    Test(RegoTestArgs),
}

#[derive(clap::Args, Debug)]
struct RegoTestArgs {
    /// A single fixture YAML file, or a directory searched recursively
    /// for `*_test.yaml` / `*_test.yml` fixture files (mirrors OPA's own
    /// `*_test.rego` naming convention, in sbproxy's YAML fixture shape).
    path: PathBuf,
    /// Fail (exit 1) when aggregate line coverage across every fixture
    /// module run in this invocation is below this percentage. Coverage
    /// is always gathered and printed; this flag only changes the exit
    /// code.
    #[arg(long = "min-coverage", value_name = "PCT")]
    min_coverage: Option<f64>,
    /// Output format. `text` (default) prints one line per case plus a
    /// coverage summary; `json` emits a single structured object for CI.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
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
    /// Write a lockfile pinning the exactly resolved serving stack.
    Lock(ModelsLockArgs),
    /// Check the verified local cache against the lockfile.
    VerifyLock(ModelsVerifyLockArgs),
    /// Reclaim content-addressed blobs referenced by no cached artifact.
    Prune(ModelsPruneArgs),
}

/// `sbproxy models prune`: reclaim unreferenced weight blobs.
#[derive(clap::Args, Debug, Default)]
struct ModelsPruneArgs {
    /// Cache directory to prune. Defaults to the configured
    /// `proxy.model_host.cache.directory` (or legacy `serve.cache_dir`)
    /// when `-f/--config` is given, then the platform default.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Report what would be reclaimed without deleting anything.
    #[arg(long)]
    dry_run: bool,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ModelEngineArg {
    #[default]
    Auto,
    Vllm,
    #[value(name = "sglang")]
    SGLang,
    LlamaCpp,
    #[value(name = "mistralrs")]
    MistralRs,
}

impl From<ModelEngineArg> for sbproxy_model_host::EngineChoice {
    fn from(value: ModelEngineArg) -> Self {
        match value {
            ModelEngineArg::Auto => Self::Auto,
            ModelEngineArg::Vllm => Self::Vllm,
            ModelEngineArg::SGLang => Self::SGLang,
            ModelEngineArg::LlamaCpp => Self::LlamaCpp,
            ModelEngineArg::MistralRs => Self::MistralRs,
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
struct ModelsLockArgs {
    /// Lockfile path to write. Defaults to `sbproxy-models.lock` next
    /// to the config given with -f/--config.
    #[arg(long = "out")]
    out: Option<PathBuf>,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ModelsVerifyLockArgs {
    /// Lockfile path to check. Defaults to `sbproxy-models.lock` next
    /// to the config (or in the current directory without -f/--config).
    #[arg(long = "lockfile")]
    lockfile: Option<PathBuf>,
    /// Content-addressed artifact cache directory.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,
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
    /// Run the managed-worker startup gate and exit 3 if any check
    /// fails. Checks driver presence, visible accelerators, per-entry
    /// CUDA compatibility, the shared memory an engine asked for, the
    /// weight-cache mount against `serve.cache_budget_gib`, and
    /// model-plane identity material. Intended for a VM bootstrap or a
    /// container entrypoint that should refuse to come up rather than
    /// fail at the first customer request.
    #[arg(long = "strict")]
    strict: bool,
}

#[derive(clap::Args, Debug)]
struct ServiceCmd {
    #[command(subcommand)]
    sub: ServiceSub,
}

#[derive(Subcommand, Debug)]
enum ServiceSub {
    /// Generate a secure config, write a launchd agent, and load it.
    Install(ServiceInstallArgs),
    /// Unload the launchd agent and remove its plist.
    Uninstall(ServiceUninstallArgs),
    /// Report whether the agent is registered with launchd and running.
    Status(ServiceStatusArgs),
    /// Internal launchd bootstrap that loads the declarative environment.
    #[command(hide = true)]
    Launch(ServiceLaunchArgs),
}

/// `sbproxy service install`: the exact same model/engine/accel/port/
/// variant surface as `sbproxy run` (flattened), so the two commands
/// resolve identically. The difference is what happens to the result:
/// `run` serves it in this process; `install` persists it and wraps it
/// in a launchd agent instead.
#[derive(clap::Args, Debug)]
struct ServiceInstallArgs {
    #[command(flatten)]
    run: RunArgs,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ServiceUninstallArgs {
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ServiceStatusArgs {
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ServiceLaunchArgs {
    /// Strict KEY=value environment file loaded before the proxy starts.
    #[arg(long = "environment", value_name = "PATH")]
    environment: PathBuf,
    /// Stable lock shared with transactional service uninstall.
    #[arg(long = "lifecycle-lock", value_name = "PATH")]
    lifecycle_lock: PathBuf,
    /// Durable registry of exact service process generations.
    #[arg(long = "uninstall-state", value_name = "PATH")]
    uninstall_state: PathBuf,
    /// Persisted proxy configuration to serve.
    #[arg(value_name = "CONFIG")]
    config: PathBuf,
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

    // Point the attested meter's self-observation at the `sbproxy_meter_*`
    // families before any config is compiled. The meter reports through a
    // seam rather than owning a metrics dependency (it must stay compilable
    // by an operator who wants the hash chain and nothing else), so nothing
    // is recorded until somebody installs the receiving end. Doing it here
    // means the first metered request of a deployment is counted, which is
    // usually the one somebody is watching. The return value is discarded
    // because a second install is refused rather than accepted, and this is
    // the only caller.
    let _ = sbproxy_observe::meter_metrics::install();

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

    // Resolve the effective log filter and format before tracing init so
    // --log-level and SB_LOG_LEVEL win over RUST_LOG, over the YAML
    // block, and over the built-in default. The priority is documented
    // in docs/observability.md and on `sbproxy_observe::logging`:
    //   1. `--log-level <level>` CLI flag (or SB_LOG_LEVEL via clap env)
    //   2. `RUST_LOG` env var (rustc-style filter syntax)
    //   3. `proxy.observability.log.level` from the config file
    //   4. `info`
    // Format follows the same order minus RUST_LOG, ending at `compact`.
    let config_log = config_log_settings_for_cli(&cli);
    let log_filter = resolve_log_filter(&cli.globals, &config_log);
    let log_format = resolve_log_format(&cli.globals, &config_log);
    let runtime_telemetry = runtime_telemetry_config_for_cli(&cli);
    if let Some(config) = runtime_telemetry.as_ref() {
        if let Err(err) = config.validate_export_metrics() {
            eprintln!("Fatal: {err}");
            std::process::exit(1);
        }
        if let Err(err) = config.validate_propagation() {
            eprintln!("Fatal: {err}");
            std::process::exit(1);
        }
    }
    let log_to_stderr = cli.check || !matches!(&cli.cmd, None | Some(Cmd::Serve(_)));
    init_tracing(
        log_filter,
        log_format,
        runtime_telemetry.as_ref(),
        log_to_stderr,
    );

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
            no_fetch: false,
        };
        run_subcommand("validate", 2, handle_validate_subcommand(&args));
    }

    let global_config_path = cli.globals.config.clone();
    // The global `--check` flag doubles as the update dry-run selector.
    let global_check = cli.check;
    match cli.cmd {
        Some(Cmd::Validate(args)) => {
            // `-f/--config` is a global, so it lands in `cli.globals`
            // rather than in this subcommand's positional. Without this
            // fallback `sbproxy validate -f sb.yml` parses fine and then
            // reports a missing path, which is what every `validate -f`
            // line in the examples and in docs/payment-settlement.md was
            // doing. The positional still wins when both are given.
            let args = ValidateArgs {
                config_path: args.config_path.or(global_config_path.clone()),
                ..args
            };
            run_subcommand("validate", 2, handle_validate_subcommand(&args));
        }
        Some(Cmd::Plan(args)) => {
            run_subcommand("plan", 1, handle_plan_subcommand(&args));
        }
        Some(Cmd::Aggregate(args)) => {
            // `-f/--config` is a global, so it lands in `cli.globals`
            // rather than in this subcommand's positional, the same way
            // `validate` has to fall back. The positional still wins.
            let args = AggregateArgs {
                config_path: args.config_path.or(global_config_path.clone()),
                ..args
            };
            run_subcommand("aggregate", 1, handle_aggregate_subcommand(&args));
        }
        Some(Cmd::Apply(args)) => {
            run_subcommand("apply", 1, handle_apply_subcommand(&args));
        }
        Some(Cmd::Config(cmd)) => {
            // `config authority` and `config pull` print plan-style
            // diffs, where exit 2 means "changes present" rather than an
            // error, so their CLI-error code is 1. The older `config`
            // subcommands keep the 2 they have always used.
            let err_code = if cmd.uses_plan_exit_codes() { 1 } else { 2 };
            run_subcommand(
                "config",
                err_code,
                handle_config_subcommand(&cmd, global_config_path.as_deref()),
            );
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
        Some(Cmd::Audit(cmd)) => {
            run_subcommand("audit", 2, handle_audit_subcommand(&cmd));
        }
        Some(Cmd::Admin(cmd)) => {
            run_subcommand(
                "admin",
                2,
                handle_admin_subcommand(&cmd, global_config_path.as_deref()),
            );
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
        Some(Cmd::Mcp(cmd)) => {
            run_subcommand(
                "mcp",
                2,
                match &cmd.sub {
                    McpSub::Lock(a) => handle_mcp_lock(a, global_config_path.as_deref()),
                    McpSub::VerifyLock(a) => {
                        handle_mcp_verify_lock(a, global_config_path.as_deref())
                    }
                },
            );
        }
        Some(Cmd::Cedar(cmd)) => {
            run_subcommand(
                "cedar",
                2,
                match &cmd.sub {
                    CedarSub::Replay(a) => {
                        let config = a
                            .config
                            .clone()
                            .or(global_config_path.clone())
                            .ok_or_else(|| anyhow::anyhow!("missing -f / --config"));
                        match config {
                            Ok(config) => {
                                cedar_cli::handle_cedar_replay(&cedar_cli::CedarReplayRequest {
                                    config,
                                    against: a.against.clone(),
                                    baseline: a.baseline.clone(),
                                    origin: a.origin.clone(),
                                    json: matches!(a.format, OutputFormat::Json),
                                })
                            }
                            Err(error) => Err(error),
                        }
                    }
                },
            );
        }
        Some(Cmd::Rego(cmd)) => {
            run_subcommand(
                "rego",
                2,
                match &cmd.sub {
                    RegoSub::Test(a) => handle_rego_test(a),
                },
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
        Some(Cmd::Service(cmd)) => {
            run_subcommand("service", 2, handle_service_subcommand(&cmd));
        }
        Some(Cmd::Connect(args)) => {
            run_subcommand(
                "connect",
                2,
                connect::run(&connect::Request {
                    direction: connect::Direction::Connect,
                    clients: args.clients,
                    base_url: args.base_url,
                    model: args.model,
                    dry_run: args.dry_run,
                    json: matches!(args.format, OutputFormat::Json),
                }),
            );
        }
        Some(Cmd::Disconnect(args)) => {
            run_subcommand(
                "disconnect",
                2,
                connect::run(&connect::Request {
                    direction: connect::Direction::Disconnect,
                    clients: args.clients,
                    base_url: connect::DEFAULT_BASE_URL.to_string(),
                    model: None,
                    dry_run: args.dry_run,
                    json: matches!(args.format, OutputFormat::Json),
                }),
            );
        }
        Some(Cmd::Completions { shell }) => {
            print_completions(shell);
        }
        Some(Cmd::Version) => unreachable!("handled by short-circuit above"),
        Some(Cmd::Serve(_)) | None => {
            let path = pick_run_path(&cli);
            // WOR-1864: `--locked` gates boot on the model lockfile.
            // The check runs before `run_proxy` (and therefore before
            // any listener binds); drift or a missing lockfile exits 2.
            if cli.locked {
                enforce_locked_serve_or_exit(path.as_deref());
            }
            // WOR-2459: refused here, before anything binds, rather
            // than ignored: a rescue boot typed under pressure with the
            // mode misspelled must not silently come up with the
            // fallback off, which is the one outcome the operator was
            // trying to avoid.
            let fallback = match cli.globals.config_fallback.as_deref() {
                None => None,
                Some(raw) => match sbproxy_config::BootFallbackMode::parse(raw) {
                    Some(mode) => Some(mode),
                    None => {
                        eprintln!(
                            "Fatal: --config-fallback must be 'off' or 'last-known-good', \
                             got '{raw}'"
                        );
                        std::process::exit(2);
                    }
                },
            };
            run_proxy(path.as_deref(), grace, fallback);
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

fn run_proxy(
    config_path: Option<&std::path::Path>,
    grace: sbproxy_core::GraceConfig,
    fallback: Option<sbproxy_config::BootFallbackMode>,
) {
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
            if let Err(e) = sbproxy_core::server::run_with_fallback(&path_str, grace, fallback) {
                eprintln!("Fatal: {e:#}");
                // WOR-2459: an exhausted ring gets its own exit code, so
                // an init system or a deployment pipeline can tell "this
                // node's config is broken and its own history could not
                // rescue it" apart from every other fatal boot failure
                // without parsing a log line. Every other failure keeps
                // the exit code it has always had.
                let code = if format!("{e:#}")
                    .contains(sbproxy_core::config_boot::RING_EXHAUSTED_MARKER)
                {
                    sbproxy_core::config_boot::EXIT_CONFIG_RING_EXHAUSTED
                } else {
                    1
                };
                std::process::exit(code);
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
    // WOR-2327: install the rotation policy before the backends check
    // below. It governs how a *resolved* credential is cached and how a
    // failed re-resolution behaves, which the key plane applies to
    // credentials it holds regardless of how many backends this config
    // declares. Both keys parsed into nothing before this call existed.
    if let Some(rotation) = &secrets.rotation {
        sbproxy_vault::install_process_rotation(std::sync::Arc::new(
            sbproxy_vault::RotationPolicy::new(
                rotation.re_resolve_interval_secs,
                rotation.grace_period_secs,
            ),
        ));
    }
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
            sbproxy_config::SecretBackendConfig::Azure {
                name,
                vault_url,
                cache_ttl_secs,
                auth,
            } => {
                let auth = match auth {
                    sbproxy_config::AzureBackendAuth::ManagedIdentity => {
                        sbproxy_vault::AzureKeyVaultAuth::ManagedIdentity
                    }
                    sbproxy_config::AzureBackendAuth::UserAssignedIdentity { client_id } => {
                        sbproxy_vault::AzureKeyVaultAuth::UserAssignedIdentity {
                            client_id: client_id.clone(),
                        }
                    }
                    sbproxy_config::AzureBackendAuth::ServicePrincipal {
                        tenant_id,
                        client_id,
                        client_secret,
                        authority,
                    } => sbproxy_vault::AzureKeyVaultAuth::ServicePrincipal {
                        tenant_id: tenant_id.clone(),
                        client_id: client_id.clone(),
                        client_secret: env_interp(client_secret),
                        authority: authority.clone(),
                    },
                    sbproxy_config::AzureBackendAuth::AzureCli => {
                        sbproxy_vault::AzureKeyVaultAuth::AzureCli
                    }
                };
                let cfg = sbproxy_vault::AzureKeyVaultConfig {
                    vault_url: vault_url.clone(),
                    auth,
                    cache_ttl_secs: *cache_ttl_secs,
                };
                match sbproxy_vault::AzureKeyVaultBackend::new(cfg) {
                    Ok(b) => manager.register_backend(
                        sbproxy_vault::VaultProviderType::AzureKeyVault,
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

/// The process-logger settings an `sb.yml` asked for.
///
/// Read off `proxy.observability.log:` before the subscriber exists.
/// Both fields are `None` when the block is absent, which is the
/// common case and means the CLI, env, and built-in defaults decide on
/// their own.
#[derive(Debug, Default, Clone)]
struct ConfigLogSettings {
    /// `proxy.observability.log.level`.
    level: Option<String>,
    /// `proxy.observability.log.format`.
    format: Option<String>,
}

/// Resolve the effective log filter, most specific source first:
///
/// 1. CLI `--log-level <level>` (clap folds in `SB_LOG_LEVEL` via
///    `env = "..."`, so the flag and the variable arrive in the same
///    field with the flag already ahead).
/// 2. `RUST_LOG`.
/// 3. `proxy.observability.log.level` from the config file.
/// 4. `info`.
///
/// CLI `--request-log-level <level>` / `SB_REQUEST_LOG_LEVEL` then
/// append an `access_log=<level>` target directive to whichever of the
/// four won.
///
/// Ranks 1 and 2 also pin the filter for the life of the process
/// (`sbproxy_observe::pin_log_filter_override`), so a later config
/// reload re-asserts YAML only when YAML is what is running. A
/// deployment that exports `RUST_LOG` today keeps getting `RUST_LOG`
/// whatever its `sb.yml` says.
///
/// The full chain, including the admin API and the reload asymmetry
/// between `level` and `format`, is documented on
/// `sbproxy_observe::logging`.
fn resolve_log_filter(g: &GlobalArgs, config: &ConfigLogSettings) -> String {
    let base = match g.log_level.as_deref().filter(|s| !s.is_empty()) {
        Some(v) => {
            sbproxy_observe::pin_log_filter_override();
            v.to_string()
        }
        None => match env::var("RUST_LOG") {
            Ok(v) if !v.is_empty() => {
                sbproxy_observe::pin_log_filter_override();
                v
            }
            _ => match config.level.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(v) => v.trim().to_string(),
                None => "info".to_string(),
            },
        },
    };
    match g.request_log_level.as_deref().filter(|s| !s.is_empty()) {
        Some(request_level) => format!("{base},access_log={request_level}"),
        None => base,
    }
}

/// Resolve the effective output format: CLI `--log-format` (clap folds
/// in `SB_LOG_FORMAT`), then `proxy.observability.log.format`, then
/// `compact`.
///
/// The flag is a `value_enum`, so clap already refused anything but
/// the three names. YAML is a free-form string and reaches here
/// unchecked, so an unknown value is named on stderr and falls back
/// rather than being silently swallowed. Stderr, not `tracing`,
/// because this runs to decide what the subscriber will be.
///
/// Unlike the filter, this cannot change without a restart: the `fmt`
/// layer is fixed when the subscriber is built and the reload handle
/// covers the filter layer only.
fn resolve_log_format(g: &GlobalArgs, config: &ConfigLogSettings) -> LogFormat {
    if let Some(flag) = g.log_format {
        return flag;
    }
    match config.format.as_deref().map(str::trim) {
        None | Some("") => LogFormat::default(),
        Some("compact") => LogFormat::Compact,
        Some("pretty") => LogFormat::Pretty,
        Some("json") => LogFormat::Json,
        Some(other) => {
            // Bounded echo. The three accepted names are short, and
            // `${VAR}` interpolation has already run by the time the
            // value gets here, so an operator who put a variable in the
            // wrong key should not have its whole expansion on stderr.
            let shown: String = other.chars().take(32).collect();
            eprintln!(
                "warning: proxy.observability.log.format: `{shown}` is not one of compact, \
                 pretty, json. Falling back to {}.",
                LogFormat::default().as_str()
            );
            LogFormat::default()
        }
    }
}

/// Read `proxy.observability.log.level` and `.format` out of the run
/// config before the subscriber is built.
///
/// Mirrors [`runtime_telemetry_config_for_cli`]: only the serve path
/// consults the file, and any read or compile failure yields the empty
/// set so the authoritative config error is still reported later,
/// through a subscriber that exists. A subcommand such as `validate`
/// keeps CLI-and-env-only logging, because the YAML block configures
/// the served process rather than the tool inspecting the file.
fn config_log_settings_for_cli(cli: &Cli) -> ConfigLogSettings {
    if cli.check || !matches!(cli.cmd, None | Some(Cmd::Serve(_))) {
        return ConfigLogSettings::default();
    }
    let Some(path) = pick_run_path(cli) else {
        return ConfigLogSettings::default();
    };
    let Ok(yaml) = std::fs::read_to_string(&path) else {
        return ConfigLogSettings::default();
    };
    let Ok(compiled) = sbproxy_config::compile_config(&yaml) else {
        return ConfigLogSettings::default();
    };
    let Some(log) = compiled
        .server
        .observability
        .as_ref()
        .and_then(|observability| observability.log.as_ref())
    else {
        return ConfigLogSettings::default();
    };
    ConfigLogSettings {
        level: log.level.clone(),
        format: log.format.clone(),
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
    // WOR-2481: install the compiled `egress.telemetry:` authorizer into
    // the process-wide configured-gate registry before `init_tracing`
    // (called just after this returns) builds any OTLP exporter, so the
    // trace and metrics exporters' boot-time egress check has something
    // to read. Runs once, here, at boot only: the trace and metrics
    // exporters are never rebuilt on reload, so there is no reload-path
    // counterpart that reinstalls this registry slot. A reload instead
    // re-verifies those already-built exporters' recorded endpoints
    // directly, in `sbproxy_core::server::lifecycle::reload_compiled_config_locked`
    // (`sbproxy_observe::telemetry::reverify_active_boot_telemetry_endpoints`).
    sbproxy_security::egress::install_configured_gate(
        sbproxy_security::egress::EgressPurpose::Telemetry,
        compiled.egress.telemetry.clone(),
    );
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
    log_to_stderr: bool,
) {
    let logging = sbproxy_observe::LoggingConfig {
        level: log_filter,
        format: format.as_str().to_string(),
        sampling: sbproxy_observe::SamplingConfig::default(),
    };
    if log_to_stderr {
        logging.init_with_resolved_filter_and_telemetry_to_stderr(telemetry);
    } else {
        logging.init_with_resolved_filter_and_telemetry(telemetry);
    }
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
            // Validate what would actually boot. A `source:` block means
            // the file on disk is a pointer, and compiling the pointer
            // would report a config valid without ever looking at the
            // document that serves traffic.
            let yaml = resolve_source_for_cli(&yaml, args.no_fetch, &path_str)?;
            let compiled = sbproxy_config::compile_config(&yaml)
                .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
            // Boot-time telemetry validation (export_metrics/enabled
            // consistency, supported propagation values) should reject
            // here too, not just at `sbproxy serve`. Probe with only
            // the fields those two checks read, not the full
            // runtime_telemetry_config mapping: that function also
            // resolves header secret references and hard-exits the
            // process on an unresolved one, which `validate` must
            // never do.
            if let Some(telemetry) = compiled
                .server
                .observability
                .as_ref()
                .and_then(|observability| observability.telemetry.as_ref())
            {
                let probe = sbproxy_observe::TelemetryConfig {
                    enabled: telemetry.enabled,
                    export_metrics: telemetry.export_metrics,
                    propagation: telemetry.propagation.clone(),
                    ..sbproxy_observe::TelemetryConfig::default()
                };
                probe.validate_export_metrics().map_err(|e| {
                    anyhow::anyhow!("config '{path_str}': {e} (this would fail at boot)")
                })?;
                probe.validate_propagation().map_err(|e| {
                    anyhow::anyhow!("config '{path_str}': {e} (this would fail at boot)")
                })?;
            }
            let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let pipeline = sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
                compiled, config_dir,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "config '{path_str}' compiled, but a module failed to construct \
                         (this would fail at boot):\n{e:#}"
                )
            })?;
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

/// Resolve a `source:` block for a CLI subcommand that is about to
/// validate or diff a config document.
///
/// With `--no-fetch`, the pointer file stands and a remote source is
/// reported on stderr rather than silently ignored. Silence is what the
/// old behaviour was, and it is why `validate` used to pass on a config
/// whose real content nobody had looked at.
///
/// # Errors
///
/// Returns an error when the `source:` block is malformed or cannot be
/// resolved.
fn resolve_source_for_cli(yaml: &str, no_fetch: bool, path_str: &str) -> anyhow::Result<String> {
    if !no_fetch {
        return Ok(sbproxy_core::config_source::resolve(yaml)?.text);
    }
    let declares_remote_source = sbproxy_config::source::parse_source_head(yaml)
        .map_err(|e| anyhow::anyhow!("config '{path_str}': {e}"))?
        .is_some();
    if declares_remote_source {
        eprintln!(
            "note: '{path_str}' declares a `source:` block and --no-fetch was passed, so only \
             the pointer file was checked. The document this proxy would actually serve was not \
             looked at."
        );
    }
    Ok(yaml.to_string())
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
    let mut plane = None;
    if let Some(path) = config_path {
        match std::fs::read_to_string(&path) {
            Ok(yaml) => {
                let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                report = with_doctor_extension_inventory(report, &yaml, config_dir);
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
                plane = extract_model_plane_identity(&yaml, config_dir);
                // The canonical `proxy.model_host` form, which the inline
                // `serve:` extraction above does not see.
                if let Some((demand, budget)) = extract_control_plane_demand(&yaml) {
                    report = report.with_control_plane_demand(demand, budget);
                }
            }
            Err(e) => {
                eprintln!("doctor: could not read config '{}': {e}", path.display());
            }
        }
    }
    // The strict gate is evaluated (and reported) whenever asked for,
    // even with no config: "nothing was configured to check" is itself
    // the answer a bootstrap needs, and every check reports `skip`
    // rather than a misleading pass.
    let strict_checks = if args.strict {
        report.strict_checks(plane.as_ref())
    } else {
        Vec::new()
    };
    if args.strict {
        exit = report.strict_exit_code(&strict_checks);
    }
    // WOR-1863: weights other local tools already cached (Ollama, LM
    // Studio, the HF hub), discovered read-only and summarized per
    // source alongside sbproxy's own model cache.
    let foreign = foreign_cache_summaries();
    match args.format {
        OutputFormat::Text => {
            let mut text = report.render_text();
            insert_after_model_cache_block(&mut text, &render_foreign_caches_text(&foreign));
            print!("{text}");
            if args.strict {
                print!("{}", render_strict_checks_text(&strict_checks));
            }
        }
        OutputFormat::Json => {
            // `DoctorReport` lives in sbproxy-core; attach the foreign
            // summary as an extra top-level field rather than widening
            // that struct.
            let mut value = serde_json::to_value(&report)?;
            if let serde_json::Value::Object(object) = &mut value {
                object.insert(
                    "foreign_model_caches".to_string(),
                    serde_json::to_value(&foreign)?,
                );
                if args.strict {
                    object.insert(
                        "strict_checks".to_string(),
                        serde_json::to_value(&strict_checks)?,
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
    }
    Ok(exit)
}

fn with_doctor_extension_inventory(
    report: sbproxy_core::doctor::DoctorReport,
    yaml: &str,
    config_dir: &std::path::Path,
) -> sbproxy_core::doctor::DoctorReport {
    if let Ok(compiled) = sbproxy_config::compile_config(yaml) {
        if let Ok(candidate) =
            sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
                compiled, config_dir,
            )
        {
            return report.with_extension_candidate(&candidate);
        }
    }
    if let Ok(config) = serde_yaml::from_str::<sbproxy_config::ConfigFile>(yaml) {
        let revision = sbproxy_core::identity::config_revision(yaml.as_bytes());
        return report.with_extension_config(&config.extensions, config_dir, Some(&revision));
    }
    report
}

/// Render the `startup gate` block `doctor --strict` appends, one line
/// per named check, in the same two-space style as the rest of the
/// report. The trailing verdict line is what an operator reads first.
fn render_strict_checks_text(checks: &[sbproxy_core::doctor::StrictCheck]) -> String {
    let mut out = String::from("\nstartup gate\n");
    for check in checks {
        out.push_str(&format!(
            "  {:<22} {:<5} {}\n",
            check.check, check.status, check.detail
        ));
    }
    let failed = checks.iter().filter(|c| c.failed()).count();
    out.push_str(&match failed {
        0 => "  verdict: pass (no startup blocker on this host)\n".to_string(),
        1 => "  verdict: FAIL (1 startup blocker)\n".to_string(),
        n => format!("  verdict: FAIL ({n} startup blockers)\n"),
    });
    out
}

/// Read what the canonical `proxy.model_host` block demands of the host,
/// for the strict gate.
///
/// `extract_serve_and_catalog` only sees the inline provider-level
/// `serve:` form. `proxy.model_host` is the form the examples and the
/// self-host docs lead with, so a gate blind to it would report six
/// `skip`s for a worker config that cannot run here. Parses only the
/// engine and cache policy, and tolerates a config it cannot fully
/// understand: an unparseable block yields no demand rather than a
/// spurious blocker.
fn extract_control_plane_demand(
    yaml: &str,
) -> Option<(sbproxy_core::doctor::ServeDemand, Option<f64>)> {
    use sbproxy_config::model_host::{
        ManagedEngineAcceleration, ManagedEngineKind, ModelHostControlConfig,
    };

    let root: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let block = root.get("proxy")?.get("model_host")?;
    let control: ModelHostControlConfig = serde_yaml::from_value(block.clone()).ok()?;

    let mut demand = sbproxy_core::doctor::ServeDemand::default();
    for (kind, engine) in &control.engines {
        // vLLM and SGLang have no non-NVIDIA backend sbproxy can launch,
        // so naming either is a CUDA demand whatever `acceleration` says.
        let cuda_engine = matches!(kind, ManagedEngineKind::Vllm | ManagedEngineKind::SGLang);
        let cuda_accel = engine.acceleration == ManagedEngineAcceleration::Cuda;
        if cuda_engine || cuda_accel {
            demand.requires_cuda = true;
            demand
                .cuda_engines
                .push(format!("proxy.model_host.engines.{kind:?}").to_lowercase());
        }
        if let Some(gib) = engine.shm_size_gib {
            let bytes = gib.saturating_mul(1024 * 1024 * 1024);
            demand.required_shm_bytes = Some(demand.required_shm_bytes.unwrap_or(0).max(bytes));
        }
    }
    Some((demand, control.cache.budget_gib))
}

/// Read the model-plane identity material `proxy.cluster` names, for the
/// strict gate's `model_plane_identity` check.
///
/// Parses the same YAML the proxy boots from, but only the security
/// block: this is deliberately not `compile_config`, because a bootstrap
/// wants the identity verdict even for a config whose origins reference
/// a secret backend that is not reachable yet. Relative paths resolve
/// against the config's own directory, matching how the proxy loads them.
/// `None` means no cluster block, which the check reports as `skip`.
fn extract_model_plane_identity(
    yaml: &str,
    config_dir: &std::path::Path,
) -> Option<sbproxy_core::doctor::ModelPlaneIdentity> {
    let root: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let cluster = root.get("proxy")?.get("cluster")?;
    let security = cluster.get("security");
    let mode = security
        .and_then(|s| s.get("mode"))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("shared_key");
    let mtls = mode == "mtls";
    let worker_role = cluster
        .get("roles")
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|roles| {
            roles
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .any(|role| role == "worker")
        });

    let resolve = |value: &str| -> PathBuf {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            config_dir.join(path)
        }
    };
    let read = |key: &str| -> Option<String> {
        security?
            .get(key)
            .and_then(serde_yaml::Value::as_str)
            .map(str::to_string)
    };

    let mut files = Vec::new();
    let mut missing_keys = Vec::new();
    for key in ["cert_file", "key_file", "ca_file"] {
        match read(key) {
            Some(value) => files.push((key, resolve(&value))),
            // Only mTLS makes the three files mandatory; shared-key mode
            // legitimately omits all of them.
            None if mtls => missing_keys.push(key),
            None => {}
        }
    }
    // Interpolated references (`env:`, `file:`, a vault URI) are resolved
    // by the secret layer at boot, not here, so treat a non-literal
    // shared key as present and let the boot path own that failure.
    let shared_key_present = if mtls {
        None
    } else {
        Some(read("shared_key").is_some_and(|value| !value.trim().is_empty()))
    };

    Some(sbproxy_core::doctor::ModelPlaneIdentity {
        worker_role,
        mtls,
        files,
        missing_keys,
        shared_key_present,
    })
}

/// Per-source rollup of the read-only foreign model-cache scan
/// (WOR-1863): weights Ollama, LM Studio, or the Hugging Face hub
/// already have on disk under the current user's home directory.
#[derive(Debug, serde::Serialize)]
struct ForeignCacheSummary {
    /// Which foreign cache the files came from.
    source: sbproxy_model_host::ForeignCacheSource,
    /// Number of weight files found for this source.
    files: usize,
    /// Combined on-disk size of those files in bytes.
    total_bytes: u64,
}

/// Scan the foreign model caches under the current home directory and
/// roll the findings up per source, in a stable order. Read-only and
/// silent about absent directories; no resolvable home directory
/// yields an empty list.
fn foreign_cache_summaries() -> Vec<ForeignCacheSummary> {
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    else {
        return Vec::new();
    };
    let mut summaries: Vec<ForeignCacheSummary> = Vec::new();
    for file in sbproxy_model_host::discover_foreign_models(&home) {
        match summaries.iter_mut().find(|s| s.source == file.source) {
            Some(summary) => {
                summary.files += 1;
                summary.total_bytes += file.size_bytes;
            }
            None => summaries.push(ForeignCacheSummary {
                source: file.source,
                files: 1,
                total_bytes: file.size_bytes,
            }),
        }
    }
    summaries
}

/// Render the `foreign model caches` doctor block, mirroring the
/// report's section formatting: one line per source found, or a
/// single `none found` line.
fn render_foreign_caches_text(summaries: &[ForeignCacheSummary]) -> String {
    let mut out = String::from("\nforeign model caches\n");
    if summaries.is_empty() {
        out.push_str("  none found\n");
        return out;
    }
    for summary in summaries {
        let plural = if summary.files == 1 { "" } else { "s" };
        out.push_str(&format!(
            "  {:<14}{} file{plural}, {}\n",
            summary.source.label(),
            summary.files,
            format_cache_size(summary.total_bytes)
        ));
    }
    out
}

/// Human-readable byte size for the foreign-caches block: GiB for
/// anything large, MiB below one GiB, raw bytes below one MiB.
fn format_cache_size(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.0} MiB", b / MIB)
    } else {
        format!("{bytes} B")
    }
}

/// Insert `block` into the rendered doctor text directly after the
/// `model cache` section, falling back to appending at the end if
/// that section marker ever moves.
fn insert_after_model_cache_block(text: &mut String, block: &str) {
    const MARKER: &str = "\nmodel cache\n";
    let insert_at = text.find(MARKER).and_then(|start| {
        let body = start + MARKER.len();
        // The section body ends where the blank line before the next
        // section header begins.
        text[body..].find("\n\n").map(|i| body + i + 1)
    });
    match insert_at {
        Some(at) => text.insert_str(at, block),
        None => text.push_str(block),
    }
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

/// The ready banner, whose loopback URLs are a claim about where the
/// listener actually is.
///
/// This prints `http://127.0.0.1:<port>` and hands the operator an
/// `OPENAI_BASE_URL` built from it. That is only true because
/// `prepare_run` pins `proxy.bind_address` to `127.0.0.1` in the config
/// it generates (WOR-2199). Before it did, this banner said loopback
/// while the listener was on every interface, which is worse than
/// saying nothing: an operator reads it and concludes the gateway is
/// not reachable from the network.
///
/// If the generated config ever binds something else, this has to print
/// what was bound. A URL here is evidence, not decoration.
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
        "mistralrs" => Ok(sbproxy_model_host::EngineChoice::MistralRs),
        "embedded" => {
            anyhow::bail!(
                "embedded is not a managed process engine; use auto, vllm, sglang, llama_cpp, \
                 or mistralrs"
            )
        }
        other => {
            anyhow::bail!(
                "unknown engine '{other}'; use auto, vllm, sglang, llama_cpp, or mistralrs"
            )
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
        sbproxy_model_host::EngineKind::LlamaCpp => {
            // The generated config pins the engine release explicitly, so
            // the pin must be one this host's macOS can load: recent
            // llama.cpp macos-arm64 assets link against macOS 26 and die
            // at dyld link time on older hosts. The host-aware default
            // picks the newest pinned build the OS supports, and fails
            // here, loudly, when none fits.
            let tag = sbproxy_model_host::default_llama_release_tag_for_host()
                .map_err(|reason| anyhow::anyhow!("select llama.cpp release: {reason}"))?;
            serde_json::json!({
                "launch": "binary",
                "version": tag,
                "acceleration": acceleration,
            })
        }
        sbproxy_model_host::EngineKind::MistralRs => serde_json::json!({
            // Binary engine like llama.cpp: PATH-first with the pinned
            // upstream prebuilt release as the fallback (WOR-1861).
            "launch": "binary",
            "version": sbproxy_model_host::mistralrs_release::DEFAULT_MISTRALRS_RELEASE_TAG,
            "acceleration": acceleration,
        }),
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
            // WOR-2199: loopback, explicitly. This command generates a
            // config for one machine to serve itself: the origins map
            // below is keyed on 127.0.0.1 and localhost, the ready
            // banner prints a loopback URL, and there is no
            // authentication on this listener. Binding every interface
            // would publish an unauthenticated model gateway to the
            // network while telling the operator it was local.
            //
            // An operator who wants it reachable writes their own
            // config and sets proxy.bind_address there, which is a
            // decision rather than a default.
            "bind_address": "127.0.0.1",
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

// --- `service` handler: launchd agent install/uninstall/status (macOS) ---
//
// `sbproxy-platform` (storage/circuit-breaker/DNS/health) has no
// precedent for OS service integration and nothing in its dependency graph
// is CLI-shaped, so this lives next to `prepare_run`/`RunArgs` in the
// binary crate instead, alongside the other host-integration code already
// here (`atomic_replace_binary`, `raise_fd_limit`, `tighten_directory_permissions`).

/// launchd label for the single per-user sbproxy agent. One agent per
/// host: a second `service install` replaces it rather than adding a
/// second one, mirroring how `sbproxy run` serves one model at a time.
const SERVICE_LABEL: &str = "dev.sbproxy.agent";

/// Seconds launchd waits for the agent to exit after SIGTERM before it
/// escalates to SIGKILL.
///
/// launchd's default is 20 seconds, which is far shorter than the proxy's
/// full drain. The drain has TWO phases of the same length: Pingora sleeps
/// the whole `grace_period_seconds`, then waits up to
/// `graceful_shutdown_timeout_seconds` for service runtimes to exit, and
/// the server sets both to the 30-second default grace
/// (`SBPROXY_SHUTDOWN_GRACE_MS`), so a shutdown after traffic takes about
/// 60 seconds end to end. The previous value of 45 only budgeted one
/// phase, so launchd SIGKILLed a draining agent mid-shutdown, skipping
/// every Rust destructor including the engine reap (WOR-2167). 90 leaves
/// the full two-phase drain room to finish; raise it alongside any
/// increase to the default grace.
///
/// Durable managed-engine ownership separately covers a forced gateway
/// death; this timeout preserves the preferred graceful path so a normal
/// `service uninstall` can drain before verifying and clearing ownership.
const SERVICE_EXIT_TIMEOUT_SECS: u32 = 90;

/// The proxy's default shutdown grace in seconds. The full drain is two
/// phases of this length (grace sleep, then runtime exit wait; see
/// `crates/sbproxy-core/src/server/lifecycle.rs`, which sets both Pingora
/// fields from the same value), and [`SERVICE_EXIT_TIMEOUT_SECS`] has to
/// exceed the sum. Kept next to it so the relationship is checked at
/// compile time rather than in a test that someone has to remember to run.
const DEFAULT_SHUTDOWN_GRACE_SECS: u32 = 30;
const _: () = assert!(
    SERVICE_EXIT_TIMEOUT_SECS > 2 * DEFAULT_SHUTDOWN_GRACE_SECS,
    "launchd would SIGKILL the agent before its two-phase shutdown drain could finish"
);

/// Filesystem locations the `service` subcommands read and write,
/// resolved from `$HOME` once so every handler agrees on the same
/// paths. The config lives under Application Support: unlike
/// `PrivateRunDirectory`'s config, it must outlive the process that
/// wrote it, since launchd rereads it on every future load. The plist
/// lives in the standard per-user launchd agent directory. The two log
/// paths are where launchd redirects the child's stdout/stderr.
struct ServicePaths {
    config: PathBuf,
    plist: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    env_file: PathBuf,
    uninstall_state: PathBuf,
    lifecycle_lock: PathBuf,
}

fn service_paths() -> anyhow::Result<ServicePaths> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME is not set"))?;
    let service_dir = home.join("Library/Application Support/sbproxy/service");
    Ok(ServicePaths {
        config: service_dir.join("sb.yml"),
        plist: home
            .join("Library/LaunchAgents")
            .join(format!("{SERVICE_LABEL}.plist")),
        stdout_log: home.join("Library/Logs/sbproxy/service.log"),
        stderr_log: home.join("Library/Logs/sbproxy/service.err.log"),
        env_file: service_dir.join("env"),
        uninstall_state: service_dir.join("uninstall-state.json"),
        lifecycle_lock: service_dir.join("lifecycle.lock"),
    })
}

const SERVICE_ENGINE_OWNERSHIP_ENV: &str = "SBPROXY_ENGINE_OWNERSHIP_DIR";
const MAX_SERVICE_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_SERVICE_PLIST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default)]
struct ServiceEnvironment {
    variables: BTreeMap<String, String>,
}

/// Header written into a freshly created service environment file.
///
/// A launchd agent inherits almost nothing from the shell that installed
/// it, so a `HF_TOKEN` exported in a terminal is invisible to the agent
/// and a gated model fails to pull with no obvious cause. This file is
/// where those values live. It is created once and never rewritten, so
/// reinstalling to change model or port does not discard the operator's
/// token.
const SERVICE_ENV_TEMPLATE: &str = "\
# sbproxy launchd agent environment.
#
# Read as data before the agent starts, so anything set here is visible
# to the served process. Use one KEY=value per line. Values are literal:
# do not use export, quotes, shell expansion, commands, or inline comments.
# `sbproxy service install` creates this file once and never overwrites it,
# so a token set here survives a reinstall.
#
# Hugging Face token required to pull a gated model:
# HF_TOKEN=hf_...
# Raise or lower the agent's log level:
# RUST_LOG=info
# Optional absolute directory for durable managed-engine ownership:
# SBPROXY_ENGINE_OWNERSHIP_DIR=/absolute/path
";

fn read_service_environment(path: &std::path::Path) -> anyhow::Result<ServiceEnvironment> {
    use std::io::Read as _;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ServiceEnvironment::default());
        }
        Err(error) => {
            return Err(anyhow::anyhow!("read '{}': {error}", path.display()));
        }
    };
    let length = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("inspect '{}': {error}", path.display()))?
        .len();
    if length > MAX_SERVICE_ENVIRONMENT_BYTES as u64 {
        anyhow::bail!(
            "read '{}': service environment exceeds maximum size of {} bytes",
            path.display(),
            MAX_SERVICE_ENVIRONMENT_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_SERVICE_ENVIRONMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", path.display()))?;
    if bytes.len() > MAX_SERVICE_ENVIRONMENT_BYTES {
        anyhow::bail!(
            "read '{}': service environment exceeds maximum size of {} bytes",
            path.display(),
            MAX_SERVICE_ENVIRONMENT_BYTES
        );
    }
    let contents = String::from_utf8(bytes)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", path.display()))?;
    parse_service_environment(path, &contents)
}

fn parse_service_environment(
    path: &std::path::Path,
    contents: &str,
) -> anyhow::Result<ServiceEnvironment> {
    let mut variables = BTreeMap::new();
    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            anyhow::bail!(
                "parse '{}', line {line_number}: expected KEY=value; shell syntax is not supported",
                path.display()
            );
        };
        let key_is_valid = !key.is_empty()
            && key
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !key_is_valid {
            anyhow::bail!(
                "parse '{}', line {line_number}: invalid environment key '{key}'; \
                 use strict KEY=value syntax without export",
                path.display()
            );
        }
        if value.trim() != value {
            anyhow::bail!(
                "parse '{}', line {line_number}: leading or trailing value whitespace is ambiguous",
                path.display()
            );
        }
        let quoted = value.starts_with('\'')
            || value.starts_with('"')
            || value.ends_with('\'')
            || value.ends_with('"');
        let shell_syntax = quoted
            || value.contains('$')
            || value.contains('`')
            || value.contains('\\')
            || value.contains(';')
            || value.contains("&&")
            || value.contains("||")
            || value.contains("<(")
            || value.contains(">(")
            || value.contains(" #")
            || value.starts_with('~');
        if shell_syntax {
            anyhow::bail!(
                "parse '{}', line {line_number}: shell syntax is not supported; \
                 provide the literal value without quotes, expansion, commands, or comments",
                path.display()
            );
        }
        if variables
            .insert(key.to_string(), value.to_string())
            .is_some()
        {
            anyhow::bail!(
                "parse '{}', line {line_number}: duplicate environment key '{key}'",
                path.display()
            );
        }
    }
    Ok(ServiceEnvironment { variables })
}

/// Create the environment file if it is absent, leaving an existing one
/// untouched. Mode 0600: it is the documented home for a Hugging Face
/// token.
fn ensure_service_env_file(path: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write as _;

    if path.exists() {
        return Ok(());
    }
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
    file.write_all(SERVICE_ENV_TEMPLATE.as_bytes())
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", path.display()))?;
    Ok(())
}

const LEGACY_SERVICE_UNINSTALL_STATE_SCHEMA_VERSION: u32 = 1;
const SERVICE_UNINSTALL_STATE_SCHEMA_VERSION: u32 = 2;
const MAX_SERVICE_OWNER_GENERATIONS: usize = 4_096;
const MAX_SERVICE_UNINSTALL_STATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SERVICE_UNLOAD_ATTEMPTS: usize = 8;
const MAX_SERVICE_UNLOAD_NO_PROGRESS: usize = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ServiceUninstallState {
    schema_version: u32,
    ownership_directory: PathBuf,
    owners: Vec<sbproxy_model_host::ManagedEngineOwner>,
    #[serde(default)]
    bootstrap_registered_owners: Vec<sbproxy_model_host::ManagedEngineOwner>,
}

#[derive(Debug)]
struct ServiceLifecycleLock {
    _file: std::fs::File,
}

#[cfg(unix)]
fn acquire_service_lifecycle_lock(path: &std::path::Path) -> anyhow::Result<ServiceLifecycleLock> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("'{}' has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", parent.display()))?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    #[cfg(target_os = "macos")]
    options.custom_flags(0x0000_0100); // O_NOFOLLOW
    #[cfg(target_os = "linux")]
    options.custom_flags(0x0002_0000); // O_NOFOLLOW
    let file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("open lifecycle lock '{}': {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("inspect lifecycle lock '{}': {error}", path.display()))?;
    let parent_metadata = std::fs::metadata(parent)
        .map_err(|error| anyhow::anyhow!("inspect '{}': {error}", parent.display()))?;
    if !metadata.file_type().is_file() || metadata.uid() != parent_metadata.uid() {
        anyhow::bail!(
            "lifecycle lock '{}' must be a regular file owned by the service directory owner",
            path.display()
        );
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| anyhow::anyhow!("secure lifecycle lock '{}': {error}", path.display()))?;
    fs2::FileExt::lock_exclusive(&file)
        .map_err(|error| anyhow::anyhow!("lock lifecycle '{}': {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| anyhow::anyhow!("sync lifecycle lock '{}': {error}", path.display()))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| anyhow::anyhow!("sync '{}': {error}", parent.display()))?;
    Ok(ServiceLifecycleLock { _file: file })
}

#[cfg(not(unix))]
fn acquire_service_lifecycle_lock(path: &std::path::Path) -> anyhow::Result<ServiceLifecycleLock> {
    anyhow::bail!(
        "service lifecycle lock '{}' is only supported on Unix",
        path.display()
    )
}

fn append_service_owner(
    state: &mut ServiceUninstallState,
    owner: &sbproxy_model_host::ManagedEngineOwner,
) -> anyhow::Result<bool> {
    if service_owner_list_contains(&state.owners, owner) {
        return Ok(false);
    }
    if state.owners.len() >= MAX_SERVICE_OWNER_GENERATIONS {
        anyhow::bail!(
            "service owner generation limit ({MAX_SERVICE_OWNER_GENERATIONS}) reached; \
             uninstall and inspect the durable lifecycle state before restarting"
        );
    }
    state.owners.push(owner.clone());
    Ok(true)
}

fn service_owner_list_contains(
    owners: &[sbproxy_model_host::ManagedEngineOwner],
    owner: &sbproxy_model_host::ManagedEngineOwner,
) -> bool {
    owners
        .iter()
        .any(|candidate| candidate.same_process_generation(owner))
}

fn register_bootstrap_service_owner(
    state: &mut ServiceUninstallState,
    owner: &sbproxy_model_host::ManagedEngineOwner,
) -> anyhow::Result<bool> {
    let owner_is_new = !service_owner_list_contains(&state.owners, owner);
    let registration_is_new =
        !service_owner_list_contains(&state.bootstrap_registered_owners, owner);
    if owner_is_new && state.owners.len() >= MAX_SERVICE_OWNER_GENERATIONS {
        anyhow::bail!(
            "service owner generation limit ({MAX_SERVICE_OWNER_GENERATIONS}) reached; \
             uninstall and inspect the durable lifecycle state before restarting"
        );
    }
    if registration_is_new
        && state.bootstrap_registered_owners.len() >= MAX_SERVICE_OWNER_GENERATIONS
    {
        anyhow::bail!(
            "bootstrap-registered service owner generation limit \
             ({MAX_SERVICE_OWNER_GENERATIONS}) reached; uninstall and inspect the durable \
             lifecycle state before restarting"
        );
    }
    if owner_is_new {
        state.owners.push(owner.clone());
    }
    if registration_is_new {
        state.bootstrap_registered_owners.push(owner.clone());
    }
    Ok(owner_is_new || registration_is_new)
}

fn register_service_owner_locked(
    _lock: &ServiceLifecycleLock,
    state_path: &std::path::Path,
    ownership_directory: &std::path::Path,
    owner: &sbproxy_model_host::ManagedEngineOwner,
) -> anyhow::Result<()> {
    if !ownership_directory.is_absolute() {
        anyhow::bail!(
            "managed-engine ownership directory '{}' must be absolute",
            ownership_directory.display()
        );
    }
    let existing = read_service_uninstall_state(state_path)?;
    let mut state = existing.unwrap_or_else(|| ServiceUninstallState {
        schema_version: SERVICE_UNINSTALL_STATE_SCHEMA_VERSION,
        ownership_directory: ownership_directory.to_path_buf(),
        owners: Vec::new(),
        bootstrap_registered_owners: Vec::new(),
    });
    if state.ownership_directory != ownership_directory {
        anyhow::bail!(
            "service lifecycle state '{}' uses ownership directory '{}', not '{}'; \
             uninstall the prior service generation before changing directories",
            state_path.display(),
            state.ownership_directory.display(),
            ownership_directory.display()
        );
    }
    if register_bootstrap_service_owner(&mut state, owner)? {
        persist_service_uninstall_state(state_path, &state)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchdJobStatus {
    NotLoaded,
    Loaded { pid: Option<u32> },
}

trait LaunchdController {
    fn status(&mut self) -> anyhow::Result<LaunchdJobStatus>;
    fn unload(&mut self, plist: &std::path::Path) -> anyhow::Result<()>;
}

struct SystemLaunchdController;

fn classify_launchctl_list_status(
    success: bool,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> anyhow::Result<LaunchdJobStatus> {
    if success {
        return Ok(LaunchdJobStatus::Loaded {
            pid: parse_launchctl_list_pid(stdout),
        });
    }

    let normalized_stderr = stderr.to_ascii_lowercase();
    let service_is_missing = normalized_stderr.contains("could not find service")
        || normalized_stderr.contains("could not find specified service")
        || normalized_stderr.contains("service cannot be found");
    if service_is_missing {
        return Ok(LaunchdJobStatus::NotLoaded);
    }

    let status = exit_code.map_or_else(
        || "terminated by signal".to_string(),
        |code| format!("exit code {code}"),
    );
    let detail = stderr.trim();
    anyhow::bail!(
        "launchctl list '{SERVICE_LABEL}' failed ({status}): {}",
        if detail.is_empty() {
            "no error output"
        } else {
            detail
        }
    );
}

impl LaunchdController for SystemLaunchdController {
    fn status(&mut self) -> anyhow::Result<LaunchdJobStatus> {
        let output = std::process::Command::new("launchctl")
            .arg("list")
            .arg(SERVICE_LABEL)
            .output()
            .map_err(|error| anyhow::anyhow!("launchctl list: {error}"))?;
        classify_launchctl_list_status(
            output.status.success(),
            output.status.code(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )
    }

    fn unload(&mut self, plist: &std::path::Path) -> anyhow::Result<()> {
        let output = std::process::Command::new("launchctl")
            .arg("unload")
            .arg(plist)
            .output()
            .map_err(|error| anyhow::anyhow!("launchctl unload: {error}"))?;
        if !output.status.success() {
            anyhow::bail!(
                "launchctl unload '{}' failed: {}",
                plist.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

trait ServiceEngineCleanup {
    fn capture_owner(&mut self, pid: u32)
        -> anyhow::Result<sbproxy_model_host::ManagedEngineOwner>;
    fn reap_owner(
        &mut self,
        directory: &std::path::Path,
        owner: &sbproxy_model_host::ManagedEngineOwner,
    ) -> anyhow::Result<usize>;
}

struct SystemServiceEngineCleanup;

impl ServiceEngineCleanup for SystemServiceEngineCleanup {
    fn capture_owner(
        &mut self,
        pid: u32,
    ) -> anyhow::Result<sbproxy_model_host::ManagedEngineOwner> {
        sbproxy_model_host::capture_managed_engine_owner(pid).ok_or_else(|| {
            anyhow::anyhow!(
                "capture exact launchd owner pid {pid}: process identity is no longer available"
            )
        })
    }

    fn reap_owner(
        &mut self,
        directory: &std::path::Path,
        owner: &sbproxy_model_host::ManagedEngineOwner,
    ) -> anyhow::Result<usize> {
        sbproxy_model_host::reap_managed_engines_owned_by_identity_at(
            directory,
            owner,
            std::time::Duration::from_secs(u64::from(SERVICE_EXIT_TIMEOUT_SECS)),
            std::time::Duration::from_secs(5),
        )
        .map_err(|error| anyhow::anyhow!("reap managed engines after service unload: {error}"))
    }
}

#[derive(Debug, Clone, Copy)]
struct ServiceUninstallOutcome {
    removed: bool,
    engines_reaped: usize,
}

fn service_engine_ownership_directory(paths: &ServicePaths) -> anyhow::Result<PathBuf> {
    let environment = read_service_environment(&paths.env_file)?;
    service_engine_ownership_directory_from_environment(
        &environment,
        &paths.env_file,
        &paths.config,
    )
}

fn service_engine_ownership_directory_from_environment(
    environment: &ServiceEnvironment,
    env_file: &std::path::Path,
    config: &std::path::Path,
) -> anyhow::Result<PathBuf> {
    if let Some(value) = environment.variables.get(SERVICE_ENGINE_OWNERSHIP_ENV) {
        if value.is_empty() {
            anyhow::bail!(
                "{SERVICE_ENGINE_OWNERSHIP_ENV} in '{}' is empty",
                env_file.display()
            );
        }
        let directory = PathBuf::from(value);
        if !directory.is_absolute() {
            anyhow::bail!(
                "{SERVICE_ENGINE_OWNERSHIP_ENV} in '{}' must be absolute",
                env_file.display()
            );
        }
        return Ok(directory);
    }
    config
        .parent()
        .and_then(std::path::Path::parent)
        .map(|application_dir| application_dir.join("managed-engines"))
        .ok_or_else(|| anyhow::anyhow!("resolve default managed-engine ownership directory"))
}

fn read_service_uninstall_state(
    path: &std::path::Path,
) -> anyhow::Result<Option<ServiceUninstallState>> {
    use std::io::Read as _;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!("read '{}': {error}", path.display()));
        }
    };
    let length = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("inspect '{}': {error}", path.display()))?
        .len();
    if length > MAX_SERVICE_UNINSTALL_STATE_BYTES as u64 {
        anyhow::bail!(
            "read '{}': lifecycle state exceeds maximum size of {} bytes",
            path.display(),
            MAX_SERVICE_UNINSTALL_STATE_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(length as usize);
    let mut limited = file.take((MAX_SERVICE_UNINSTALL_STATE_BYTES + 1) as u64);
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", path.display()))?;
    if bytes.len() > MAX_SERVICE_UNINSTALL_STATE_BYTES {
        anyhow::bail!(
            "read '{}': lifecycle state exceeds maximum size of {} bytes",
            path.display(),
            MAX_SERVICE_UNINSTALL_STATE_BYTES
        );
    }
    let mut state: ServiceUninstallState = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("parse '{}': {error}", path.display()))?;
    match state.schema_version {
        LEGACY_SERVICE_UNINSTALL_STATE_SCHEMA_VERSION => {
            // Schema 1 mixed bootstrap registrations with owners observed by
            // uninstall, so none of its entries can prove registration.
            state.bootstrap_registered_owners.clear();
            state.schema_version = SERVICE_UNINSTALL_STATE_SCHEMA_VERSION;
        }
        SERVICE_UNINSTALL_STATE_SCHEMA_VERSION => {}
        _ => anyhow::bail!("validate '{}': unsupported or unsafe state", path.display()),
    }
    if !state.ownership_directory.is_absolute()
        || state.owners.len() > MAX_SERVICE_OWNER_GENERATIONS
        || state.bootstrap_registered_owners.len() > MAX_SERVICE_OWNER_GENERATIONS
        || !state
            .bootstrap_registered_owners
            .iter()
            .all(|owner| service_owner_list_contains(&state.owners, owner))
    {
        anyhow::bail!("validate '{}': unsupported or unsafe state", path.display());
    }
    Ok(Some(state))
}

fn persist_service_uninstall_state(
    path: &std::path::Path,
    state: &ServiceUninstallState,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("'{}' has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".uninstall-state-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| anyhow::anyhow!("encode uninstall state: {error}"))?;
    if bytes.len() + 1 > MAX_SERVICE_UNINSTALL_STATE_BYTES {
        anyhow::bail!(
            "persist '{}': lifecycle state exceeds maximum size of {} bytes",
            path.display(),
            MAX_SERVICE_UNINSTALL_STATE_BYTES
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", temporary.display()))?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow::anyhow!("persist '{}': {error}", path.display()));
    }
    Ok(())
}

fn remove_service_file(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| anyhow::anyhow!("sync '{}': {error}", parent.display()))?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!("remove '{}': {error}", path.display())),
    }
}

fn service_plist_uses_registered_bootstrap(paths: &ServicePaths) -> anyhow::Result<bool> {
    use std::io::Read as _;

    let file = match std::fs::File::open(&paths.plist) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "read service plist '{}': {error}",
                paths.plist.display()
            ));
        }
    };
    let length = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("inspect '{}': {error}", paths.plist.display()))?
        .len();
    if length > MAX_SERVICE_PLIST_BYTES as u64 {
        anyhow::bail!(
            "read '{}': service plist exceeds maximum size of {} bytes",
            paths.plist.display(),
            MAX_SERVICE_PLIST_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_SERVICE_PLIST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", paths.plist.display()))?;
    if bytes.len() > MAX_SERVICE_PLIST_BYTES {
        anyhow::bail!(
            "read '{}': service plist exceeds maximum size of {} bytes",
            paths.plist.display(),
            MAX_SERVICE_PLIST_BYTES
        );
    }
    let plist = String::from_utf8(bytes)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", paths.plist.display()))?;
    Ok([
        "<string>service</string>",
        "<string>launch</string>",
        "<string>--environment</string>",
        "<string>--lifecycle-lock</string>",
        "<string>--uninstall-state</string>",
        &format!(
            "<string>{}</string>",
            xml_escape(&paths.lifecycle_lock.to_string_lossy())
        ),
        &format!(
            "<string>{}</string>",
            xml_escape(&paths.uninstall_state.to_string_lossy())
        ),
    ]
    .into_iter()
    .all(|marker| plist.contains(marker)))
}

fn perform_service_uninstall(
    paths: &ServicePaths,
    launchd: &mut dyn LaunchdController,
    cleanup: &mut dyn ServiceEngineCleanup,
) -> anyhow::Result<ServiceUninstallOutcome> {
    // A launchd replacement must register under this same lock before it
    // can exec the gateway. Holding it through unload makes the registry
    // and launchd transition one cooperative transaction.
    let _lifecycle_lock = acquire_service_lifecycle_lock(&paths.lifecycle_lock)?;
    let removed = paths.plist.exists();
    let mut state = read_service_uninstall_state(&paths.uninstall_state)?;
    let mut status = launchd.status()?;

    if matches!(status, LaunchdJobStatus::Loaded { .. })
        && !service_plist_uses_registered_bootstrap(paths)?
    {
        anyhow::bail!(
            "launchd job '{SERVICE_LABEL}' uses a legacy plist without exact generation \
             registration; unloading it cannot close the KeepAlive replacement race. \
             Reinstall the intended model with this sbproxy version (`sbproxy service install \
             <model>`), wait for `sbproxy service status` to report running, then retry uninstall. \
             The existing plist and lifecycle state were retained."
        );
    }

    if state.is_none() && status == LaunchdJobStatus::NotLoaded {
        remove_service_file(&paths.plist)?;
        return Ok(ServiceUninstallOutcome {
            removed,
            engines_reaped: 0,
        });
    }

    // The plist on disk can be newer than the generation launchd is still
    // running. Prove the exact initially observed process completed this
    // version's bootstrap registration before trusting the cooperative lock.
    // Owners recorded only by an older uninstall attempt do not carry that
    // provenance and cannot authorize unload.
    let mut initially_registered_owner = match status {
        LaunchdJobStatus::Loaded { pid: Some(pid) } => {
            let owner = cleanup.capture_owner(pid)?;
            let was_bootstrap_registered = state.as_ref().is_some_and(|state| {
                service_owner_list_contains(&state.bootstrap_registered_owners, &owner)
            });
            if !was_bootstrap_registered {
                anyhow::bail!(
                    "launchd job '{SERVICE_LABEL}' generation pid {pid} was not registered by \
                     the service bootstrap; refusing to unload because the plist on disk cannot \
                     prove which generation launchd is running. Reinstall the intended model \
                     with this sbproxy version (`sbproxy service install <model>`), wait for \
                     `sbproxy service status` to report running, then retry uninstall. The \
                     existing plist and lifecycle state were retained."
                );
            }
            Some((pid, owner))
        }
        LaunchdJobStatus::NotLoaded | LaunchdJobStatus::Loaded { pid: None } => None,
    };

    if state.is_none() {
        state = Some(ServiceUninstallState {
            schema_version: SERVICE_UNINSTALL_STATE_SCHEMA_VERSION,
            ownership_directory: service_engine_ownership_directory(paths)?,
            owners: Vec::new(),
            bootstrap_registered_owners: Vec::new(),
        });
    }
    let state = state.as_mut().expect("uninstall state initialized");
    // Persist the transaction before touching launchd. In particular, a
    // loaded job without a PID cannot be tied to an exact owner yet and
    // must leave both retry handles intact.
    persist_service_uninstall_state(&paths.uninstall_state, state)?;

    let mut unload_attempts = 0usize;
    let mut no_progress = 0usize;
    let mut prior_owner: Option<sbproxy_model_host::ManagedEngineOwner> = None;
    loop {
        let pid = match status {
            LaunchdJobStatus::NotLoaded => break,
            LaunchdJobStatus::Loaded { pid: Some(pid) } => pid,
            LaunchdJobStatus::Loaded { pid: None } => {
                anyhow::bail!(
                    "launchd job '{SERVICE_LABEL}' is loaded but has no PID; \
                     exact managed-engine ownership cannot be captured yet"
                );
            }
        };

        let owner = if let Some((registered_pid, owner)) = initially_registered_owner.take() {
            debug_assert_eq!(registered_pid, pid);
            owner
        } else {
            cleanup.capture_owner(pid)?
        };
        let owner_was_added = append_service_owner(state, &owner)?;
        if owner_was_added {
            persist_service_uninstall_state(&paths.uninstall_state, state)?;
        }
        if prior_owner
            .as_ref()
            .is_some_and(|prior| prior.same_process_generation(&owner))
            && !owner_was_added
        {
            no_progress += 1;
            if no_progress >= MAX_SERVICE_UNLOAD_NO_PROGRESS {
                anyhow::bail!(
                    "launchd unload made no progress after {no_progress} repeated observations \
                     of pid {pid}; retry handles were retained"
                );
            }
        } else {
            no_progress = 0;
        }
        prior_owner = Some(owner);
        if unload_attempts >= MAX_SERVICE_UNLOAD_ATTEMPTS {
            anyhow::bail!(
                "launchd job '{SERVICE_LABEL}' remained loaded after \
                 {MAX_SERVICE_UNLOAD_ATTEMPTS} unload attempts; retry handles were retained"
            );
        }
        unload_attempts += 1;

        match launchd.unload(&paths.plist) {
            Ok(()) => {
                // KeepAlive can replace the process generation between the
                // first status call and unload. Re-query until launchd
                // confirms the job is gone, capturing and durably recording
                // every replacement generation it reports.
                status = launchd.status()?;
            }
            Err(unload_error) => {
                status = launchd.status()?;
                match status {
                    LaunchdJobStatus::NotLoaded => break,
                    LaunchdJobStatus::Loaded {
                        pid: Some(replacement_pid),
                    } => {
                        let replacement_owner = cleanup.capture_owner(replacement_pid)?;
                        if append_service_owner(state, &replacement_owner)? {
                            persist_service_uninstall_state(&paths.uninstall_state, state)?;
                        }
                        return Err(unload_error);
                    }
                    LaunchdJobStatus::Loaded { pid: None } => {
                        return Err(anyhow::anyhow!(
                            "launchd job '{SERVICE_LABEL}' remains loaded without a PID: \
                             {unload_error:#}"
                        ));
                    }
                }
            }
        }
    }

    let mut engines_reaped = 0;
    for owner in &state.owners {
        engines_reaped += cleanup.reap_owner(&state.ownership_directory, owner)?;
    }
    // The plist remains the retry handle until every exact owner has exited
    // and every one of its durable engine records has been resolved.
    remove_service_file(&paths.plist)?;
    remove_service_file(&paths.uninstall_state)?;
    // Keep lifecycle_lock permanently. Unlinking a cooperative lock path can
    // split future lockers across different inodes while one still holds the
    // old file descriptor.
    Ok(ServiceUninstallOutcome {
        removed,
        engines_reaped,
    })
}

/// Escape the five XML predefined entities. Every value interpolated
/// into [`render_service_plist`] is a filesystem path, but escaping is
/// cheap and a wrong plist silently fails to load rather than erroring
/// loudly, so this is not worth skipping.
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render the launchd property list that runs `binary serve <config>`
/// at load and restarts it if it exits. Pure string building: no
/// filesystem or `launchctl` access, so it is covered by a plain unit
/// test.
///
/// The hidden `service launch` bootstrap reads the strict environment file
/// as data and then execs `binary serve <config>`. This keeps credentials
/// out of the world-readable plist, prevents shell evaluation, and leaves
/// launchd supervising the proxy at the same PID.
fn render_service_plist(binary: &std::path::Path, paths: &ServicePaths) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{binary}</string>
		<string>service</string>
		<string>launch</string>
		<string>--environment</string>
		<string>{env_file}</string>
		<string>--lifecycle-lock</string>
		<string>{lifecycle_lock}</string>
		<string>--uninstall-state</string>
		<string>{uninstall_state}</string>
		<string>{config}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ExitTimeOut</key>
	<integer>{exit_timeout}</integer>
	<key>StandardOutPath</key>
	<string>{stdout}</string>
	<key>StandardErrorPath</key>
	<string>{stderr}</string>
</dict>
</plist>
"#,
        label = SERVICE_LABEL,
        exit_timeout = SERVICE_EXIT_TIMEOUT_SECS,
        binary = xml_escape(&binary.to_string_lossy()),
        config = xml_escape(&paths.config.to_string_lossy()),
        stdout = xml_escape(&paths.stdout_log.to_string_lossy()),
        stderr = xml_escape(&paths.stderr_log.to_string_lossy()),
        env_file = xml_escape(&paths.env_file.to_string_lossy()),
        lifecycle_lock = xml_escape(&paths.lifecycle_lock.to_string_lossy()),
        uninstall_state = xml_escape(&paths.uninstall_state.to_string_lossy()),
    )
}

fn handle_service_subcommand(cmd: &ServiceCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        ServiceSub::Install(args) => handle_service_install(args),
        ServiceSub::Uninstall(args) => handle_service_uninstall(args),
        ServiceSub::Status(args) => handle_service_status(args),
        ServiceSub::Launch(args) => handle_service_launch(args),
    }
}

fn handle_service_launch(args: &ServiceLaunchArgs) -> anyhow::Result<i32> {
    if args.lifecycle_lock.parent() != args.uninstall_state.parent() {
        anyhow::bail!(
            "service lifecycle lock '{}' and state '{}' must share a directory",
            args.lifecycle_lock.display(),
            args.uninstall_state.display()
        );
    }
    let lifecycle_lock = acquire_service_lifecycle_lock(&args.lifecycle_lock)?;
    let environment = read_service_environment(&args.environment)?;
    let ownership_directory = service_engine_ownership_directory_from_environment(
        &environment,
        &args.environment,
        &args.config,
    )?;
    let owner = sbproxy_model_host::capture_managed_engine_owner(std::process::id())
        .ok_or_else(|| anyhow::anyhow!("capture exact service bootstrap process identity"))?;
    register_service_owner_locked(
        &lifecycle_lock,
        &args.uninstall_state,
        &ownership_directory,
        &owner,
    )?;

    let binary = std::env::current_exe()
        .map_err(|error| anyhow::anyhow!("resolve current executable: {error}"))?;
    let mut command = std::process::Command::new(binary);
    command.arg("serve").arg(&args.config);
    // An inherited caller value must not mask the declarative file or its
    // documented default. Always pass the resolved absolute path so process
    // recovery and uninstall cannot diverge if launchd omits HOME.
    command.env_remove(SERVICE_ENGINE_OWNERSHIP_ENV);
    command.envs(environment.variables);
    command.env(SERVICE_ENGINE_OWNERSHIP_ENV, &ownership_directory);
    // Registration is durable before this release. If uninstall owns the
    // lock, this bootstrap cannot reach exec; if it already registered,
    // uninstall will reap its exact generation even if launchd hides it.
    drop(lifecycle_lock);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let error = command.exec();
        Err(anyhow::anyhow!(
            "exec service proxy for '{}': {error}",
            args.config.display()
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = command;
        anyhow::bail!("launchd services are macOS-only")
    }
}

/// `sbproxy service install <model>`: resolve the same secure config
/// `sbproxy run` would generate (loopback bind, admin enabled with a
/// random local password), persist it, and register a launchd agent
/// that serves it in the background. `--dry-run` (inherited from the
/// flattened `RunArgs`) prints the plist and config without installing.
fn handle_service_install(args: &ServiceInstallArgs) -> anyhow::Result<i32> {
    use zeroize::Zeroize;

    if !cfg!(target_os = "macos") {
        anyhow::bail!("launchd services are macOS-only; use `sbproxy run` or `sbproxy serve`");
    }

    let mut prepared = prepare_run(&args.run)?;
    let paths = service_paths()?;

    if args.run.dry_run {
        let _ = read_service_environment(&paths.env_file)?;
        let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("sbproxy"));
        println!(
            "# would install launchd agent '{}' for {}:{} at {}\n{}\n{}",
            SERVICE_LABEL,
            prepared.artifact.logical_model,
            prepared.artifact.variant_id,
            paths.plist.display(),
            render_service_plist(&binary, &paths),
            prepared.yaml,
        );
        prepared.admin_password.zeroize();
        prepared.yaml.zeroize();
        return Ok(0);
    }

    for dir in [
        paths.config.parent(),
        paths.plist.parent(),
        paths.stdout_log.parent(),
    ]
    .into_iter()
    .flatten()
    {
        std::fs::create_dir_all(dir)
            .map_err(|error| anyhow::anyhow!("create '{}': {error}", dir.display()))?;
    }

    // The config must persist for launchd to reread on every future load,
    // unlike `PrivateRunDirectory`'s, which is removed on drop. A prior
    // install's config is replaced outright: `write_private_run_config`
    // insists on creating a new file, and the old admin password embedded
    // in it is going away with the plist that referenced it.
    if paths.config.exists() {
        std::fs::remove_file(&paths.config).map_err(|error| {
            anyhow::anyhow!("remove stale '{}': {error}", paths.config.display())
        })?;
    }
    if let Err(error) = write_private_run_config(&paths.config, prepared.yaml.as_bytes()) {
        prepared.admin_password.zeroize();
        prepared.yaml.zeroize();
        return Err(error);
    }
    prepared.yaml.zeroize();

    // Created once, never rewritten: reinstalling to change the model or
    // the port must not throw away a token the operator put here.
    ensure_service_env_file(&paths.env_file)?;
    let _ = read_service_environment(&paths.env_file)?;

    let binary = std::env::current_exe()
        .map_err(|error| anyhow::anyhow!("resolve current executable: {error}"))?;
    let plist = render_service_plist(&binary, &paths);
    std::fs::write(&paths.plist, plist)
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", paths.plist.display()))?;

    // Clear out a prior load of the same label first: `launchctl load` on
    // an already-loaded label is a silent no-op, so a second install (a
    // new port, model, or password) would never take effect without
    // this. Absence is the common case and not an error.
    let _ = std::process::Command::new("launchctl")
        .arg("unload")
        .arg(&paths.plist)
        .output();
    let output = std::process::Command::new("launchctl")
        .arg("load")
        .arg("-w")
        .arg(&paths.plist)
        .output()
        .map_err(|error| anyhow::anyhow!("launchctl load: {error}"))?;
    prepared.admin_password.zeroize();
    if !output.status.success() {
        anyhow::bail!(
            "launchctl load '{}' failed: {}",
            paths.plist.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    match args.format {
        OutputFormat::Text => println!(
            "Installed {} as launchd agent '{}'.\nConfig: {}\nPlist:  {}\nLogs:   {}\nEnv:    {}\n",
            prepared.name,
            SERVICE_LABEL,
            paths.config.display(),
            paths.plist.display(),
            paths.stdout_log.display(),
            paths.env_file.display(),
        ),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "service.install",
                serde_json::json!({
                    "label": SERVICE_LABEL,
                    "model": prepared.name,
                    "config_path": paths.config.to_string_lossy(),
                    "plist_path": paths.plist.to_string_lossy(),
                    "stdout_log": paths.stdout_log.to_string_lossy(),
                    "stderr_log": paths.stderr_log.to_string_lossy(),
                    "env_file": paths.env_file.to_string_lossy(),
                }),
            ))?
        ),
    }
    Ok(0)
}

/// `sbproxy service uninstall`: unload the agent and remove its plist.
/// Idempotent: uninstalling an agent that was never installed reports
/// nothing removed rather than failing, since the end state either way
/// is what the operator asked for.
fn handle_service_uninstall(args: &ServiceUninstallArgs) -> anyhow::Result<i32> {
    if !cfg!(target_os = "macos") {
        anyhow::bail!("launchd services are macOS-only");
    }

    let paths = service_paths()?;
    let outcome = perform_service_uninstall(
        &paths,
        &mut SystemLaunchdController,
        &mut SystemServiceEngineCleanup,
    )?;

    match args.format {
        OutputFormat::Text => {
            if outcome.removed {
                println!(
                    "Uninstalled launchd agent '{SERVICE_LABEL}' (reaped {} managed engine(s)).",
                    outcome.engines_reaped
                );
            } else {
                println!(
                    "No launchd agent '{SERVICE_LABEL}' was installed (reaped {} managed engine(s) from a prior retry, if any).",
                    outcome.engines_reaped
                );
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "service.uninstall",
                serde_json::json!({
                    "label": SERVICE_LABEL,
                    "removed": outcome.removed,
                    "engines_reaped": outcome.engines_reaped,
                }),
            ))?
        ),
    }
    Ok(0)
}

/// `sbproxy service status`: ask `launchctl list` whether the agent is
/// registered, and whether it currently has a PID. Exit 0 when running,
/// 1 otherwise (registered-but-stopped and never-installed alike), so a
/// caller can `sbproxy service status || restart-it` without parsing
/// output.
fn handle_service_status(args: &ServiceStatusArgs) -> anyhow::Result<i32> {
    if !cfg!(target_os = "macos") {
        anyhow::bail!("launchd services are macOS-only");
    }

    let mut launchd = SystemLaunchdController;
    let (registered, pid) = match launchd.status()? {
        LaunchdJobStatus::NotLoaded => (false, None),
        LaunchdJobStatus::Loaded { pid } => (true, pid),
    };
    let running = pid.is_some();
    // Report the paths a running agent is actually using, so recovering
    // an agent installed months ago does not start with a hunt for its
    // logs or its token file.
    let paths = service_paths()?;

    match args.format {
        OutputFormat::Text => {
            if !registered {
                println!("{SERVICE_LABEL}: not installed");
            } else {
                if let Some(pid) = pid {
                    println!("{SERVICE_LABEL}: running (pid {pid})");
                } else {
                    println!("{SERVICE_LABEL}: registered, not running");
                }
                println!("Config: {}", paths.config.display());
                println!("Logs:   {}", paths.stdout_log.display());
                println!(
                    "Env:    {}{}",
                    paths.env_file.display(),
                    if paths.env_file.exists() {
                        ""
                    } else {
                        " (absent)"
                    }
                );
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "service.status",
                serde_json::json!({
                    "label": SERVICE_LABEL,
                    "registered": registered,
                    "running": running,
                    "pid": pid,
                    "config_path": paths.config.to_string_lossy(),
                    "stdout_log": paths.stdout_log.to_string_lossy(),
                    "stderr_log": paths.stderr_log.to_string_lossy(),
                    "env_file": paths.env_file.to_string_lossy(),
                    "env_file_present": paths.env_file.exists(),
                }),
            ))?
        ),
    }
    Ok(if running { 0 } else { 1 })
}

/// Extract the `"PID" = <n>;` value from `launchctl list <label>`'s
/// stdout. Absent means the agent is loaded but not currently running.
fn parse_launchctl_list_pid(text: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("\"PID\" = ")?;
        rest.trim_end_matches(';').parse::<u32>().ok()
    })
}

// --- `models` handler (WOR-1803) ---

fn handle_models_subcommand(
    cmd: &ModelsCmd,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    match &cmd.sub {
        // `sbproxy models` with no subcommand lists.
        None => handle_models_list(&ModelsListArgs::default(), config_path),
        Some(ModelsSub::List(a)) => handle_models_list(a, config_path),
        Some(ModelsSub::Show(a)) => handle_models_show(a, config_path),
        Some(ModelsSub::Pull(a)) => handle_models_pull(a, config_path),
        Some(ModelsSub::Remove(a)) => handle_models_remove(a, config_path),
        Some(ModelsSub::Ps(a)) => handle_models_ps(a),
        Some(ModelsSub::Stop(a)) => handle_models_stop(a),
        Some(ModelsSub::Prune(a)) => handle_models_prune(a, config_path),
        Some(ModelsSub::Lock(a)) => handle_models_lock(a, config_path),
        Some(ModelsSub::VerifyLock(a)) => handle_models_verify_lock(a, config_path),
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
        sbproxy_model_host::EngineKind::MistralRs => "mistralrs",
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
        sbproxy_config::ManagedEngineChoice::MistralRs => {
            sbproxy_model_host::EngineChoice::MistralRs
        }
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

/// Wrap one subcommand's JSON result in the shared `{command,
/// schema_version, ...}` envelope every `--format json` surface prints.
fn cli_command_envelope(command: &'static str, value: serde_json::Value) -> serde_json::Value {
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
            serde_json::to_string_pretty(&cli_command_envelope("models.ps", status))?
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
            serde_json::to_string_pretty(&cli_command_envelope("models.stop", stopped))?
        ),
        OutputFormat::Text => {
            let state = stopped
                .get("state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("stopped");
            println!("{} {state}", args.deployment);
        }
    }
    Ok(0)
}

// --- `models lock` / `models verify-lock` handlers (WOR-1864) ---

/// Default lockfile location: next to the active config, or the
/// current directory when no config was given.
fn default_lockfile_path(config_path: Option<&std::path::Path>) -> PathBuf {
    match config_path.and_then(std::path::Path::parent) {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(sbproxy_model_host::LOCKFILE_NAME),
        _ => PathBuf::from(sbproxy_model_host::LOCKFILE_NAME),
    }
}

/// The engine version/image pin for a resolved artifact, when the
/// config pins one: a per-deployment pin (WOR-1906) on a matching
/// canonical deployment wins over the legacy node-wide `engines:`
/// provisioning for the selected engine. Unpinned engines lock the
/// kind alone.
fn locked_engine_pin(
    artifact: &sbproxy_model_host::ResolvedArtifact,
    serve: Option<&sbproxy_model_host::ModelHostConfig>,
    canonical: Option<&sbproxy_config::ModelHostControlConfig>,
) -> (Option<String>, Option<String>) {
    if let Some(deployment) = canonical.and_then(|canonical| {
        canonical
            .deployments
            .values()
            .filter(|deployment| {
                deployment.model == artifact.logical_model
                    && (deployment.engine_version.is_some() || deployment.engine_image.is_some())
            })
            // Prefer the deployment pinning the exact selected variant.
            .max_by_key(|deployment| {
                deployment.variant.as_deref() == Some(artifact.variant_id.as_str())
            })
    }) {
        return (
            deployment.engine_version.clone(),
            deployment.engine_image.clone(),
        );
    }
    if let Some(provisioning) = serve.and_then(|serve| serve.engines.get(&artifact.engine)) {
        let version = provisioning
            .acquire
            .as_ref()
            .and_then(|acquire| acquire.version.clone());
        if version.is_some() || provisioning.image.is_some() {
            return (version, provisioning.image.clone());
        }
    }
    (None, None)
}

/// Resolve `selections` on this host's worker profile into the exact
/// locked identities `models lock` writes and the `--locked` boot
/// check pins against. Two selections resolving to the same artifact
/// collapse into one entry.
fn resolve_locked_models(
    selections: Vec<PullSelection>,
    catalog: &sbproxy_model_host::Catalog,
    serve: Option<&sbproxy_model_host::ModelHostConfig>,
    canonical: Option<&sbproxy_config::ModelHostControlConfig>,
) -> anyhow::Result<Vec<sbproxy_model_host::LockedModel>> {
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let worker = sbproxy_model_host::WorkerProfile::from_descriptors(&report.gpus)
        .map_err(|error| anyhow::anyhow!("resolve lock worker: {error}"))?;
    let mut models: Vec<sbproxy_model_host::LockedModel> = Vec::with_capacity(selections.len());
    for selection in selections {
        let model = &selection.model;
        let entry = catalog
            .get(model)
            .ok_or_else(|| anyhow::anyhow!("model '{model}' is not in the catalog"))?;
        if entry.variants.is_empty() {
            anyhow::bail!(
                "model '{model}' has no exact catalog v2 variant; migrate its files, sizes, digests, and revision before locking"
            );
        }
        let artifact = catalog.resolve_artifact(
            &sbproxy_model_host::ResolveArtifactRequest {
                model: selection.model.clone(),
                variant: selection.variant.clone(),
                engine: selection.engine,
                replicas: selection.replicas,
                heterogeneous_variants: selection.heterogeneous_variants,
            },
            &worker,
        )?;
        // Two selections resolving to the same artifact lock one entry.
        if models
            .iter()
            .any(|locked| locked.artifact_digest == artifact.artifact_digest)
        {
            continue;
        }
        let (version, image) = locked_engine_pin(&artifact, serve, canonical);
        let locked =
            sbproxy_model_host::LockedModel::from(&artifact).with_engine_pin(version, image);
        models.push(locked);
    }
    Ok(models)
}

#[derive(serde::Serialize)]
struct ModelsLockRow {
    name: String,
    variant: String,
    engine: String,
    artifact_digest: String,
}

#[derive(serde::Serialize)]
struct ModelsLockOutput {
    schema_version: u32,
    command: &'static str,
    path: PathBuf,
    catalog_revision: String,
    models: Vec<ModelsLockRow>,
}

fn handle_models_lock(
    args: &ModelsLockArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let Some(config_path) = config_path else {
        anyhow::bail!(
            "models lock requires -f/--config: the lockfile pins that config's serve entries"
        );
    };
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", config_path.display()))?;
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
    let selections = configured_pull_selections(serve.as_ref(), canonical.as_ref());
    if selections.is_empty() {
        anyhow::bail!(
            "config '{}' has no serve entries to lock",
            config_path.display()
        );
    }

    let models = resolve_locked_models(selections, &catalog, serve.as_ref(), canonical.as_ref())?;
    let generated_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let lockfile = sbproxy_model_host::Lockfile::new(
        generated_at_ms,
        catalog.catalog_revision.clone(),
        models,
    );
    let path = args
        .out
        .clone()
        .unwrap_or_else(|| default_lockfile_path(Some(config_path)));
    sbproxy_model_host::write_lockfile(&path, &lockfile)
        .map_err(|error| anyhow::anyhow!("write lockfile '{}': {error}", path.display()))?;

    let output = ModelsLockOutput {
        schema_version: 1,
        command: "models.lock",
        path: path.clone(),
        catalog_revision: lockfile.catalog_revision.clone(),
        models: lockfile
            .models
            .iter()
            .map(|locked| ModelsLockRow {
                name: locked.name.clone(),
                variant: locked.variant_id.clone(),
                engine: engine_kind_name(locked.engine.kind).to_string(),
                artifact_digest: locked.artifact_digest.clone(),
            })
            .collect(),
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            for row in &output.models {
                println!(
                    "{}:{} locked (sha256:{}, engine {})",
                    row.name, row.variant, row.artifact_digest, row.engine
                );
            }
            println!(
                "wrote {} ({} models, catalog {})",
                path.display(),
                output.models.len(),
                output.catalog_revision
            );
        }
    }
    Ok(0)
}

#[derive(serde::Serialize)]
struct ModelsVerifyLockRow {
    name: String,
    variant: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(serde::Serialize)]
struct ModelsVerifyLockOutput {
    schema_version: u32,
    command: &'static str,
    lockfile: PathBuf,
    drift: usize,
    models: Vec<ModelsVerifyLockRow>,
}

fn handle_models_verify_lock(
    args: &ModelsVerifyLockArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let path = args
        .lockfile
        .clone()
        .unwrap_or_else(|| default_lockfile_path(config_path));
    let lockfile = sbproxy_model_host::read_lockfile(&path)
        .map_err(|error| anyhow::anyhow!("read lockfile '{}': {error}", path.display()))?;
    let root = model_cache_root(args.cache_dir.as_deref());
    let manager = sbproxy_model_host::ArtifactManager::new(root, models_pull_transport()?)?;
    let cached = manager.cached_artifacts()?;
    let drifts = sbproxy_model_host::diff_against_cache(&lockfile, &cached);

    let rows: Vec<ModelsVerifyLockRow> = lockfile
        .models
        .iter()
        .map(|locked| {
            let drift = drifts.iter().find(|drift| {
                drift.name() == locked.name && drift.variant_id() == locked.variant_id
            });
            let (status, detail) = match drift {
                None => ("ok".to_string(), None),
                Some(drift) => (
                    match drift {
                        sbproxy_model_host::LockDrift::Missing { .. } => "missing".to_string(),
                        sbproxy_model_host::LockDrift::DigestMismatch { .. } => {
                            "digest_mismatch".to_string()
                        }
                        // Only the serve-time check produces this
                        // variant; verify-lock diffs the cache alone.
                        sbproxy_model_host::LockDrift::Unlocked { .. } => "unlocked".to_string(),
                    },
                    Some(drift.to_string()),
                ),
            };
            ModelsVerifyLockRow {
                name: locked.name.clone(),
                variant: locked.variant_id.clone(),
                status,
                detail,
            }
        })
        .collect();
    let output = ModelsVerifyLockOutput {
        schema_version: 1,
        command: "models.verify-lock",
        lockfile: path.clone(),
        drift: drifts.len(),
        models: rows,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            for locked in &lockfile.models {
                match drifts.iter().find(|drift| {
                    drift.name() == locked.name && drift.variant_id() == locked.variant_id
                }) {
                    None => println!(
                        "{}:{} ok (sha256:{})",
                        locked.name, locked.variant_id, locked.artifact_digest
                    ),
                    Some(drift) => {
                        println!("{}:{} drift: {drift}", locked.name, locked.variant_id)
                    }
                }
            }
            if drifts.is_empty() {
                println!(
                    "{}: {} models match the verified cache",
                    path.display(),
                    lockfile.models.len()
                );
            } else {
                println!(
                    "{}: {} of {} models drifted",
                    path.display(),
                    drifts.len(),
                    lockfile.models.len()
                );
            }
        }
    }
    Ok(if drifts.is_empty() { 0 } else { 2 })
}

// --- `mcp lock` / `mcp verify-lock` handlers (WOR-2443) ---

/// One `type: mcp` action found in a config, with the pieces the
/// lockfile commands need.
struct McpActionSite {
    /// Where in the config document it was found, for error messages
    /// that name the action an operator has to go edit.
    location: String,
    /// The parsed action config, ready to compile.
    config: Box<sbproxy_modules::action::mcp::McpActionConfig>,
}

/// Find every `type: mcp` action in a config document.
///
/// Walks the whole document rather than the two or three paths an action
/// is usually written at. An mcp action can sit under an origin, a
/// route, or a forward rule, and a walker that enumerated those paths
/// would silently skip a config shape someone adds later. Skipping is
/// the bad failure here: the operator gets "no mcp action found" for a
/// config that plainly has one.
fn find_mcp_actions(doc: &serde_yaml::Value, path: &str, found: &mut Vec<McpActionSite>) {
    match doc {
        serde_yaml::Value::Mapping(map) => {
            let is_mcp = map
                .get(serde_yaml::Value::from("type"))
                .and_then(|t| t.as_str())
                == Some("mcp");
            if is_mcp {
                // A malformed mcp action is reported by the caller that
                // needs it, not here: this function answers "where are
                // they", and failing the whole walk on one bad block
                // would hide the good ones.
                if let Ok(config) = serde_yaml::from_value::<
                    sbproxy_modules::action::mcp::McpActionConfig,
                >(doc.clone())
                {
                    found.push(McpActionSite {
                        location: path.to_string(),
                        config: Box::new(config),
                    });
                }
                return;
            }
            for (key, value) in map {
                let key = key.as_str().unwrap_or("?");
                let child = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                find_mcp_actions(value, &child, found);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, value) in items.iter().enumerate() {
                find_mcp_actions(value, &format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

/// Load a config and return every mcp action in it.
fn mcp_action_sites(config_path: Option<&std::path::Path>) -> anyhow::Result<Vec<McpActionSite>> {
    let Some(config_path) = config_path else {
        anyhow::bail!(
            "mcp lock requires -f/--config: the lockfile pins the tools that config federates"
        );
    };
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", config_path.display()))?;
    // Interpolate before parsing, the same way boot does. A federated
    // server origin written as `${MCP_HOST}` has to resolve here too, or
    // the CLI tries to dial the literal placeholder and reports a
    // connection failure that names a host nobody configured.
    let yaml = interpolate_env_vars(&yaml);
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml)
        .map_err(|error| anyhow::anyhow!("parse config '{}': {error}", config_path.display()))?;
    let mut found = Vec::new();
    find_mcp_actions(&doc, "", &mut found);
    if found.is_empty() {
        anyhow::bail!(
            "config '{}' has no `type: mcp` action to lock",
            config_path.display()
        );
    }
    Ok(found)
}

/// Discover the live tool catalogue for one mcp action.
///
/// Compiles the action exactly as boot does and refreshes through the
/// same federation handle, so what gets pinned is what the gateway would
/// advertise: the same namespacing, the same collision handling, the
/// same OpenAPI-derived and stdio-backed tools. Reimplementing discovery
/// here would produce a baseline for a catalogue nobody serves.
///
/// No listener is bound. This is the property `verify-lock` needs to run
/// in CI.
///
/// The versioning gate is dropped for the discovery compile, and that is
/// load bearing twice over. A `mode: block` gate filters tools it judges
/// in violation, so regenerating a baseline through a live gate would
/// drop exactly the tools whose contracts moved: the operator runs
/// `mcp lock` to accept a change and gets a lockfile with the changed
/// tool missing, which then reads as a removal. It also stops `mcp lock`
/// printing `lockfile unreadable; gate fails open` on the very run whose
/// job is to create that file.
fn discover_mcp_tools(
    site: &McpActionSite,
) -> anyhow::Result<Vec<sbproxy_extension::mcp::federation::FederatedTool>> {
    let mut config = (*site.config).clone();
    config.tool_versioning = None;
    let action = sbproxy_modules::action::mcp::McpAction::from_parsed(config)
        .map_err(|error| anyhow::anyhow!("compile mcp action at {}: {error}", site.location))?;
    let federation = std::sync::Arc::clone(&action.federation);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("build discovery runtime: {error}"))?;
    runtime.block_on(async move {
        federation
            .refresh_tools()
            .await
            .map_err(|error| anyhow::anyhow!("discover tools: {error}"))?;
        Ok(federation.list_tools())
    })
}

/// The declared-version table for an action, parsed to semver.
fn declared_versions(
    site: &McpActionSite,
) -> anyhow::Result<std::collections::HashMap<String, semver::Version>> {
    let mut out = std::collections::HashMap::new();
    let Some(versioning) = site.config.tool_versioning.as_ref() else {
        return Ok(out);
    };
    for (tool, raw) in &versioning.declared_versions {
        let parsed = semver::Version::parse(raw).map_err(|error| {
            anyhow::anyhow!(
                "tool_versioning.declared_versions['{tool}'] at {} is not semver: {error}",
                site.location
            )
        })?;
        out.insert(tool.clone(), parsed);
    }
    Ok(out)
}

/// Where an action's baseline is written.
///
/// The action's own `tool_versioning.lockfile` is the answer whenever it
/// has one, because that is the file the running gate reads. Writing
/// anywhere else would produce a baseline the gate never loads, which
/// looks like success and changes nothing.
///
/// The path is used exactly as written, with no rebasing onto the config
/// directory, because the gate resolves it against the process working
/// directory (`std::fs::read_to_string(&gate.lockfile_path)` at refresh
/// time). Resolving it here against the config instead would put the
/// file where the gate does not look whenever the two directories differ,
/// which is the precise failure this function exists to avoid and would
/// still report success.
fn mcp_lockfile_path(
    site: &McpActionSite,
    out: Option<&std::path::Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(out) = out {
        return Ok(out.to_path_buf());
    }
    if let Some(configured) = site
        .config
        .tool_versioning
        .as_ref()
        .and_then(|v| v.lockfile.as_deref())
        .filter(|p| !p.is_empty())
    {
        return Ok(PathBuf::from(configured));
    }
    anyhow::bail!(
        "the mcp action at {} has no tool_versioning.lockfile; add one, or pass --out to choose \
         a path",
        site.location
    )
}

/// The server label a generated baseline records.
///
/// The federated upstreams, sorted, rather than the gateway's own name.
/// A baseline is a statement about what those upstreams advertised, so
/// an operator reading a stale lockfile can see which set it covered.
fn generated_for_label(site: &McpActionSite) -> String {
    let mut names: Vec<&str> = site
        .config
        .federated_servers
        .iter()
        .map(|s| s.origin.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    names.join(", ")
}

#[derive(serde::Serialize)]
struct McpLockRow {
    tool: String,
    semver: String,
    contract_digest: String,
}

#[derive(serde::Serialize)]
struct McpLockOutput {
    schema_version: u32,
    command: &'static str,
    path: PathBuf,
    action: String,
    generated_for: String,
    tools: Vec<McpLockRow>,
}

fn handle_mcp_lock(
    args: &McpLockArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let sites = mcp_action_sites(config_path)?;
    if args.out.is_some() && sites.len() > 1 {
        anyhow::bail!(
            "--out names one file but this config has {} mcp actions ({}); drop --out to write \
             each action's configured tool_versioning.lockfile",
            sites.len(),
            sites
                .iter()
                .map(|s| s.location.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut outputs = Vec::new();
    for site in &sites {
        let path = mcp_lockfile_path(site, args.out.as_deref())?;
        let declared = declared_versions(site)?;
        let tools = discover_mcp_tools(site)?;
        if tools.is_empty() {
            anyhow::bail!(
                "the mcp action at {} advertised no tools; refusing to write an empty baseline, \
                 which would pin nothing and pass every check",
                site.location
            );
        }
        let generated_for = generated_for_label(site);
        let lockfile = sbproxy_extension::mcp::compat::build_lockfile(
            generated_for.clone(),
            &tools,
            &declared,
        );
        let yaml = lockfile
            .to_yaml()
            .map_err(|error| anyhow::anyhow!("serialize lockfile: {error}"))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| {
                anyhow::anyhow!("create lockfile directory '{}': {error}", parent.display())
            })?;
        }
        std::fs::write(&path, &yaml)
            .map_err(|error| anyhow::anyhow!("write lockfile '{}': {error}", path.display()))?;
        outputs.push(McpLockOutput {
            schema_version: 1,
            command: "mcp.lock",
            path,
            action: site.location.clone(),
            generated_for,
            tools: lockfile
                .tools
                .iter()
                .map(|(tool, lock)| McpLockRow {
                    tool: tool.clone(),
                    semver: lock.semver.to_string(),
                    contract_digest: lock.contract_digest.clone(),
                })
                .collect(),
        });
    }

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&outputs)?),
        OutputFormat::Text => {
            for output in &outputs {
                for row in &output.tools {
                    println!("{} {} ({})", row.tool, row.semver, row.contract_digest);
                }
                println!(
                    "wrote {} ({} tools from {})",
                    output.path.display(),
                    output.tools.len(),
                    output.generated_for
                );
            }
        }
    }
    Ok(0)
}

#[derive(serde::Serialize)]
struct McpVerifyLockRow {
    tool: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(serde::Serialize)]
struct McpVerifyLockOutput {
    schema_version: u32,
    command: &'static str,
    lockfile: PathBuf,
    action: String,
    drift: usize,
    tools: Vec<McpVerifyLockRow>,
}

fn handle_mcp_verify_lock(
    args: &McpVerifyLockArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let sites = mcp_action_sites(config_path)?;
    if args.lockfile.is_some() && sites.len() > 1 {
        anyhow::bail!(
            "--lockfile names one file but this config has {} mcp actions; drop it to check each \
             action against its configured tool_versioning.lockfile",
            sites.len()
        );
    }

    let mut outputs = Vec::new();
    let mut stale = 0usize;
    for site in &sites {
        let path = mcp_lockfile_path(site, args.lockfile.as_deref())?;
        let yaml = std::fs::read_to_string(&path).map_err(|error| {
            anyhow::anyhow!(
                "read lockfile '{}': {error}; run `sbproxy mcp lock` to create it",
                path.display()
            )
        })?;
        let baseline = sbproxy_extension::mcp::compat::Lockfile::from_yaml(&yaml)
            .map_err(|error| anyhow::anyhow!("parse lockfile '{}': {error}", path.display()))?;
        let tools = discover_mcp_tools(site)?;
        let drift = sbproxy_extension::mcp::compat::diff_lockfile(&baseline, &tools);
        stale += drift.iter().filter(|d| d.is_stale()).count();
        outputs.push(McpVerifyLockOutput {
            schema_version: 1,
            command: "mcp.verify-lock",
            lockfile: path,
            action: site.location.clone(),
            drift: drift.iter().filter(|d| d.is_stale()).count(),
            tools: drift
                .iter()
                .map(|d| McpVerifyLockRow {
                    tool: d.tool().to_string(),
                    status: d.kind(),
                    detail: match d {
                        sbproxy_extension::mcp::compat::Drift::Changed { from, to, .. } => {
                            Some(format!("{from} -> {to}"))
                        }
                        sbproxy_extension::mcp::compat::Drift::UnknownScheme { digest, .. } => {
                            Some(format!(
                                "digest scheme not implemented by this build: {digest}"
                            ))
                        }
                        _ => None,
                    },
                })
                .collect(),
        });
    }

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&outputs)?),
        OutputFormat::Text => {
            for output in &outputs {
                for row in &output.tools {
                    match &row.detail {
                        Some(detail) => println!("{} {} ({detail})", row.tool, row.status),
                        None => println!("{} {}", row.tool, row.status),
                    }
                }
                if output.drift == 0 {
                    println!("{} matches the live catalogue", output.lockfile.display());
                } else {
                    println!(
                        "{} is stale: {} tool(s) drifted; run `sbproxy mcp lock` after reviewing",
                        output.lockfile.display(),
                        output.drift
                    );
                }
            }
        }
    }
    // Exit 2 on drift, matching `models verify-lock`, so CI fails on a
    // baseline that no longer describes what is served.
    Ok(if stale == 0 { 0 } else { 2 })
}

// --- `rego test` (WOR-2482): the offline `opa test` analogue ---

/// Default rule evaluated when a fixture does not name one. Matches
/// `policies[] type: rego`'s own default, so a fixture pasted from a
/// live policy does not need to repeat `query`.
fn default_rego_test_query() -> String {
    "data.sbproxy.allow".to_owned()
}

/// Default evaluation budget, matching `policies[] type: rego`.
const fn default_rego_test_budget_ms() -> u64 {
    50
}

/// Default `input` document for a case that omits one: an empty
/// object, for a module whose query does not read `input` at all.
fn default_rego_test_input() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Maximum size of one fixture YAML file. A test fixture is authored
/// text, not a bulk dataset; the cap is the same order of magnitude as
/// `read_bounded_cli_file`'s other CLI-input limits, and exists so a
/// mistyped path (a large unrelated file) is refused before the YAML
/// parser spends time reporting it is not a fixture.
const MAX_REGO_TEST_FIXTURE_BYTES: usize = 4 * 1024 * 1024;

/// One `sbproxy rego test` fixture file: the module under test, shared
/// by every case in the file, and the cases to run against it.
///
/// Field names mirror `policies[] type: rego` (`module`, `module_path`,
/// `query`, `data`, `budget_ms`, `rego_v0`) exactly, and take the same
/// defaults, so the block pasted from a fixture into a `policies[]`
/// entry, or the other way around, is the same policy.
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RegoTestFixture {
    /// Inline Rego source. Mutually exclusive with `module_path`.
    #[serde(default)]
    module: Option<String>,
    /// A `.rego` file to load. A relative path resolves against the
    /// directory containing THIS fixture file, not the process's
    /// current working directory (unlike `policies[] type: rego`'s own
    /// `module_path`, which is CLI/process relative), so a fixture
    /// swept from a directory tree can colocate its module beside it
    /// (`policies/authz/policy_test.yaml` naming `module_path:
    /// policy.rego`) instead of depending on where `sbproxy rego test`
    /// happened to be invoked from. An absolute path is used as-is.
    /// Read fresh on every run. Mutually exclusive with `module`.
    #[serde(default)]
    module_path: Option<String>,
    /// The rule reference evaluated for every case in this file.
    #[serde(default = "default_rego_test_query")]
    query: String,
    /// OPA-style base data: a JSON object the module reads as
    /// `data.<name>`, separate from the module.
    #[serde(default)]
    data: Option<serde_json::Value>,
    /// Evaluation budget in milliseconds.
    #[serde(default = "default_rego_test_budget_ms")]
    budget_ms: u64,
    /// Parse `module`/`module_path` as pre-OPA-1.0 Rego v0 instead of
    /// the v1 default.
    #[serde(default)]
    rego_v0: bool,
    /// The cases to run against the compiled module.
    cases: Vec<RegoTestCase>,
}

/// One case inside a [`RegoTestFixture`]: an `input` document and the
/// value `query` must return for it.
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RegoTestCase {
    /// Human-readable name. Printed on every pass/fail line, so a
    /// failing case is named in the output rather than only counted.
    name: String,
    /// The `input` document the query is evaluated against.
    #[serde(default = "default_rego_test_input")]
    input: serde_json::Value,
    /// The value `query` must evaluate to for this case to pass,
    /// compared as JSON against the query's actual result. An
    /// undefined rule reads as JSON `null` (matching
    /// [`sbproxy_extension::rego::CompiledRego::eval_value`]), so a
    /// case expecting "no opinion" writes `expect: null`.
    expect: serde_json::Value,
}

/// Fixture files a directory argument to `sbproxy rego test` is
/// searched for, recursively, plus any I/O fault the walk hit along
/// the way. A file argument is used as-is regardless of its name.
///
/// An unreadable subdirectory, an entry that disappears mid-walk, or a
/// broken symlink is recorded as a [`RegoTestFixtureError`] naming the
/// directory or entry, and the walk continues into every sibling and
/// every other pending directory - the same per-fault isolation
/// [`run_one_fixture`] gives a broken fixture, so one bad subdirectory
/// cannot hide the fixtures sitting right next to it. Only `path`
/// itself being unreadable (the top-level argument, checked before any
/// walking starts) is a hard `Err`: there is nothing to isolate a
/// fault from when nothing has been discovered yet.
fn discover_rego_test_fixtures(
    path: &std::path::Path,
) -> anyhow::Result<(Vec<PathBuf>, Vec<RegoTestFixtureError>)> {
    let metadata =
        std::fs::metadata(path).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    if metadata.is_file() {
        return Ok((vec![path.to_path_buf()], Vec::new()));
    }
    let mut fixtures = Vec::new();
    let mut errors = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(RegoTestFixtureError {
                    fixture: dir.display().to_string(),
                    error: format!("read directory: {error}"),
                });
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(RegoTestFixtureError {
                        fixture: dir.display().to_string(),
                        error: format!("read directory entry: {error}"),
                    });
                    continue;
                }
            };
            let entry_path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    errors.push(RegoTestFixtureError {
                        fixture: entry_path.display().to_string(),
                        error: format!("stat: {error}"),
                    });
                    continue;
                }
            };
            if file_type.is_dir() {
                pending.push(entry_path);
                continue;
            }
            let is_fixture = matches!(
                entry_path.file_name().and_then(|name| name.to_str()),
                Some(name) if name.ends_with("_test.yaml") || name.ends_with("_test.yml")
            );
            if is_fixture {
                fixtures.push(entry_path);
            }
        }
    }
    fixtures.sort();
    Ok((fixtures, errors))
}

/// Resolve a fixture's `module_path` against the directory containing
/// the fixture file that named it, not the process's current working
/// directory, so a fixture found by a recursive directory sweep can
/// colocate its module beside it regardless of where `sbproxy rego
/// test` was invoked from.
///
/// An absolute `relative` passes through unchanged: `Path::join`
/// already discards the base when the joined path is absolute, so this
/// only documents that behavior rather than special-casing it.
fn resolve_fixture_relative_path(fixture_path: &std::path::Path, relative: &str) -> PathBuf {
    match fixture_path.parent() {
        Some(parent) => parent.join(relative),
        None => PathBuf::from(relative),
    }
}

#[derive(serde::Serialize, Debug)]
struct RegoTestCaseOutput {
    fixture: String,
    case: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(serde::Serialize, Debug)]
struct RegoTestCoverageOutput {
    fixture: String,
    path: String,
    covered_lines: usize,
    not_covered_lines: Vec<u32>,
    percent: f64,
}

/// A fault against a fixture, or against the directory walk that was
/// looking for one, that never produced case or coverage results:
/// an unreadable path, malformed YAML, a `module`/`module_path`
/// conflict or omission, no `cases`, a non-positive `budget_ms`, a
/// module that failed to compile (see [`run_one_fixture`]), or an
/// unreadable subdirectory / broken entry the discovery walk hit
/// before a fixture was even found (see
/// [`discover_rego_test_fixtures`]). `fixture` names whichever of
/// those - a fixture file or a directory/entry - the fault is against.
/// Kept distinct from a case whose `expect` disagreed with the actual
/// result, which is a verdict a fixture DID produce.
#[derive(serde::Serialize, Debug)]
struct RegoTestFixtureError {
    fixture: String,
    error: String,
}

#[derive(serde::Serialize, Debug)]
struct RegoTestOutput {
    schema_version: u32,
    command: &'static str,
    cases: Vec<RegoTestCaseOutput>,
    passed: usize,
    failed: usize,
    coverage: Vec<RegoTestCoverageOutput>,
    coverage_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_coverage: Option<f64>,
    coverage_ok: bool,
    errors: Vec<RegoTestFixtureError>,
}

impl RegoTestOutput {
    /// The process exit code this result implies. Fixture errors take
    /// precedence over case/coverage verdicts: a batch with one broken
    /// fixture and nine failing cases is still `2`, since a fixture
    /// that never ran cannot also be counted as a case failure.
    ///
    /// * `2` - at least one fixture itself was unusable (a config/IO
    ///   class fault; see [`RegoTestFixtureError`]).
    /// * `1` - every fixture ran, but a case disagreed with `expect`
    ///   or `--min-coverage` was not met.
    /// * `0` - every fixture ran, every case passed, and coverage (if
    ///   checked) cleared the threshold.
    fn exit_code(&self) -> i32 {
        if !self.errors.is_empty() {
            2
        } else if self.failed != 0 || !self.coverage_ok {
            1
        } else {
            0
        }
    }
}

/// One fixture's case and coverage results, before they are folded
/// into the batch-wide [`RegoTestOutput`]. Not serialized on its own;
/// exists only so [`run_rego_tests`] can isolate a per-fixture fault
/// (see [`run_one_fixture`]) without discarding what already ran.
struct RegoTestFixtureRun {
    cases: Vec<RegoTestCaseOutput>,
    coverage: Vec<RegoTestCoverageOutput>,
    failed: usize,
}

/// Run every case in one fixture file.
///
/// Isolated from [`run_rego_tests`] so a fault specific to this
/// fixture - an unreadable path, malformed YAML, a `module`/
/// `module_path` conflict or omission, no `cases`, a non-positive
/// `budget_ms`, or a module that fails to compile - is a single `Err`
/// the caller records against this fixture and moves past, rather than
/// a `?` that would discard every other fixture's results too.
///
/// # Errors
///
/// Returns an error naming what about the fixture itself is broken.
/// Never returns an error for a case that ran but disagreed with
/// `expect`; that is reflected in the returned `failed` count and each
/// case's `status` instead.
fn run_one_fixture(
    fixture_path: &std::path::Path,
    fixture_label: &str,
) -> anyhow::Result<RegoTestFixtureRun> {
    let bytes = read_bounded_cli_file(
        fixture_path,
        MAX_REGO_TEST_FIXTURE_BYTES,
        "rego test fixture",
    )?;
    let text =
        std::str::from_utf8(&bytes).map_err(|error| anyhow::anyhow!("not UTF-8: {error}"))?;
    let fixture: RegoTestFixture =
        serde_yaml::from_str(text).map_err(|error| anyhow::anyhow!("{error}"))?;
    anyhow::ensure!(!fixture.cases.is_empty(), "has no `cases`; nothing to run");
    // Mirrors `RegoPolicy::new`'s own refusal
    // (`crates/sbproxy-modules/src/policy/rego.rs`): without this, a
    // zero budget reaches `CompiledRego::compile`'s load-time trial
    // evaluation and dies there with a "semantic fault" message that
    // has nothing to do with the module's actual logic.
    anyhow::ensure!(
        fixture.budget_ms > 0,
        "budget_ms must be greater than zero; a zero budget would refuse every case \
         before it ran"
    );

    let (module, site) = match (&fixture.module, &fixture.module_path) {
        (Some(_), Some(_)) => anyhow::bail!(
            "set either `module` (inline Rego source) or `module_path` (a path to a .rego \
             file), not both"
        ),
        (None, None) => anyhow::bail!(
            "needs `module` (inline Rego source) or `module_path` (a path to a .rego file)"
        ),
        (Some(module), None) => (module.clone(), fixture_label.to_owned()),
        (None, Some(path)) => {
            let resolved = resolve_fixture_relative_path(fixture_path, path);
            let module = std::fs::read_to_string(&resolved).map_err(|error| {
                anyhow::anyhow!("loading module from {}: {error}", resolved.display())
            })?;
            (module, path.trim_end_matches(".rego").to_owned())
        }
    };

    let mut compiled = sbproxy_extension::rego::CompiledRego::compile(
        site,
        &module,
        fixture.query.clone(),
        fixture.budget_ms,
        fixture.data.clone(),
        fixture.rego_v0,
    )?;
    compiled.set_enable_coverage(true);

    let mut cases = Vec::new();
    let mut failed = 0usize;
    for case in &fixture.cases {
        match compiled.eval_value(case.input.clone(), "") {
            Ok(actual) if actual == case.expect => {
                cases.push(RegoTestCaseOutput {
                    fixture: fixture_label.to_owned(),
                    case: case.name.clone(),
                    status: "pass",
                    detail: None,
                });
            }
            Ok(actual) => {
                failed += 1;
                cases.push(RegoTestCaseOutput {
                    fixture: fixture_label.to_owned(),
                    case: case.name.clone(),
                    status: "fail",
                    detail: Some(format!("expected {}, got {actual}", case.expect)),
                });
            }
            Err(error) => {
                failed += 1;
                cases.push(RegoTestCaseOutput {
                    fixture: fixture_label.to_owned(),
                    case: case.name.clone(),
                    status: "fail",
                    detail: Some(error.to_string()),
                });
            }
        }
    }

    let report = compiled.coverage_report()?;
    let coverage = report
        .into_iter()
        .map(|file| {
            let percent = file.percent();
            RegoTestCoverageOutput {
                fixture: fixture_label.to_owned(),
                path: file.path,
                covered_lines: file.covered.len(),
                not_covered_lines: file.not_covered,
                percent,
            }
        })
        .collect();

    Ok(RegoTestFixtureRun {
        cases,
        coverage,
        failed,
    })
}

/// Run every fixture in `fixture_paths` and gather coverage, without
/// printing anything or deciding an exit code.
///
/// Split out from [`handle_rego_test`] so the pass/fail/coverage/error
/// verdict is a plain value a test can assert on directly, rather than
/// something only observable by capturing this process's stdout. Each
/// fixture runs through [`run_one_fixture`] independently: one broken
/// fixture is recorded in the returned value's `errors` and the sweep
/// continues, rather than aborting every other fixture's results.
///
/// # Errors
///
/// Returns an error only for a fault in the sweep itself, which cannot
/// happen today - a per-fixture fault is caught by [`run_one_fixture`]
/// and never propagates past this function. Kept `Result` because
/// every other handler in this file returns one and a caller should
/// not have to special-case this one if that ever changes.
fn run_rego_tests(
    fixture_paths: &[PathBuf],
    min_coverage: Option<f64>,
) -> anyhow::Result<RegoTestOutput> {
    let mut cases = Vec::new();
    let mut coverage = Vec::new();
    let mut errors = Vec::new();
    let mut failed = 0usize;

    for fixture_path in fixture_paths {
        let fixture_label = fixture_path.display().to_string();
        match run_one_fixture(fixture_path, &fixture_label) {
            Ok(run) => {
                failed += run.failed;
                cases.extend(run.cases);
                coverage.extend(run.coverage);
            }
            Err(error) => {
                errors.push(RegoTestFixtureError {
                    fixture: fixture_label,
                    error: error.to_string(),
                });
            }
        }
    }

    let total_covered: usize = coverage.iter().map(|row| row.covered_lines).sum();
    let total_not_covered: usize = coverage.iter().map(|row| row.not_covered_lines.len()).sum();
    let total_lines = total_covered + total_not_covered;
    let coverage_percent = if total_lines == 0 {
        100.0
    } else {
        (total_covered as f64 / total_lines as f64) * 100.0
    };
    let coverage_ok = match min_coverage {
        Some(min) => coverage_percent >= min,
        None => true,
    };
    let passed = cases.len() - failed;

    Ok(RegoTestOutput {
        schema_version: 1,
        command: "rego.test",
        cases,
        passed,
        failed,
        coverage,
        coverage_percent,
        min_coverage,
        coverage_ok,
        errors,
    })
}

/// `sbproxy rego test`: run every case in one or more fixture files
/// through the same engine construction `policy: rego` and
/// `ai_routing_policy` use, and print a per-module coverage summary.
///
/// This is the offline `opa test` analogue the parity scout (WOR-2482)
/// found missing: a fixture-driven way to prove a Rego module decides
/// the way its author intends before it ever reaches `sb.yml`, plus the
/// per-module line coverage Regorus's own
/// `set_enable_coverage`/`get_coverage_report` already ship but nothing
/// in this repository called before this command.
///
/// # Errors
///
/// Returns an error only when nothing could be discovered or run at
/// all: an unreadable `path` itself, or a directory with no
/// `*_test.yaml` / `*_test.yml` fixtures in it and no discovery fault
/// either. A fault specific to one discovered fixture (unreadable,
/// malformed, a bad `module`/`module_path` pairing, no cases, a
/// non-positive `budget_ms`, or a module that fails to compile), or
/// hit while walking a directory looking for fixtures (an unreadable
/// subdirectory, a broken entry), does not propagate as an `Err`: it
/// is recorded and the sweep continues, which is why the exit code
/// carries three states rather than two - see
/// `RegoTestOutput::exit_code`.
fn handle_rego_test(args: &RegoTestArgs) -> anyhow::Result<i32> {
    let (fixture_paths, discovery_errors) = discover_rego_test_fixtures(&args.path)?;
    if fixture_paths.is_empty() && discovery_errors.is_empty() {
        anyhow::bail!(
            "no rego test fixtures found at {}; pass a fixture YAML file directly, or a \
             directory containing *_test.yaml / *_test.yml files",
            args.path.display()
        );
    }

    let mut output = run_rego_tests(&fixture_paths, args.min_coverage)?;
    // Discovery-time faults (an unreadable subdirectory, a broken
    // entry) surface first, ahead of faults specific to a fixture that
    // was actually found, so both classes land in the same `errors`
    // list and the same exit-code precedence covers both.
    let mut errors = discovery_errors;
    errors.append(&mut output.errors);
    output.errors = errors;

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            for case in &output.cases {
                match &case.detail {
                    Some(detail) => println!("FAIL {} :: {}: {detail}", case.fixture, case.case),
                    None => println!("PASS {} :: {}", case.fixture, case.case),
                }
            }
            for error in &output.errors {
                println!("ERROR {}: {}", error.fixture, error.error);
            }
            for row in &output.coverage {
                let missed = if row.not_covered_lines.is_empty() {
                    String::new()
                } else {
                    format!(", missed lines {:?}", row.not_covered_lines)
                };
                println!(
                    "coverage: {} {}/{} lines ({:.1}%){missed}",
                    row.path,
                    row.covered_lines,
                    row.covered_lines + row.not_covered_lines.len(),
                    row.percent,
                );
            }
            let threshold = match args.min_coverage {
                Some(min) if output.coverage_ok => format!(" (>= {min}% required)"),
                Some(min) => format!(" (below the {min}% required)"),
                None => String::new(),
            };
            println!(
                "{} passed, {} failed, {} errored, {:.1}% total coverage{threshold}",
                output.passed,
                output.failed,
                output.errors.len(),
                output.coverage_percent
            );
        }
    }

    Ok(output.exit_code())
}

// --- `--locked` serve-time lockfile enforcement (WOR-1864) ---

/// Read the lockfile for the `--locked` boot check. A missing file is
/// the distinct operator error `no lockfile at <path>; run sbproxy
/// models lock` (exit 2 at the call site), never a silent pass. An
/// unreadable or invalid file surfaces the underlying read error.
fn read_serve_lockfile(path: &std::path::Path) -> anyhow::Result<sbproxy_model_host::Lockfile> {
    if !path.exists() {
        anyhow::bail!("no lockfile at {}; run sbproxy models lock", path.display());
    }
    sbproxy_model_host::read_lockfile(path)
        .map_err(|error| anyhow::anyhow!("read lockfile '{}': {error}", path.display()))
}

/// Resolve every configured serve/deployment entry in `config_path`
/// for the `--locked` boot check, plus the cache directory the serve
/// path would use (canonical `model_host.cache.directory` first, then
/// the legacy serve `cache_dir`, mirroring the boot-time resolution).
/// A config with no `proxy.model_host` and no `serve:` block yields
/// an empty model set: the check then only diffs the lockfile against
/// the cache.
fn locked_models_for_config(
    config_path: &std::path::Path,
) -> anyhow::Result<(Vec<sbproxy_model_host::LockedModel>, Option<String>)> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", config_path.display()))?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let compiled = sbproxy_config::compile_config(&yaml)?;
    let canonical = compiled.server.model_host.clone();
    let legacy = extract_serve_and_catalog(&yaml, config_dir)?;
    let (serve, catalog) = match legacy {
        Some((serve, catalog)) => (Some(serve), catalog),
        None => (None, sbproxy_model_host::Catalog::builtin()),
    };
    let cache_dir = canonical
        .as_ref()
        .and_then(|control| control.cache.directory.clone())
        .or_else(|| serve.as_ref().and_then(|serve| serve.cache_dir.clone()));
    let selections = configured_pull_selections(serve.as_ref(), canonical.as_ref());
    if selections.is_empty() {
        return Ok((Vec::new(), cache_dir));
    }
    let models = resolve_locked_models(selections, &catalog, serve.as_ref(), canonical.as_ref())?;
    Ok((models, cache_dir))
}

/// The `--locked` pre-boot check (WOR-1864): read `sbproxy-models.lock`
/// next to the config, diff it against the verified weight cache, and
/// pin every configured serve/deployment entry's resolved artifact
/// digest to the lock. Any drift prints the same per-model drift lines
/// `models verify-lock` prints and returns the refusal as an `Err`;
/// the caller exits 2 before any listener starts. A clean lock logs
/// one info line and returns `Ok`.
fn enforce_locked_serve(config_path: &std::path::Path) -> anyhow::Result<()> {
    let lockfile_path = default_lockfile_path(Some(config_path));
    let lockfile = read_serve_lockfile(&lockfile_path)?;
    let (configured, cache_dir) = locked_models_for_config(config_path)?;
    let root = sbproxy_model_host::resolve_cache_dir_default(cache_dir.as_deref());
    let manager = sbproxy_model_host::ArtifactManager::new(root, models_pull_transport()?)?;
    let cached = manager.cached_artifacts()?;
    let drifts = sbproxy_model_host::lockfile::verify_for_serve(&lockfile, &cached, &configured);
    if drifts.is_empty() {
        tracing::info!(
            lockfile = %lockfile_path.display(),
            models = lockfile.models.len(),
            "lockfile clean; serving the locked model stack"
        );
        return Ok(());
    }
    for drift in &drifts {
        println!("{}:{} drift: {drift}", drift.name(), drift.variant_id());
    }
    anyhow::bail!("refusing to serve: lockfile drift")
}

/// Apply `--locked` before boot: run [`enforce_locked_serve`] and exit
/// 2 on any failure (drift, missing lockfile, or an unresolvable
/// config), so listeners never start against a drifted stack. Returns
/// only when the lock is clean.
fn enforce_locked_serve_or_exit(config_path: Option<&std::path::Path>) {
    let Some(config_path) = config_path else {
        eprintln!("--locked requires a config path (positional or -f/--config)");
        std::process::exit(2);
    };
    if let Err(error) = enforce_locked_serve(config_path) {
        eprintln!("{error:#}");
        std::process::exit(2);
    }
}

fn configured_artifact_protection(
    config_path: &std::path::Path,
    catalog: &sbproxy_model_host::Catalog,
    worker: &sbproxy_model_host::WorkerProfile,
) -> anyhow::Result<sbproxy_model_host::CacheProtection> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", config_path.display()))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let pipeline = sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
        compiled, config_dir,
    )?;
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
                sbproxy_config::ManagedEngineChoice::MistralRs => {
                    sbproxy_model_host::EngineChoice::MistralRs
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

fn handle_models_prune(
    args: &ModelsPruneArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let configured = configured_model_cache_dir(config_path);
    let root = model_cache_root(args.cache_dir.as_deref().or(configured.as_deref()));
    // Prune is local-only: it never fetches, so no transport is wired.
    let manager = sbproxy_model_host::ArtifactManager::new(
        root,
        std::sync::Arc::new(sbproxy_model_host::UnavailableArtifactTransport),
    )?;
    let report = manager.prune(args.dry_run)?;
    let output = cli_command_envelope(
        "models.prune",
        serde_json::json!({
            "dry_run": report.dry_run,
            "orphan_blobs": report.orphan_blobs,
            "reclaimed_bytes": report.reclaimed_bytes,
            "before_bytes": report.before_bytes,
        }),
    );
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            let verb = if report.dry_run {
                "would reclaim"
            } else {
                "reclaimed"
            };
            println!(
                "{verb} {} across {} unreferenced blob(s) ({} cached before prune)",
                format_cache_size(report.reclaimed_bytes),
                report.orphan_blobs,
                format_cache_size(report.before_bytes),
            );
        }
    }
    Ok(0)
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
    let output = cli_command_envelope(
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
/// Cache directory configured in `config_path`, mirroring the pull path's
/// resolution order: the canonical `proxy.model_host.cache.directory`
/// first, then the legacy provider `serve.cache_dir`. `None` without a
/// config or when neither is set, which lets the platform default apply.
/// Read-only status commands (`models list`, `models show`) use this so
/// they inspect the same cache the pull and serve paths write; without it
/// a `-f` invocation silently reads the platform default cache instead.
fn configured_model_cache_dir(config_path: Option<&std::path::Path>) -> Option<PathBuf> {
    let config_path = config_path?;
    let yaml = std::fs::read_to_string(config_path).ok()?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let canonical = sbproxy_config::compile_config(&yaml)
        .ok()
        .and_then(|compiled| compiled.server.model_host)
        .and_then(|control| control.cache.directory.map(PathBuf::from));
    if canonical.is_some() {
        return canonical;
    }
    extract_serve_and_catalog(&yaml, config_dir)
        .ok()
        .flatten()
        .and_then(|(serve, _)| serve.cache_dir.map(PathBuf::from))
}

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
    /// / serving state needs a running gateway and is not shown here. A
    /// not-pulled model whose declared files all have a size-matching
    /// candidate in one foreign cache (Ollama, LM Studio, the HF hub)
    /// carries an appended `importable from <source>` marker; the size
    /// match is a cheap list-time heuristic, and the real digest
    /// verification happens at import (WOR-1863).
    status: String,
}

/// Build the model rows from a catalog, the host report, the cache
/// dir, and one foreign-cache scan. Pure over its inputs (the
/// report/probe and the scan are passed in), so it is unit-testable.
fn build_model_rows(
    catalog: &sbproxy_model_host::Catalog,
    report: &sbproxy_core::doctor::DoctorReport,
    cache_root: &std::path::Path,
    foreign: &[sbproxy_model_host::ForeignModelFile],
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
                } else if let Some(source) = foreign_import_source(resolved.as_ref(), foreign) {
                    format!("not-pulled, importable from {}", source.label())
                } else {
                    "not-pulled".to_string()
                },
            }
        })
        .collect()
}

/// The single foreign cache whose files could seed every declared file
/// of the resolved artifact, judged by exact byte-size match only
/// (WOR-1863). List time never hashes: the size match is a cheap
/// heuristic that only decides whether to show the marker, and the
/// real verification happens at import, where each candidate is
/// stream-hashed with SHA-256 and the staged bytes are re-verified by
/// the cache's promote path. Sources are tried in the scan's stable
/// order, and a model whose files are only covered by a mix of sources
/// shows no marker.
fn foreign_import_source(
    resolved: Option<&sbproxy_model_host::ResolvedArtifact>,
    foreign: &[sbproxy_model_host::ForeignModelFile],
) -> Option<sbproxy_model_host::ForeignCacheSource> {
    let artifact = resolved?;
    if artifact.files.is_empty() || foreign.is_empty() {
        return None;
    }
    let mut sources: Vec<_> = foreign.iter().map(|file| file.source).collect();
    sources.sort();
    sources.dedup();
    sources.into_iter().find(|source| {
        artifact.files.iter().all(|file| {
            foreign
                .iter()
                .any(|c| c.source == *source && c.size_bytes == file.size_bytes)
        })
    })
}

/// Raw foreign-cache scan for `models list` (WOR-1863): the weight
/// files Ollama, LM Studio, or the Hugging Face hub already hold under
/// the current home directory. Read-only; no resolvable home directory
/// yields an empty list.
fn foreign_model_files() -> Vec<sbproxy_model_host::ForeignModelFile> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| sbproxy_model_host::discover_foreign_models(&PathBuf::from(home)))
        .unwrap_or_default()
}

fn handle_models_list(
    args: &ModelsListArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let catalog = load_models_catalog(args.catalog_file.as_deref())?;
    let configured = configured_model_cache_dir(config_path);
    let root = model_cache_root(args.cache_dir.as_deref().or(configured.as_deref()));
    let report = sbproxy_core::doctor::DoctorReport::collect();
    let foreign = foreign_model_files();
    let rows = build_model_rows(&catalog, &report, &root, &foreign);

    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
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
        sbproxy_model_host::EngineChoice::MistralRs => "mistralrs",
    }
}

fn pull_policy_name(policy: sbproxy_model_host::PullPolicy) -> &'static str {
    match policy {
        sbproxy_model_host::PullPolicy::OnBoot => "on_boot",
        sbproxy_model_host::PullPolicy::OnDemand => "on_demand",
        sbproxy_model_host::PullPolicy::Manual => "manual",
    }
}

fn handle_models_show(
    args: &ModelsShowArgs,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let catalog = load_models_catalog(args.catalog_file.as_deref())?;
    let configured = configured_model_cache_dir(config_path);
    let root = model_cache_root(args.cache_dir.as_deref().or(configured.as_deref()));
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
            serde_json::to_string_pretty(&cli_command_envelope(
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
const MISTRALRS_RELEASE_REPO: &str = "EricLBuehler/mistral.rs";

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
    // The effective default pin is host-aware on macOS: an older host
    // reports the newest pinned build its OS can load. When even that
    // fails (host older than every pin), report the newest pin so the
    // freshness table still renders; acquisition surfaces the real error.
    let pinned = sbproxy_model_host::default_llama_release_tag_for_host()
        .unwrap_or(sbproxy_model_host::DEFAULT_LLAMA_RELEASE_TAG)
        .to_string();
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
        {
            let pinned = sbproxy_model_host::mistralrs_release::DEFAULT_MISTRALRS_RELEASE_TAG;
            let latest = github_latest_release(MISTRALRS_RELEASE_REPO);
            let update = latest.as_deref().map(|l| l != pinned).unwrap_or(false);
            EngineFreshness {
                engine: "mistralrs",
                installed: engine_version("mistralrs"),
                pinned_release: Some(pinned.to_string()),
                latest_release: latest,
                update_available: update,
            }
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

/// Dispatch `sbproxy config <sub>`.
///
/// `global_config` is `-f/--config` (or `SB_CONFIG_FILE`) as parsed at the
/// top level. It is threaded in because `-f` is a global flag, so a
/// subcommand that documents "defaults to `-f/--config`" cannot see it from
/// its own args struct.
fn handle_config_subcommand(
    cmd: &ConfigCmd,
    global_config: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    match &cmd.sub {
        ConfigSub::Migrate(args) => handle_config_migrate(args),
        ConfigSub::ImportLitellm(args) => handle_config_import_litellm(args),
        ConfigSub::Print(args) => handle_config_print(args, global_config),
        ConfigSub::Authority(cmd) => match &cmd.sub {
            ConfigAuthoritySub::Init(args) => handle_authority_init(args),
            ConfigAuthoritySub::Publish(args) => handle_authority_publish(args),
            ConfigAuthoritySub::Status(args) => handle_authority_status(args),
            ConfigAuthoritySub::Rollback(args) => handle_authority_rollback(args),
            ConfigAuthoritySub::Subscriber(cmd) => match &cmd.sub {
                AuthoritySubscriberSub::Add(args) => handle_authority_subscriber_add(args),
                AuthoritySubscriberSub::List(args) => handle_authority_subscriber_list(args),
                AuthoritySubscriberSub::Revoke(args) => handle_authority_subscriber_revoke(args),
            },
        },
        ConfigSub::Pull(args) => handle_config_pull(args, global_config),
        ConfigSub::History(args) => handle_config_history(args),
        ConfigSub::Show(args) => handle_config_show(args),
        ConfigSub::Rollback(args) => handle_config_rollback(args),
        ConfigSub::Diff(args) => handle_config_diff(args),
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

/// Render one config for `sbproxy config print`, through both masks.
///
/// A free function rather than the body of [`handle_config_print`],
/// because the property worth testing is what comes *out* and the handler
/// reads a path and writes to stdout. Nothing outside the dispatch called
/// the handler, so a test on the two masks had to reimplement the pipeline
/// and then claim it was pinning the real one.
///
/// Two passes, and they are complementary rather than redundant.
/// [`mask_secrets`] is a key-name allowlist, which cannot cover
/// `key_management.crypto.root_of_trust.address`: `address` is a
/// non-secret key name almost everywhere else in the schema, so listing it
/// would mask a dozen fields that are not secrets to hide one that is.
/// `redact_config_document` masks that one by position, leaving the host
/// readable, and it is the config-document form deliberately: a URL's
/// userinfo here is a whole scalar an operator wrote, so it may carry
/// base64 padding and sub-delims that the narrower log-line form stops at.
/// Both preserve key separators, so the printed document still parses.
fn render_config_for_print(
    config: &sbproxy_config::ConfigFile,
    as_json: bool,
) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(config)?;
    mask_secrets(&mut value);
    let rendered = if as_json {
        serde_json::to_string_pretty(&value)?
    } else {
        serde_yaml::to_string(&value)?
    };
    Ok(sbproxy_observe::redact::redact_config_document(&rendered))
}

/// `sbproxy config print`: the effective config after built-in defaults +
/// the file + `${ENV}` interpolation, with secret values masked. Makes
/// it obvious what a box will actually do (WOR-1805).
fn handle_config_print(
    args: &ConfigPrintArgs,
    global_config: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    let path = resolve_config_path(args.config_path.as_deref(), global_config)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("read config '{}': {e}", path.display()))?;
    // Apply the same `${ENV}` interpolation the compiler does, so an
    // env-overridden value shows through as its resolved value.
    let interpolated = interpolate_env_vars(&raw);
    // Deserialize to the typed config (serde fills built-in defaults),
    // then re-serialize so defaults show explicitly.
    let config: sbproxy_config::ConfigFile = serde_yaml::from_str(&interpolated)
        .map_err(|e| anyhow::anyhow!("parse config '{}': {e}", path.display()))?;
    let rendered = render_config_for_print(&config, args.json)?;
    if args.json {
        println!("{rendered}");
    } else {
        print!("{rendered}");
    }
    Ok(0)
}

// --- `config authority` + `config pull` handlers ---
//
// Every command here that changes what the fleet sees goes over the admin
// API and reports what the server returned. None of them reaches for an
// in-process primitive: `sbproxy apply` used to do that, compiling the
// config into the short-lived CLI process, swapping that process's own
// pipeline, and printing success without ever contacting the proxy, so its
// exit code meant nothing. `config pull --dry-run` is the one local command,
// and it is local because it applies nothing at all.

/// File the generated Ed25519 signing seed is written to, inside `--dir`.
const AUTHORITY_SIGNING_KEY_FILE: &str = "authority-signing.key";

/// File the verifying-key map subscribers install is written to.
const AUTHORITY_VERIFYING_KEYS_FILE: &str = "authority-keys.json";

/// Resolve the config path for a subcommand that takes it positionally.
///
/// Priority: the positional path, then the global `-f/--config`, then
/// `SB_CONFIG_FILE`. Matches the order `serve` resolves its own path in.
fn resolve_config_path(
    positional: Option<&std::path::Path>,
    global_config: Option<&std::path::Path>,
) -> anyhow::Result<PathBuf> {
    positional
        .or(global_config)
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::env::var_os("SB_CONFIG_FILE").map(PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!("no config file: pass a path or set -f/--config / SB_CONFIG_FILE")
        })
}

/// Body for one admin request that carries one.
enum AdminRequestBody {
    /// A JSON document, sent as `application/json`.
    Json(serde_json::Value),
    /// A verbatim YAML document, sent as `application/yaml`.
    ///
    /// The publish route takes the payload as the request body rather than
    /// wrapped in a JSON field, so the bytes that get signed are the bytes
    /// the operator wrote.
    Yaml(String),
}

/// What one admin request produced.
enum AdminOutcome {
    /// The admin API answered. Carries the status and the decoded body
    /// (`Null` when the answer was not JSON).
    Answered {
        /// HTTP status the admin API returned.
        status: reqwest::StatusCode,
        /// Decoded response body.
        body: serde_json::Value,
    },
    /// Nothing answered at the admin URL, so nothing happened. Carries the
    /// transport reason for the operator-facing line.
    Unreachable(String),
}

/// Decode one admin JSON response without ever retaining more than the
/// caller's fixed ceiling plus the sentinel byte used to detect overflow.
fn read_bounded_admin_json(
    reader: impl std::io::Read,
    maximum: usize,
    surface: &str,
) -> anyhow::Result<serde_json::Value> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    reader
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {surface} admin response: {error}"))?;
    if bytes.len() > maximum {
        anyhow::bail!("{surface} admin response exceeds the {maximum} byte limit");
    }
    Ok(serde_json::from_slice(&bytes).unwrap_or_else(|_| non_json_admin_body(&bytes)))
}

/// Stand in for an admin response body that arrived and was not JSON.
///
/// `Null` was indistinguishable from a JSON `null` and from no body at
/// all, so a reverse proxy answering the admin listener with an HTML error
/// page left the operator a bare status code. The marker keeps the shape
/// `report_admin_refusal` reads (`code` and `error`) and carries a bounded,
/// single-line excerpt so the answering party is identifiable.
fn non_json_admin_body(bytes: &[u8]) -> serde_json::Value {
    const MAX_EXCERPT_CHARS: usize = 120;
    if bytes.is_empty() {
        return serde_json::Value::Null;
    }
    let excerpt: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_EXCERPT_CHARS)
        .collect();
    serde_json::json!({
        "code": "non_json_response",
        "error": format!(
            "{} byte response body was not JSON: {}",
            bytes.len(),
            excerpt.trim()
        ),
    })
}

/// Send one admin request, returning the status alongside the body.
///
/// `admin_request_json` collapses every non-2xx into an error, which is
/// right for the commands whose only useful answer is the happy path. These
/// commands have to tell an authority that refused (exit 4) apart from one
/// that never answered (exit 7): an exit code that conflates the two is
/// exactly the defect that made `apply`'s old exit code worthless.
fn admin_request_parts(
    args: &ModelsAdminArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<AdminRequestBody>,
) -> anyhow::Result<AdminOutcome> {
    admin_request_parts_with_timeout(args, method, path, body, std::time::Duration::from_secs(60))
}

fn admin_request_parts_with_timeout(
    args: &ModelsAdminArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<AdminRequestBody>,
    timeout: std::time::Duration,
) -> anyhow::Result<AdminOutcome> {
    admin_request_parts_inner(args, method, path, body, timeout, None)
}

fn admin_request_parts_bounded_with_timeout(
    args: &ModelsAdminArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<AdminRequestBody>,
    timeout: std::time::Duration,
    maximum_response_bytes: usize,
    surface: &'static str,
) -> anyhow::Result<AdminOutcome> {
    admin_request_parts_inner(
        args,
        method,
        path,
        body,
        timeout,
        Some((maximum_response_bytes, surface)),
    )
}

fn admin_request_parts_inner(
    args: &ModelsAdminArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<AdminRequestBody>,
    timeout: std::time::Duration,
    response_limit: Option<(usize, &'static str)>,
) -> anyhow::Result<AdminOutcome> {
    use zeroize::Zeroize;

    let base_url = args.admin_url.as_deref().unwrap_or(DEFAULT_ADMIN_URL);
    let username = args.username.as_deref().unwrap_or("admin");
    let mut password = args.password.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "admin password is required via --password or SB_ADMIN_PASSWORD. A publishing node \
             refuses the shipped default password, so an authority always has a real one"
        )
    })?;
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        // Publishing runs the full boot-equivalent validation on the
        // server, so the read budget matches `apply`'s rather than the
        // 30s the read-only model-host routes use.
        .timeout(timeout)
        .build()?;
    let mut request = client
        .request(method, &url)
        .basic_auth(username, Some(password.as_str()));
    match body {
        Some(AdminRequestBody::Json(value)) => request = request.json(&value),
        Some(AdminRequestBody::Yaml(document)) => {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/yaml")
                .body(document);
        }
        None => {}
    }
    let request = request.build();
    // Cleared as soon as the Authorization header exists, matching
    // `admin_request_json` and `apply_to_running_proxy`.
    password.zeroize();
    let response = match client.execute(request?) {
        Ok(response) => response,
        Err(error) => return Ok(AdminOutcome::Unreachable(error.to_string())),
    };
    let status = response.status();
    if let Some((maximum, surface)) = response_limit {
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            anyhow::bail!("{surface} admin response exceeds the {maximum} byte limit");
        }
    }
    let body = match response_limit {
        Some((maximum, surface)) => read_bounded_admin_json(response, maximum, surface)?,
        None => response.json().unwrap_or(serde_json::Value::Null),
    };
    Ok(AdminOutcome::Answered { status, body })
}

/// Report an admin API that refused, and return the documented exit code 4.
fn report_admin_refusal(
    command: &str,
    status: reqwest::StatusCode,
    body: &serde_json::Value,
) -> i32 {
    let error = body
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("the admin API gave no reason");
    let code = body
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    // "the admin API" rather than "the authority": most callers here
    // (`config history`, `config show`, `config rollback`, `config diff`)
    // talk to a proxy node's own admin API, and telling an operator
    // mid-incident that "the authority refused" sends them to look at
    // the wrong machine.
    eprintln!("{command}: the admin API refused (HTTP {status}, {code}): {error}");
    eprintln!("{command}: nothing changed.");
    4
}

/// Report an unreachable admin API, and return the documented exit code 7.
///
/// Deliberately never followed by a local fallback. A command that cannot
/// reach the authority has not published, rolled back, or revoked anything,
/// and saying otherwise is worse than saying nothing.
fn report_admin_unreachable(command: &str, args: &ModelsAdminArgs, reason: &str) -> i32 {
    let base_url = args.admin_url.as_deref().unwrap_or(DEFAULT_ADMIN_URL);
    eprintln!("{command}: could not reach the admin API at {base_url}: {reason}");
    eprintln!(
        "{command}: nothing was changed. Point --admin-url (or SB_ADMIN_URL) at the running \
         authority's admin listener."
    );
    7
}

/// Name a generated key after its own public key: `authority-` plus the
/// first twelve alphanumeric characters of the base64 public material,
/// lowercased.
///
/// Derived rather than dated because rotation is additive: an operator
/// generating a second key wants a second name, and two keys made in the
/// same month would collide on a date-shaped default. Derived from the
/// public half and never from the seed, because the seed's entropy must not
/// show up in a value the verifying-key file publishes.
fn derived_key_id(verifying_material_base64: &str) -> String {
    let suffix: String = verifying_material_base64
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .map(|character| character.to_ascii_lowercase())
        .collect();
    format!("authority-{suffix}")
}

/// Set a directory this command just created to owner-only.
///
/// Best effort: a failure is reported and does not abort, because the
/// signing key inside it carries its own mode and its own refusal to load
/// when that mode is wrong.
#[cfg(unix)]
fn tighten_directory_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        eprintln!(
            "config authority init: warning: could not set '{}' to owner-only (0700): {error}",
            path.display()
        );
    }
}

/// Windows has no mode bits to set, so this is a no-op there rather than a
/// false assurance.
#[cfg(not(unix))]
fn tighten_directory_permissions(_path: &std::path::Path) {}

/// Warn when the directory holding a signing key can be reached by another
/// account on the box.
///
/// A warning and not a refusal: the key file itself is owner-only and
/// `ConfigBundleSigner` refuses to load one that is not, so a loose
/// directory mode is a risk to whatever else lives there rather than to the
/// key. Worth saying out loud all the same, because an operator who ran
/// `chmod 755` on a parent path has no other prompt to notice.
#[cfg(unix)]
fn warn_if_directory_is_reachable_by_others(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        eprintln!(
            "config authority init: warning: '{}' is mode {:o}, so other accounts on this host \
             can reach it. Run `chmod 700 {}`.",
            path.display(),
            mode & 0o777,
            path.display(),
        );
    }
}

/// Windows has no mode bits to check.
#[cfg(not(unix))]
fn warn_if_directory_is_reachable_by_others(_path: &std::path::Path) {}

/// Write private key material with owner-only permissions.
///
/// The mode is requested in the open and set again afterwards: the first
/// covers a file this call creates, so it is never briefly world-readable,
/// and the second covers `--force` over a file that already exists with a
/// looser mode. Getting either wrong would also mean an authority that
/// cannot start, since the loader refuses a group-readable signing key.
fn write_owner_only(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                anyhow::anyhow!(
                    "set owner-only permissions on '{}': {error}",
                    path.display()
                )
            },
        )?;
    }
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", path.display()))?;
    Ok(())
}

/// Fold one signer's verifying-key entry into the map at `path`, keeping
/// whatever is already there.
///
/// Rotation is additive: subscribers trust the old key and the new one at
/// once, then drop the old entry a window later. Replacing the file
/// wholesale would withdraw the old key's trust at the same instant the new
/// key starts signing, which is the window rotation exists to avoid.
fn merge_verifying_keys(path: &std::path::Path, entry: &str) -> anyhow::Result<String> {
    let mut merged = match std::fs::read_to_string(path) {
        Ok(existing) => serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            &existing,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "'{}' exists but is not a verifying-key object ({error}). Move it aside or fix \
                 it, rather than having this overwrite keys subscribers may still be trusting",
                path.display()
            )
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::Map::new(),
        Err(error) => {
            return Err(anyhow::anyhow!("read '{}': {error}", path.display()));
        }
    };
    let generated: serde_json::Map<String, serde_json::Value> = serde_json::from_str(entry)
        .map_err(|error| anyhow::anyhow!("decode the generated verifying-key entry: {error}"))?;
    merged.extend(generated);
    serde_json::to_string_pretty(&serde_json::Value::Object(merged))
        .map_err(|error| anyhow::anyhow!("encode the verifying-key file: {error}"))
}

/// `sbproxy config authority init`: generate the authority's key pair, write
/// the signing key owner-only, write the verifying-key file subscribers
/// install, and print what to copy where.
///
/// Local by definition: a signing key that travelled over a network to get
/// to its own authority is a signing key that has been somewhere else.
///
/// Exit codes: 0 generated, 1 CLI or IO error, 3 refused because a signing
/// key already exists and `--force` was not given.
fn handle_authority_init(args: &AuthorityInitArgs) -> anyhow::Result<i32> {
    use rand::RngCore as _;
    use sbproxy_config::config_bundle::{
        encode_signing_key_seed, ConfigBundleSigner, ED25519_KEY_BYTES,
    };
    use zeroize::Zeroize as _;

    let directory = args.directory.as_path();
    let created = !directory.exists();
    std::fs::create_dir_all(directory).map_err(|error| {
        anyhow::anyhow!(
            "create authority directory '{}': {error}",
            directory.display()
        )
    })?;
    if created {
        tighten_directory_permissions(directory);
    }
    warn_if_directory_is_reachable_by_others(directory);

    let key_path = directory.join(AUTHORITY_SIGNING_KEY_FILE);
    let keys_path = directory.join(AUTHORITY_VERIFYING_KEYS_FILE);
    if key_path.exists() && !args.force {
        eprintln!(
            "config authority init: '{}' already exists. Overwriting a signing key means every \
             bundle it signed stops verifying for any subscriber that has not installed the new \
             verifying key yet, so this refuses rather than guess.",
            key_path.display()
        );
        eprintln!(
            "config authority init: pass --force to rotate (the new verifying key is added to \
             '{}' alongside the old one), or point --dir somewhere else.",
            keys_path.display()
        );
        return Ok(3);
    }

    let mut seed = [0u8; ED25519_KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    // The key id we want names the key's own public half, and the signer is
    // what computes that, so the pair is built twice: once to learn the
    // public key, once under the name that describes it. Cheap, and it
    // keeps the id derivation out of the crypto crate.
    let key_id = match args.key_id.as_deref() {
        Some(key_id) => key_id.to_string(),
        None => {
            let probe = ConfigBundleSigner::ed25519_from_seed_bytes("authority-pending", &seed)
                .map_err(|error| anyhow::anyhow!("derive the authority key id: {error}"))?;
            derived_key_id(&probe.verifying_material_base64())
        }
    };
    let signer = ConfigBundleSigner::ed25519_from_seed_bytes(&key_id, &seed).map_err(|error| {
        anyhow::anyhow!("build a signer for key id {key_id:?}: {error}. Key ids accept letters, digits, and . - _ :")
    })?;
    let verifying_material = signer.verifying_material_base64();
    let entry = signer
        .verifying_key_file_json()
        .map_err(|error| anyhow::anyhow!("render the verifying-key entry: {error}"))?;
    let keys_body = merge_verifying_keys(&keys_path, &entry)?;

    let mut signing_body = encode_signing_key_seed(&seed);
    seed.zeroize();
    let write_result = write_owner_only(&key_path, &signing_body);
    // Cleared whether or not the write succeeded: the failure path is
    // exactly where a copy of a signing key should not linger.
    signing_body.zeroize();
    write_result?;
    std::fs::write(&keys_path, &keys_body)
        .map_err(|error| anyhow::anyhow!("write '{}': {error}", keys_path.display()))?;

    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "command": "config.authority.init",
                "directory": directory,
                "authority_id": args.authority_id,
                "key_id": key_id,
                "algorithm": "ed25519",
                "signing_key_file": key_path,
                "verifying_keys_file": keys_path,
                // The public half, safe to publish. The seed appears in no
                // output, in either format.
                "verifying_material": verifying_material,
                "rotated": args.force,
            }))?
        ),
        OutputFormat::Text => {
            println!(
                "config authority init: wrote {} (owner-only) and {}",
                key_path.display(),
                keys_path.display()
            );
            println!("config authority init: key id {key_id}");
            println!();
            println!("On the authority, under proxy.config_authority.publish:");
            println!("  authority_id: {}", args.authority_id);
            println!("  key_id: {key_id}");
            println!("  signing_key_file: {}", key_path.display());
            println!("  store_dir: {}", directory.join("store").display());
            println!();
            println!("On every subscriber, under proxy.config_authority.upstream:");
            println!("  verifying_keys_file: <this node's copy of authority-keys.json>");
            println!();
            println!(
                "Copy {AUTHORITY_VERIFYING_KEYS_FILE} to each subscriber. Never copy \
                 {AUTHORITY_SIGNING_KEY_FILE} anywhere: it is the key that mints configuration \
                 for the whole fleet."
            );
            println!(
                "Then register each subscriber with `sbproxy config authority subscriber add \
                 <subscriber-id>`."
            );
        }
    }
    Ok(0)
}

/// Publish a composed document through the config authority's admin
/// route.
///
/// The same route `sbproxy config authority publish` posts to, so the
/// composed document goes through `compile_config`, the pipeline
/// construction, the model-runtime check and the denied-path screen on
/// the authority side rather than being trusted because the aggregator
/// produced it.
struct AdminApiPublisher<'a> {
    admin: &'a ModelsAdminArgs,
    mode: BundleModeArg,
}

impl sbproxy_core::config_aggregator::CompositionPublisher for AdminApiPublisher<'_> {
    fn publish(&self, config_yaml: &str) -> Result<u64, String> {
        let route = format!(
            "{}?mode={}",
            sbproxy_core::config_authority::PUBLISH_PATH,
            self.mode.as_str()
        );
        let outcome = admin_request_parts(
            self.admin,
            reqwest::Method::POST,
            &route,
            Some(AdminRequestBody::Yaml(config_yaml.to_string())),
        )
        .map_err(|error| format!("{error:#}"))?;
        match outcome {
            AdminOutcome::Unreachable(reason) => Err(format!(
                "could not reach the admin API at {}: {reason}",
                self.admin.admin_url.as_deref().unwrap_or(DEFAULT_ADMIN_URL)
            )),
            AdminOutcome::Answered { status, body } if !status.is_success() => {
                let error = body
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("the admin API gave no reason");
                let code = body
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                Err(format!("HTTP {status} ({code}): {error}"))
            }
            AdminOutcome::Answered { body, .. } => Ok(json_u64(&body, "revision")),
        }
    }
}

/// `sbproxy aggregate`: fetch, compose, and publish or write.
///
/// Exit codes: 0 published, written, or unchanged; 1 a CLI or
/// composition error (through `run_subcommand`); 2 `--dry-run` found
/// changes; 3 the composition or the authority refused it.
fn handle_aggregate_subcommand(args: &AggregateArgs) -> anyhow::Result<i32> {
    let path = args
        .config_path
        .clone()
        .or_else(|| std::env::var("SB_CONFIG_FILE").ok().map(PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing config path: aggregate takes the runtime document that carries \
                 `origin_sources:`, as a positional argument or through -f / --config"
            )
        })?;
    // `from_path` rather than a read plus `from_document`, so a
    // `--watch` run re-reads the document each cycle instead of
    // composing from the one it saw at start-up.
    let mut aggregator = sbproxy_core::config_aggregator::Aggregator::from_path(
        &path,
        sbproxy_config::source::FetchContext::with_git_binary(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    aggregator
        .resolve_credentials()
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    if args.watch {
        let publisher = AdminApiPublisher {
            admin: &args.admin,
            mode: args.mode,
        };
        let polls = (args.polls > 0).then_some(args.polls);
        {
            let entries = aggregator.entries().len();
            let timings = aggregator.timings();
            println!(
                "aggregate: watching {entries} entr{}; poll {}s, debounce {}s, ceiling {}s",
                if entries == 1 { "y" } else { "ies" },
                timings.poll_interval_secs,
                timings.debounce_secs,
                timings.max_deferral_secs
            );
        }
        sbproxy_core::config_aggregator::aggregation_loop(&mut aggregator, &publisher, polls);
        return Ok(0);
    }

    let composed = match aggregator.compose() {
        Ok(composed) => composed,
        Err(error) => {
            use sbproxy_core::config_aggregator::AggregateError;
            eprintln!("aggregate: {error}");
            // Both classes exit 3 because neither published anything.
            // The second line differs because the next action does: a
            // deadline or an unreachable repository leaves the fleet on
            // its last good revision and is worth waiting out, while a
            // document that will not compose needs somebody to edit it.
            match error {
                AggregateError::Deadline { .. } | AggregateError::Unresolvable { .. } => {
                    eprintln!(
                        "aggregate: nothing was published; every subscriber is still serving \
                         the last revision this authority published."
                    );
                }
                _ => eprintln!("aggregate: nothing was published and nothing was written."),
            }
            return Ok(3);
        }
    };
    for failure in &composed.failed {
        eprintln!(
            "aggregate: warning: entry `{}` ({}) did not resolve: {}{}",
            failure.entry,
            failure.repo,
            failure.reason,
            failure
                .reused_commit
                .as_deref()
                .map_or_else(String::new, |commit| format!(
                    "; reusing its last resolved document at {commit}"
                ))
        );
    }

    if let Some(host) = args.explain.as_deref() {
        let Some(provenance) = composed.provenance.get(host) else {
            let known: Vec<&str> = composed.provenance.keys().map(String::as_str).collect();
            eprintln!(
                "aggregate: nothing composed for '{host}'. This composition produced: {}",
                if known.is_empty() {
                    "(no hosts)".to_string()
                } else {
                    known.join(", ")
                }
            );
            return Ok(3);
        };
        match args.format {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&cli_command_envelope(
                    "aggregate.explain",
                    serde_json::json!({ "host": host, "provenance": provenance }),
                ))?
            ),
            OutputFormat::Text => print!("{}", provenance.render(host)),
        }
        return Ok(0);
    }

    if let Some(out) = args.out.as_deref() {
        if args.dry_run {
            let diff = sbproxy_core::config_aggregator::Aggregator::diff_against(&composed, out)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            return Ok(report_aggregate_dry_run(
                args,
                &composed,
                out,
                diff.as_deref(),
            ));
        }
        sbproxy_core::config_aggregator::Aggregator::write_composed(&composed, out)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        // The header goes to stderr as well as into the file, so an
        // operator watching a CI job sees which revisions produced the
        // artifact without opening it.
        eprint!("{}", composed.header());
        match args.format {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&cli_command_envelope(
                    "aggregate.out",
                    aggregate_summary_json(&composed, Some(&out.display().to_string()), None),
                ))?
            ),
            OutputFormat::Text => println!(
                "aggregate: wrote {} origins from {} entries to {} ({} bytes, digest {})",
                composed.origins,
                composed.resolved.len(),
                out.display(),
                composed.yaml.len(),
                composed.content_digest
            ),
        }
        return Ok(0);
    }

    let publisher = AdminApiPublisher {
        admin: &args.admin,
        mode: args.mode,
    };
    match aggregator.publish_composed(composed, &publisher) {
        Ok(sbproxy_core::config_aggregator::RoundOutcome::Published { revision, outcome }) => {
            match args.format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&cli_command_envelope(
                        "aggregate.publish",
                        aggregate_summary_json(&outcome, None, Some(revision)),
                    ))?
                ),
                OutputFormat::Text => println!(
                    "aggregate: published revision {revision} ({} origins from {} entries, \
                     digest {})",
                    outcome.origins,
                    outcome.resolved.len(),
                    outcome.content_digest
                ),
            }
            Ok(0)
        }
        Ok(sbproxy_core::config_aggregator::RoundOutcome::Unchanged { outcome }) => {
            match args.format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&cli_command_envelope(
                        "aggregate.publish",
                        aggregate_summary_json(&outcome, None, None),
                    ))?
                ),
                OutputFormat::Text => println!(
                    "aggregate: the composed document is unchanged (digest {}), so nothing was \
                     published and no subscriber reloaded",
                    outcome.content_digest
                ),
            }
            Ok(0)
        }
        // `RoundOutcome` is `#[non_exhaustive]`, so a decision added
        // later reaches this arm rather than failing to compile in a
        // downstream crate. Reporting the digest and exiting 0 is the
        // conservative reading: nothing about the authority changed that
        // this binary understands.
        Ok(other) => {
            eprintln!("aggregate: the round finished with an outcome this build does not render");
            let _ = other;
            Ok(0)
        }
        Err(error) => {
            eprintln!("aggregate: {error}");
            eprintln!("aggregate: nothing changed on the authority.");
            Ok(3)
        }
    }
}

/// Print what `--out --dry-run` would change, and pick the exit code.
fn report_aggregate_dry_run(
    args: &AggregateArgs,
    composed: &sbproxy_core::config_aggregator::CompositionOutcome,
    out: &std::path::Path,
    diff: Option<&[String]>,
) -> i32 {
    let (changed, lines) = match diff {
        // The file is not there, so writing it is entirely a change.
        None => (true, Vec::new()),
        Some(lines) => (!lines.is_empty(), lines.to_vec()),
    };
    if matches!(args.format, OutputFormat::Json) {
        let body = cli_command_envelope(
            "aggregate.dry-run",
            serde_json::json!({
                "out": out.display().to_string(),
                "exists": diff.is_some(),
                "changed": changed,
                "diff": lines,
                "origins": composed.origins,
                "content_digest": composed.content_digest,
            }),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".to_string())
        );
        return i32::from(changed) * 2;
    }
    if diff.is_none() {
        println!(
            "aggregate: {} does not exist; composing would create it with {} origins",
            out.display(),
            composed.origins
        );
        return 2;
    }
    if !changed {
        println!(
            "aggregate: {} already holds this composition (digest {})",
            out.display(),
            composed.content_digest
        );
        return 0;
    }
    println!("aggregate: {} would change:", out.display());
    for line in &lines {
        println!("  {line}");
    }
    2
}

/// The shared JSON summary for the three `aggregate` output shapes.
fn aggregate_summary_json(
    composed: &sbproxy_core::config_aggregator::CompositionOutcome,
    out: Option<&str>,
    revision: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "out": out,
        "revision": revision,
        "origins": composed.origins,
        "content_digest": composed.content_digest,
        "bytes": composed.yaml.len(),
        "duration_ms": composed.duration.as_millis(),
        "resolved": composed.resolved,
        "failed": composed.failed,
        "drops": composed.drops,
        "provenance_hosts": composed.provenance.keys().collect::<Vec<_>>(),
    })
}

/// `sbproxy config authority publish`: validate the payload the way the
/// authority will, then publish it over the admin API.
///
/// The local validation is the same function the server route runs, so a
/// payload that would be refused is refused here, before a revision number
/// is spent on it.
///
/// Exit codes: 0 published (or validated under `--validate-only`), 1 CLI or
/// IO error, 3 the payload was refused locally and nothing was sent, 4 the
/// authority refused it, 7 the authority was unreachable.
fn handle_authority_publish(args: &AuthorityPublishArgs) -> anyhow::Result<i32> {
    let path = args.config.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "missing -f / --config: publish takes the payload document subscribers should apply, \
             not this node's own config file"
        )
    })?;
    let yaml = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read payload '{}': {error}", path.display()))?;
    // Relative model-host paths in a payload resolve on each subscriber,
    // not here, so the directory holding the payload is the best available
    // stand-in. That axis of the check is advisory; the rest is not.
    let validation_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let unresolved =
        match sbproxy_core::config_authority::validate_publish_payload(&yaml, validation_dir) {
            Ok(unresolved) => unresolved,
            Err(error) => {
                eprintln!("config authority publish: {error}");
                eprintln!(
                    "config authority publish: nothing was published and no revision was \
                     consumed. Fix the payload and run it again."
                );
                return Ok(3);
            }
        };
    if !unresolved.is_empty() {
        eprintln!(
            "config authority publish: warning: the payload carries ${{VAR}} reference(s) this \
             host cannot resolve: {}",
            unresolved.join(", ")
        );
        eprintln!(
            "config authority publish: warning: a subscriber that cannot resolve them either \
             refuses the bundle rather than applying the literal text."
        );
    }
    if args.validate_only {
        println!(
            "config authority publish: {} passes every check the authority runs. Nothing was \
             published (--validate-only).",
            path.display()
        );
        return Ok(0);
    }

    let route = format!(
        "{}?mode={}",
        sbproxy_core::config_authority::PUBLISH_PATH,
        args.mode.as_str()
    );
    let outcome = admin_request_parts(
        &args.admin,
        reqwest::Method::POST,
        &route,
        Some(AdminRequestBody::Yaml(yaml)),
    )?;
    let body = match outcome {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority publish",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority publish",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope("config.authority.publish", body))?
        ),
        OutputFormat::Text => {
            println!(
                "config authority publish: published revision {} (mode {}, key {}, digest {})",
                json_u64(&body, "revision"),
                body.get("mode")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(args.mode.as_str()),
                body.get("key_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                body.get("content_digest")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
            );
            println!(
                "config authority publish: subscribers take it on their next poll. Watch the \
                 rollout with `sbproxy config authority status`."
            );
        }
    }
    Ok(0)
}

/// `sbproxy config authority status`: what is published, under which key,
/// and which subscribers have taken it.
///
/// Read-only, and the document it prints carries no secret: subscriber
/// records name a credential id, never the credential, and the verifying
/// material is the public half of the signing key by construction.
///
/// Exit codes: 0 reported, 1 CLI or IO error, 4 the authority refused, 7 the
/// authority was unreachable.
fn handle_authority_status(args: &AuthorityStatusArgs) -> anyhow::Result<i32> {
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::GET,
        sbproxy_core::config_authority::STATUS_PATH,
        None,
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority status",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority status",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
        OutputFormat::Text => {
            let current_revision = json_u64(&body, "current_revision");
            println!(
                "authority {} key {} ({})",
                body.get("authority_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                body.get("key_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                body.get("algorithm")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
            );
            if current_revision == 0 {
                println!("revision: none published yet");
            } else {
                println!(
                    "revision: {current_revision} (digest {}, previous {}, highest reserved {})",
                    body.get("current_content_digest")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    body.get("previous_revision")
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_string(), |revision| revision.to_string()),
                    json_u64(&body, "high_water_revision"),
                );
            }
            println!(
                "subscribers: {} registered, {} live",
                json_u64(&body, "subscriber_count"),
                json_u64(&body, "live_subscriber_count"),
            );
            if let Some(subscribers) = body
                .get("subscribers")
                .and_then(serde_json::Value::as_array)
            {
                for subscriber in subscribers {
                    let last_seen = json_u64(subscriber, "last_seen_revision");
                    let state = if subscriber
                        .get("revoked")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        "revoked"
                    } else if subscriber
                        .get("up_to_date")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        "current"
                    } else if last_seen == 0 {
                        "never fetched"
                    } else {
                        "behind"
                    };
                    println!(
                        "{}\tcredential={}\tlast_seen_revision={last_seen}\t{state}",
                        subscriber
                            .get("subscriber_id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown"),
                        subscriber
                            .get("credential_id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown"),
                    );
                }
            }
        }
    }
    Ok(0)
}

/// `sbproxy config authority rollback`: republish the previous revision's
/// payload.
///
/// The new revision number is above the one it replaces, because a
/// subscriber's anti-replay cursor refuses anything that is not. A rollback
/// that re-served the old number would reach only the nodes that had not yet
/// taken the revision being undone, which is the opposite of what an
/// operator wants at that moment.
///
/// Exit codes: 0 rolled back, 1 CLI or IO error, 4 the authority refused
/// (typically no previous revision to return to), 7 unreachable.
fn handle_authority_rollback(args: &AuthorityRollbackArgs) -> anyhow::Result<i32> {
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::POST,
        sbproxy_core::config_authority::ROLLBACK_PATH,
        None,
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority rollback",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority rollback",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope("config.authority.rollback", body))?
        ),
        OutputFormat::Text => {
            println!(
                "config authority rollback: republished revision {}'s payload as revision {}, \
                 replacing revision {}",
                json_u64(&body, "restored_from_revision"),
                json_u64(&body, "revision"),
                json_u64(&body, "replaced_revision"),
            );
            println!(
                "config authority rollback: the number moves forward because a subscriber refuses \
                 a revision that is not greater than the one it applied. Subscribers take it on \
                 their next poll."
            );
        }
    }
    Ok(0)
}

/// `sbproxy config authority subscriber add`: register a subscriber and mint
/// its credential.
///
/// The authority stores only a SHA-256 fingerprint of the credential, so the
/// clear token printed here is the only copy that will ever exist. Text mode
/// prints it alone on stdout, the way `cluster token create` does, so
/// `export SB_CONFIG_AUTHORITY_TOKEN="$(...)"` works; the note saying it is
/// shown once goes to stderr so it cannot end up inside that variable.
///
/// Exit codes: 0 registered, 1 CLI or IO error, 4 the authority refused, 7
/// unreachable.
fn handle_authority_subscriber_add(args: &AuthoritySubscriberAddArgs) -> anyhow::Result<i32> {
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::POST,
        sbproxy_core::config_authority::SUBSCRIBERS_PATH,
        Some(AdminRequestBody::Json(serde_json::json!({
            "subscriber_id": args.subscriber_id,
        }))),
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority subscriber add",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority subscriber add",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    let credential = body
        .get("credential")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the authority registered the subscriber but returned no credential; register \
                 again once you know why, since this one cannot be recovered"
            )
        })?;
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "config.authority.subscriber.add",
                body.clone()
            ))?
        ),
        OutputFormat::Text => println!("{credential}"),
    }
    eprintln!(
        "config authority subscriber add: registered {} (credential id {}).",
        args.subscriber_id,
        body.get("credential_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
    );
    eprintln!(
        "config authority subscriber add: the credential above is shown once and never again. \
         The authority keeps only a SHA-256 fingerprint of it."
    );
    eprintln!(
        "config authority subscriber add: give it to that node as \
         proxy.config_authority.upstream.credential, by secret reference (env:NAME, file:/path, \
         secret://backend/name) rather than inline."
    );
    Ok(0)
}

/// `sbproxy config authority subscriber list`: the roster and each node's
/// last-seen revision.
///
/// Exit codes: as `config authority status`.
fn handle_authority_subscriber_list(args: &AuthoritySubscriberListArgs) -> anyhow::Result<i32> {
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::GET,
        sbproxy_core::config_authority::SUBSCRIBERS_PATH,
        None,
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority subscriber list",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority subscriber list",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
        OutputFormat::Text => {
            println!(
                "{} subscriber(s) registered, {} live",
                json_u64(&body, "subscriber_count"),
                json_u64(&body, "live_subscriber_count"),
            );
            if let Some(subscribers) = body
                .get("subscribers")
                .and_then(serde_json::Value::as_array)
            {
                for subscriber in subscribers {
                    println!(
                        "{}\tcredential={}\tlast_seen_revision={}\trevoked={}",
                        subscriber
                            .get("subscriber_id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown"),
                        subscriber
                            .get("credential_id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown"),
                        json_u64(subscriber, "last_seen_revision"),
                        subscriber
                            .get("revoked")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                    );
                }
            }
        }
    }
    Ok(0)
}

/// `sbproxy config authority subscriber revoke`: retire one credential, or
/// every credential one node holds.
///
/// Exit codes: 0 the authority answered, 1 CLI or IO error (including
/// naming neither selector), 4 the authority refused, 7 unreachable. A
/// selector that matches nothing is a successful answer reporting
/// `revoked: false`, not an error: the operator's goal (that credential
/// cannot fetch) holds either way.
fn handle_authority_subscriber_revoke(args: &AuthoritySubscriberRevokeArgs) -> anyhow::Result<i32> {
    let selector = match (args.credential_id.as_deref(), args.subscriber_id.as_deref()) {
        (Some(credential_id), _) => serde_json::json!({"credential_id": credential_id}),
        (None, Some(subscriber_id)) => serde_json::json!({"subscriber_id": subscriber_id}),
        (None, None) => {
            anyhow::bail!(
                "name what to revoke: --credential-id <id> for one credential, or \
                 --subscriber-id <id> for every credential that node holds"
            )
        }
    };
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::POST,
        sbproxy_core::config_authority::SUBSCRIBER_REVOKE_PATH,
        Some(AdminRequestBody::Json(selector)),
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config authority subscriber revoke",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal(
                "config authority subscriber revoke",
                status,
                &body,
            ));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "config.authority.subscriber.revoke",
                body
            ))?
        ),
        OutputFormat::Text => {
            // The route answers `true`/`false` for a credential and a count
            // for a subscriber, so both shapes get read.
            let revoked = body.get("revoked");
            let described = match revoked {
                Some(serde_json::Value::Bool(true)) => "revoked".to_string(),
                Some(serde_json::Value::Bool(false)) => {
                    "already revoked or not known to this authority".to_string()
                }
                Some(serde_json::Value::Number(count)) => {
                    format!("{count} credential(s) revoked")
                }
                _ => "the authority gave no revocation count".to_string(),
            };
            println!(
                "config authority subscriber revoke: {}: {described}",
                args.credential_id
                    .as_deref()
                    .or(args.subscriber_id.as_deref())
                    .unwrap_or("unknown"),
            );
            println!(
                "config authority subscriber revoke: a revoked node keeps serving what it \
                 already applied; it stops receiving updates."
            );
        }
    }
    Ok(0)
}

/// One line naming what an operator can do about a bundle the subscriber
/// refused.
fn pull_refusal_hint(result: sbproxy_core::config_subscriber::CycleResult) -> &'static str {
    use sbproxy_core::config_subscriber::CycleResult;

    match result {
        CycleResult::VerifyFailed => {
            "the signature, schema, digest, expiry, declared mode, or replay cursor rejected it. \
             Check that verifying_keys_file holds the authority's current key and that `mode` \
             here matches the mode the bundle was published under."
        }
        CycleResult::CompileFailed => {
            "the merged document could not be produced or carries an unresolved ${VAR}. Export \
             the variables this node is expected to provide, or fix the payload."
        }
        CycleResult::DeniedPath => {
            "the bundle names a path every subscriber owns outright (listeners, TLS, admin, \
             secrets, cluster, model_host, config_authority, source). The whole bundle is \
             refused, not the offending keys."
        }
        CycleResult::ConfinementRefused => {
            "the bundle reaches for this node's environment or filesystem (an env:, file:, or \
             vault:// reference, or a host path) that only the operator's own config may name. \
             Move that value into the root config here, or write the literal in the bundle."
        }
        // Not reachable from `evaluate`, which neither fetches nor reloads.
        // Named anyway so a new variant cannot be added without deciding
        // what it means here.
        CycleResult::Applied
        | CycleResult::NotModified
        | CycleResult::Unreachable
        | CycleResult::ReloadBusy => "see the log line above for the reason.",
    }
}

/// Diff the merged authority document against the local one.
///
/// The baseline is this node's file and the proposal is the merged document,
/// which is exactly the change one poll cycle would make. A boot-time
/// construction failure folds in as an error finding, the same channel
/// `plan` and `apply` use, so it reaches exit 3 rather than being reported
/// as a clean diff.
fn merged_plan_report(
    local_yaml: &str,
    merged_yaml: &str,
    config_dir: &std::path::Path,
) -> anyhow::Result<sbproxy_config::PlanReport> {
    let baseline = serde_yaml::from_str::<sbproxy_config::ConfigFile>(local_yaml)
        .map_err(|error| anyhow::anyhow!("parse the local document as ConfigFile: {error}"))?;
    let compiled = sbproxy_config::compile_config(merged_yaml)
        .map_err(|error| anyhow::anyhow!("the merged document does not compile:\n{error:#}"))?;
    let construction_error =
        sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
            compiled, config_dir,
        )
        .err()
        .map(|error| format!("{error:#}"));
    let proposed = serde_yaml::from_str::<sbproxy_config::ConfigFile>(merged_yaml)
        .map_err(|error| anyhow::anyhow!("parse the merged document as ConfigFile: {error}"))?;
    let mut report = sbproxy_config::plan(&baseline, &proposed);
    if let Some(message) = construction_error.as_deref() {
        push_construction_finding(&mut report, message);
    }
    Ok(report)
}

/// `sbproxy config pull --dry-run`: run a real poll cycle up to the point of
/// applying, and print the diff it would have applied.
///
/// The one command in this group that is deliberately local, because it
/// applies nothing. `ConfigSubscriber::fetch` is the only transport and
/// `ConfigSubscriber::evaluate` is pure (verify, mode check, cursor probe on
/// a clone, merge, unresolved-`${VAR}` screen), so the interesting half of a
/// cycle runs here with the bundle cache, the replay cursor, and the running
/// pipeline all untouched. Applying is the running proxy's own poll loop's
/// job: a short-lived CLI process cannot swap a server's pipeline, and
/// pretending otherwise is the defect that made `apply`'s exit code
/// worthless before #764.
///
/// Exit codes: 0 nothing to apply, 1 CLI or IO error, 2 changes present, 3
/// the bundle or the merged document was refused, 7 the authority was
/// unreachable.
fn handle_config_pull(
    args: &ConfigPullArgs,
    global_config: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    if !args.dry_run {
        anyhow::bail!(
            "config pull requires --dry-run. There is no local apply: a node takes its \
             authority's bundles through its own poll loop, and a short-lived CLI process cannot \
             swap a running proxy's pipeline. Use --dry-run to preview what the next poll would \
             apply."
        );
    }
    let path = resolve_config_path(args.config_path.as_deref(), global_config)?;
    let local_yaml = std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("read config '{}': {error}", path.display()))?;
    let compiled = sbproxy_config::compile_config(&local_yaml).map_err(|error| {
        anyhow::anyhow!("config '{}' did not compile:\n{error:#}", path.display())
    })?;
    let upstream = compiled
        .server
        .config_authority
        .as_ref()
        .and_then(|authority| authority.upstream.as_ref())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "'{}' sets no proxy.config_authority.upstream, so there is no authority to pull \
                 from. A node that publishes rather than subscribes uses `config authority \
                 status` instead.",
                path.display()
            )
        })?;
    // Secret references in the credential resolve through the process
    // resolver, exactly as they do at boot, so `secret://` works here and
    // not only in the server.
    install_secret_resolver(&path);
    let path_str = path.to_string_lossy().into_owned();
    let subscriber = sbproxy_core::config_subscriber::ConfigSubscriber::new(&path_str, &upstream)?;
    if !subscriber.has_keys() {
        eprintln!(
            "config pull: warning: no verifying key set loaded from {}, so no bundle can be \
             verified and none would be applied.",
            upstream.verifying_keys_file
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let fetched = runtime.block_on(subscriber.fetch());
    let signed = match fetched {
        sbproxy_core::config_subscriber::FetchResult::Unreachable(reason) => {
            eprintln!(
                "config pull: the authority at {} could not be reached: {reason}",
                upstream.url
            );
            eprintln!(
                "config pull: nothing was applied. A running node in this state keeps serving \
                 the configuration it already applied."
            );
            return Ok(7);
        }
        sbproxy_core::config_subscriber::FetchResult::NotModified => {
            println!(
                "config pull: the authority is serving revision {}, which this node already \
                 holds. No changes, and nothing was applied.",
                subscriber.revision()
            );
            return Ok(0);
        }
        sbproxy_core::config_subscriber::FetchResult::Bundle(signed) => signed,
    };
    // Mirrors the poll loop, which short-circuits before evaluating: an
    // authority that does not implement `If-None-Match` re-serves the
    // applied revision every interval, and that is a no-op rather than a
    // change.
    if subscriber.holds_revision(&signed.bundle) {
        println!(
            "config pull: the authority re-served revision {}, which this node already holds. No \
             changes, and nothing was applied.",
            signed.bundle.revision
        );
        return Ok(0);
    }
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let candidate = match subscriber.evaluate(&signed, &local_yaml, now_unix_ms) {
        Ok(candidate) => candidate,
        Err(refusal) => {
            eprintln!(
                "config pull: revision {} was refused ({}): {}",
                signed.bundle.revision,
                refusal.result.as_str(),
                pull_refusal_hint(refusal.result),
            );
            eprintln!("config pull: {}", refusal.detail);
            eprintln!(
                "config pull: nothing was applied. The bundle cache, the replay cursor, and the \
                 running configuration are all untouched."
            );
            return Ok(3);
        }
    };
    let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let report = match merged_plan_report(&local_yaml, candidate.merged_yaml(), config_dir) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "config pull: revision {} verified, but the merged document would be refused: \
                 {error:#}",
                candidate.revision()
            );
            eprintln!("config pull: nothing was applied.");
            return Ok(3);
        }
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "command": "config.pull",
                // Load-bearing, not decoration: this command never applies
                // anything, and a consumer should not have to infer that.
                "applied": false,
                "dry_run": true,
                "authority_url": upstream.url,
                "mode": upstream.mode,
                "offered_revision": candidate.revision(),
                "applied_revision": subscriber.revision(),
                "plan": report,
            }))?
        ),
        OutputFormat::Text => {
            println!(
                "config pull: authority offers revision {}; this node has applied {}. Dry run: \
                 nothing is applied.",
                candidate.revision(),
                subscriber.revision(),
            );
            print!("{}", sbproxy_config::render_text(&report));
            println!(
                "config pull: nothing was applied. The bundle cache, the replay cursor, and the \
                 running configuration are all untouched. The proxy's own poll loop is what \
                 applies a bundle."
            );
        }
    }
    Ok(plan_exit_code(&report))
}

/// `sbproxy config history`: list every config revision recorded in the
/// running proxy's `proxy.config_history` ring (WOR-2456/2457), newest
/// first. Speaks to the admin API the same way `apply` and `config
/// authority status` do: `--admin-url`/`SB_ADMIN_URL`,
/// `--username`/`SB_ADMIN_USERNAME`, `--password`/`SB_ADMIN_PASSWORD`.
fn handle_config_history(args: &ConfigHistoryArgs) -> anyhow::Result<i32> {
    let body = match admin_request_parts(
        &args.admin,
        reqwest::Method::GET,
        "/admin/config/history",
        None,
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config history",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal("config history", status, &body));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
        OutputFormat::Text => print_config_history_table(&body),
    }
    Ok(0)
}

/// Render `GET /admin/config/history`'s body as the `--format text`
/// table: one row per revision, in the order the admin API already
/// returns them (newest first).
fn print_config_history_table(body: &serde_json::Value) {
    let lineage = body
        .get("lineage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let lkg_line = body
        .get("lkg_revision")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(String::new, |revision| {
            format!(", last-known-good revision {revision}")
        });
    println!("lineage {lineage}{lkg_line}");

    let entries = body
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        println!("no config revisions recorded yet");
        return;
    }
    println!("REVISION\tSTATE\tBLAST RADIUS\tPROVENANCE\tAPPLIED AT\tACTOR\tDIGEST");
    for entry in &entries {
        let revision = json_u64(entry, "revision");
        let state = entry
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let blast_radius = entry
            .get("blast_radius")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let provenance = entry
            .get("provenance")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let applied_at = entry
            .get("applied_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let actor = entry
            .get("actor")
            .and_then(serde_json::Value::as_str)
            .filter(|actor| !actor.is_empty())
            .unwrap_or("-");
        let digest = entry
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        println!(
            "{revision}\t{state}\t{blast_radius}\t{provenance}\t{applied_at}\t{actor}\t{digest}"
        );
    }
}

/// `sbproxy config rollback --to <rev|digest|last-known-good>`: ask the
/// running proxy to re-apply a config revision it already stored
/// (WOR-2460).
///
/// Speaks to the admin API the way `config history` and `apply` do.
/// Exit codes follow the `config` family's convention: `0` on a
/// rollback that applied, `4` when the node refused it (an unknown
/// revision, a stale `--expected-current`, an unconfirmed restart-class
/// change), and `2` on a CLI-level error, which `run_subcommand` maps.
///
/// The `--confirm` flag is the typed confirmation a restart-class or
/// breaking rollback needs. The node computes the blast radius from the
/// two stored documents, so the CLI does not have to guess: run without
/// `--confirm` first, read the refusal, and re-run naming the revision
/// back if the radius is one you accept.
fn handle_config_rollback(args: &ConfigRollbackArgs) -> anyhow::Result<i32> {
    let mut body = serde_json::Map::new();
    // A digest is 64 lowercase hex characters; a revision is a number.
    // Deciding here rather than making the operator pick a flag is the
    // one place this CLI guesses, and it guesses from a shape that
    // cannot be both.
    if args.to == "last-known-good" {
        body.insert(
            "target".to_string(),
            serde_json::Value::String("last-known-good".to_string()),
        );
    } else if let Ok(revision) = args.to.parse::<u64>() {
        body.insert("revision".to_string(), serde_json::json!(revision));
    } else {
        body.insert(
            "digest".to_string(),
            serde_json::Value::String(args.to.clone()),
        );
    }
    if let Some(expected) = args.expected_current {
        body.insert("expected_current".to_string(), serde_json::json!(expected));
    }
    if let Some(confirm) = args.confirm {
        body.insert("confirm_revision".to_string(), serde_json::json!(confirm));
    }
    if let Some(lineage) = args.lineage.as_deref() {
        body.insert(
            "lineage".to_string(),
            serde_json::Value::String(lineage.to_string()),
        );
    }
    if args.force {
        body.insert("force".to_string(), serde_json::json!(true));
    }
    let payload = AdminRequestBody::Json(serde_json::Value::Object(body));

    let answer = match admin_request_parts(
        &args.admin,
        reqwest::Method::POST,
        "/admin/config/rollback",
        Some(payload),
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config rollback",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            // Printed rather than swallowed: the refusal body is where
            // the available revisions and both sides of a stale
            // `expected_current` live, and it is the whole reason this
            // route names them.
            report_admin_refusal("config rollback", status, &body);
            if matches!(args.format, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
            return Ok(4);
        }
        AdminOutcome::Answered { body, .. } => body,
    };

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&answer)?),
        OutputFormat::Text => print_config_rollback_text(&answer),
    }
    Ok(0)
}

/// Render a successful rollback for `--format text`.
///
/// Every warning the node returned is printed, and the config-file line
/// is printed whether or not the node listed it, because that is the
/// half of the recovery the rollback did not do.
fn print_config_rollback_text(body: &serde_json::Value) {
    let restored = json_u64(body, "restored_revision");
    let digest = body
        .get("restored_digest")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let radius = body
        .get("blast_radius")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    println!("config rollback: restored revision {restored} ({digest}), blast radius {radius}");
    // Both of these are conditional on `appended_revision`, and on the
    // same one: a rollback onto the document already running is
    // deduplicated by the ring, so it appends nothing and marks nothing
    // reverted. Keying the "marked reverted" line on `previous_revision`
    // printed a false claim on exactly the no-op rollback the server
    // side exists to handle, which is also the one an operator is most
    // likely to reach for mid-incident.
    match (
        body.get("appended_revision")
            .and_then(serde_json::Value::as_u64),
        body.get("previous_revision")
            .and_then(serde_json::Value::as_u64),
    ) {
        (Some(appended), previous) => {
            if let Some(previous) = previous {
                println!("config rollback: revision {previous} is marked reverted");
            }
            println!(
                "config rollback: appended as revision {appended}; history is append-only, so \
                 this rollback is itself in the history"
            );
        }
        (None, _) => println!(
            "config rollback: that revision was already what this node was running, so nothing \
             was appended and no revision was marked reverted"
        ),
    }
    if body
        .get("soaking")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        println!(
            "config rollback: the restored revision is soaking like any other candidate. \
             POST /admin/config/confirm promotes it early; a failed soak leaves the \
             last-known-good pointer where it is"
        );
    }
    for warning in body
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&Vec::new())
    {
        if let Some(warning) = warning.as_str() {
            println!("config rollback: warning: {warning}");
        }
    }
}

/// `sbproxy config diff [<rev>] [--from <a> --to <b>]`: a plan between
/// two stored config revisions, or between what is running and one
/// stored revision (WOR-2460).
///
/// Junos has both forms and the second is the one people want
/// mid-incident: `show | compare rollback n` diffs against one stored
/// revision, and `show system rollback 3 compare 1` diffs two stored
/// revisions that need not be adjacent. Cisco's
/// `show archive config differences` is the same idea.
///
/// Reads only. Nothing is applied, no pointer moves, and the running
/// config is untouched whichever form is used. Exit codes follow
/// `plan`'s convention through [`ConfigCmd::uses_plan_exit_codes`]: `0`
/// when the two revisions are identical, `2` when they differ.
fn handle_config_diff(args: &ConfigDiffArgs) -> anyhow::Result<i32> {
    let to = match (args.to.as_deref(), args.to_flag.as_deref()) {
        (Some(_), Some(_)) => {
            eprintln!(
                "config diff: name the target revision once, either as the positional argument \
                 or as --to, not both"
            );
            return Ok(1);
        }
        (Some(positional), None) => positional,
        (None, Some(flag)) => flag,
        (None, None) => {
            eprintln!(
                "config diff: name a target revision, for example `sbproxy config diff 7` or \
                 `sbproxy config diff --from 5 --to 7`. `sbproxy config history` lists what is \
                 in the ring"
            );
            return Ok(1);
        }
    };
    let mut path = format!("/admin/config/diff?to={}", urlencoding_lite(to));
    if let Some(from) = args.from.as_deref() {
        path.push_str(&format!("&from={}", urlencoding_lite(from)));
    }
    let body = match admin_request_parts(&args.admin, reqwest::Method::GET, &path, None)? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config diff",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal("config diff", status, &body));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
        OutputFormat::Text => {
            let from = describe_diff_side(body.get("from"), "the running configuration");
            let to = describe_diff_side(body.get("to"), "unknown");
            let radius = body
                .get("max_blast_radius")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            println!("config diff: {from} -> {to}, largest blast radius {radius}");
            print!(
                "{}",
                body.get("plan_text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
            );
        }
    }
    // `plan`'s convention: 2 means "changes present" and is not an
    // error, so a script can branch on "is this rollback a no-op".
    let changes = json_u64(&body, "changes");
    Ok(if changes == 0 { 0 } else { 2 })
}

/// Name one side of a diff for the text header.
fn describe_diff_side(side: Option<&serde_json::Value>, when_absent: &str) -> String {
    side.and_then(|side| side.get("revision"))
        .and_then(serde_json::Value::as_u64)
        .map_or_else(
            || when_absent.to_string(),
            |revision| format!("revision {revision}"),
        )
}

/// Percent-encode the handful of characters a revision selector could
/// carry that would otherwise break the query string.
///
/// Deliberately tiny rather than a dependency: the accepted values are a
/// decimal number and the literal `last-known-good`, and anything else
/// is refused by the route with a message naming both forms. This exists
/// so a typo cannot smuggle an `&` into the next parameter.
fn urlencoding_lite(value: &str) -> String {
    // Over bytes, not chars: `character as u32 & 0xFF` truncated a
    // non-ASCII scalar to its low byte, so `U+0100` encoded as `%00`
    // and the server was handed a different string than the operator
    // typed. Percent-encoding is defined on octets, and `as_bytes` on a
    // `&str` is already UTF-8.
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// `sbproxy config show <rev>`: resolve a revision number to its
/// content digest via `GET /admin/config/history` (the same listing
/// `config history` prints), then print the stored document
/// `GET /admin/config/history/{digest}` returns for that revision.
fn handle_config_show(args: &ConfigShowArgs) -> anyhow::Result<i32> {
    let list_body = match admin_request_parts(
        &args.admin,
        reqwest::Method::GET,
        "/admin/config/history",
        None,
    )? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config show",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal("config show", status, &body));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    let digest = list_body
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .find(|&entry| json_u64(entry, "revision") == args.revision)
        })
        .and_then(|entry| entry.get("digest"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let Some(digest) = digest else {
        eprintln!(
            "config show: revision {} was not found in this node's config history. Run \
             `sbproxy config history` to see what is currently in the ring.",
            args.revision
        );
        return Ok(4);
    };

    // The digest is always a lowercase hex sha256 minted by the store
    // itself (see `sbproxy_config::revision_store`'s `sha256_hex`), so it
    // carries nothing a URL path needs escaped.
    let detail_path = format!("/admin/config/history/{digest}");
    let detail = match admin_request_parts(&args.admin, reqwest::Method::GET, &detail_path, None)? {
        AdminOutcome::Unreachable(reason) => {
            return Ok(report_admin_unreachable(
                "config show",
                &args.admin,
                &reason,
            ));
        }
        AdminOutcome::Answered { status, body } if !status.is_success() => {
            return Ok(report_admin_refusal("config show", status, &body));
        }
        AdminOutcome::Answered { body, .. } => body,
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&detail)?),
        OutputFormat::Text => print!("{}", config_show_document_text(&detail)),
    }
    Ok(0)
}

/// The `--format text` rendering of `GET /admin/config/history/{digest}`'s
/// response: the `document` field, verbatim, and nothing else. The admin
/// route redacts `document` (and `plan_text`) before it ever serializes
/// a response -- see `sbproxy_core::admin::handle_config_history_detail`
/// -- so there is nothing left for the CLI to redact here; this
/// function does no transformation of its own precisely so a test can
/// assert that fact, rather than only asserting the server-side JSON
/// shape. `--format json` above takes the same already-redacted `detail`
/// value through `serde_json::to_string_pretty` with no extra field
/// access, so it carries the identical guarantee.
fn config_show_document_text(detail: &serde_json::Value) -> &str {
    detail
        .get("document")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// `${VAR}` interpolation for the CLI paths that read a config file
/// without compiling it (`config print`, `mcp lock`).
///
/// This is [`sbproxy_config::interpolate_env_vars`], the compiler's own
/// pass, rather than a copy of it. A local copy shipped here for a while
/// and had drifted three ways from the pass it claimed to match: it
/// substituted `$${VAR}`, which is the documented escape and must stay
/// literal; it substituted `${args.id}` and `${steps.x.y}`, which are
/// MCP local-tool vocabulary the executor owns at call time; and it had
/// no `${VAR:-default}` support at all, so a shipped example resolving
/// to its default printed the raw placeholder instead. A second reader
/// of the environment on a config path is only safe while it is the
/// same reader; WOR-2433 makes it literally so.
fn interpolate_env_vars(input: &str) -> String {
    sbproxy_config::interpolate_env_vars(input)
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
            // Both halves of `key_management.crypto`. `pepper` was on
            // neither this list nor any pattern, so an inline
            // `pepper: a-long-random-server-pepper` came back verbatim on
            // every config surface: it is the salt inbound key hashes are
            // built with, and leaking it is what makes a stolen hash table
            // worth brute-forcing. `master_key` is in the pattern pass's
            // alternation, so it was single-covered; naming it here makes
            // both double-covered, which is what the rest of this list is.
            | "pepper"
            | "master_key"
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

fn handle_audit_subcommand(cmd: &AuditCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        AuditSub::Verify(args) => handle_audit_verify(args),
    }
}

/// `sbproxy audit verify`: re-derive the security, config, key, or admin
/// audit chain from genesis and report the first record that does not
/// check out.
///
/// Reads the file and nothing else. No config, no admin API, no running
/// proxy: an auditor with a copy of the chain and the public key can run
/// this against a file the proxy that wrote it no longer has, which is
/// the point of signing the entries rather than merely logging them.
fn handle_audit_verify(args: &AuditVerifyArgs) -> anyhow::Result<i32> {
    use sbproxy_observe::audit_chain::{
        verify_admin_audit_chain, verify_config_audit_chain, verify_key_audit_chain,
        verify_security_audit_chain, verifying_key_from_seed_hex,
    };

    let verifying_key = match args.signing_seed_hex.as_deref() {
        Some(seed) => Some(verifying_key_from_seed_hex(seed)?),
        None => None,
    };
    let result = match args.channel.as_str() {
        "config" => verify_config_audit_chain(&args.path, verifying_key.as_ref())?,
        "key" => verify_key_audit_chain(&args.path, verifying_key.as_ref())?,
        "admin" => verify_admin_audit_chain(&args.path, verifying_key.as_ref())?,
        _ => verify_security_audit_chain(&args.path, verifying_key.as_ref())?,
    };
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
                    "audit verify: OK ({} record{}, {})",
                    result.entries,
                    if result.entries == 1 { "" } else { "s" },
                    if verifying_key.is_some() {
                        "chain + signatures"
                    } else {
                        "chain only, no signing seed given"
                    },
                );
            } else {
                eprintln!(
                    "audit verify: FAILED at record {}: {}",
                    result.broken_seq.map(|s| s.to_string()).unwrap_or_default(),
                    result.reason.as_deref().unwrap_or("unknown"),
                );
            }
        }
    }

    Ok(if result.ok { 0 } else { 1 })
}

fn handle_ai_subcommand(cmd: &AiCmd) -> anyhow::Result<i32> {
    match &cmd.sub {
        AiSub::Ledger(ledger) => match &ledger.sub {
            LedgerSub::Verify(args) => handle_ledger_verify(args),
            LedgerSub::Report(args) => handle_ledger_report(args),
            LedgerSub::Reconcile(args) => handle_ledger_reconcile(args),
        },
        AiSub::Prompt(prompt) => match &prompt.sub {
            PromptSub::Optimize(args) => handle_prompt_optimize(args),
            PromptSub::Select(args) => handle_prompt_select(args),
        },
        AiSub::Workflow(workflow) => match &workflow.sub {
            WorkflowSub::Discover(args) => handle_workflow_discover(args),
            WorkflowSub::Validate(args) => handle_workflow_validate(args),
            WorkflowSub::Run(args) => handle_workflow_run(args),
        },
        AiSub::Dataset(dataset) => match &dataset.sub {
            DatasetSub::Register(args) => handle_dataset_register(args),
        },
        AiSub::Evaluate(args) => handle_ai_evaluate(args),
    }
}

const MAX_AI_TOOLKIT_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_AI_WORKFLOW_INPUT_BYTES: usize = 256 * 1024;
const MAX_AI_TOOLKIT_ADMIN_RESPONSE_BYTES: usize = 1024 * 1024;

fn load_workflow_document(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    let bytes = read_bounded_cli_file(path, MAX_AI_TOOLKIT_DOCUMENT_BYTES, "workflow")?;
    serde_yaml::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("parse workflow {}: {error}", path.display()))
}

fn load_ai_toolkit_json(
    path: &std::path::Path,
    limit: usize,
    description: &str,
) -> anyhow::Result<serde_json::Value> {
    let bytes = read_bounded_cli_file(path, limit, description)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("parse {description} {}: {error}", path.display()))
}

fn handle_ai_toolkit_admin(
    command: &str,
    admin: &ModelsAdminArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<i32> {
    validate_ai_toolkit_admin_body(command, body.as_ref())?;
    match admin_request_parts_bounded_with_timeout(
        admin,
        method,
        path,
        body.map(AdminRequestBody::Json),
        std::time::Duration::from_secs(65),
        MAX_AI_TOOLKIT_ADMIN_RESPONSE_BYTES,
        "AI toolkit",
    )? {
        AdminOutcome::Answered { status, body } if status.is_success() => {
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(0)
        }
        AdminOutcome::Answered { status, body } => Ok(report_admin_refusal(command, status, &body)),
        AdminOutcome::Unreachable(reason) => Ok(report_admin_unreachable(command, admin, &reason)),
    }
}

fn validate_ai_toolkit_admin_body(
    command: &str,
    body: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let Some(value) = body else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_AI_TOOLKIT_DOCUMENT_BYTES {
        anyhow::bail!(
            "{command} request exceeds the {MAX_AI_TOOLKIT_DOCUMENT_BYTES}-byte aggregate limit"
        );
    }
    Ok(())
}

fn handle_workflow_discover(args: &WorkflowDiscoverArgs) -> anyhow::Result<i32> {
    let mut url = reqwest::Url::parse("http://localhost/admin/ai-toolkit/agents")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("origin", &args.origin);
        if let Some(capability) = args.capability.as_deref() {
            query.append_pair("capability", capability);
        }
    }
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    handle_ai_toolkit_admin(
        "ai workflow discover",
        &args.admin,
        reqwest::Method::GET,
        &path,
        None,
    )
}

fn handle_workflow_validate(args: &WorkflowValidateArgs) -> anyhow::Result<i32> {
    let workflow = load_workflow_document(&args.path)?;
    handle_ai_toolkit_admin(
        "ai workflow validate",
        &args.admin,
        reqwest::Method::POST,
        "/admin/ai-toolkit/workflows/validate",
        Some(serde_json::json!({
            "origin": args.origin,
            "workflow": workflow,
        })),
    )
}

fn handle_workflow_run(args: &WorkflowRunArgs) -> anyhow::Result<i32> {
    let input = load_ai_toolkit_json(&args.input, MAX_AI_WORKFLOW_INPUT_BYTES, "workflow input")?;
    handle_ai_toolkit_admin(
        "ai workflow run",
        &args.admin,
        reqwest::Method::POST,
        "/admin/ai-toolkit/workflows/run",
        Some(serde_json::json!({
            "origin": args.origin,
            "workflow": args.workflow,
            "input": input,
        })),
    )
}

fn handle_dataset_register(args: &DatasetRegisterArgs) -> anyhow::Result<i32> {
    let dataset = load_ai_toolkit_json(
        &args.dataset,
        MAX_AI_TOOLKIT_DOCUMENT_BYTES,
        "evaluation dataset",
    )?;
    let mut dataset = dataset
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("evaluation dataset must be a JSON object"))?;
    dataset.insert(
        "origin".to_string(),
        serde_json::Value::String(args.origin.clone()),
    );
    handle_ai_toolkit_admin(
        "ai dataset register",
        &args.admin,
        reqwest::Method::POST,
        "/admin/ai-toolkit/datasets/register",
        Some(serde_json::Value::Object(dataset)),
    )
}

fn handle_ai_evaluate(args: &EvaluateArgs) -> anyhow::Result<i32> {
    let length_bounds = (args.min_bytes.is_some() || args.max_bytes.is_some()).then(|| {
        (
            args.min_bytes.unwrap_or(0),
            args.max_bytes.unwrap_or(1024 * 1024),
        )
    });
    if let Some((min_bytes, max_bytes)) = length_bounds {
        if min_bytes > max_bytes {
            anyhow::bail!("--min-bytes must not exceed --max-bytes");
        }
    }
    let responses = load_ai_toolkit_json(
        &args.responses,
        MAX_AI_TOOLKIT_DOCUMENT_BYTES,
        "evaluation responses",
    )?;
    if !responses.is_array() {
        anyhow::bail!("evaluation responses must be a JSON array");
    }

    // Injected only when a bound was asked for: an always-on metric diluted
    // the reported pass rate, and its 1 MiB default was refused outright by
    // configs that lower `limits.max_response_bytes` below it.
    let mut metrics = Vec::new();
    if let Some((min_bytes, max_bytes)) = length_bounds {
        metrics.push(serde_json::json!({
            "type": "length_range",
            "min": min_bytes,
            "max": max_bytes,
        }));
    }
    if !args.required_keywords.is_empty() {
        metrics.push(serde_json::json!({
            "type": "contains_keywords",
            "keywords": args.required_keywords,
        }));
    }
    if let Some(path) = args.json_schema.as_deref() {
        let schema = load_ai_toolkit_json(path, MAX_AI_TOOLKIT_DOCUMENT_BYTES, "JSON Schema")?;
        metrics.push(serde_json::json!({
            "type": "json_schema",
            "schema": schema,
        }));
    }

    let parameters = match args.parameters.as_deref() {
        Some(path) => {
            load_ai_toolkit_json(path, MAX_AI_TOOLKIT_DOCUMENT_BYTES, "evaluation parameters")?
        }
        None => serde_json::json!({}),
    };
    let judge = match args.judge_responses.as_deref() {
        Some(path) => {
            let judge_model = args.judge_model.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--judge-model is required with --judge-responses")
            })?;
            if args.judge_criteria.is_empty() {
                anyhow::bail!("at least one --judge-criterion is required with --judge-responses");
            }
            let judge_responses = load_ai_toolkit_json(
                path,
                MAX_AI_TOOLKIT_DOCUMENT_BYTES,
                "offline judge responses",
            )?;
            if !judge_responses.is_array() {
                anyhow::bail!("offline judge responses must be a JSON array");
            }
            Some(serde_json::json!({
                "judge_model": judge_model,
                "criteria": args.judge_criteria,
                "responses": judge_responses,
            }))
        }
        None => {
            if args.judge_model.is_some() || !args.judge_criteria.is_empty() {
                anyhow::bail!("--judge-model and --judge-criterion require --judge-responses");
            }
            None
        }
    };

    handle_ai_toolkit_admin(
        "ai evaluate",
        &args.admin,
        reqwest::Method::POST,
        "/admin/ai-toolkit/evaluations/run",
        Some(serde_json::json!({
            "origin": args.origin,
            "experiment_id": args.experiment_id,
            "experiment_name": args.experiment_name,
            "dataset": {"name": args.dataset, "version": args.version},
            "model": args.model,
            "prompt_version": args.prompt_version,
            "parameters": parameters,
            "responses": responses,
            "judge": judge,
            "metrics": metrics,
        })),
    )
}

fn handle_prompt_select(args: &PromptSelectArgs) -> anyhow::Result<i32> {
    handle_ai_toolkit_admin(
        "ai prompt select",
        &args.admin,
        reqwest::Method::POST,
        "/admin/ai-toolkit/prompts/select",
        Some(serde_json::json!({
            "origin": args.origin,
            "name": args.name,
            "cohort": args.cohort,
        })),
    )
}

fn handle_prompt_optimize(args: &PromptOptimizeArgs) -> anyhow::Result<i32> {
    const MAX_PROMPT_BYTES: usize = 1024 * 1024;
    const MAX_EVAL_SET_BYTES: usize = 16 * 1024 * 1024;

    let prompt_bytes = read_bounded_cli_file(&args.prompt, MAX_PROMPT_BYTES, "system prompt")?;
    let prompt = std::str::from_utf8(&prompt_bytes)
        .map_err(|error| anyhow::anyhow!("system prompt must be UTF-8: {error}"))?;
    let eval_bytes = read_bounded_cli_file(&args.eval_set, MAX_EVAL_SET_BYTES, "eval set")?;
    let cases = sbproxy_ai::prompt_optimizer::parse_prompt_eval_jsonl(&eval_bytes)?;
    let api_key = match args.api_key_env.as_deref() {
        Some(name) => {
            if name.trim().is_empty() || name.contains('=') {
                anyhow::bail!("--api-key-env must name one environment variable");
            }
            Some(
                std::env::var(name)
                    .map_err(|_| anyhow::anyhow!("environment variable {name:?} is not set"))?,
            )
        }
        None => None,
    };
    let mut client = sbproxy_ai::prompt_optimizer::OpenAiPromptOptimizationClient::new(
        &args.endpoint,
        api_key,
        std::time::Duration::from_secs(args.timeout_secs),
    )?;
    if let Some(host) = args.host_header.as_deref() {
        client = client.with_host_header(host)?;
    }
    let config = sbproxy_ai::prompt_optimizer::PromptOptimizationConfig {
        name: args.name.clone(),
        version: args.prompt_version.clone(),
        task_model: args.task_model.clone(),
        optimizer_model: args
            .optimizer_model
            .clone()
            .unwrap_or_else(|| args.task_model.clone()),
        metric: args.metric.into(),
        noise_tolerance: args.noise_tolerance,
        max_candidates: args.max_candidates,
        max_requests: args.max_requests,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("build prompt optimizer runtime: {error}"))?;
    let artifact = runtime.block_on(sbproxy_ai::prompt_optimizer::optimize_prompt(
        &client, prompt, &cases, &config,
    ))?;
    let mut output = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| anyhow::anyhow!("serialize prompt artifact: {error}"))?;
    output.push(b'\n');
    std::fs::write(&args.output, output).map_err(|error| {
        anyhow::anyhow!("write prompt artifact {}: {error}", args.output.display())
    })?;
    println!(
        "prompt optimize: wrote {} ({} -> {} tokens, quality {:.4} -> {:.4})",
        args.output.display(),
        artifact.original_tokens,
        artifact.optimized_tokens,
        artifact.baseline_score,
        artifact.optimized_score
    );
    Ok(0)
}

fn read_bounded_cli_file(
    path: &std::path::Path,
    maximum: usize,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("read {label} {}: {error}", path.display()))?;
    read_bounded_cli_open_file(file, path, maximum, label)
}

fn read_bounded_cli_open_file(
    file: std::fs::File,
    path: &std::path::Path,
    maximum: usize,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {label} {}: {error}", path.display()))?;
    if bytes.len() > maximum {
        anyhow::bail!(
            "{label} {} exceeds the {} byte limit",
            path.display(),
            maximum
        );
    }
    Ok(bytes)
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

/// `sbproxy ai ledger report`: aggregate a value ledger (the redb file
/// the AI handler keeps at `<cache_dir>/value-ledger.redb`) into the same
/// report the admin `GET /admin/model-host/value` route serves, without a
/// running server.
///
/// Reads the file directly and offline, the way `ai ledger verify` reads
/// its artifact; querying a live proxy stays the admin route's job (an
/// admin-URL mode is a possible later extension). A missing file is the
/// normal state before any value is recorded, so it reports an empty
/// ledger rather than an error.
fn handle_ledger_report(args: &LedgerReportArgs) -> anyhow::Result<i32> {
    handle_ledger_report_to(args, &mut std::io::stdout())
}

/// The testable core of `handle_ledger_report`: writes the report to
/// `out` instead of stdout, so tests can assert on it without capturing
/// the process's real stdout.
fn handle_ledger_report_to(
    args: &LedgerReportArgs,
    out: &mut impl std::io::Write,
) -> anyhow::Result<i32> {
    // `ValueLedger::open` creates a missing database, so probe first: a
    // report must never write the file it is reporting on.
    let report = if args.path.exists() {
        sbproxy_ai::value_ledger::ValueLedger::open(&args.path)?.report()
    } else {
        sbproxy_model_host::ValueReport::default()
    };

    match args.format {
        OutputFormat::Json => {
            // The exact serialization the admin value route returns, so
            // the two surfaces stay key-for-key interchangeable.
            writeln!(out, "{}", serde_json::to_string(&report)?)?;
        }
        OutputFormat::Text => {
            if report.models.is_empty() && report.compression.is_empty() {
                writeln!(out, "ledger report: no value recorded yet")?;
                return Ok(0);
            }
            if !report.models.is_empty() {
                writeln!(
                    out,
                    "{:<24} {:>8} {:>8} {:>14} {:>14}",
                    "MODEL", "LOCAL", "CLOUD", "SAVED_USD", "CLOUD_USD"
                )?;
                for model in &report.models {
                    writeln!(
                        out,
                        "{:<24} {:>8} {:>8} {:>14} {:>14}",
                        model.model,
                        model.local_completions,
                        model.cloud_completions,
                        usd_from_micros(model.saved_micros),
                        usd_from_micros(model.cloud_spent_micros),
                    )?;
                }
                writeln!(
                    out,
                    "totals: {} local, {} cloud, saved USD {}, cloud spent USD {}",
                    report.total_local_completions,
                    report.total_cloud_completions,
                    usd_from_micros(report.total_saved_micros),
                    usd_from_micros(report.total_cloud_spent_micros),
                )?;
            }
            if !report.compression.is_empty() {
                if !report.models.is_empty() {
                    writeln!(out)?;
                }
                writeln!(
                    out,
                    "{:<24} {:<20} {:>14} {:>14} PRECISION",
                    "MODEL", "LEVER", "TOKENS_SAVED", "GROSS_USD"
                )?;
                for row in &report.compression {
                    writeln!(
                        out,
                        "{:<24} {:<20} {:>14} {:>14} {}",
                        row.model,
                        row.lever,
                        row.tokens_saved,
                        usd_from_micros(row.gross_cost_saved_micros),
                        row.token_count_precision.as_str(),
                    )?;
                }
                writeln!(
                    out,
                    "compression totals: {} tokens saved, USD {} gross input cost avoided",
                    report.total_compression_tokens_saved,
                    usd_from_micros(report.total_compression_gross_cost_saved_micros),
                )?;
            }
        }
    }

    Ok(0)
}

/// `sbproxy ai ledger reconcile`: compare the local usage ledger against
/// a provider's own usage export, per (day, model), to surface spend the
/// gateway's own metering path never saw (WOR-2476).
fn handle_ledger_reconcile(args: &LedgerReconcileArgs) -> anyhow::Result<i32> {
    handle_ledger_reconcile_to(args, &mut std::io::stdout())
}

/// The testable core of `handle_ledger_reconcile`: writes the report to
/// `out` instead of stdout, so tests can assert on it without capturing
/// the process's real stdout.
fn handle_ledger_reconcile_to(
    args: &LedgerReconcileArgs,
    out: &mut impl std::io::Write,
) -> anyhow::Result<i32> {
    const MAX_PROVIDER_EXPORT_BYTES: usize = 32 * 1024 * 1024;
    const CAVEAT: &str = "This only proves bypass for usage visible to the provider org and \
API key that produced this export: a different org, project, or key would not appear here at \
all. Clock-window edges (the export's bucket boundary vs. the ledger's recorded_at) and \
key/org attribution differences can also put a row on one side only; treat a ledger-only row \
as a lead, not proof.";

    let verifying_key = match args.signing_seed_hex.as_deref() {
        Some(seed) => Some(sbproxy_ai::usage_ledger::verifying_key_from_seed_hex(seed)?),
        None => None,
    };

    // Reconciling an unverified chain would let a tampered ledger explain
    // away real bypass evidence (or manufacture fake evidence), so this
    // refuses to proceed on a broken chain rather than comparing against
    // content nothing has confirmed is intact.
    let verify_result =
        sbproxy_ai::usage_ledger::verify_ledger(&args.path, verifying_key.as_ref())?;
    if !verify_result.ok {
        anyhow::bail!(
            "usage ledger {} does not verify at seq {}: {} (run `sbproxy ai ledger verify` for details; refusing to reconcile against an unverified chain)",
            args.path.display(),
            verify_result
                .broken_seq
                .map(|s| s.to_string())
                .unwrap_or_default(),
            verify_result.reason.as_deref().unwrap_or("unknown"),
        );
    }

    let ledger_entries = sbproxy_ai::usage_ledger::read_ledger_entries(&args.path)?;
    let export_bytes = read_bounded_cli_file(
        &args.provider_export,
        MAX_PROVIDER_EXPORT_BYTES,
        "provider usage export",
    )?;
    let (format_label, provider_rows) = match args.format {
        ProviderExportFormatArg::OpenaiUsage => (
            "openai-usage",
            sbproxy_ai::usage_ledger::parse_openai_usage_export(&export_bytes)?,
        ),
    };

    let report = sbproxy_ai::usage_ledger::reconcile_usage(&ledger_entries, &provider_rows);
    let bypass_requests_total = report.total_unseen_by_ledger();
    let bypass_rows: Vec<_> = report.bypass_rows().collect();
    let ledger_only_rows: Vec<_> = report
        .rows
        .iter()
        .filter(|r| r.unseen_by_provider() > 0)
        .collect();
    let signature_checked = verifying_key.is_some();

    match args.output {
        OutputFormat::Json => {
            let obj = serde_json::json!({
                "path": args.path.to_string_lossy(),
                "provider_export": args.provider_export.to_string_lossy(),
                "format": format_label,
                "chain_signature_checked": signature_checked,
                "rows_compared": report.rows.len(),
                "bypass_requests_total": bypass_requests_total,
                "bypass_rows": bypass_rows,
                "ledger_only_rows": ledger_only_rows,
                "strict": args.strict,
                "caveat": CAVEAT,
            });
            writeln!(out, "{}", serde_json::to_string(&obj)?)?;
        }
        OutputFormat::Text => {
            writeln!(
                out,
                "usage ledger reconcile: {} vs {} ({format_label})",
                args.path.display(),
                args.provider_export.display(),
            )?;
            writeln!(
                out,
                "chain: verified ({})",
                if signature_checked {
                    "chain + signatures"
                } else {
                    "chain only, no signing seed given"
                },
            )?;
            writeln!(out, "rows compared: {}", report.rows.len())?;
            writeln!(out)?;
            if bypass_rows.is_empty() {
                writeln!(out, "bypass evidence: none found for the rows compared.")?;
            } else {
                writeln!(
                    out,
                    "bypass evidence (provider export shows usage the ledger never recorded):"
                )?;
                for row in &bypass_rows {
                    writeln!(
                        out,
                        "  {:<10} {:<24} {} request(s) unseen by the ledger ({} token(s))",
                        row.day,
                        row.model,
                        row.unseen_by_ledger(),
                        row.provider_total_tokens,
                    )?;
                }
                writeln!(
                    out,
                    "  total: {bypass_requests_total} request(s) unseen by the ledger"
                )?;
            }
            writeln!(out)?;
            if ledger_only_rows.is_empty() {
                writeln!(out, "ledger-only: none.")?;
            } else {
                writeln!(
                    out,
                    "ledger-only (the ledger recorded usage this export does not show):"
                )?;
                for row in &ledger_only_rows {
                    writeln!(
                        out,
                        "  {:<10} {:<24} {} request(s) unseen by the export",
                        row.day,
                        row.model,
                        row.unseen_by_provider(),
                    )?;
                }
            }
            writeln!(out)?;
            writeln!(out, "{CAVEAT}")?;
        }
    }

    let exit = if args.strict && bypass_requests_total > 0 {
        1
    } else {
        0
    };
    Ok(exit)
}

/// Format micro-USD as a decimal dollar string with at least two and at
/// most six fractional digits, trailing zeros beyond the second decimal
/// trimmed: `10_500` renders `0.0105`, `1_500_000` renders `1.50`.
///
/// Mirrors `format_micros_trimmed` in `sbproxy-modules`' ai_crawl money
/// type, the workspace's micros-to-decimal convention. That helper is
/// private to its crate and pulling it out for one caller is not a clean
/// seam, so the convention is mirrored here instead.
fn usd_from_micros(micros: u64) -> String {
    let full = format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000);
    let trimmed = full.trim_end_matches('0');
    let trimmed = trimmed.trim_end_matches('.');
    match trimmed.split_once('.') {
        Some((int_part, frac)) if frac.len() >= 2 => format!("{int_part}.{frac}"),
        Some((int_part, frac)) => format!("{int_part}.{frac:0<2}"),
        None => format!("{trimmed}.00"),
    }
}

fn handle_admin_subcommand(
    cmd: &AdminCliCmd,
    global_config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    match &cmd.sub {
        AdminSub::HashPassword(args) => handle_admin_hash_password(args, global_config_path),
    }
}

/// `sbproxy admin hash-password`: print the `password_hash` value to paste
/// into `proxy.admin.operators[].password_hash`.
///
/// Resolves the pepper the same way the running server does: from
/// `key_management.crypto.pepper` in `-f/--config` when set, else the
/// fixed default, so the printed hash verifies against a server booted
/// from the same config.
fn handle_admin_hash_password(
    args: &HashPasswordArgs,
    global_config_path: Option<&std::path::Path>,
) -> anyhow::Result<i32> {
    handle_admin_hash_password_to(args, global_config_path, &mut std::io::stdout())
}

/// The testable core of `handle_admin_hash_password`: writes the hash to
/// `out` instead of stdout, so tests can assert on it without capturing the
/// process's real stdout.
fn handle_admin_hash_password_to(
    args: &HashPasswordArgs,
    global_config_path: Option<&std::path::Path>,
    out: &mut impl std::io::Write,
) -> anyhow::Result<i32> {
    let password = match (args.password.as_deref(), args.password_stdin) {
        (Some(_), true) => {
            anyhow::bail!("pass either --password or --password-stdin, not both")
        }
        (Some(p), false) => p.to_string(),
        (None, true) => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {e}"))?;
            line.trim_end_matches(['\n', '\r']).to_string()
        }
        (None, false) => anyhow::bail!(
            "missing password\n\nusage: sbproxy admin hash-password --password-stdin\n   or: sbproxy admin hash-password --password <value>"
        ),
    };

    let key_management = global_config_path
        .map(|path| -> anyhow::Result<_> {
            let yaml = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read config '{}': {e}", path.display()))?;
            let compiled = sbproxy_config::compile_config(&yaml)
                .map_err(|e| anyhow::anyhow!("config did not compile: {e:#}"))?;
            Ok(compiled.server.key_management)
        })
        .transpose()?
        .flatten();
    let pepper = sbproxy_core::key_plane::resolve_admin_operator_pepper(key_management.as_ref())
        .map_err(|e| anyhow::anyhow!("resolve admin operator pepper: {e}"))?;
    writeln!(
        out,
        "{}",
        sbproxy_core::key_plane::hash_admin_operator_password(&password, &pepper)
    )?;
    Ok(0)
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
    load_and_validate_with(path, false)
}

/// [`load_and_validate`] with control over whether a `source:` block is
/// resolved.
///
/// `plan` exposes the choice as `--no-fetch`; `apply` always resolves,
/// because the document it is about to push is the resolved one.
fn load_and_validate_with(
    path: &std::path::Path,
    no_fetch: bool,
) -> anyhow::Result<(sbproxy_config::ConfigFile, Option<String>)> {
    let path_str = path.to_string_lossy();
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path_str}': {e}"))?;
    // Diff and validate the document that would boot, not the pointer at
    // it. Both sides of a plan go through here, so an `--against`
    // baseline that is itself git-sourced resolves too.
    let yaml = resolve_source_for_cli(&yaml, no_fetch, &path_str)?;
    let compiled = sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path_str}' did not compile:\n{e:#}"))?;
    // WOR-1815: run the boot-time module constructors too, so `plan`
    // and `apply` catch a config that compiles but cannot boot. The
    // error is returned as data rather than an abort so the callers
    // can fold it into their findings report: `plan` renders it next
    // to the other semantic findings and exits 3, the same channel
    // the validate-rule findings use.
    let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let construction_error =
        sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
            compiled, config_dir,
        )
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
    let (proposed, construction_error) = load_and_validate_with(config, args.no_fetch)?;
    // The baseline is the operator's current state; only the proposed
    // side's construction result gates the plan.
    let baseline = match args.against.as_deref() {
        Some(p) => load_and_validate_with(p, args.no_fetch)?.0,
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
    if let Some(host) = args.explain_origin.as_deref() {
        return handle_plan_explain_origin(args, host);
    }
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

/// `sbproxy plan --explain-origin <host>`: why is this policy here.
///
/// The question a security engineer has when an origin is the product of
/// four layers and two repositories, answered on the same verb they
/// already reach for to ask what a config change would do. It composes
/// exactly as the aggregator does, through the same
/// [`sbproxy_core::config_aggregator::Aggregator`], so what this prints
/// and what a publish records cannot disagree.
///
/// Exit 0 when the host composed, 3 when it did not, and the refusal
/// names every host this composition did produce.
fn handle_plan_explain_origin(args: &PlanArgs, host: &str) -> anyhow::Result<i32> {
    if args.no_fetch {
        anyhow::bail!(
            "--explain-origin composes the project repositories `origin_sources:` names, which \
             --no-fetch forbids. Drop --no-fetch, or compose on a host that can reach them with \
             `sbproxy aggregate --out`"
        );
    }
    let path = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config"))?;
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", path.display()))?;
    let mut aggregator = sbproxy_core::config_aggregator::Aggregator::from_document(&text)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    aggregator
        .resolve_credentials()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let composed = match aggregator.compose() {
        Ok(composed) => composed,
        Err(error) => {
            eprintln!("plan: {error}");
            return Ok(3);
        }
    };
    let Some(provenance) = composed.provenance.get(host) else {
        let known: Vec<&str> = composed.provenance.keys().map(String::as_str).collect();
        eprintln!(
            "plan: nothing composed for '{host}'. This composition produced: {}",
            if known.is_empty() {
                "(no hosts)".to_string()
            } else {
                known.join(", ")
            }
        );
        return Ok(3);
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&cli_command_envelope(
                "plan.explain-origin",
                serde_json::json!({ "host": host, "provenance": provenance }),
            ))?
        ),
        OutputFormat::Text => print!("{}", provenance.render(host)),
    }
    Ok(0)
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
/// YAML, runs plan-time semantic validation, then pushes the config to a
/// running proxy over the admin API and reports what the server did with
/// it. Refuses to apply when any `Severity::Error` finding is present.
///
/// Exit codes: 0 applied, 3 validation refused, 4 the proxy refused it,
/// 6 another apply holds the lock, 7 no proxy reachable, 8 applied but
/// degraded.
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
/// Default admin endpoint, matching `AdminConfig`'s own defaults.
const DEFAULT_ADMIN_URL: &str = "http://127.0.0.1:9090";

/// Push `yaml` to a running proxy over the admin API and report what the
/// server did with it.
///
/// This is the whole point of `apply`. It used to call the in-process
/// reload, which compiled the config into the short-lived CLI process,
/// swapped that process's own pipeline, printed success, and exited
/// without ever contacting the proxy. A running server picked the change
/// up only if its file watcher happened to notice the file, so the exit
/// code said nothing about whether the config was accepted or even seen.
///
/// `PUT /admin/config` is used rather than `POST /admin/reload` because
/// apply is given a file, not a promise that the file is the one the
/// proxy booted with. The server validates, persists, and swaps.
fn apply_to_running_proxy(args: &ApplyArgs, yaml: &str) -> anyhow::Result<i32> {
    use zeroize::Zeroize;

    let base_url = args.admin_url.as_deref().unwrap_or(DEFAULT_ADMIN_URL);
    let username = args.username.as_deref().unwrap_or("admin");
    let mut password = args.password.clone().unwrap_or_default();

    let url = format!("{}/admin/config", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let request = client
        .put(&url)
        .basic_auth(username, Some(password.as_str()))
        .header(reqwest::header::CONTENT_TYPE, "application/yaml")
        .body(yaml.to_string())
        .build();
    password.zeroize();

    let response = match client.execute(request?) {
        Ok(response) => response,
        Err(error) => {
            // Never fall back to something local that looks like success.
            eprintln!(
                "apply: could not reach the admin API at {base_url}: {error}\n\
                 apply: nothing was applied. Point --admin-url at the running \
                 proxy, or pass --validate-only to check the config without \
                 applying it."
            );
            return Ok(7);
        }
    };

    let status = response.status();
    let body: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let reason = body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("admin request failed");
        eprintln!("apply: the proxy refused the config (HTTP {status}): {reason}");
        return Ok(4);
    }

    let revision = body
        .get("config_revision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    // `fully_applied` is absent on older proxies; absence is not failure.
    let fully_applied = body
        .get("fully_applied")
        .and_then(serde_json::Value::as_bool);
    let degraded: Vec<&str> = body
        .get("degraded")
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();

    if fully_applied == Some(false) || !degraded.is_empty() {
        let named = if degraded.is_empty() {
            "one or more subsystems".to_string()
        } else {
            degraded.join(", ")
        };
        println!("apply: applied to {base_url}, config revision {revision}");
        eprintln!(
            "apply: warning: the config loaded but {named} did not take effect and \
             kept stale state. The proxy is serving the new config otherwise."
        );
        return Ok(8);
    }

    println!("apply: applied to {base_url}, config revision {revision}");
    Ok(0)
}

fn handle_apply_subcommand(args: &ApplyArgs) -> anyhow::Result<i32> {
    if let Some(plan_path) = args.plan_file.as_deref() {
        return handle_apply_from_plan_file(args, plan_path);
    }
    let yaml_path = args
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing -f / --config or -p / --plan"))?;
    handle_apply_from_yaml(args, yaml_path)
}

/// `apply -f <yaml>` flow. Acquires the apply-lock, validates, and
/// pushes the config to a running proxy over the admin API. Refuses on
/// validation errors (exit 3) or lock contention (exit 6).
fn handle_apply_from_yaml(args: &ApplyArgs, yaml_path: &std::path::Path) -> anyhow::Result<i32> {
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
    if args.validate_only {
        println!("apply: {yaml_path_str} is valid. Nothing was applied (--validate-only).");
        return Ok(0);
    }
    let yaml = std::fs::read_to_string(yaml_path)
        .map_err(|e| anyhow::anyhow!("read {yaml_path_str}: {e}"))?;
    apply_to_running_proxy(args, &yaml)
}

/// `apply -p <plan-file>` flow. Reads the plan-file, locates the
/// proposed YAML by reading the path the operator supplied via the
/// `SB_APPLY_CONFIG` env var, recomputes the plan, and rejects with
/// exit 5 if the baseline_revision drifted.
fn handle_apply_from_plan_file(
    args: &ApplyArgs,
    plan_path: &std::path::Path,
) -> anyhow::Result<i32> {
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

    if args.validate_only {
        println!(
            "apply: {yaml_path} is valid (via plan-file {plan_path_str}). \
             Nothing was applied (--validate-only)."
        );
        return Ok(0);
    }
    let yaml = std::fs::read_to_string(&yaml_path)
        .map_err(|e| anyhow::anyhow!("read {yaml_path}: {e}"))?;
    println!("apply: applying {yaml_path} (via plan-file {plan_path_str})");
    apply_to_running_proxy(args, &yaml)
}

#[cfg(test)]
mod test_env;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvVarGuard;

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

    /// A unique scratch path for the value-ledger report tests. Mirrors
    /// `temp_config`'s pid-plus-counter convention rather than adding a
    /// dev-dependency this crate does not otherwise carry.
    fn temp_value_ledger_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sbproxy-ledger-report-{tag}-{}-{n}.redb",
            std::process::id()
        ))
    }

    fn ledger_report_output(path: &std::path::Path, format: OutputFormat) -> (i32, String) {
        let args = LedgerReportArgs {
            path: path.to_path_buf(),
            format,
        };
        let mut out = Vec::new();
        let code = handle_ledger_report_to(&args, &mut out).expect("report runs");
        (code, String::from_utf8(out).expect("utf-8 output"))
    }

    #[test]
    fn ai_ledger_report_cli_surface_parses_path_and_format() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "ai",
            "ledger",
            "report",
            "value-ledger.redb",
            "--format",
            "json",
        ])
        .unwrap();
        let Some(Cmd::Ai(cmd)) = cli.cmd else {
            panic!("ai ledger report parsed to the wrong command");
        };
        let AiSub::Ledger(LedgerCmd {
            sub: LedgerSub::Report(args),
        }) = cmd.sub
        else {
            panic!("ai ledger report parsed to the wrong command");
        };
        assert_eq!(args.path, PathBuf::from("value-ledger.redb"));
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn ledger_report_aggregates_lanes_like_the_admin_route() {
        let path = temp_value_ledger_path("lanes");
        let price = sbproxy_model_host::CloudPrice {
            prompt_micros_per_mtok: 3_000_000,
            completion_micros_per_mtok: 15_000_000,
        };
        {
            let ledger = sbproxy_ai::value_ledger::ValueLedger::open(&path).expect("open ledger");
            ledger.record_local("qwen", 1000, 500, price); // saves 10_500
            ledger.record_local("qwen", 1000, 500, price); // saves 10_500
            ledger.record_cloud("qwen", 1000, 500, price); // spends 10_500
            ledger.record_compression(
                "gpt-4o-mini",
                sbproxy_ai::compression::LeverKind::WindowFit,
                500,
                75,
                sbproxy_model_host::TokenCountPrecision::ModelTokenizer,
            );
        }

        let (code, json_out) = ledger_report_output(&path, OutputFormat::Json);
        assert_eq!(code, 0);
        let report: serde_json::Value = serde_json::from_str(&json_out).expect("report json");
        // The same keys the admin value route serves, raw micros included.
        // models[0] is the compression target's zeroed lane (BTreeMap order).
        let qwen = &report["models"][1];
        assert_eq!(qwen["model"], "qwen");
        assert_eq!(qwen["local_completions"], 2);
        assert_eq!(qwen["cloud_completions"], 1);
        assert_eq!(qwen["saved_micros"], 21_000);
        assert_eq!(qwen["cloud_spent_micros"], 10_500);
        assert_eq!(report["total_saved_micros"], 21_000);
        assert_eq!(report["total_cloud_spent_micros"], 10_500);
        assert_eq!(report["compression"][0]["model"], "gpt-4o-mini");
        assert_eq!(report["compression"][0]["lever"], "window_fit");
        assert_eq!(report["compression"][0]["tokens_saved"], 500);
        assert_eq!(report["compression"][0]["gross_cost_saved_micros"], 75);
        assert_eq!(report["total_compression_tokens_saved"], 500);

        let (code, text) = ledger_report_output(&path, OutputFormat::Text);
        assert_eq!(code, 0);
        assert!(text.contains("qwen"), "text report names the model: {text}");
        assert!(
            text.contains("0.021") && text.contains("0.0105"),
            "micros render as trimmed decimal dollars: {text}"
        );
        assert!(
            text.contains("0.000075"),
            "sub-cent compression value keeps its micros precision: {text}"
        );
        assert!(
            text.contains("model_tokenizer"),
            "precision column carries the token-count signal: {text}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_report_missing_or_empty_ledger_is_a_clean_zero() {
        // Missing file: the normal state before any value is recorded.
        let missing = temp_value_ledger_path("missing");
        let (code, text) = ledger_report_output(&missing, OutputFormat::Text);
        assert_eq!(code, 0, "a missing value ledger is not an error");
        assert!(text.contains("no value recorded yet"), "text: {text}");
        assert!(
            !missing.exists(),
            "reporting must not create the database it reports on"
        );

        let (code, json_out) = ledger_report_output(&missing, OutputFormat::Json);
        assert_eq!(code, 0);
        let report: serde_json::Value = serde_json::from_str(&json_out).expect("report json");
        assert_eq!(report["models"], serde_json::json!([]));
        assert_eq!(report["total_saved_micros"], 0);

        // An existing ledger with no recorded lanes reads the same way.
        let empty = temp_value_ledger_path("empty");
        drop(sbproxy_ai::value_ledger::ValueLedger::open(&empty).expect("create empty ledger"));
        let (code, text) = ledger_report_output(&empty, OutputFormat::Text);
        assert_eq!(code, 0);
        assert!(text.contains("no value recorded yet"), "text: {text}");
        let _ = std::fs::remove_file(&empty);
    }

    /// A unique scratch path for the usage-ledger reconcile tests.
    /// Mirrors `temp_value_ledger_path`'s pid-plus-counter convention.
    fn temp_jsonl_ledger_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sbproxy-ledger-reconcile-{tag}-{}-{n}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn ai_ledger_reconcile_cli_surface_parses_flags() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "ai",
            "ledger",
            "reconcile",
            "usage-ledger.jsonl",
            "--provider-export",
            "openai-usage-export.json",
            "--format",
            "openai-usage",
            "--strict",
            "--output",
            "json",
        ])
        .unwrap();
        let Some(Cmd::Ai(cmd)) = cli.cmd else {
            panic!("ai ledger reconcile parsed to the wrong command");
        };
        let AiSub::Ledger(LedgerCmd {
            sub: LedgerSub::Reconcile(args),
        }) = cmd.sub
        else {
            panic!("ai ledger reconcile parsed to the wrong command");
        };
        assert_eq!(args.path, PathBuf::from("usage-ledger.jsonl"));
        assert_eq!(
            args.provider_export,
            PathBuf::from("openai-usage-export.json")
        );
        assert!(matches!(args.format, ProviderExportFormatArg::OpenaiUsage));
        assert!(args.strict);
        assert!(matches!(args.output, OutputFormat::Json));
    }

    /// Red-first proof for WOR-2476: an empty local ledger (nothing the
    /// gateway ever metered) reconciled against the checked-in OpenAI
    /// usage export fixture (`crates/sbproxy-ai/tests/fixtures/openai-usage-export.json`)
    /// must flag every row in that fixture as bypass evidence, because an
    /// empty ledger has no matching request for any of them, and
    /// `--strict` must turn that into a nonzero exit.
    #[test]
    fn ai_ledger_reconcile_flags_an_injected_provider_only_row_and_strict_exits_nonzero() {
        let ledger_path = temp_jsonl_ledger_path("bypass");
        let _ = std::fs::remove_file(&ledger_path);
        // A 0-byte file is a trivially valid (empty) hash chain: both
        // `verify_ledger` and `read_ledger_entries` parse zero lines and
        // succeed. Written directly with a plain filesystem call, not
        // through the ledger-opening constructor this crate's usage-sink
        // wiring uses in production, so this test does not become that
        // constructor's first cross-crate caller.
        std::fs::write(&ledger_path, b"").expect("create empty ledger file");

        let export_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("sbproxy-ai")
            .join("tests")
            .join("fixtures")
            .join("openai-usage-export.json");
        assert!(
            export_path.exists(),
            "fixture must exist at {}",
            export_path.display()
        );

        let args = LedgerReconcileArgs {
            path: ledger_path.clone(),
            provider_export: export_path,
            format: ProviderExportFormatArg::OpenaiUsage,
            signing_seed_hex: None,
            strict: false,
            output: OutputFormat::Json,
        };
        let mut out = Vec::new();
        let code = handle_ledger_reconcile_to(&args, &mut out).expect("reconcile runs");
        assert_eq!(
            code, 0,
            "without --strict the command reports but does not fail the run"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&out).expect("reconcile json output");
        let bypass_total = report["bypass_requests_total"]
            .as_u64()
            .expect("bypass_requests_total is a number");
        assert_eq!(
            bypass_total, 320,
            "every request in the fixture (210 + 47 + 63) is unseen by an empty ledger: {report}"
        );
        assert_eq!(report["rows_compared"], 3);

        let strict_args = LedgerReconcileArgs {
            strict: true,
            ..args
        };
        let mut strict_out = Vec::new();
        let strict_code =
            handle_ledger_reconcile_to(&strict_args, &mut strict_out).expect("reconcile runs");
        assert_eq!(
            strict_code, 1,
            "an injected provider-side-only row must fail a --strict run"
        );

        let _ = std::fs::remove_file(&ledger_path);
    }

    #[test]
    fn usd_from_micros_trims_to_the_workspace_money_convention() {
        assert_eq!(usd_from_micros(0), "0.00");
        assert_eq!(usd_from_micros(10_000), "0.01");
        assert_eq!(usd_from_micros(10_500), "0.0105");
        assert_eq!(usd_from_micros(75), "0.000075");
        assert_eq!(usd_from_micros(1_500_000), "1.50");
        assert_eq!(usd_from_micros(2_000_000), "2.00");
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
    fn doctor_extension_inventory_uses_candidate_attachment_scope() {
        let directory = temp_env_path("doctor-extension-inventory");
        let _ = std::fs::remove_dir_all(&directory);
        let bundle = directory.join("bundles").join("doctor-lifecycle");
        std::fs::create_dir_all(&bundle).expect("create doctor lifecycle bundle");
        std::fs::write(
            bundle.join("entry.js"),
            r#"export function inspect() {
                return { version: "sbproxy-envelope/v1", decision: "continue" };
            }
            export function enforce() {
                return { version: "sbproxy-envelope/v1", decision: "allow" };
            }
"#,
        )
        .expect("write doctor lifecycle artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: doctor-lifecycle
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: doctor_guardrail
    export: inspect
  - kind: policy
    type: doctor_unattached_policy
    export: enforce
"#,
        )
        .expect("write doctor lifecycle manifest");
        let report = with_doctor_extension_inventory(
            sbproxy_core::doctor::DoctorReport::collect(),
            "proxy: {}\nextensions:\n  bundles_dir: bundles\n",
            &directory,
        );

        assert_eq!(
            report.extensions.scope.mode,
            sbproxy_plugin::ExtensionScopeMode::Doctor
        );
        assert_eq!(
            report
                .extensions
                .hooks
                .iter()
                .find(|hook| hook.kind == sbproxy_plugin::ExtensionHookKind::AiGuardrailInput)
                .map(|hook| (hook.id.as_str(), hook.state)),
            Some((
                "doctor-lifecycle:ai_guardrail_input:doctor_guardrail",
                sbproxy_plugin::ExtensionState::Active,
            ))
        );
        assert_eq!(
            report
                .extensions
                .hooks
                .iter()
                .find(|hook| hook.kind == sbproxy_plugin::ExtensionHookKind::Policy)
                .map(|hook| hook.state),
            Some(sbproxy_plugin::ExtensionState::Unconsumed)
        );
        std::fs::remove_dir_all(directory).expect("remove doctor lifecycle fixture");
    }

    #[test]
    fn control_plane_demand_reads_the_canonical_model_host_block() {
        // Regression: the strict gate originally only saw the inline
        // provider-level `serve:` form, so a `proxy.model_host` worker
        // config reported six skips and a pass on a host with no GPU.
        let config = "proxy:\n  model_host:\n    cache:\n      budget_gib: 40\n    engines:\n      vllm:\n        launch: container\n        image: vllm/vllm-openai:v0.10.0\n        shm_size_gib: 8\n";
        let (demand, budget) =
            extract_control_plane_demand(config).expect("proxy.model_host parses");

        assert!(demand.requires_cuda, "a vLLM engine is a CUDA demand");
        assert_eq!(demand.cuda_engines, vec!["proxy.model_host.engines.vllm"]);
        assert_eq!(demand.required_shm_bytes, Some(8 * 1024 * 1024 * 1024));
        assert_eq!(budget, Some(40.0));
    }

    #[test]
    fn control_plane_demand_is_absent_without_the_block() {
        let config = "origins:\n  api.local:\n    upstream: https://test.sbproxy.dev\n";
        assert!(extract_control_plane_demand(config).is_none());
    }

    #[test]
    fn control_plane_demand_treats_portable_llama_cpp_as_no_cuda_demand() {
        // llama.cpp runs on Metal and CPU, so only an explicit
        // `acceleration: cuda` makes it a CUDA demand.
        let portable = "proxy:\n  model_host:\n    engines:\n      llama_cpp:\n        launch: binary\n        version: b9905\n        acceleration: auto\n";
        let (demand, _) = extract_control_plane_demand(portable).expect("parses");
        assert!(
            !demand.requires_cuda,
            "auto acceleration is not a CUDA demand"
        );

        let pinned = "proxy:\n  model_host:\n    engines:\n      llama_cpp:\n        launch: binary\n        acceleration: cuda\n";
        let (demand, _) = extract_control_plane_demand(pinned).expect("parses");
        assert!(demand.requires_cuda);
    }

    #[test]
    fn model_plane_identity_is_absent_without_a_cluster_block() {
        // A single-box config has no model plane, and the strict gate has
        // to be able to report that rather than inventing a failure.
        let config =
            "origins:\n  ai.local:\n    action:\n      providers:\n        - name: local\n";
        assert!(
            extract_model_plane_identity(config, std::path::Path::new(".")).is_none(),
            "no proxy.cluster block means no model-plane identity to check"
        );
    }

    #[test]
    fn model_plane_identity_lists_mtls_files_and_missing_keys() {
        let config = "proxy:\n  cluster:\n    cluster_id: fleet\n    roles: [worker]\n    security:\n      mode: mtls\n      cert_file: tls/worker.crt\n      key_file: /abs/worker.key\n";
        let plane = extract_model_plane_identity(config, std::path::Path::new("/etc/sbproxy"))
            .expect("cluster block parses");

        assert!(plane.worker_role, "roles: [worker] is the worker role");
        assert!(plane.mtls);
        // A relative path resolves against the config's own directory,
        // matching how the proxy loads it.
        assert_eq!(
            plane.files[0].1,
            std::path::Path::new("/etc/sbproxy/tls/worker.crt")
        );
        // An absolute path is left alone.
        assert_eq!(plane.files[1].1, std::path::Path::new("/abs/worker.key"));
        // mTLS makes the unset CA a violation, not a shrug.
        assert_eq!(plane.missing_keys, vec!["ca_file"]);
        assert_eq!(plane.shared_key_present, None);
    }

    #[test]
    fn model_plane_identity_flags_shared_key_mode_with_no_key() {
        let missing = "proxy:\n  cluster:\n    cluster_id: fleet\n    roles: [gateway]\n    security:\n      mode: shared_key\n";
        let plane = extract_model_plane_identity(missing, std::path::Path::new("."))
            .expect("cluster block parses");
        assert!(!plane.worker_role);
        assert!(!plane.mtls);
        assert_eq!(plane.shared_key_present, Some(false));
        // Shared-key mode does not owe the three mTLS files.
        assert!(plane.missing_keys.is_empty());

        let present = "proxy:\n  cluster:\n    cluster_id: fleet\n    security:\n      mode: shared_key\n      shared_key: env:SB_MESH_KEY\n";
        let plane = extract_model_plane_identity(present, std::path::Path::new("."))
            .expect("cluster block parses");
        assert_eq!(plane.shared_key_present, Some(true));
    }

    #[test]
    fn strict_text_block_names_every_check_and_the_verdict() {
        use sbproxy_core::doctor::StrictCheck;
        let text = render_strict_checks_text(&[
            StrictCheck {
                check: "driver",
                status: "pass",
                detail: "NVIDIA driver 550.54.15 present".to_string(),
            },
            StrictCheck {
                check: "cache_mount",
                status: "fail",
                detail: "not enough space".to_string(),
            },
        ]);
        assert!(text.contains("startup gate"));
        assert!(text.contains("driver"));
        assert!(text.contains("cache_mount"));
        assert!(
            text.contains("verdict: FAIL (1 startup blocker)"),
            "the verdict line is what an operator reads first: {text}"
        );
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
    fn service_install_cli_surface_flattens_run_args() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "service",
            "install",
            "qwen3-14b",
            "--port",
            "9000",
            "--format",
            "json",
        ])
        .unwrap();
        let Some(Cmd::Service(ServiceCmd {
            sub: ServiceSub::Install(args),
        })) = cli.cmd
        else {
            panic!("service install parsed to the wrong command");
        };
        assert_eq!(args.run.model, "qwen3-14b");
        assert_eq!(args.run.port, 9000);
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn service_install_reuses_run_config_generation() {
        // `service install` flattens `RunArgs` and calls the exact same
        // `prepare_run` as `sbproxy run`, so the launchd-installed
        // service gets the same loopback-bind, admin-enabled, random-
        // password config as a foreground `run`.
        let args = ServiceInstallArgs {
            run: RunArgs {
                model: "qwen2.5-0.5b-instruct".to_string(),
                name: Some("service-test".to_string()),
                port: 8080,
                engine: "auto".to_string(),
                accel: "auto".to_string(),
                cache_dir: None,
                variant: Some("q4_k_m".to_string()),
                admin_port: Some(9092),
                dry_run: false,
            },
            format: OutputFormat::Text,
        };
        let prepared = prepare_run(&args.run).expect("prepare canonical service config");
        let yaml: serde_yaml::Value = serde_yaml::from_str(&prepared.yaml).unwrap();
        assert_eq!(prepared.name, "service-test");
        assert_eq!(yaml["proxy"]["admin"]["enabled"], true);
        assert_eq!(yaml["proxy"]["admin"]["bind"], "127.0.0.1");
        assert_eq!(yaml["proxy"]["admin"]["port"], 9092);
        // WOR-2199: the public listener gets the same assertion the
        // admin listener already had. Before this, only the admin half
        // of "secure defaults" was pinned, and the public half was
        // hardcoded to every interface with nothing checking it.
        assert_eq!(yaml["proxy"]["bind_address"], "127.0.0.1");
        assert_eq!(prepared.admin_password.len(), 64);
        assert!(!prepared.yaml.contains("serve:"));
    }

    /// The service paths a plist test renders against, with an overridable
    /// home so the shell-quoting case can use an awkward one.
    fn service_paths_fixture(home: &str) -> ServicePaths {
        ServicePaths {
            config: PathBuf::from(format!(
                "{home}/Library/Application Support/sbproxy/service/sb.yml"
            )),
            plist: PathBuf::from(format!("{home}/Library/LaunchAgents/{SERVICE_LABEL}.plist")),
            stdout_log: PathBuf::from(format!("{home}/Library/Logs/sbproxy/service.log")),
            stderr_log: PathBuf::from(format!("{home}/Library/Logs/sbproxy/service.err.log")),
            env_file: PathBuf::from(format!(
                "{home}/Library/Application Support/sbproxy/service/env"
            )),
            uninstall_state: PathBuf::from(format!(
                "{home}/Library/Application Support/sbproxy/service/uninstall-state.json"
            )),
            lifecycle_lock: PathBuf::from(format!(
                "{home}/Library/Application Support/sbproxy/service/lifecycle.lock"
            )),
        }
    }

    #[test]
    fn service_plist_contains_program_arguments_and_bootstrap() {
        let paths = service_paths_fixture("/Users/test");
        let plist = render_service_plist(std::path::Path::new("/usr/local/bin/sbproxy"), &paths);
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>service</string>"));
        assert!(plist.contains("<string>launch</string>"));
        assert!(plist.contains("/usr/local/bin/sbproxy"));
        assert!(plist.contains(&format!("<string>{SERVICE_LABEL}</string>")));
        assert!(plist.contains("/Users/test/Library/Application Support/sbproxy/service/sb.yml"));
    }

    #[test]
    fn service_plist_bootstraps_with_the_declarative_environment_file() {
        let paths = service_paths_fixture("/Users/test");
        let plist = render_service_plist(std::path::Path::new("/usr/local/bin/sbproxy"), &paths);

        assert!(plist.contains("<string>service</string>"), "{plist}");
        assert!(plist.contains("<string>launch</string>"), "{plist}");
        assert!(plist.contains("<string>--environment</string>"), "{plist}");
        assert!(
            plist.contains("<string>--lifecycle-lock</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>--uninstall-state</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("/Users/test/Library/Application Support/sbproxy/service/env"),
            "the plist does not reference the environment file: {plist}"
        );
        assert!(
            plist
                .contains("/Users/test/Library/Application Support/sbproxy/service/lifecycle.lock"),
            "the plist does not pass the cooperative lifecycle lock: {plist}"
        );
        assert!(
            !plist.contains("/bin/sh") && !plist.contains("set -a;"),
            "launchd must not interpret the declarative environment as shell code: {plist}"
        );
    }

    #[test]
    fn service_plist_xml_escapes_a_home_directory_containing_an_apostrophe() {
        let paths = service_paths_fixture("/Users/o'brien");
        let plist = render_service_plist(std::path::Path::new("/usr/local/bin/sbproxy"), &paths);

        assert!(
            plist.contains("/Users/o&apos;brien/Library/Application Support/sbproxy/service/env"),
            "the direct ProgramArguments value must be valid XML: {plist}"
        );
        assert!(
            !plist.contains(r"\&apos;"),
            "direct ProgramArguments must not contain shell-quoting artifacts: {plist}"
        );
    }

    #[test]
    fn service_plist_gives_the_drain_longer_than_launchd_would() {
        // launchd's default ExitTimeOut (20s) is shorter than the proxy's
        // default shutdown grace (30s), so an agent still draining
        // in-flight requests at 20 seconds would be SIGKILLed part-way
        // through, skipping every destructor on the shutdown path.
        let paths = service_paths_fixture("/Users/test");
        let plist = render_service_plist(std::path::Path::new("/usr/local/bin/sbproxy"), &paths);
        assert!(
            plist.contains("<key>ExitTimeOut</key>"),
            "the plist must set ExitTimeOut or launchd kills the drain early: {plist}"
        );
        // The ordering against the default shutdown grace is a compile-time
        // assertion next to the constant itself, so it cannot drift.
        assert!(
            plist.contains(&format!("<integer>{SERVICE_EXIT_TIMEOUT_SECS}</integer>")),
            "{plist}"
        );
    }

    /// A unique scratch path for the env-file tests. Mirrors
    /// `temp_config`'s pid-plus-counter convention rather than adding a
    /// dev-dependency this crate does not otherwise carry.
    fn temp_env_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sbproxy-service-env-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    #[test]
    fn service_env_file_is_created_once_and_never_overwritten() {
        let env_file = temp_env_path("once");
        let _ = std::fs::remove_file(&env_file);

        ensure_service_env_file(&env_file).expect("create");
        let template = std::fs::read_to_string(&env_file).expect("read");
        assert!(
            template.contains("HF_TOKEN"),
            "the template must name the variable a gated model needs: {template}"
        );

        // An operator's token has to survive a reinstall that changes the
        // model or the port.
        std::fs::write(&env_file, "HF_TOKEN=hf_operator_secret\n").expect("write");
        ensure_service_env_file(&env_file).expect("second call is a no-op");
        assert_eq!(
            std::fs::read_to_string(&env_file).expect("read"),
            "HF_TOKEN=hf_operator_secret\n",
            "reinstalling must not discard the operator's environment file"
        );
        let _ = std::fs::remove_file(&env_file);
    }

    #[test]
    fn service_env_template_examples_are_valid_when_uncommented() {
        let examples = SERVICE_ENV_TEMPLATE
            .lines()
            .filter_map(|line| line.strip_prefix("# "))
            .filter(|line| {
                line.starts_with("HF_TOKEN=")
                    || line.starts_with("RUST_LOG=")
                    || line.starts_with("SBPROXY_ENGINE_OWNERSHIP_DIR=")
            })
            .collect::<Vec<_>>()
            .join("\n");

        let environment = parse_service_environment(std::path::Path::new("service-env"), &examples)
            .expect("every commented assignment should work when uncommented");

        assert_eq!(
            environment.variables.get("HF_TOKEN").map(String::as_str),
            Some("hf_...")
        );
        assert_eq!(
            environment
                .variables
                .get(SERVICE_ENGINE_OWNERSHIP_ENV)
                .map(String::as_str),
            Some("/absolute/path")
        );
    }

    #[cfg(unix)]
    #[test]
    fn service_env_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let env_file = temp_env_path("mode");
        let _ = std::fs::remove_file(&env_file);
        ensure_service_env_file(&env_file).expect("create");
        let mode = std::fs::metadata(&env_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the documented home for a Hugging Face token must not be group or world readable"
        );
        let _ = std::fs::remove_file(&env_file);
    }

    #[test]
    fn launchctl_list_pid_parses_running_and_missing() {
        let running = "{\n\t\"LimitLoadToSessionType\" = \"Aqua\";\n\t\"Label\" = \"dev.sbproxy.agent\";\n\t\"OnDemand\" = false;\n\t\"LastExitStatus\" = 0;\n\t\"PID\" = 4321;\n};\n";
        assert_eq!(parse_launchctl_list_pid(running), Some(4321));
        let loaded_not_running =
            "{\n\t\"Label\" = \"dev.sbproxy.agent\";\n\t\"LastExitStatus\" = 0;\n};\n";
        assert_eq!(parse_launchctl_list_pid(loaded_not_running), None);
    }

    #[test]
    fn launchctl_list_classifies_only_known_missing_service_as_not_loaded() {
        let status = classify_launchctl_list_status(
            false,
            Some(113),
            "",
            "Could not find service \"dev.sbproxy.agent\" in domain for user gui: 501",
        )
        .expect("known launchd absence");

        assert_eq!(status, LaunchdJobStatus::NotLoaded);
    }

    #[test]
    fn launchctl_list_propagates_real_status_errors() {
        let error = classify_launchctl_list_status(
            false,
            Some(1),
            "",
            "Operation not permitted while contacting launchd",
        )
        .expect_err("permission errors must not look like an absent service");

        let message = error.to_string();
        assert!(message.contains("exit code 1"), "{message}");
        assert!(message.contains("Operation not permitted"), "{message}");
    }

    fn service_temp_paths(tag: &str) -> ServicePaths {
        let root = temp_env_path(tag);
        let service = root.join("service");
        std::fs::create_dir_all(&service).unwrap();
        ServicePaths {
            config: service.join("sb.yml"),
            plist: root.join("dev.sbproxy.agent.plist"),
            stdout_log: root.join("service.log"),
            stderr_log: root.join("service.err.log"),
            env_file: service.join("env"),
            uninstall_state: service.join("uninstall-state.json"),
            lifecycle_lock: service.join("lifecycle.lock"),
        }
    }

    fn write_registered_service_plist(paths: &ServicePaths) {
        std::fs::write(
            &paths.plist,
            render_service_plist(std::path::Path::new("/usr/local/bin/sbproxy"), paths),
        )
        .unwrap();
    }

    struct FakeLaunchd {
        statuses: std::collections::VecDeque<LaunchdJobStatus>,
        unload_fails: bool,
        unload_calls: usize,
    }

    impl LaunchdController for FakeLaunchd {
        fn status(&mut self) -> anyhow::Result<LaunchdJobStatus> {
            self.statuses
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("unexpected fake launchd status call"))
        }

        fn unload(&mut self, _plist: &std::path::Path) -> anyhow::Result<()> {
            self.unload_calls += 1;
            if self.unload_fails {
                anyhow::bail!("injected launchctl unload failure");
            }
            Ok(())
        }
    }

    struct FakeServiceEngineCleanup {
        owner: sbproxy_model_host::ManagedEngineOwner,
        owners_by_pid: std::collections::HashMap<u32, sbproxy_model_host::ManagedEngineOwner>,
        fail_reap: bool,
        capture_calls: usize,
        captured_pids: Vec<u32>,
        reaped_directories: Vec<PathBuf>,
        reaped_owners: Vec<sbproxy_model_host::ManagedEngineOwner>,
    }

    impl ServiceEngineCleanup for FakeServiceEngineCleanup {
        fn capture_owner(
            &mut self,
            pid: u32,
        ) -> anyhow::Result<sbproxy_model_host::ManagedEngineOwner> {
            self.capture_calls += 1;
            self.captured_pids.push(pid);
            Ok(self.owners_by_pid.get(&pid).unwrap_or(&self.owner).clone())
        }

        fn reap_owner(
            &mut self,
            directory: &std::path::Path,
            owner: &sbproxy_model_host::ManagedEngineOwner,
        ) -> anyhow::Result<usize> {
            self.reaped_directories.push(directory.to_path_buf());
            self.reaped_owners.push(owner.clone());
            if self.fail_reap {
                anyhow::bail!("injected exact-owner reap failure");
            }
            Ok(1)
        }
    }

    fn fake_service_cleanup(fail_reap: bool) -> FakeServiceEngineCleanup {
        FakeServiceEngineCleanup {
            owner: sbproxy_model_host::capture_managed_engine_owner(std::process::id())
                .expect("capture test process identity"),
            owners_by_pid: std::collections::HashMap::new(),
            fail_reap,
            capture_calls: 0,
            captured_pids: Vec::new(),
            reaped_directories: Vec::new(),
            reaped_owners: Vec::new(),
        }
    }

    fn fake_managed_engine_owner(
        pid: u32,
        start_fingerprint: u64,
    ) -> sbproxy_model_host::ManagedEngineOwner {
        fake_managed_engine_owner_with_executable(pid, start_fingerprint, None)
    }

    fn fake_managed_engine_owner_with_executable(
        pid: u32,
        start_fingerprint: u64,
        executable: Option<&str>,
    ) -> sbproxy_model_host::ManagedEngineOwner {
        serde_json::from_value(serde_json::json!({
            "pid": pid,
            "start_fingerprint": start_fingerprint,
            "executable": executable,
        }))
        .expect("construct a distinct opaque owner token")
    }

    fn register_test_service_owner(
        paths: &ServicePaths,
        owner: &sbproxy_model_host::ManagedEngineOwner,
    ) {
        let ownership_directory =
            service_engine_ownership_directory(paths).expect("resolve test ownership directory");
        let lifecycle_lock =
            acquire_service_lifecycle_lock(&paths.lifecycle_lock).expect("lock lifecycle");
        register_service_owner_locked(
            &lifecycle_lock,
            &paths.uninstall_state,
            &ownership_directory,
            owner,
        )
        .expect("register test bootstrap generation");
    }

    #[cfg(unix)]
    #[test]
    fn service_launch_registration_persists_exact_owner_before_exec() {
        let paths = service_temp_paths("launch-registration");
        let ownership_directory = paths.config.parent().unwrap().join("managed-engines");
        let owner = fake_managed_engine_owner(5101, 61);
        let lifecycle_lock =
            acquire_service_lifecycle_lock(&paths.lifecycle_lock).expect("lock lifecycle");

        register_service_owner_locked(
            &lifecycle_lock,
            &paths.uninstall_state,
            &ownership_directory,
            &owner,
        )
        .expect("register exact bootstrap generation");

        let state = read_service_uninstall_state(&paths.uninstall_state)
            .unwrap()
            .expect("durable lifecycle state");
        assert_eq!(state.ownership_directory, ownership_directory);
        assert_eq!(state.owners, vec![owner.clone()]);
        assert_eq!(state.bootstrap_registered_owners, vec![owner]);
        assert!(paths.lifecycle_lock.exists());
        drop(lifecycle_lock);
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn service_launch_registration_rejects_owner_generation_overflow() {
        let paths = service_temp_paths("owner-overflow");
        let ownership_directory = paths.config.parent().unwrap().join("managed-engines");
        let owners = (0..MAX_SERVICE_OWNER_GENERATIONS)
            .map(|index| fake_managed_engine_owner(20_000 + index as u32, 10_000 + index as u64))
            .collect::<Vec<_>>();
        persist_service_uninstall_state(
            &paths.uninstall_state,
            &ServiceUninstallState {
                schema_version: SERVICE_UNINSTALL_STATE_SCHEMA_VERSION,
                ownership_directory: ownership_directory.clone(),
                owners: owners.clone(),
                bootstrap_registered_owners: Vec::new(),
            },
        )
        .unwrap();
        let lifecycle_lock =
            acquire_service_lifecycle_lock(&paths.lifecycle_lock).expect("lock lifecycle");

        let error = register_service_owner_locked(
            &lifecycle_lock,
            &paths.uninstall_state,
            &ownership_directory,
            &fake_managed_engine_owner(99_999, 99_999),
        )
        .expect_err("the lifecycle registry must have a hard owner cap");

        assert!(
            error.to_string().contains("owner generation limit"),
            "{error:#}"
        );
        let state = read_service_uninstall_state(&paths.uninstall_state)
            .unwrap()
            .unwrap();
        assert_eq!(state.owners, owners);
        assert!(state.bootstrap_registered_owners.is_empty());
        drop(lifecycle_lock);
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_state_rejects_oversized_file_before_read() {
        let paths = service_temp_paths("oversized-state");
        let file = std::fs::File::create(&paths.uninstall_state).unwrap();
        file.set_len((MAX_SERVICE_UNINSTALL_STATE_BYTES + 1) as u64)
            .unwrap();

        let error = read_service_uninstall_state(&paths.uninstall_state)
            .expect_err("oversized lifecycle state must be rejected before allocation");

        assert!(error.to_string().contains("maximum size"), "{error:#}");
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn service_lifecycle_lock_does_not_follow_a_symlink() {
        use std::os::unix::fs::symlink;

        let paths = service_temp_paths("lock-symlink");
        let target = paths.config.parent().unwrap().join("lock-target");
        std::fs::write(&target, "do not lock through this path").unwrap();
        symlink(&target, &paths.lifecycle_lock).unwrap();

        let error = acquire_service_lifecycle_lock(&paths.lifecycle_lock)
            .expect_err("a lifecycle lock symlink must fail closed");

        assert!(error.to_string().contains("lifecycle lock"), "{error:#}");
        assert_eq!(
            std::fs::read_to_string(target).unwrap(),
            "do not lock through this path"
        );
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_uses_the_service_env_ownership_directory() {
        let paths = service_temp_paths("ownership-env");
        let service_directory = paths.env_file.parent().unwrap().join("from-service-env");
        std::fs::write(
            &paths.env_file,
            format!(
                "SBPROXY_ENGINE_OWNERSHIP_DIR={}\n",
                service_directory.display()
            ),
        )
        .unwrap();
        let caller_shell = paths.env_file.parent().unwrap().join("from-caller-shell");
        let caller_shell = caller_shell.display().to_string();
        let _env =
            EnvVarGuard::set(&[("SBPROXY_ENGINE_OWNERSHIP_DIR", Some(caller_shell.as_str()))]);

        let selected = service_engine_ownership_directory(&paths).unwrap();

        assert_eq!(selected, service_directory);
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_environment_rejects_duplicate_assignments() {
        let paths = service_temp_paths("duplicate-environment");
        std::fs::write(
            &paths.env_file,
            "SBPROXY_ENGINE_OWNERSHIP_DIR=/first\n\
             SBPROXY_ENGINE_OWNERSHIP_DIR=/second\n",
        )
        .unwrap();

        let error = service_engine_ownership_directory(&paths)
            .expect_err("duplicate keys could select different startup and cleanup values");

        assert!(error.to_string().contains("duplicate"), "{error:#}");
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_environment_rejects_shell_syntax() {
        let paths = service_temp_paths("shell-environment");
        std::fs::write(
            &paths.env_file,
            "HF_TOKEN=$(cat /tmp/token)\n\
             SBPROXY_ENGINE_OWNERSHIP_DIR=/managed-engines\n",
        )
        .unwrap();

        let error = service_engine_ownership_directory(&paths)
            .expect_err("the service environment is declarative, not a shell program");

        assert!(error.to_string().contains("shell syntax"), "{error:#}");
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_environment_rejects_an_oversized_file_before_reading_it() {
        let paths = service_temp_paths("oversized-environment");
        let file = std::fs::File::create(&paths.env_file).unwrap();
        file.set_len((MAX_SERVICE_ENVIRONMENT_BYTES + 1) as u64)
            .unwrap();

        let error = read_service_environment(&paths.env_file)
            .expect_err("service bootstrap must bound environment-file allocation");

        assert!(error.to_string().contains("maximum size"), "{error:#}");
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_accepts_an_already_unloaded_job_without_calling_unload() {
        let paths = service_temp_paths("already-unloaded");
        std::fs::write(&paths.plist, "plist").unwrap();
        let mut launchd = FakeLaunchd {
            statuses: [LaunchdJobStatus::NotLoaded].into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);

        let outcome = perform_service_uninstall(&paths, &mut launchd, &mut cleanup).unwrap();

        assert!(outcome.removed);
        assert_eq!(outcome.engines_reaped, 0);
        assert_eq!(launchd.unload_calls, 0);
        assert_eq!(cleanup.capture_calls, 0);
        assert!(!paths.plist.exists());
        assert!(!paths.uninstall_state.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn service_uninstall_fails_closed_for_a_loaded_legacy_plist() {
        let paths = service_temp_paths("loaded-legacy-plist");
        std::fs::write(
            &paths.plist,
            "<string>/bin/sh</string><string>-c</string><string>exec sbproxy serve</string>",
        )
        .unwrap();
        let mut launchd = FakeLaunchd {
            statuses: [LaunchdJobStatus::Loaded {
                pid: Some(std::process::id()),
            }]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("a legacy KeepAlive job has no complete owner-generation registry");

        assert!(error.to_string().contains("legacy plist"), "{error:#}");
        assert!(error.to_string().contains("service install"), "{error:#}");
        assert_eq!(launchd.unload_calls, 0);
        assert_eq!(cleanup.capture_calls, 0);
        assert!(paths.plist.exists(), "legacy retry handle must remain");
        assert!(!paths.uninstall_state.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_fails_closed_when_loaded_generation_has_no_registry() {
        let paths = service_temp_paths("loaded-without-registry");
        write_registered_service_plist(&paths);
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(std::process::id()),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("a plist marker cannot prove the running generation registered");

        assert!(error.to_string().contains("not registered"), "{error:#}");
        assert_eq!(launchd.unload_calls, 0);
        assert_eq!(cleanup.capture_calls, 1);
        assert!(paths.plist.exists(), "the retry handle must remain");
        assert!(
            !paths.uninstall_state.exists(),
            "uninstall must not invent registration state"
        );
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_fails_closed_when_registry_has_only_an_unrelated_owner() {
        let paths = service_temp_paths("loaded-with-unrelated-registry");
        write_registered_service_plist(&paths);
        let ownership_directory = paths
            .config
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("managed-engines");
        let unrelated_owner = fake_managed_engine_owner(91_001, 91_001);
        persist_service_uninstall_state(
            &paths.uninstall_state,
            &ServiceUninstallState {
                schema_version: SERVICE_UNINSTALL_STATE_SCHEMA_VERSION,
                ownership_directory,
                owners: vec![unrelated_owner.clone()],
                bootstrap_registered_owners: Vec::new(),
            },
        )
        .unwrap();
        let state_before = std::fs::read(&paths.uninstall_state).unwrap();
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(std::process::id()),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("an unrelated owner cannot authorize unloading this generation");

        assert!(error.to_string().contains("not registered"), "{error:#}");
        assert_eq!(launchd.unload_calls, 0);
        assert_eq!(cleanup.capture_calls, 1);
        assert!(paths.plist.exists(), "the retry handle must remain");
        assert_eq!(
            std::fs::read(&paths.uninstall_state).unwrap(),
            state_before,
            "an untrusted observation must not mutate lifecycle state"
        );
        let state = read_service_uninstall_state(&paths.uninstall_state)
            .unwrap()
            .unwrap();
        assert_eq!(state.owners, vec![unrelated_owner]);
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_does_not_trust_an_owner_recorded_only_by_uninstall() {
        let paths = service_temp_paths("loaded-with-unregistered-observation");
        write_registered_service_plist(&paths);
        let ownership_directory = paths
            .config
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("managed-engines");
        let mut cleanup = fake_service_cleanup(false);
        persist_service_uninstall_state(
            &paths.uninstall_state,
            &ServiceUninstallState {
                schema_version: SERVICE_UNINSTALL_STATE_SCHEMA_VERSION,
                ownership_directory,
                owners: vec![cleanup.owner.clone()],
                bootstrap_registered_owners: Vec::new(),
            },
        )
        .unwrap();
        let state_before = std::fs::read(&paths.uninstall_state).unwrap();
        let mut launchd = FakeLaunchd {
            statuses: [LaunchdJobStatus::Loaded {
                pid: Some(std::process::id()),
            }]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("an uninstall observation does not prove bootstrap registration");

        assert!(error.to_string().contains("not registered"), "{error:#}");
        assert_eq!(launchd.unload_calls, 0);
        assert_eq!(cleanup.capture_calls, 1);
        assert_eq!(
            std::fs::read(&paths.uninstall_state).unwrap(),
            state_before,
            "uninstall must preserve the provenance-bearing registry"
        );
        assert!(paths.plist.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_matches_registration_by_process_generation() {
        let paths = service_temp_paths("registration-survives-binary-replacement");
        write_registered_service_plist(&paths);
        let pid = 92_001;
        let registered_owner =
            fake_managed_engine_owner_with_executable(pid, 92_001, Some("/usr/local/bin/sbproxy"));
        let recaptured_owner = fake_managed_engine_owner_with_executable(
            pid,
            92_001,
            Some("/usr/local/bin/sbproxy (deleted)"),
        );
        register_test_service_owner(&paths, &registered_owner);
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded { pid: Some(pid) },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        cleanup.owners_by_pid.insert(pid, recaptured_owner);

        let outcome = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect("an executable audit-path change must not change process identity");

        assert_eq!(launchd.unload_calls, 1);
        assert_eq!(outcome.engines_reaped, 1);
        assert_eq!(cleanup.reaped_owners, vec![registered_owner]);
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_retains_exact_retry_state_and_plist_until_reap_succeeds() {
        let paths = service_temp_paths("transaction");
        write_registered_service_plist(&paths);
        let ownership_directory = paths
            .env_file
            .parent()
            .unwrap()
            .join("service-only-ownership");
        std::fs::write(
            &paths.env_file,
            format!(
                "SBPROXY_ENGINE_OWNERSHIP_DIR={}\n",
                ownership_directory.display()
            ),
        )
        .unwrap();
        let mut first_launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(std::process::id()),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut failing_cleanup = fake_service_cleanup(true);
        register_test_service_owner(&paths, &failing_cleanup.owner);

        let error = perform_service_uninstall(&paths, &mut first_launchd, &mut failing_cleanup)
            .expect_err("reap failure must leave a retry transaction");

        assert!(error.to_string().contains("exact-owner reap failure"));
        assert!(paths.plist.exists(), "plist is the durable retry handle");
        assert!(paths.uninstall_state.exists());
        let state = read_service_uninstall_state(&paths.uninstall_state)
            .unwrap()
            .expect("retry state");
        assert_eq!(state.ownership_directory, ownership_directory);
        assert_eq!(state.owners, vec![failing_cleanup.owner.clone()]);

        let mut retry_launchd = FakeLaunchd {
            statuses: [LaunchdJobStatus::NotLoaded].into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut succeeding_cleanup = fake_service_cleanup(false);
        let outcome =
            perform_service_uninstall(&paths, &mut retry_launchd, &mut succeeding_cleanup)
                .expect("retry exact persisted owner");

        assert_eq!(outcome.engines_reaped, 1);
        assert_eq!(succeeding_cleanup.capture_calls, 0);
        assert_eq!(
            succeeding_cleanup.reaped_directories,
            vec![ownership_directory]
        );
        assert!(!paths.plist.exists());
        assert!(!paths.uninstall_state.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_accepts_unload_failure_when_launchd_reports_not_loaded() {
        let paths = service_temp_paths("unload-race");
        write_registered_service_plist(&paths);
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(std::process::id()),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: true,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        register_test_service_owner(&paths, &cleanup.owner);

        let outcome = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect("a concurrently unloaded job already reached the requested state");

        assert_eq!(outcome.engines_reaped, 1);
        assert_eq!(launchd.unload_calls, 1);
        assert!(!paths.plist.exists());
        assert!(!paths.uninstall_state.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_keeps_transaction_when_unload_fails_and_job_is_still_loaded() {
        let paths = service_temp_paths("unload-failure");
        write_registered_service_plist(&paths);
        let running = LaunchdJobStatus::Loaded {
            pid: Some(std::process::id()),
        };
        let mut launchd = FakeLaunchd {
            statuses: [running, running].into(),
            unload_fails: true,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        register_test_service_owner(&paths, &cleanup.owner);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("a still-loaded job must preserve its transaction");

        assert!(error.to_string().contains("unload failure"));
        assert!(paths.plist.exists());
        assert!(paths.uninstall_state.exists());
        assert!(cleanup.reaped_directories.is_empty());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_records_every_keepalive_generation_before_cleanup() {
        let paths = service_temp_paths("keepalive-generations");
        write_registered_service_plist(&paths);
        let first_pid = 4101;
        let replacement_pid = 4102;
        let first_owner = fake_managed_engine_owner(first_pid, 51);
        let replacement_owner = fake_managed_engine_owner(replacement_pid, 52);
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(first_pid),
                },
                LaunchdJobStatus::Loaded {
                    pid: Some(replacement_pid),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        cleanup.owners_by_pid.insert(first_pid, first_owner.clone());
        cleanup
            .owners_by_pid
            .insert(replacement_pid, replacement_owner.clone());
        register_test_service_owner(&paths, &first_owner);

        let outcome = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect("every observed KeepAlive generation is captured");

        assert_eq!(launchd.unload_calls, 2);
        assert_eq!(cleanup.captured_pids, vec![first_pid, replacement_pid]);
        assert_eq!(cleanup.reaped_owners, vec![first_owner, replacement_owner]);
        assert_eq!(outcome.engines_reaped, 2);
        assert!(!paths.plist.exists());
        assert!(!paths.uninstall_state.exists());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn service_uninstall_reaps_pre_registered_replacement_when_unload_hides_it() {
        let paths = service_temp_paths("pre-registered-replacement");
        write_registered_service_plist(&paths);
        let ownership_directory = paths.config.parent().unwrap().join("managed-engines");
        let first_pid = 6101;
        let first_owner = fake_managed_engine_owner(first_pid, 71);
        let replacement_owner = fake_managed_engine_owner(6102, 72);
        {
            let lifecycle_lock =
                acquire_service_lifecycle_lock(&paths.lifecycle_lock).expect("lock lifecycle");
            register_service_owner_locked(
                &lifecycle_lock,
                &paths.uninstall_state,
                &ownership_directory,
                &first_owner,
            )
            .unwrap();
            register_service_owner_locked(
                &lifecycle_lock,
                &paths.uninstall_state,
                &ownership_directory,
                &replacement_owner,
            )
            .unwrap();
        }
        let mut launchd = FakeLaunchd {
            statuses: [
                LaunchdJobStatus::Loaded {
                    pid: Some(first_pid),
                },
                LaunchdJobStatus::NotLoaded,
            ]
            .into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        cleanup.owners_by_pid.insert(first_pid, first_owner.clone());

        let outcome = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect("the registry covers a replacement hidden by unload");

        assert_eq!(launchd.unload_calls, 1);
        assert_eq!(cleanup.captured_pids, vec![first_pid]);
        assert_eq!(cleanup.reaped_owners, vec![first_owner, replacement_owner]);
        assert_eq!(outcome.engines_reaped, 2);
        assert!(!paths.plist.exists());
        assert!(!paths.uninstall_state.exists());
        assert!(
            paths.lifecycle_lock.exists(),
            "never unlink a cooperative lock path"
        );
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn service_uninstall_bounds_same_pid_no_progress_and_retains_handles() {
        let paths = service_temp_paths("bounded-no-progress");
        write_registered_service_plist(&paths);
        let pid = 7101;
        let running = LaunchdJobStatus::Loaded { pid: Some(pid) };
        let mut launchd = FakeLaunchd {
            statuses: vec![running; MAX_SERVICE_UNLOAD_ATTEMPTS + 2].into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);
        let owner = fake_managed_engine_owner(pid, 81);
        cleanup.owners_by_pid.insert(pid, owner.clone());
        register_test_service_owner(&paths, &owner);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("a launchd job that never changes must fail in bounded time");

        assert!(error.to_string().contains("no progress"), "{error:#}");
        assert!(launchd.unload_calls <= MAX_SERVICE_UNLOAD_ATTEMPTS);
        assert!(paths.plist.exists());
        assert!(paths.uninstall_state.exists());
        assert!(paths.lifecycle_lock.exists());
        assert!(cleanup.reaped_owners.is_empty());
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn service_uninstall_preserves_retry_handles_when_loaded_job_has_no_pid() {
        let paths = service_temp_paths("loaded-without-pid");
        write_registered_service_plist(&paths);
        let mut launchd = FakeLaunchd {
            statuses: [LaunchdJobStatus::Loaded { pid: None }].into(),
            unload_fails: false,
            unload_calls: 0,
        };
        let mut cleanup = fake_service_cleanup(false);

        let error = perform_service_uninstall(&paths, &mut launchd, &mut cleanup)
            .expect_err("an ownerless loaded generation cannot be cleaned exactly");

        assert!(error.to_string().contains("has no PID"), "{error:#}");
        assert_eq!(launchd.unload_calls, 0);
        assert!(cleanup.captured_pids.is_empty());
        assert!(cleanup.reaped_owners.is_empty());
        assert!(paths.plist.exists());
        assert!(
            paths.uninstall_state.exists(),
            "the durable retry transaction must survive"
        );
        let _ = std::fs::remove_dir_all(paths.config.parent().unwrap().parent().unwrap());
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

    /// The masks `sbproxy config print` actually runs, through the
    /// function the handler calls rather than a reimplementation of it.
    ///
    /// The earlier version of this test built its own `serde_json::Value`
    /// and called the two passes by hand, so its doc claimed a revert it
    /// could not observe: nothing outside the dispatch called
    /// `handle_config_print`, and deleting the `redact_config_document`
    /// line from it left the test green. `render_config_for_print` is the
    /// seam now, and both reverts redden this.
    ///
    /// The fixture is a real `ConfigFile`, parsed from YAML, so a field
    /// that stops serializing under that name reddens it too.
    #[test]
    fn config_print_masks_a_url_userinfo_and_keeps_one_marker() {
        let config: sbproxy_config::ConfigFile = serde_yaml::from_str(
            r#"
proxy:
  key_management:
    enabled: true
    crypto:
      pepper: literal-inline-pepper
      master_key: literal-master-secret
      root_of_trust:
        provider: vault_transit
        address: https://sbproxy:hvs.CAESIQpAbCdEf=@vault.internal:8200
        mount: transit
        key_name: sbproxy-root
        token: literal-transit-token
"#,
        )
        .expect("fixture parses");
        let rendered = render_config_for_print(&config, false).expect("renders");

        // The positional mask, on the field no key-name rule can cover,
        // with the base64 padding a Vault token actually carries.
        assert!(
            !rendered.contains("hvs.CAESIQpAbCdEf="),
            "the address carries userinfo and no key-name rule covers it: {rendered}"
        );
        assert!(
            rendered.contains("https://[REDACTED]@vault.internal:8200"),
            "the host has to survive, or the operator cannot tell which Vault this is: \
             {rendered}"
        );

        // And the three key-name secrets in the same block.
        for masked in [
            "literal-inline-pepper",
            "literal-master-secret",
            "literal-transit-token",
        ] {
            assert!(!rendered.contains(masked), "{masked} leaked: {rendered}");
        }

        // One surface, one marker. `mask_secrets` stamps `***MASKED***`
        // and the pattern pass must not restamp what it already did.
        assert!(
            !rendered.contains("[REDACTED]\n"),
            "a whole value masked as [REDACTED] means the pattern pass restamped a key-name \
             mask: {rendered}"
        );
        assert_eq!(
            rendered.matches("[REDACTED]").count(),
            1,
            "the only positional mask on this document is the address userinfo: {rendered}"
        );
        assert_eq!(
            rendered.matches("***MASKED***").count(),
            3,
            "pepper, master_key and token keep their own marker: {rendered}"
        );

        // The document still parses, which is the invariant both passes
        // are built around.
        serde_yaml::from_str::<serde_yaml::Value>(&rendered)
            .unwrap_or_else(|e| panic!("masked document no longer parses ({e}): {rendered}"));
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

    /// The CLI's `${VAR}` pass is the compiler's, not a lookalike
    /// (WOR-2433). Each of these three was wrong while a local copy
    /// stood here, and each one is a config path reading the process
    /// environment on semantics nothing else in the workspace shares.
    #[test]
    fn config_print_env_interpolation_is_the_compilers_pass() {
        // The documented `$$` escape stays literal rather than being
        // substituted.
        assert_eq!(interpolate_env_vars("p=$${PATH}"), "p=$${PATH}");
        // MCP local-tool vocabulary belongs to the executor at call
        // time, not to a config-load-time environment read.
        assert_eq!(
            interpolate_env_vars("${args.user_id}/${steps.fetch.body.x}"),
            "${args.user_id}/${steps.fetch.body.x}"
        );
        // `${VAR:-default}` takes its shell meaning, so a config whose
        // value resolves to a default prints that default rather than
        // the raw placeholder.
        assert_eq!(
            interpolate_env_vars("k=${SB_DEFINITELY_UNSET_XYZZY:-fixture-local-token}"),
            "k=fixture-local-token"
        );
    }

    #[test]
    fn models_list_rows_cover_the_catalog_with_a_fit_verdict() {
        let catalog = sbproxy_model_host::Catalog::builtin();
        let report = sbproxy_core::doctor::DoctorReport::collect();
        // A cache root that does not exist -> everything reads not-pulled.
        let root = std::env::temp_dir().join("sbproxy-models-test-nonexistent");
        // An empty foreign scan -> no importable markers appear.
        let rows = build_model_rows(&catalog, &report, &root, &[]);
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
    fn models_list_importable_marker_requires_full_size_coverage_from_one_source() {
        use sbproxy_model_host::{ForeignCacheSource, ForeignModelFile};
        let artifact = sbproxy_model_host::ResolvedArtifact {
            catalog_revision: "list-fixture".to_string(),
            logical_model: "fixture".to_string(),
            variant_id: "exact".to_string(),
            artifact_digest: "a".repeat(64),
            format: sbproxy_model_host::ArtifactFormat::Gguf,
            quant: "q4".to_string(),
            engine: sbproxy_model_host::EngineKind::LlamaCpp,
            source: "hf:Fixture/List".to_string(),
            revision: "main".to_string(),
            files: vec![
                sbproxy_model_host::ArtifactFile {
                    path: "a.gguf".to_string(),
                    sha256: "b".repeat(64),
                    size_bytes: 10,
                },
                sbproxy_model_host::ArtifactFile {
                    path: "b.gguf".to_string(),
                    sha256: "c".repeat(64),
                    size_bytes: 20,
                },
            ],
            context_length: 4096,
            license: "apache-2.0".to_string(),
            stability: sbproxy_model_host::SupportLevel::Preview,
            pickle_allowed: false,
            modality: Default::default(),
        };
        let candidate = |source, size_bytes: u64| ForeignModelFile {
            source,
            path: std::path::PathBuf::from("/scan/fixture"),
            repo_or_name: "fixture".to_string(),
            size_bytes,
            format_hint: None,
        };
        // Every declared file size-covered by one source -> that source.
        let full = vec![
            candidate(ForeignCacheSource::Ollama, 10),
            candidate(ForeignCacheSource::Ollama, 20),
        ];
        assert_eq!(
            foreign_import_source(Some(&artifact), &full),
            Some(ForeignCacheSource::Ollama)
        );
        // Partial coverage, coverage split across sources, or no
        // resolved artifact -> no marker.
        assert_eq!(foreign_import_source(Some(&artifact), &full[..1]), None);
        let split = vec![
            candidate(ForeignCacheSource::Ollama, 10),
            candidate(ForeignCacheSource::LmStudio, 20),
        ];
        assert_eq!(foreign_import_source(Some(&artifact), &split), None);
        assert_eq!(foreign_import_source(None, &full), None);
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

    /// The YAML half of the precedence chain: what
    /// `proxy.observability.log:` asked for.
    fn config_log(level: Option<&str>, format: Option<&str>) -> ConfigLogSettings {
        ConfigLogSettings {
            level: level.map(str::to_string),
            format: format.map(str::to_string),
        }
    }

    /// No `proxy.observability.log:` block at all.
    fn no_config_log() -> ConfigLogSettings {
        ConfigLogSettings::default()
    }

    // --- log-filter precedence ---

    #[test]
    fn log_filter_cli_wins_over_env() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", Some("trace"))]);
        let got = resolve_log_filter(&globals_with_log(Some("debug"), None), &no_config_log());
        assert_eq!(got, "debug");
    }

    #[test]
    fn log_filter_falls_through_to_rust_log() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", Some("sbproxy=trace"))]);
        let got = resolve_log_filter(&globals_with_log(None, None), &no_config_log());
        assert_eq!(got, "sbproxy=trace");
    }

    #[test]
    fn log_filter_default_info() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        assert_eq!(
            resolve_log_filter(&globals_with_log(None, None), &no_config_log()),
            "info"
        );
    }

    #[test]
    fn request_log_level_cli_appends_access_log_target() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(
            &globals_with_log(Some("warn"), Some("debug")),
            &no_config_log(),
        );
        assert_eq!(got, "warn,access_log=debug");
    }

    #[test]
    fn request_log_level_env_appends_access_log_target() {
        // SB_REQUEST_LOG_LEVEL is read by clap when the CLI flag is
        // absent. Drive that path by populating `GlobalArgs` the way
        // clap would: with the env value already folded into the
        // `request_log_level` field.
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(&globals_with_log(None, Some("trace")), &no_config_log());
        assert_eq!(got, "info,access_log=trace");
    }

    // --- log-filter precedence: the YAML rank ---

    /// The defect this fixes. An operator writes `level: debug` in
    /// `sb.yml`, passes no flag, exports no `RUST_LOG`, and gets debug
    /// output instead of silence.
    #[test]
    fn log_filter_yaml_level_applies_without_cli_or_rust_log() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(
            &globals_with_log(None, None),
            &config_log(Some("debug"), None),
        );
        assert_eq!(got, "debug");
    }

    /// A per-target directive is a filter like any other, so the YAML
    /// rank accepts the same syntax the flag does.
    #[test]
    fn log_filter_yaml_level_accepts_a_target_directive() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(
            &globals_with_log(None, None),
            &config_log(Some("sbproxy_ai=debug,h2=warn"), None),
        );
        assert_eq!(got, "sbproxy_ai=debug,h2=warn");
    }

    #[test]
    fn log_filter_cli_wins_over_yaml_level() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(
            &globals_with_log(Some("warn"), None),
            &config_log(Some("debug"), None),
        );
        assert_eq!(got, "warn");
    }

    /// The compatibility promise: a deployment that exports `RUST_LOG`
    /// keeps resolving to `RUST_LOG` after this change, whatever the
    /// config file now says.
    #[test]
    fn log_filter_rust_log_wins_over_yaml_level() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", Some("warn"))]);
        let got = resolve_log_filter(
            &globals_with_log(None, None),
            &config_log(Some("debug"), None),
        );
        assert_eq!(got, "warn");
    }

    /// An empty or whitespace-only value is an absent value, matching
    /// how the CLI rank already treats an empty flag.
    #[test]
    fn log_filter_blank_yaml_level_falls_through_to_the_default() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(&globals_with_log(None, None), &config_log(Some("  "), None));
        assert_eq!(got, "info");
    }

    /// `--request-log-level` narrows one target on top of whichever
    /// rank won, including the YAML one.
    #[test]
    fn request_log_level_appends_on_top_of_a_yaml_level() {
        let _env = EnvVarGuard::set(&[("RUST_LOG", None)]);
        let got = resolve_log_filter(
            &globals_with_log(None, Some("trace")),
            &config_log(Some("warn"), None),
        );
        assert_eq!(got, "warn,access_log=trace");
    }

    // --- log-format precedence ---

    #[test]
    fn log_format_yaml_applies_without_a_flag() {
        let got = resolve_log_format(
            &globals_with_log(None, None),
            &config_log(None, Some("json")),
        );
        assert_eq!(got, LogFormat::Json);
    }

    #[test]
    fn log_format_cli_wins_over_yaml() {
        let globals = GlobalArgs {
            log_format: Some(LogFormat::Pretty),
            ..Default::default()
        };
        let got = resolve_log_format(&globals, &config_log(None, Some("json")));
        assert_eq!(got, LogFormat::Pretty);
    }

    #[test]
    fn log_format_defaults_to_compact_with_neither() {
        let got = resolve_log_format(&globals_with_log(None, None), &no_config_log());
        assert_eq!(got, LogFormat::Compact);
    }

    /// clap refuses an unknown `--log-format`, but YAML is a free-form
    /// string. An unknown value must not resolve to something the
    /// operator did not ask for without saying so.
    #[test]
    fn log_format_unknown_yaml_value_falls_back_to_compact() {
        let got = resolve_log_format(
            &globals_with_log(None, None),
            &config_log(None, Some("logfmt")),
        );
        assert_eq!(got, LogFormat::Compact);
    }

    // --- clap env-var precedence (CLI > env) ---

    #[test]
    fn clap_cli_log_level_wins_over_sb_log_level() {
        let _env = EnvVarGuard::set(&[("SB_LOG_LEVEL", Some("warn"))]);
        let cli = parse(&["sbproxy", "--log-level", "debug", "/tmp/sb.yml"]);
        assert_eq!(cli.globals.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn clap_sb_log_level_env_fills_the_gap() {
        let _env = EnvVarGuard::set(&[("SB_LOG_LEVEL", Some("warn"))]);
        let cli = parse(&["sbproxy", "/tmp/sb.yml"]);
        assert_eq!(cli.globals.log_level.as_deref(), Some("warn"));
    }

    #[test]
    fn clap_shutdown_grace_cli_wins_over_env() {
        let _env = EnvVarGuard::set(&[("SBPROXY_SHUTDOWN_GRACE_MS", Some("5000"))]);
        let cli = parse(&["sbproxy", "--shutdown-grace-ms", "12000", "/tmp/sb.yml"]);
        assert_eq!(cli.globals.shutdown_grace_ms, Some(12_000));
    }

    #[test]
    fn clap_shutdown_grace_env_only() {
        let _env = EnvVarGuard::set(&[("SBPROXY_SHUTDOWN_GRACE_MS", Some("45000"))]);
        let cli = parse(&["sbproxy", "/tmp/sb.yml"]);
        assert_eq!(cli.globals.shutdown_grace_ms, Some(45_000));
    }

    #[test]
    fn clap_grace_time_cli_wins_over_env() {
        let _env = EnvVarGuard::set(&[("SB_GRACE_TIME", Some("30"))]);
        let cli = parse(&["sbproxy", "--grace-time", "5", "/tmp/sb.yml"]);
        assert_eq!(cli.globals.grace_time, Some(5));
    }

    /// The 30s default tracks Kubernetes' default
    /// `terminationGracePeriodSeconds`. Any change here is a
    /// behaviour change for orchestrators that rely on the default.
    #[test]
    fn shutdown_grace_default_is_30_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_GRACE_MS, 30_000);
    }

    // --- apply talks to a running proxy ---

    fn apply_args_pointing_at(url: &str) -> ApplyArgs {
        ApplyArgs {
            config: None,
            plan_file: None,
            admin_url: Some(url.to_string()),
            username: None,
            password: Some("test-password".to_string()),
            validate_only: false,
        }
    }

    /// The behaviour this whole change exists for. Apply used to compile
    /// the config into its own process, swap that process's pipeline, and
    /// print success without contacting anything. An unreachable proxy
    /// must now be a distinct non-zero exit, not a local no-op wearing a
    /// success message.
    #[test]
    fn apply_reports_an_unreachable_proxy_rather_than_succeeding_locally() {
        // Bind and immediately drop, so the port is almost certainly
        // closed but is a real address rather than a routing black hole.
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
            probe.local_addr().expect("probe addr").port()
        };
        let args = apply_args_pointing_at(&format!("http://127.0.0.1:{port}"));

        let code = apply_to_running_proxy(&args, "proxy:\n  http_bind_port: 0\n")
            .expect("unreachable proxy is a reported exit code, not an Err");

        assert_eq!(
            code, 7,
            "an unreachable admin API must exit 7 so a deploy script can tell \
             the difference between applied and never delivered"
        );
    }

    /// A trailing slash on the admin URL must not produce a double slash
    /// in the request path.
    #[test]
    fn apply_admin_url_trailing_slash_is_normalised() {
        let base = "http://127.0.0.1:9090/";
        assert_eq!(
            format!("{}/admin/config", base.trim_end_matches('/')),
            "http://127.0.0.1:9090/admin/config"
        );
    }

    /// The password must never reach a log line through Debug.
    #[test]
    fn apply_args_debug_redacts_the_password() {
        let args = apply_args_pointing_at("http://127.0.0.1:9090");
        let rendered = format!("{args:?}");
        assert!(
            !rendered.contains("test-password"),
            "ApplyArgs Debug leaked the admin password: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "expected a redaction marker"
        );
    }

    // --- config authority ---

    /// Every config-authority command carries an admin password, so every one
    /// of their args structs has to redact it. They flatten `ModelsAdminArgs`
    /// rather than declaring the three flags again precisely so its
    /// hand-written `Debug` covers them, and this is what keeps a future
    /// command from declaring its own field and losing the redaction.
    #[test]
    fn config_authority_args_debug_redacts_the_password() {
        let admin = ModelsAdminArgs {
            admin_url: Some("http://127.0.0.1:9090".to_string()),
            username: Some("admin".to_string()),
            password: Some("test-password".to_string()),
        };
        let rendered = [
            format!(
                "{:?}",
                AuthorityPublishArgs {
                    config: Some(PathBuf::from("payload.yml")),
                    mode: BundleModeArg::Overlay,
                    validate_only: false,
                    admin: admin.clone(),
                    format: OutputFormat::Text,
                }
            ),
            format!(
                "{:?}",
                AuthorityStatusArgs {
                    admin: admin.clone(),
                    format: OutputFormat::Text,
                }
            ),
            format!(
                "{:?}",
                AuthorityRollbackArgs {
                    admin: admin.clone(),
                    format: OutputFormat::Text,
                }
            ),
            format!(
                "{:?}",
                AuthoritySubscriberAddArgs {
                    subscriber_id: "edge-01".to_string(),
                    admin: admin.clone(),
                    format: OutputFormat::Text,
                }
            ),
            format!(
                "{:?}",
                AuthoritySubscriberListArgs {
                    admin: admin.clone(),
                    format: OutputFormat::Text,
                }
            ),
            format!(
                "{:?}",
                AuthoritySubscriberRevokeArgs {
                    credential_id: Some("0lJ8kQ2vTn5mAqRt".to_string()),
                    subscriber_id: None,
                    admin,
                    format: OutputFormat::Text,
                }
            ),
        ];
        for rendered in rendered {
            assert!(
                !rendered.contains("test-password"),
                "a config-authority args Debug leaked the admin password: {rendered}"
            );
            assert!(
                rendered.contains("<redacted>"),
                "expected a redaction marker: {rendered}"
            );
        }
    }

    /// The whole surface parses, including the two nested subcommand levels
    /// and the flags that pick the wire behaviour.
    #[test]
    fn config_authority_cli_surface_parses() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "config",
            "authority",
            "publish",
            "-f",
            "payload.yml",
            "--mode",
            "replace",
            "--format",
            "json",
        ])
        .expect("publish parses");
        let Some(Cmd::Config(ConfigCmd {
            sub:
                ConfigSub::Authority(ConfigAuthorityCmd {
                    sub: ConfigAuthoritySub::Publish(args),
                }),
        })) = cli.cmd
        else {
            panic!("config authority publish parsed to the wrong command");
        };
        assert_eq!(args.config, Some(PathBuf::from("payload.yml")));
        assert_eq!(args.mode, BundleModeArg::Replace);
        assert_eq!(args.mode.as_str(), "replace");

        let cli = Cli::try_parse_from([
            "sbproxy",
            "config",
            "authority",
            "subscriber",
            "add",
            "edge-01",
        ])
        .expect("subscriber add parses");
        let Some(Cmd::Config(ConfigCmd {
            sub:
                ConfigSub::Authority(ConfigAuthorityCmd {
                    sub:
                        ConfigAuthoritySub::Subscriber(AuthoritySubscriberCmd {
                            sub: AuthoritySubscriberSub::Add(args),
                        }),
                }),
        })) = cli.cmd
        else {
            panic!("subscriber add parsed to the wrong command");
        };
        assert_eq!(args.subscriber_id, "edge-01");

        // The two selectors are mutually exclusive: revoking one credential
        // and revoking every credential a node holds are different acts.
        assert!(Cli::try_parse_from([
            "sbproxy",
            "config",
            "authority",
            "subscriber",
            "revoke",
            "--credential-id",
            "one",
            "--subscriber-id",
            "edge-01",
        ])
        .is_err());
    }

    /// `config authority` and `config pull` report through `plan`'s exit
    /// codes, where 2 is "changes present". Their CLI-error code therefore
    /// has to be 1, or a diff would be indistinguishable from a broken
    /// invocation.
    #[test]
    fn config_subcommands_that_print_a_diff_use_plans_error_code() {
        let plan_style = [
            vec!["sbproxy", "config", "pull", "sb.yml", "--dry-run"],
            vec!["sbproxy", "config", "authority", "status"],
            // WOR-2460. `config diff` prints a plan, so it reports the
            // same way. Listed here rather than trusted: this test is
            // named for the property, and a member of the set it does
            // not name is a member nothing checks.
            vec!["sbproxy", "config", "diff", "7"],
            vec!["sbproxy", "config", "diff", "--from", "5", "--to", "7"],
        ];
        for argv in plan_style {
            let cli = Cli::try_parse_from(&argv).expect("parses");
            let Some(Cmd::Config(cmd)) = cli.cmd else {
                panic!("{argv:?} parsed to the wrong command");
            };
            assert!(cmd.uses_plan_exit_codes(), "{argv:?}");
        }
        let cli = Cli::try_parse_from(["sbproxy", "config", "print", "sb.yml"]).expect("parses");
        let Some(Cmd::Config(cmd)) = cli.cmd else {
            panic!("config print parsed to the wrong command");
        };
        assert!(
            !cmd.uses_plan_exit_codes(),
            "the older config subcommands keep the exit 2 they have always used for errors"
        );
    }

    /// A generated key id names its own public half, so two keys never
    /// collide in a verifying-key file during an additive rotation.
    #[test]
    fn derived_key_ids_are_readable_valid_and_key_specific() {
        let first = derived_key_id("3p8Q0mB1yV4kX7wR2tL6nS9cF5jH0dA8gZ2eK4uY1oM=");
        let second = derived_key_id("9kL2xP7bT4mV1nQ8wR5tY6sF3jH0dA8gZ2eK4uY1oM=");
        assert_ne!(first, second);
        assert!(first.starts_with("authority-"), "{first}");
        // Only characters a bundle identifier accepts: the base64 alphabet's
        // `+` and `/` would be refused by the signer.
        assert!(
            first
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-'),
            "{first}"
        );
        assert_eq!(first.len(), "authority-".len() + 12);
    }

    /// A rotation adds a key rather than replacing the file, because the old
    /// key has to keep verifying while subscribers are updated.
    #[test]
    fn merging_verifying_keys_keeps_the_entries_already_there() {
        let path = temp_config(
            "{\n  \"authority-old\": {\"algorithm\": \"ed25519\", \"key\": \"AAA=\"}\n}\n",
        );
        let merged = merge_verifying_keys(
            &path,
            "{\n  \"authority-new\": {\"algorithm\": \"ed25519\", \"key\": \"BBB=\"}\n}\n",
        )
        .expect("merge");
        let merged: serde_json::Value = serde_json::from_str(&merged).expect("merged JSON");
        assert_eq!(merged["authority-old"]["key"], "AAA=");
        assert_eq!(merged["authority-new"]["key"], "BBB=");

        // A file that is not a key map is a refusal, not something to
        // overwrite: subscribers may be trusting whatever is in it.
        let garbage = temp_config("not json at all\n");
        assert!(merge_verifying_keys(&garbage, "{}").is_err());

        // A missing file is the first-run case, not an error.
        let absent = path.with_extension("absent");
        assert!(merge_verifying_keys(&absent, "{}").is_ok());
    }

    /// A refused bundle has to be named in terms an operator can act on, so
    /// every `CycleResult` gets a hint rather than a bare label.
    #[test]
    fn every_pull_refusal_has_a_hint() {
        use sbproxy_core::config_subscriber::CycleResult;

        for result in [
            CycleResult::Applied,
            CycleResult::NotModified,
            CycleResult::Unreachable,
            CycleResult::VerifyFailed,
            CycleResult::CompileFailed,
            CycleResult::DeniedPath,
            CycleResult::ReloadBusy,
        ] {
            assert!(
                !pull_refusal_hint(result).is_empty(),
                "{} has no hint",
                result.as_str()
            );
        }
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
    fn parses_config_history_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "config",
            "history",
            "--admin-url",
            "http://127.0.0.1:9091",
            "--username",
            "admin",
            "--password",
            "secret",
            "--format",
            "json",
        ]);
        let cmd = match cli.cmd {
            Some(Cmd::Config(cmd)) => cmd,
            other => panic!("expected Config, got {other:?}"),
        };
        let ConfigSub::History(args) = cmd.sub else {
            panic!("expected History subcommand");
        };
        assert_eq!(
            args.admin.admin_url.as_deref(),
            Some("http://127.0.0.1:9091")
        );
        assert_eq!(args.admin.username.as_deref(), Some("admin"));
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn parses_config_show_subcommand_with_a_revision_number() {
        let cli = parse(&["sbproxy", "config", "show", "7"]);
        let cmd = match cli.cmd {
            Some(Cmd::Config(cmd)) => cmd,
            other => panic!("expected Config, got {other:?}"),
        };
        let ConfigSub::Show(args) = cmd.sub else {
            panic!("expected Show subcommand");
        };
        assert_eq!(args.revision, 7);
        assert!(matches!(args.format, OutputFormat::Text));
    }

    #[test]
    fn config_show_requires_a_revision_argument() {
        let err = Cli::try_parse_from(["sbproxy", "config", "show"]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("required") || msg.contains("REVISION"),
            "expected a missing-argument message, got: {msg}"
        );
    }

    /// WOR-2460. The escape hatch's own surface: the target defaults to
    /// the last known good, and every guard the route offers is
    /// reachable from the command line, because an operator who has to
    /// open a browser mid-incident does not have the escape hatch.
    #[test]
    fn parses_config_rollback_subcommand_with_every_guard() {
        let cli = parse(&["sbproxy", "config", "rollback"]);
        let Some(Cmd::Config(cmd)) = cli.cmd else {
            panic!("expected Config");
        };
        assert!(
            !cmd.uses_plan_exit_codes(),
            "a rollback applies; it does not print a plan",
        );
        let ConfigSub::Rollback(args) = cmd.sub else {
            panic!("expected Rollback");
        };
        assert_eq!(
            args.to, "last-known-good",
            "the bare form is the one an operator types under pressure",
        );
        assert_eq!(args.expected_current, None);
        assert_eq!(args.confirm, None);
        assert!(!args.force);

        let cli = parse(&[
            "sbproxy",
            "config",
            "rollback",
            "--to",
            "41",
            "--expected-current",
            "43",
            "--confirm",
            "41",
            "--lineage",
            "0f9c2c1e-0000-4000-8000-000000000000",
            "--force",
            "--format",
            "json",
        ]);
        let Some(Cmd::Config(cmd)) = cli.cmd else {
            panic!("expected Config");
        };
        let ConfigSub::Rollback(args) = cmd.sub else {
            panic!("expected Rollback");
        };
        assert_eq!(args.to, "41");
        assert_eq!(args.expected_current, Some(43));
        assert_eq!(args.confirm, Some(41));
        assert_eq!(
            args.lineage.as_deref(),
            Some("0f9c2c1e-0000-4000-8000-000000000000")
        );
        assert!(args.force);
        assert!(matches!(args.format, OutputFormat::Json));
    }

    /// WOR-2460. `config diff` takes its target as a positional or as
    /// `--to`, and naming it twice or not at all is a usage error rather
    /// than a precedence rule. Both refusals are reached before any
    /// admin request, so this drives the real handler.
    #[test]
    fn config_diff_wants_its_target_named_exactly_once() {
        let both = parse(&["sbproxy", "config", "diff", "7", "--to", "9"]);
        let Some(Cmd::Config(cmd)) = both.cmd else {
            panic!("expected Config");
        };
        let ConfigSub::Diff(args) = cmd.sub else {
            panic!("expected Diff");
        };
        assert_eq!(
            handle_config_diff(&args).expect("a usage error is not an anyhow failure"),
            1,
            "naming the target twice is refused rather than resolved by precedence",
        );

        let neither = parse(&["sbproxy", "config", "diff"]);
        let Some(Cmd::Config(cmd)) = neither.cmd else {
            panic!("expected Config");
        };
        let ConfigSub::Diff(args) = cmd.sub else {
            panic!("expected Diff");
        };
        assert_eq!(handle_config_diff(&args).expect("a usage error"), 1);

        // And the two accepted forms carry what they were given.
        let positional = parse(&["sbproxy", "config", "diff", "7"]);
        let Some(Cmd::Config(cmd)) = positional.cmd else {
            panic!("expected Config");
        };
        let ConfigSub::Diff(args) = cmd.sub else {
            panic!("expected Diff");
        };
        assert_eq!(args.to.as_deref(), Some("7"));
        assert_eq!(args.from, None);

        let pair = parse(&[
            "sbproxy", "config", "diff", "--from", "5", "--to", "7", "--format", "json",
        ]);
        let Some(Cmd::Config(cmd)) = pair.cmd else {
            panic!("expected Config");
        };
        let ConfigSub::Diff(args) = cmd.sub else {
            panic!("expected Diff");
        };
        assert_eq!(args.from.as_deref(), Some("5"));
        assert_eq!(args.to_flag.as_deref(), Some("7"));
        assert_eq!(args.to, None);
    }

    /// WOR-2460. The query-string encoder exists so a typed revision
    /// selector cannot smuggle a second parameter into the diff request,
    /// which is the only claim it makes and therefore the one to pin.
    #[test]
    fn a_revision_selector_cannot_smuggle_a_query_parameter() {
        assert_eq!(urlencoding_lite("7"), "7");
        assert_eq!(urlencoding_lite("last-known-good"), "last-known-good");
        assert_eq!(
            urlencoding_lite("7&from=1"),
            "7%26from%3D1",
            "an ampersand and an equals sign are both encoded, so neither opens a parameter",
        );
        assert_eq!(urlencoding_lite("a b"), "a%20b");
        assert_eq!(urlencoding_lite("../etc"), "..%2Fetc");
        // Percent-encoding is defined on octets. A non-ASCII scalar
        // encodes as its UTF-8 bytes, not as a truncated low byte,
        // which `U+0100` would otherwise render as the NUL escape.
        assert_eq!(urlencoding_lite("\u{0100}"), "%C4%80");
        assert_eq!(urlencoding_lite("revisión"), "revisi%C3%B3n");
        assert_eq!(
            urlencoding_lite("7#frag"),
            "7%23frag",
            "a fragment marker would otherwise truncate the path at the server",
        );
    }

    // A test named `config_show_displays_whatever_the_server_sent_verbatim
    // _including_redaction` used to sit here. It hand-built a `detail` JSON
    // whose document was already redacted and asserted a two-line field
    // accessor returned it, so it passed identically with redaction deleted
    // and pinned nothing. The enforcement lives server-side, in admin.rs's
    // `config_history_detail_redacts_a_literal_secret_while_the_ring_file_keeps_the_original`.
    // The CLI property worth pinning (that `handle_config_show` issues the
    // two admin GETs and applies no transformation of its own) needs an
    // admin-server mock this test module does not have; until one exists,
    // no test here is more honest than a test that proves nothing.

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
    fn audit_verify_exits_zero_on_a_signed_trail_and_one_on_a_damaged_one() {
        // The operator-facing half of WOR-2318, driven the way an auditor
        // drives it: a file, a seed, and no running proxy anywhere.
        use sbproxy_observe::audit::SecurityAuditEntry;
        use sbproxy_observe::audit_chain::{install_security_audit_chain, SecurityAuditChain};

        let dir = std::env::temp_dir().join(format!("sb-audit-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("security-audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let seed = "ab".repeat(32);

        let chain = SecurityAuditChain::open(&path, &seed, "sbproxy-audit").expect("chain opens");
        if install_security_audit_chain(chain).is_err() {
            // The slot is process-global and taken. Nothing here is worth
            // asserting against somebody else's chain.
            return;
        }
        for index in 0..2 {
            SecurityAuditEntry::policy_violation(
                "ip_filter",
                format!("blocked-{index}"),
                403,
                Some("api.example.com".to_string()),
                None,
                None,
                Some("GET".to_string()),
            )
            .emit();
        }

        let verify = |seed_hex: Option<&str>| {
            handle_audit_verify(&AuditVerifyArgs {
                path: path.clone(),
                signing_seed_hex: seed_hex.map(str::to_string),
                format: OutputFormat::Json,
                channel: "security".to_string(),
            })
        };

        assert_eq!(
            verify(Some(&seed)).expect("the chain is readable"),
            0,
            "an untouched trail verifies against its key"
        );

        // Replace the trail with something that is not one. The exit code
        // is what an auditor keys their alerting off, so it is what this
        // asserts on.
        std::fs::write(&path, "{\"seq\":0,\"recorded_at\":\"x\"}\n").expect("path is writable");
        assert_eq!(
            verify(None).expect("a damaged trail is reported, not an error"),
            1,
            "a file that is not a chain fails verification"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parses_audit_verify_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "audit",
            "verify",
            "/var/lib/sbproxy/security-audit.jsonl",
            "--signing-seed-hex",
            "00",
            "--format",
            "json",
        ]);
        match cli.cmd {
            Some(Cmd::Audit(cmd)) => match cmd.sub {
                AuditSub::Verify(args) => {
                    assert_eq!(
                        args.path,
                        std::path::PathBuf::from("/var/lib/sbproxy/security-audit.jsonl")
                    );
                    assert_eq!(args.signing_seed_hex.as_deref(), Some("00"));
                    assert!(matches!(args.format, OutputFormat::Json));
                    assert_eq!(args.channel, "security", "default channel is security");
                }
            },
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    #[test]
    fn parses_audit_verify_subcommand_with_config_channel() {
        let cli = parse(&[
            "sbproxy",
            "audit",
            "verify",
            "/var/lib/sbproxy/config-audit.jsonl",
            "--channel",
            "config",
        ]);
        match cli.cmd {
            Some(Cmd::Audit(cmd)) => match cmd.sub {
                AuditSub::Verify(args) => {
                    assert_eq!(args.channel, "config");
                }
            },
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    // --- `rego test` (WOR-2482) ---

    #[test]
    fn parses_rego_test_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "rego",
            "test",
            "policies/",
            "--min-coverage",
            "80",
            "--format",
            "json",
        ]);
        match cli.cmd {
            Some(Cmd::Rego(cmd)) => match cmd.sub {
                RegoSub::Test(args) => {
                    assert_eq!(args.path, std::path::PathBuf::from("policies/"));
                    assert_eq!(args.min_coverage, Some(80.0));
                    assert!(matches!(args.format, OutputFormat::Json));
                }
            },
            other => panic!("expected Rego, got {other:?}"),
        }
    }

    #[test]
    fn parses_cedar_replay_subcommand() {
        let cli = parse(&[
            "sbproxy",
            "cedar",
            "replay",
            "-f",
            "sb.yml",
            "--against",
            "traffic.jsonl",
            "--baseline",
            "old.yml",
            "--origin",
            "mcp.example.com",
            "--format",
            "json",
        ]);
        match cli.cmd {
            Some(Cmd::Cedar(cmd)) => match cmd.sub {
                CedarSub::Replay(args) => {
                    assert_eq!(args.config, Some(std::path::PathBuf::from("sb.yml")));
                    assert_eq!(args.against, std::path::PathBuf::from("traffic.jsonl"));
                    assert_eq!(args.baseline, Some(std::path::PathBuf::from("old.yml")));
                    assert_eq!(args.origin.as_deref(), Some("mcp.example.com"));
                    assert!(matches!(args.format, OutputFormat::Json));
                }
            },
            other => panic!("expected Cedar, got {other:?}"),
        }
    }

    /// Unique per-test scratch directory under the OS temp dir, mirroring
    /// the audit-verify CLI tests' convention (no `tempfile` dependency
    /// in this crate).
    fn rego_test_scratch_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sb-rego-test-cli-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    const PASSING_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false

  allow if {
      input.request.method == "GET"
  }
cases:
  - name: get is allowed
    input:
      request:
        method: GET
    expect: true
  - name: post is denied
    input:
      request:
        method: POST
    expect: false
"#;

    #[test]
    fn rego_test_passing_suite_exits_zero_with_coverage_output() {
        let dir = rego_test_scratch_dir("passing");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, PASSING_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("a well-formed fixture runs");
        assert_eq!(output.failed, 0, "{output:?}");
        assert_eq!(output.passed, 2, "{output:?}");
        assert!(
            !output.coverage.is_empty(),
            "a passing run must still produce coverage output: {output:?}"
        );

        let exit = handle_rego_test(&RegoTestArgs {
            path: fixture_path,
            min_coverage: None,
            format: OutputFormat::Json,
        })
        .expect("the handler runs end to end");
        assert_eq!(exit, 0, "a passing suite must exit 0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    const FAILING_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false

  allow if {
      input.request.method == "GET"
  }
cases:
  - name: get is allowed
    input:
      request:
        method: GET
    expect: true
  - name: post is wrongly expected allowed
    input:
      request:
        method: POST
    expect: true
"#;

    #[test]
    fn rego_test_failing_case_exits_nonzero_naming_the_case() {
        let dir = rego_test_scratch_dir("failing");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, FAILING_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the fixture parses and its module compiles");
        assert_eq!(output.failed, 1, "{output:?}");
        let failing = output
            .cases
            .iter()
            .find(|case| case.status == "fail")
            .expect("exactly one case fails");
        assert_eq!(
            failing.case, "post is wrongly expected allowed",
            "the failing case must be named in the result, not just counted"
        );

        let exit = handle_rego_test(&RegoTestArgs {
            path: fixture_path,
            min_coverage: None,
            format: OutputFormat::Text,
        })
        .expect("the handler runs end to end");
        assert_eq!(exit, 1, "a failing case must exit nonzero");

        let _ = std::fs::remove_dir_all(&dir);
    }

    const PARTIAL_COVERAGE_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false

  allow if {
      input.request.method == "GET"
      input.request.path == "/health"
  }
cases:
  - name: post never matches
    input:
      request:
        method: POST
        path: /health
    expect: false
  - name: put never matches either
    input:
      request:
        method: PUT
        path: /health
    expect: false
"#;

    #[test]
    fn rego_test_min_coverage_below_actual_passes_above_actual_fails() {
        // Both cases fail the rule's first condition (method is never
        // GET), so by Rego's own short-circuit body semantics the second
        // condition (`input.request.path`) never executes across the
        // whole fixture: coverage is guaranteed strictly between 0% and
        // 100%, without this test depending on Regorus's exact line
        // attribution to know which percentage that is.
        let dir = rego_test_scratch_dir("coverage");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, PARTIAL_COVERAGE_FIXTURE).expect("write fixture");

        let baseline = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the fixture parses and its module compiles");
        assert_eq!(baseline.failed, 0, "{baseline:?}");
        assert!(
            baseline.coverage_percent > 0.0 && baseline.coverage_percent < 100.0,
            "the short-circuited branch must leave coverage partial: {baseline:?}"
        );

        let below = run_rego_tests(
            std::slice::from_ref(&fixture_path),
            Some(baseline.coverage_percent - 0.01),
        )
        .expect("reruns cleanly");
        assert!(
            below.coverage_ok,
            "a --min-coverage below actual coverage must pass: {below:?}"
        );

        let above = run_rego_tests(
            std::slice::from_ref(&fixture_path),
            Some(baseline.coverage_percent + 0.01),
        )
        .expect("reruns cleanly");
        assert!(
            !above.coverage_ok,
            "a --min-coverage above actual coverage must fail: {above:?}"
        );

        let exit_below = handle_rego_test(&RegoTestArgs {
            path: fixture_path.clone(),
            min_coverage: Some(baseline.coverage_percent - 0.01),
            format: OutputFormat::Text,
        })
        .expect("the handler runs end to end");
        assert_eq!(exit_below, 0, "below-threshold coverage must still exit 0");

        let exit_above = handle_rego_test(&RegoTestArgs {
            path: fixture_path,
            min_coverage: Some(baseline.coverage_percent + 0.01),
            format: OutputFormat::Text,
        })
        .expect("the handler runs end to end");
        assert_eq!(exit_above, 1, "above-threshold coverage must exit nonzero");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rego_test_discovers_fixtures_recursively_in_a_directory() {
        let dir = rego_test_scratch_dir("discovery");
        let nested = dir.join("nested");
        std::fs::create_dir_all(&nested).expect("nested dir");
        let fixture_path = nested.join("authz_test.yaml");
        std::fs::write(&fixture_path, PASSING_FIXTURE).expect("write fixture");
        // A file that must not be picked up: wrong suffix.
        std::fs::write(dir.join("notes.txt"), "not a fixture").expect("write decoy");

        let (found, discovery_errors) =
            discover_rego_test_fixtures(&dir).expect("directory is readable");
        assert_eq!(
            found,
            vec![fixture_path],
            "only the *_test.yaml file must be discovered, found recursively"
        );
        assert!(discovery_errors.is_empty(), "{discovery_errors:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- fix round 1 (review findings) ---

    const COLOCATED_MODULE_SOURCE: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
}
"#;

    const COLOCATED_MODULE_PATH_FIXTURE: &str = r#"
module_path: policy.rego
cases:
  - name: get is allowed
    input:
      request:
        method: GET
    expect: true
  - name: post is denied
    input:
      request:
        method: POST
    expect: false
"#;

    #[test]
    fn rego_test_module_path_resolves_against_the_fixture_directory_not_the_cwd() {
        // Finding 1: a bare `module_path: policy.rego` in a fixture
        // discovered by a directory sweep must resolve against the
        // fixture's OWN directory. The process's real cwd (wherever
        // `cargo test` runs from) has no `policy.rego` at all, so if
        // resolution fell back to it, this would fail to read the
        // module and land in `output.errors` instead of passing.
        let dir = rego_test_scratch_dir("colocated-module");
        let nested = dir.join("policies").join("authz");
        std::fs::create_dir_all(&nested).expect("nested dir");
        std::fs::write(nested.join("policy.rego"), COLOCATED_MODULE_SOURCE)
            .expect("write colocated module");
        std::fs::write(
            nested.join("policy_test.yaml"),
            COLOCATED_MODULE_PATH_FIXTURE,
        )
        .expect("write fixture");

        let (found, discovery_errors) =
            discover_rego_test_fixtures(&dir).expect("directory is readable");
        assert_eq!(found, vec![nested.join("policy_test.yaml")], "{found:?}");
        assert!(discovery_errors.is_empty(), "{discovery_errors:?}");

        let output = run_rego_tests(&found, None).expect("the sweep itself does not fail");
        assert!(
            output.errors.is_empty(),
            "a bare module_path must resolve against the fixture's own directory: {output:?}"
        );
        assert_eq!(output.failed, 0, "{output:?}");
        assert_eq!(output.passed, 2, "{output:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    const BROKEN_FIXTURE: &str = r#"
module: |
  not rego at all
cases:
  - name: whatever
    expect: true
"#;

    #[test]
    fn rego_test_one_broken_fixture_does_not_discard_the_others_results() {
        // Finding 2: a directory sweep with one good fixture and one
        // broken one must still report the good fixture's results, and
        // name the broken one and its error, rather than aborting the
        // whole batch.
        let dir = rego_test_scratch_dir("mixed-batch");
        std::fs::write(dir.join("good_test.yaml"), PASSING_FIXTURE).expect("write good fixture");
        std::fs::write(dir.join("broken_test.yaml"), BROKEN_FIXTURE).expect("write broken fixture");

        let (found, discovery_errors) =
            discover_rego_test_fixtures(&dir).expect("directory is readable");
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(discovery_errors.is_empty(), "{discovery_errors:?}");

        let output = run_rego_tests(&found, None).expect("the sweep itself does not fail");
        assert_eq!(
            output.errors.len(),
            1,
            "exactly the broken fixture must be recorded as errored: {output:?}"
        );
        assert!(
            output.errors[0].fixture.ends_with("broken_test.yaml"),
            "the error must name the broken fixture: {output:?}"
        );
        assert_eq!(
            output.passed, 2,
            "the good fixture's cases must still run and pass: {output:?}"
        );
        assert_eq!(output.failed, 0, "{output:?}");
        assert_eq!(
            output.exit_code(),
            2,
            "a fixture error must exit 2, beating any case/coverage verdict: {output:?}"
        );

        let exit = handle_rego_test(&RegoTestArgs {
            path: dir.clone(),
            min_coverage: None,
            format: OutputFormat::Text,
        })
        .expect("the handler runs end to end");
        assert_eq!(exit, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    const ZERO_BUDGET_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false

  allow if {
      input.request.method == "GET"
  }
budget_ms: 0
cases:
  - name: get is allowed
    input:
      request:
        method: GET
    expect: true
"#;

    #[test]
    fn rego_test_fixture_zero_budget_ms_is_refused_with_a_clear_message() {
        // Finding 3: `budget_ms: 0` must be caught at the fixture layer
        // with the same message shape `RegoPolicy::new` uses in
        // production, rather than reaching `CompiledRego::compile`'s
        // load-time trial and surfacing a misleading "semantic fault".
        let dir = rego_test_scratch_dir("zero-budget");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, ZERO_BUDGET_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the sweep itself does not fail");
        assert_eq!(output.errors.len(), 1, "{output:?}");
        assert!(
            output.errors[0]
                .error
                .contains("budget_ms must be greater than zero"),
            "must name the same invariant production's RegoPolicy::new refuses on: {output:?}"
        );
        assert!(
            !output.errors[0].error.contains("semantic fault"),
            "must not surface the misleading load-time-trial message: {output:?}"
        );
        assert_eq!(output.exit_code(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    const BOTH_MODULE_FIELDS_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false
module_path: policy.rego
cases:
  - name: whatever
    expect: false
"#;

    #[test]
    fn rego_test_fixture_with_both_module_and_module_path_is_refused() {
        // Finding 4.
        let dir = rego_test_scratch_dir("both-module-fields");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, BOTH_MODULE_FIELDS_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the sweep itself does not fail");
        assert_eq!(output.errors.len(), 1, "{output:?}");
        assert!(output.errors[0].error.contains("not both"), "{output:?}");
        assert_eq!(output.exit_code(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    const NEITHER_MODULE_FIELD_FIXTURE: &str = r#"
cases:
  - name: whatever
    expect: false
"#;

    #[test]
    fn rego_test_fixture_with_neither_module_nor_module_path_is_refused() {
        // Finding 4.
        let dir = rego_test_scratch_dir("neither-module-field");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, NEITHER_MODULE_FIELD_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the sweep itself does not fail");
        assert_eq!(output.errors.len(), 1, "{output:?}");
        assert!(output.errors[0].error.contains("module_path"), "{output:?}");
        assert_eq!(output.exit_code(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    const EMPTY_CASES_FIXTURE: &str = r#"
module: |
  package sbproxy

  default allow := false
cases: []
"#;

    #[test]
    fn rego_test_fixture_with_no_cases_is_refused() {
        // Finding 4.
        let dir = rego_test_scratch_dir("empty-cases");
        let fixture_path = dir.join("authz_test.yaml");
        std::fs::write(&fixture_path, EMPTY_CASES_FIXTURE).expect("write fixture");

        let output = run_rego_tests(std::slice::from_ref(&fixture_path), None)
            .expect("the sweep itself does not fail");
        assert_eq!(output.errors.len(), 1, "{output:?}");
        assert!(output.errors[0].error.contains("no `cases`"), "{output:?}");
        assert_eq!(output.exit_code(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- fix round 2 (residual review finding: the discovery walk
    // itself must isolate its own I/O faults, not just fixture faults)
    // ---

    #[cfg(unix)]
    #[test]
    fn rego_test_unreadable_subdirectory_does_not_abort_the_sweep() {
        use std::os::unix::fs::PermissionsExt;

        /// Restores `path` to `mode` on drop, including during a
        /// panic's unwind, so a failed assertion between locking the
        /// directory down and this test's own explicit restore cannot
        /// leave the scratch directory permanently un-removable at
        /// 0o000. Hand-rolled rather than the `scopeguard` crate:
        /// `scopeguard` is not a dependency of `crates/sbproxy` and
        /// this is the minimal equivalent for exactly this one use.
        struct RestorePermissionsOnDrop {
            path: PathBuf,
            mode: u32,
        }

        impl Drop for RestorePermissionsOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(
                    &self.path,
                    std::fs::Permissions::from_mode(self.mode),
                );
            }
        }

        let dir = rego_test_scratch_dir("unreadable-subdir");
        std::fs::write(dir.join("good_test.yaml"), PASSING_FIXTURE).expect("write good fixture");
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).expect("locked dir");
        // A fixture inside `locked` that must never surface, proving the
        // directory was genuinely skipped rather than merely empty.
        std::fs::write(locked.join("hidden_test.yaml"), PASSING_FIXTURE)
            .expect("write hidden fixture");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock down the subdirectory");
        let restore = RestorePermissionsOnDrop {
            path: locked.clone(),
            mode: 0o700,
        };

        if std::fs::read_dir(&locked).is_ok() {
            // Running with a privilege (commonly root, or some CI
            // sandboxes) that bypasses the owner-permission bits this
            // test depends on. `restore` still fires on the way out;
            // nothing to assert against an enforcement the OS never
            // actually applied here.
            drop(restore);
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // `locked` stays 0o000 through both calls below: the direct
        // discovery call and `handle_rego_test`'s own internal
        // re-discovery must see the SAME unreadable directory, not one
        // this test already relaxed after the first call.
        let (found, discovery_errors) =
            discover_rego_test_fixtures(&dir).expect("the sweep itself does not fail");
        assert_eq!(
            found,
            vec![dir.join("good_test.yaml")],
            "the good fixture outside the locked directory must still be found: {found:?}"
        );
        assert_eq!(discovery_errors.len(), 1, "{discovery_errors:?}");
        assert!(
            discovery_errors[0].fixture.ends_with("locked"),
            "the error must name the unreadable directory: {discovery_errors:?}"
        );

        let output = run_rego_tests(&found, None).expect("the sweep itself does not fail");
        assert_eq!(
            output.passed, 2,
            "the good fixture's cases must still run: {output:?}"
        );
        assert_eq!(output.failed, 0, "{output:?}");

        let exit = handle_rego_test(&RegoTestArgs {
            path: dir.clone(),
            min_coverage: None,
            format: OutputFormat::Text,
        })
        .expect("the handler runs end to end");
        assert_eq!(
            exit, 2,
            "an unreadable subdirectory must exit 2, same as a broken fixture"
        );

        drop(restore);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_audit_verify_subcommand_with_key_channel() {
        let cli = parse(&[
            "sbproxy",
            "audit",
            "verify",
            "/var/lib/sbproxy/key-audit.jsonl",
            "--channel",
            "key",
        ]);
        match cli.cmd {
            Some(Cmd::Audit(cmd)) => match cmd.sub {
                AuditSub::Verify(args) => {
                    assert_eq!(args.channel, "key");
                }
            },
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    #[test]
    fn parses_audit_verify_subcommand_with_admin_channel() {
        let cli = parse(&[
            "sbproxy",
            "audit",
            "verify",
            "/var/lib/sbproxy/admin-audit.jsonl",
            "--channel",
            "admin",
        ]);
        match cli.cmd {
            Some(Cmd::Audit(cmd)) => match cmd.sub {
                AuditSub::Verify(args) => {
                    assert_eq!(args.channel, "admin");
                }
            },
            other => panic!("expected Audit, got {other:?}"),
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
        let _env = EnvVarGuard::set(&[("SB_LOG_FORMAT", Some("json"))]);
        let cli = Cli::try_parse_from(["sbproxy", "cfg.yml"]).expect("env fallback should parse");
        assert_eq!(cli.globals.log_format, Some(LogFormat::Json));
    }

    #[test]
    fn log_format_unset_yields_compact_default() {
        let _env = EnvVarGuard::set(&[("SB_LOG_FORMAT", None)]);
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

    #[test]
    fn runtime_telemetry_config_rejects_unsupported_propagation_at_boot_validation() {
        let raw = sbproxy_config::ObservabilityTelemetryConfig {
            enabled: true,
            propagation: Some("b3".to_string()),
            ..sbproxy_config::ObservabilityTelemetryConfig::default()
        };

        let mapped = runtime_telemetry_config(&raw);
        let error = mapped
            .validate_propagation()
            .expect_err("b3 propagation is not wired");
        let message = error.to_string();
        assert!(message.contains("b3"), "{message}");
        assert!(message.contains("w3c"), "{message}");
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
        let env = EnvVarGuard::set(&[("SB_DISABLE_SB_FLAGS", None)]);
        for v in ["1", "true", "TRUE", "yes", "on", "YES", " On "] {
            env.update("SB_DISABLE_SB_FLAGS", v);
            assert!(env_disable_sb_flags(), "expected truthy for {v}");
        }
    }

    #[test]
    fn env_disable_sb_flags_rejects_other_values() {
        let env = EnvVarGuard::set(&[("SB_DISABLE_SB_FLAGS", None)]);
        for v in ["0", "false", "no", "off", ""] {
            env.update("SB_DISABLE_SB_FLAGS", v);
            assert!(!env_disable_sb_flags(), "expected falsy for '{v}'");
        }
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

    #[test]
    fn serve_locked_flag_parses_on_serve_and_bare_run_forms() {
        let serve = Cli::try_parse_from(["sbproxy", "serve", "sb.yml", "--locked"]).unwrap();
        assert!(serve.locked);
        assert!(matches!(serve.cmd, Some(Cmd::Serve(_))));

        let bare = Cli::try_parse_from(["sbproxy", "--locked", "sb.yml"]).unwrap();
        assert!(bare.locked);
        assert!(bare.cmd.is_none());
        assert_eq!(bare.config_path, Some(PathBuf::from("sb.yml")));

        // Without the flag, the run form parses exactly as before.
        let unlocked = Cli::try_parse_from(["sbproxy", "serve", "sb.yml"]).unwrap();
        assert!(!unlocked.locked);
    }

    #[test]
    fn read_serve_lockfile_missing_file_is_a_distinct_error() {
        let path = std::env::temp_dir().join(format!(
            "sbproxy-locked-test-{}-missing/sbproxy-models.lock",
            std::process::id()
        ));
        let error = read_serve_lockfile(&path).expect_err("a missing lockfile must not pass");
        let message = error.to_string();
        assert!(message.contains("no lockfile at"), "got: {message}");
        assert!(
            message.contains("run sbproxy models lock"),
            "got: {message}"
        );
    }

    #[test]
    fn read_serve_lockfile_reads_back_a_written_lockfile() {
        let marker = temp_config("");
        let path = marker.with_extension("lock");
        let lockfile = sbproxy_model_host::Lockfile::new(1, "cli-fixture".to_string(), Vec::new());
        sbproxy_model_host::write_lockfile(&path, &lockfile).unwrap();
        let read = read_serve_lockfile(&path).expect("written lockfile must read back");
        assert_eq!(read, lockfile);
        let _ = std::fs::remove_file(marker);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enforce_locked_serve_refuses_when_no_lockfile_exists() {
        // A config directory without sbproxy-models.lock refuses before
        // touching the config, the cache, or any listener. The config
        // lives in its own directory so a stray lockfile in the shared
        // temp dir cannot turn the refusal into a pass.
        let dir = std::env::temp_dir().join(format!("sbproxy-locked-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("sb.yml");
        std::fs::write(&config, MINIMAL_VALID).unwrap();
        let error = enforce_locked_serve(&config).expect_err("no lockfile must refuse to serve");
        assert!(
            error.to_string().contains("no lockfile at"),
            "got: {error:#}"
        );
        let _ = std::fs::remove_dir_all(dir);
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
            no_fetch: false,
        }
    }

    /// `validate -f <path>` and `validate --config <path>` must reach the
    /// handler with a path.
    ///
    /// Both forms are advertised: the field's own doc comment says
    /// "Equivalent to `-f <path>`", the missing-path error prints
    /// `sbproxy validate --config <path>` as a usage line, and fifteen
    /// lines across `examples/` and `docs/payment-settlement.md` invoke
    /// the flag form. None of them worked, because `-f/--config` is a
    /// global and parses into `cli.globals` rather than into this
    /// subcommand's positional, so clap accepted the command line and
    /// the handler then reported a missing path. Nothing caught it:
    /// every existing test here constructs `ValidateArgs` directly and
    /// so never goes through clap.
    #[test]
    fn validate_accepts_the_config_flag_it_documents() {
        for argv in [
            ["sbproxy", "validate", "-f", "sb.yml"],
            ["sbproxy", "validate", "--config", "sb.yml"],
        ] {
            let cli = parse(&argv);
            let Some(Cmd::Validate(args)) = cli.cmd else {
                panic!("{argv:?} must parse as the validate subcommand");
            };
            assert_eq!(
                args.config_path.or(cli.globals.config),
                Some(PathBuf::from("sb.yml")),
                "{argv:?} must resolve a config path for the handler"
            );
        }
    }

    /// A positional path wins over the global flag when both are given,
    /// so `-f` cannot silently retarget an explicit argument.
    #[test]
    fn validate_positional_path_wins_over_the_config_flag() {
        let cli = parse(&["sbproxy", "validate", "positional.yml", "-f", "flag.yml"]);
        let Some(Cmd::Validate(args)) = cli.cmd else {
            panic!("must parse as the validate subcommand");
        };
        assert_eq!(
            args.config_path.or(cli.globals.config),
            Some(PathBuf::from("positional.yml"))
        );
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

    fn temp_extension_config(
        entry_source: &str,
        action_type: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let path = temp_config("");
        let bundle_directory_name = format!(
            "{}-bundles",
            path.file_stem()
                .expect("temporary config has a file stem")
                .to_string_lossy()
        );
        let bundle_root = path
            .parent()
            .expect("temporary config has a parent")
            .join(&bundle_directory_name)
            .join("validate-action");
        std::fs::create_dir_all(&bundle_root).expect("create validation bundle directory");
        std::fs::write(bundle_root.join("entry.js"), entry_source)
            .expect("write validation bundle entry");
        std::fs::write(
            bundle_root.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: validate-action
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: validate_action
    export: run
"#,
        )
        .expect("write validation bundle manifest");
        std::fs::write(
            &path,
            format!(
                "extensions:\n  bundles_dir: {bundle_directory_name}\norigins:\n  extension.local:\n    action:\n      type: {action_type}\n"
            ),
        )
        .expect("write extension config");

        let bundle_directory = bundle_root
            .parent()
            .expect("bundle root has a parent directory")
            .to_path_buf();
        (path, bundle_directory)
    }

    fn temp_model_cli_extension_config() -> (std::path::PathBuf, std::path::PathBuf) {
        let path = temp_config("");
        let bundle_directory_name = format!(
            "{}-bundles",
            path.file_stem()
                .expect("temporary config has a file stem")
                .to_string_lossy()
        );
        let bundle_directory = path
            .parent()
            .expect("temporary config has a parent")
            .join(&bundle_directory_name);
        let bundle_root = bundle_directory.join("model-cli-chain");
        std::fs::create_dir_all(&bundle_root).expect("create model CLI bundle directory");
        std::fs::write(
            bundle_root.join("entry.js"),
            r#"export function respond() {
  return { version: "sbproxy-envelope/v1", outcome: "response", status: 204, headers: [], body_base64: "" };
}
export function allow() {
  return { version: "sbproxy-envelope/v1", decision: "allow" };
}
export function transform() {
  return { version: "sbproxy-envelope/v1", body_base64: "" };
}
"#,
        )
        .expect("write model CLI bundle entry");
        std::fs::write(
            bundle_root.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: model-cli-chain
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: model_cli_action
    export: respond
  - kind: policy
    type: model_cli_policy
    export: allow
  - kind: transform
    type: model_cli_transform
    export: transform
"#,
        )
        .expect("write model CLI bundle manifest");
        std::fs::write(
            &path,
            format!(
                "extensions:\n  bundles_dir: {bundle_directory_name}\norigins:\n  model-cli.local:\n    action:\n      type: model_cli_action\n    policies:\n      - type: model_cli_policy\n    transforms:\n      - type: model_cli_transform\n"
            ),
        )
        .expect("write model CLI extension config");
        (path, bundle_directory)
    }

    #[test]
    fn validate_loads_dynamic_action_bundle_relative_to_config() {
        let (path, bundle_directory) = temp_extension_config(
            r#"export function run() {
                return {
                    version: "sbproxy-envelope/v1",
                    outcome: "response",
                    status: 204,
                    headers: [],
                    body_base64: ""
                };
            }"#,
            "validate_action",
        );

        let outcome = handle_validate_subcommand(&validate_args(&path, false));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(bundle_directory);
        assert_eq!(outcome.expect("dynamic action config should validate"), 0);
    }

    #[test]
    fn model_cli_artifact_protection_loads_the_relative_dynamic_chain() {
        let (path, bundle_directory) = temp_model_cli_extension_config();
        let worker = sbproxy_model_host::WorkerProfile {
            accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
            compute_capability: None,
            memory_bytes: u64::MAX,
            engines: std::collections::BTreeSet::new(),
        };

        let outcome =
            configured_artifact_protection(&path, &sbproxy_model_host::Catalog::builtin(), &worker);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(bundle_directory);
        outcome.expect("model pull and remove should load the configured extension chain");
    }

    #[test]
    fn validate_rejects_invalid_unreferenced_extension_bundle() {
        let (path, bundle_directory) =
            temp_extension_config("export function anotherName() {}", "static");

        let error = handle_validate_subcommand(&validate_args(&path, false))
            .expect_err("an invalid configured bundle must fail validation even when unreferenced");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(bundle_directory);
        assert!(format!("{error:#}").contains("export"), "{error:#}");
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
    fn validate_rejects_unsupported_propagation_that_boot_rejects() {
        let path = temp_config(
            "proxy:\n  http_bind_port: 8080\n  observability:\n    telemetry:\n      propagation: b3\norigins:\n  \"x.local\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n",
        );
        let err = handle_validate_subcommand(&validate_args(&path, false))
            .expect_err("propagation: b3 must fail validate the same way it fails boot");
        let message = format!("{err:#}");
        assert!(message.contains("b3"), "{message}");
        assert!(message.contains("w3c"), "{message}");
        assert_eq!(
            handle_validate_subcommand(&validate_args(&path, true)).unwrap(),
            2
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_rejects_export_metrics_without_enabled_that_boot_rejects() {
        let path = temp_config(
            "proxy:\n  http_bind_port: 8080\n  observability:\n    telemetry:\n      export_metrics: true\norigins:\n  \"x.local\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n",
        );
        assert!(handle_validate_subcommand(&validate_args(&path, false)).is_err());
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
    fn validate_gates_mesh_compression_on_cluster_replication() {
        fn mesh_compression_config(replication_block: &str) -> String {
            format!(
                r#"proxy:
  cluster:
    cluster_id: compression-test
    node_id: gateway-a
    roles: [gateway]
    seeds: ["127.0.0.1:17946"]
    gossip_port: 17946
    transport_port: 18946
    advertise_addr: "127.0.0.1:17946"
    transport_advertise_addr: "127.0.0.1:18946"
    state_dir: ./state/compression-test
{replication_block}    security:
      mode: shared_key
      development: true
      shared_key: validation-only-secret
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: primary
          api_key: test-key
          models: [gpt-4o]
        - name: summarizer
          api_key: test-key
          models: [gpt-4o-mini]
      compression:
        state: {{ backend: mesh, ttl: 1h }}
        levers:
          - type: summary_buffer
            min_tokens: 100
            retain_recent_messages: 2
            target_summary_tokens: 20
            summarizer:
              provider: summarizer
              model: gpt-4o-mini
              timeout: 2s
"#
            )
        }

        // A cluster without a replication block cannot host mesh
        // compression state; boot and validation fail loud.
        let rejected = temp_config(&mesh_compression_config(""));
        assert!(handle_validate_subcommand(&validate_args(&rejected, false)).is_err());
        assert_eq!(
            handle_validate_subcommand(&validate_args(&rejected, true)).unwrap(),
            2
        );
        let _ = std::fs::remove_file(&rejected);

        // With cluster replication configured, backend: mesh validates.
        let accepted = temp_config(&mesh_compression_config(
            "    replication:\n      factor: 2\n",
        ));
        assert_eq!(
            handle_validate_subcommand(&validate_args(&accepted, false)).unwrap(),
            0
        );
        assert_eq!(
            handle_validate_subcommand(&validate_args(&accepted, true)).unwrap(),
            0
        );
        let _ = std::fs::remove_file(&accepted);
    }

    #[test]
    fn validate_rejects_unsupported_legacy_managed_fields() {
        let path = temp_config(
            "origins:\n  ai.local:\n    action:\n      type: ai_proxy\n      providers:\n        - name: local\n          serve:\n            models:\n              - model: qwen3-14b\n                engine: llama_cpp\n                speculative: {}\n",
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
            no_fetch: false,
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
            no_fetch: false,
            against: None,
            format: OutputFormat::Text,
            out: None,
            explain_origin: None,
        };
        assert_eq!(handle_plan_subcommand(&args).unwrap(), 2);
        // Plan against itself: no changes -> exit 0.
        let args = PlanArgs {
            config: Some(path.clone()),
            no_fetch: false,
            against: Some(path.clone()),
            format: OutputFormat::Text,
            out: None,
            explain_origin: None,
        };
        assert_eq!(handle_plan_subcommand(&args).unwrap(), 0);
        let _ = std::fs::remove_file(&path);
    }

    /// `--watch` refuses the one-shot flags rather than dropping them.
    ///
    /// It used to return before `--out` and `--explain` were read, so
    /// `aggregate --out f.yml --watch` looped POSTing composed documents
    /// to the admin API while the file was never written. On a node with
    /// an admin listener that is a fleet publish nobody asked for
    /// (WOR-2432 review, Major 5).
    #[test]
    fn aggregate_watch_refuses_the_one_shot_flags() {
        use clap::Parser as _;

        for conflicting in [
            vec!["--out", "composed.yml"],
            vec!["--explain", "api.example.com"],
            vec!["--out", "composed.yml", "--dry-run"],
        ] {
            let mut argv = vec!["sbproxy", "aggregate", "-f", "sb.yml", "--watch"];
            argv.extend(conflicting.iter().copied());
            let parsed = Cli::try_parse_from(&argv);
            assert!(
                parsed.is_err(),
                "`{}` must be refused rather than silently dropping a flag",
                argv.join(" ")
            );
        }

        // And each of them still parses on its own, so the conflict is
        // the pairing rather than the flag.
        for alone in [
            vec!["--out", "composed.yml"],
            vec!["--explain", "api.example.com"],
        ] {
            let mut argv = vec!["sbproxy", "aggregate", "-f", "sb.yml"];
            argv.extend(alone.iter().copied());
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "`{}` is a valid one-shot invocation",
                argv.join(" ")
            );
        }
        assert!(
            Cli::try_parse_from(["sbproxy", "aggregate", "-f", "sb.yml", "--watch"]).is_ok(),
            "and --watch on its own is valid"
        );
    }

    #[test]
    fn handle_plan_missing_config_is_usage_error() {
        let args = PlanArgs {
            config: None,
            no_fetch: false,
            against: None,
            format: OutputFormat::Text,
            out: None,
            explain_origin: None,
        };
        assert!(handle_plan_subcommand(&args).is_err());
    }

    // --- admin hash-password handler ---

    #[test]
    fn hash_password_with_no_config_uses_the_default_pepper() {
        let args = HashPasswordArgs {
            password: Some("hunter2".to_string()),
            password_stdin: false,
        };
        let mut out = Vec::new();
        let code = handle_admin_hash_password_to(&args, None, &mut out).unwrap();
        assert_eq!(code, 0);
        let printed = String::from_utf8(out).unwrap().trim().to_string();
        let expected = sbproxy_core::key_plane::hash_admin_operator_password(
            "hunter2",
            &sbproxy_core::key_plane::default_admin_operator_pepper(),
        );
        assert_eq!(printed, expected);
    }

    #[test]
    fn hash_password_prefers_a_pinned_key_management_pepper() {
        let path = temp_config(
            "proxy:\n  http_bind_port: 8080\n  key_management:\n    crypto:\n      pepper: pinned-pepper\norigins:\n  \"x.local\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n",
        );
        let args = HashPasswordArgs {
            password: Some("hunter2".to_string()),
            password_stdin: false,
        };
        let mut out = Vec::new();
        let code = handle_admin_hash_password_to(&args, Some(&path), &mut out).unwrap();
        assert_eq!(code, 0);
        let printed = String::from_utf8(out).unwrap().trim().to_string();
        let expected =
            sbproxy_core::key_plane::hash_admin_operator_password("hunter2", b"pinned-pepper");
        assert_eq!(printed, expected);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hash_password_requires_exactly_one_input_source() {
        let neither = HashPasswordArgs {
            password: None,
            password_stdin: false,
        };
        assert!(handle_admin_hash_password_to(&neither, None, &mut Vec::new()).is_err());

        let both = HashPasswordArgs {
            password: Some("x".to_string()),
            password_stdin: true,
        };
        assert!(handle_admin_hash_password_to(&both, None, &mut Vec::new()).is_err());
    }

    #[test]
    fn prompt_optimize_cli_parses_nested_contract() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "ai",
            "prompt",
            "optimize",
            "--prompt",
            "system.txt",
            "--eval-set",
            "eval.jsonl",
            "--endpoint",
            "http://127.0.0.1:8080/v1",
            "--host-header",
            "ai.local",
            "--task-model",
            "task",
            "--name",
            "answer",
            "--prompt-version",
            "2",
            "--output",
            "artifact.json",
        ])
        .expect("prompt optimizer CLI parses");
        let Some(Cmd::Ai(cmd)) = cli.cmd else {
            panic!("expected ai prompt optimize");
        };
        let AiSub::Prompt(prompt) = cmd.sub else {
            panic!("expected ai prompt optimize");
        };
        let PromptSub::Optimize(args) = prompt.sub else {
            panic!("expected ai prompt optimize");
        };
        assert_eq!(args.metric, PromptEvalMetricArg::ExactMatch);
        assert_eq!(args.max_candidates, 8);
        assert_eq!(args.max_requests, 256);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.host_header.as_deref(), Some("ai.local"));
        assert_eq!(args.prompt_version, "2");
    }

    #[test]
    fn orchestration_evaluation_and_rollout_have_supported_cli_surfaces() {
        for arguments in [
            vec![
                "sbproxy",
                "ai",
                "workflow",
                "discover",
                "--origin",
                "api.local",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
            vec![
                "sbproxy",
                "ai",
                "workflow",
                "validate",
                "workflow.yml",
                "--origin",
                "api.local",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
            vec![
                "sbproxy",
                "ai",
                "workflow",
                "run",
                "--origin",
                "api.local",
                "--workflow",
                "support",
                "--input",
                "input.json",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
            vec![
                "sbproxy",
                "ai",
                "dataset",
                "register",
                "--origin",
                "api.local",
                "--dataset",
                "dataset.json",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
            vec![
                "sbproxy",
                "ai",
                "evaluate",
                "--origin",
                "api.local",
                "--dataset",
                "support",
                "--version",
                "2",
                "--responses",
                "responses.json",
                "--experiment-id",
                "run-1",
                "--experiment-name",
                "candidate",
                "--model",
                "model-a",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
            vec![
                "sbproxy",
                "ai",
                "prompt",
                "select",
                "--origin",
                "api.local",
                "--name",
                "support",
                "--cohort",
                "customer-1",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
            ],
        ] {
            Cli::try_parse_from(arguments).expect("shipping AI CLI seam must parse");
        }
    }

    #[test]
    fn evaluation_dataset_version_is_distinct_from_global_version_flag() {
        let cli = Cli::try_parse_from([
            "sbproxy",
            "ai",
            "evaluate",
            "--origin",
            "api.local",
            "--dataset",
            "support",
            "--version",
            "2",
            "--responses",
            "responses.json",
            "--experiment-id",
            "run-1",
            "--experiment-name",
            "candidate",
            "--model",
            "model-a",
            "--admin-url",
            "http://127.0.0.1:9090",
            "--password",
            "secret",
        ])
        .expect("evaluation dataset version must parse without selecting CLI version output");

        assert!(!cli.version);
        let Some(Cmd::Ai(cmd)) = cli.cmd else {
            panic!("expected ai evaluate command");
        };
        let AiSub::Evaluate(args) = cmd.sub else {
            panic!("expected ai evaluate command");
        };
        assert_eq!(args.version, 2);
    }

    #[test]
    fn toolkit_cli_has_no_agent_token_or_inline_secret_option() {
        for forbidden in ["--agent-token", "--shared-secret", "--judge-api-key"] {
            let parsed = Cli::try_parse_from([
                "sbproxy",
                "ai",
                "workflow",
                "run",
                "--origin",
                "api.local",
                "--workflow",
                "support",
                "--input",
                "input.json",
                "--admin-url",
                "http://127.0.0.1:9090",
                "--password",
                "secret",
                forbidden,
                "private-value",
            ]);
            assert!(parsed.is_err(), "forbidden credential option {forbidden}");
        }
    }

    #[test]
    fn toolkit_cli_bounds_the_final_aggregate_admin_request() {
        let small = serde_json::json!({"responses": ["bounded"]});
        validate_ai_toolkit_admin_body("ai evaluate", Some(&small))
            .expect("small aggregate is admitted");

        let oversized = serde_json::json!({
            "responses": ["x".repeat(MAX_AI_TOOLKIT_DOCUMENT_BYTES)]
        });
        let error = validate_ai_toolkit_admin_body("ai evaluate", Some(&oversized))
            .expect_err("envelope pushes request over the shared cap");
        assert!(error.to_string().contains("aggregate limit"));
    }

    #[test]
    fn bounded_admin_json_accepts_exact_limit_and_refuses_the_next_byte() {
        let exact = br#"{"ok":true}"#;
        let value = read_bounded_admin_json(std::io::Cursor::new(exact), exact.len(), "AI toolkit")
            .expect("an exact-limit admin response is admitted");
        assert_eq!(value, serde_json::json!({"ok": true}));

        let mut oversized = exact.to_vec();
        oversized.push(b' ');
        let error =
            read_bounded_admin_json(std::io::Cursor::new(oversized), exact.len(), "AI toolkit")
                .expect_err("one byte over the admin response limit is refused");
        assert_eq!(
            error.to_string(),
            format!(
                "AI toolkit admin response exceeds the {} byte limit",
                exact.len()
            )
        );
    }

    /// An admin body that is present but not JSON has to stay
    /// distinguishable from a JSON `null` and from no body at all, or a
    /// reverse proxy's HTML error page leaves the operator a bare status
    /// code with nothing naming who answered.
    #[test]
    fn bounded_admin_json_marks_a_non_json_body_rather_than_dropping_it() {
        let html = b"<html><head><title>502 Bad Gateway</title></head></html>";
        let value = read_bounded_admin_json(std::io::Cursor::new(html), html.len(), "AI toolkit")
            .expect("a non-JSON body under the limit is still admitted");
        assert_eq!(value["code"], "non_json_response");
        let error = value["error"].as_str().expect("marker carries a reason");
        assert!(error.contains("502 Bad Gateway"), "{error}");
        assert!(error.contains(&html.len().to_string()), "{error}");

        // A real JSON null, and an empty body, keep reading as Null.
        assert_eq!(
            read_bounded_admin_json(std::io::Cursor::new(b"null"), 8, "AI toolkit")
                .expect("null is valid JSON"),
            serde_json::Value::Null
        );
        assert_eq!(
            read_bounded_admin_json(std::io::Cursor::new(b""), 8, "AI toolkit")
                .expect("an empty body is not a discarded one"),
            serde_json::Value::Null
        );
    }

    #[test]
    fn toolkit_cli_refuses_an_oversized_response_from_the_selected_admin_url() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind admin fixture");
        let address = listener.local_addr().expect("read admin fixture address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept toolkit request");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("bound fixture request read");
            let mut request = Vec::new();
            let mut scratch = [0_u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = stream.read(&mut scratch).expect("read toolkit request");
                assert!(read > 0, "toolkit client closed before request headers");
                request.extend_from_slice(&scratch[..read]);
            }

            let body = format!(
                r#"{{"padding":"{}"}}"#,
                "x".repeat(MAX_AI_TOOLKIT_ADMIN_RESPONSE_BYTES)
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write oversized response headers");
            let _ = stream.write_all(body.as_bytes());
        });
        let admin = ModelsAdminArgs {
            admin_url: Some(format!("http://{address}")),
            username: Some("admin".to_string()),
            password: Some("private-test-password".to_string()),
        };

        let error = handle_ai_toolkit_admin(
            "ai workflow discover",
            &admin,
            reqwest::Method::GET,
            "/admin/ai-toolkit/agents?origin=api.local",
            None,
        )
        .expect_err("the stock toolkit CLI must cap an arbitrary admin response");
        server.join().expect("admin fixture exits");
        assert_eq!(
            error.to_string(),
            format!(
                "AI toolkit admin response exceeds the {MAX_AI_TOOLKIT_ADMIN_RESPONSE_BYTES} byte limit"
            )
        );
        assert!(!error.to_string().contains("private-test-password"));
    }

    #[test]
    fn bounded_cli_file_accepts_exact_limit_and_refuses_the_next_byte() {
        let path = temp_config("abcd");
        assert_eq!(
            read_bounded_cli_file(&path, 4, "test input").expect("exact-limit file is admitted"),
            b"abcd"
        );

        std::fs::write(&path, b"abcde").expect("grow fixture by one byte");
        let error = read_bounded_cli_file(&path, 4, "test input")
            .expect_err("one byte over the file limit is refused");
        assert_eq!(
            error.to_string(),
            format!("test input {} exceeds the 4 byte limit", path.display())
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cli_file_reader_keeps_the_opened_descriptor_after_replacement() {
        let path = temp_config("original");
        let opened = std::fs::File::open(&path).expect("open original descriptor");
        let replacement = temp_config("replacement");
        std::fs::rename(&replacement, &path).expect("replace path after opening descriptor");

        let bytes = read_bounded_cli_open_file(opened, &path, 32, "test input")
            .expect("opened descriptor remains authoritative");
        assert_eq!(bytes, b"original");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bounded_cli_file_reader_refuses_growth_after_open() {
        use std::io::Write as _;

        let path = temp_config("abcd");
        let opened = std::fs::File::open(&path).expect("open bounded descriptor");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open fixture for growth")
            .write_all(b"e")
            .expect("grow fixture after reader opened");

        let error = read_bounded_cli_open_file(opened, &path, 4, "test input")
            .expect_err("post-open growth is still bounded");
        assert_eq!(
            error.to_string(),
            format!("test input {} exceeds the 4 byte limit", path.display())
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn prompt_optimize_handler_writes_admin_ready_static_artifact() {
        use std::io::{Read as _, Write as _};

        fn read_request(stream: &mut std::net::TcpStream) {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut scratch = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut scratch).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&scratch[..read]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::to_string)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            while bytes.len() < header_end + content_length {
                let read = stream.read(&mut scratch).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&scratch[..read]);
            }
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for content in ["alpha", r#"["Return only the requested word."]"#, "alpha"] {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                let body = serde_json::json!({
                    "choices": [{"message": {"content": content}}]
                })
                .to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let prompt = temp_config(
            "You are a careful assistant. Return exactly the requested word and no other text.",
        );
        let eval_set = temp_config(r#"{"id":"one","input":"Say alpha","expected":"alpha"}"#);
        let output = temp_config("{}");
        let args = PromptOptimizeArgs {
            prompt: prompt.clone(),
            eval_set: eval_set.clone(),
            endpoint: format!("http://{address}/v1"),
            host_header: None,
            api_key_env: None,
            task_model: "task-model".to_string(),
            optimizer_model: None,
            metric: PromptEvalMetricArg::ExactMatch,
            noise_tolerance: 0.0,
            max_candidates: 1,
            max_requests: 3,
            timeout_secs: 5,
            name: "concise-answer".to_string(),
            prompt_version: "2".to_string(),
            output: output.clone(),
        };

        assert_eq!(handle_prompt_optimize(&args).unwrap(), 0);
        server.join().unwrap();
        let artifact: sbproxy_ai::prompt_optimizer::OptimizedPromptArtifact =
            serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(artifact.name, "concise-answer");
        assert_eq!(artifact.prompt_version.version, "2");
        assert_eq!(
            artifact.prompt_version.template,
            "Return only the requested word."
        );
        assert!(artifact.prompt_version.variables.is_empty());
        assert!(artifact.optimized_tokens < artifact.original_tokens);

        for path in [prompt, eval_set, output] {
            let _ = std::fs::remove_file(path);
        }
    }
}
