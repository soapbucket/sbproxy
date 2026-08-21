//! `sbproxy connect`: point the coding agents installed on this machine at
//! this gateway. `sbproxy disconnect`: put them back.
//!
//! Every other verb in this binary edits files this project owns. This one
//! touches a developer's own machine, so it holds itself to rules the rest of
//! the CLI does not need.
//!
//! # What it writes, and the two reasons that set is small
//!
//! One file: `$CODEX_HOME/sbproxy.config.toml`. Claude Code gets printed
//! exports. Cursor, Cline, and GitHub Copilot get printed instructions naming
//! the exact fields to fill in. Detection runs for all five either way,
//! because "Cursor is installed, here are its three fields, and Cline is not
//! installed so ignore that section" is the part a static page cannot do.
//!
//! **The first reason is that a separate profile file beats editing a shared
//! one.** `codex --profile <name>` layers `$CODEX_HOME/<name>.config.toml` on
//! top of the user's `config.toml` (verified against codex-cli 0.149.0:
//! `codex --help` documents the flag as "Layer `$CODEX_HOME/<name>.config.toml`
//! on top of the base user config"). So this verb creates a file that did not
//! exist, that nothing else owns, and that `disconnect` can simply delete. A
//! real `~/.codex/config.toml` carries trust decisions, marketplace
//! registrations, and per-plugin state; the safest edit to it is none.
//!
//! This is also what the one comparable shipped verb does. Ollama's
//! `ollama launch <tool>` (<https://ollama.com/blog/launch>) writes
//! `~/.codex/ollama-launch.config.toml` and runs `codex --profile
//! ollama-launch` rather than touching `config.toml`, detects each integration
//! with a `PATH` lookup, skips the write when the bytes already match, and
//! stages every write through a temp file and a rename. Where this verb
//! departs from it is `--dry-run`: `ollama launch` asks for confirmation
//! instead, which shows the operator nothing and cannot run in CI.
//!
//! **The second reason is that three of the five clients have no file worth
//! writing.** Cursor, Cline, and Copilot BYOK are settings screens backed by
//! the VS Code / Electron `state.vscdb` SQLite store plus OS secret storage.
//! Ollama does write into `state.vscdb`, and reading what it writes is the
//! argument against doing it: the SQLite write only flips a model-picker
//! visibility flag, the connection itself comes from a JSON file, and the
//! write is guarded by a process check and a prompt to quit the editor first.
//! A cosmetic write that needs the editor shut down is not a thing to put
//! behind an unattended CLI verb. Ollama ships integrations for Codex,
//! Copilot, Cline, and a dozen more, and none for Cursor.
//!
//! # It does not take a credential
//!
//! Deliberate, and possible because Codex supports env-var indirection:
//! `model_providers.<id>.env_key` names the variable Codex reads the key out
//! of, so the file holds the name of the secret and never the secret. Claude
//! Code reads `ANTHROPIC_AUTH_TOKEN` from the environment the same way.
//!
//! That is also the norm among CLIs that do write credentials: `aws configure`
//! creates `~/.aws/credentials` at 0600 and warns when the mode is looser,
//! `gh auth login` prefers the OS keyring and prints "Authentication
//! credentials saved in plain text" when it cannot, and `docker login` says
//! the same about `config.json`. Indirection is available here, so the
//! stronger option is the one to take.
//!
//! Because nothing written is a secret, a shared machine and a config file
//! that is not mode 0600 are not this verb's problem to solve. It still
//! reports a group- or world-readable destination rather than silently
//! tightening it: the mode of somebody's own file is their decision, and a CLI
//! that quietly changes it is the class of surprise this module exists to
//! avoid. Mode is preserved across a rewrite for the same reason, so a 0600
//! file does not come back 0644 at this process's umask.
//!
//! If a client is ever added that has a config file and no env indirection,
//! that is a new decision and it belongs in this comment, not in a `--key`
//! flag added on the way past.
//!
//! # Never clobber, write atomically, be reversible
//!
//! The Codex edit is a structural TOML edit through `toml_edit`, so comments,
//! key order, and every unrelated table survive even in a file the operator
//! has hand-edited. Anything that cannot be edited structurally (a
//! `model_providers` that is not a table) is refused with a message naming the
//! key, never overwritten. `apply` re-reads the file and refuses if it
//! changed since the plan was built, so a diff the operator approved is the
//! diff that lands.
//!
//! `replace_atomically` stages a sibling temp file, fsyncs it, renames it
//! over the destination, and fsyncs the directory. The destination is never
//! opened for writing, so no reader ever sees a truncated config.
//!
//! The rename is the boundary between "nothing happened" and "it happened".
//! A failure before it is a failure: the destination still holds every old
//! byte and the run says so. A failure of the directory fsync *after* it is
//! not, because the new bytes are already there;
//! `Durability::NotSynced` carries that case so the run reports a write
//! that landed and is not yet crash-proof rather than a write that did not
//! happen. `sync_all` on macOS is `F_FULLFSYNC`, which answers ENOTSUP on an
//! SMB- or FUSE-mounted home, so this is somebody's every run rather than a
//! rare race, and telling them nothing was written when a file now exists is
//! the one report that leaves them unable to undo it.
//!
//! # Nothing this verb takes away exists in only one place
//!
//! The first change to a file copies the original to `<path>.sbproxy.bak`, and
//! that copy is never overwritten afterwards, so the pristine original stays
//! recoverable no matter how many times `connect` runs.
//!
//! A removal needs its own copy, and for a while it did not have one. The
//! `.bak` holds the file as it was before the *first* `connect`, so a
//! `disconnect` that leaned on it deleted every hand edit made since. So
//! `Destination::Remove` carries the path it stages the current bytes at,
//! `<path>.sbproxy.removed`, and carries it unconditionally: a removal cannot
//! be constructed without somewhere for its bytes to go, which is why a third
//! direction added later cannot quietly reintroduce the hole. `apply` copies
//! before it unlinks, and refuses up front when `<path>.sbproxy.removed`
//! already holds something else, because overwriting the rescue copy is the
//! same defect one level down.
//!
//! `--dry-run` prints the unified diff and touches nothing. Every run ends by
//! printing the command that undoes it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Named provider this verb registers, and the Codex profile it registers it
/// in. One string so a rename cannot half-apply.
const PROVIDER_NAME: &str = "sbproxy";

/// Suffix appended to a config path for the one-time pre-change backup.
const BACKUP_SUFFIX: &str = ".sbproxy.bak";

/// Suffix appended to a config path for the copy a removal stages before it
/// unlinks. Distinct from [`BACKUP_SUFFIX`] on purpose: the `.bak` is the file
/// as it was before the first `connect`, this is the file as it was at the
/// moment `disconnect` took it away, and collapsing the two is what made a
/// second `disconnect` lossy.
const REMOVED_SUFFIX: &str = ".sbproxy.removed";

/// Environment variable Codex is told to read the gateway key from.
const CODEX_ENV_KEY: &str = "SBPROXY_API_KEY";

/// Codex's own wire selector. `"chat"` was accepted once and is not any more:
/// codex-cli 0.149.0 refuses to load a provider carrying it, with the error
/// "`wire_api = \"chat\"` is no longer supported. How to fix: set `wire_api =
/// \"responses\"` in your provider config." `docs/use-case-connect-codex.md`
/// still told operators to write `chat`, which is why that page is gone.
const CODEX_WIRE_API: &str = "responses";

/// Default gateway base URL: the loopback data-plane port `sbproxy run` and
/// every shipped connect example bind.
pub(crate) const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080/v1";

/// Largest client config this verb will read into memory. The files it edits
/// are a few kilobytes; anything past this is not a config it understands, and
/// refusing beats rewriting it.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Per-side line ceiling for the unified diff. The diff table is quadratic, so
/// it is bounded rather than trusted; past this the printer reports line counts
/// instead. 2000 lines a side is ~16 MiB of table, and no client config in the
/// wild is close.
const MAX_DIFF_LINES: usize = 2000;

/// Lines of unchanged context the diff keeps around each change.
const DIFF_CONTEXT: usize = 3;

/// Header written at the top of a profile file this verb creates, so somebody
/// finding it in six months knows what made it and how to remove it.
const CODEX_PROFILE_HEADER: &str = "\
# Written by `sbproxy connect codex`.
#
# Codex layers this file over ~/.codex/config.toml when it runs as
# `codex --profile sbproxy`. Your own config.toml is not touched.
# Undo with `sbproxy disconnect codex`, or just delete this file.
";

// --- The machine this runs on ----------------------------------------

/// Everything about the host this verb reads, gathered once so the planner is
/// a pure function of it.
///
/// `path_dirs` is split here rather than inside the probe because
/// `sbproxy_model_host::resolve_on_path` reads the process `PATH` directly,
/// and `scripts/check-env-mutation.sh` refuses the `set_var` a unit test would
/// otherwise need to steer it. The executable predicate itself is still that
/// crate's, so there is one definition of what counts as runnable.
#[derive(Debug, Clone)]
struct Environment {
    /// The user's home directory, or `None` when neither `HOME` nor
    /// `USERPROFILE` is set.
    home: Option<PathBuf>,
    /// `CODEX_HOME`, which overrides `~/.codex` when Codex is installed with a
    /// relocated state directory.
    codex_home: Option<PathBuf>,
    /// `PATH`, already split into directories.
    path_dirs: Vec<PathBuf>,
}

impl Environment {
    /// Read the host environment. Nothing here mutates it.
    fn from_process() -> Self {
        let path_dirs = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        Self {
            home: std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from),
            codex_home: std::env::var_os("CODEX_HOME").map(PathBuf::from),
            path_dirs,
        }
    }

    /// Build an environment explicitly, for tests that must not touch the
    /// process environment.
    #[cfg(test)]
    fn fixture(home: &Path) -> Self {
        Self {
            home: Some(home.to_path_buf()),
            codex_home: None,
            path_dirs: Vec::new(),
        }
    }

    /// Resolve `name` against `PATH`, returning the first executable hit.
    fn launcher(&self, name: &str) -> Option<PathBuf> {
        self.path_dirs
            .iter()
            .map(|dir| dir.join(name))
            .find(|candidate| sbproxy_model_host::is_executable_file(candidate))
    }

    /// Join `parts` onto the home directory, or `None` when there is no home.
    fn in_home(&self, parts: &[&str]) -> Option<PathBuf> {
        let mut path = self.home.clone()?;
        for part in parts {
            path.push(part);
        }
        Some(path)
    }

    /// Render `path` with the home prefix collapsed to `~`, so output and docs
    /// do not carry the operator's username.
    fn display(&self, path: &Path) -> String {
        match self
            .home
            .as_deref()
            .and_then(|home| path.strip_prefix(home).ok())
        {
            Some(rest) => format!("~/{}", rest.display()),
            None => path.display().to_string(),
        }
    }
}

// --- The gateway URL --------------------------------------------------

/// The gateway address in the two shapes clients want it: an origin for
/// Anthropic-wire clients and an origin plus `/v1` for OpenAI-wire ones.
///
/// Operators paste whichever form their last doc showed them, so both parse.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayUrl {
    /// Scheme, host, and port with no trailing path. What
    /// `ANTHROPIC_BASE_URL` wants.
    root: String,
    /// `root` plus `/v1`. What every OpenAI-compatible client wants.
    openai: String,
}

impl GatewayUrl {
    /// Parse an operator-supplied base URL, with or without a trailing `/v1`.
    ///
    /// A malformed URL written into somebody's editor config is worse than an
    /// error, so anything that is not `http://` or `https://` followed by a
    /// host is refused here rather than passed through.
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let trimmed = raw.trim();
        let rest = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("https://"))
            .ok_or_else(|| {
                anyhow::anyhow!("base URL '{raw}' must start with http:// or https://")
            })?;
        if rest.split('/').next().unwrap_or_default().is_empty() {
            anyhow::bail!("base URL '{raw}' names no host");
        }
        let without_slash = trimmed.trim_end_matches('/');
        let root = without_slash
            .strip_suffix("/v1")
            .unwrap_or(without_slash)
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            openai: format!("{root}/v1"),
            root,
        })
    }
}

// --- The clients ------------------------------------------------------

/// One coding agent this verb knows how to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Client {
    /// OpenAI Codex CLI. Gets a profile file of its own.
    Codex,
    /// Anthropic Claude Code. Reads `ANTHROPIC_BASE_URL` from the environment.
    ClaudeCode,
    /// Cursor. Settings screen, and no vendor automates it.
    Cursor,
    /// Cline, the VS Code extension. Settings screen.
    Cline,
    /// GitHub Copilot BYOK. Settings screen, backed by a JSON file whose
    /// location moves with the VS Code profile.
    Copilot,
}

impl Client {
    /// Every client, in the order output lists them.
    const ALL: &'static [Client] = &[
        Client::Codex,
        Client::ClaudeCode,
        Client::Cursor,
        Client::Cline,
        Client::Copilot,
    ];

    /// Stable identifier used on the command line and in `--format json`.
    fn slug(self) -> &'static str {
        match self {
            Client::Codex => "codex",
            Client::ClaudeCode => "claude-code",
            Client::Cursor => "cursor",
            Client::Cline => "cline",
            Client::Copilot => "copilot",
        }
    }

    /// Human name for prose.
    fn label(self) -> &'static str {
        match self {
            Client::Codex => "Codex CLI",
            Client::ClaudeCode => "Claude Code",
            Client::Cursor => "Cursor",
            Client::Cline => "Cline",
            Client::Copilot => "GitHub Copilot",
        }
    }

    /// Parse a client name from the command line.
    fn parse(name: &str) -> anyhow::Result<Self> {
        Client::ALL
            .iter()
            .copied()
            .find(|client| client.slug() == name)
            .ok_or_else(|| {
                let known: Vec<&str> = Client::ALL.iter().map(|c| c.slug()).collect();
                anyhow::anyhow!(
                    "unknown client '{name}'; known clients: {}",
                    known.join(", ")
                )
            })
    }
}

// --- Detection --------------------------------------------------------

/// What found a client, or that nothing did.
///
/// Three findings rather than a boolean, because "not installed", "installed
/// where this shell cannot see it", and "installed and never run" are three
/// different things for the reader to do next. The third is the absence of a
/// config file under a client that was found, which [`Change`] carries.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Presence {
    /// No launcher on `PATH` and no state directory. Nothing is created for a
    /// client in this state.
    Absent,
    /// The client's launcher resolved on `PATH`.
    OnPath(PathBuf),
    /// No launcher on `PATH`, but the client's own directory exists: a GUI
    /// install that never edited `PATH`, or a shell that does not have it.
    StateDirOnly(PathBuf),
}

impl Presence {
    /// Whether anything at all was found.
    fn found(&self) -> bool {
        !matches!(self, Presence::Absent)
    }

    /// One-line explanation of what the probe saw.
    fn describe(&self, env: &Environment) -> String {
        match self {
            Presence::Absent => "not installed".to_string(),
            Presence::OnPath(path) => format!("{} (on PATH)", env.display(path)),
            Presence::StateDirOnly(path) => format!(
                "{} (state directory; no launcher on PATH)",
                env.display(path)
            ),
        }
    }
}

/// Probe one client: launcher on `PATH` first, then any of its own directories.
fn detect(env: &Environment, client: Client) -> Presence {
    let (launcher, dirs): (Option<&str>, Vec<PathBuf>) = match client {
        Client::Codex => (Some("codex"), codex_home(env).into_iter().collect()),
        Client::ClaudeCode => (
            Some("claude"),
            env.in_home(&[".claude"]).into_iter().collect(),
        ),
        Client::Cursor => (Some("cursor"), cursor_dirs(env)),
        Client::Cline => (Some("cline"), extension_dirs(env, "saoudrizwan.claude-dev")),
        Client::Copilot => (Some("copilot"), extension_dirs(env, "github.copilot")),
    };
    if let Some(name) = launcher {
        if let Some(path) = env.launcher(name) {
            return Presence::OnPath(path);
        }
    }
    dirs.into_iter()
        .find(|dir| dir.is_dir())
        .map_or(Presence::Absent, Presence::StateDirOnly)
}

/// Codex's state directory: `CODEX_HOME` when set, `~/.codex` otherwise.
fn codex_home(env: &Environment) -> Option<PathBuf> {
    env.codex_home.clone().or_else(|| env.in_home(&[".codex"]))
}

/// Where a Cursor install leaves its own directories on each platform.
/// Presence only; nothing here is written.
fn cursor_dirs(env: &Environment) -> Vec<PathBuf> {
    [
        env.in_home(&["Library", "Application Support", "Cursor"]),
        env.in_home(&[".config", "Cursor"]),
        env.in_home(&["AppData", "Roaming", "Cursor"]),
        env.in_home(&[".cursor"]),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// VS Code (and Cursor, and Insiders, and Windsurf) install extensions into
/// per-publisher directories whose names carry a version suffix, so this looks
/// for a prefix match rather than an exact path.
fn extension_dirs(env: &Environment, prefix: &str) -> Vec<PathBuf> {
    let roots = [
        env.in_home(&[".vscode", "extensions"]),
        env.in_home(&[".vscode-insiders", "extensions"]),
        env.in_home(&[".cursor", "extensions"]),
        env.in_home(&[".windsurf", "extensions"]),
    ];
    let mut found = Vec::new();
    for root in roots.into_iter().flatten() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(prefix) && entry.path().is_dir() {
                found.push(entry.path());
            }
        }
    }
    found
}

// --- What one client's change looks like ------------------------------

/// The change this verb would make for one client.
#[derive(Debug, Clone)]
enum Change {
    /// Client not detected. Nothing is written: a config file for a program
    /// that is not installed is litter at best and a wrong answer at worst.
    NotInstalled,
    /// A config file written, rewritten, or removed.
    File(FileEdit),
    /// The client reads its base URL from the environment. The verb prints the
    /// exports; a shell profile belongs to its owner.
    Env(Vec<(String, String)>),
    /// A settings screen with no file contract this verb will write: the
    /// fields to fill in.
    Manual(Vec<String>),
    /// Detected, but the config could not be read or parsed. Carries why, so
    /// the operator can fix it rather than guess.
    Blocked(String),
}

/// Where a staged change leaves the destination, and where the bytes it takes
/// away are kept.
///
/// The two arms are deliberately asymmetric, and the asymmetry is the whole
/// safety property. A write can honestly have no copy to make: the one-time
/// `.sbproxy.bak` is about the *pristine* original, so once one exists the
/// answer is `None` and nothing is lost, because the bytes being replaced are
/// still described by the diff the run prints and the file they came from is
/// still recoverable. A removal can not: the bytes it unlinks exist nowhere
/// else the moment it finishes. So `Remove` carries a staging path and
/// `Option` does not appear in it. Sharing one nullable `backup` field across
/// both directions is exactly the bug this shape removes; a direction added
/// later has to pick an arm, and picking `Remove` means naming the path its
/// bytes survive at.
#[derive(Debug, Clone)]
enum Destination {
    /// Replace the file with these bytes, copying the current file to
    /// `backup` first when this is the first change this verb has made to it.
    /// `None` when there is nothing to copy (the file does not exist) or when
    /// a backup from an earlier run is already there and must not be
    /// overwritten.
    Write {
        /// The bytes to leave at the destination.
        body: String,
        /// Where the one-time pristine copy goes, when this run makes one.
        backup: Option<PathBuf>,
    },
    /// Remove the file, after copying its current bytes to `staged`.
    Remove {
        /// Where the about-to-be-removed bytes are written first. Not
        /// optional: see the type's own docs.
        staged: PathBuf,
    },
}

/// A staged change to one config file.
#[derive(Debug, Clone)]
struct FileEdit {
    /// The file itself.
    path: PathBuf,
    /// Its current bytes, or `None` when it does not exist.
    before: Option<String>,
    /// What happens to it, and where its current bytes are kept.
    destination: Destination,
    /// The destination's current unix mode, carried onto the replacement.
    mode: Option<u32>,
    /// Whether the current mode lets group or other read the file. Reported,
    /// never changed.
    world_readable: bool,
}

impl FileEdit {
    /// The bytes this edit leaves at [`FileEdit::path`], or `None` when it
    /// removes the file.
    fn after(&self) -> Option<&str> {
        match &self.destination {
            Destination::Write { body, .. } => Some(body.as_str()),
            Destination::Remove { .. } => None,
        }
    }

    /// Where this run copies the current bytes before changing them, when it
    /// copies them at all. The `.sbproxy.bak` for a first write, the
    /// `.sbproxy.removed` for a removal.
    fn preserved(&self) -> Option<&Path> {
        match &self.destination {
            Destination::Write { backup, .. } => backup.as_deref(),
            Destination::Remove { staged } => Some(staged.as_path()),
        }
    }

    /// Whether applying this edit would change anything on disk. A second
    /// `connect` run with the same arguments lands here, which is what makes
    /// the verb idempotent, and so does a `disconnect` with no profile to
    /// remove.
    fn is_noop(&self) -> bool {
        self.before.as_deref() == self.after()
    }
}

/// One client's row in the plan.
#[derive(Debug, Clone)]
struct ClientPlan {
    /// Which client.
    client: Client,
    /// What the probe found.
    presence: Presence,
    /// What would change.
    change: Change,
}

// --- Planning ---------------------------------------------------------

/// Whether the plan is for `connect` or `disconnect`. The detection, backup,
/// atomic-write, and reporting halves are shared; only the rendered file
/// differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Register the gateway as a Codex profile and name the exports.
    Connect,
    /// Remove what `connect` created.
    Disconnect,
}

impl Direction {
    /// The verb's own name, for the undo hint and the JSON report.
    fn verb(self) -> &'static str {
        match self {
            Direction::Connect => "connect",
            Direction::Disconnect => "disconnect",
        }
    }
}

/// Everything a render needs that the host does not supply.
#[derive(Debug, Clone)]
struct Settings {
    /// Where the gateway listens.
    url: GatewayUrl,
    /// Model id to select, or `None` to leave whatever the client already
    /// selects alone. Writing a model id nobody asked for is a behavior change
    /// wearing a convenience's clothes.
    model: Option<String>,
    /// Connect or disconnect.
    direction: Direction,
}

/// Build the plan for every requested client. Reads the filesystem; writes
/// nothing.
fn plan(env: &Environment, settings: &Settings, wanted: &[Client]) -> Vec<ClientPlan> {
    wanted
        .iter()
        .map(|&client| {
            let presence = detect(env, client);
            let change = if presence.found() {
                match client {
                    Client::Codex => match plan_codex(env, settings) {
                        Ok(edit) => Change::File(edit),
                        Err(error) => Change::Blocked(format!("{error:#}")),
                    },
                    Client::ClaudeCode => plan_claude_code(settings),
                    Client::Cursor | Client::Cline | Client::Copilot => {
                        Change::Manual(manual_steps(client, settings))
                    }
                }
            } else {
                Change::NotInstalled
            };
            ClientPlan {
                client,
                presence,
                change,
            }
        })
        .collect()
}

/// Stage the Codex change against the profile file this verb owns, never
/// against `config.toml`.
fn plan_codex(env: &Environment, settings: &Settings) -> anyhow::Result<FileEdit> {
    let home = codex_home(env)
        .ok_or_else(|| anyhow::anyhow!("no home directory: set HOME or CODEX_HOME"))?;
    let path = home.join(format!("{PROVIDER_NAME}.config.toml"));
    let before = read_config(&path)?;
    let destination = match settings.direction {
        Direction::Connect => {
            let body = render_codex_profile(before.as_deref().unwrap_or_default(), settings)?;
            // The header is prepended rather than parsed as the starting
            // document. A TOML document that is nothing but comments carries
            // them as trailing trivia, so inserting the first key would render
            // the explanation below the thing it explains. On every later run
            // the comments are a real prefix on `model_provider` and the
            // structural edit preserves them, which is what keeps a second
            // run a byte-for-byte fixed point.
            let body = if before.is_some() {
                body
            } else {
                format!("{CODEX_PROFILE_HEADER}\n{body}")
            };
            // The one-time copy of the pristine original, and only that: once
            // one exists this is `None` and the file on disk keeps holding the
            // state before the first `connect`.
            let backup_path = backup_path_for(&path);
            let backup = (before.is_some() && !backup_path.exists()).then_some(backup_path);
            Destination::Write { body, backup }
        }
        // The file is this verb's own, named after it and carrying a header
        // that says so, so reversing means removing it rather than unpicking
        // keys out of somebody else's document. What it may not do is take
        // the bytes with it: the profile is editable by hand and the module
        // docs promise those edits survive, so the removal stages the current
        // file next to itself first.
        Direction::Disconnect => {
            let staged = staging_path_for(&path);
            if let Some(body) = before.as_deref() {
                // Refused at plan time rather than in `apply`, so `--dry-run`
                // reports it too and nothing has been touched when it does.
                // Byte-identical is not a conflict: rewriting the same
                // content takes nothing away.
                let kept = read_config(&staged).ok().flatten();
                if staged.exists() && kept.as_deref() != Some(body) {
                    anyhow::bail!(
                        "'{}' already holds a different profile an earlier `disconnect` \
                         rescued, and removing this one would overwrite it. Move it \
                         somewhere safe or delete it, then re-run.",
                        staged.display()
                    );
                }
            }
            Destination::Remove { staged }
        }
    };
    let (mode, world_readable) = file_mode(&path);
    Ok(FileEdit {
        path,
        before,
        destination,
        mode,
        world_readable,
    })
}

/// Claude Code takes its endpoint from the environment, so the change is an
/// export rather than a file. `ANTHROPIC_AUTH_TOKEN` is named but never
/// valued: the credential is not this verb's to hold.
fn plan_claude_code(settings: &Settings) -> Change {
    match settings.direction {
        Direction::Connect => Change::Env(vec![(
            "ANTHROPIC_BASE_URL".to_string(),
            settings.url.root.clone(),
        )]),
        Direction::Disconnect => Change::Manual(vec![
            "unset ANTHROPIC_BASE_URL, and remove it from your shell profile".to_string(),
        ]),
    }
}

/// The fields to fill in by hand, per client.
fn manual_steps(client: Client, settings: &Settings) -> Vec<String> {
    if settings.direction == Direction::Disconnect {
        return vec![format!(
            "clear the base URL you set in {}'s settings to fall back to its own backend",
            client.label()
        )];
    }
    let base = &settings.url.openai;
    let model = settings.model.as_deref().unwrap_or("<your model alias>");
    match client {
        Client::Cursor => vec![
            "Settings -> Models".to_string(),
            format!("Override OpenAI Base URL: {base}"),
            "OpenAI API Key: your sbproxy key".to_string(),
            "chat and agent mode follow this; tab autocomplete stays on Cursor's own backend"
                .to_string(),
        ],
        Client::Cline => vec![
            "API Provider: OpenAI Compatible".to_string(),
            format!("Base URL: {base}"),
            "API Key: your sbproxy key".to_string(),
            format!("Model ID: {model}"),
        ],
        Client::Copilot => vec![
            "add a custom model provider in the Copilot Chat model picker (BYOK)".to_string(),
            format!("Base URL: {base}"),
            "API Key: your sbproxy key".to_string(),
            format!("Model: {model}"),
            "VS Code 1.109 and later store this in chatLanguageModels.json next to settings.json \
             in the active profile directory, so the picker is not the only way in"
                .to_string(),
        ],
        Client::Codex | Client::ClaudeCode => Vec::new(),
    }
}

/// Read a client config, refusing anything implausibly large rather than
/// holding it in memory and rewriting it.
///
/// The stat is `symlink_metadata`, not `metadata`, because the write half is
/// a `rename(2)` onto this path and `rename` replaces the *link* rather than
/// its target. A `stow` or `chezmoi` user whose profile is a link into their
/// dotfiles would get the link silently swapped for a regular file, their
/// dotfiles copy orphaned and stale, and no line of output saying so. The
/// report cannot warn about it either: `run` applies before it describes, so
/// a note would be a post-mortem. Refusing is the only answer that reaches
/// the operator while the link still exists.
fn read_config(path: &Path) -> anyhow::Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => anyhow::bail!("read '{}': {error}", path.display()),
    };
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)
            .map(|target| target.display().to_string())
            .unwrap_or_else(|_| "somewhere this process cannot read".to_string());
        anyhow::bail!(
            "'{}' is a symlink to '{target}'. This verb replaces the file at that path, \
             which would break the link and leave the file it points at stale; run it \
             against '{target}' instead, or remove the link first.",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("'{}' is not a regular file", path.display());
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        anyhow::bail!(
            "'{}' is {} bytes, past the {MAX_CONFIG_BYTES}-byte ceiling this verb will rewrite",
            path.display(),
            metadata.len()
        );
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("read '{}': {error}", path.display()))
}

/// The destination's unix mode, and whether group or other can read it.
fn file_mode(path: &Path) -> (Option<u32>, bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o7777;
                (Some(mode), mode & 0o044 != 0)
            }
            Err(_) => (None, false),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        (None, false)
    }
}

/// Where the one-time backup for `path` lives.
fn backup_path_for(path: &Path) -> PathBuf {
    suffixed(path, BACKUP_SUFFIX)
}

/// Where a removal stages the bytes it is about to unlink.
fn staging_path_for(path: &Path) -> PathBuf {
    suffixed(path, REMOVED_SUFFIX)
}

/// `path` with `suffix` appended to its file name, so the copy lands beside
/// the original rather than in a directory the operator did not name.
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

// --- Rendering the Codex profile --------------------------------------

/// Add (or update) the `sbproxy` provider in the profile document and select
/// it, leaving every other key, table, and comment where it was.
///
/// The merge matters even though this verb owns the file: an operator who
/// added a `model_reasoning_effort` line to it should not lose it to the next
/// `connect`.
fn render_codex_profile(existing: &str, settings: &Settings) -> anyhow::Result<String> {
    use toml_edit::{value, DocumentMut, Item, Table};

    let mut doc: DocumentMut = existing
        .parse()
        .map_err(|error| anyhow::anyhow!("parse the profile as TOML: {error}"))?;

    doc["model_provider"] = value(PROVIDER_NAME);
    if let Some(model) = settings.model.as_deref() {
        doc["model"] = value(model);
    }

    // `[model_providers]` is a header nobody writes on its own, so when this
    // verb creates it the table is marked implicit and only the child header
    // `[model_providers.sbproxy]` renders. An existing one is left as the
    // operator wrote it.
    let fresh = doc.get("model_providers").is_none();
    let providers = doc
        .entry("model_providers")
        .or_insert(Item::Table(Table::new()));
    let providers = providers.as_table_mut().ok_or_else(|| {
        anyhow::anyhow!("`model_providers` is not a table; refusing to overwrite it")
    })?;
    if fresh {
        providers.set_implicit(true);
    }

    let entry = providers
        .entry(PROVIDER_NAME)
        .or_insert(Item::Table(Table::new()));
    let table = entry.as_table_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "`model_providers.{PROVIDER_NAME}` is not a table; refusing to overwrite it"
        )
    })?;
    table["name"] = value("SBproxy");
    table["base_url"] = value(settings.url.openai.as_str());
    // The key's name, never the key. See the module docs.
    table["env_key"] = value(CODEX_ENV_KEY);
    table["env_key_instructions"] = value(
        "Mint a gateway key with `curl -u admin:<password> -X POST \
         <admin-url>/admin/keys`, then export it as SBPROXY_API_KEY.",
    );
    table["wire_api"] = value(CODEX_WIRE_API);

    Ok(doc.to_string())
}

// --- Writing ----------------------------------------------------------

/// Whether a change that landed is also guaranteed to survive a crash.
///
/// Two states rather than folding the second into an error, because they are
/// opposite instructions to the operator. An error means the file is
/// untouched and there is nothing to undo. `NotSynced` means the file is
/// already replaced or already gone and only the *durability* of that is
/// unproven, so the undo hint applies and the operator needs to know the path
/// exists.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Durability {
    /// The change is on disk and the directory holding it was synced.
    Durable,
    /// The rename or the unlink landed; the directory sync did not. Carries
    /// the sentence to print, which names the file and the syscall's
    /// complaint.
    NotSynced(String),
}

impl Durability {
    /// Fold two steps of one apply together. The first complaint wins: it is
    /// the one nearest the cause, and one unsynced step makes the whole run
    /// unsynced.
    fn and(self, next: Durability) -> Durability {
        match self {
            Durability::Durable => next,
            already => already,
        }
    }

    /// The warning to print, when there is one.
    fn warning(&self) -> Option<&str> {
        match self {
            Durability::Durable => None,
            Durability::NotSynced(why) => Some(why.as_str()),
        }
    }
}

/// Replace `path` with `contents` without ever opening `path` for writing.
///
/// Stage a sibling temp file, fsync it, rename it over the destination, then
/// fsync the directory so the rename itself survives a crash. A reader of the
/// destination sees either every old byte or every new byte and never a
/// truncated file, which is the property that matters when the file belongs to
/// a running editor.
///
/// `mode` carries the destination's existing unix mode onto the replacement.
/// Codex creates its config files at 0600, so a replacement left at this
/// process's umask default would quietly widen a private file.
///
/// The result splits at the rename: `Err` means the destination still holds
/// every old byte, `Ok(Durability::NotSynced)` means it holds the new ones and
/// the directory fsync did not answer. See `Durability`.
fn replace_atomically(
    path: &Path,
    contents: &str,
    mode: Option<u32>,
) -> anyhow::Result<Durability> {
    replace_atomically_with(path, contents, mode, sync_dir)
}

/// `replace_atomically` with the directory sync passed in.
///
/// The seam exists because the failure it guards is not producible in a temp
/// directory: `sync_all` answers ENOTSUP on an SMB or FUSE mount and nothing
/// else, so a test that wants the post-rename branch has to supply the
/// refusal. Both production callers pass [`sync_dir`], so the path a test
/// exercises is the path an operator runs.
fn replace_atomically_with(
    path: &Path,
    contents: &str,
    mode: Option<u32>,
    sync: fn(&Path) -> std::io::Result<()>,
) -> anyhow::Result<Durability> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create '{}': {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        nanos()
    ));

    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Born private, then relaxed to whatever the destination already was.
        // The other order would leave a readable window.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&temporary, path)
    })();

    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow::anyhow!("write '{}': {error}", path.display()));
    }
    // Past the rename. The destination already holds `contents`, so whatever
    // the directory sync answers, reporting this as a failed write would be
    // false and would talk the operator out of the undo they now need.
    Ok(match sync(parent) {
        Ok(()) => Durability::Durable,
        Err(error) => Durability::NotSynced(format!(
            "'{}' was written, but syncing '{}' failed: {error}. The new bytes are in \
             place; only their survival across a crash before the filesystem flushes is \
             unproven.",
            path.display(),
            parent.display()
        )),
    })
}

/// Remove `path` and make the removal durable.
///
/// Splits at the unlink for the same reason `replace_atomically` splits at
/// the rename: once the file is gone, a directory sync that will not answer
/// does not put it back.
fn remove_durably(path: &Path) -> anyhow::Result<Durability> {
    remove_durably_with(path, sync_dir)
}

/// [`remove_durably`] with the directory sync passed in. See
/// [`replace_atomically_with`] for why the seam is here.
fn remove_durably_with(
    path: &Path,
    sync: fn(&Path) -> std::io::Result<()>,
) -> anyhow::Result<Durability> {
    std::fs::remove_file(path)
        .map_err(|error| anyhow::anyhow!("remove '{}': {error}", path.display()))?;
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(Durability::Durable);
    };
    Ok(match sync(parent) {
        Ok(()) => Durability::Durable,
        Err(error) => Durability::NotSynced(format!(
            "'{}' was removed, but syncing '{}' failed: {error}. The file is gone; only \
             the removal's survival across a crash before the filesystem flushes is \
             unproven.",
            path.display(),
            parent.display()
        )),
    })
}

/// fsync a directory so a rename into it is durable. Directories are not
/// openable for sync on Windows, where the rename is already ordered by the
/// filesystem, so this is a unix-only step.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Nanoseconds since the epoch, for temp-file uniqueness. A clock that refuses
/// to answer yields zero; the pid in the same name still separates writers.
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

/// Apply one staged edit: confirm the file is still what the plan read, back
/// the original up once, then replace or remove it.
///
/// The re-read is a compare-and-swap, not belt and braces. Codex rewrites
/// files under `CODEX_HOME` while it runs, so a file that changed between plan
/// and apply means the diff the operator just approved is not the diff that
/// would land. Refusing and naming the file is the only answer that cannot
/// lose somebody's edit.
///
/// The backup is written before the change and only when no backup from an
/// earlier run exists, so the copy on disk is always the file as it was before
/// this verb first touched it.
///
/// A removal copies first and unlinks second, in that order, so the bytes it
/// takes away exist at a second path before they stop existing at the first.
/// The order is not an optimization to revisit: reversed, a failed copy leaves
/// nothing anywhere.
fn apply(edit: &FileEdit) -> anyhow::Result<Durability> {
    if edit.is_noop() {
        return Ok(Durability::Durable);
    }
    if read_config(&edit.path)? != edit.before {
        anyhow::bail!(
            "'{}' changed while this ran; nothing was written. Re-run to see the new diff.",
            edit.path.display()
        );
    }
    match &edit.destination {
        Destination::Write { body, backup } => {
            let mut durability = Durability::Durable;
            if let (Some(backup), Some(original)) = (backup.as_deref(), edit.before.as_deref()) {
                durability = durability.and(replace_atomically(backup, original, edit.mode)?);
            }
            Ok(durability.and(replace_atomically(&edit.path, body, edit.mode)?))
        }
        Destination::Remove { staged } => {
            // `before` is `Some` here: a removal with nothing to remove is a
            // no-op and returned above. The `let ... else` is the compiler's
            // proof of that rather than an `unwrap` asserting it.
            let Some(original) = edit.before.as_deref() else {
                return Ok(Durability::Durable);
            };
            let durability = replace_atomically(staged, original, edit.mode)?;
            Ok(durability.and(remove_durably(&edit.path)?))
        }
    }
}

// --- Diff -------------------------------------------------------------

/// Line-level unified diff with [`DIFF_CONTEXT`] lines of context.
///
/// The table is quadratic in the line counts, which is why
/// [`MAX_CONFIG_BYTES`] is not the only bound: past [`MAX_DIFF_LINES`] a side,
/// this reports counts instead of rendering.
fn unified_diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    if a.len() > MAX_DIFF_LINES || b.len() > MAX_DIFF_LINES {
        return format!(
            "    (diff suppressed: {} lines before, {} lines after)\n",
            a.len(),
            b.len()
        );
    }

    // table[i][j] = length of the longest common subsequence of a[i..] and
    // b[j..]. Walked forwards afterwards so ops come out in document order.
    let width = b.len() + 1;
    let mut table = vec![0u32; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }

    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    for line in &a[i..] {
        ops.push(('-', line));
    }
    for line in &b[j..] {
        ops.push(('+', line));
    }

    render_hunks(&ops)
}

/// Print only the changed ops and the context around them, with a `...`
/// marker wherever unchanged lines were elided.
fn render_hunks(ops: &[(char, &str)]) -> String {
    let keep: Vec<bool> = (0..ops.len())
        .map(|index| {
            let low = index.saturating_sub(DIFF_CONTEXT);
            let high = (index + DIFF_CONTEXT + 1).min(ops.len());
            ops[low..high].iter().any(|(sigil, _)| *sigil != ' ')
        })
        .collect();
    let mut out = String::new();
    let mut elided = false;
    for (index, (sigil, line)) in ops.iter().enumerate() {
        if keep[index] {
            if elided {
                out.push_str("    ...\n");
                elided = false;
            }
            out.push_str(&format!("    {sigil}{line}\n"));
        } else {
            elided = true;
        }
    }
    out
}

// --- Reporting --------------------------------------------------------

/// One client's row in `--format json`.
#[derive(Debug, serde::Serialize)]
struct ClientReport {
    /// Stable client identifier.
    client: &'static str,
    /// What happened, or would happen: one of `not_installed`, `unchanged`,
    /// `would_write`, `wrote`, `env_only`, `manual`, `blocked`, or `failed`.
    status: &'static str,
    /// How the client was found, in prose.
    detected: String,
    /// The config file, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// The copy of the previous contents this run wrote: the one-time
    /// `.sbproxy.bak` on a first change, the `.sbproxy.removed` on a removal.
    ///
    /// Present only when the copy exists on disk. A `--dry-run` writes no
    /// copy, so it reports none; the text output still names where the copy
    /// would go, under a `would` verb that says it has not happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<String>,
    /// A change that landed with a caveat: the bytes are in place and the
    /// directory sync that makes them crash-proof did not answer. Not a
    /// failure, and not silence either.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    /// Environment variables the operator should export.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    /// Fields to fill in by hand.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    steps: Vec<String>,
    /// Why nothing could be done, when `status` is `blocked` or `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The whole run, for `--format json`.
#[derive(Debug, serde::Serialize)]
struct Report {
    /// Which verb produced this.
    action: &'static str,
    /// The gateway address written into every client.
    base_url: String,
    /// Whether anything was written.
    dry_run: bool,
    /// One row per requested client.
    clients: Vec<ClientReport>,
}

/// What happened to one client's change on this run.
#[derive(Debug, Clone)]
enum Outcome {
    /// Nothing was written: either `--dry-run`, or there was nothing to write.
    Planned,
    /// The file was replaced or removed. Carries whether the change is also
    /// durable, which is a separate question from whether it happened.
    Applied(Durability),
    /// The write was attempted and refused. Carries why. Reaching this means
    /// the destination is untouched.
    Failed(String),
}

// --- The verb ---------------------------------------------------------

/// Everything the CLI layer passes down. Kept separate from clap's arg struct
/// so this module has no opinion about how the flags were spelled.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    /// Connect or disconnect.
    pub(crate) direction: Direction,
    /// Clients named on the command line; empty means every one this verb
    /// knows.
    pub(crate) clients: Vec<String>,
    /// Gateway base URL, with or without a trailing `/v1`.
    pub(crate) base_url: String,
    /// Model id to select, or `None` to leave the client's own choice alone.
    pub(crate) model: Option<String>,
    /// Print the diff and change nothing.
    pub(crate) dry_run: bool,
    /// `true` for JSON output.
    pub(crate) json: bool,
}

/// Run `connect` or `disconnect`. Returns the process exit code: `0` when
/// every requested client was handled, `2` when one of them could not be.
pub(crate) fn run(request: &Request) -> anyhow::Result<i32> {
    let env = Environment::from_process();
    let settings = Settings {
        url: GatewayUrl::parse(&request.base_url)?,
        model: request.model.clone(),
        direction: request.direction,
    };

    let named = !request.clients.is_empty();
    let wanted: Vec<Client> = if named {
        let mut clients = request
            .clients
            .iter()
            .map(|name| Client::parse(name))
            .collect::<anyhow::Result<Vec<_>>>()?;
        clients.sort_unstable();
        clients.dedup();
        clients
    } else {
        Client::ALL.to_vec()
    };

    let plans = plan(&env, &settings, &wanted);

    // A client the operator asked for by name and that is not here is an
    // error: they expected it to be configured and it was not. The unnamed
    // sweep says so and exits clean, because "you do not have Cline" is an
    // answer rather than a fault.
    if named {
        let missing: Vec<&str> = plans
            .iter()
            .filter(|entry| matches!(entry.change, Change::NotInstalled))
            .map(|entry| entry.client.slug())
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "{} not found on this machine; nothing was changed",
                missing.join(", ")
            );
        }
    }

    // Write first, then report, so a report never claims a write that failed.
    // Each client is independent: one that could not be handled does not stop
    // the rest, and the exit code says whether there was one.
    let mut outcomes = Vec::new();
    let mut wrote_anything = false;
    let mut degraded = false;
    for entry in &plans {
        let outcome = match (&entry.change, request.dry_run) {
            (Change::File(edit), false) if !edit.is_noop() => match apply(edit) {
                Ok(durability) => {
                    wrote_anything = true;
                    Outcome::Applied(durability)
                }
                Err(error) => Outcome::Failed(format!("{error:#}")),
            },
            _ => Outcome::Planned,
        };
        // A write that landed without its directory sync is not degraded: the
        // change the operator asked for is on disk and the report says so on
        // its own line. Exiting 2 there would send a CI job looking for a
        // failure that did not happen.
        degraded |=
            matches!(entry.change, Change::Blocked(_)) || matches!(outcome, Outcome::Failed(_));
        outcomes.push(outcome);
    }

    let rows: Vec<(ClientReport, String)> = plans
        .iter()
        .zip(&outcomes)
        .map(|(entry, outcome)| describe(&env, entry, outcome))
        .collect();

    if request.json {
        let report = Report {
            action: settings.direction.verb(),
            base_url: settings.url.openai.clone(),
            dry_run: request.dry_run,
            clients: rows.into_iter().map(|(report, _)| report).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for (_, block) in &rows {
            print!("{block}");
        }
        print!("{}", footer(&settings, request.dry_run, wrote_anything));
    }
    Ok(if degraded { 2 } else { 0 })
}

/// Render one client's row, both as a JSON record and as the text block.
///
/// One function so the two surfaces cannot drift: a status that appears in
/// `--format json` and not in the text output is how an operator and their CI
/// end up disagreeing about what happened.
fn describe(env: &Environment, entry: &ClientPlan, outcome: &Outcome) -> (ClientReport, String) {
    let detected = entry.presence.describe(env);
    let mut block = format!("{}  {}\n", entry.client.slug(), entry.client.label());
    block.push_str(&format!("    found: {detected}\n"));
    let mut report = ClientReport {
        client: entry.client.slug(),
        status: "not_installed",
        detected,
        path: None,
        backup: None,
        warning: None,
        env: BTreeMap::new(),
        steps: Vec::new(),
        reason: None,
    };

    if let Outcome::Failed(reason) = outcome {
        report.status = "failed";
        report.reason = Some(reason.clone());
        block.push_str(&format!("    failed: {reason}\n\n"));
        return (report, block);
    }

    match &entry.change {
        Change::NotInstalled => {}
        Change::Blocked(reason) => {
            report.status = "blocked";
            report.reason = Some(reason.clone());
            block.push_str(&format!("    blocked: {reason}\n"));
        }
        Change::File(edit) => {
            report.path = Some(env.display(&edit.path));
            if edit.is_noop() {
                report.status = "unchanged";
                let why = if edit.before.is_some() {
                    "already says this"
                } else {
                    "is not there"
                };
                block.push_str(&format!(
                    "    unchanged: {} {why}\n",
                    env.display(&edit.path)
                ));
            } else {
                let durability = match outcome {
                    Outcome::Applied(durability) => Some(durability),
                    _ => None,
                };
                let applied = durability.is_some();
                let (status, verb) = match (applied, edit.after().is_some()) {
                    (true, true) => ("wrote", "wrote"),
                    (true, false) => ("wrote", "removed"),
                    (false, true) => ("would_write", "would write"),
                    (false, false) => ("would_write", "would remove"),
                };
                report.status = status;
                // Only when the copy is on disk. A plan that names a path
                // nothing wrote is a rollback point a setup script would
                // believe in.
                report.backup = if applied {
                    edit.preserved().map(|path| env.display(path))
                } else {
                    None
                };
                block.push_str(&format!("    {verb}: {}\n", env.display(&edit.path)));
                if let Some(why) = durability.and_then(Durability::warning) {
                    report.warning = Some(why.to_string());
                    block.push_str(&format!("    warning: {why}\n"));
                }
                block.push_str(&backup_line(env, edit, applied));
                block.push_str(&mode_line(env, edit));
                block.push_str(&unified_diff(
                    edit.before.as_deref().unwrap_or_default(),
                    edit.after().unwrap_or_default(),
                ));
            }
            block.push_str(&client_notes(entry.client));
        }
        Change::Env(vars) => {
            report.status = "env_only";
            report.env = vars.iter().cloned().collect();
            block.push_str("    reads the environment, not a file:\n");
            for (name, value) in vars {
                block.push_str(&format!("    export {name}={value}\n"));
            }
            block.push_str(&client_notes(entry.client));
        }
        Change::Manual(steps) => {
            report.status = "manual";
            report.steps = steps.clone();
            block.push_str("    no file this verb will write; set these by hand:\n");
            for step in steps {
                block.push_str(&format!("    - {step}\n"));
            }
        }
    }
    block.push('\n');
    (report, block)
}

/// Where the previous contents went, or are going.
///
/// The tense tracks `applied`, because this line is printed for a `--dry-run`
/// too and a plan that says `backup: <path>` reads as a file that is already
/// there. The removal line names a different file from the write line on
/// purpose: `.sbproxy.bak` is the profile before the first `connect`,
/// `.sbproxy.removed` is the profile `disconnect` just took away, and telling
/// an operator to look in the first one for the second one is how a hand
/// edit gets written off as unrecoverable.
fn backup_line(env: &Environment, edit: &FileEdit, applied: bool) -> String {
    match &edit.destination {
        Destination::Remove { staged } if applied => format!(
            "    saved: {}, which holds the profile this removed\n",
            env.display(staged)
        ),
        Destination::Remove { staged } => format!(
            "    would save: {}, a copy of the profile as it is now\n",
            env.display(staged)
        ),
        Destination::Write {
            backup: Some(path), ..
        } => format!(
            "    {}: {}\n",
            if applied { "backup" } else { "would back up" },
            env.display(path)
        ),
        Destination::Write { backup: None, .. } if edit.before.is_some() => format!(
            "    backup: {} already exists and holds this file as it was before the first \
             connect; it is not overwritten\n",
            env.display(&backup_path_for(&edit.path))
        ),
        Destination::Write { backup: None, .. } => {
            "    backup: none, this file did not exist yet\n".to_string()
        }
    }
}

/// Report a group- or world-readable destination. Reported, never changed:
/// the mode of somebody's own file is their decision, and a CLI that silently
/// tightens it is the class of surprise this verb exists to avoid.
fn mode_line(env: &Environment, edit: &FileEdit) -> String {
    match (edit.world_readable, edit.mode) {
        (true, Some(mode)) => format!(
            "    note: {} is mode {mode:04o}, readable by other users on this machine. \
             The mode is preserved as-is; nothing written here is a secret.\n",
            env.display(&edit.path)
        ),
        _ => String::new(),
    }
}

/// Per-client notes worth printing next to the change: where the credential
/// comes from, and anything about the client that changes what to expect.
fn client_notes(client: Client) -> String {
    match client {
        Client::Codex => format!(
            "    run it as: codex --profile {PROVIDER_NAME}\n\
             \x20   credential: Codex reads ${CODEX_ENV_KEY}. This verb writes the variable's \
             name, never its value.\n\
             \x20   note: Codex only accepts wire_api = \"{CODEX_WIRE_API}\". The gateway serves \
             stateless /v1/responses and refuses a request carrying previous_response_id, \
             conversation, or store: true with a 400 naming the field.\n"
        ),
        Client::ClaudeCode => "    credential: Claude Code reads $ANTHROPIC_AUTH_TOKEN. This \
             verb writes the variable's name, never its value.\n"
            .to_string(),
        Client::Cursor | Client::Cline | Client::Copilot => String::new(),
    }
}

/// The closing block: how to mint a key, and how to undo the run.
fn footer(settings: &Settings, dry_run: bool, wrote_anything: bool) -> String {
    if dry_run {
        return "nothing was written (--dry-run).\n".to_string();
    }
    match settings.direction {
        Direction::Connect => {
            let mut out = String::new();
            if wrote_anything {
                out.push_str("undo: sbproxy disconnect\n");
            }
            out.push_str(&format!(
                "mint a key: curl -s -u admin:<admin password> -X POST {}/admin/keys \\\n  \
                 -H 'content-type: application/json' -d '{{\"name\":\"coding-agent\"}}'\n",
                admin_url_hint(&settings.url.root)
            ));
            out.push_str(&format!(
                "then: export {CODEX_ENV_KEY}=<the token that returns>\n"
            ));
            out
        }
        Direction::Disconnect => "redo: sbproxy connect\n".to_string(),
    }
}

/// The admin port sits next to the data-plane port in every shipped example,
/// so the mint hint points at 9090 on the same host rather than guessing.
fn admin_url_hint(root: &str) -> String {
    match root.rsplit_once(':') {
        Some((prefix, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            format!("{prefix}:9090")
        }
        _ => format!("{root}:9090"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sbproxy-connect-unit-{}-{}-{name}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        dir
    }

    fn settings(direction: Direction) -> Settings {
        Settings {
            url: GatewayUrl::parse("http://127.0.0.1:8080/v1").expect("parse url"),
            model: None,
            direction,
        }
    }

    /// The one-time `.sbproxy.bak` this edit would write, if any. Narrower
    /// than [`FileEdit::preserved`] on purpose: a removal's staging copy is a
    /// different promise and the tests that care say which one they mean.
    fn one_time_backup(edit: &FileEdit) -> Option<&Path> {
        match &edit.destination {
            Destination::Write { backup, .. } => backup.as_deref(),
            Destination::Remove { .. } => None,
        }
    }

    /// A directory sync that refuses, standing in for `F_FULLFSYNC` on an SMB
    /// or FUSE mount. `ENOTSUP` is what those answer; the kind is what the
    /// message has to survive, not the exact string.
    fn refusing_sync(_dir: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Operation not supported",
        ))
    }

    /// A profile file an operator has already edited by hand: comments, a key
    /// this verb does not own, and a second provider.
    const EDITED_PROFILE: &str = r#"# my notes
model_reasoning_effort = "high"

[model_providers.other]
name = "other"
base_url = "https://example.invalid/v1"
"#;

    #[test]
    fn connect_preserves_comments_and_every_unrelated_key() {
        let rendered =
            render_codex_profile(EDITED_PROFILE, &settings(Direction::Connect)).expect("render");
        assert!(
            rendered.contains("# my notes"),
            "comment dropped:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"model_reasoning_effort = "high""#),
            "{rendered}"
        );
        assert!(rendered.contains("[model_providers.other]"), "{rendered}");
        assert!(
            rendered.contains("https://example.invalid/v1"),
            "{rendered}"
        );
        assert!(
            rendered.contains(r#"model_provider = "sbproxy""#),
            "{rendered}"
        );
        assert!(rendered.contains("[model_providers.sbproxy]"), "{rendered}");
        assert!(
            rendered.contains(r#"env_key = "SBPROXY_API_KEY""#),
            "{rendered}"
        );
        assert!(rendered.contains(r#"wire_api = "responses""#), "{rendered}");
    }

    #[test]
    fn a_second_render_is_a_fixed_point() {
        let once =
            render_codex_profile(EDITED_PROFILE, &settings(Direction::Connect)).expect("first");
        let twice = render_codex_profile(&once, &settings(Direction::Connect)).expect("second");
        assert_eq!(once, twice, "a second render must change nothing");
    }

    #[test]
    fn a_non_table_provider_entry_is_refused_rather_than_overwritten() {
        let hostile = "model_providers = 7\n";
        let error =
            render_codex_profile(hostile, &settings(Direction::Connect)).expect_err("must refuse");
        assert!(
            format!("{error}").contains("not a table"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn nothing_this_verb_renders_carries_a_credential() {
        let rendered = render_codex_profile("", &settings(Direction::Connect)).expect("render");
        assert!(rendered.contains("env_key"), "{rendered}");
        assert!(
            !rendered.contains("api_key = ") && !rendered.contains("experimental_bearer_token"),
            "a literal key field appeared:\n{rendered}"
        );
    }

    #[test]
    fn replace_atomically_keeps_the_destination_mode_and_leaves_no_temp_file() {
        let dir = scratch("mode");
        let path = dir.join("sbproxy.config.toml");
        std::fs::write(&path, "before\n").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let (mode, _) = file_mode(&path);
        replace_atomically(&path, "after\n", mode).expect("replace");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "after\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let after = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
            assert_eq!(after, 0o600, "mode was not preserved");
        }
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .expect("readdir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read-only destination in a writable directory. `rename(2)` needs
    /// write permission on the directory and none on the file, so the atomic
    /// path succeeds here while an in-place write returns `EACCES`. This is
    /// the deterministic proof that the destination is never opened for
    /// writing, which is what makes a partial write unobservable.
    #[cfg(unix)]
    #[test]
    fn a_read_only_destination_is_replaced_rather_than_truncated() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("readonly");
        let path = dir.join("sbproxy.config.toml");
        std::fs::write(&path, "before\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).expect("chmod");
        assert!(
            std::fs::write(&path, "naive\n").is_err(),
            "precondition: an in-place write must fail on a 0444 file"
        );
        replace_atomically(&path, "after\n", Some(0o444)).expect("atomic replace");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "after\n");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, 0o444);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the same property. A write that fails has to fail
    /// before the destination is touched, so the operator is left with the old
    /// file rather than half of the new one. Staging into the destination's
    /// own directory makes an unwritable directory fail at `create_new`, which
    /// is the earliest point there is; a truncate-in-place writer would have
    /// emptied the file by then.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_original_whole_and_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("failed-write");
        let path = dir.join("sbproxy.config.toml");
        std::fs::write(&path, EDITED_PROFILE).expect("seed");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        // Root ignores the directory mode, so confirm the precondition rather
        // than asserting a refusal the kernel was never going to make.
        let staging_is_blocked = std::fs::File::create(dir.join(".probe")).is_err();
        if staging_is_blocked {
            let error = replace_atomically(&path, "should not land\n", Some(0o600))
                .expect_err("an unwritable directory must fail the stage");
            assert!(format!("{error:#}").contains("write"), "{error:#}");
        }

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("restore");
        if staging_is_blocked {
            assert_eq!(
                std::fs::read_to_string(&path).expect("read"),
                EDITED_PROFILE,
                "the original must survive a failed replace byte for byte"
            );
            let leftovers: Vec<String> = std::fs::read_dir(&dir)
                .expect("readdir")
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".tmp"))
                .collect();
            assert!(
                leftovers.is_empty(),
                "temp files left behind: {leftovers:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_apply_never_overwrites_the_first_backup() {
        let dir = scratch("backup");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        std::fs::write(codex.join("sbproxy.config.toml"), EDITED_PROFILE).expect("seed");
        let env = Environment::fixture(&home);

        let first = plan_codex(&env, &settings(Direction::Connect)).expect("plan one");
        let expected_backup = codex.join("sbproxy.config.toml.sbproxy.bak");
        assert_eq!(one_time_backup(&first), Some(expected_backup.as_path()));
        apply(&first).expect("apply one");

        // A different base URL, so the second run genuinely rewrites the file.
        let moved = Settings {
            url: GatewayUrl::parse("http://127.0.0.1:9999/v1").expect("url"),
            model: None,
            direction: Direction::Connect,
        };
        let second = plan_codex(&env, &moved).expect("plan two");
        assert!(
            one_time_backup(&second).is_none(),
            "the backup must not be rewritten"
        );
        apply(&second).expect("apply two");

        let backup = std::fs::read_to_string(codex.join("sbproxy.config.toml.sbproxy.bak"))
            .expect("read backup");
        assert_eq!(
            backup, EDITED_PROFILE,
            "the backup must still hold the file as it was before the first connect"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_refuses_when_the_file_moved_under_it() {
        let dir = scratch("cas");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        let path = codex.join("sbproxy.config.toml");
        std::fs::write(&path, EDITED_PROFILE).expect("seed");
        let env = Environment::fixture(&home);
        let staged = plan_codex(&env, &settings(Direction::Connect)).expect("plan");

        // Somebody else writes between plan and apply.
        std::fs::write(&path, "model = \"someone-elses-edit\"\n").expect("interleave");
        let error = apply(&staged).expect_err("must refuse");
        assert!(
            format!("{error}").contains("changed while this ran"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "model = \"someone-elses-edit\"\n",
            "the interleaved write must survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disconnect_removes_the_profile_and_leaves_config_toml_untouched() {
        let dir = scratch("disconnect");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        let user_config = codex.join("config.toml");
        std::fs::write(&user_config, EDITED_PROFILE).expect("seed user config");
        let env = Environment::fixture(&home);

        apply(&plan_codex(&env, &settings(Direction::Connect)).expect("plan")).expect("connect");
        assert!(codex.join("sbproxy.config.toml").is_file());

        let removal = plan_codex(&env, &settings(Direction::Disconnect)).expect("plan removal");
        apply(&removal).expect("disconnect");
        assert!(
            !codex.join("sbproxy.config.toml").exists(),
            "the profile should be gone"
        );
        assert_eq!(
            std::fs::read_to_string(&user_config).expect("read"),
            EDITED_PROFILE,
            "config.toml must never be touched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lifecycle the page describes, one step further than the two
    /// removal tests above go: connect, hand-edit, disconnect.
    ///
    /// Both of those run on a fresh tree, so `.sbproxy.bak` never pre-exists
    /// and the removal only ever sees the branch that had something to copy.
    /// This one exercises the other branch, which is the one operators live
    /// in: the `.bak` is taken by the first `connect` and holds the file as it
    /// was *before* it, so a removal that leans on the `.bak` deletes every
    /// edit made since. Every `disconnect` after the first used to.
    #[test]
    fn disconnect_keeps_an_edit_the_bak_was_never_going_to_hold() {
        let dir = scratch("disconnect-handedit");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        let profile = codex.join("sbproxy.config.toml");
        std::fs::write(&profile, EDITED_PROFILE).expect("seed profile");
        let env = Environment::fixture(&home);

        // 1. connect. `.sbproxy.bak` takes the pristine original, once.
        apply(&plan_codex(&env, &settings(Direction::Connect)).expect("plan")).expect("connect");
        let backup = codex.join("sbproxy.config.toml.sbproxy.bak");
        assert_eq!(
            std::fs::read_to_string(&backup).expect("read the backup"),
            EDITED_PROFILE
        );

        // 2. the operator edits the profile that connect just wrote. These
        //    bytes are now in exactly one place on the machine.
        let hand_edited = format!(
            "# a note I added by hand\n{}",
            std::fs::read_to_string(&profile).expect("read the profile")
        );
        std::fs::write(&profile, &hand_edited).expect("hand edit");

        // 3. disconnect.
        let removal = plan_codex(&env, &settings(Direction::Disconnect)).expect("plan removal");
        apply(&removal).expect("disconnect");

        assert!(!profile.exists(), "the profile should be gone");
        assert_eq!(
            std::fs::read_to_string(&backup).expect("read the backup"),
            EDITED_PROFILE,
            "the .bak still holds the pre-first-connect original and nothing else"
        );
        assert_eq!(
            std::fs::read_to_string(codex.join("sbproxy.config.toml.sbproxy.removed"))
                .expect("the removed profile has to still be somewhere"),
            hand_edited,
            "disconnect destroyed the only copy of the operator's edit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the same invariant. The rescue copy is not a slot to
    /// overwrite either: a second removal carrying different bytes is refused
    /// at plan time, by name, with nothing unlinked. Identical bytes are not a
    /// conflict, because rewriting the same content takes nothing away.
    #[test]
    fn a_removal_that_would_clobber_an_earlier_rescue_copy_is_refused() {
        let dir = scratch("clobber-rescue");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        let profile = codex.join("sbproxy.config.toml");
        let staged = codex.join("sbproxy.config.toml.sbproxy.removed");
        std::fs::write(&profile, "model = \"the one on disk now\"\n").expect("seed profile");
        std::fs::write(&staged, "model = \"an earlier rescue\"\n").expect("seed rescue");
        let env = Environment::fixture(&home);

        let error = plan_codex(&env, &settings(Direction::Disconnect)).expect_err("must refuse");
        let message = format!("{error:#}");
        assert!(message.contains("sbproxy.removed"), "{message}");
        assert!(profile.is_file(), "nothing may be unlinked on a refusal");
        assert_eq!(
            std::fs::read_to_string(&staged).expect("read rescue"),
            "model = \"an earlier rescue\"\n",
            "the earlier rescue copy must survive untouched"
        );

        // Same content on both sides: nothing is at stake, so it proceeds.
        std::fs::write(&staged, "model = \"the one on disk now\"\n").expect("match the rescue");
        let removal = plan_codex(&env, &settings(Direction::Disconnect)).expect("plan removal");
        apply(&removal).expect("disconnect");
        assert!(!profile.exists(), "the profile should be gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory sync that will not answer is not a write that did not
    /// happen. `sync_all` is `F_FULLFSYNC` on macOS, which returns ENOTSUP on
    /// an SMB- or FUSE-mounted home, so this is somebody's every run. Folding
    /// it into the error told them nothing was written while the file sat on
    /// disk, which is the one report that leaves them unable to undo it.
    #[test]
    fn a_sync_failure_after_the_rename_is_a_write_that_landed() {
        let dir = scratch("not-synced");
        let path = dir.join("sbproxy.config.toml");
        std::fs::write(&path, "before\n").expect("seed");

        let durability = replace_atomically_with(&path, "after\n", None, refusing_sync)
            .expect("a post-rename sync failure must not read as a failed write");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "after\n",
            "the rename landed, so the new bytes are the ones on disk"
        );
        let why = durability
            .warning()
            .expect("the report has to say the sync did not land");
        assert!(why.contains("was written"), "{why}");
        assert!(why.contains("sbproxy.config.toml"), "{why}");

        let durability = remove_durably_with(&path, refusing_sync)
            .expect("a post-unlink sync failure must not read as a failed removal");
        assert!(!path.exists(), "the unlink landed");
        let why = durability
            .warning()
            .expect("the report has to say the sync did not land");
        assert!(why.contains("was removed"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reporting half of the same property. `describe` returns early on a
    /// failure and prints one `failed:` line, which for an unsynced write
    /// would tell the operator nothing was written while the file sits on
    /// disk: no path, no backup, no diff, and no `undo` hint. So this case
    /// reports as a write, with the warning beside it.
    #[test]
    fn an_unsynced_write_is_reported_as_a_write_with_a_warning() {
        let dir = scratch("report-unsynced");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        std::fs::write(codex.join("sbproxy.config.toml"), EDITED_PROFILE).expect("seed");
        let env = Environment::fixture(&home);
        let entry = ClientPlan {
            client: Client::Codex,
            presence: Presence::OnPath(home.join("bin").join("codex")),
            change: Change::File(plan_codex(&env, &settings(Direction::Connect)).expect("plan")),
        };
        let outcome = Outcome::Applied(Durability::NotSynced(
            "'x' was written, but syncing 'y' failed: Operation not supported".to_string(),
        ));

        let (report, block) = describe(&env, &entry, &outcome);
        assert_eq!(report.status, "wrote", "{block}");
        assert_eq!(
            report.warning.as_deref(),
            Some("'x' was written, but syncing 'y' failed: Operation not supported")
        );
        assert_eq!(
            report.backup.as_deref(),
            Some("~/.codex/sbproxy.config.toml.sbproxy.bak")
        );
        assert!(
            block.contains("wrote: ~/.codex/sbproxy.config.toml\n"),
            "{block}"
        );
        assert!(block.contains("    warning: "), "{block}");
        assert!(
            block.contains("backup: ~/.codex/sbproxy.config.toml.sbproxy.bak"),
            "{block}"
        );
        assert!(
            block.contains("+[model_providers.sbproxy]"),
            "the diff has to survive an unsynced write:\n{block}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `stow` or `chezmoi` profile is a link into somebody's dotfiles, and
    /// `rename(2)` onto it replaces the link rather than its target. Refused
    /// rather than noted, because `run` applies before it describes, so a note
    /// would arrive after the link was already gone.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_profile_is_refused_rather_than_swapped_for_a_regular_file() {
        let dir = scratch("symlink");
        let home = dir.join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&codex).expect("mkdir");
        let dotfiles = dir.join("dotfiles");
        std::fs::create_dir_all(&dotfiles).expect("mkdir dotfiles");
        let target = dotfiles.join("sbproxy.config.toml");
        std::fs::write(&target, EDITED_PROFILE).expect("seed the dotfiles copy");
        let link = codex.join("sbproxy.config.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let env = Environment::fixture(&home);

        let error = plan_codex(&env, &settings(Direction::Connect)).expect_err("must refuse");
        let message = format!("{error:#}");
        assert!(message.contains("symlink"), "{message}");
        assert!(
            message.contains("dotfiles"),
            "the target has to be named: {message}"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat the link")
                .file_type()
                .is_symlink(),
            "the link was replaced anyway"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read the dotfiles copy"),
            EDITED_PROFILE,
            "the file the link points at must be untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disconnect_with_no_profile_is_a_no_op() {
        let dir = scratch("disconnect-absent");
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".codex")).expect("mkdir");
        let env = Environment::fixture(&home);
        let edit = plan_codex(&env, &settings(Direction::Disconnect)).expect("plan");
        assert!(edit.is_noop());
        apply(&edit).expect("apply");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_gateway_url_parses_with_or_without_the_v1_suffix() {
        let with = GatewayUrl::parse("http://127.0.0.1:8080/v1").expect("with");
        let without = GatewayUrl::parse("http://127.0.0.1:8080").expect("without");
        let trailing = GatewayUrl::parse("http://127.0.0.1:8080/v1/").expect("trailing");
        assert_eq!(with, without);
        assert_eq!(with, trailing);
        assert_eq!(with.root, "http://127.0.0.1:8080");
        assert_eq!(with.openai, "http://127.0.0.1:8080/v1");
    }

    #[test]
    fn a_url_without_a_scheme_or_host_is_refused() {
        assert!(GatewayUrl::parse("127.0.0.1:8080").is_err());
        assert!(GatewayUrl::parse("ftp://127.0.0.1:8080").is_err());
        assert!(GatewayUrl::parse("http://").is_err());
        assert!(GatewayUrl::parse("http:///v1").is_err());
    }

    #[test]
    fn the_diff_shows_added_lines_with_context_and_elides_the_rest() {
        let before = (1..=40).map(|n| format!("line {n}\n")).collect::<String>();
        let after = format!("{before}tail\n");
        let diff = unified_diff(&before, &after);
        assert!(diff.contains("+tail"), "{diff}");
        assert!(
            diff.contains("..."),
            "unchanged lines were not elided:\n{diff}"
        );
        assert!(
            !diff.contains("    line 1\n"),
            "far context leaked:\n{diff}"
        );
    }

    #[test]
    fn an_absent_client_is_never_written_to() {
        let dir = scratch("absent");
        let home = dir.join("empty-home");
        std::fs::create_dir_all(&home).expect("mkdir");
        let env = Environment::fixture(&home);
        for entry in plan(&env, &settings(Direction::Connect), Client::ALL) {
            assert!(
                matches!(entry.change, Change::NotInstalled),
                "{} was planned against an empty home: {:?}",
                entry.client.slug(),
                entry.change
            );
        }
        assert!(
            !home.join(".codex").exists(),
            "a config directory was created for a client that is not installed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_installed_but_never_configured_codex_is_a_create_not_a_rewrite() {
        let dir = scratch("neverrun");
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".codex")).expect("mkdir");
        let env = Environment::fixture(&home);
        let edit = plan_codex(&env, &settings(Direction::Connect)).expect("plan");
        assert!(edit.before.is_none(), "nothing should have been read");
        assert!(one_time_backup(&edit).is_none(), "nothing to back up");
        let rendered = edit.after().expect("a body").to_string();
        assert!(rendered.contains("[model_providers.sbproxy]"));
        assert!(
            rendered.contains("sbproxy disconnect codex"),
            "the created file should say how to remove it:\n{rendered}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
