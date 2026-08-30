// SPDX-License-Identifier: Apache-2.0
//! Config-source loader.
//!
//! The compiler historically accepted a single string of YAML and went
//! straight to parsing. The loader adds an optional `source:` discriminator
//! on [`crate::ConfigFile`] that lets operators load the underlying
//! text from places other than the inline file:
//!
//! * [`crate::ConfigSource::Local`] - keep the historical behaviour;
//!   the file the operator hands the binary is the config.
//! * [`crate::ConfigSource::Git`] - clone a remote repository at an
//!   optional revision and read one file inside it as the config text.
//! * [`crate::ConfigSource::GitOverlay`] - resolve a base source first,
//!   then layer one or more overlay sources on top, merging the YAML
//!   at each step.
//!
//! Everything in this module operates on `String` payloads. The result
//! flows straight back into [`crate::compile_config`], which keeps the
//! existing schema, env-var interpolation, and validation pipeline
//! unchanged.
//!
//! ## What a git source proves
//!
//! Transport trust and nothing more: HTTPS plus whatever the git host
//! authenticated the fetch as. There is no signature over the document
//! and no provenance beyond "the remote served this". That is what every
//! GitOps tool offers and it is a reasonable place to stand, but it is
//! not the guarantee a signed config bundle carries. Two settings close
//! most of the gap and both are the operator's choice:
//!
//! * Pin `revision` to a full commit sha. The loader resolves `HEAD`
//!   after fetching and refuses the document when it does not equal the
//!   pin, so a branch moving underneath the node cannot be followed.
//! * Set `verify_signature: true`. The loader then requires a good
//!   signature on the resolved tag or commit.
//! * Set `confine: true` when the repository is written by somebody
//!   other than whoever runs the proxy. The fetched document then goes
//!   through [`crate::confined_template`] with
//!   [`crate::ConfinementPolicy::remote_document`]: no secret reference
//!   that reads this host (`env:NAME`, `file:PATH`, `vault://env/NAME`)
//!   and no config key naming a path on it. Off by default, because on
//!   an ordinary GitOps node the repository *is* the operator's config
//!   and the local file is only a pointer, so sealing those spellings
//!   would leave the operator nowhere to write a secret reference at
//!   all (WOR-2433).
//!
//! ## How a git source is fetched
//!
//! Production resolution prefers the `git` binary on `PATH` and falls
//! back to an in-process clone (`gix`) when that binary is missing. The
//! official distroless image has neither a shell nor git, so the
//! fallback is what a git-sourced config uses there. A host that pins
//! the binary with [`FetchContext::with_git_binary_at`] still fails as
//! [`crate::source::ConfigSourceError::MissingGitBinary`] when that path
//! cannot be run. `verify_signature: true` always needs `git`: the
//! in-process path cannot verify GPG or SSH signatures.
//!
//! ## Recursion
//!
//! Overlay chains are bounded by
//! [`crate::source::MAX_RECURSION_DEPTH`]. The cap
//! prevents a malicious or accidental overlay loop from spinning up
//! unbounded git clones.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_yaml::Value as YamlValue;
use tempfile::TempDir;
use thiserror::Error;

use crate::config_merge::BaseOrigin;
use crate::types::ConfigSource;

/// Hard cap on `GitOverlay` nesting depth. The compiler trades the
/// flexibility of arbitrarily deep overlay chains for a predictable
/// upper bound on disk and network use.
pub const MAX_RECURSION_DEPTH: usize = 8;

/// SIGKILL an entire process group by the group leader's pid.
///
/// `git` spawns helpers (credential helpers, `git-remote-*` transports,
/// ssh), so the process that hangs is often not the one this code holds
/// a handle to. `Child::kill` signals only the direct child, which reaps
/// git and reparents its helpers to init, still running and still
/// holding this call's scratch descriptors. Signalling the group reaches
/// all of them.
///
/// The group is created by `process_group(0)` at spawn, so `pid` is also
/// the group id. The guard against signalling our own group is the
/// important part: without `process_group(0)` (a spawn this code did not
/// make, or a future non-unix path) the child would share the parent's
/// group and `kill(-pgid)` would take down the proxy itself.
///
/// Failures are ignored deliberately. The only ones reachable here are a
/// group that already exited and a permissions error that a retry cannot
/// fix, and the caller is already returning a timeout.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    // This crate is `#![forbid(unsafe_code)]`, so the raw `kill(-pgid)`
    // the model-host supervisor uses is not available here. rustix wraps
    // the same syscall safely.
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    let Some(pgid) = rustix::process::Pid::from_raw(raw) else {
        return;
    };
    // Never signal our own group: without the `process_group(0)` above
    // the child would share the proxy's group and this would take the
    // proxy down with it.
    if rustix::process::getpgrp() == pgid {
        return;
    }
    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::Kill);
}

/// Interval between `try_wait` probes while a `git` child runs.
///
/// Short enough that the enforced timeout is accurate to a fraction of a
/// second, long enough that waiting out a one-minute clone costs a
/// negligible number of syscalls.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Largest `timeout_secs` a source may ask for.
///
/// An hour is far past any legitimate config-repository fetch, and the
/// cap also keeps the deadline arithmetic away from the point where
/// adding a `Duration` to an `Instant` overflows.
const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(3600);

/// Largest number of stderr bytes carried into an error message.
///
/// `git` can be verbose on failure and the whole thing ends up in a log
/// line, so the tail is truncated rather than reproduced in full.
const MAX_CAPTURED_STDERR: usize = 4 * 1024;

/// Errors raised by [`load_from_source`] and [`resolve_document`].
///
/// Each variant carries a human-readable message; the prefix in the
/// `Display` impl tells operators which stage of the loader failed. No
/// variant ever carries a credential: the repository URL is redacted
/// before it reaches a message, and captured `git` output is scrubbed.
#[derive(Debug, Error)]
pub enum ConfigSourceError {
    /// A git clone (or local-fixture clone) failed. The wrapped string
    /// is the underlying error or the captured stderr from `git`.
    #[error("source.clone: {0}")]
    Clone(String),
    /// Reading the resolved config file off disk failed.
    #[error("source.read: {0}")]
    Read(String),
    /// Merging two YAML documents in a `GitOverlay` chain failed (one
    /// side was not parseable or the YAML root was the wrong shape).
    #[error("source.merge: {0}")]
    Merge(String),
    /// The overlay chain exceeded [`MAX_RECURSION_DEPTH`].
    #[error("source.recursion: max recursion depth exceeded")]
    RecursionLimit,
    /// The `git` binary is not installed or is not executable. Named
    /// separately so the message can name the dependency instead of
    /// reporting a spawn failure nobody can act on.
    #[error("source.git_missing: {0}")]
    MissingGitBinary(String),
    /// The fetch did not finish inside the configured timeout and the
    /// child process was killed.
    #[error("source.timeout: {0}")]
    Timeout(String),
    /// `revision` pinned a commit sha and the resolved `HEAD` is a
    /// different commit, so following it would mean serving a document
    /// the operator did not pin.
    #[error("source.revision: {0}")]
    RevisionMismatch(String),
    /// `verify_signature` was set and the resolved tag or commit has no
    /// valid signature.
    #[error("source.signature: {0}")]
    Signature(String),
    /// The source block itself is unusable: an empty repo URL, an empty
    /// path, a path that escapes the repository, or a timeout of zero.
    #[error("source.invalid: {0}")]
    Invalid(String),
    /// The document the repository served reaches for something only the
    /// host owner may reach: a secret read straight off the process
    /// environment or the filesystem, or a host path the proxy would
    /// open (WOR-2433). Only raised for a source the operator marked
    /// `confine: true`.
    ///
    /// Separate from [`Self::Invalid`] because it is not a malformed
    /// document. It parses, it would compile, and refusing it is a trust
    /// decision rather than a syntax one, so it earns its own metric
    /// label and its own operator message. A fetched document that does
    /// not parse is reported as [`Self::Invalid`] even though the
    /// confinement check is what noticed, so this counter keeps meaning
    /// "somebody tried to reach this host".
    #[error("source.confinement: {0}")]
    Confinement(String),
}

impl ConfigSourceError {
    /// Whether this error means the source could not be reached, as
    /// opposed to reaching it and refusing what it served.
    ///
    /// The refresh poller keeps serving its cached document either way,
    /// but the two get different metric labels because only one of them
    /// is the operator's content being wrong.
    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(
            self,
            Self::Clone(_) | Self::Timeout(_) | Self::MissingGitBinary(_)
        )
    }

    /// Stable `result` label for `sbproxy_config_source_fetch_total`.
    #[must_use]
    pub const fn metric_label(&self) -> &'static str {
        match self {
            Self::Clone(_) | Self::MissingGitBinary(_) => "unreachable",
            Self::Timeout(_) => "timeout",
            Self::RevisionMismatch(_) => "revision_mismatch",
            Self::Signature(_) => "verify_failed",
            Self::Confinement(_) => "confinement_refused",
            Self::Read(_) | Self::Merge(_) | Self::RecursionLimit | Self::Invalid(_) => "invalid",
        }
    }
}

/// One resolved git revision: what was asked for and what it turned
/// out to be.
///
/// The commit plays the part an `ETag` plays for a signed bundle. An
/// unchanged commit means the document cannot have changed, so the
/// refresh path skips the recompile and the reload entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRevision {
    /// Repository the document was read from, with any credential
    /// already removed.
    pub repo: String,
    /// Branch, tag, or sha that was requested. `HEAD` when the source
    /// named no revision.
    pub reference: String,
    /// Commit the reference resolved to.
    pub commit: String,
}

/// A resolved config document plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDocument {
    /// The config text, ready for [`crate::compile_config`].
    pub text: String,
    /// The git revisions this document was assembled from, in
    /// resolution order. Empty for a purely local source.
    pub revisions: Vec<ResolvedRevision>,
}

impl ResolvedDocument {
    /// A local document: the inline file stands as written.
    #[must_use]
    pub fn local(text: String) -> Self {
        Self {
            text,
            revisions: Vec::new(),
        }
    }

    /// Whether any part of this document came from git.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.revisions.is_empty()
    }

    /// The provenance tag [`crate::merge_config`] should record for
    /// leaves this document contributes.
    ///
    /// The first resolved revision is the base of the chain, which is
    /// the one an operator asking "which repository is this from?"
    /// means.
    #[must_use]
    pub fn base_origin(&self) -> BaseOrigin {
        match self.revisions.first() {
            None => BaseOrigin::Local,
            Some(revision) => BaseOrigin::Git {
                repo: revision.repo.clone(),
                reference: revision.reference.clone(),
                commit: revision.commit.clone(),
            },
        }
    }

    /// Identity of this resolution for change detection: every resolved
    /// commit, in order.
    ///
    /// Two resolutions with the same fingerprint resolved the same
    /// content, so the refresh path can skip the compile and the reload.
    #[must_use]
    pub fn revision_fingerprint(&self) -> String {
        self.revisions
            .iter()
            .map(|revision| revision.commit.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The commit to publish on `sbproxy_config_source_revision_info`,
    /// which is the base of the chain.
    #[must_use]
    pub fn head_commit(&self) -> Option<&str> {
        self.revisions
            .first()
            .map(|revision| revision.commit.as_str())
    }
}

/// One fetch the loader asks a [`Cloner`] to perform.
///
/// `Debug` is implemented by hand rather than derived so the separate
/// credential can never enter a log line.
pub struct FetchRequest<'a> {
    /// Repository URL with any configured userinfo removed.
    pub repo: &'a str,
    /// Resolved credential carried separately from `repo`.
    pub credential: Option<&'a str>,
    /// Username selected from configured URL userinfo, when present.
    /// This is not secret and is only used to form ephemeral HTTP auth.
    pub credential_username: Option<&'a str>,
    /// Branch, tag, or full commit sha, or `None` for the default
    /// branch.
    pub revision: Option<&'a str>,
    /// Hard timeout for the whole fetch.
    pub timeout: Duration,
    /// Whether the resolved tag or commit must carry a valid signature.
    pub verify_signature: bool,
    /// Empty directory the working tree is materialized into.
    pub dest: &'a Path,
    /// Writable directory outside `dest` for captured child output.
    ///
    /// Separate from `dest` because `git clone` refuses a destination
    /// that already has files in it, and a log file is a file.
    pub scratch: &'a Path,
}

impl std::fmt::Debug for FetchRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FetchRequest")
            .field("repo", &redact_repo(self.repo))
            .field("revision", &self.revision)
            .field("has_credential", &self.credential.is_some())
            .field("timeout", &self.timeout)
            .field("verify_signature", &self.verify_signature)
            .finish_non_exhaustive()
    }
}

/// Pluggable git fetch surface (test seam).
///
/// The default production implementation shells out to `git`. Tests
/// install a fake that copies a fixture directory into the destination;
/// the loader logic stays identical.
pub trait Cloner: Send + Sync {
    /// Materialize `request.repo` at `request.revision` into
    /// `request.dest` and report the commit it resolved to.
    ///
    /// The directory at `dest` exists and is empty when the cloner is
    /// invoked.
    fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError>;

    /// Confirm the transport this cloner needs is usable, before any
    /// repository is contacted.
    ///
    /// The production implementation runs `git --version` so a host
    /// with no `git` fails with a message naming the dependency rather
    /// than with a clone error.
    fn preflight(&self) -> Result<(), ConfigSourceError> {
        Ok(())
    }

    /// Ask the remote which commit a reference points at, without
    /// materializing a working tree.
    ///
    /// One network round trip and no working tree, which is what makes
    /// a poll affordable at fifty repositories: `git ls-remote` answers
    /// the only question a change detector has. Argo CD's repo-server
    /// resolves an ambiguous revision the same way and keys its
    /// manifest cache on the resolved commit sha, so an unchanged sha
    /// never reaches a clone (WOR-2438).
    ///
    /// `Ok(None)` means "this cloner cannot answer cheaply", not "the
    /// reference does not exist". The default is `Ok(None)` so a cloner
    /// that only knows how to materialize a tree keeps working and its
    /// caller falls back to a fetch; a missing reference is an
    /// [`ConfigSourceError`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigSourceError::Clone`] when the remote refused the
    /// request or named no such reference, and
    /// [`ConfigSourceError::Timeout`] when the round trip outran
    /// `request.timeout`.
    fn ls_remote(
        &self,
        request: &LsRemoteRequest<'_>,
    ) -> Result<Option<String>, ConfigSourceError> {
        let _ = request;
        Ok(None)
    }
}

/// One cheap remote-reference lookup, the polling half of
/// [`FetchRequest`].
///
/// No `dest`, because nothing is materialized. `Debug` is implemented by
/// hand for the same reason [`FetchRequest`]'s is: the separate
/// credential must never enter a log line.
pub struct LsRemoteRequest<'a> {
    /// Repository URL with any configured userinfo removed.
    pub repo: &'a str,
    /// Resolved credential carried separately from `repo`.
    pub credential: Option<&'a str>,
    /// Username selected from configured URL userinfo, when present.
    pub credential_username: Option<&'a str>,
    /// Branch, tag, or full commit sha, or `None` for the default
    /// branch's `HEAD`.
    pub revision: Option<&'a str>,
    /// Hard timeout for the round trip.
    pub timeout: Duration,
    /// Writable directory for captured child output. `git ls-remote`
    /// writes its answer to stdout, and this is where that is captured.
    pub scratch: &'a Path,
}

impl std::fmt::Debug for LsRemoteRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LsRemoteRequest")
            .field("repo", &redact_repo(self.repo))
            .field("revision", &self.revision)
            .field("has_credential", &self.credential.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Production cloner. Shells out to the `git` binary the caller
/// configured on [`FetchContext`].
pub struct GitBinaryCloner {
    /// Path or basename of the git binary to invoke.
    pub git: PathBuf,
}

impl GitBinaryCloner {
    /// Run one `git` invocation with a hard timeout, returning its
    /// captured stderr.
    ///
    /// See [`kill_process_group`] for why the timeout signals a group
    /// rather than the child alone.
    ///
    /// Output is redirected to a file rather than a pipe on purpose: a
    /// piped child that fills the pipe buffer blocks forever, and this
    /// function's whole job is to be the thing that cannot hang.
    fn run(
        &self,
        args: &[&str],
        working_dir: Option<&Path>,
        scratch: &Path,
        timeout: Duration,
        http_auth: Option<&GitHttpAuth>,
    ) -> Result<GitOutput, ConfigSourceError> {
        let log_path = scratch.join("git-stderr.log");
        let out_path = scratch.join("git-stdout.log");
        let stderr_file = std::fs::File::create(&log_path)
            .map_err(|e| ConfigSourceError::Clone(format!("open git log: {e}")))?;
        let stdout_file = std::fs::File::create(&out_path)
            .map_err(|e| ConfigSourceError::Clone(format!("open git log: {e}")))?;

        let mut command = Command::new(&self.git);
        command.args(args);
        if let Some(dir) = working_dir {
            command.current_dir(dir);
        }
        // No interactive prompt can ever be answered here, and one that
        // waits for an answer is a hang that the timeout below then has to
        // clean up. These three turn every credential prompt into an
        // immediate failure instead. The askpass helpers are removed
        // rather than blanked, because git will happily try to execute an
        // empty program name.
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env_remove("GIT_ASKPASS");
        command.env_remove("SSH_ASKPASS");
        command.env("GCM_INTERACTIVE", "never");
        if let Some(auth) = http_auth {
            // Git reads these as command-scoped configuration. Unlike an
            // authenticated remote URL, the header never enters argv or
            // `.git/config`, and it disappears with the child process.
            command.env("GIT_CONFIG_COUNT", "1");
            command.env("GIT_CONFIG_KEY_0", "http.extraHeader");
            command.env("GIT_CONFIG_VALUE_0", &auth.header);
        }
        command.stdin(Stdio::null());
        command.stdout(Stdio::from(stdout_file));
        command.stderr(Stdio::from(stderr_file));

        // Put the child in its own process group so the timeout below can
        // signal the whole tree.
        //
        // `git` shells out constantly (credential helpers, `git-remote-*`
        // transports, an ssh it spawned). Killing only the direct child
        // reaps git and leaves whatever it spawned running, still holding
        // this scratch directory's descriptors open. That is a process
        // leaked on every reload against a hung remote, and a scratch
        // directory that cannot be cleaned while it is held.
        //
        // Same approach the model-host supervisor uses for engine
        // subprocesses; see `signal_isolated_process_group` there.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }

        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigSourceError::MissingGitBinary(format!(
                    "the `git` binary was not found at '{}'. A `source: {{kind: git}}` config \
                     shells out to git, so every host resolving one needs git installed \
                     (container images included). Install git, or point at it explicitly",
                    self.git.display()
                ))
            } else {
                ConfigSourceError::Clone(format!("spawn git: {e}"))
            }
        })?;

        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(e) => return Err(ConfigSourceError::Clone(format!("wait for git: {e}"))),
            }
            if Instant::now() >= deadline {
                // Kill the whole group, then reap, so neither the child
                // nor anything it spawned outlives this call holding a
                // network connection or a scratch descriptor open.
                //
                // The group signal comes first: killing the direct child
                // alone would reparent its children to init while they
                // keep running, and there would be no handle left to find
                // them by.
                #[cfg(unix)]
                kill_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return Err(ConfigSourceError::Timeout(format!(
                    "`git {}` did not finish within {}s and was killed",
                    args.first().copied().unwrap_or("?"),
                    timeout.as_secs_f64()
                )));
            }
            std::thread::sleep(CHILD_POLL_INTERVAL);
        };

        let stderr = read_capped(&log_path);
        let stdout = read_capped(&out_path);
        Ok(GitOutput {
            success: status.success(),
            stdout,
            stderr,
        })
    }

    /// Resolve `HEAD` in an already-materialized working tree.
    fn head_commit(
        &self,
        dest: &Path,
        scratch: &Path,
        timeout: Duration,
    ) -> Result<String, ConfigSourceError> {
        let output = self.run(&["rev-parse", "HEAD"], Some(dest), scratch, timeout, None)?;
        if !output.success {
            return Err(ConfigSourceError::Clone(format!(
                "git rev-parse HEAD failed: {}",
                output.stderr.trim()
            )));
        }
        let commit = output.stdout.trim().to_string();
        if commit.is_empty() {
            return Err(ConfigSourceError::Clone(
                "git rev-parse HEAD produced no commit".to_string(),
            ));
        }
        Ok(commit)
    }
}

/// Ephemeral HTTP authorization passed to Git through command-scoped
/// environment configuration.
struct GitHttpAuth {
    header: String,
    encoded: String,
}

impl GitHttpAuth {
    fn new(username: Option<&str>, credential: Option<&str>, repo: &str) -> Option<Self> {
        let credential = credential?;
        if !repo.starts_with("https://") && !repo.starts_with("http://") {
            return None;
        }
        let username = username
            .filter(|value| !value.is_empty())
            .unwrap_or("x-access-token");
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{credential}"));
        Some(Self {
            header: format!("Authorization: Basic {encoded}"),
            encoded,
        })
    }
}

/// One completed `git` invocation.
struct GitOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Read at most [`MAX_CAPTURED_STDERR`] bytes of a captured stream,
/// lossily. A missing file reads as empty.
fn read_capped(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let start = bytes.len().saturating_sub(MAX_CAPTURED_STDERR);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// Whether `revision` is a full commit sha, and therefore a pin rather
/// than a moving reference.
///
/// Only the full 40-hex (SHA-1) and 64-hex (SHA-256) forms count. An
/// abbreviated sha is deliberately treated as a reference: it cannot be
/// fetched directly and it cannot be compared against a resolved `HEAD`
/// without deciding how many characters are enough.
#[must_use]
pub fn is_full_commit_sha(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64) && revision.chars().all(|c| c.is_ascii_hexdigit())
}

/// Remove any embedded credential from a repository URL so it is safe
/// to log.
///
/// `https://token@host/repo.git` and `https://user:token@host/repo.git`
/// both become `https://host/repo.git`. A URL with no userinfo is
/// returned unchanged. Applied to every repository string that reaches a
/// log line, an error message, or a provenance record.
#[must_use]
pub fn redact_repo(repo: &str) -> String {
    let Some(scheme_end) = repo.find("://") else {
        return repo.to_string();
    };
    let after_scheme = scheme_end + 3;
    let authority_end = repo[after_scheme..]
        .find('/')
        .map_or(repo.len(), |offset| after_scheme + offset);
    let authority = &repo[after_scheme..authority_end];
    match authority.rfind('@') {
        None => repo.to_string(),
        Some(at) => format!(
            "{}{}{}",
            &repo[..after_scheme],
            &authority[at + 1..],
            &repo[authority_end..]
        ),
    }
}

/// Username from configured URL userinfo, before [`redact_repo`] removes it.
fn repo_username(repo: &str) -> Option<String> {
    let scheme_end = repo.find("://")? + 3;
    let authority_end = repo[scheme_end..]
        .find('/')
        .map_or(repo.len(), |offset| scheme_end + offset);
    let authority = &repo[scheme_end..authority_end];
    let userinfo = authority.rsplit_once('@')?.0;
    let username = userinfo
        .split_once(':')
        .map_or(userinfo, |(username, _)| username);
    (!username.is_empty()).then(|| username.to_string())
}

/// Strip anything that looks like a credential out of captured `git`
/// output before it reaches a log line.
///
/// `git` echoes the remote URL in most of its failure messages, and a
/// URL carrying an injected token would otherwise land in the logs.
#[must_use]
pub fn scrub_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let (before, tail) = rest.split_at(index + 3);
        out.push_str(before);
        // The authority runs to the next delimiter that cannot appear
        // inside it.
        let authority_end = tail
            .find(|c: char| c == '/' || c.is_whitespace() || c == '\'' || c == '"')
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at) => out.push_str(&authority[at + 1..]),
            None => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

impl Cloner for GitBinaryCloner {
    fn preflight(&self) -> Result<(), ConfigSourceError> {
        match Command::new(&self.git)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(ConfigSourceError::MissingGitBinary(format!(
                "`{} --version` exited with {status}; the `git` binary is required to resolve a \
                 `source: {{kind: git}}` config",
                self.git.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ConfigSourceError::MissingGitBinary(format!(
                    "the `git` binary was not found at '{}'. A `source: {{kind: git}}` config \
                     shells out to git, so every host resolving one needs git installed \
                     (container images included). Install git, or point at it explicitly",
                    self.git.display()
                )))
            }
            Err(e) => Err(ConfigSourceError::MissingGitBinary(format!(
                "`{} --version` could not be run: {e}",
                self.git.display()
            ))),
        }
    }

    fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
        let dest = request.dest;
        let dest_str = dest.to_string_lossy().to_string();
        let pinned = request.revision.is_some_and(is_full_commit_sha);
        // `git clone --branch` takes a short name and refuses a
        // fully-qualified ref: `--branch refs/tags/v1.4.2` fails with
        // "Remote branch refs/tags/v1.4.2 not found in upstream origin".
        // A production-tier `origin_sources` entry has to spell a tag
        // that way (WOR-2436), because git does not tell a tag from a
        // branch by spelling, so the clone path cannot serve it and the
        // targeted fetch below has to. `git fetch origin <full ref>`
        // takes it exactly as written, which is the whole reason that
        // spelling was chosen.
        let qualified = request
            .revision
            .is_some_and(|revision| revision.starts_with("refs/"));
        let http_auth = GitHttpAuth::new(
            request.credential_username,
            request.credential,
            request.repo,
        );

        if pinned || qualified {
            let revision = request.revision.unwrap_or_default();
            self.fetch_targeted(request, &dest_str, revision, http_auth.as_ref())?;
        } else {
            let mut args: Vec<&str> = vec!["clone", "--quiet", "--depth", "1"];
            if let Some(reference) = request.revision {
                args.push("--branch");
                args.push(reference);
            }
            args.push("--");
            args.push(request.repo);
            args.push(&dest_str);
            let output = self.run(
                &args,
                None,
                request.scratch,
                request.timeout,
                http_auth.as_ref(),
            )?;
            if !output.success {
                return Err(ConfigSourceError::Clone(format!(
                    "git clone of {} failed: {}",
                    redact_repo(request.repo),
                    scrub_credentials(output.stderr.trim())
                )));
            }
        }

        let commit = self.head_commit(dest, request.scratch, request.timeout)?;
        if pinned {
            let sha = request.revision.unwrap_or_default();
            if !commit.eq_ignore_ascii_case(sha) {
                return Err(ConfigSourceError::RevisionMismatch(format!(
                    "revision pins commit {sha} but {} resolved to {commit}; refusing to serve a \
                     document the pin does not name",
                    redact_repo(request.repo)
                )));
            }
        }
        if request.verify_signature {
            self.verify_signature(request, dest, request.scratch, &commit)?;
        }
        Ok(ResolvedRevision {
            repo: redact_repo(request.repo),
            reference: request.revision.unwrap_or("HEAD").to_string(),
            commit,
        })
    }

    fn ls_remote(
        &self,
        request: &LsRemoteRequest<'_>,
    ) -> Result<Option<String>, ConfigSourceError> {
        // A full sha is its own answer. Asking the remote about it costs
        // a round trip to learn what the config already states, and the
        // server may not advertise the commit at all when it is not the
        // tip of a ref.
        if let Some(revision) = request.revision {
            if is_full_commit_sha(revision) {
                return Ok(Some(revision.to_ascii_lowercase()));
            }
        }
        let http_auth = GitHttpAuth::new(
            request.credential_username,
            request.credential,
            request.repo,
        );
        // `--exit-code` turns "the reference does not exist" into a
        // non-zero exit rather than a silent empty answer, which would
        // otherwise read as "unchanged" forever.
        //
        // Two patterns, not one. `git ls-remote <repo> refs/tags/v1`
        // prints only the tag object; the peeled `refs/tags/v1^{}` line
        // that carries the commit does not match that pattern and is
        // filtered out, so asking for the peeled form explicitly is the
        // only way to see it. Verified against git 2.50: the pair
        // returns both lines for an annotated tag, and for a branch or
        // `HEAD` the second pattern simply matches nothing and the exit
        // code still reflects the first.
        let peeled = request.revision.map_or_else(
            || "HEAD^{}".to_string(),
            |revision| format!("{revision}^{{}}"),
        );
        let mut args: Vec<&str> = vec!["ls-remote", "--exit-code", "--", request.repo];
        args.push(request.revision.unwrap_or("HEAD"));
        args.push(&peeled);
        let output = self.run(
            &args,
            None,
            request.scratch,
            request.timeout,
            http_auth.as_ref(),
        )?;
        if !output.success {
            return Err(ConfigSourceError::Clone(format!(
                "git ls-remote of {} failed: {}",
                redact_repo(request.repo),
                scrub_credentials(output.stderr.trim())
            )));
        }
        Ok(resolved_ls_remote_sha(&output.stdout))
    }
}

/// The commit `git ls-remote` resolved a reference to.
///
/// Each line is `<sha>\t<ref>`. An **annotated** tag has two: the tag
/// object, and the commit it points at under a `^{}` suffix. The peeled
/// line is the one this returns when it is present, because the tag
/// object's sha is not what any checkout of that tag reports, and a
/// change detector that compared a tag object against a checked-out
/// commit would find them different forever and clone on every single
/// round. A production tier pins with `refs/tags/<name>`, so that is
/// not an edge case; it is the main case.
///
/// The peeled line only arrives because the caller asks for it by name.
/// `git ls-remote <repo> refs/tags/v1` filters to refs matching that
/// pattern, and `refs/tags/v1^{}` does not match it, so a single-pattern
/// query returns the tag object alone. See the caller.
///
/// # What this cannot see
///
/// Whether the reference is ambiguous. `git ls-remote <repo> <ref>`
/// matches by suffix, so a bare name can match more than one namespace,
/// and this takes the peeled line of whichever came back. That is why
/// the production tier requires the unambiguous `refs/tags/<name>`
/// spelling and why the commit recorded on a composition still comes
/// from the fetch rather than from here.
fn resolved_ls_remote_sha(stdout: &str) -> Option<String> {
    let mut fallback = None;
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let (Some(sha), reference) = (fields.next(), fields.next()) else {
            continue;
        };
        if sha.is_empty() {
            continue;
        }
        if reference.is_some_and(|reference| reference.ends_with("^{}")) {
            return Some(sha.to_ascii_lowercase());
        }
        if fallback.is_none() {
            fallback = Some(sha.to_ascii_lowercase());
        }
    }
    fallback
}

impl GitBinaryCloner {
    /// Materialize one exact revision: a full commit sha, or a
    /// fully-qualified ref such as `refs/tags/v1.4.2`.
    ///
    /// Two things `git clone` cannot do, and one path that does both.
    /// `git clone --depth 1` cannot ask for an arbitrary commit: the
    /// server has to allow it, which most do not by default (it is
    /// `uploadpack.allowReachableSHA1InWant`). And `git clone --branch`
    /// takes a short name, so it refuses a fully-qualified ref outright.
    /// `git init` plus a targeted shallow fetch takes either, and falls
    /// back to a full fetch of every ref when the server refuses the
    /// shallow one.
    fn fetch_targeted(
        &self,
        request: &FetchRequest<'_>,
        dest_str: &str,
        sha: &str,
        http_auth: Option<&GitHttpAuth>,
    ) -> Result<(), ConfigSourceError> {
        let dest = request.dest;
        let scratch = request.scratch;
        let started = Instant::now();
        let remaining =
            |started: Instant| -> Duration { request.timeout.saturating_sub(started.elapsed()) };

        let init = self.run(
            &["init", "--quiet", dest_str],
            None,
            scratch,
            request.timeout,
            None,
        )?;
        if !init.success {
            return Err(ConfigSourceError::Clone(format!(
                "git init failed: {}",
                scrub_credentials(init.stderr.trim())
            )));
        }
        let add_remote = self.run(
            &["remote", "add", "origin", request.repo],
            Some(dest),
            scratch,
            remaining(started),
            None,
        )?;
        if !add_remote.success {
            return Err(ConfigSourceError::Clone(format!(
                "git remote add failed: {}",
                scrub_credentials(add_remote.stderr.trim())
            )));
        }

        // The shallow, targeted fetch first. It is one commit over the
        // wire when the server allows it.
        let shallow = self.run(
            &["fetch", "--quiet", "--depth", "1", "origin", sha],
            Some(dest),
            scratch,
            remaining(started),
            http_auth,
        )?;
        if !shallow.success {
            // Fall back to fetching every ref, then look for the commit
            // locally. Slower and heavier, and the only thing that works
            // against a server without `allowReachableSHA1InWant`.
            let full = self.run(
                &["fetch", "--quiet", "--tags", "origin"],
                Some(dest),
                scratch,
                remaining(started),
                http_auth,
            )?;
            if !full.success {
                return Err(ConfigSourceError::Clone(format!(
                    "git fetch of {} at {sha} failed, both as a shallow targeted fetch \
                     (the server may not allow one for a bare commit) and as a full fetch: {}",
                    redact_repo(request.repo),
                    scrub_credentials(full.stderr.trim())
                )));
            }
            let checkout = self.run(
                &["checkout", "--quiet", "--detach", sha],
                Some(dest),
                scratch,
                remaining(started),
                None,
            )?;
            if !checkout.success {
                return Err(ConfigSourceError::RevisionMismatch(format!(
                    "{sha} is not present in {} after a full fetch; the pin names a revision \
                     this repository does not contain: {}",
                    redact_repo(request.repo),
                    scrub_credentials(checkout.stderr.trim())
                )));
            }
            return Ok(());
        }

        let checkout = self.run(
            &["checkout", "--quiet", "--detach", "FETCH_HEAD"],
            Some(dest),
            scratch,
            remaining(started),
            None,
        )?;
        if !checkout.success {
            return Err(ConfigSourceError::Clone(format!(
                "git checkout of the fetched commit failed: {}",
                scrub_credentials(checkout.stderr.trim())
            )));
        }
        Ok(())
    }

    /// Require a good signature on the resolved tag or commit.
    ///
    /// A named tag is checked as a tag first, because an operator who
    /// signs releases signs the tag object rather than every commit on
    /// the branch. Otherwise, and when the tag check does not apply, the
    /// commit itself has to be signed.
    fn verify_signature(
        &self,
        request: &FetchRequest<'_>,
        dest: &Path,
        scratch: &Path,
        commit: &str,
    ) -> Result<(), ConfigSourceError> {
        if let Some(reference) = request.revision {
            if !is_full_commit_sha(reference) {
                let tag = self.run(
                    &["verify-tag", reference],
                    Some(dest),
                    scratch,
                    request.timeout,
                    None,
                )?;
                if tag.success {
                    return Ok(());
                }
            }
        }
        let commit_check = self.run(
            &["verify-commit", commit],
            Some(dest),
            scratch,
            request.timeout,
            None,
        )?;
        if commit_check.success {
            return Ok(());
        }
        Err(ConfigSourceError::Signature(format!(
            "verify_signature is set, but neither the reference nor commit {commit} in {} carries \
             a signature this host can verify: {}. Import the signing key into the git \
             trust store, or clear verify_signature",
            redact_repo(request.repo),
            scrub_credentials(commit_check.stderr.trim())
        )))
    }
}

/// Production cloner: `git` on PATH, then an in-process `gix` fetch.
///
/// [`FetchContext::with_git_binary_at`] stays on [`GitBinaryCloner`]
/// alone so a deliberately missing path still names the dependency.
struct GitOrGixCloner {
    git: GitBinaryCloner,
}

impl Cloner for GitOrGixCloner {
    fn preflight(&self) -> Result<(), ConfigSourceError> {
        Ok(())
    }

    fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
        if self.git.preflight().is_ok() {
            return self.git.fetch(request);
        }
        fetch_with_gix(request)
    }

    fn ls_remote(
        &self,
        request: &LsRemoteRequest<'_>,
    ) -> Result<Option<String>, ConfigSourceError> {
        if self.git.preflight().is_ok() {
            return self.git.ls_remote(request);
        }
        // The in-process fallback has no cheap remote query, so the
        // caller falls back to a fetch rather than believing nothing
        // moved. Answering `Ok(None)` here rather than erroring is the
        // difference between a slower poll and a poll that stops.
        Ok(None)
    }
}

fn gix_clone_error(error: impl std::fmt::Display) -> ConfigSourceError {
    ConfigSourceError::Clone(format!(
        "in-process git clone failed: {}",
        scrub_credentials(&error.to_string())
    ))
}

/// Map a gix failure to [`ConfigSourceError::Timeout`] when the deadline
/// thread has already flipped the interrupt flag. Otherwise the failure
/// stays a clone/unreachable error. Pin fetch and pin checkout used to
/// miss this remap, so a distroless timeout after a slow all-heads clone
/// incremented the wrong metric.
fn gix_timeout_or(
    interrupt: &AtomicBool,
    repo: &str,
    timeout: Duration,
    what: &str,
    error: impl std::fmt::Display,
) -> ConfigSourceError {
    if interrupt.load(Ordering::SeqCst) {
        ConfigSourceError::Timeout(format!(
            "in-process git {what} of {} did not finish within {}s",
            redact_repo(repo),
            timeout.as_secs_f64()
        ))
    } else {
        gix_clone_error(error)
    }
}

fn fetch_with_gix(request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
    if request.verify_signature {
        return Err(ConfigSourceError::Signature(
            "`verify_signature: true` requires the `git` binary; the in-process fallback cannot \
             verify GPG or SSH signatures. Install git, or clear verify_signature"
                .to_string(),
        ));
    }

    let pinned = request.revision.is_some_and(is_full_commit_sha);
    let http_auth = GitHttpAuth::new(
        request.credential_username,
        request.credential,
        request.repo,
    );
    let dest = request.dest;
    if dest.exists() {
        let is_empty = std::fs::read_dir(dest)
            .map_err(|error| ConfigSourceError::Clone(format!("read clone dest: {error}")))?
            .next()
            .is_none();
        if is_empty {
            std::fs::remove_dir(dest)
                .map_err(|error| ConfigSourceError::Clone(format!("reset clone dest: {error}")))?;
        }
    }

    let interrupt = Arc::new(AtomicBool::new(false));
    let timeout_flag = Arc::clone(&interrupt);
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let timeout = request.timeout;
    std::thread::spawn(move || {
        if stop_rx.recv_timeout(timeout).is_err() {
            timeout_flag.store(true, Ordering::SeqCst);
        }
    });

    let result = (|| {
        let mut prepare = gix::clone::PrepareFetch::new(
            request.repo,
            dest,
            gix::create::Kind::WithWorktree,
            gix::create::Options::default(),
            gix::open::Options::isolated(),
        )
        .map_err(gix_clone_error)?;

        if let Some(header) = http_auth.as_ref() {
            prepare = prepare
                .with_in_memory_config_overrides([format!("http.extraHeader={}", header.header)]);
        }

        if let Some(revision) = request.revision.filter(|value| !is_full_commit_sha(value)) {
            prepare = prepare
                .with_ref_name(Some(revision))
                .map_err(gix_clone_error)?;
        }
        if pinned {
            // Fetch every advertised head, not just default-branch HEAD,
            // so a pin on another branch is in the object database.
            prepare = prepare.configure_remote(|mut remote| {
                remote
                    .replace_refspecs(
                        std::iter::once("+refs/heads/*:refs/remotes/origin/*"),
                        gix::remote::Direction::Fetch,
                    )
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
                Ok(remote)
            });
        } else {
            prepare = prepare.with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
                std::num::NonZeroU32::MIN,
            ));
        }

        let (mut checkout, _outcome) = prepare
            .fetch_then_checkout(gix::progress::Discard, interrupt.as_ref())
            .map_err(|error| {
                gix_timeout_or(
                    interrupt.as_ref(),
                    request.repo,
                    request.timeout,
                    "clone",
                    error,
                )
            })?;
        let (repo, _outcome) = checkout
            .main_worktree(gix::progress::Discard, interrupt.as_ref())
            .map_err(|error| {
                gix_timeout_or(
                    interrupt.as_ref(),
                    request.repo,
                    request.timeout,
                    "checkout",
                    error,
                )
            })?;

        let mut commit = repo.head_id().map_err(gix_clone_error)?.to_string();
        if pinned {
            let sha = request.revision.unwrap_or_default();
            if !commit.eq_ignore_ascii_case(sha) {
                if repo
                    .rev_parse_single(gix::bstr::ByteSlice::as_bstr(sha.as_bytes()))
                    .is_err()
                {
                    fetch_gix_sha(
                        &repo,
                        sha,
                        request.repo,
                        request.timeout,
                        interrupt.as_ref(),
                    )?;
                }
                commit = checkout_gix_commit(
                    &repo,
                    sha,
                    request.repo,
                    request.timeout,
                    interrupt.as_ref(),
                )?;
            }
        }
        Ok(ResolvedRevision {
            repo: redact_repo(request.repo),
            reference: request.revision.unwrap_or("HEAD").to_string(),
            commit,
        })
    })();
    let _ = stop_tx.send(());
    result
}

fn checkout_gix_commit(
    repo: &gix::Repository,
    sha: &str,
    repo_url: &str,
    timeout: Duration,
    interrupt: &AtomicBool,
) -> Result<String, ConfigSourceError> {
    let id = repo
        .rev_parse_single(gix::bstr::ByteSlice::as_bstr(sha.as_bytes()))
        .map_err(|_| {
            ConfigSourceError::RevisionMismatch(format!(
                "commit {sha} is not present in {} after an in-process fetch; the pin names a \
                 commit this repository does not contain",
                redact_repo(repo_url)
            ))
        })?;
    let hex = id.to_string();
    let object = repo
        .find_object(id)
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "checkout", error))?;
    let tree = object
        .peel_to_tree()
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "checkout", error))?;
    let mut index = repo
        .index_from_tree(&tree.id())
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "checkout", error))?;
    let workdir = repo.workdir().ok_or_else(|| {
        ConfigSourceError::Clone("in-process git clone produced a bare repository".to_string())
    })?;
    let objects = repo.objects.clone();
    gix::worktree::state::checkout(
        &mut index,
        workdir,
        objects,
        &gix::progress::Discard,
        &gix::progress::Discard,
        interrupt,
        Default::default(),
    )
    .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "checkout", error))?;
    Ok(hex)
}

/// Fetch one commit by sha into an already-cloned repository.
///
/// Mirrors `GitBinaryCloner::fetch_pinned_sha`: a targeted want-sha, used
/// when the pin is not on any advertised branch (a dangling or
/// otherwise-unadvertised commit). Servers without
/// `uploadpack.allowReachableSHA1InWant` fail this the same way `git fetch
/// origin <sha>` does.
fn fetch_gix_sha(
    repo: &gix::Repository,
    sha: &str,
    repo_url: &str,
    timeout: Duration,
    interrupt: &AtomicBool,
) -> Result<(), ConfigSourceError> {
    let mut remote = repo
        .find_remote(gix::bstr::ByteSlice::as_bstr("origin".as_bytes()))
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "clone", error))?;
    let spec = format!("+{sha}:refs/sbproxy/pin");
    remote
        .replace_refspecs(
            std::iter::once(spec.as_str()),
            gix::remote::Direction::Fetch,
        )
        .map_err(|error| {
            if interrupt.load(Ordering::SeqCst) {
                gix_timeout_or(interrupt, repo_url, timeout, "clone", &error)
            } else {
                ConfigSourceError::Clone(format!(
                    "in-process git pin refspec failed: {}",
                    scrub_credentials(&error.to_string())
                ))
            }
        })?;
    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "clone", error))?;
    let prepared = connection
        .prepare_fetch(gix::progress::Discard, Default::default())
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "clone", error))?;
    prepared
        .receive(gix::progress::Discard, interrupt)
        .map_err(|error| gix_timeout_or(interrupt, repo_url, timeout, "clone", error))?;
    Ok(())
}

/// Inputs the loader needs to resolve a [`ConfigSource`].
///
/// The temp-dir root is the parent directory git clones land under;
/// each `Git` invocation creates its own [`TempDir`] inside it so
/// cleanup is automatic on drop. The cloner is the strategy actually
/// used to populate that directory; production code prefers the `git`
/// binary and falls back to an in-process clone, and tests wire a
/// fixture-copying stub.
pub struct FetchContext {
    /// Optional override for the temp-dir parent. When `None`, the
    /// OS temp dir is used.
    pub temp_root: Option<PathBuf>,
    /// Cloner strategy used by [`ConfigSource::Git`].
    pub cloner: Box<dyn Cloner>,
    /// Resolved credential per repository URL, keyed by the exact
    /// `repo` string in the config.
    ///
    /// The loader never resolves a secret itself: `sbproxy-config` has
    /// no secret backend and must not grow one. The caller resolves
    /// every `credential:` reference through the process
    /// `SecretResolver` and hands the results in here, which also keeps
    /// resolution failures at boot rather than at the first refresh.
    pub credentials: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for FetchContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FetchContext")
            .field("temp_root", &self.temp_root)
            .field("credentials", &self.credentials.len())
            .finish_non_exhaustive()
    }
}

impl FetchContext {
    /// Build a production fetch context that prefers `git` on `PATH`
    /// and falls back to an in-process clone when that binary is missing.
    #[must_use]
    pub fn with_git_binary() -> Self {
        Self {
            temp_root: None,
            cloner: Box::new(GitOrGixCloner {
                git: GitBinaryCloner {
                    git: PathBuf::from("git"),
                },
            }),
            credentials: std::collections::HashMap::new(),
        }
    }

    /// Build a fetch context that shells out to a specific git binary.
    #[must_use]
    pub fn with_git_binary_at(git: impl Into<PathBuf>) -> Self {
        Self {
            temp_root: None,
            cloner: Box::new(GitBinaryCloner { git: git.into() }),
            credentials: std::collections::HashMap::new(),
        }
    }

    /// Build a fetch context with a custom cloner. The test suite uses
    /// this seam to install a fixture-copying stub in place of `git`.
    #[must_use]
    pub fn with_cloner(cloner: Box<dyn Cloner>) -> Self {
        Self {
            temp_root: None,
            cloner,
            credentials: std::collections::HashMap::new(),
        }
    }

    /// Record the resolved credential for one repository URL.
    #[must_use]
    pub fn with_credential(
        mut self,
        repo: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        self.credentials.insert(repo.into(), credential.into());
        self
    }

    /// Confirm the transport is usable before any repository is
    /// contacted.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigSourceError::MissingGitBinary`] when this context
    /// was built with [`Self::with_git_binary_at`] and that binary cannot
    /// be run. [`Self::with_git_binary`] succeeds without `git`; fetch
    /// then uses the in-process fallback.
    pub fn preflight(&self) -> Result<(), ConfigSourceError> {
        self.cloner.preflight()
    }

    fn new_tempdir(&self) -> Result<TempDir, ConfigSourceError> {
        match &self.temp_root {
            Some(root) => {
                TempDir::new_in(root).map_err(|e| ConfigSourceError::Clone(format!("tempdir: {e}")))
            }
            None => TempDir::new().map_err(|e| ConfigSourceError::Clone(format!("tempdir: {e}"))),
        }
    }
}

/// One Git working tree requested by a callback-oriented consumer.
///
/// The credential field is a secret reference, never a secret value. The
/// corresponding resolved value must already be present in
/// [`FetchContext::credentials`]. Keeping the context in the request preserves
/// the two-argument [`materialize_git_tree`] interface while allowing callers
/// and tests to inject the existing cloning machinery.
pub struct GitTreeRequest<'a> {
    /// Repository URL before credential interpolation.
    pub repo: &'a str,
    /// Full commit SHA or signature-verified reference to materialize.
    pub revision: Option<&'a str>,
    /// Optional secret reference declared for this repository.
    pub credential: Option<&'a str>,
    /// Whether the selected revision must carry a verifiable signature.
    pub verify_signature: bool,
    /// Hard timeout for cloning and revision verification.
    pub timeout: Duration,
    /// Shared cloning, credential, and temporary-directory context.
    pub fetch_context: &'a FetchContext,
}

impl std::fmt::Debug for GitTreeRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitTreeRequest")
            .field("repo", &redact_repo(self.repo))
            .field("revision", &self.revision)
            .field("has_credential", &self.credential.is_some())
            .field("verify_signature", &self.verify_signature)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// A verified Git checkout borrowed for the duration of one callback.
pub struct MaterializedGitTree<'a> {
    root: &'a Path,
    revision: &'a ResolvedRevision,
}

impl MaterializedGitTree<'_> {
    /// Return the root of the temporary checkout.
    #[must_use]
    pub const fn root(&self) -> &Path {
        self.root
    }

    /// Return the verified resolved revision for this checkout.
    #[must_use]
    pub const fn revision(&self) -> &ResolvedRevision {
        self.revision
    }
}

/// Materialize a verified Git tree and invoke a callback while it exists.
///
/// Clone timeout, credential injection, revision pin verification, signature
/// verification, and cleanup all use the same [`Cloner`] implementation as
/// configuration sources. The temporary checkout is dropped after the
/// callback returns, including when the callback returns an error.
///
/// # Errors
///
/// Returns the caller's error type for invalid requests, clone or verification
/// failures, temporary-directory failures, and callback failures. A declared
/// credential without a resolved value fails before any fetch is attempted.
pub fn materialize_git_tree<T, E>(
    request: GitTreeRequest<'_>,
    callback: impl for<'tree> FnOnce(MaterializedGitTree<'tree>) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<ConfigSourceError>,
{
    if request.repo.trim().is_empty() {
        return Err(
            ConfigSourceError::Invalid("Git tree repository must not be empty".to_owned()).into(),
        );
    }
    if request.timeout.is_zero() || request.timeout > MAX_FETCH_TIMEOUT {
        return Err(ConfigSourceError::Invalid(format!(
            "Git tree timeout must be between 1 and {} seconds",
            MAX_FETCH_TIMEOUT.as_secs()
        ))
        .into());
    }

    request.fetch_context.cloner.preflight().map_err(E::from)?;
    let tempdir = request.fetch_context.new_tempdir().map_err(E::from)?;
    let dest = tempdir.path().join("repo");
    let scratch = tempdir.path().join("scratch");
    std::fs::create_dir_all(&dest)
        .map_err(|error| ConfigSourceError::Clone(format!("mkdir target: {error}")))
        .map_err(E::from)?;
    std::fs::create_dir_all(&scratch)
        .map_err(|error| ConfigSourceError::Clone(format!("mkdir scratch: {error}")))
        .map_err(E::from)?;

    let resolved_credential = request
        .credential
        .and_then(|_| request.fetch_context.credentials.get(request.repo))
        .map(String::as_str);
    if request.credential.is_some() && resolved_credential.is_none() {
        return Err(ConfigSourceError::Invalid(format!(
            "a credential is declared for {} but no resolved credential was supplied",
            redact_repo(request.repo)
        ))
        .into());
    }
    let clean_repo = redact_repo(request.repo);
    let credential_username = repo_username(request.repo);
    let http_auth = GitHttpAuth::new(
        credential_username.as_deref(),
        resolved_credential,
        &clean_repo,
    );
    let fetch = FetchRequest {
        repo: &clean_repo,
        credential: resolved_credential,
        credential_username: credential_username.as_deref(),
        revision: request.revision,
        timeout: request.timeout,
        verify_signature: request.verify_signature,
        dest: &dest,
        scratch: &scratch,
    };
    let revision = request
        .fetch_context
        .cloner
        .fetch(&fetch)
        .map_err(|error| {
            sanitize_materialization_error(error, resolved_credential, http_auth.as_ref())
        })
        .map_err(E::from)?;
    callback(MaterializedGitTree {
        root: &dest,
        revision: &revision,
    })
}

/// Cap on one file read out of a materialized checkout.
///
/// A config document and an origin profile are both hand-written YAML:
/// the largest in this repository is a few tens of kilobytes and the
/// bundle a composed document goes into is capped at 4 MiB, so 4 MiB is
/// generous for either and still bounded.
///
/// The cap exists because the file is authored by whoever owns the
/// repository, which for an `origin_sources` entry is deliberately not
/// whoever runs the proxy. Checking a size *after* `read_to_string` has
/// already allocated is not a cap at all: one project repository
/// committing a two-gigabyte file would take the process that composes
/// the whole fleet's configuration down, and it would do it again on
/// the next round.
pub const MAX_CHECKOUT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read one file out of a materialized checkout, refusing anything that
/// is not a plain file genuinely inside it.
///
/// Three refusals, and the middle one is the reason this is a shared
/// function rather than a `join` at each call site.
///
/// * A relative path with no `..` component and no absolute prefix.
///   This constrains the **runtime** document, which is the trusted
///   half: `source.path` and `origin_sources.entries[].path` are both
///   written by whoever runs the proxy.
/// * A path whose resolved target is still inside the checkout, and
///   which is a regular file rather than a symlink. This constrains the
///   **checkout**, which is the untrusted half. `git clone`
///   materializes symlinks, so a project repository can commit
///   `sbproxy/origin.yaml` as a link at the aggregator's own
///   `/etc/sbproxy/sb.yml` and be read with the aggregator's filesystem
///   rights. A traversal check on the configured path cannot see that,
///   and a guard narrower than its claim is worse than none.
/// * A file past `max_bytes`, checked with `metadata` **before** the
///   read rather than after it.
///
/// # What this cannot see
///
/// A file that grows between the `metadata` call and the read. The
/// window is microseconds and the checkout is a temporary directory this
/// process just created, so the only writer is a `git` that has already
/// exited. The read is capped by `take` anyway, so the worst case is a
/// truncated document that fails to parse rather than an unbounded
/// allocation.
///
/// # Errors
///
/// Returns [`ConfigSourceError::Invalid`] for a path shape that is
/// refused before anything is opened, and [`ConfigSourceError::Read`]
/// for a missing file, an unreadable one, a symlink, an escape, or one
/// past `max_bytes`. The three cases are distinguished in the message,
/// because "not in the repository" and "there but unreadable" send an
/// operator to different places.
pub fn read_file_within(
    root: &Path,
    relative: &str,
    max_bytes: u64,
    label: &str,
) -> Result<String, ConfigSourceError> {
    use std::io::Read as _;

    let candidate = Path::new(relative);
    if candidate.is_absolute()
        || relative
            .split('/')
            .any(|part| part == ".." || part == "." || part.is_empty())
    {
        return Err(ConfigSourceError::Invalid(format!(
            "{label} '{relative}' must be a relative path inside the repository, with no `..` \
             or `.` components"
        )));
    }
    let full = root.join(candidate);
    // `symlink_metadata` does not follow, so a link is visible as one.
    let metadata = std::fs::symlink_metadata(&full).map_err(|error| {
        ConfigSourceError::Read(format!(
            "{label} '{relative}' is not in the repository at the resolved revision: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigSourceError::Read(format!(
            "{label} '{relative}' is a symbolic link. A repository this proxy does not own can \
             point a link anywhere the reading process can reach, so a link is refused rather \
             than followed; commit the file itself"
        )));
    }
    if !metadata.is_file() {
        return Err(ConfigSourceError::Read(format!(
            "{label} '{relative}' is not a regular file"
        )));
    }
    if metadata.len() > max_bytes {
        return Err(ConfigSourceError::Read(format!(
            "{label} '{relative}' is {} bytes, past the {max_bytes}-byte limit for a file read \
             out of a repository this proxy does not own",
            metadata.len()
        )));
    }
    // Belt and braces after the symlink refusal: a hard link, or a
    // component of the path that is itself a link, still has to resolve
    // inside the checkout.
    let resolved_root = std::fs::canonicalize(root)
        .map_err(|error| ConfigSourceError::Read(format!("resolve the checkout root: {error}")))?;
    let resolved = std::fs::canonicalize(&full).map_err(|error| {
        ConfigSourceError::Read(format!("resolve {label} '{relative}': {error}"))
    })?;
    if !resolved.starts_with(&resolved_root) {
        return Err(ConfigSourceError::Read(format!(
            "{label} '{relative}' resolves outside the checkout"
        )));
    }
    let file = std::fs::File::open(&resolved).map_err(|error| {
        ConfigSourceError::Read(format!("{label} '{relative}' could not be opened: {error}"))
    })?;
    let mut text = String::new();
    file.take(max_bytes)
        .read_to_string(&mut text)
        .map_err(|error| {
            ConfigSourceError::Read(format!(
                "{label} '{relative}' is there but could not be read (it may not be UTF-8): \
                 {error}"
            ))
        })?;
    Ok(text)
}

/// Ask a repository which commit an entry's revision points at, with no
/// working tree materialized.
///
/// The polling half of [`materialize_git_tree`], and it takes the same
/// [`GitTreeRequest`] so a caller cannot poll one repository and fetch
/// another. Credential resolution, redaction, and the missing-credential
/// refusal are the same code path, deliberately: a poll that
/// authenticated differently from the fetch beside it would report a
/// change the fetch could not then read.
///
/// `Ok(None)` means the cloner cannot answer cheaply and the caller
/// should fetch. `Ok(Some(sha))` is a change detector, not a promise
/// about what a checkout will report: an annotated tag resolves to its
/// peeled commit here, and an ambiguous reference resolves to whichever
/// namespace the remote matched.
///
/// # Errors
///
/// Returns [`ConfigSourceError::Invalid`] for an empty repository, an
/// out-of-range timeout, or a declared credential with no resolved
/// value; [`ConfigSourceError::Clone`] when the remote refused;
/// [`ConfigSourceError::Timeout`] when the round trip outran the
/// request's timeout.
pub fn poll_git_revision(
    request: &GitTreeRequest<'_>,
) -> Result<Option<String>, ConfigSourceError> {
    if request.repo.trim().is_empty() {
        return Err(ConfigSourceError::Invalid(
            "Git tree repository must not be empty".to_owned(),
        ));
    }
    if request.timeout.is_zero() || request.timeout > MAX_FETCH_TIMEOUT {
        return Err(ConfigSourceError::Invalid(format!(
            "Git tree timeout must be between 1 and {} seconds",
            MAX_FETCH_TIMEOUT.as_secs()
        )));
    }
    let resolved_credential = request
        .credential
        .and_then(|_| request.fetch_context.credentials.get(request.repo))
        .map(String::as_str);
    if request.credential.is_some() && resolved_credential.is_none() {
        return Err(ConfigSourceError::Invalid(format!(
            "a credential is declared for {} but no resolved credential was supplied",
            redact_repo(request.repo)
        )));
    }
    let tempdir = request.fetch_context.new_tempdir()?;
    let scratch = tempdir.path().join("scratch");
    std::fs::create_dir_all(&scratch)
        .map_err(|error| ConfigSourceError::Clone(format!("mkdir scratch: {error}")))?;
    let clean_repo = redact_repo(request.repo);
    let credential_username = repo_username(request.repo);
    let http_auth = GitHttpAuth::new(
        credential_username.as_deref(),
        resolved_credential,
        &clean_repo,
    );
    let poll = LsRemoteRequest {
        repo: &clean_repo,
        credential: resolved_credential,
        credential_username: credential_username.as_deref(),
        revision: request.revision,
        timeout: request.timeout,
        scratch: &scratch,
    };
    request
        .fetch_context
        .cloner
        .ls_remote(&poll)
        .map_err(|error| {
            sanitize_materialization_error(error, resolved_credential, http_auth.as_ref())
        })
}

fn sanitize_materialization_error(
    error: ConfigSourceError,
    resolved_credential: Option<&str>,
    http_auth: Option<&GitHttpAuth>,
) -> ConfigSourceError {
    fn clean(
        mut detail: String,
        credential: Option<&str>,
        http_auth: Option<&GitHttpAuth>,
    ) -> String {
        if let Some(auth) = http_auth {
            detail = detail.replace(&auth.header, "[redacted]");
            detail = detail.replace(&auth.encoded, "[redacted]");
        }
        if let Some(credential) = credential.filter(|value| !value.is_empty()) {
            detail = detail.replace(credential, "[redacted]");
        }
        scrub_credentials(&detail)
    }

    match error {
        ConfigSourceError::Clone(detail) => {
            ConfigSourceError::Clone(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::Read(detail) => {
            ConfigSourceError::Read(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::Merge(detail) => {
            ConfigSourceError::Merge(clean(detail, resolved_credential, http_auth))
        }
        // A confinement refusal names a field path and a static form,
        // never a value, and its label is redacted at the point it is
        // built (`confine_fetched_document`) because this sanitizer only
        // wraps the fetch and the check runs after `load_git` returns.
        // It goes through `clean` anyway: this match is exhaustive on
        // purpose so that a new variant has to make this decision
        // explicitly, and a second scrub of an already-redacted string
        // is a no-op rather than a cost.
        ConfigSourceError::Confinement(detail) => {
            ConfigSourceError::Confinement(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::MissingGitBinary(detail) => {
            ConfigSourceError::MissingGitBinary(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::Timeout(detail) => {
            ConfigSourceError::Timeout(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::RevisionMismatch(detail) => {
            ConfigSourceError::RevisionMismatch(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::Signature(detail) => {
            ConfigSourceError::Signature(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::Invalid(detail) => {
            ConfigSourceError::Invalid(clean(detail, resolved_credential, http_auth))
        }
        ConfigSourceError::RecursionLimit => ConfigSourceError::RecursionLimit,
    }
}

/// Resolve a [`ConfigSource`] to a YAML/TOML config text.
///
/// The result is the same flavour of text the caller would have
/// otherwise written inline: it flows straight into
/// [`crate::compile_config`]. `inline_text` is the content of the
/// file the operator handed the binary; it is used as the `Local`
/// payload (so the historical "no source field" path still works).
///
/// # Errors
///
/// Returns [`ConfigSourceError`] naming the stage that failed.
///
/// # Blocking I/O
///
/// Resolving a [`ConfigSource::Git`] source does blocking
/// filesystem work (tempdir creation, `mkdir`, `read_to_string`) and
/// shells out to `git` synchronously through [`Cloner::fetch`].
/// That work runs inline rather than pulling a tokio runtime dependency
/// into this (public) crate: it happens at config load and reload, never
/// on the per-request path. A caller that drives this from a hot
/// reconcile loop should dispatch it to a blocking thread pool itself.
pub async fn load_from_source(
    source: &ConfigSource,
    inline_text: &str,
    fetch_ctx: &FetchContext,
) -> Result<String, ConfigSourceError> {
    load_source_blocking(source, inline_text, fetch_ctx).map(|resolved| resolved.text)
}

/// [`load_from_source`] without the async wrapper.
///
/// The boot path and the reload transaction are both synchronous and
/// run outside any tokio runtime, so they call this directly rather
/// than block on a future that never yields.
///
/// # Errors
///
/// Returns [`ConfigSourceError`] naming the stage that failed.
pub fn load_source_blocking(
    source: &ConfigSource,
    inline_text: &str,
    fetch_ctx: &FetchContext,
) -> Result<ResolvedDocument, ConfigSourceError> {
    let mut revisions = Vec::new();
    let text = load_with_depth(source, inline_text, fetch_ctx, 0, &mut revisions)?;
    Ok(ResolvedDocument { text, revisions })
}

/// Parse the `source:` discriminator out of one config text and resolve
/// it.
///
/// This is the single entry point every caller that has "the bytes an
/// operator handed us" should use: boot, the reload transaction, the
/// refresh poller, `sbproxy validate`, `sbproxy plan`, and the config
/// authority's publish path. A document with no `source:` block, or an
/// explicit `source: {kind: local}`, resolves to itself with no I/O at
/// all, so the call is free on the historical path.
///
/// # Errors
///
/// Returns [`ConfigSourceError::Invalid`] when the `source:` block does
/// not parse, and otherwise whatever [`load_source_blocking`] returns.
pub fn resolve_document(
    inline_text: &str,
    fetch_ctx: &FetchContext,
) -> Result<ResolvedDocument, ConfigSourceError> {
    let Some(source) = parse_source_head(inline_text)? else {
        return Ok(ResolvedDocument::local(inline_text.to_string()));
    };
    load_source_blocking(&source, inline_text, fetch_ctx)
}

/// Read just the `source:` block out of a config text.
///
/// Returns `Ok(None)` for a document with no `source:` and for an
/// explicit `kind: local`, which are the same thing. Parsed with a
/// permissive one-field type so a config that is otherwise garbage
/// still reports its source error here rather than behind a downstream
/// schema failure.
///
/// A blank document (empty, whitespace, comments, or a bare `---`) has no
/// source, the same way [`crate::merge_config`] treats it as an empty
/// mapping. Deciding it is malformed here would turn "you published an
/// empty payload" into a confusing parse error about a block the
/// operator never wrote.
///
/// # Errors
///
/// Returns [`ConfigSourceError::Invalid`] when the block is present but
/// malformed, or when the document root is not a mapping.
pub fn parse_source_head(inline_text: &str) -> Result<Option<ConfigSource>, ConfigSourceError> {
    #[derive(serde::Deserialize)]
    struct SourceHead {
        #[serde(default)]
        source: Option<ConfigSource>,
    }
    // Parse the document as YAML first so a syntax error anywhere is
    // reported as a document problem, not as a malformed `source:`
    // block the file may not even contain (WOR-2710). Only deserialize
    // the `source:` subtree when that key is present.
    let value: serde_yaml::Value = match serde_yaml::from_str(inline_text) {
        Ok(value) => value,
        Err(e) => {
            if inline_text.trim().is_empty() {
                return Ok(None);
            }
            return Err(ConfigSourceError::Invalid(format!(
                "failed to parse config: {e}"
            )));
        }
    };
    if matches!(value, serde_yaml::Value::Null) {
        return Ok(None);
    }
    let Some(mapping) = value.as_mapping() else {
        return Err(ConfigSourceError::Invalid(
            "config root must be a mapping".to_string(),
        ));
    };
    let Some(source_value) = mapping.get(serde_yaml::Value::String("source".to_string())) else {
        return Ok(None);
    };
    let head = SourceHead {
        source: serde_yaml::from_value(source_value.clone()).map_err(|e| {
            ConfigSourceError::Invalid(format!("failed to parse `source:` block: {e}"))
        })?,
    };
    Ok(match head.source {
        None | Some(ConfigSource::Local) => None,
        Some(source) => Some(source),
    })
}

/// The refresh cadence a resolved source wants, or `None` when every
/// git node in it disabled refresh.
///
/// A tree with several git nodes refreshes on the shortest cadence any
/// of them asked for: they are all inputs to one document, so the
/// document is only as fresh as its most impatient input.
#[must_use]
pub fn refresh_interval(source: &ConfigSource) -> Option<Duration> {
    match source {
        ConfigSource::Local => None,
        ConfigSource::Git {
            refresh_interval_secs,
            ..
        } => (*refresh_interval_secs > 0).then(|| Duration::from_secs(*refresh_interval_secs)),
        ConfigSource::GitOverlay { base, overlays } => std::iter::once(base.as_ref())
            .chain(overlays.iter())
            .filter_map(refresh_interval)
            .min(),
    }
}

/// Every `credential:` reference named anywhere in a source tree,
/// paired with the repository it belongs to.
///
/// The caller resolves each one through the process `SecretResolver`
/// and hands the results back on [`FetchContext::credentials`].
#[must_use]
pub fn credential_references(source: &ConfigSource) -> Vec<(String, String)> {
    fn walk(source: &ConfigSource, out: &mut Vec<(String, String)>) {
        match source {
            ConfigSource::Local => {}
            ConfigSource::Git {
                repo, credential, ..
            } => {
                if let Some(credential) = credential {
                    out.push((repo.clone(), credential.clone()));
                }
            }
            ConfigSource::GitOverlay { base, overlays } => {
                walk(base, out);
                for overlay in overlays {
                    walk(overlay, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(source, &mut out);
    out
}

fn load_with_depth(
    source: &ConfigSource,
    inline_text: &str,
    fetch_ctx: &FetchContext,
    depth: usize,
    revisions: &mut Vec<ResolvedRevision>,
) -> Result<String, ConfigSourceError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(ConfigSourceError::RecursionLimit);
    }
    match source {
        ConfigSource::Local => Ok(inline_text.to_string()),
        ConfigSource::Git {
            repo,
            revision,
            path,
            credential,
            verify_signature,
            confine,
            timeout_secs,
            refresh_interval_secs: _,
        } => {
            let spec = GitSpec {
                repo: repo.as_str(),
                revision: revision.as_deref(),
                path: path.as_str(),
                credential: credential.as_deref(),
                verify_signature: *verify_signature,
                timeout: Duration::from_secs(*timeout_secs),
            };
            let (text, resolved) = load_git(&spec, fetch_ctx)?;
            // The document a repository serves is authored by whoever
            // can push to that repository, which is not necessarily
            // whoever runs this proxy. When the operator says those are
            // different parties (`source.confine: true`), the document
            // gets the same boundary a config-authority bundle gets
            // (WOR-2433).
            //
            // Opt-in rather than on by default, because flipping it on
            // is a fail-closed upgrade on a running fleet: every GitOps
            // deployment whose repository names a host path would refuse
            // its own config on the release that changed the default,
            // and a node that boots into a refusal serves nothing. The
            // unconfined path is not silent, though - a document that
            // reaches for this host logs one warning naming the first
            // finding, so an operator on the default learns the setting
            // exists. See `ConfigSource::Git`'s `confine` field for the
            // rest.
            //
            // `remote_document()` keeps `${VAR}`, which is the
            // documented and only supported way to run one shared
            // document across a fleet, and withholds the two powers a
            // remote document was never granted: a secret reference read
            // straight off this host, and a host path the proxy opens.
            if *confine {
                confine_fetched_document(&spec, &text)?;
            } else {
                warn_unconfined_host_reference(&spec, &text, &resolved);
            }
            revisions.push(resolved);
            Ok(text)
        }
        ConfigSource::GitOverlay { base, overlays } => {
            let mut acc = load_with_depth(base, inline_text, fetch_ctx, depth + 1, revisions)?;
            for overlay in overlays {
                let next = load_with_depth(overlay, inline_text, fetch_ctx, depth + 1, revisions)?;
                acc = merge_yaml_text(&acc, &next)?;
            }
            Ok(acc)
        }
    }
}

/// Check a fetched document against the externally-authored boundary,
/// naming it by repository and path.
///
/// Two details the call site would otherwise get wrong. The label goes
/// through [`redact_repo`] like every other repository string that
/// reaches a log line or an error message: this one is rendered on every
/// boot and every refresh of a refusing document, and a `source.repo`
/// carrying `https://token@host/repo.git` would print the token each
/// time (WOR-2433 re-review). And a document that does not parse is
/// reported as [`ConfigSourceError::Invalid`], not as a confinement
/// refusal: this check is the first parse of the fetched text, and
/// `Confinement` means "it parses, it would compile, and this node
/// refuses what it reaches for", which is what makes its metric label
/// worth reading.
fn confine_fetched_document(spec: &GitSpec<'_>, text: &str) -> Result<(), ConfigSourceError> {
    let label = format!("{}:{}", redact_repo(spec.repo), spec.path);
    crate::confined_template::check_confined_document(
        &label,
        text,
        &crate::confined_template::ConfinementPolicy::remote_document(),
    )
    .map_err(|error| match error {
        // "config fragment does not parse as YAML" is the wrong noun for
        // a whole document an operator hands the proxy, and this check is
        // the first thing that parses it, so the message is rebuilt here
        // rather than borrowed (WOR-2433 re-review).
        crate::confined_template::ConfinedTemplateError::Parse { source, .. } => {
            ConfigSourceError::Invalid(format!(
                "config document `{label}` does not parse as YAML: {source}"
            ))
        }
        other => ConfigSourceError::Confinement(other.to_string()),
    })
}

/// Warn once when an **unconfined** git source serves a document that
/// reaches for this host.
///
/// `source.confine` defaults to off, which keeps every GitOps fleet
/// working across the upgrade, and leaves the operator with no signal
/// that the setting exists or that their repository is reaching for the
/// node. This is that signal: the same checker the opt-in runs, with the
/// refusal turned into one warning naming the source and the key. The
/// value is never rendered - the checker's own refusals carry a field
/// path and a static form and never a value, which is what makes this
/// safe to log.
///
/// The **first** finding, not one per finding: the checker returns on
/// the first thing it refuses, so a document naming both a host path and
/// an `env:` reference reports one of them now and the other once that
/// one is fixed. Four places used to say "one warning per finding" and
/// the code never did (WOR-2433 re-review round 3); they say this now.
///
/// Skipped entirely for a `(source, commit)` this process has already
/// walked. `confine` defaults to off, so this walk is on the ordinary
/// path: it parses the whole document into a `serde_yaml::Value` and
/// allocates a `String` per scalar, and the refresh poller resolves the
/// same commit every cycle. A commit and a path pin the bytes, so
/// re-walking them can only produce the answer already given, and the
/// finding dedup below suppressed the line but not the work
/// (WOR-2433 re-review round 3).
///
/// Deduplicated per source and finding on top of that, because a
/// refresh that does bring a new commit usually brings the same finding
/// with it. A document that changes to reach for something else warns
/// again, which is the behavior that matters.
///
/// The key path in the summary is assembled from the fetched document's
/// own mapping key names, and YAML permits a newline or an ANSI escape
/// inside a quoted key, so it goes through
/// [`crate::extensions::sanitize_detail`] before it is formatted: an
/// unsanitized document-controlled string at a log site is newline log
/// forging. The label goes through it too, after [`redact_repo`].
///
/// Returns the redacted source label and the summary it logged, for the
/// test that pins this, and `None` when the document reaches for nothing
/// (or when this revision, or this exact finding, has already been
/// reported).
fn warn_unconfined_host_reference(
    spec: &GitSpec<'_>,
    text: &str,
    resolved: &ResolvedRevision,
) -> Option<(String, String)> {
    let label =
        crate::extensions::sanitize_detail(&format!("{}:{}", redact_repo(spec.repo), spec.path));
    if !first_check_of_revision(&label, &resolved.commit) {
        return None;
    }
    let refusal = crate::confined_template::check_confined_document(
        &label,
        text,
        &crate::confined_template::ConfinementPolicy::remote_document(),
    )
    .err()?;
    // Every host-reaching refusal warns; the two that do not are the
    // compile's business and are reported by the compile that follows
    // (`Parse` is a malformed document, `YamlTag` is a tag the compiler
    // refuses on every path). No other variant can occur under
    // `remote_document`, which grants `${VAR}` and the operator's own
    // declared secret backends.
    //
    // `HostReachingDefault` was missing here for one round, which made
    // the default path silent on the exact spelling the same round
    // closed: `refuse_host_reaching_default` runs *before*
    // `refuse_host_secret_reference` on a string, so
    // `api_key: "${SB_NOPE:-env:AWS_SECRET_ACCESS_KEY}"` produced this
    // variant and nothing else, and this function answered `None`
    // (WOR-2433 re-review round 4).
    let summary = match &refusal {
        crate::confined_template::ConfinedTemplateError::HostSecretReference {
            path, form, ..
        } => format!(
            "`{}` is a `{form}` secret reference read off this host",
            crate::extensions::sanitize_detail(path)
        ),
        crate::confined_template::ConfinedTemplateError::HostFileInlining { path, .. } => {
            format!(
                "`{}` names a path the proxy opens on this host",
                crate::extensions::sanitize_detail(path)
            )
        }
        crate::confined_template::ConfinedTemplateError::HostReachingDefault {
            path, form, ..
        } => format!(
            "`{}` writes a `${{VAR:-default}}` whose default is {form}",
            crate::extensions::sanitize_detail(path)
        ),
        crate::confined_template::ConfinedTemplateError::Parse { .. }
        | crate::confined_template::ConfinedTemplateError::YamlTag { .. } => return None,
        _ => return None,
    };
    if !first_report_of(&label, &summary) {
        return None;
    }
    tracing::warn!(
        source = %label,
        finding = %summary,
        "config source is not confined and its document reaches for this host; the \
         repository can read this node's environment, secrets and filesystem. Set \
         `source.confine: true` to refuse that, after moving the named key into the \
         layer this node owns"
    );
    Some((label, summary))
}

/// Whether this process has yet walked `commit` for `label`.
///
/// Same bounded shape as [`first_report_of`], and bounded for the same
/// reason: a process that has resolved this many distinct commits is
/// long-lived enough that walking one document again costs less than the
/// set does. A poisoned lock falls through to walking, because the walk
/// is what produces the warning and silence is the wrong failure here.
fn first_check_of_revision(label: &str, commit: &str) -> bool {
    static CHECKED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let checked = CHECKED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let Ok(mut seen) = checked.lock() else {
        return true;
    };
    if seen.len() >= MAX_REMEMBERED_UNCONFINED_FINDINGS {
        return true;
    }
    seen.insert(format!("{label} @ {commit}"))
}

/// Whether this is the first time `summary` has been reported for
/// `label` in this process.
///
/// Bounded: the set stops growing at
/// [`MAX_REMEMBERED_UNCONFINED_FINDINGS`], after which every finding is
/// treated as new. A process with that many distinct findings has a
/// louder problem than a repeated log line.
fn first_report_of(label: &str, summary: &str) -> bool {
    static REPORTED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let reported = REPORTED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let Ok(mut seen) = reported.lock() else {
        // A poisoned lock means another thread panicked while holding
        // it. Warning twice is better than not warning.
        return true;
    };
    if seen.len() >= MAX_REMEMBERED_UNCONFINED_FINDINGS {
        return true;
    }
    seen.insert(format!("{label} :: {summary}"))
}

/// How many distinct unconfined-source entries this process remembers,
/// for the finding dedup and for the revision cache alike.
const MAX_REMEMBERED_UNCONFINED_FINDINGS: usize = 256;

/// One `Git` source, flattened so the loader is not passing seven
/// arguments around.
struct GitSpec<'a> {
    repo: &'a str,
    revision: Option<&'a str>,
    path: &'a str,
    credential: Option<&'a str>,
    verify_signature: bool,
    timeout: Duration,
}

fn load_git(
    spec: &GitSpec<'_>,
    fetch_ctx: &FetchContext,
) -> Result<(String, ResolvedRevision), ConfigSourceError> {
    if spec.repo.trim().is_empty() {
        return Err(ConfigSourceError::Invalid(
            "source.repo must not be empty".to_string(),
        ));
    }
    if spec.path.trim().is_empty() {
        return Err(ConfigSourceError::Invalid(
            "source.path must name the config file inside the repository".to_string(),
        ));
    }
    if spec.timeout.is_zero() || spec.timeout > MAX_FETCH_TIMEOUT {
        return Err(ConfigSourceError::Invalid(format!(
            "source.timeout_secs must be between 1 and {}; a fetch with no timeout can hang \
             startup, which this repository has already paid for once",
            MAX_FETCH_TIMEOUT.as_secs()
        )));
    }
    // A path that walks out of the checkout would read an arbitrary file
    // off the proxy host, which is not what "a file inside the
    // repository" means.
    let relative = Path::new(spec.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigSourceError::Invalid(format!(
            "source.path '{}' must be a relative path inside the repository, with no `..` \
             components",
            spec.path
        )));
    }

    materialize_git_tree(
        GitTreeRequest {
            repo: spec.repo,
            revision: spec.revision,
            credential: spec.credential,
            verify_signature: spec.verify_signature,
            timeout: spec.timeout,
            fetch_context: fetch_ctx,
        },
        |tree| {
            // The same guard the aggregator uses, for the same reason:
            // a `confine: true` source is a repository this proxy does
            // not own, and `git clone` materializes symlinks.
            let text = read_file_within(
                tree.root(),
                &relative.to_string_lossy(),
                MAX_CHECKOUT_FILE_BYTES,
                "source.path",
            )
            .map_err(|error| {
                ConfigSourceError::Read(format!(
                    "'{}' at {} in {}: {error}",
                    spec.path,
                    tree.revision().commit,
                    redact_repo(spec.repo)
                ))
            })?;
            Ok((text, tree.revision().clone()))
        },
    )
}

/// Merge two YAML documents shallow-deep: maps are merged by key with
/// the overlay winning collisions, sequences are replaced wholesale,
/// scalars are overwritten. The result is re-serialised back to YAML
/// text so the rest of the compile path stays string-shaped.
fn merge_yaml_text(base: &str, overlay: &str) -> Result<String, ConfigSourceError> {
    let mut base_val: YamlValue = serde_yaml::from_str(base)
        .map_err(|e| ConfigSourceError::Merge(format!("parse base: {e}")))?;
    let overlay_val: YamlValue = serde_yaml::from_str(overlay)
        .map_err(|e| ConfigSourceError::Merge(format!("parse overlay: {e}")))?;
    merge_yaml_value(&mut base_val, overlay_val);
    serde_yaml::to_string(&base_val)
        .map_err(|e| ConfigSourceError::Merge(format!("serialise result: {e}")))
}

fn merge_yaml_value(base: &mut YamlValue, overlay: YamlValue) {
    match (base, overlay) {
        (YamlValue::Mapping(base_map), YamlValue::Mapping(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) => merge_yaml_value(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_val) => {
            *base_slot = overlay_val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A `{:?}` of a poll request must not print the credential.
    ///
    /// Pins the registry line in `scripts/secret-debug-registry.txt`.
    /// The struct carries a resolved credential, so a derived `Debug`
    /// would put a token into any log line, panic message or test
    /// failure that formatted the request.
    #[test]
    fn debug_never_renders_the_ls_remote_credential() {
        let request = LsRemoteRequest {
            repo: "https://git.test/acme/checkout",
            credential: Some("sk-live-LSREMOTE-SENTINEL"),
            credential_username: Some("git"),
            revision: Some("refs/tags/v1.4.2"),
            timeout: Duration::from_secs(5),
            scratch: Path::new("/tmp"),
        };
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("LSREMOTE-SENTINEL"),
            "the credential reached a Debug rendering: {rendered}"
        );
        assert!(
            rendered.contains("has_credential: true"),
            "presence is still reported, so a Debug is worth having: {rendered}"
        );
    }

    /// An annotated tag's peeled commit wins over the tag object.
    #[test]
    fn ls_remote_output_resolves_to_the_peeled_commit() {
        let tag_object = "1".repeat(40);
        let commit = "2".repeat(40);
        let annotated =
            format!("{tag_object}\trefs/tags/v1.4.2\n{commit}\trefs/tags/v1.4.2^{{}}\n");
        assert_eq!(
            resolved_ls_remote_sha(&annotated),
            Some(commit.clone()),
            "the tag object's sha is not what a checkout of that tag reports, so comparing it \
             against one would clone on every round forever"
        );
        // A lightweight tag and a branch print one line and have no
        // peeled form, so the only line is the answer.
        let lightweight = format!("{commit}\trefs/tags/v1.4.2\n");
        assert_eq!(resolved_ls_remote_sha(&lightweight), Some(commit));
        assert_eq!(resolved_ls_remote_sha(""), None);
        assert_eq!(resolved_ls_remote_sha("\n\n"), None);
    }

    /// A cloner that only knows how to materialize a tree answers the
    /// cheap question with "I cannot", so its caller fetches rather than
    /// believing nothing moved.
    #[test]
    fn the_default_ls_remote_says_it_cannot_answer_rather_than_saying_unchanged() {
        struct TreeOnly;
        impl Cloner for TreeOnly {
            fn fetch(
                &self,
                _request: &FetchRequest<'_>,
            ) -> Result<ResolvedRevision, ConfigSourceError> {
                Err(ConfigSourceError::Clone("not used".to_string()))
            }
        }
        let request = LsRemoteRequest {
            repo: "https://git.test/acme/checkout",
            credential: None,
            credential_username: None,
            revision: None,
            timeout: Duration::from_secs(5),
            scratch: Path::new("/tmp"),
        };
        assert_eq!(
            TreeOnly
                .ls_remote(&request)
                .expect("the default never errors"),
            None,
            "`Ok(None)` is \"cannot answer cheaply\" and not \"the reference does not exist\""
        );
    }

    /// Fixture-copying stub that swaps in for `git clone` in tests.
    /// Each `repo` key maps to a directory layout that is copied into
    /// the destination when the loader asks for it.
    struct FixtureCloner {
        // Maps `repo` URL -> list of (relative path, file contents).
        repos: HashMapOfRepos,
        // Captured calls, for assertion.
        calls: Mutex<Vec<CapturedClone>>,
    }

    type HashMapOfRepos = std::collections::HashMap<String, Vec<(&'static str, &'static str)>>;

    /// One recorded clone: the repo asked for, the revision requested, and
    /// the credential reference resolved for it.
    ///
    /// Named rather than an inline tuple because the credential element took
    /// it past clippy's `type_complexity` threshold, and because three
    /// same-shaped `Option<String>` positions are worth labelling.
    type CapturedClone = (String, Option<String>, Option<String>);

    impl FixtureCloner {
        fn new(repos: HashMapOfRepos) -> Self {
            Self {
                repos,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Cloner for FixtureCloner {
        fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
            self.calls.lock().expect("calls lock").push((
                request.repo.to_string(),
                request.revision.map(str::to_string),
                request.credential.map(str::to_string),
            ));
            let layout = self.repos.get(request.repo).ok_or_else(|| {
                ConfigSourceError::Clone(format!("unknown fixture repo: {}", request.repo))
            })?;
            for (rel, contents) in layout {
                let target = request.dest.join(rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ConfigSourceError::Clone(format!("mkdir: {e}")))?;
                }
                std::fs::write(&target, contents)
                    .map_err(|e| ConfigSourceError::Clone(format!("write: {e}")))?;
            }
            Ok(ResolvedRevision {
                repo: redact_repo(request.repo),
                reference: request.revision.unwrap_or("HEAD").to_string(),
                commit: "a".repeat(40),
            })
        }
    }

    fn ctx_with(cloner: FixtureCloner) -> (FetchContext, Arc<FixtureCloner>) {
        // Wrap in Arc so the test can still inspect call counts after
        // handing ownership of the trait object to `FetchContext`.
        let arc = Arc::new(cloner);
        let trait_obj: Box<dyn Cloner> = Box::new(ArcClonerProxy(arc.clone()));
        (FetchContext::with_cloner(trait_obj), arc)
    }

    /// Thin proxy so the `FixtureCloner` can live behind an `Arc` and
    /// also be passed to `FetchContext` as a `Box<dyn Cloner>`.
    struct ArcClonerProxy(Arc<FixtureCloner>);

    impl Cloner for ArcClonerProxy {
        fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
            self.0.fetch(request)
        }
    }

    /// A `Git` source with the loader's own defaults, so a test only
    /// spells out the fields it cares about.
    fn git_source(repo: &str, revision: Option<&str>, path: &str) -> ConfigSource {
        ConfigSource::Git {
            repo: repo.to_string(),
            revision: revision.map(str::to_string),
            path: path.to_string(),
            credential: None,
            verify_signature: false,
            confine: false,
            timeout_secs: 60,
            refresh_interval_secs: 60,
        }
    }

    fn load(
        source: &ConfigSource,
        inline: &str,
        ctx: &FetchContext,
    ) -> Result<ResolvedDocument, ConfigSourceError> {
        load_source_blocking(source, inline, ctx)
    }

    /// WOR-2433 re-review. The confinement label is built from the
    /// `source.repo` string, which may carry a token, and it is rendered
    /// on every boot and every refresh of a refusing document. This
    /// error never passes through `sanitize_materialization_error`
    /// either, because that only wraps the fetch and this check runs
    /// after `load_git` has returned, so the redaction has to happen
    /// where the label is built.
    #[test]
    fn a_confinement_refusal_never_carries_the_repositorys_credential() {
        for repo in [
            "https://ghp_examplesecrettoken@github.com/acme/config.git",
            "https://acme:ghp_examplesecrettoken@github.com/acme/config.git",
        ] {
            let spec = GitSpec {
                repo,
                revision: None,
                path: "sb.yml",
                credential: None,
                verify_signature: false,
                timeout: Duration::from_secs(60),
            };
            let error = confine_fetched_document(
                &spec,
                "origins:\n  api:\n    authentication:\n      api_key: \"env:AWS_SECRET_ACCESS_KEY\"\n",
            )
            .expect_err("a confined document may not read this host's environment");

            let rendered = error.to_string();
            assert!(
                !rendered.contains("ghp_examplesecrettoken"),
                "the refusal carried the repository credential: {rendered}"
            );
            assert!(
                rendered.contains("github.com/acme/config.git:sb.yml"),
                "the refusal must still say which document it refused: {rendered}"
            );
        }
    }

    /// A resolved revision for the warning tests, which care about the
    /// commit only as a cache key.
    fn revision_at(commit: &str) -> ResolvedRevision {
        ResolvedRevision {
            repo: "https://example.test/warn.git".into(),
            reference: "HEAD".into(),
            commit: commit.into(),
        }
    }

    /// WOR-2433 re-review, the ruling on the default. `source.confine`
    /// stays off, so the unconfined path has to say something: an
    /// operator who never heard of the setting otherwise gets no signal
    /// that their repository can read this node's environment.
    #[test]
    fn an_unconfined_source_reaching_for_this_host_warns_once_per_finding() {
        let spec = GitSpec {
            repo: "https://ghp_examplesecrettoken@github.com/acme/warn-once.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        let document =
            "origins:\n  api:\n    authentication:\n      api_key: \"env:AWS_SECRET_ACCESS_KEY\"\n";

        let (label, summary) =
            warn_unconfined_host_reference(&spec, document, &revision_at("warn-once-1"))
                .expect("an unconfined source reaching for this host must be reported");

        assert!(
            !label.contains("ghp_examplesecrettoken"),
            "the warning carried the repository credential: {label}"
        );
        assert!(
            label.contains("github.com/acme/warn-once.git:sb.yml"),
            "{label}"
        );
        assert!(
            summary.contains("origins.api.authentication.api_key"),
            "the warning must name the key: {summary}"
        );
        assert!(
            !summary.contains("AWS_SECRET_ACCESS_KEY"),
            "the warning named the variable rather than the form: {summary}"
        );
        // A new commit, so the revision cache does not answer this one:
        // the walk runs again and the finding dedup is what stays quiet.
        assert!(
            warn_unconfined_host_reference(&spec, document, &revision_at("warn-once-2")).is_none(),
            "the same finding must not be reported on every refresh cycle"
        );
    }

    /// WOR-2433 re-review round 3, New 9. The docs say the warning fires
    /// "at boot and again whenever a refresh brings a revision this
    /// process has not already checked", and the dedup set above
    /// suppressed the log line without suppressing the walk: a full
    /// `serde_yaml` parse plus a `String` per scalar, every refresh
    /// cycle, on the default path where nothing asked for a check.
    ///
    /// The observable is a *different* finding at the same commit. The
    /// finding dedup cannot explain silence here, so the only thing that
    /// can is the walk not having run.
    #[test]
    fn an_unconfined_source_is_not_rewalked_at_a_revision_already_checked() {
        let spec = GitSpec {
            repo: "https://github.com/acme/warn-revision.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        let commit = revision_at("f00dcafe");

        let (_, first) = warn_unconfined_host_reference(
            &spec,
            "origins:\n  api:\n    authentication:\n      api_key: \"env:AWS_SECRET_ACCESS_KEY\"\n",
            &commit,
        )
        .expect("the first sight of a revision is walked");
        assert!(first.contains("api_key"), "{first}");

        assert!(
            warn_unconfined_host_reference(
                &spec,
                "origins:\n  api:\n    request_modifiers:\n      - rego_module_path: /etc/x.rego\n",
                &commit,
            )
            .is_none(),
            "a revision this process already walked must not be walked again"
        );

        // And a genuinely new revision is walked, so the skip is a cache
        // rather than a mute button.
        assert!(
            warn_unconfined_host_reference(
                &spec,
                "origins:\n  api:\n    request_modifiers:\n      - rego_module_path: /etc/x.rego\n",
                &revision_at("deadbeef"),
            )
            .is_some(),
            "a revision this process has not checked must be walked"
        );
    }

    /// WOR-2433 re-review round 3, New 5. The key path in the summary is
    /// assembled from the document's own mapping key names, and YAML
    /// permits a newline or an ANSI escape inside a quoted key, so an
    /// externally authored repository could forge a complete log line
    /// under the default fmt layer.
    #[test]
    fn a_document_controlled_key_cannot_forge_a_log_line() {
        let spec = GitSpec {
            repo: "https://github.com/acme/warn-forge.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        // A quoted key carrying a newline, a carriage return and an ANSI
        // SGR sequence, wrapped around a key the guard refuses so the
        // path reaches the log line at all.
        let document = concat!(
            "\"forged\\n2026-08-27T00:00:00Z WARN sbproxy: all clear\\r\\u001b[31m\":\n",
            "  rego_module_path: /etc/sbproxy/x.rego\n",
        );

        let (label, summary) =
            warn_unconfined_host_reference(&spec, document, &revision_at("forge"))
                .expect("the host path is still refused; only its rendering changes");

        for (name, rendered) in [("label", &label), ("finding", &summary)] {
            assert!(
                !rendered.contains('\n') && !rendered.contains('\r'),
                "a newline survived into the {name} field: {rendered:?}"
            );
            assert!(
                !rendered.contains('\u{1b}'),
                "an ANSI escape survived into the {name} field: {rendered:?}"
            );
            assert!(
                !rendered.chars().any(char::is_control),
                "a control character survived into the {name} field: {rendered:?}"
            );
        }
        assert!(
            summary.contains("rego_module_path"),
            "the warning must still name the key it refused: {summary}"
        );
    }

    #[test]
    fn an_unconfined_source_naming_a_host_path_warns_about_the_key() {
        let spec = GitSpec {
            repo: "https://github.com/acme/warn-path.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        let document =
            "origins:\n  api:\n    request_modifiers:\n      - rego_module_path: /etc/sbproxy/x.rego\n";

        let (_, summary) =
            warn_unconfined_host_reference(&spec, document, &revision_at("warn-path"))
                .expect("a host path in an unconfined document must be reported");

        assert!(summary.contains("rego_module_path"), "{summary}");
        assert!(
            !summary.contains("/etc/sbproxy/x.rego"),
            "the warning echoed the path: {summary}"
        );
    }

    /// WOR-2433 re-review round 4, New 2. `confine` defaults to off, and
    /// the docs say the warning "is the answer to what would
    /// `confine: true` refuse if I turned it on". For a document that
    /// reaches the host through a `${VAR:-default}` it was not: the walk
    /// produced `HostReachingDefault`, this function rendered two
    /// variants and returned `None` for everything else, and
    /// `first_check_of_revision` then cached the silence for the life of
    /// the process at that commit.
    #[test]
    fn an_unconfined_source_reaching_for_this_host_through_a_default_warns() {
        let spec = GitSpec {
            repo: "https://github.com/acme/warn-default.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };

        let (_, summary) = warn_unconfined_host_reference(
            &spec,
            "origins:\n  api:\n    authentication:\n      api_key: \"${SB_NOPE_2433:-env:AWS_SECRET_ACCESS_KEY}\"\n",
            &revision_at("warn-default-1"),
        )
        .expect("a default that reaches this host is a finding like any other");
        assert!(summary.contains("api_key"), "{summary}");
        assert!(
            !summary.contains("AWS_SECRET_ACCESS_KEY"),
            "the warning echoed the default it refused: {summary}"
        );

        let (_, summary) = warn_unconfined_host_reference(
            &spec,
            "origins:\n  api:\n    action:\n      type: proxy\n      url: \"${SB_NOPE_2433:-/etc/sbproxy/x}\"\n",
            &revision_at("warn-default-2"),
        )
        .expect("an absolute path in a default is a finding too");
        assert!(summary.contains("url"), "{summary}");
        assert!(
            !summary.contains("/etc/sbproxy/x"),
            "the warning echoed the path it refused: {summary}"
        );
    }

    #[test]
    fn the_loader_reports_an_unconfined_source_that_reaches_for_this_host() {
        // A covered function is not a wired one. The dedup set is the
        // observable: if `load` reported this finding, a direct call
        // with the same source and document returns `None` because it
        // has already been said.
        const DOCUMENT: &str =
            "origins:\n  api:\n    authentication:\n      api_key: \"env:AWS_SECRET_ACCESS_KEY\"\n";
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/warn-wired.git".into(),
            vec![("sb.yml", DOCUMENT)],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let source = git_source(
            "https://example.test/warn-wired.git",
            Some("main"),
            "sb.yml",
        );

        let loaded = load(&source, "", &ctx).expect("an unconfined source still loads");
        assert_eq!(loaded.text, DOCUMENT, "and is served unchanged");

        let spec = GitSpec {
            repo: "https://example.test/warn-wired.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        // A commit the fixture never resolved to, so the revision cache
        // cannot answer this call and the finding dedup is still the
        // only thing that can make it quiet.
        assert!(
            warn_unconfined_host_reference(&spec, DOCUMENT, &revision_at("not-the-fixtures"))
                .is_none(),
            "the loader did not report the finding, so nothing warned the operator"
        );
    }

    #[test]
    fn an_unconfined_source_with_a_clean_document_says_nothing() {
        // `${VAR}` is the documented way one shared document names
        // per-node values, so it is not a finding and must not train
        // operators to ignore this warning.
        let spec = GitSpec {
            repo: "https://github.com/acme/warn-clean.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };

        assert!(warn_unconfined_host_reference(
            &spec,
            "proxy:\n  cluster:\n    node_id: \"${SB_NODE_ID}\"\n",
            &revision_at("warn-clean"),
        )
        .is_none());
    }

    /// The other half of the same site: a document that does not parse is
    /// a syntax problem, not a trust decision, so it must not climb the
    /// confinement counter.
    #[test]
    fn a_confined_document_that_does_not_parse_is_invalid() {
        let spec = GitSpec {
            repo: "https://github.com/acme/config.git",
            revision: None,
            path: "sb.yml",
            credential: None,
            verify_signature: false,
            timeout: Duration::from_secs(60),
        };
        let error = confine_fetched_document(&spec, "origins:\n  api\n    action: [unclosed\n")
            .expect_err("a malformed document must fail");
        assert!(matches!(error, ConfigSourceError::Invalid(_)), "{error:?}");
        assert_eq!(error.metric_label(), "invalid");
    }

    #[test]
    fn local_round_trips_inline_text() {
        let ctx = FetchContext::with_git_binary();
        let inline = "proxy: {}\norigins: {}\n";
        let result = load(&ConfigSource::Local, inline, &ctx).expect("local loads");
        assert_eq!(result.text, inline);
        assert!(!result.is_remote());
        assert_eq!(result.base_origin(), BaseOrigin::Local);
    }

    #[test]
    fn git_reads_the_requested_file() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/repo.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":8080\"\n")],
        );
        let (ctx, cloner) = ctx_with(FixtureCloner::new(repos));
        let source = git_source("https://example.test/repo.git", Some("main"), "sb.yml");
        let result = load(&source, "", &ctx).expect("git loads");
        assert!(result.text.contains("listen"));
        assert!(result.is_remote());
        assert_eq!(
            result.base_origin(),
            BaseOrigin::Git {
                repo: "https://example.test/repo.git".into(),
                reference: "main".into(),
                commit: "a".repeat(40),
            }
        );
        let calls = cloner.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://example.test/repo.git");
        assert_eq!(calls[0].1.as_deref(), Some("main"));
    }

    #[test]
    fn git_overlay_merges_base_and_overlay() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/base.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":8080\"\norigins:\n  a: {}\n")],
        );
        repos.insert(
            "https://example.test/overlay.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":9090\"\norigins:\n  b: {}\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let base = git_source("https://example.test/base.git", None, "sb.yml");
        let overlay = git_source("https://example.test/overlay.git", None, "sb.yml");
        let source = ConfigSource::GitOverlay {
            base: Box::new(base),
            overlays: vec![overlay],
        };
        let merged = load(&source, "", &ctx).expect("overlay loads");
        let parsed: YamlValue = serde_yaml::from_str(&merged.text).expect("parse merged");
        let proxy = parsed.get("proxy").expect("proxy map");
        assert_eq!(
            proxy.get("listen").and_then(YamlValue::as_str),
            Some(":9090"),
            "overlay scalar wins"
        );
        let origins = parsed.get("origins").expect("origins map");
        assert!(origins.get("a").is_some(), "base map key survives");
        assert!(origins.get("b").is_some(), "overlay map key merges in");
        // Both revisions are recorded, base first, so the fingerprint
        // changes when either input moves.
        assert_eq!(merged.revisions.len(), 2);
        assert_eq!(merged.revisions[0].repo, "https://example.test/base.git");
    }

    #[test]
    fn recursion_limit_kicks_in_at_nine_levels() {
        // Build an overlay chain 9 levels deep. Each level wraps the
        // previous in another `GitOverlay`. The cap is 8, so the 9th
        // level must trip `RecursionLimit`.
        let mut inner = ConfigSource::Local;
        for _ in 0..9 {
            inner = ConfigSource::GitOverlay {
                base: Box::new(inner),
                overlays: vec![],
            };
        }
        let ctx = FetchContext::with_git_binary();
        let err = load(&inner, "x: 1\n", &ctx).expect_err("9-deep overlay must error");
        assert!(matches!(err, ConfigSourceError::RecursionLimit));
    }

    #[test]
    fn merge_overlay_replaces_scalars_and_unions_maps() {
        let base = "a: 1\nb:\n  c: 1\n  d: 2\n";
        let overlay = "b:\n  c: 9\ne: 5\n";
        let merged = merge_yaml_text(base, overlay).expect("merge ok");
        let parsed: YamlValue = serde_yaml::from_str(&merged).expect("parse");
        assert_eq!(parsed.get("a").and_then(YamlValue::as_i64), Some(1));
        assert_eq!(parsed.get("e").and_then(YamlValue::as_i64), Some(5));
        let b = parsed.get("b").expect("b");
        assert_eq!(b.get("c").and_then(YamlValue::as_i64), Some(9));
        assert_eq!(b.get("d").and_then(YamlValue::as_i64), Some(2));
    }

    #[test]
    fn full_shas_are_pins_and_everything_else_is_a_reference() {
        assert!(is_full_commit_sha(&"a".repeat(40)));
        assert!(is_full_commit_sha(&"0".repeat(64)));
        assert!(!is_full_commit_sha("abc1234"), "abbreviated sha");
        assert!(!is_full_commit_sha("main"));
        assert!(!is_full_commit_sha(&"z".repeat(40)), "not hex");
    }

    #[test]
    fn repo_urls_are_redacted_before_they_reach_a_log_line() {
        assert_eq!(
            redact_repo("https://ghp_secrettoken@github.com/acme/config.git"),
            "https://github.com/acme/config.git"
        );
        assert_eq!(
            redact_repo("https://user:ghp_secrettoken@github.com/acme/config.git"),
            "https://github.com/acme/config.git"
        );
        assert_eq!(
            redact_repo("https://github.com/acme/config.git"),
            "https://github.com/acme/config.git"
        );
        assert_eq!(
            redact_repo("git@github.com:acme/config.git"),
            "git@github.com:acme/config.git"
        );
    }

    #[test]
    fn captured_git_output_never_carries_a_credential() {
        let noisy = "fatal: could not read from \
                     https://x-access-token:ghp_secrettoken@github.com/acme/config.git/info/refs";
        let scrubbed = scrub_credentials(noisy);
        assert!(!scrubbed.contains("ghp_secrettoken"), "{scrubbed}");
        assert!(
            scrubbed.contains("github.com/acme/config.git"),
            "{scrubbed}"
        );
    }

    #[test]
    fn credential_becomes_ephemeral_http_authorization() {
        let auth = GitHttpAuth::new(None, Some("tok/en+x"), "https://github.com/acme/c.git")
            .expect("https credential gets auth");
        assert!(auth.header.starts_with("Authorization: Basic "));
        assert!(!auth.header.contains("tok/en+x"));
        assert!(GitHttpAuth::new(None, Some("tok"), "git@github.com:acme/c.git").is_none());
        assert!(GitHttpAuth::new(None, None, "https://github.com/acme/c.git").is_none());

        assert_eq!(
            repo_username("https://git-user@example.test/private.git").as_deref(),
            Some("git-user")
        );
    }

    #[test]
    fn source_head_parses_only_the_source_block() {
        assert!(parse_source_head("proxy:\n  http_bind_port: 8080\n")
            .expect("no source parses")
            .is_none());
        assert!(parse_source_head("source:\n  kind: local\n")
            .expect("local parses")
            .is_none());
        for blank in ["", "   \n", "# just a comment\n", "---\n"] {
            assert!(
                parse_source_head(blank)
                    .expect("a blank document has no source")
                    .is_none(),
                "{blank:?}"
            );
        }
        let parsed = parse_source_head(
            "source:\n  kind: git\n  repo: https://example.test/r.git\n  path: sb.yml\n",
        )
        .expect("git parses")
        .expect("git source present");
        assert!(matches!(parsed, ConfigSource::Git { .. }));
        assert!(parse_source_head("source:\n  kind: nope\n").is_err());
    }

    /// WOR-2710 repro: any whole-document YAML syntax error is wrapped as
    /// a `source:` block failure even when the document has no `source:`
    /// key. Desired: the message names the real parse problem, not a
    /// feature the file never uses. Fails on current code.
    #[test]
    fn parse_source_head_does_not_blame_source_for_unrelated_yaml_syntax_error() {
        let yaml = "proxy:\n  http_bind_port: 8080\nclient_secret: [REDACTED\n";
        assert!(!yaml.contains("source:"), "fixture must be source-free");
        let err = parse_source_head(yaml).expect_err("unclosed flow sequence is invalid YAML");
        let msg = err.to_string();
        assert!(
            !msg.contains("failed to parse `source:` block"),
            "WOR-2710: syntax error mislabeled as source: block: {msg}"
        );
    }

    /// WOR-2710 companion: unquoted `[REDACTED]` (the mask GET /admin/config
    /// writes for keyed secrets) is valid YAML as a one-element flow
    /// sequence, so parse_source_head accepts a source-free redacted
    /// document. The type mismatch surfaces later; the mislabel bug is
    /// only for syntax failures.
    #[test]
    fn unquoted_redacted_marker_parses_as_yaml_flow_sequence() {
        let yaml = "proxy:\n  http_bind_port: 8080\nclient_secret: [REDACTED]\n";
        assert!(parse_source_head(yaml)
            .expect("redacted source-free doc still parses")
            .is_none());
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("serde_yaml accepts the marker");
        assert!(
            value["client_secret"].is_sequence(),
            "unquoted [REDACTED] is a flow sequence, not a string"
        );
    }

    #[test]
    fn refresh_interval_is_the_shortest_any_git_node_asked_for() {
        let mut fast = git_source("https://example.test/a.git", None, "sb.yml");
        if let ConfigSource::Git {
            refresh_interval_secs,
            ..
        } = &mut fast
        {
            *refresh_interval_secs = 15;
        }
        let mut off = git_source("https://example.test/b.git", None, "sb.yml");
        if let ConfigSource::Git {
            refresh_interval_secs,
            ..
        } = &mut off
        {
            *refresh_interval_secs = 0;
        }
        assert_eq!(refresh_interval(&ConfigSource::Local), None);
        assert_eq!(refresh_interval(&off), None, "0 disables refresh");
        let overlay = ConfigSource::GitOverlay {
            base: Box::new(off),
            overlays: vec![fast],
        };
        assert_eq!(refresh_interval(&overlay), Some(Duration::from_secs(15)));
    }

    #[test]
    fn a_path_escaping_the_checkout_is_refused() {
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(std::collections::HashMap::new()));
        for bad in ["../../etc/passwd", "/etc/passwd", "a/../../b.yml"] {
            let source = git_source("https://example.test/r.git", None, bad);
            let err = load(&source, "", &ctx).expect_err("escaping path must be refused");
            assert!(
                matches!(err, ConfigSourceError::Invalid(_)),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn an_unresolved_credential_reference_is_refused_rather_than_fetched_anonymously() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/private.git".into(),
            vec![("sb.yml", "proxy: {}\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let source = ConfigSource::Git {
            repo: "https://example.test/private.git".into(),
            revision: None,
            path: "sb.yml".into(),
            credential: Some("env:SB_GIT_TOKEN".into()),
            verify_signature: false,
            confine: false,
            timeout_secs: 60,
            refresh_interval_secs: 60,
        };
        let err = load(&source, "", &ctx).expect_err("missing resolved credential");
        assert!(matches!(err, ConfigSourceError::Invalid(_)), "{err:?}");
    }

    #[test]
    fn a_resolved_credential_stays_separate_from_the_repository_url() {
        let repo = "https://example.test/private.git";
        let secret = "ghp_private_token_value";
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(repo.into(), vec![("sb.yml", "proxy: {}\n")]);
        let (ctx, cloner) = ctx_with(FixtureCloner::new(repos));
        let ctx = ctx.with_credential(repo, secret);
        let source = ConfigSource::Git {
            repo: repo.into(),
            revision: None,
            path: "sb.yml".into(),
            credential: Some("env:SB_GIT_TOKEN".into()),
            verify_signature: false,
            confine: false,
            timeout_secs: 60,
            refresh_interval_secs: 60,
        };

        load(&source, "", &ctx).expect("private source loads");

        let calls = cloner.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, repo);
        assert_eq!(calls[0].2.as_deref(), Some(secret));
        assert!(!calls[0].0.contains(secret));
    }

    struct CredentialEchoCloner;

    impl Cloner for CredentialEchoCloner {
        fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
            use base64::Engine as _;

            let credential = request.credential.expect("test credential");
            let debug = format!("{request:?}");
            assert!(!debug.contains(credential), "{debug}");
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("x-access-token:{credential}"));
            Err(ConfigSourceError::Clone(format!(
                "remote rejected {credential} in Authorization: Basic {encoded}"
            )))
        }
    }

    #[test]
    fn raw_and_encoded_credentials_are_removed_from_cloner_errors() {
        use base64::Engine as _;

        let repo = "https://example.test/private.git";
        let secret = "ghp_private_token_value";
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{secret}"));
        let ctx =
            FetchContext::with_cloner(Box::new(CredentialEchoCloner)).with_credential(repo, secret);

        let error = materialize_git_tree(
            GitTreeRequest {
                repo,
                revision: Some(&"a".repeat(40)),
                credential: Some("env:SB_GIT_TOKEN"),
                verify_signature: false,
                timeout: Duration::from_secs(60),
                fetch_context: &ctx,
            },
            |_| Ok::<_, ConfigSourceError>(()),
        )
        .expect_err("fixture cloner fails");
        let displayed = error.to_string();

        assert!(!displayed.contains(secret), "{displayed}");
        assert!(!displayed.contains(&encoded), "{displayed}");
        assert!(displayed.contains("[redacted]"), "{displayed}");
    }

    #[cfg(unix)]
    #[test]
    fn git_http_auth_never_enters_arguments_or_persisted_remote_metadata() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary test directory");
        let git = directory.path().join("git-fixture");
        let audit = directory.path().join("git-fixture.audit");
        std::fs::write(
            &git,
            r#"#!/bin/sh
audit="$0.audit"
printf '%s\t%s\t%s\n' "$*" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_VALUE_0" >> "$audit"
case "$1" in
  --version) exit 0 ;;
  init) mkdir -p "$3/.git"; : > "$3/.git/config" ;;
  remote) printf '[remote "origin"]\n\turl = %s\n' "$4" > .git/config ;;
  rev-parse) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' ;;
esac
exit 0
"#,
        )
        .expect("write git fixture");
        let mut permissions = std::fs::metadata(&git)
            .expect("git fixture metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&git, permissions).expect("make git fixture executable");

        let repo = "https://example.test/private.git";
        let secret = "ghp_private_token_value";
        let ctx = FetchContext::with_git_binary_at(&git).with_credential(repo, secret);
        let persisted = materialize_git_tree(
            GitTreeRequest {
                repo,
                revision: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                credential: Some("env:SB_GIT_TOKEN"),
                verify_signature: false,
                timeout: Duration::from_secs(10),
                fetch_context: &ctx,
            },
            |tree| {
                std::fs::read_to_string(tree.root().join(".git/config"))
                    .map_err(|error| ConfigSourceError::Read(error.to_string()))
            },
        )
        .expect("fixture fetch succeeds");
        let audit = std::fs::read_to_string(audit).expect("read git audit");

        assert!(persisted.contains(repo), "{persisted}");
        assert!(!persisted.contains(secret), "{persisted}");
        for line in audit.lines() {
            let arguments = line.split('\t').next().unwrap_or_default();
            assert!(!arguments.contains(secret), "{arguments}");
        }
        assert!(audit.contains("http.extraHeader"), "{audit}");
        assert!(audit.contains("Authorization: Basic "), "{audit}");
    }

    #[test]
    fn credential_references_are_collected_from_the_whole_tree() {
        let mut with_credential = git_source("https://example.test/a.git", None, "sb.yml");
        if let ConfigSource::Git { credential, .. } = &mut with_credential {
            *credential = Some("env:TOKEN_A".into());
        }
        let overlay = ConfigSource::GitOverlay {
            base: Box::new(with_credential),
            overlays: vec![git_source("https://example.test/b.git", None, "sb.yml")],
        };
        assert_eq!(
            credential_references(&overlay),
            vec![(
                "https://example.test/a.git".to_string(),
                "env:TOKEN_A".to_string()
            )]
        );
    }

    #[test]
    fn a_missing_git_binary_names_the_dependency() {
        let ctx = FetchContext::with_git_binary_at("/nonexistent/sbproxy-test-git");
        let err = ctx
            .preflight()
            .expect_err("missing git must fail preflight");
        assert!(
            matches!(err, ConfigSourceError::MissingGitBinary(_)),
            "{err:?}"
        );
        assert!(err.to_string().contains("git"), "{err}");
        assert!(err.is_unreachable());
        assert_eq!(err.metric_label(), "unreachable");
    }

    #[test]
    fn production_preflight_succeeds_without_a_git_binary() {
        let cloner = GitOrGixCloner {
            git: GitBinaryCloner {
                git: PathBuf::from("/nonexistent/sbproxy-test-git"),
            },
        };
        cloner
            .preflight()
            .expect("the in-process fallback keeps preflight green");
        FetchContext::with_git_binary()
            .preflight()
            .expect("production preflight does not require git on PATH");
    }

    #[test]
    fn in_process_git_clones_a_local_repository_when_git_is_missing() {
        if !Command::new("git")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            eprintln!("skipping: need git to create the fixture");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let work = dir.path().join("repo");
        std::fs::create_dir_all(&work).expect("mkdir");
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(&work)
                .output()
                .expect("spawn git");
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "--quiet"]);
        git(&["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(&["config", "user.email", "fixture@example.test"]);
        git(&["config", "user.name", "Fixture"]);
        git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(work.join("sb.yml"), "proxy: {}\n").expect("write");
        git(&["add", "sb.yml"]);
        git(&["commit", "--quiet", "-m", "initial"]);
        let url = format!("file://{}", work.display());
        let dest = dir.path().join("dest");
        std::fs::create_dir_all(&dest).expect("mkdir dest");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        let cloner = GitOrGixCloner {
            git: GitBinaryCloner {
                git: PathBuf::from("/nonexistent/sbproxy-test-git"),
            },
        };
        let resolved = cloner
            .fetch(&FetchRequest {
                repo: &url,
                credential: None,
                credential_username: None,
                revision: Some("main"),
                timeout: Duration::from_secs(30),
                verify_signature: false,
                dest: &dest,
                scratch: &scratch,
            })
            .expect("gix clone");
        assert!(
            dest.join("sb.yml").is_file(),
            "worktree must be checked out"
        );
        assert_eq!(resolved.reference, "main");
        assert!(!resolved.commit.is_empty());
    }

    #[test]
    fn in_process_git_fetches_a_pin_that_is_not_on_the_default_branch() {
        if !Command::new("git")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            eprintln!("skipping: need git to create the fixture");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let work = dir.path().join("repo");
        std::fs::create_dir_all(&work).expect("mkdir");
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(&work)
                .output()
                .expect("spawn git");
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "--quiet"]);
        git(&["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(&["config", "user.email", "fixture@example.test"]);
        git(&["config", "user.name", "Fixture"]);
        git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(work.join("sb.yml"), "on: main\n").expect("write");
        git(&["add", "sb.yml"]);
        git(&["commit", "--quiet", "-m", "main"]);
        git(&["checkout", "--quiet", "-b", "other"]);
        std::fs::write(work.join("sb.yml"), "on: other\n").expect("write");
        git(&["add", "sb.yml"]);
        git(&["commit", "--quiet", "-m", "other"]);
        let pin = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work)
                .output()
                .expect("rev-parse")
                .stdout,
        )
        .expect("utf8")
        .trim()
        .to_string();
        git(&["checkout", "--quiet", "main"]);
        let url = format!("file://{}", work.display());
        let dest = dir.path().join("dest");
        std::fs::create_dir_all(&dest).expect("mkdir dest");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        let cloner = GitOrGixCloner {
            git: GitBinaryCloner {
                git: PathBuf::from("/nonexistent/sbproxy-test-git"),
            },
        };
        let resolved = cloner
            .fetch(&FetchRequest {
                repo: &url,
                credential: None,
                credential_username: None,
                revision: Some(&pin),
                timeout: Duration::from_secs(30),
                verify_signature: false,
                dest: &dest,
                scratch: &scratch,
            })
            .expect("gix clone of a non-default-branch pin");
        assert_eq!(
            std::fs::read_to_string(dest.join("sb.yml")).expect("read checkout"),
            "on: other\n"
        );
        assert!(resolved.commit.eq_ignore_ascii_case(&pin), "{resolved:?}");
    }

    #[test]
    fn in_process_git_refuses_signature_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        std::fs::create_dir_all(&dest).expect("mkdir dest");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        let cloner = GitOrGixCloner {
            git: GitBinaryCloner {
                git: PathBuf::from("/nonexistent/sbproxy-test-git"),
            },
        };
        let err = cloner
            .fetch(&FetchRequest {
                repo: "file:///does/not/matter",
                credential: None,
                credential_username: None,
                revision: None,
                timeout: Duration::from_secs(5),
                verify_signature: true,
                dest: &dest,
                scratch: &scratch,
            })
            .expect_err("signature verification needs git");
        assert!(matches!(err, ConfigSourceError::Signature(_)), "{err:?}");
    }

    #[test]
    fn in_process_git_maps_interrupt_to_timeout_not_clone() {
        let interrupt = AtomicBool::new(true);
        let timed_out = gix_timeout_or(
            &interrupt,
            "https://user:secret@example.test/repo.git",
            Duration::from_secs(12),
            "clone",
            "cancelled by interrupt",
        );
        assert!(
            matches!(timed_out, ConfigSourceError::Timeout(_)),
            "{timed_out:?}"
        );
        assert_eq!(timed_out.metric_label(), "timeout");
        let detail = timed_out.to_string();
        assert!(detail.contains("12"), "{detail}");
        assert!(
            !detail.contains("secret"),
            "timeout text must redact credentials: {detail}"
        );

        let interrupt = AtomicBool::new(false);
        let clone = gix_timeout_or(
            &interrupt,
            "https://example.test/repo.git",
            Duration::from_secs(12),
            "clone",
            "network down",
        );
        assert!(matches!(clone, ConfigSourceError::Clone(_)), "{clone:?}");
        assert_eq!(clone.metric_label(), "unreachable");
    }

    #[test]
    fn materialized_git_tree_lives_through_callback_then_is_removed() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/extensions.git".into(),
            vec![("bundles/a/bundle.yaml", "kind: Bundle\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let observed = Arc::new(Mutex::new(None));
        let capture = observed.clone();

        let revision = materialize_git_tree(
            GitTreeRequest {
                repo: "https://example.test/extensions.git",
                revision: Some(&"a".repeat(40)),
                credential: None,
                verify_signature: false,
                timeout: Duration::from_secs(60),
                fetch_context: &ctx,
            },
            move |tree| {
                assert!(tree.root().join("bundles/a/bundle.yaml").is_file());
                *capture.lock().unwrap() = Some(tree.root().to_owned());
                Ok::<_, ConfigSourceError>(tree.revision().clone())
            },
        )
        .unwrap();

        assert_eq!(revision.commit, "a".repeat(40));
        let path = observed.lock().unwrap().clone().unwrap();
        assert!(!path.exists(), "temporary checkout survived callback");
    }

    #[test]
    fn materialized_git_tree_is_removed_when_callback_errors() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/extensions.git".into(),
            vec![("bundle.yaml", "kind: Bundle\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let observed = Arc::new(Mutex::new(None));
        let capture = observed.clone();

        let error = materialize_git_tree(
            GitTreeRequest {
                repo: "https://example.test/extensions.git",
                revision: Some(&"a".repeat(40)),
                credential: None,
                verify_signature: false,
                timeout: Duration::from_secs(60),
                fetch_context: &ctx,
            },
            move |tree| {
                *capture.lock().unwrap() = Some(tree.root().to_owned());
                Err::<(), _>(ConfigSourceError::Read(
                    "fixture callback rejected tree".into(),
                ))
            },
        )
        .unwrap_err();

        assert!(matches!(error, ConfigSourceError::Read(_)));
        let path = observed.lock().unwrap().clone().unwrap();
        assert!(!path.exists(), "temporary checkout survived callback error");
    }

    #[test]
    fn git_tree_request_debug_and_errors_hide_credentials() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/private.git".into(),
            vec![("bundle.yaml", "kind: Bundle\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let pinned_revision = "a".repeat(40);
        let request = GitTreeRequest {
            repo: "https://secret-user@example.test/private.git",
            revision: Some(&pinned_revision),
            credential: Some("env:VERY_PRIVATE_TOKEN"),
            verify_signature: false,
            timeout: Duration::from_secs(60),
            fetch_context: &ctx,
        };

        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-user"), "{debug}");
        assert!(!debug.contains("VERY_PRIVATE_TOKEN"), "{debug}");
        let error = materialize_git_tree(request, |_| Ok::<_, ConfigSourceError>(())).unwrap_err();
        let displayed = error.to_string();
        assert!(displayed.contains("credential"), "{displayed}");
        assert!(!displayed.contains("secret-user"), "{displayed}");
        assert!(!displayed.contains("VERY_PRIVATE_TOKEN"), "{displayed}");
    }
}
