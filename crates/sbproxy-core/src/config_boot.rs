// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Booting on the last known good config when the one this node was
//! told to boot on does not work (WOR-2459).
//!
//! # The defect
//!
//! `sbproxy run` read the file, resolved `source:`, compiled, and bound,
//! and any failure was `exit(1)`. That is correct on a first boot: a
//! node with no working config has nothing to serve. It is wrong on the
//! thousandth, when the node served fine for six months, someone pushed
//! a typo, and there is a perfectly good config sitting in the revision
//! ring.
//!
//! # Off by default, and the flag beats the file
//!
//! `--config-fallback <off|last-known-good>` (env `SB_CONFIG_FALLBACK`)
//! overrides `proxy.config_history.boot.fallback`, and deliberately
//! wins: a rescue boot must not depend on the file being right, and the
//! file is what is broken.
//!
//! # Booting on the fallback is loud
//!
//! A node quietly serving a config nobody wrote is worse than one that
//! is down, because nobody goes looking for it. So a fallback boot
//! warns at startup, sets `sbproxy_config_fallback_active` to 1, and
//! keeps saying so on the admin surface until an operator clears the pin
//! with `DELETE /admin/config/fallback`.
//!
//! # The watcher has to stop, or this ships nothing
//!
//! `start_config_watcher` watches the config's *directory* and re-reads
//! the config path on any event in it. Boot from the ring with that
//! watcher live and the first filesystem event in that directory
//! re-applies the broken file, looping straight back into the state the
//! fallback just rescued the node from. So while the pin is in place,
//! the file watcher and the SIGHUP path are inert (both converge on
//! `reload_from_config_yaml`, which is where the single guard lives) and
//! so is the `source:` refresh poller.
//!
//! Authority polling stays live, deliberately. A fleet-wide fix pushed
//! from the control plane is how this should end, and refusing it would
//! leave the node pinned until somebody SSHes in.
//!
//! # The double fault
//!
//! An entry that was good in October need not construct after an upgrade
//! that tightened validation. Borrowing systemd-boot's boot counting,
//! `boot_attempts` on the entry being tried is incremented **on disk
//! before** the attempt and cleared once the process has served for
//! `boot.success_secs`. `boot.max_attempts` failures retire that entry
//! and the walk continues down the ring. The ring is finite and each
//! exhausted candidate leaves it permanently, so the walk terminates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use sbproxy_config::{BootFallbackMode, ConfigHistoryConfig, RevisionStore};

/// Process exit code used when the fallback walked the whole ring and
/// nothing booted.
///
/// `78` is `EX_CONFIG` from `sysexits.h`: "something was found in an
/// unconfigured or misconfigured state". Distinct from the plain `1`
/// every other fatal boot failure uses, so an init system or a
/// deployment pipeline can tell "this node's config is broken and its
/// history could not rescue it" apart from every other reason a process
/// died, without parsing a log line.
pub const EXIT_CONFIG_RING_EXHAUSTED: i32 = 78;

/// The phrase the crate-private `BootWalkFailure::Exhausted` renders, and the one
/// `crates/sbproxy/src/main.rs` matches on to choose
/// [`EXIT_CONFIG_RING_EXHAUSTED`] over the plain `1`.
///
/// A named constant rather than the same sentence typed in two places:
/// `run` returns `anyhow::Error`, so the binary has a string and not a
/// type to dispatch on, and a reworded message would otherwise silently
/// drop the distinct exit code with nothing going red.
/// `an_exhausted_ring_names_every_revision_tried_and_why` asserts the
/// rendered message still carries it.
pub const RING_EXHAUSTED_MARKER: &str = "the config revision ring was exhausted";

/// Whether this process is serving a config its boot fallback restored.
static ON_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Which revision the pin names, for the admin surface.
static PINNED: OnceLock<Mutex<Option<PinnedRevision>>> = OnceLock::new();

fn pinned() -> &'static Mutex<Option<PinnedRevision>> {
    PINNED.get_or_init(|| Mutex::new(None))
}

/// Longest rendered boot failure, in characters.
///
/// The reason is the compile failure the configured document produced.
/// Bounding it keeps a pathological error (a parser that echoes a large
/// document back) from turning a status route into a way to read the
/// node's configuration a kilobyte at a time.
///
/// This used to bound only the copy the admin surface serves, on the
/// stated grounds that the failure was available in full elsewhere.
/// That is still true on the default mode, where the binary prints it
/// on stderr rather than logging it, and false on the other one, where
/// the boot path's own `error!` is scrubbed and bounded like every
/// other rendering.
///
/// Which mode carries the untruncated text, exactly:
///
/// * `--config-fallback=off`, **the default**, never reaches this bound
///   at all. `boot_document` returns the file's bytes untouched, the
///   compile failure surfaces from `run_with_fallback`, and the binary
///   prints it whole with `eprintln!("Fatal: {e:#}")`. Unscrubbed and
///   unbounded, exactly as it was before any of this existed.
/// * `--config-fallback=last-known-good` bounds every rendering,
///   because they all go through [`scrub_boot_failure`]: the pin, the
///   boot walk's `error!`, each ring candidate's reason, and the fatal
///   error on the ring-empty and store-unavailable paths.
///
/// So the trade is scoped to the mode that asked for a fallback, and it
/// is the right way round: that mode is the one whose failure text
/// becomes a product surface, served on `GET /admin/config/fallback`
/// and copied into a Kubernetes condition. A node on it that needs the
/// untruncated failure runs `sbproxy validate` against the document,
/// which prints the whole thing. A node on the default already has it
/// on stderr.
///
/// Characters rather than bytes, deliberately, because the cut has to
/// land on a character boundary and a byte budget would have to walk
/// back to one anyway. What that costs is stated rather than left to be
/// discovered: a reason made entirely of four-byte scalars is 2 KiB on
/// the wire, so this is a bound on how much of a document can be echoed
/// and not a bound on response size. The operator edge applies the same
/// character bound again over what a pod returns
/// (`sbproxy-k8s-operator`'s `bounded_reason`), and the pod response
/// body itself is capped in bytes there.
const MAX_FALLBACK_REASON_CHARS: usize = 512;

/// The ring entry a fallback boot is serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRevision {
    /// Ring revision this process booted on.
    pub revision: u64,
    /// Its content digest.
    pub digest: String,
    /// Why the configured document did not boot, credential-scrubbed,
    /// flattened of control characters, and bounded to 512 characters.
    ///
    /// `None` on a pin an operator or a test set directly rather than
    /// one a boot walk produced. A controller that owns this node's
    /// configuration reads this to say *why* it stopped reconciling,
    /// which is the difference between an alert somebody can act on and
    /// one that only says something is wrong (WOR-2467).
    pub reason: Option<String>,
}

/// What replaces a redacted value in a pin reason.
const REDACTED: &str = "[REDACTED]";

/// The phrase the secret resolver's refusal is built around.
///
/// `resolve_secret_reference` bails with
/// `<field> references the secret '<value>' but no secret backend is
/// configured` and echoes `<value>` verbatim, so an operator who inlined
/// a literal credential where a `secret://` reference belongs has that
/// credential in the compile error. That error reaches
/// [`PinnedRevision::reason`], `GET /admin/config/fallback`, and from
/// there a Kubernetes condition message any CR reader can see.
const SECRET_ECHO_MARKER: &str = "references the secret '";

impl PinnedRevision {
    /// A pin carrying the failure that caused the fallback, scrubbed,
    /// flattened of control characters, and truncated to 512 characters
    /// on a character boundary.
    ///
    /// # Why this flattens control characters
    ///
    /// The reason is quoted from an operator-authored document, so it
    /// can carry whatever that document contained: a newline, a `\r`,
    /// or an ANSI escape introducer. It is served by
    /// `GET /admin/config/fallback` and copied into a Kubernetes
    /// condition, and both reach a terminal verbatim through `curl` and
    /// `kubectl describe`. The operator applies the same flattening at
    /// its own edge, because it cannot trust a pod; this one is here
    /// because the node's own admin route is a consumer too and had no
    /// such edge in front of it.
    ///
    /// # Why this scrubs
    ///
    /// The reason is a compile or resolve failure over an
    /// operator-authored document, and two shapes in that document can
    /// carry a credential into the message: a URL with userinfo, which
    /// [`sbproxy_config::scrub_credentials`] strips, and an inline
    /// literal where a secret reference belongs, which the resolver
    /// echoes between single quotes. Both are removed here, at the one
    /// place a boot failure becomes a value this process will serve.
    ///
    /// This is a second line rather than the first. The right place to
    /// stop the second shape is the resolver's own message, and the
    /// documented answer is not to inline a literal at all. What makes
    /// scrubbing worth doing here anyway is the audience: before this,
    /// the echo reached an admin-authenticated route; the operator
    /// copies it into a CR condition that `kubectl get sbproxy` shows to
    /// anyone with read access to the namespace.
    #[must_use]
    pub fn with_reason(revision: u64, digest: String, reason: &str) -> Self {
        let bounded = scrub_boot_failure(reason);
        Self {
            revision,
            digest,
            reason: (!bounded.is_empty()).then_some(bounded),
        }
    }
}

/// Everything a boot failure needs before anything renders it, in one
/// place: credential scrub, control-character flattening, trim, and the
/// [`MAX_FALLBACK_REASON_CHARS`] bound.
///
/// # Every consumer, because a partial list is what went wrong here
///
/// This string is quoted from an operator-authored document, so it can
/// carry an inlined credential the secret resolver echoes, an ANSI
/// escape, or a whole document. It reaches four places:
///
/// * [`PinnedRevision::reason`], served by `GET /admin/config/fallback`
///   and copied into a Kubernetes condition.
/// * the boot walk's `error!` log line.
/// * [`FailedCandidate::reason`], which
///   [`BootWalkFailure::Exhausted`]'s `Display` renders into the error
///   that reaches `eprintln!("Fatal: ...")`, and from there pod logs.
/// * the primary document's own failure on the ring-empty and
///   store-unavailable paths, same destination.
///
/// The first two were sanitized and the last two were not, while this
/// function's own documentation claimed there were only two consumers.
/// Naming all four is the point: the next one added has somewhere to
/// look.
///
/// Not covered, deliberately: `--config-fallback=off` returns the raw
/// error, exactly as it did before any of this existed. Widening that
/// is a separate change to a path this one does not own.
pub(crate) fn scrub_boot_failure(reason: &str) -> String {
    let scrubbed = redact_secret_echo(&sbproxy_config::scrub_credentials(reason));
    let flattened: String = scrubbed
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = flattened.trim();
    match trimmed.char_indices().nth(MAX_FALLBACK_REASON_CHARS) {
        Some((cut, _)) => format!("{}...", &trimmed[..cut]),
        None => trimmed.to_string(),
    }
}

/// Replace the value the secret resolver echoes between single quotes.
///
/// Deliberately narrow: it rewrites only the text between the quotes
/// that follow [`SECRET_ECHO_MARKER`], so the rest of the message, which
/// is what makes the failure diagnosable, survives intact.
fn redact_secret_echo(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len());
    let mut rest = reason;
    while let Some(index) = rest.find(SECRET_ECHO_MARKER) {
        let (before, tail) = rest.split_at(index + SECRET_ECHO_MARKER.len());
        out.push_str(before);
        match tail.find('\'') {
            Some(end) => {
                out.push_str(REDACTED);
                out.push('\'');
                rest = &tail[end + 1..];
            }
            // An unterminated quote: drop the remainder rather than
            // guess where the value ends.
            None => {
                out.push_str(REDACTED);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// One candidate the walk tried and why it did not boot.
///
/// Crate-private, with [`BootWalkFailure`] and [`walk_for_bootable`],
/// because `server::lifecycle` is the only consumer and always has
/// been. They were `pub` by habit, which put them in the pub-item
/// ratchet's unreferenced bucket, where the count came to rest on
/// whether a comment in another file happened to spell the name. A
/// visibility the compiler enforces is a better floor than a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailedCandidate {
    /// Ring revision tried.
    pub revision: u64,
    /// Its content digest.
    pub digest: String,
    /// Why it did not boot, or why it was skipped.
    ///
    /// Built through the crate-private `FailedCandidate::new`, which
    /// applies the same `scrub_boot_failure` the pin gets. Every one of
    /// these is rendered into the fatal error by
    /// [`BootWalkFailure::Exhausted`]'s `Display`, so an unsanitized
    /// one reaches pod logs multiplied by the number of candidates
    /// tried.
    pub reason: String,
}

impl FailedCandidate {
    /// A candidate failure with its reason sanitized and bounded.
    fn new(revision: u64, digest: String, reason: &str) -> Self {
        Self {
            revision,
            digest,
            reason: scrub_boot_failure(reason),
        }
    }
}

/// Why a fallback boot could not produce a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootWalkFailure {
    /// The ring held no candidate at all. A first boot: the node exits
    /// exactly the way `fallback: off` does, and says the ring was empty
    /// rather than pretending a fallback was attempted.
    RingEmpty,
    /// Every candidate in the ring was tried and none booted. Names each
    /// one and why.
    Exhausted(Vec<FailedCandidate>),
    /// The ring itself could not be opened, so no fallback is possible.
    StoreUnavailable(String),
}

impl std::fmt::Display for BootWalkFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RingEmpty => write!(
                formatter,
                "the config revision ring is empty, so there is no last known good \
                 configuration to fall back to"
            ),
            Self::StoreUnavailable(error) => write!(
                formatter,
                "the config revision ring could not be opened, so no fallback is possible: \
                 {error}"
            ),
            Self::Exhausted(tried) => {
                write!(
                    formatter,
                    "{RING_EXHAUSTED_MARKER}; {} candidate(s) were tried and none booted:",
                    tried.len()
                )?;
                for candidate in tried {
                    write!(
                        formatter,
                        "\n  revision {} ({}): {}",
                        candidate.revision, candidate.digest, candidate.reason
                    )?;
                }
                Ok(())
            }
        }
    }
}

/// The document a fallback boot resolved, and which ring entry it came
/// from.
#[derive(Debug, Clone)]
pub struct FallbackDocument {
    /// Pre-resolution bytes of the rescued revision, as they were
    /// stored.
    pub yaml: String,
    /// Which entry this is.
    pub pinned: PinnedRevision,
}

/// Resolve which fallback mode the command line or the environment
/// names, or `None` when neither does and the config file's own
/// `boot.fallback` decides.
///
/// The command line beats the environment, which beats the config file.
/// A rescue boot must not depend on the file being right, and the file
/// is what is broken; the environment sits between the two because a
/// systemd drop-in is how an operator makes a rescue survive a restart
/// without editing the config they are trying to replace.
///
/// Split out so the caller can answer "is a fallback even wanted" before
/// parsing the config file for the block that names the ring. On a node
/// that never asked for a fallback, which is every node by default, that
/// keeps the boot path byte-identical to the release before this one:
/// one read, one `source:` resolve, one compile, and the same error
/// (WOR-2459 fix round, Major 6).
///
/// `SB_CONFIG_FALLBACK` is read here rather than by clap. Letting clap
/// own the variable put it in the `flag` slot, which made this branch
/// unreachable in production and turned an unparseable value into
/// `exit(2)` instead of the documented warn-and-fall-through
/// (WOR-2459 fix round, Major 11).
#[must_use]
pub fn mode_from_flag_or_env(
    flag: Option<BootFallbackMode>,
    environment: Option<&str>,
) -> Option<BootFallbackMode> {
    if let Some(mode) = flag {
        return Some(mode);
    }
    let raw = environment?;
    if let Some(mode) = BootFallbackMode::parse(raw) {
        return Some(mode);
    }
    tracing::warn!(
        value = %raw,
        "SB_CONFIG_FALLBACK is not one of off | last-known-good; ignoring it and using the \
         configured boot fallback mode",
    );
    None
}

/// Recover `proxy.config_history` from a document that did not compile.
///
/// The chicken-and-egg problem this solves: the ring's directory is
/// named by the very config that is broken. A lenient partial parse gets
/// the block out of a document whose *other* half is what failed, which
/// is the common case (a typo in an origin, a misspelled key, an
/// unresolvable `${VAR}`). When even that fails, the defaults are used,
/// with `enabled` forced on: an operator who typed
/// `--config-fallback=last-known-good` has asked for the ring to be
/// read, and refusing because the broken file does not say `enabled:
/// true` would answer the wrong question.
#[must_use]
pub fn history_config_from_broken_document(yaml: &str) -> ConfigHistoryConfig {
    #[derive(serde::Deserialize)]
    struct ProxyOnly {
        proxy: Option<ProxyBlock>,
    }
    #[derive(serde::Deserialize)]
    struct ProxyBlock {
        config_history: Option<ConfigHistoryConfig>,
    }
    let recovered = serde_yaml::from_str::<ProxyOnly>(yaml)
        .ok()
        .and_then(|document| document.proxy)
        .and_then(|proxy| proxy.config_history);
    match recovered {
        Some(mut history) => {
            history.enabled = true;
            history
        }
        // No warning here: this runs on the mode-resolution path too,
        // which every boot takes, and a node whose config simply has no
        // `proxy.config_history` block must not warn about it once per
        // start. The walk logs the directory it settled on instead.
        None => ConfigHistoryConfig {
            enabled: true,
            ..ConfigHistoryConfig::default()
        },
    }
}

/// Walk the ring for a revision that compiles, incrementing each
/// candidate's durable boot counter before it is tried.
///
/// `compiles` is the caller's "does this construct" test, kept as a
/// parameter so this walk is testable without a proxy and so the real
/// boot path can use exactly the same compile step it would have used on
/// the primary document.
///
/// The counter is incremented **before** the attempt and left
/// incremented on failure. That ordering is the whole point: the failure
/// this counter exists to survive is a boot that dies partway through,
/// taking any in-memory count with it.
///
/// # Errors
///
/// Returns [`BootWalkFailure`] when the ring cannot be opened, holds no
/// candidate, or holds only candidates that do not boot.
pub(crate) fn walk_for_bootable(
    history: &ConfigHistoryConfig,
    max_attempts: u32,
    mut compiles: impl FnMut(&str) -> Result<(), String>,
) -> Result<FallbackDocument, BootWalkFailure> {
    tracing::warn!(
        dir = %history.dir,
        "reading the config revision ring for a bootable configuration",
    );
    let mut store = RevisionStore::open(&history.dir, history.keep, None)
        .map_err(|error| BootWalkFailure::StoreUnavailable(error.to_string()))?;
    // Asked of the store rather than re-derived here: it reads the same
    // layout constants the writer uses, so a rename moves both together
    // (re-review, new Major 1).
    store
        .refuse_shared_files()
        .map_err(|error| BootWalkFailure::StoreUnavailable(error.to_string()))?;
    let candidates = store.boot_candidates();
    if candidates.is_empty() {
        return Err(BootWalkFailure::RingEmpty);
    }

    let mut tried = Vec::new();
    for candidate in candidates {
        if candidate.boot_attempts >= max_attempts {
            // Already spent its budget on an earlier boot that died
            // before it could clear the counter.
            retire(&mut store, candidate.revision);
            tried.push(FailedCandidate::new(
                candidate.revision,
                candidate.digest.clone(),
                &format!(
                    "already failed {} boot attempt(s), at or past the max_attempts of \
                     {max_attempts}; retired",
                    candidate.boot_attempts
                ),
            ));
            continue;
        }
        let attempts = match store.begin_boot_attempt(candidate.revision) {
            Ok(attempts) => attempts,
            Err(error) => {
                // A counter that cannot be persisted would let this walk
                // retry the same dead entry forever, so the candidate is
                // skipped rather than tried.
                tried.push(FailedCandidate::new(
                    candidate.revision,
                    candidate.digest.clone(),
                    &format!("its boot attempt counter could not be persisted: {error}"),
                ));
                continue;
            }
        };
        let yaml = match store.read_blob(&candidate.digest) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(yaml) => yaml,
                Err(error) => {
                    tried.push(FailedCandidate::new(
                        candidate.revision,
                        candidate.digest.clone(),
                        &format!("its stored document is not UTF-8: {error}"),
                    ));
                    continue;
                }
            },
            Err(error) => {
                tried.push(FailedCandidate::new(
                    candidate.revision,
                    candidate.digest.clone(),
                    &format!("its stored document could not be read: {error}"),
                ));
                continue;
            }
        };
        match compiles(&yaml) {
            Ok(()) => {
                return Ok(FallbackDocument {
                    yaml,
                    pinned: PinnedRevision {
                        revision: candidate.revision,
                        digest: candidate.digest,
                        // The walk knows which candidate booted, not why
                        // the configured document did not. The boot path
                        // has that error and stamps it on with
                        // `PinnedRevision::with_reason`.
                        reason: None,
                    },
                });
            }
            Err(reason) => {
                if attempts >= max_attempts {
                    retire(&mut store, candidate.revision);
                }
                tried.push(FailedCandidate::new(
                    candidate.revision,
                    candidate.digest.clone(),
                    &format!("attempt {attempts} of {max_attempts}: {reason}"),
                ));
            }
        }
    }
    Err(BootWalkFailure::Exhausted(tried))
}

/// Retire one entry, logging rather than failing: a walk that cannot
/// persist a retirement still has to finish.
fn retire(store: &mut RevisionStore, revision: u64) {
    if let Err(error) = store.retire_unbootable(revision) {
        tracing::error!(
            error = %error,
            revision,
            "could not retire an unbootable config revision; the next boot will try it again",
        );
    }
}

/// Pin this process to a revision the fallback rescued, loudly.
pub fn mark_on_fallback(pin: PinnedRevision) {
    ON_FALLBACK.store(true, Ordering::SeqCst);
    *pinned()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pin.clone());
    sbproxy_observe::metrics::set_config_fallback_active(true);
    tracing::warn!(
        revision = pin.revision,
        digest = %pin.digest,
        "this node booted on a configuration restored from its revision ring, not on the \
         config file it was pointed at. the file watcher, SIGHUP, and the source: refresh \
         poller are suspended until an operator clears the pin with DELETE \
         /admin/config/fallback. config-authority polling stays live, so a fleet-wide fix \
         still reaches this node",
    );
}

/// Whether this process is serving a config its boot fallback restored.
#[must_use]
pub fn on_fallback() -> bool {
    ON_FALLBACK.load(Ordering::SeqCst)
}

/// The revision the pin names, when one is in place.
#[must_use]
pub fn pinned_revision() -> Option<PinnedRevision> {
    pinned()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Clear the pin: the `DELETE /admin/config/fallback` path.
///
/// Returns what was pinned, or `None` when nothing was. Clearing is all
/// it takes to resume the suspended paths: each of them checks
/// [`reload_suspended`] on every cycle rather than being torn down at
/// boot, precisely so an operator can bring them back without a restart.
pub fn clear_fallback() -> Option<PinnedRevision> {
    let previous = pinned()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    ON_FALLBACK.store(false, Ordering::SeqCst);
    sbproxy_observe::metrics::set_config_fallback_active(false);
    if let Some(pin) = &previous {
        tracing::warn!(
            revision = pin.revision,
            "an operator cleared the config fallback pin; the file watcher, SIGHUP, and the \
             source: refresh poller are live again",
        );
    }
    previous
}

/// Whether `trigger` must not reload right now.
///
/// The three suspended triggers are named explicitly rather than
/// inverted from the one that stays live, so adding a fourth reload
/// trigger later means deciding about it here rather than inheriting an
/// answer by accident.
///
/// | Trigger | While pinned |
/// | -- | -- |
/// | `file_watcher` (and SIGHUP, which shares it) | Suspended |
/// | `config_refresh_poller` | Suspended |
/// | `config_authority` | **Live**: a fleet-wide fix is how this ends |
/// | `api` (`POST /admin/reload`) | Live: an operator asking explicitly |
#[must_use]
pub fn reload_suspended(trigger: &str) -> bool {
    if !on_fallback() {
        return false;
    }
    matches!(trigger, "file_watcher" | "config_refresh_poller")
}

/// Clear the boot counter on the pinned revision once this process has
/// served for `success_secs`.
///
/// Spawned as a plain thread rather than a tokio task: it runs once,
/// sleeps, and exits, and the boot path that calls it has no runtime of
/// its own. A process that dies before the timer fires leaves the
/// counter incremented, which is exactly the point: three of those and
/// the entry is retired.
pub fn spawn_boot_success_timer(revision: u64, success_secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(success_secs));
        confirm_boot_success_now(revision);
    });
}

/// Clear the boot counter on `revision` through the **process-owned**
/// ring handle.
///
/// [`RevisionStore`] documents itself single-owner: every mutator clones
/// the handle's in-memory index, edits the clone, and writes the whole
/// thing back. A second handle opened on the same directory therefore
/// does not merge, it overwrites, and the loser is whichever handle
/// writes last. Opening one here meant the recorder's very next write,
/// an ordinary `append` or `record_soak_verdict`, restored the counter
/// this had just cleared from its own older snapshot. A node that booted
/// on the fallback and kept applying configs never cleared the counter,
/// and three such boots retired its only rescue target while it had
/// booted and served correctly every time (WOR-2459 fix round,
/// Blocker 2).
///
/// A no-op when no ring is open, which is the same condition under which
/// nothing could have incremented the counter in the first place.
pub(crate) fn confirm_boot_success_now(revision: u64) {
    let Some(recorder) = crate::config_history::current_config_history_recorder() else {
        tracing::warn!(
            revision,
            "no config history ring is open, so the boot attempt counter for the revision this \
             node booted on cannot be cleared",
        );
        return;
    };
    recorder.confirm_boot_success(revision);
    tracing::info!(
        revision,
        "the fallback boot has served long enough to count as successful; its boot attempt \
         counter is cleared",
    );
}

/// Reset the module's process state. Tests only: the pin is process
/// global and one test must not leak into the next.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    let _ = clear_fallback();
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::{AppendMetadata, BaseOrigin};

    fn history(dir: &std::path::Path) -> ConfigHistoryConfig {
        ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().into_owned(),
            keep: 8,
            ..ConfigHistoryConfig::default()
        }
    }

    fn metadata(applied_at: u64) -> AppendMetadata {
        AppendMetadata {
            provenance: BaseOrigin::Local,
            blast_radius: None,
            secrets_fingerprint: None,
            actor: Some("test".to_string()),
            applied_at,
            degraded: Vec::new(),
        }
    }

    /// The flag beats the environment, which beats the file. A rescue
    /// boot must not depend on the file being right.
    #[test]
    fn the_command_line_flag_beats_the_environment_and_the_file() {
        assert_eq!(
            mode_from_flag_or_env(Some(BootFallbackMode::LastKnownGood), Some("off")),
            Some(BootFallbackMode::LastKnownGood),
        );
        assert_eq!(
            mode_from_flag_or_env(None, Some("last-known-good")),
            Some(BootFallbackMode::LastKnownGood),
        );
        // Neither decided, so the caller falls back to the file's own
        // `boot.fallback`.
        assert_eq!(mode_from_flag_or_env(None, None), None);
        // An unparseable environment value falls through to the file
        // rather than silently enabling or disabling the fallback. This
        // branch is only reachable because `SB_CONFIG_FALLBACK` is read
        // here rather than declared on the clap argument: while clap
        // owned it, the variable landed in the `flag` slot and a typo
        // exited the process instead (WOR-2459 fix round, Major 11).
        assert_eq!(mode_from_flag_or_env(None, Some("maybe")), None);
    }

    /// A first boot with an empty ring exits the way `off` does, and
    /// says the ring was empty rather than pretending a fallback was
    /// attempted.
    #[test]
    fn an_empty_ring_says_so_rather_than_pretending() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let failure = walk_for_bootable(&history(temp.path()), 3, |_| Ok(()))
            .expect_err("an empty ring cannot rescue a boot");
        assert_eq!(failure, BootWalkFailure::RingEmpty);
        assert!(format!("{failure}").contains("empty"), "{failure}");
    }

    /// Verification residual R5. The control was covered and its wiring
    /// was not: every assertion drove `refuse_shared_files` directly, so
    /// deleting the call from `walk_for_bootable` left the suite green.
    /// A covered function is not a wired one.
    #[cfg(unix)]
    #[test]
    fn the_walk_refuses_a_ring_whose_index_anyone_can_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = history(temp.path());
        {
            let mut store = RevisionStore::open(temp.path(), history.keep, None).expect("open");
            store
                .append(b"rescued: yes\n", metadata(1))
                .expect("append");
        }

        // An ordinary ring boots, so the guard is not a blanket refusal.
        walk_for_bootable(&history, 3, |_| Ok(())).expect("a 0600 ring boots");

        // Widen the index, and the walk itself must refuse before it
        // offers a single candidate.
        let index = temp.path().join("index.json");
        std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let failure = walk_for_bootable(&history, 3, |_| {
            panic!("no candidate may be compiled from a ring this walk should have refused")
        })
        .expect_err("the walk refuses a shared ring");
        let BootWalkFailure::StoreUnavailable(reason) = &failure else {
            panic!("expected StoreUnavailable, got {failure:?}");
        };
        assert!(reason.contains("index.json"), "{reason}");
        assert!(reason.contains("644"), "the mode is named: {reason}");
    }

    /// The walk boots the last known good entry first.
    #[test]
    fn the_walk_boots_the_last_known_good_entry_first() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = history(temp.path());
        let good_revision = {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            store.append(b"a: 1\n", metadata(1)).expect("append");
            let good = store.append(b"a: 2\n", metadata(2)).expect("append");
            store.append(b"a: 3\n", metadata(3)).expect("append");
            store
                .record_soak_verdict(good.revision, sbproxy_config::SoakVerdict::Successful)
                .expect("promote");
            good.revision
        };

        let document = walk_for_bootable(&history, 3, |_| Ok(())).expect("a candidate boots");
        assert_eq!(document.pinned.revision, good_revision);
        assert_eq!(document.yaml, "a: 2\n");
    }

    /// An entry that fails to boot `max_attempts` times is retired and
    /// the walk moves to the next candidate.
    #[test]
    fn an_entry_that_fails_max_attempts_is_retired_and_the_walk_continues() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = history(temp.path());
        let (bad, good) = {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            let good = store.append(b"good: yes\n", metadata(1)).expect("append");
            let bad = store.append(b"bad: yes\n", metadata(2)).expect("append");
            (bad.revision, good.revision)
        };

        // Two boots that both die on the newest entry. `max_attempts` of
        // 2 means the second one retires it.
        for _ in 0..2 {
            let document = walk_for_bootable(&history, 2, |yaml| {
                if yaml.starts_with("bad") {
                    Err("this one does not construct".to_string())
                } else {
                    Ok(())
                }
            })
            .expect("the older entry boots");
            assert_eq!(document.pinned.revision, good);
        }

        let store = RevisionStore::open(temp.path(), 8, None).expect("reopen");
        let retired = store
            .entries()
            .iter()
            .find(|entry| entry.revision == bad)
            .expect("the entry survives retirement");
        assert!(
            retired.boot_retired,
            "an entry that spent its attempt budget leaves the walk",
        );
        assert!(
            !store
                .boot_candidates()
                .iter()
                .any(|entry| entry.revision == bad),
            "and the next boot does not offer it again",
        );
    }

    /// An exhausted ring names every revision it tried and why, because
    /// that message is the whole of what an operator has to work with at
    /// 3am.
    #[test]
    fn an_exhausted_ring_names_every_revision_tried_and_why() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = history(temp.path());
        {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            store.append(b"one: 1\n", metadata(1)).expect("append");
            store.append(b"two: 2\n", metadata(2)).expect("append");
        }

        let failure = walk_for_bootable(&history, 3, |_| Err("nothing constructs".to_string()))
            .expect_err("nothing booted");
        let BootWalkFailure::Exhausted(tried) = &failure else {
            panic!("expected an exhausted ring, got {failure:?}");
        };
        assert_eq!(tried.len(), 2, "both candidates were tried: {tried:?}");
        let rendered = format!("{failure}");
        for candidate in tried {
            assert!(
                rendered.contains(&candidate.revision.to_string()),
                "revision {} is named: {rendered}",
                candidate.revision,
            );
        }
        assert!(rendered.contains("nothing constructs"), "{rendered}");
        assert!(
            rendered.contains(RING_EXHAUSTED_MARKER),
            "the binary dispatches the distinct exit code off this phrase: {rendered}",
        );
    }

    /// The boot counter is left incremented on a failed attempt, so a
    /// process that dies partway through still spends an attempt.
    #[test]
    fn a_failed_attempt_leaves_the_counter_incremented_on_disk() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = history(temp.path());
        let revision = {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            store
                .append(b"one: 1\n", metadata(1))
                .expect("append")
                .revision
        };

        let _ = walk_for_bootable(&history, 5, |_| Err("no".to_string()));
        let store = RevisionStore::open(temp.path(), 8, None).expect("reopen");
        assert_eq!(
            store
                .entries()
                .iter()
                .find(|entry| entry.revision == revision)
                .expect("entry")
                .boot_attempts,
            1,
            "the counter is on disk, not in the process that just died",
        );
    }

    /// B2 red-first. `RevisionStore` is documented single-owner: every
    /// mutator rewrites the whole index from the handle's own snapshot.
    /// A boot-success timer that opened a second handle on a directory
    /// the process recorder already owns had its cleared counter
    /// deterministically reverted by the recorder's next write, so a node
    /// that booted on the fallback and kept applying configs never
    /// actually cleared the counter, and three such boots retired its
    /// only rescue target.
    #[test]
    fn clearing_the_boot_counter_survives_the_recorders_next_write() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = ConfigHistoryConfig {
            enabled: true,
            dir: temp.path().to_string_lossy().into_owned(),
            ..ConfigHistoryConfig::default()
        };

        // The boot walk's own handle, exactly as `walk_for_bootable`
        // leaves it: one attempt recorded, handle dropped.
        let rescued = {
            let mut store = RevisionStore::open(temp.path(), history.keep, None).expect("open");
            let entry = store
                .append(b"rescued: yes\n", metadata(1))
                .expect("append");
            store
                .begin_boot_attempt(entry.revision)
                .expect("attempt persists");
            entry.revision
        };

        // The process recorder opens next and holds its own snapshot,
        // which reads `boot_attempts = 1`.
        crate::config_history::clear_config_history_recorder();
        let recorder = std::sync::Arc::new(
            crate::config_history::ConfigHistoryRecorder::from_config(Some(&history))
                .expect("opens")
                .expect("enabled"),
        );
        crate::config_history::install_config_history_recorder(recorder.clone());

        // The success timer fires.
        confirm_boot_success_now(rescued);

        // ... and then the node keeps working: a later revision applies
        // and its soak closes, both of which rewrite the index.
        let later = recorder
            .record(b"later: yes\n", metadata(2))
            .expect("a second revision");
        recorder.record_soak_verdict(later.revision, sbproxy_config::SoakVerdict::Successful);

        let store = RevisionStore::open(temp.path(), history.keep, None).expect("reopen");
        let attempts = store
            .entries()
            .iter()
            .find(|entry| entry.revision == rescued)
            .expect("the rescued entry survives")
            .boot_attempts;
        crate::config_history::clear_config_history_recorder();
        assert_eq!(
            attempts, 0,
            "the recorder's next write must not resurrect a boot counter the timer cleared",
        );
    }

    /// The three suspended triggers, and the one that deliberately is
    /// not.
    #[test]
    fn the_pin_suspends_the_local_triggers_and_leaves_authority_polling_live() {
        reset_for_test();
        assert!(
            !reload_suspended("file_watcher"),
            "nothing is suspended before a fallback boot",
        );

        mark_on_fallback(PinnedRevision::with_reason(
            4,
            "abc".to_string(),
            "unknown action type: statik",
        ));
        assert_eq!(
            pinned_revision().and_then(|pin| pin.reason).as_deref(),
            Some("unknown action type: statik"),
            "the pin carries why the configured document failed",
        );
        assert!(on_fallback());
        assert!(reload_suspended("file_watcher"));
        assert!(reload_suspended("config_refresh_poller"));
        assert!(
            !reload_suspended("config_authority"),
            "a fleet-wide fix pushed from the control plane is how this ends",
        );
        assert!(
            !reload_suspended("api"),
            "an operator asking explicitly is not the loop this guards against",
        );

        let cleared = clear_fallback().expect("something was pinned");
        assert_eq!(cleared.revision, 4);
        assert!(!on_fallback());
        assert!(
            !reload_suspended("file_watcher"),
            "clearing the pin resumes every suspended path",
        );
        assert!(clear_fallback().is_none(), "clearing twice pins nothing");
        reset_for_test();
    }

    /// The ring directory is named by the very config that is broken, so
    /// the block is recovered from the broken document when it can be.
    #[test]
    fn the_history_block_is_recovered_from_a_document_that_did_not_compile() {
        let broken = "proxy:\n  config_history:\n    dir: /srv/ring\n    keep: 4\n  \
                      http2_cleartextt: true\n";
        let history = history_config_from_broken_document(broken);
        assert_eq!(history.dir, "/srv/ring");
        assert_eq!(history.keep, 4);
        assert!(
            history.enabled,
            "an operator who asked for the fallback on the command line has asked for the \
             ring to be read",
        );

        // Not even parseable as YAML: the defaults, still enabled.
        let history = history_config_from_broken_document("\t: [unbalanced\n");
        assert_eq!(history.dir, "/var/lib/sbproxy/config-history");
        assert!(history.enabled);
    }

    /// The reason is a compile failure over an operator-authored
    /// document, and it is served on an admin route and copied into a
    /// Kubernetes condition any CR reader can see.
    #[test]
    fn a_fallback_reason_carries_no_credential_into_the_admin_surface() {
        let inline = PinnedRevision::with_reason(
            1,
            "digest".to_string(),
            "source.credential references the secret 'ghp_exampleliteraltoken' but no secret \
             backend is configured to resolve it; declare one under proxy.secrets.backends",
        )
        .reason
        .expect("a reason");
        assert!(
            !inline.contains("ghp_exampleliteraltoken"),
            "an inlined literal must not reach the admin surface: {inline}",
        );
        assert!(inline.contains("[REDACTED]"), "{inline}");
        assert!(
            inline.contains("proxy.secrets.backends"),
            "and the rest of the message, which is what makes it diagnosable, survives: \
             {inline}",
        );

        let url = PinnedRevision::with_reason(
            1,
            "digest".to_string(),
            "source: clone of https://user:ghp_exampleurltoken@git.example.com/acme/cfg.git \
             failed",
        )
        .reason
        .expect("a reason");
        assert!(
            !url.contains("ghp_exampleurltoken") && !url.contains("user:"),
            "userinfo in a URL must not reach it either: {url}",
        );
        assert!(url.contains("git.example.com"), "{url}");

        // An unterminated quote drops the remainder rather than guessing.
        let ragged = PinnedRevision::with_reason(
            1,
            "digest".to_string(),
            "source.credential references the secret 'ghp_exampleunterminated",
        )
        .reason
        .expect("a reason");
        assert!(!ragged.contains("ghp_exampleunterminated"), "{ragged}");

        // An ordinary compile failure is untouched.
        let ordinary = "unknown action type: statik";
        assert_eq!(
            PinnedRevision::with_reason(1, "digest".to_string(), ordinary).reason,
            Some(ordinary.to_string()),
        );
    }

    #[test]
    fn a_fallback_reason_is_bounded_so_a_status_route_cannot_echo_a_document_back() {
        let long = "x".repeat(MAX_FALLBACK_REASON_CHARS * 3);
        let pin = PinnedRevision::with_reason(1, "digest".to_string(), &long);
        let reason = pin.reason.expect("a reason");
        assert_eq!(
            reason.chars().count(),
            MAX_FALLBACK_REASON_CHARS + 3,
            "bounded, with an ellipsis saying it was cut",
        );
        assert!(reason.ends_with("..."), "{reason}");

        // A multi-byte character on the boundary is cut on a character
        // boundary rather than panicking mid-codepoint.
        let wide = "\u{00e9}".repeat(MAX_FALLBACK_REASON_CHARS * 2);
        let cut = PinnedRevision::with_reason(1, "digest".to_string(), &wide)
            .reason
            .expect("a reason");
        assert_eq!(cut.chars().count(), MAX_FALLBACK_REASON_CHARS + 3);

        assert_eq!(
            PinnedRevision::with_reason(1, "digest".to_string(), "   ").reason,
            None,
            "an empty reason is absent rather than an empty string",
        );
    }

    /// The same string, on the path that renders every candidate.
    ///
    /// `BootWalkFailure::Exhausted`'s `Display` writes each candidate's
    /// reason into the error that reaches `eprintln!("Fatal: ...")`, so
    /// an unsanitized one is multiplied by the number of candidates
    /// tried. The pin was sanitized and this was not.
    #[test]
    fn a_failed_candidate_reason_is_sanitized_like_the_pin() {
        let hostile = format!(
            "source.credential references the secret 'ghp_realtoken' at \u{1b}[2J{}",
            "x".repeat(MAX_FALLBACK_REASON_CHARS * 2),
        );
        let candidate = FailedCandidate::new(4, "digest".to_string(), &hostile);

        assert!(
            !candidate.reason.contains("ghp_realtoken"),
            "the resolver's echo must not reach a fatal log: {}",
            candidate.reason,
        );
        assert!(
            !candidate.reason.chars().any(char::is_control),
            "no control character survives: {:?}",
            candidate.reason,
        );
        assert_eq!(
            candidate.reason.chars().count(),
            MAX_FALLBACK_REASON_CHARS + 3,
            "bounded like the pin, with an ellipsis saying it was cut",
        );

        // And the whole rendered failure carries the bounded form, so a
        // ring of candidates cannot multiply an unbounded string.
        let rendered = BootWalkFailure::Exhausted(vec![candidate]).to_string();
        assert!(!rendered.contains("ghp_realtoken"), "{rendered}");
        assert!(rendered.contains("revision 4"), "{rendered}");
    }

    #[test]
    fn a_fallback_reason_carries_no_control_character_to_a_terminal() {
        // The reason is quoted from an operator-authored document and
        // is served raw by the admin route, so an escape introducer in
        // that document would reach whatever renders the answer.
        let hostile = "unknown action type:\u{1b}[2Jstatik\r\nsecond line\u{0}";
        let reason = PinnedRevision::with_reason(7, "digest".to_string(), hostile)
            .reason
            .expect("a reason");
        assert!(
            !reason.chars().any(char::is_control),
            "no control character survives: {reason:?}"
        );
        assert!(
            reason.starts_with("unknown action type:"),
            "the diagnosable part survives: {reason:?}"
        );
        assert!(
            reason.contains("statik") && reason.contains("second line"),
            "flattened rather than truncated at the first control character: {reason:?}"
        );
    }
}
