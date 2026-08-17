// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Honouring `source:`: resolve the config document from where the
//! operator said it lives, and keep it fresh.
//!
//! A `source: {kind: git, ...}` block used to parse, appear in the JSON
//! Schema, and do nothing at all. This module is the seam that makes it
//! mean something. Every path that turns operator bytes into a running
//! configuration goes through [`crate::config_source::resolve`]:
//!
//! * boot, in `server::lifecycle::run`
//! * the reload transaction, so the file watcher, SIGHUP, and
//!   `POST /admin/reload` all honour it
//! * the refresh poller in this module
//! * `sbproxy validate` and `sbproxy plan`, unless `--no-fetch`
//! * the config authority's publish path, so a git-backed authority
//!   signs the resolved document rather than the pointer to it
//!
//! # Resolution order
//!
//! Fixed, and the same everywhere: resolve `source:` to get the base
//! document, then apply the authority overlay from
//! `proxy.config_authority.upstream` if one is configured, then compile.
//! The authority wins over git, because the deny list is what protects
//! the box and the authority is the layer it is enforced against. Git
//! content is operator-owned and therefore unrestricted, which is right:
//! it is equivalent to the operator editing the file by hand.
//!
//! # What refresh does
//!
//! The same shape as the config-authority subscriber, deliberately: an
//! interval with jitter, a cached last-good document, and the same
//! failure table. **The resolved commit plays the part the `ETag` plays
//! for a bundle**, so a resolution that lands on the commit already
//! serving costs one fetch and nothing else: no recompile, no reload.
//!
//! The apply step never waits for the reload lock. A poller that blocks
//! behind a slow reload queues up and eventually applies a commit that
//! has since been superseded, so it uses the try-lock entry point and
//! records `reload_busy` instead.
//!
//! # Node identity
//!
//! One repository serving a whole fleet cannot carry `proxy.cluster` as
//! written, because `ClusterRestartFingerprint` covers every per-node
//! field in it and any change to any of them rejects the reload
//! outright. The supported pattern is `${VAR}` interpolation: the shared
//! document carries `node_id: ${SB_NODE_ID}` and each host exports its
//! own value. An unresolved reference under `proxy.cluster` is a hard
//! error rather than the usual warning, because the literal placeholder
//! text would otherwise become the node's identity.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use sbproxy_config::config_merge::BaseOrigin;
use sbproxy_config::source::{FetchContext, ResolvedDocument};
use sbproxy_config::types::ConfigSource;

use crate::server::TryReloadOutcome;

/// Fraction of the refresh interval the jitter spans, either side of it.
///
/// A fleet that restarts together would otherwise hit the git host in
/// lockstep forever, turning a rolling restart into a repeating
/// thundering herd against someone's SCM.
const JITTER_FRACTION: f64 = 0.15;

/// The config document a `source:` block resolved to, and where from.
///
/// Published process-wide because two consumers need it and neither owns
/// it. The config-authority subscriber merges its bundle over this
/// document rather than over the pointer file on disk, and tags the
/// merge with this `origin` so provenance can say `git` rather than
/// `local`. The refresh poller compares `fingerprint` to decide whether
/// anything changed.
#[derive(Debug, Clone)]
pub struct ResolvedBase {
    /// The resolved document text.
    pub yaml: String,
    /// Provenance tag for every leaf the merge takes from this document.
    pub origin: BaseOrigin,
    /// Resolved commits, joined, as change-detection identity.
    pub fingerprint: String,
}

/// The document the local `source:` block currently resolves to.
static RESOLVED_BASE: OnceLock<ArcSwapOption<ResolvedBase>> = OnceLock::new();

fn resolved_base_slot() -> &'static ArcSwapOption<ResolvedBase> {
    RESOLVED_BASE.get_or_init(ArcSwapOption::empty)
}

/// Publish the document a `source:` block resolved to.
///
/// Called only after the document has been proved to compile and has
/// been applied, so a resolution that failed cannot repoint the merge
/// base at a document nothing is serving.
pub fn publish_resolved_base(base: ResolvedBase) {
    resolved_base_slot().store(Some(Arc::new(base)));
}

/// The document a `source:` block resolved to, or `None` on a node whose
/// config is the local file.
#[must_use]
pub fn current_resolved_base() -> Option<Arc<ResolvedBase>> {
    resolved_base_slot().load_full()
}

/// Forget the resolved base. Test-only; a running node never unresolves.
#[cfg(test)]
pub(crate) fn clear_resolved_base() {
    resolved_base_slot().store(None);
}

/// Stable `kind` metric label for one source shape.
#[must_use]
pub fn source_kind_label(source: &ConfigSource) -> &'static str {
    match source {
        ConfigSource::Local => "local",
        ConfigSource::Git { .. } => "git",
        ConfigSource::GitOverlay { .. } => "git_overlay",
    }
}

/// Resolve the `source:` block in one config document.
///
/// A document with no `source:`, or an explicit `kind: local`, is
/// returned as-is and does no I/O at all, so every call site can route
/// through this unconditionally.
///
/// Credentials are resolved here rather than inside `sbproxy-config`:
/// that crate has no secret backend and must not grow one. Each
/// `credential:` reference goes through the process `SecretResolver`, so
/// `env:`, `${VAR}`, `file:`, `vault://`, and `secret://` all behave the
/// way they do everywhere else in the config, and a broken reference
/// fails here rather than at the first refresh.
///
/// # Errors
///
/// Returns an error when the `source:` block is malformed, when a
/// credential reference cannot be resolved, when the `git` binary is
/// missing, when the fetch fails or times out, when a pinned commit does
/// not match the resolved `HEAD`, or when a required signature is
/// absent.
pub fn resolve(inline_yaml: &str) -> anyhow::Result<ResolvedDocument> {
    let Some(source) = sbproxy_config::source::parse_source_head(inline_yaml)
        .map_err(|error| anyhow::anyhow!("config source: {error}"))?
    else {
        return Ok(ResolvedDocument::local(inline_yaml.to_string()));
    };
    let kind = source_kind_label(&source);
    let fetch_ctx = build_fetch_context(&source)?;
    match sbproxy_config::source::load_source_blocking(&source, inline_yaml, &fetch_ctx) {
        Ok(resolved) => {
            // A shared document names its per-node values through
            // `${VAR}`, and a host that did not export one must not take
            // the literal placeholder text as its node identity. Checked
            // before the counter records success, because a document this
            // node cannot use is not a resolution that worked.
            if let Err(error) = sbproxy_config::ensure_node_local_refs_resolved(&resolved.text) {
                sbproxy_observe::metrics::record_config_source_fetch(kind, "invalid");
                return Err(error);
            }
            sbproxy_observe::metrics::record_config_source_fetch(kind, "ok");
            if let Some(commit) = resolved.head_commit() {
                sbproxy_observe::metrics::set_config_source_revision_info(commit);
            }
            tracing::info!(
                kind,
                commit = resolved.head_commit().unwrap_or("unknown"),
                repo = resolved
                    .revisions
                    .first()
                    .map_or("", |revision| revision.repo.as_str()),
                "config source resolved",
            );
            Ok(resolved)
        }
        Err(error) => {
            sbproxy_observe::metrics::record_config_source_fetch(kind, error.metric_label());
            Err(anyhow::anyhow!("config source: {error}"))
        }
    }
}

/// Build the fetch context for one source, resolving every credential
/// reference it names.
fn build_fetch_context(source: &ConfigSource) -> anyhow::Result<FetchContext> {
    let mut fetch_ctx = FetchContext::with_git_binary();
    for (repo, reference) in sbproxy_config::source::credential_references(source) {
        let resolved = resolve_secret_reference(&reference, "source.credential")?;
        fetch_ctx.credentials.insert(repo, resolved);
    }
    Ok(fetch_ctx)
}

/// Build the Git fetch context for configured extension bundle sources.
///
/// This deliberately reuses [`resolve_secret_reference`] instead of giving
/// the bundle loader another secret authority. Errors identify the source
/// index and redacted repository, but never repeat the reference or value.
pub(crate) fn build_extension_fetch_context(
    config: &sbproxy_config::ExtensionBundlesConfig,
) -> anyhow::Result<FetchContext> {
    let mut fetch_ctx = FetchContext::with_git_binary();
    for (index, source) in config.sources.iter().enumerate() {
        let sbproxy_config::BundleSourceConfig::Git {
            repo,
            credential: Some(reference),
            ..
        } = source
        else {
            continue;
        };
        let resolved = resolve_secret_reference(reference, "extensions.sources[].credential")
            .map_err(|_| {
                anyhow::anyhow!(
                    "extensions.sources[{index}].credential for {} could not be resolved",
                    sbproxy_config::redact_repo(repo)
                )
            })?;
        fetch_ctx.credentials.insert(repo.clone(), resolved);
    }
    Ok(fetch_ctx)
}

/// Resolve one secret reference into its value.
///
/// Routes through the process secret resolver when one is installed, so
/// `secret://`, `vault://`, `file:`, and `${VAR}` behave exactly as they
/// do everywhere else in the config. `env:NAME` is normalized to the
/// resolver's `${NAME}` form so the documented spelling works.
///
/// Without a resolver (`sbproxy validate`, unit tests, a serve run whose
/// config declares no `proxy.secrets` backends) the environment and file
/// forms are handled here and a provider URI is a hard error. The
/// reference text is never used as the value: a literal `secret://...`
/// arriving at a git host as a password is the failure this avoids.
///
/// # Errors
///
/// Returns an error when the reference cannot be resolved. The error
/// names the field and the reference, never the resolved value.
pub fn resolve_secret_reference(reference: &str, field: &str) -> anyhow::Result<String> {
    let reference = reference.trim();
    let normalized = match reference.strip_prefix("env:") {
        Some(name) => format!("${{{name}}}"),
        None => reference.to_string(),
    };
    if let Some(resolver) = sbproxy_vault::process_resolver() {
        return resolver
            .resolve(&normalized)
            .map_err(|error| anyhow::anyhow!("resolve {field}: {error:#}"));
    }
    if let Some(name) = normalized
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return std::env::var(name).map_err(|_| {
            anyhow::anyhow!("{field} names the environment variable {name}, which is not set")
        });
    }
    if let Some(path) = normalized.strip_prefix("file:") {
        return std::fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(|error| anyhow::anyhow!("read {field} file '{path}': {error}"));
    }
    anyhow::bail!(
        "{field} references the secret '{reference}' but no secret backend is configured to \
         resolve it; declare one under proxy.secrets.backends"
    )
}

/// Whether the `git` binary this host would use is present and runnable,
/// and what it reports as its version.
///
/// `sbproxy doctor` renders this. `git` is a runtime dependency of any
/// config that names a git source, so a host missing it should find out
/// before it boots rather than from a clone error at 03:00.
#[must_use]
pub fn git_binary_status() -> (Option<std::path::PathBuf>, Option<String>) {
    let path = sbproxy_model_host::resolve_on_path("git");
    let version = path.as_ref().and_then(|_| {
        let output = std::process::Command::new("git")
            .arg("--version")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
    });
    (path, version)
}

/// What one refresh cycle did, and the `result` label it records.
///
/// One enum for both so a new outcome cannot be added without giving it
/// a label, which is how a metric ends up with an undocumented value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCycle {
    /// Resolved a new commit, and it compiled and applied.
    Applied,
    /// Resolved the commit already serving. No compile, no reload.
    NotModified,
    /// The remote could not be reached, or `git` is not installed. The
    /// document already serving keeps serving.
    Unreachable,
    /// The fetch was killed for exceeding its timeout.
    Timeout,
    /// A pinned commit did not match the resolved `HEAD`.
    RevisionMismatch,
    /// A required signature was absent or unverifiable.
    VerifyFailed,
    /// The source block or the resolved path is unusable.
    Invalid,
    /// The resolved document did not compile or could not be
    /// constructed.
    CompileFailed,
    /// Another reload held the reload lock. Nothing was applied.
    ReloadBusy,
}

impl SourceCycle {
    /// Stable metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "ok",
            Self::NotModified => "not_modified",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::RevisionMismatch => "revision_mismatch",
            Self::VerifyFailed => "verify_failed",
            Self::Invalid => "invalid",
            Self::CompileFailed => "compile_failed",
            Self::ReloadBusy => "reload_busy",
        }
    }

    /// Map a resolution failure onto the cycle it produced.
    #[must_use]
    fn from_metric_label(label: &str) -> Self {
        match label {
            "timeout" => Self::Timeout,
            "revision_mismatch" => Self::RevisionMismatch,
            "verify_failed" => Self::VerifyFailed,
            "invalid" => Self::Invalid,
            _ => Self::Unreachable,
        }
    }
}

/// Re-resolve one `source:` block on a timer and apply what changed.
///
/// Construction records the commit the boot resolution landed on, so the
/// first cycle after startup is a no-op unless the repository moved in
/// between.
pub struct SourcePoller {
    /// Path to the pointer file, which is the label the reload
    /// transaction logs and the file `/admin/drift` compares against.
    config_path: String,
    source: ConfigSource,
    kind: &'static str,
    interval: Duration,
    /// Commits the document currently serving was resolved from.
    fingerprint: String,
    /// The last document that resolved cleanly, kept so an unreachable
    /// remote is visibly a no-op rather than a mystery.
    cached: Option<ResolvedDocument>,
    /// Consecutive resolution failures, for the log line only.
    consecutive_failures: u64,
}

impl std::fmt::Debug for SourcePoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourcePoller")
            .field("config_path", &self.config_path)
            .field("kind", &self.kind)
            .field("interval", &self.interval)
            .field("fingerprint", &self.fingerprint)
            .field("consecutive_failures", &self.consecutive_failures)
            .finish_non_exhaustive()
    }
}

impl SourcePoller {
    /// Build a poller for the source in `inline_yaml`, or `None` when
    /// the document has no remote source or disabled refresh.
    ///
    /// `boot` is the resolution that produced the running configuration.
    /// Its fingerprint seeds the change detector, so a poller that
    /// starts one second after boot does not immediately re-apply the
    /// commit already serving.
    ///
    /// # Errors
    ///
    /// Returns an error when the `source:` block cannot be parsed.
    pub fn from_boot(
        config_path: &str,
        inline_yaml: &str,
        boot: &ResolvedDocument,
    ) -> anyhow::Result<Option<Self>> {
        let Some(source) = sbproxy_config::source::parse_source_head(inline_yaml)
            .map_err(|error| anyhow::anyhow!("config source: {error}"))?
        else {
            return Ok(None);
        };
        let Some(interval) = sbproxy_config::source::refresh_interval(&source) else {
            tracing::info!(
                kind = source_kind_label(&source),
                "config source refresh is disabled (refresh_interval_secs: 0); the document is \
                 re-resolved at boot and on every ordinary reload only",
            );
            return Ok(None);
        };
        Ok(Some(Self {
            config_path: config_path.to_string(),
            kind: source_kind_label(&source),
            source,
            interval,
            fingerprint: boot.revision_fingerprint(),
            cached: Some(boot.clone()),
            consecutive_failures: 0,
        }))
    }

    /// Commits the document currently serving was resolved from.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The interval between cycles, before jitter.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Decide what a fresh resolution means, without touching the live
    /// pipeline.
    ///
    /// Pure: no reload, nothing published, nothing persisted. Split out
    /// from [`Self::poll_once`] so the interesting half, which is
    /// "did the commit move", is testable without a server or a
    /// repository.
    #[must_use]
    pub fn evaluate(&self, resolved: &ResolvedDocument) -> SourceCycle {
        if resolved.revision_fingerprint() == self.fingerprint {
            SourceCycle::NotModified
        } else {
            SourceCycle::Applied
        }
    }

    /// Run one cycle: resolve, compare the commit, and apply if it moved.
    ///
    /// Records `sbproxy_config_source_fetch_total{kind,result}` exactly
    /// once per cycle: this function is the only place that writes it, so
    /// for everything after it, so the counter's sum over a node is the
    /// number of cycles attempted.
    pub fn poll_once(&mut self) -> SourceCycle {
        let resolved = match resolve_from(&self.source, &self.config_path) {
            Ok(resolved) => resolved,
            Err((error, label)) => {
                self.consecutive_failures += 1;
                tracing::error!(
                    error = %error,
                    kind = self.kind,
                    consecutive_failures = self.consecutive_failures,
                    serving_commit = self.cached
                        .as_ref()
                        .and_then(ResolvedDocument::head_commit)
                        .unwrap_or("none"),
                    "config source could not be resolved; continuing to serve the document \
                     already applied",
                );
                let cycle = SourceCycle::from_metric_label(label);
                sbproxy_observe::metrics::record_config_source_fetch(self.kind, cycle.as_str());
                return cycle;
            }
        };
        self.consecutive_failures = 0;

        if self.evaluate(&resolved) == SourceCycle::NotModified {
            sbproxy_observe::metrics::record_config_source_fetch(self.kind, "not_modified");
            return SourceCycle::NotModified;
        }

        // Resolution order: the git document is the base, and the
        // authority overlay goes on top of it. A subscriber that has
        // already applied a bundle re-applies its payload here, so a
        // moved commit cannot silently drop central policy until the
        // next authority poll.
        let base_origin = resolved.base_origin();
        let effective = match crate::config_subscriber::overlay_applied_bundle(
            &resolved.text,
            base_origin.clone(),
        ) {
            Ok(Some(merged)) => merged,
            Ok(None) => resolved.text.clone(),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    commit = resolved.head_commit().unwrap_or("unknown"),
                    "the authority bundle already applied could not be merged over the newly \
                     resolved source document; keeping the configuration already serving",
                );
                sbproxy_observe::metrics::record_config_source_fetch(self.kind, "compile_failed");
                return SourceCycle::CompileFailed;
            }
        };

        let outcome = crate::server::try_reload_from_config_yaml(
            &self.config_path,
            &effective,
            "config_refresh_poller",
        );
        let cycle = match outcome {
            Ok(TryReloadOutcome::Applied(outcome)) => {
                let commit = resolved.head_commit().unwrap_or("unknown");
                if outcome.is_fully_applied() {
                    tracing::info!(commit, kind = self.kind, "config source applied");
                } else {
                    tracing::error!(
                        commit,
                        degraded = %outcome,
                        "config source applied, but some subsystems did not; this node serves \
                         the resolved document with stale state for those subsystems",
                    );
                }
                self.fingerprint = resolved.revision_fingerprint();
                publish_resolved_base(ResolvedBase {
                    yaml: resolved.text.clone(),
                    origin: base_origin,
                    fingerprint: self.fingerprint.clone(),
                });
                self.restore_drift_baseline();
                self.cached = Some(resolved);
                SourceCycle::Applied
            }
            Ok(TryReloadOutcome::Busy) => {
                tracing::info!(
                    commit = resolved.head_commit().unwrap_or("unknown"),
                    "another reload is in flight; skipping this config source cycle and \
                     retrying at the next interval",
                );
                SourceCycle::ReloadBusy
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    commit = resolved.head_commit().unwrap_or("unknown"),
                    "the resolved config source document was rejected by the reload \
                     transaction; the previously applied configuration keeps serving",
                );
                SourceCycle::CompileFailed
            }
        };
        sbproxy_observe::metrics::record_config_source_fetch(self.kind, cycle.as_str());
        cycle
    }

    /// Re-point the drift baseline at the pointer file on disk.
    ///
    /// The reload transaction records the hash of whatever it applied,
    /// which here is the resolved document. `GET /admin/drift` compares
    /// that baseline against the file on disk, so leaving the resolved
    /// hash there reports drift on every scrape forever, which trains an
    /// operator to ignore the signal. The question that endpoint answers
    /// is "has the local file changed since we read it?", so the baseline
    /// is the local file. Whether the *source* moved is what
    /// `sbproxy_config_source_revision_info` answers.
    fn restore_drift_baseline(&self) {
        match std::fs::read(&self.config_path) {
            Ok(bytes) => {
                crate::admin::record_loaded_config_content_hash(&crate::identity::config_revision(
                    &bytes,
                ));
            }
            Err(error) => tracing::warn!(
                error = %error,
                path = %self.config_path,
                "could not re-read the pointer file to restore the drift baseline; \
                 /admin/drift may report drift that is not there",
            ),
        }
    }

    /// Poll forever, with jitter.
    ///
    /// The first sleep is a random fraction of a whole interval so a
    /// fleet that restarted together does not arrive at the git host in
    /// lockstep; every later sleep is the interval plus or minus the
    /// documented jitter fraction of it.
    pub fn run(mut self) {
        tracing::info!(
            kind = self.kind,
            refresh_interval_secs = self.interval.as_secs(),
            commit = self
                .cached
                .as_ref()
                .and_then(ResolvedDocument::head_commit)
                .unwrap_or("unknown"),
            "config source refresh started",
        );
        std::thread::sleep(self.interval.mul_f64(random_unit()));
        loop {
            self.poll_once();
            std::thread::sleep(jitter(self.interval));
        }
    }
}

/// Resolve one already-parsed source, mapping the failure onto its
/// metric label so the caller does not re-derive it.
///
/// Records nothing: the poller records exactly one counter sample per
/// cycle, from the cycle's own label, so a failure counted here would be
/// counted twice.
///
/// The `config_path` is carried for the log line and for the `Local`
/// leaves of an overlay chain: it is the file the operator edits, and an
/// error that does not name it is an error nobody can locate.
fn resolve_from(
    source: &ConfigSource,
    config_path: &str,
) -> Result<ResolvedDocument, (anyhow::Error, &'static str)> {
    let inline_yaml = match std::fs::read_to_string(config_path) {
        Ok(yaml) => yaml,
        Err(error) => {
            return Err((
                anyhow::anyhow!("failed to read config file '{config_path}': {error}"),
                "invalid",
            ))
        }
    };
    let fetch_ctx = match build_fetch_context(source) {
        Ok(context) => context,
        Err(error) => return Err((error, "invalid")),
    };
    match sbproxy_config::source::load_source_blocking(source, &inline_yaml, &fetch_ctx) {
        Ok(resolved) => {
            // Same node-identity guard the boot path applies. A commit
            // that dropped the `${VAR}` a host relies on must not be
            // applied on a timer with nobody watching.
            if let Err(error) = sbproxy_config::ensure_node_local_refs_resolved(&resolved.text) {
                return Err((error, "invalid"));
            }
            if let Some(commit) = resolved.head_commit() {
                sbproxy_observe::metrics::set_config_source_revision_info(commit);
            }
            Ok(resolved)
        }
        Err(error) => {
            let label = error.metric_label();
            Err((anyhow::anyhow!("config source: {error}"), label))
        }
    }
}

/// Start the refresh loop on its own thread, if one is configured.
///
/// Pingora owns the process's main runtime and does not hand out a
/// handle, and the resolution itself is synchronous (it shells out to
/// `git` with a hard timeout), so this is a plain thread rather than a
/// tokio task. The reload it performs blocks that thread for the length
/// of a pipeline rebuild, which is fine precisely because the thread
/// exists for one job.
pub fn spawn(poller: Option<SourcePoller>) {
    let Some(poller) = poller else {
        return;
    };
    std::thread::Builder::new()
        .name("sbproxy-config-source".to_string())
        .spawn(move || poller.run())
        .map_err(|error| {
            tracing::error!(
                error = %error,
                "failed to spawn the config source refresh thread; this node will not pick up \
                 changes to its configured source",
            );
        })
        .ok();
}

/// A uniform sample in `[0, 1)`.
fn random_unit() -> f64 {
    rand::random::<f64>()
}

/// `interval` scaled by a uniform factor in
/// `[1 - JITTER_FRACTION, 1 + JITTER_FRACTION]`.
fn jitter(interval: Duration) -> Duration {
    let factor = 1.0 - JITTER_FRACTION + random_unit() * 2.0 * JITTER_FRACTION;
    interval.mul_f64(factor)
}

/// Serializes tests that touch the process-wide resolved-base slot.
static BASE_SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Take the lock that serializes tests over the resolved-base slot.
///
/// The slot is process-wide, so two tests mutating it in parallel would
/// see each other's writes.
#[doc(hidden)]
pub fn lock_resolved_base_for_test() -> std::sync::MutexGuard<'static, ()> {
    BASE_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::source::ResolvedRevision;

    fn git_source(repo: &str, refresh_secs: u64) -> ConfigSource {
        ConfigSource::Git {
            repo: repo.to_string(),
            revision: Some("main".to_string()),
            path: "sb.yml".to_string(),
            credential: None,
            verify_signature: false,
            timeout_secs: 60,
            refresh_interval_secs: refresh_secs,
        }
    }

    fn resolved(commit: &str) -> ResolvedDocument {
        ResolvedDocument {
            text: "proxy: {}\n".to_string(),
            revisions: vec![ResolvedRevision {
                repo: "https://example.test/config.git".to_string(),
                reference: "main".to_string(),
                commit: commit.to_string(),
            }],
        }
    }

    fn poller_at(commit: &str) -> SourcePoller {
        let boot = resolved(commit);
        SourcePoller {
            config_path: "/nonexistent/sb.yml".to_string(),
            kind: "git",
            source: git_source("https://example.test/config.git", 60),
            interval: Duration::from_secs(60),
            fingerprint: boot.revision_fingerprint(),
            cached: Some(boot),
            consecutive_failures: 0,
        }
    }

    #[test]
    fn an_unchanged_commit_is_not_a_reload() {
        let poller = poller_at(&"a".repeat(40));
        assert_eq!(
            poller.evaluate(&resolved(&"a".repeat(40))),
            SourceCycle::NotModified,
            "the same commit must never trigger a recompile",
        );
    }

    #[test]
    fn a_moved_branch_is_a_reload() {
        let poller = poller_at(&"a".repeat(40));
        assert_eq!(
            poller.evaluate(&resolved(&"b".repeat(40))),
            SourceCycle::Applied,
        );
    }

    #[test]
    fn an_overlay_changing_either_input_is_a_reload() {
        let mut boot = resolved(&"a".repeat(40));
        boot.revisions.push(ResolvedRevision {
            repo: "https://example.test/overlay.git".to_string(),
            reference: "main".to_string(),
            commit: "b".repeat(40),
        });
        let poller = SourcePoller {
            config_path: "/nonexistent/sb.yml".to_string(),
            kind: "git_overlay",
            source: git_source("https://example.test/config.git", 60),
            interval: Duration::from_secs(60),
            fingerprint: boot.revision_fingerprint(),
            cached: Some(boot.clone()),
            consecutive_failures: 0,
        };
        assert_eq!(poller.evaluate(&boot), SourceCycle::NotModified);
        let mut moved = boot.clone();
        moved.revisions[1].commit = "c".repeat(40);
        assert_eq!(poller.evaluate(&moved), SourceCycle::Applied);
    }

    #[test]
    fn no_source_block_means_no_poller() {
        let boot = ResolvedDocument::local("proxy: {}\n".to_string());
        assert!(SourcePoller::from_boot("/tmp/sb.yml", "proxy: {}\n", &boot)
            .expect("parses")
            .is_none());
        assert!(
            SourcePoller::from_boot("/tmp/sb.yml", "source:\n  kind: local\n", &boot)
                .expect("parses")
                .is_none()
        );
    }

    #[test]
    fn zero_refresh_interval_means_no_poller() {
        let boot = resolved(&"a".repeat(40));
        let yaml = "source:\n  kind: git\n  repo: https://example.test/c.git\n  \
                    path: sb.yml\n  refresh_interval_secs: 0\n";
        assert!(SourcePoller::from_boot("/tmp/sb.yml", yaml, &boot)
            .expect("parses")
            .is_none());
    }

    #[test]
    fn a_git_source_gets_a_poller_seeded_at_the_boot_commit() {
        let boot = resolved(&"a".repeat(40));
        let yaml = "source:\n  kind: git\n  repo: https://example.test/c.git\n  \
                    path: sb.yml\n  refresh_interval_secs: 30\n";
        let poller = SourcePoller::from_boot("/tmp/sb.yml", yaml, &boot)
            .expect("parses")
            .expect("git source gets a poller");
        assert_eq!(poller.interval(), Duration::from_secs(30));
        assert_eq!(poller.fingerprint(), &"a".repeat(40));
        assert_eq!(poller.evaluate(&boot), SourceCycle::NotModified);
    }

    #[test]
    fn an_unresolvable_source_keeps_the_document_already_serving() {
        // The whole point of the cached last-good document: a git host
        // that goes away must not take the proxy's configuration with it.
        let dir = tempfile::tempdir().expect("tempdir");
        let pointer = dir.path().join("sb.yml");
        std::fs::write(
            &pointer,
            format!(
                "source:\n  kind: git\n  repo: file://{}/not-a-repository\n  \
                 revision: main\n  path: sb.yml\n  timeout_secs: 10\n",
                dir.path().display()
            ),
        )
        .expect("write pointer");

        let boot = resolved(&"a".repeat(40));
        let mut poller = SourcePoller {
            config_path: pointer.to_string_lossy().into_owned(),
            kind: "git",
            source: git_source("https://example.test/config.git", 60),
            interval: Duration::from_secs(60),
            fingerprint: boot.revision_fingerprint(),
            cached: Some(boot.clone()),
            consecutive_failures: 0,
        };
        // Point the poller at the unresolvable repository the pointer
        // names, so the cycle exercises the real resolution path.
        poller.source = sbproxy_config::source::parse_source_head(
            &std::fs::read_to_string(&pointer).expect("read pointer"),
        )
        .expect("pointer parses")
        .expect("pointer names a source");

        let cycle = poller.poll_once();
        assert!(
            matches!(
                cycle,
                SourceCycle::Unreachable | SourceCycle::Timeout | SourceCycle::Invalid
            ),
            "a missing repository must be a fetch failure, got {cycle:?}",
        );
        assert_eq!(
            poller.fingerprint(),
            &boot.revision_fingerprint(),
            "a failed resolution must not advance the applied commit",
        );
        let boot_commit = "a".repeat(40);
        assert_eq!(
            poller
                .cached
                .as_ref()
                .and_then(ResolvedDocument::head_commit),
            Some(boot_commit.as_str()),
            "the cached last-good document keeps serving",
        );
        assert_eq!(poller.consecutive_failures, 1);
    }

    #[test]
    fn cycle_labels_are_the_documented_set() {
        let labels: Vec<&str> = [
            SourceCycle::Applied,
            SourceCycle::NotModified,
            SourceCycle::Unreachable,
            SourceCycle::Timeout,
            SourceCycle::RevisionMismatch,
            SourceCycle::VerifyFailed,
            SourceCycle::Invalid,
            SourceCycle::CompileFailed,
            SourceCycle::ReloadBusy,
        ]
        .iter()
        .map(|cycle| cycle.as_str())
        .collect();
        assert_eq!(
            labels,
            vec![
                "ok",
                "not_modified",
                "unreachable",
                "timeout",
                "revision_mismatch",
                "verify_failed",
                "invalid",
                "compile_failed",
                "reload_busy",
            ],
        );
    }

    #[test]
    fn jitter_stays_inside_the_documented_band() {
        let interval = Duration::from_secs(60);
        for _ in 0..256 {
            let jittered = jitter(interval);
            assert!(
                jittered >= interval.mul_f64(1.0 - JITTER_FRACTION)
                    && jittered <= interval.mul_f64(1.0 + JITTER_FRACTION),
                "{jittered:?} is outside the jitter band",
            );
        }
    }

    #[test]
    fn resolving_a_document_with_no_source_does_no_io() {
        let yaml = "proxy:\n  http_bind_port: 8080\n";
        let resolved = resolve(yaml).expect("a local document resolves to itself");
        assert_eq!(resolved.text, yaml);
        assert!(!resolved.is_remote());
        assert_eq!(resolved.base_origin(), BaseOrigin::Local);
    }

    #[test]
    fn bundle_credentials_resolve_through_the_existing_secret_authority() {
        let directory = tempfile::tempdir().expect("temporary secret directory");
        let secret_path = directory.path().join("git-token");
        std::fs::write(&secret_path, "bundle-private-token\n").expect("write secret fixture");
        let repo = "https://example.test/private-bundles.git";
        let config = sbproxy_config::ExtensionBundlesConfig {
            bundles_dir: None,
            grants: Default::default(),
            sources: vec![sbproxy_config::BundleSourceConfig::Git {
                repo: repo.to_string(),
                revision: "a".repeat(40),
                path: "bundles".to_string(),
                credential: Some(format!("file:{}", secret_path.display())),
                verify_signature: false,
                timeout_secs: 60,
                refresh_interval_secs: 60,
            }],
        };

        let context = build_extension_fetch_context(&config).expect("credential resolves");

        assert_eq!(
            context.credentials.get(repo).map(String::as_str),
            Some("bundle-private-token")
        );
        let debug = format!("{context:?}");
        assert!(!debug.contains("bundle-private-token"), "{debug}");
        assert!(
            !debug.contains(&secret_path.to_string_lossy().to_string()),
            "{debug}"
        );
    }

    #[test]
    fn bundle_credential_resolution_errors_do_not_repeat_secret_material() {
        let secret_material = "literal-private-token-that-must-not-leak";
        let config = sbproxy_config::ExtensionBundlesConfig {
            bundles_dir: None,
            grants: Default::default(),
            sources: vec![sbproxy_config::BundleSourceConfig::Git {
                repo: "https://example.test/private-bundles.git".to_string(),
                revision: "a".repeat(40),
                path: "bundles".to_string(),
                credential: Some(secret_material.to_string()),
                verify_signature: false,
                timeout_secs: 60,
                refresh_interval_secs: 60,
            }],
        };

        let error = build_extension_fetch_context(&config)
            .expect_err("a literal is not a resolvable secret reference");
        let displayed = error.to_string();

        assert!(displayed.contains("extensions.sources[0].credential"));
        assert!(!displayed.contains(secret_material), "{displayed}");
    }

    #[test]
    fn a_malformed_source_block_is_an_error_not_a_silent_local_read() {
        let error = resolve("source:\n  kind: not_a_kind\n").expect_err("malformed source");
        assert!(error.to_string().contains("config source"), "{error:#}");
    }

    #[test]
    fn the_resolved_base_slot_round_trips() {
        let _guard = lock_resolved_base_for_test();
        clear_resolved_base();
        assert!(current_resolved_base().is_none());
        publish_resolved_base(ResolvedBase {
            yaml: "proxy: {}\n".to_string(),
            origin: BaseOrigin::Git {
                repo: "https://example.test/c.git".to_string(),
                reference: "main".to_string(),
                commit: "a".repeat(40),
            },
            fingerprint: "a".repeat(40),
        });
        let base = current_resolved_base().expect("published base is readable");
        assert!(matches!(base.origin, BaseOrigin::Git { .. }));
        clear_resolved_base();
    }

    #[test]
    fn source_kind_labels_are_stable() {
        assert_eq!(source_kind_label(&ConfigSource::Local), "local");
        assert_eq!(
            source_kind_label(&git_source("https://example.test/c.git", 60)),
            "git"
        );
        assert_eq!(
            source_kind_label(&ConfigSource::GitOverlay {
                base: Box::new(ConfigSource::Local),
                overlays: vec![],
            }),
            "git_overlay"
        );
    }
}
