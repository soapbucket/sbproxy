// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Config-authority subscriber: pull signed configuration from an
//! upstream authority and apply it through the ordinary reload
//! transaction.
//!
//! # What one cycle does
//!
//! 1. `GET {url}/config-authority/v1/bundle` with the current
//!    [`sbproxy_config::ConfigBundleCursor`] in `If-None-Match`. A `304` ends the cycle:
//!    no compile, no merge, no reload.
//! 2. Verify the envelope against the [`sbproxy_config::VerifyingKeySet`] loaded from
//!    `verifying_keys_file`. Signature, schema version, content digest,
//!    algorithm, and expiry are all checked by
//!    [`sbproxy_config::SignedConfigBundle::verify_at`]; this module adds only the
//!    declared-mode check and the anti-replay cursor probe.
//! 3. Merge the payload over the base document with
//!    [`sbproxy_config::merge_config`], in the configured mode. The base
//!    is the local file, or, on a node whose local file declares a
//!    `source:` block, the document that source resolved to. The
//!    [`sbproxy_config::BaseOrigin`] tag follows: `local` for a local
//!    file, `git` for a resolved repository, so the provenance map has
//!    three values rather than two.
//! 4. Refuse a merged document that still carries an unresolved
//!    `${VAR}` reference.
//! 5. Apply through `try_reload_from_config_yaml`, the same three-phase
//!    reject / construct / commit transaction a SIGHUP takes.
//! 6. Persist the verified bundle and the advanced cursor, then publish
//!    the revision and age gauges.
//!
//! # Why the poller never waits for the reload lock
//!
//! The reload lock is held for the whole prepare-and-publish body, which
//! on a large config is not brief. A poller that blocks on it queues up:
//! every skipped interval wakes into the same lock and eventually applies
//! a revision that has already been superseded. So the apply step uses
//! the try-lock entry point and reports `reload_busy` instead, and the
//! next interval retries with whatever the authority is serving by then.
//!
//! # Polling is the required path; gossip only shortens the wait
//!
//! Every subscriber converges by polling, on `poll_interval`, and that is
//! what the contract promises. A subscriber that also happens to be a mesh
//! member gets an accelerator on top: the authority announces its current
//! revision into typed cluster state, and
//! [`crate::config_subscriber::ConfigSubscriber::await_next_cycle`] cuts the
//! interval short when it sees a revision this node does not hold. The pull
//! it triggers is the same cycle as any other, with every verification step
//! intact; nothing gossiped is ever adopted as configuration. See
//! [`crate::config_gossip`].
//!
//! A subscriber with no mesh node holds no watcher and takes none of that
//! code: `await_next_cycle` is one `sleep`. That case is not an afterthought,
//! it is the common one. Managed-service subscribers reach the authority over
//! the internet and are in nobody's gossip cluster.
//!
//! # Failure behaviour
//!
//! | Situation | Behaviour |
//! |---|---|
//! | Authority unreachable | Keep serving the cached bundle. Error log, `unreachable` counter, age gauge climbs. |
//! | Signature, schema, digest, expiry, declared-mode, or replay refusal | Reject the candidate. Previous config keeps serving. `verify_failed`. |
//! | Merged document does not compile or cannot be constructed | Reject the candidate. `compile_failed`. |
//! | Merged document carries an unresolved `${VAR}` | Reject the candidate. `compile_failed`. |
//! | Bundle names a subscriber-owned path | Reject the candidate. `denied_path`. |
//! | Another reload in flight | Skip the cycle. `reload_busy`. |
//! | Cold boot, no cache, `overlay` | Boot on the local document with a loud warning. |
//! | Cold boot, no cache, `replace` (or `require_bundle_on_boot`) | Refuse to start. |
//!
//! # Boot does no network I/O
//!
//! [`crate::config_subscriber::fold_boot_bundle`] reads the cache and the key file and nothing
//! else. Startup that depends on a remote fetch is startup that hangs
//! when the remote is slow, which this repo has already paid for. A node
//! whose cache is empty therefore boots on its local document (overlay)
//! or refuses to start (replace), and the first poll cycle a few seconds
//! later brings in the authority's document. Seeding `cache_path` with a
//! signed bundle is how a `replace` subscriber comes up the first time.
//!
//! # Staleness is measured from local receipt
//!
//! Age comes from when this node received and applied a bundle, not from
//! the authority's `issued_at`. Two clocks that disagree would otherwise
//! produce a negative or absurd age at exactly the moment an operator is
//! trying to decide whether config distribution is stuck. Receipt time is
//! stored beside the cached bundle so it survives a restart. `issued_at`
//! is still enforced, through the bundle's own expiry check.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sbproxy_config::config_bundle::{
    BundleMode, ConfigBundle, ConfigBundleCursor, SignedConfigBundle, VerifyingKeySet,
    MAX_CONFIG_YAML_BYTES,
};
use sbproxy_config::config_merge::{merge_config, BaseOrigin, MergeError, MergeMode};
use sbproxy_config::types::ConfigAuthorityUpstreamConfig;
use sbproxy_config::CompiledConfig;
use serde::{Deserialize, Serialize};

use crate::server::TryReloadOutcome;

/// Path the subscriber appends to the configured authority URL.
///
/// Versioned in the path so an authority can serve a second bundle shape
/// alongside this one during an upgrade.
pub const BUNDLE_ENDPOINT_PATH: &str = "/config-authority/v1/bundle";

/// Header carrying `subscriber_id` on every fetch, so an authority can
/// scope what it publishes without inspecting the credential.
pub const SUBSCRIBER_ID_HEADER: &str = "x-sbproxy-subscriber-id";

/// Suffix appended to `cache_path` for the anti-replay cursor file.
pub const CURSOR_FILE_SUFFIX: &str = ".cursor";

/// Connect timeout for a bundle fetch.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total request timeout for a bundle fetch, connect included.
///
/// Cycles never overlap, so a slow authority delays the next cycle rather
/// than stacking requests on top of each other.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Fraction of the poll interval the jitter spans, either side of it.
///
/// A fleet that restarts together would otherwise poll in lockstep
/// forever, turning a rolling restart into a repeating thundering herd.
const JITTER_FRACTION: f64 = 0.15;

/// Largest response body accepted from the authority, in bytes.
///
/// JSON string escaping can roughly double a YAML payload made mostly of
/// newlines, so the envelope bound is twice the payload bound plus room
/// for the surrounding fields. Matches the bound
/// [`SignedConfigBundle::from_json`] enforces, applied while reading so a
/// hostile authority cannot make a subscriber buffer the whole stream
/// first.
const MAX_RESPONSE_BYTES: usize = 2 * MAX_CONFIG_YAML_BYTES + 64 * 1024;

/// The authority payload this node last applied, kept so a document
/// resolved from a `source:` block can have the same overlay re-applied
/// on top of it.
///
/// Resolution order is fixed: the source document is the base and the
/// authority overlay goes on top. Without this, a git source that moved
/// would reload the repository's document alone and silently drop
/// central policy until the next authority poll, which is a fleet-wide
/// window where the configuration is not what either layer says it is.
///
/// The payload was verified before it was applied, so re-merging it
/// needs no signature check. Only the payload is kept, never a key.
#[derive(Debug, Clone)]
pub struct AppliedAuthority {
    /// The authority document, as published and verified.
    pub config_yaml: String,
    /// How the document combines with the base document.
    pub merge_mode: MergeMode,
    /// Revision of the payload, as the authority numbered it.
    pub revision: u64,
    /// Identifier the authority published under.
    pub authority_id: String,
}

/// The authority payload currently applied on this node, if any.
static APPLIED_BUNDLE: std::sync::Mutex<Option<AppliedAuthority>> = std::sync::Mutex::new(None);

/// The authority payload this node has applied, if any.
///
/// `None` on a node with no upstream authority, which includes a node that
/// has one configured but has not yet completed a poll. A caller reporting
/// on configuration ownership wants exactly this distinction: an authority
/// that is configured but has never been reached owns nothing yet, and the
/// node's own file is still the whole story.
#[must_use]
pub fn applied_authority() -> Option<AppliedAuthority> {
    APPLIED_BUNDLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Record the authority payload this node has applied.
fn record_applied_bundle(bundle: &ConfigBundle) {
    let mut slot = APPLIED_BUNDLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(AppliedAuthority {
        config_yaml: bundle.config_yaml.clone(),
        merge_mode: match bundle.mode {
            BundleMode::Overlay => MergeMode::Overlay,
            BundleMode::Replace => MergeMode::Replace,
        },
        revision: bundle.revision,
        authority_id: bundle.authority_id.clone(),
    });
}

/// Install an applied authority payload directly. Test-only; a running
/// node only ever reaches this state by verifying and applying a bundle.
#[cfg(test)]
pub(crate) fn set_applied_authority(applied: AppliedAuthority) {
    let mut slot = APPLIED_BUNDLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(applied);
}

/// Merge the authority payload this node already applied over a freshly
/// resolved base document.
///
/// `Ok(None)` means this node has no authority overlay, so the base
/// document is the effective document and the caller applies it
/// unchanged. That is the standalone-GitOps shape and the common case.
///
/// Called by the config-source refresh poller so a moved commit lands
/// underneath the authority's document rather than replacing it. The
/// deny list still applies: an authority payload naming `source:` was
/// already refused when it was first merged, and it is refused again
/// here.
///
/// # Errors
///
/// Returns an error when the merge fails, including when the recorded
/// payload names a subscriber-owned path.
pub fn overlay_applied_bundle(
    base_yaml: &str,
    base_origin: BaseOrigin,
) -> anyhow::Result<Option<String>> {
    let applied = {
        let slot = APPLIED_BUNDLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.clone()
    };
    let Some(applied) = applied else {
        return Ok(None);
    };
    let merged = merge_config(
        base_yaml,
        base_origin,
        &applied.config_yaml,
        applied.merge_mode,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "re-merging authority {} revision {} over the resolved source document failed: \
             {error}",
            applied.authority_id,
            applied.revision
        )
    })?;
    Ok(Some(merged.merged_yaml))
}

/// Forget the applied authority payload. Test-only.
#[cfg(test)]
pub(crate) fn clear_applied_bundle() {
    let mut slot = APPLIED_BUNDLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = None;
}

/// Cursor rendered as an HTTP entity tag, or `None` when nothing has been
/// applied yet and every revision is new.
///
/// The wire form is `"<revision>-<content_digest>"`. Both halves matter:
/// the revision is what the authority compares, and the digest is what
/// makes a same-revision content change visible rather than a silent
/// `304`.
#[must_use]
pub fn cursor_etag(cursor: &ConfigBundleCursor) -> Option<String> {
    if cursor.revision == 0 || cursor.content_digest.is_empty() {
        return None;
    }
    Some(format!("\"{}-{}\"", cursor.revision, cursor.content_digest))
}

/// The verified bundle this node last applied, plus when it arrived.
///
/// Receipt time is stored rather than derived so the age gauge and the
/// staleness window survive a restart, and so neither depends on the
/// authority's clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedBundle {
    /// When this node received and applied the bundle, in unix
    /// milliseconds on the local clock.
    pub received_at_unix_ms: u64,
    /// The signed envelope exactly as the authority served it, so a
    /// restart re-verifies the signature instead of trusting the file.
    pub bundle: SignedConfigBundle,
}

impl CachedBundle {
    /// Load the cached bundle. `Ok(None)` means no cache exists yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists but is unreadable, is not a
    /// regular file, is oversized, or does not decode.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Option<Self>> {
        let path = path.as_ref();
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "read config bundle cache '{}': {error}",
                    path.display()
                ))
            }
        };
        if !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!(
                "config bundle cache '{}' is empty or not a regular file",
                path.display()
            );
        }
        if metadata.len() > MAX_RESPONSE_BYTES as u64 {
            anyhow::bail!(
                "config bundle cache '{}' is {} bytes; the limit is {MAX_RESPONSE_BYTES} bytes",
                path.display(),
                metadata.len()
            );
        }
        let bytes = std::fs::read(path).map_err(|error| {
            anyhow::anyhow!("read config bundle cache '{}': {error}", path.display())
        })?;
        let cached: Self = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow::anyhow!("decode config bundle cache '{}': {error}", path.display())
        })?;
        Ok(Some(cached))
    }

    /// Write the cache atomically: a temporary file in the same
    /// directory, flushed, then renamed over the target. A crash
    /// mid-write leaves the previous cache or the new one, never a
    /// truncated file a later boot would refuse.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload cannot be encoded, the parent
    /// directory cannot be created, or the write or rename fails.
    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        let mut body = serde_json::to_vec(self)
            .map_err(|error| anyhow::anyhow!("encode config bundle cache: {error}"))?;
        body.push(b'\n');
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "create config bundle cache directory '{}': {error}",
                parent.display()
            )
        })?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config-bundle.json");
        // Pid plus nanoseconds keeps two writers in one directory from
        // colliding. The rename is the atomic step, not the create.
        let temporary = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            now_unix_ms()
        ));
        let result = (|| {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&body)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.map_err(|error| {
            anyhow::anyhow!("write config bundle cache '{}': {error}", path.display())
        })
    }

    /// Seconds since this node received the bundle, floored at zero so a
    /// clock that stepped backwards reports fresh rather than negative.
    #[must_use]
    pub fn age_secs(&self, now_unix_ms: u64) -> u64 {
        now_unix_ms.saturating_sub(self.received_at_unix_ms) / 1_000
    }
}

/// What one fetch attempt produced.
#[derive(Debug)]
pub enum FetchResult {
    /// The authority served a bundle. Not yet verified.
    Bundle(Box<SignedConfigBundle>),
    /// The authority answered `304 Not Modified`, or served the exact
    /// revision this node already holds.
    NotModified,
    /// The authority could not be reached, timed out, answered with a
    /// status other than `200` or `304`, or sent something undecodable.
    /// Carries the reason for the log line.
    Unreachable(String),
}

/// The outcome of one poll cycle, and the `result` label it records.
///
/// One enum for both so a new outcome cannot be added without giving it a
/// label, which is how a metric ends up with an undocumented value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleResult {
    /// Fetched, verified, merged, and applied.
    Applied,
    /// Nothing to do: a `304`, or a re-serve of the applied revision.
    NotModified,
    /// The authority could not be reached. The cached bundle keeps
    /// serving.
    Unreachable,
    /// The envelope failed verification, declared a mode this subscriber
    /// does not run, or tried to move the cursor backwards.
    VerifyFailed,
    /// The merged document did not compile, could not be constructed, or
    /// still carried an unresolved `${VAR}` reference.
    CompileFailed,
    /// The bundle named a path the subscriber owns outright.
    DeniedPath,
    /// Another reload held the reload lock. Nothing was examined.
    ReloadBusy,
}

impl CycleResult {
    /// Stable metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "ok",
            Self::NotModified => "not_modified",
            Self::Unreachable => "unreachable",
            Self::VerifyFailed => "verify_failed",
            Self::CompileFailed => "compile_failed",
            Self::DeniedPath => "denied_path",
            Self::ReloadBusy => "reload_busy",
        }
    }
}

/// A verified bundle merged over the local document, ready to apply.
///
/// Holding this means every check that can refuse a candidate without
/// touching the live pipeline has already passed.
#[derive(Debug)]
pub struct MergedCandidate {
    merged_yaml: String,
    cursor: ConfigBundleCursor,
    revision: u64,
    signed: SignedConfigBundle,
    /// Where the merge base (`base_yaml`) came from, computed once in
    /// [`ConfigSubscriber::evaluate`] against the base this candidate was
    /// actually merged over. Carried through to
    /// [`ConfigSubscriber::apply`] rather than recomputed there: by then
    /// only `merged_yaml` is in scope, a document with no `source:`
    /// block of its own, so re-deriving an origin from it would
    /// misreport a git-sourced base as [`BaseOrigin::Local`].
    base_origin: BaseOrigin,
}

impl MergedCandidate {
    /// Authority revision this candidate carries.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The merged document that would be applied.
    #[must_use]
    pub fn merged_yaml(&self) -> &str {
        &self.merged_yaml
    }
}

/// A subscriber to one upstream config authority.
///
/// Construction reads the key file and the cursor and builds the HTTP
/// client; it performs no network I/O. The decision logic
/// ([`Self::evaluate`]) is separable from the transport
/// ([`Self::fetch`]) so the interesting half is testable without a
/// server.
pub struct ConfigSubscriber {
    /// Path to the local document, which is both the merge base and the
    /// label the reload transaction logs.
    config_path: String,
    /// Authority base URL with any trailing slash removed.
    base_url: String,
    subscriber_id: String,
    /// Resolved bearer credential. Resolved once at construction so a
    /// broken secret reference fails at boot rather than at 03:00.
    credential: Option<String>,
    verifying_keys_file: PathBuf,
    /// Trusted keys, or `None` when the key file could not be loaded. A
    /// cycle retries the load, so an operator fixing the file does not
    /// need to restart the process.
    keys: Option<VerifyingKeySet>,
    allow_shared_secret_keys: bool,
    mode: BundleMode,
    merge_mode: MergeMode,
    /// Effective `require_bundle_on_boot`, with the `replace` default
    /// already resolved by the config layer.
    requires_bundle_on_boot: bool,
    poll_interval: Duration,
    max_staleness: Duration,
    cache_path: PathBuf,
    cursor_path: PathBuf,
    cursor: ConfigBundleCursor,
    /// Local receipt time of the bundle currently serving, if any.
    received_at_unix_ms: Option<u64>,
    client: reqwest::Client,
    /// The gossip accelerator, present only on a mesh member.
    ///
    /// `None` is the whole of the non-mesh code path: a subscriber without a
    /// watcher sleeps out its jittered interval exactly as it did before the
    /// accelerator existed. Managed-service subscribers are in nobody's
    /// gossip cluster, so that path is the one that has to stay boring.
    gossip: Option<crate::config_gossip::ConfigGossipWatcher>,
    /// Cursor revision at which a gossip hint last shortened the wait.
    ///
    /// Bounds the accelerator to one early pull per applied revision. Without
    /// it, an announcement the pull cannot satisfy (a revision this node
    /// refuses, a peer announcing a number no authority ever served, a reload
    /// that stays busy) would still be a hint on the next probe, and the next,
    /// so the subscriber would fetch on the probe cadence instead of the poll
    /// interval: fast enough to trip the authority's own per-subscriber rate
    /// limit and turn a speed-up into a stream of `429`s. One pull per
    /// revision means a hint that does not move the cursor costs exactly one
    /// extra fetch, after which this node is back on its interval.
    gossip_pulled_at_cursor: Option<u64>,
}

impl std::fmt::Debug for ConfigSubscriber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigSubscriber")
            .field("config_path", &self.config_path)
            .field("base_url", &self.base_url)
            .field("subscriber_id", &self.subscriber_id)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "<redacted>"),
            )
            .field("mode", &self.mode)
            .field("keys", &self.keys.as_ref().map(VerifyingKeySet::len))
            .field("cursor", &self.cursor)
            .field("gossip_accelerated", &self.gossip.is_some())
            .finish_non_exhaustive()
    }
}

impl ConfigSubscriber {
    /// Build a subscriber from a validated `proxy.config_authority.upstream`
    /// block.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential reference cannot be
    /// resolved, when the persisted cursor is unreadable or malformed, or
    /// when the HTTP client cannot be built. A missing or malformed key
    /// file is deliberately not fatal here: it is reported, and
    /// [`Self::boot_from_cache`] decides whether the node may serve
    /// without one.
    pub fn new(
        config_path: &str,
        upstream: &ConfigAuthorityUpstreamConfig,
    ) -> anyhow::Result<Self> {
        let credential = match upstream.credential.as_deref() {
            Some(reference) => Some(resolve_credential(reference)?),
            None => None,
        };
        let cache_path = PathBuf::from(&upstream.cache_path);
        let cursor_path = cursor_path_for(&cache_path);
        let cursor = ConfigBundleCursor::load(&cursor_path)
            .map_err(|error| {
                anyhow::anyhow!(
                    "read config bundle cursor '{}': {error}",
                    cursor_path.display()
                )
            })?
            .unwrap_or_default();
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // A config authority that answers with a redirect is a
            // misconfiguration, and following one would let it move the
            // fetch off the host the operator named.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| anyhow::anyhow!("build config authority HTTP client: {error}"))?;

        let mut subscriber = Self {
            config_path: config_path.to_string(),
            base_url: upstream.url.trim_end_matches('/').to_string(),
            subscriber_id: upstream.subscriber_id.clone(),
            credential,
            verifying_keys_file: PathBuf::from(&upstream.verifying_keys_file),
            keys: None,
            allow_shared_secret_keys: upstream.allow_shared_secret_keys,
            mode: upstream.mode,
            merge_mode: upstream.merge_mode(),
            requires_bundle_on_boot: upstream.requires_bundle_on_boot(),
            poll_interval: Duration::from_secs(upstream.poll_interval_secs),
            max_staleness: Duration::from_secs(upstream.max_staleness_secs),
            cache_path,
            cursor_path,
            cursor,
            received_at_unix_ms: None,
            client,
            // Deliberately not resolved here. Construction runs from
            // `fold_boot_bundle`, which the boot path calls before the
            // process cluster is installed, so asking for a handle now would
            // always answer `None` and quietly disable the accelerator on
            // every clustered node. `run` resolves it instead, by which
            // point the cluster is up.
            gossip: None,
            gossip_pulled_at_cursor: None,
        };
        subscriber.load_keys();
        Ok(subscriber)
    }

    /// Install a gossip accelerator, replacing any already attached.
    ///
    /// [`Self::run`] resolves the process cluster's watcher on its own, so
    /// production never needs this. It exists so a test can point a
    /// subscriber at a specific cluster handle without installing a
    /// process-wide one.
    pub fn attach_gossip(&mut self, watcher: crate::config_gossip::ConfigGossipWatcher) {
        self.gossip = Some(watcher);
    }

    /// Whether a gossip accelerator is attached.
    ///
    /// `false` is the non-mesh subscriber: it converges by polling and takes
    /// no cluster code path at all.
    #[must_use]
    pub const fn is_gossip_accelerated(&self) -> bool {
        self.gossip.is_some()
    }

    /// Revision this node currently serves. Zero means none applied.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.cursor.revision
    }

    /// The anti-replay cursor, as persisted.
    #[must_use]
    pub const fn cursor(&self) -> &ConfigBundleCursor {
        &self.cursor
    }

    /// Whether a usable verifying-key set is loaded.
    #[must_use]
    pub const fn has_keys(&self) -> bool {
        self.keys.is_some()
    }

    /// (Re)load the verifying-key file, reporting failure without
    /// tearing the subscriber down.
    fn load_keys(&mut self) {
        match VerifyingKeySet::from_file(&self.verifying_keys_file) {
            Ok(keys) => {
                let keys = keys.allow_shared_secret(self.allow_shared_secret_keys);
                if keys.is_empty() {
                    tracing::error!(
                        path = %self.verifying_keys_file.display(),
                        "config authority verifying-key file declares no keys; every bundle \
                         will be refused until it does",
                    );
                }
                self.keys = Some(keys);
            }
            Err(error) => {
                self.keys = None;
                tracing::error!(
                    error = %error,
                    path = %self.verifying_keys_file.display(),
                    "config authority verifying-key file could not be loaded; bundles cannot \
                     be verified and none will be applied",
                );
            }
        }
    }

    /// Re-read the verifying-key file, keeping the current keys if the read
    /// fails.
    ///
    /// Called once per cycle so the trust file is the trust anchor rather
    /// than a snapshot of it at boot. Before this, keys were loaded once at
    /// startup and re-read only when the file had failed to load entirely,
    /// which broke both halves of the rotation the docs promise:
    ///
    /// - **Adding** a key ID never took effect. An operator who added a
    ///   second entry to a working file saw every bundle signed by it refused
    ///   indefinitely, with `key ID ... is not in the verifying key set`.
    /// - **Removing** one never took effect either, which is the half that
    ///   matters more. A key revoked because it leaked kept verifying bundles
    ///   until every node had been restarted, so revocation was a rolling
    ///   restart rather than an edit.
    ///
    /// Both were found by the two-process rotation drill. No unit test could
    /// see either, because they all construct the key set directly and never
    /// go through the file.
    ///
    /// A failed read keeps the keys already loaded instead of dropping to
    /// none. A file being rewritten is briefly unreadable or truncated, and
    /// treating that instant as "trust nothing" would turn an ordinary
    /// rotation into a window where every bundle is refused. The error is
    /// logged on every cycle it persists, so a genuinely broken file is loud.
    ///
    /// The cost is one small read per poll interval, which is at least five
    /// seconds. That is the right trade against a trust anchor that cannot be
    /// revoked without a restart.
    fn refresh_keys(&mut self) {
        match VerifyingKeySet::from_file(&self.verifying_keys_file) {
            Ok(keys) => {
                let keys = keys.allow_shared_secret(self.allow_shared_secret_keys);
                if keys.is_empty() {
                    tracing::error!(
                        path = %self.verifying_keys_file.display(),
                        "config authority verifying-key file declares no keys; every bundle \
                         will be refused until it does",
                    );
                }
                let changed = self
                    .keys
                    .as_ref()
                    .is_none_or(|current| current.len() != keys.len());
                if changed {
                    tracing::info!(
                        keys_before = self.keys.as_ref().map_or(0, VerifyingKeySet::len),
                        keys_after = keys.len(),
                        path = %self.verifying_keys_file.display(),
                        "config authority verifying-key set changed on disk and is now in \
                         effect without a restart",
                    );
                }
                self.keys = Some(keys);
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    path = %self.verifying_keys_file.display(),
                    kept_keys = self.keys.as_ref().map_or(0, VerifyingKeySet::len),
                    "config authority verifying-key file could not be re-read; keeping the \
                     key set already loaded",
                );
            }
        }
    }

    /// Whether `bundle` is the exact revision and content this node
    /// already serves, which makes the cycle a no-op.
    ///
    /// Covers an authority that does not implement `If-None-Match`: it
    /// re-serves the current bundle every interval, and this keeps that
    /// from being recompiled and reloaded every interval.
    #[must_use]
    pub fn holds_revision(&self, bundle: &ConfigBundle) -> bool {
        self.cursor.revision == bundle.revision
            && self.cursor.content_digest == bundle.content_digest
    }

    /// Verify, replay-check, merge, and screen one candidate bundle
    /// against `base_yaml`, the local document.
    ///
    /// Pure: no network, no filesystem, no process global, nothing
    /// published and nothing persisted. Every check that can refuse a
    /// candidate without touching the live pipeline lives here, which is
    /// what makes the interesting half of a cycle testable without a
    /// server.
    ///
    /// # Errors
    ///
    /// Returns the [`CycleResult`] the caller should record. Every arm
    /// leaves the previously applied configuration serving.
    pub fn evaluate(
        &self,
        signed: &SignedConfigBundle,
        base_yaml: &str,
        now_unix_ms: u64,
    ) -> Result<MergedCandidate, CycleResult> {
        // No trusted keys means nothing can be verified, so nothing can be
        // applied. `load_keys` already logged why, once per attempt, and
        // every cycle retries the load.
        let Some(keys) = self.keys.as_ref() else {
            return Err(CycleResult::VerifyFailed);
        };
        let bundle = match signed.verify_at(keys, now_unix_ms) {
            Ok(bundle) => bundle,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    authority_url = %self.base_url,
                    "config bundle failed verification; keeping the configuration already \
                     serving",
                );
                return Err(CycleResult::VerifyFailed);
            }
        };
        // The envelope declares how it expects to be applied. A
        // subscriber configured the other way would either drop keys the
        // author meant to keep or keep keys the author meant to drop,
        // both silently, so the disagreement is refused instead of
        // resolved by guessing.
        if bundle.mode != self.mode {
            tracing::error!(
                bundle_mode = %format_mode(bundle.mode),
                configured_mode = %format_mode(self.mode),
                revision = bundle.revision,
                "config bundle declares a different apply mode than this subscriber is \
                 configured for; refusing it",
            );
            return Err(CycleResult::VerifyFailed);
        }
        // Anti-replay, on a probe copy so a later failure cannot leave
        // the real cursor advanced past a bundle that never applied.
        let mut probe = self.cursor.clone();
        if let Err(error) = probe.advance(bundle) {
            tracing::error!(
                error = %error,
                applied_revision = self.cursor.revision,
                candidate_revision = bundle.revision,
                "config bundle refused by the anti-replay cursor",
            );
            return Err(CycleResult::VerifyFailed);
        }

        // Computed once, from the base this candidate is actually merged
        // over, and carried on the returned candidate: `merged.merged_yaml`
        // has no `source:` block of its own, so deriving an origin from it
        // later would misreport a git-sourced base as `BaseOrigin::Local`.
        let base_origin = base_origin_for(base_yaml);
        let merged = match merge_config(
            base_yaml,
            base_origin.clone(),
            &bundle.config_yaml,
            self.merge_mode,
        ) {
            Ok(outcome) => outcome,
            Err(MergeError::DeniedPaths(paths)) => {
                tracing::error!(
                    denied = %paths.join(", "),
                    revision = bundle.revision,
                    "config bundle claims paths this node owns; refusing the whole bundle",
                );
                return Err(CycleResult::DeniedPath);
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    revision = bundle.revision,
                    "config bundle could not be merged over the local document",
                );
                return Err(CycleResult::CompileFailed);
            }
        };
        // An unresolved `${VAR}` in a hand-edited config is a warning
        // because a person is watching the log. Nobody is watching this
        // one: an authority document naming a variable this node does not
        // export would take effect as the literal text `${VAR}`, fleet
        // wide, and quietly do the wrong thing.
        let unresolved = sbproxy_config::unresolved_env_references(&merged.merged_yaml);
        if !unresolved.is_empty() {
            tracing::error!(
                refs = %unresolved.join(", "),
                revision = bundle.revision,
                "config bundle leaves unresolved ${{VAR}} reference(s) after merging; refusing \
                 it rather than applying the literal text as a value",
            );
            return Err(CycleResult::CompileFailed);
        }

        Ok(MergedCandidate {
            merged_yaml: merged.merged_yaml,
            cursor: probe,
            revision: bundle.revision,
            signed: signed.clone(),
            base_origin,
        })
    }

    /// Apply a merged candidate through the shared reload transaction,
    /// then persist the cursor and the cache.
    ///
    /// Never blocks on the reload lock: a reload already in flight yields
    /// [`CycleResult::ReloadBusy`] and the candidate is dropped, because
    /// by the next interval the authority may well be serving a newer
    /// one.
    pub fn apply(&mut self, candidate: MergedCandidate) -> CycleResult {
        let outcome = match crate::server::try_reload_from_config_yaml(
            &self.config_path,
            &candidate.merged_yaml,
            "config_authority",
            candidate.base_origin.clone(),
        ) {
            Ok(TryReloadOutcome::Applied(outcome)) => outcome,
            Ok(TryReloadOutcome::Busy) => {
                tracing::info!(
                    revision = candidate.revision,
                    "another reload is in flight; skipping this config bundle cycle and \
                     retrying at the next interval",
                );
                return CycleResult::ReloadBusy;
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    revision = candidate.revision,
                    "config bundle was rejected by the reload transaction; the previously \
                     applied configuration keeps serving",
                );
                return CycleResult::CompileFailed;
            }
        };

        // A reload that published the pipeline while a subsystem stayed
        // on prior state is not a clean apply, and the two counters are
        // disjoint so neither hides the other.
        if outcome.is_fully_applied() {
            sbproxy_observe::metrics::record_config_bundle_applied();
            tracing::info!(revision = candidate.revision, "config bundle applied",);
        } else {
            sbproxy_observe::metrics::record_config_bundle_applied_degraded();
            tracing::error!(
                revision = candidate.revision,
                degraded = %outcome,
                "config bundle applied, but some subsystems did not; this node serves the \
                 authority's configuration with stale state for those subsystems",
            );
        }

        let received_at_unix_ms = now_unix_ms();
        // Recorded so the config-source refresh poller can put this same
        // overlay back on top of a newly resolved base document, which is
        // what keeps the documented resolution order true on every apply
        // rather than only on the authority's own cycles.
        record_applied_bundle(&candidate.signed.bundle);
        self.cursor = candidate.cursor;
        self.received_at_unix_ms = Some(received_at_unix_ms);
        self.persist(&candidate.signed, received_at_unix_ms);
        self.restore_drift_baseline();
        sbproxy_observe::metrics::set_config_bundle_revision(
            i64::try_from(candidate.revision).unwrap_or(i64::MAX),
        );
        self.publish_age();
        CycleResult::Applied
    }

    /// Persist the cursor and the cache after a successful apply.
    ///
    /// Failure here is logged and does not change the cycle's result:
    /// the pipeline is already live on this bundle, and reporting the
    /// apply as failed would be a lie. What it does cost is the next
    /// boot, which falls back to the previous cache or to the local
    /// document, so it is logged at error level.
    fn persist(&self, signed: &SignedConfigBundle, received_at_unix_ms: u64) {
        // The cursor first: a cursor without its cache refuses a replay
        // of an older bundle, while a cache without its cursor would
        // re-apply on the next boot from revision zero.
        self.persist_cursor();
        let cached = CachedBundle {
            received_at_unix_ms,
            bundle: signed.clone(),
        };
        if let Err(error) = cached.save(&self.cache_path) {
            tracing::error!(
                error = %error,
                path = %self.cache_path.display(),
                "config bundle could not be cached; this node will boot on its local \
                 document if the authority is unreachable at the time",
            );
        }
    }

    /// Persist the anti-replay cursor, logging rather than failing.
    ///
    /// A cursor that cannot be written costs the next restart, which may
    /// then accept a revision this process has already moved past, so the
    /// failure is loud even though nothing about the running node changes.
    fn persist_cursor(&self) {
        if let Err(error) = self.cursor.save(&self.cursor_path) {
            tracing::error!(
                error = %error,
                path = %self.cursor_path.display(),
                "config bundle cursor could not be persisted; a restart may accept a \
                 superseded revision",
            );
        }
    }

    /// Re-point the drift baseline at the local document.
    ///
    /// The reload transaction records the hash of whatever it applied,
    /// which for a subscriber is the merged document. `GET /admin/drift`
    /// compares the baseline against the file on disk, so leaving the
    /// merged hash there reports drift on every scrape forever, which
    /// trains an operator to ignore the signal. The question the endpoint
    /// answers is "has the local file changed since we read it?", so the
    /// baseline is the local file.
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
                "could not re-read the local document to restore the drift baseline; \
                 /admin/drift may report drift that is not there",
            ),
        }
    }

    /// Publish the age of the bundle currently serving, in seconds.
    ///
    /// Called every cycle, not only on apply, so the gauge climbs while
    /// the authority is unreachable.
    pub fn publish_age(&self) {
        if let Some(received_at_unix_ms) = self.received_at_unix_ms {
            let age = now_unix_ms().saturating_sub(received_at_unix_ms) as f64 / 1_000.0;
            sbproxy_observe::metrics::set_config_bundle_age_seconds(age);
        }
    }

    /// Log at error level once per cycle while the serving bundle is
    /// older than `max_staleness`.
    ///
    /// A running node keeps serving: the window is a boot-time gate, and
    /// turning it into a kill switch would take a fleet offline for a
    /// control-plane outage the data plane does not depend on.
    fn warn_if_stale(&self) {
        let Some(received_at_unix_ms) = self.received_at_unix_ms else {
            return;
        };
        let age = Duration::from_millis(now_unix_ms().saturating_sub(received_at_unix_ms));
        if age > self.max_staleness {
            tracing::error!(
                age_secs = age.as_secs(),
                max_staleness_secs = self.max_staleness.as_secs(),
                authority_url = %self.base_url,
                revision = self.cursor.revision,
                "config bundle is older than max_staleness; this node is still serving it, \
                 but it has not heard a usable answer from the authority in that long",
            );
        }
    }

    /// Read the document that every merge uses as its base.
    ///
    /// On a node whose local file declares a `source:` block, the base is
    /// the document that source resolved to, not the pointer file. The
    /// pointer file is a few lines naming a repository; merging a bundle
    /// over it would discard the whole configuration the repository
    /// carries.
    ///
    /// `None` is a refusal, not an empty base: merging over a document
    /// this node cannot read would silently discard whatever the operator
    /// put in it.
    fn read_base_document(&self) -> Option<String> {
        if let Some(base) = crate::config_source::current_resolved_base() {
            return Some(base.yaml.clone());
        }
        match std::fs::read_to_string(&self.config_path) {
            Ok(yaml) => Some(yaml),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    path = %self.config_path,
                    "config authority merge base could not be read; keeping the configuration \
                     already serving",
                );
                None
            }
        }
    }

    /// Decide what a missing or unusable bundle means at boot: refuse to
    /// start, or start on the local document with a loud warning.
    fn boot_without_bundle(&self, reason: &str) -> anyhow::Result<Option<String>> {
        if self.requires_bundle_on_boot {
            let replace_note = if self.mode == BundleMode::Replace {
                " Under `mode: replace` the local document is not a servable configuration, so \
                 there is nothing to fall back to."
            } else {
                ""
            };
            anyhow::bail!(
                "refusing to start: {reason}, and this node requires an authority config \
                 bundle before it can serve.{replace_note} Seed '{}' with a signed bundle from \
                 the authority, or clear `require_bundle_on_boot`",
                self.cache_path.display(),
            );
        }
        tracing::warn!(
            reason = %reason,
            authority_url = %self.base_url,
            cache_path = %self.cache_path.display(),
            "starting on the local document with no authority configuration applied; the \
             first poll cycle applies the authority's bundle once it answers",
        );
        Ok(None)
    }

    /// Fetch the current bundle from the authority.
    ///
    /// Sends the cursor as `If-None-Match` so an unchanged revision costs
    /// one conditional request and no compile. The response body is
    /// bounded while it is read.
    pub async fn fetch(&self) -> FetchResult {
        let url = format!("{}{}", self.base_url, BUNDLE_ENDPOINT_PATH);
        let mut request = self
            .client
            .get(&url)
            .header(SUBSCRIBER_ID_HEADER, self.subscriber_id.as_str());
        if let Some(etag) = cursor_etag(&self.cursor) {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(credential) = self.credential.as_deref() {
            request = request.bearer_auth(credential);
        }

        let mut response = match request.send().await {
            Ok(response) => response,
            Err(error) => return FetchResult::Unreachable(error.to_string()),
        };
        let status = response.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return FetchResult::NotModified;
        }
        if !status.is_success() {
            return FetchResult::Unreachable(format!("authority answered HTTP {status}"));
        }

        let mut body: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                        return FetchResult::Unreachable(format!(
                            "authority response exceeds the {MAX_RESPONSE_BYTES} byte limit"
                        ));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    return FetchResult::Unreachable(format!("read authority response: {error}"))
                }
            }
        }
        match SignedConfigBundle::from_json(&body) {
            Ok(signed) => FetchResult::Bundle(Box::new(signed)),
            Err(error) => FetchResult::Unreachable(format!("decode authority response: {error}")),
        }
    }

    /// Run one full cycle and record its result.
    ///
    /// Records `sbproxy_config_bundle_fetch_total{result}` exactly once,
    /// whichever way the cycle goes, so the counter's sum is the number
    /// of cycles attempted.
    pub async fn poll_once(&mut self) -> CycleResult {
        if self.keys.is_none() {
            // An operator who fixes the key file should not have to
            // restart the process for it to take effect.
            self.load_keys();
        }
        // Bound before the match rather than matched on directly: the
        // fetch future borrows `self`, and a match scrutinee's temporaries
        // live until the end of the match, which would put that borrow in
        // the way of the `&mut self` apply below.
        let fetched = self.fetch().await;
        // Re-read the trust file before verifying, so an added key ID takes
        // effect and a removed one stops working, both without a restart.
        // Only worth doing when there is something to verify.
        if matches!(fetched, FetchResult::Bundle(_)) {
            self.refresh_keys();
        }
        let result = match fetched {
            FetchResult::NotModified => CycleResult::NotModified,
            FetchResult::Unreachable(reason) => {
                tracing::error!(
                    reason = %reason,
                    authority_url = %self.base_url,
                    revision = self.cursor.revision,
                    "config authority is unreachable; continuing to serve the configuration \
                     already applied",
                );
                CycleResult::Unreachable
            }
            FetchResult::Bundle(signed) => {
                if self.holds_revision(&signed.bundle) {
                    CycleResult::NotModified
                } else if let Some(base_yaml) = self.read_base_document() {
                    let evaluated = self.evaluate(&signed, &base_yaml, now_unix_ms());
                    match evaluated {
                        Ok(candidate) => self.apply(candidate),
                        Err(result) => result,
                    }
                } else {
                    CycleResult::CompileFailed
                }
            }
        };
        sbproxy_observe::metrics::record_config_bundle_fetch(result.as_str());
        self.publish_age();
        self.warn_if_stale();
        result
    }

    /// Sleep until the next cycle is due.
    ///
    /// The jittered poll interval, cut short when a cluster peer announces a
    /// revision this node does not hold. Returns what woke it.
    ///
    /// Without a gossip accelerator this is one `sleep` and nothing else,
    /// which is exactly what a non-mesh subscriber does and the only thing it
    /// does.
    ///
    /// At most one wait per applied revision is shortened; see
    /// `gossip_pulled_at_cursor` for why.
    pub async fn await_next_cycle(&mut self) -> crate::config_gossip::CycleTrigger {
        use crate::config_gossip::CycleTrigger;

        let interval = jitter(self.poll_interval);
        let Some(watcher) = self.gossip.as_ref() else {
            tokio::time::sleep(interval).await;
            return CycleTrigger::Interval;
        };
        if self.gossip_pulled_at_cursor == Some(self.cursor.revision) {
            // A hint already bought this revision an early pull and the pull
            // did not move the cursor. Whatever the announcement is saying,
            // this node cannot act on it, so stop asking faster than the
            // interval and let the ordinary cycle keep retrying.
            tokio::time::sleep(interval).await;
            return CycleTrigger::Interval;
        }
        let trigger = watcher.wait(self.cursor.revision, interval).await;
        if trigger == CycleTrigger::Gossip {
            self.gossip_pulled_at_cursor = Some(self.cursor.revision);
            tracing::info!(
                trigger = trigger.as_str(),
                applied_revision = self.cursor.revision,
                "a cluster peer announced a config revision this node does not hold; polling the \
                 authority now rather than waiting out the interval",
            );
        }
        trigger
    }

    /// Poll forever, with jitter.
    ///
    /// The first sleep is a random fraction of a whole interval so a
    /// fleet that restarted together does not arrive at the authority in
    /// lockstep; every later sleep is the interval plus or minus the
    /// documented jitter fraction of it, or less when a cluster peer
    /// announces a newer revision first.
    pub async fn run(mut self) {
        // Resolved here rather than at construction: this runs from the
        // boot path's task spawn, after the process cluster is installed.
        // A watcher already attached by a caller wins, so a test can pin one.
        if self.gossip.is_none() {
            self.gossip = crate::config_gossip::ConfigGossipWatcher::process();
        }
        tracing::info!(
            authority_url = %self.base_url,
            subscriber_id = %self.subscriber_id,
            mode = %format_mode(self.mode),
            poll_interval_secs = self.poll_interval.as_secs(),
            revision = self.cursor.revision,
            gossip_accelerated = self.is_gossip_accelerated(),
            "config authority subscriber started",
        );
        tokio::time::sleep(self.poll_interval.mul_f64(random_unit())).await;
        loop {
            self.poll_once().await;
            self.await_next_cycle().await;
        }
    }

    /// Boot from the cached bundle, returning the document this node
    /// should serve.
    ///
    /// `Ok(Some(merged))` means a cached bundle was verified, merged over
    /// `local_yaml`, and proved to compile. `Ok(None)` means there is no
    /// usable bundle and the local document stands, which is only
    /// returned when the subscriber does not require one.
    ///
    /// Performs no network I/O. See the module docs for why.
    ///
    /// # Errors
    ///
    /// Returns an error when no usable bundle is available and
    /// `require_bundle_on_boot` is in effect (which `mode: replace`
    /// implies), because there is then nothing this node can serve.
    pub fn boot_from_cache(&mut self, local_yaml: &str) -> anyhow::Result<Option<String>> {
        let cached = match CachedBundle::load(&self.cache_path) {
            Ok(Some(cached)) => cached,
            Ok(None) => return self.boot_without_bundle("no cached config bundle exists"),
            Err(error) => {
                return self
                    .boot_without_bundle(&format!("the cached config bundle is unusable: {error}"))
            }
        };

        let now = now_unix_ms();
        let age = Duration::from_secs(cached.age_secs(now));
        if age > self.max_staleness {
            return self.boot_without_bundle(&format!(
                "the cached config bundle is {}s old, past the {}s max_staleness",
                age.as_secs(),
                self.max_staleness.as_secs()
            ));
        }

        let candidate = match self.evaluate(&cached.bundle, local_yaml, now) {
            Ok(candidate) => candidate,
            Err(result) => {
                return self.boot_without_bundle(&format!(
                    "the cached config bundle was refused ({})",
                    result.as_str()
                ))
            }
        };
        // Prove the merged document compiles before it becomes the boot
        // configuration, so a poisoned cache surfaces here rather than as
        // a confusing failure in the middle of pipeline construction.
        if let Err(error) = sbproxy_config::compile_config(&candidate.merged_yaml) {
            return self.boot_without_bundle(&format!(
                "the merged cached config bundle does not compile: {error:#}"
            ));
        }

        record_applied_bundle(&cached.bundle.bundle);
        self.cursor = candidate.cursor;
        self.received_at_unix_ms = Some(cached.received_at_unix_ms);
        // A cache seeded by hand may arrive without a cursor beside it, so
        // write one now rather than letting the next restart start over at
        // revision zero.
        self.persist_cursor();
        sbproxy_observe::metrics::record_config_bundle_applied();
        sbproxy_observe::metrics::set_config_bundle_revision(
            i64::try_from(candidate.revision).unwrap_or(i64::MAX),
        );
        self.publish_age();
        self.warn_if_stale();
        tracing::info!(
            revision = candidate.revision,
            age_secs = age.as_secs(),
            authority_url = %self.base_url,
            "booting on the cached authority config bundle",
        );
        Ok(Some(candidate.merged_yaml))
    }
}

/// Fold a cached authority bundle into the boot configuration.
///
/// Returns the document this node serves, its compiled form, and the
/// subscriber to spawn (`None` when no authority is configured). Called
/// before anything downstream reads the compiled config, because
/// listeners, TLS hostnames, and the request pipeline all have to
/// describe the configuration this node actually serves.
///
/// The drift baseline stays the local file's hash and is deliberately
/// computed by the caller before this runs; see
/// `ConfigSubscriber::restore_drift_baseline`.
///
/// # Errors
///
/// Returns an error when the subscriber cannot be built (an unresolvable
/// credential, an unreadable cursor), when a required bundle is missing
/// or unusable, or when the merged document fails to compile with a
/// required bundle in force.
pub fn fold_boot_bundle(
    config_path: &str,
    local_yaml: String,
    compiled: CompiledConfig,
) -> anyhow::Result<(String, CompiledConfig, Option<ConfigSubscriber>)> {
    // Cloned out before the `let ... else`, so the `else` arm can move
    // `compiled` into the return value without a live borrow of it.
    let upstream = compiled
        .server
        .config_authority
        .as_ref()
        .and_then(|authority| authority.upstream.as_ref())
        .cloned();
    let Some(upstream) = upstream else {
        return Ok((local_yaml, compiled, None));
    };
    let mut subscriber = ConfigSubscriber::new(config_path, &upstream)?;
    match subscriber.boot_from_cache(&local_yaml)? {
        Some(merged_yaml) => {
            // `boot_from_cache` already proved this compiles and threw the
            // result away, so that the refuse-or-warn decision lives in
            // one place. Compiling it again costs a few milliseconds once
            // per boot and keeps this function from having to make that
            // decision a second time.
            let merged_compiled = sbproxy_config::compile_config(&merged_yaml)?;
            Ok((merged_yaml, merged_compiled, Some(subscriber)))
        }
        None => Ok((local_yaml, compiled, Some(subscriber))),
    }
}

/// Start the poll loop on its own thread, if a subscriber is configured.
///
/// Pingora owns the process's main runtime and does not hand out a
/// handle, so the poller gets a dedicated runtime on a background thread,
/// the same shape the SIGHUP handler uses.
///
/// Two deliberate choices about that runtime. It is multi-threaded with
/// one worker rather than current-thread, because the reload transaction
/// reaches `tokio::task::block_in_place` when a pipeline lifecycle hook is
/// registered, and that call panics on a current-thread runtime. And the
/// apply step blocks its worker for the length of a pipeline rebuild,
/// which is fine precisely because this runtime exists for one task: no
/// request, no listener, and no other timer shares it.
pub fn spawn(subscriber: Option<ConfigSubscriber>) {
    let Some(subscriber) = subscriber else {
        return;
    };
    std::thread::Builder::new()
        .name("sbproxy-config-authority".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("sbproxy-config-authority-rt")
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "failed to build the config authority runtime; this node will not \
                         pull configuration updates",
                    );
                    return;
                }
            };
            runtime.block_on(subscriber.run());
        })
        .map_err(|error| {
            tracing::error!(
                error = %error,
                "failed to spawn the config authority thread; this node will not pull \
                 configuration updates",
            );
        })
        .ok();
}

/// The provenance tag for a merge base document.
///
/// `Git` only when the base actually is the document a `source:` block
/// resolved to, compared by content rather than assumed: the tag ends up
/// in the provenance map an operator reads to answer "who set this
/// value", and a tag that names a repository the value did not come from
/// is worse than no tag at all.
fn base_origin_for(base_yaml: &str) -> BaseOrigin {
    match crate::config_source::current_resolved_base() {
        Some(base) if base.yaml == base_yaml => base.origin.clone(),
        _ => BaseOrigin::Local,
    }
}

/// Cursor file that accompanies one cache file.
fn cursor_path_for(cache_path: &Path) -> PathBuf {
    let mut name = cache_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "config-bundle.json".to_string());
    name.push_str(CURSOR_FILE_SUFFIX);
    cache_path.with_file_name(name)
}

/// Resolve the credential reference into a bearer token.
///
/// Routes through the process secret resolver when one is installed, so
/// `secret://`, `vault://`, `file:`, and `${VAR}` behave exactly as they
/// do everywhere else in the config. `env:NAME` is normalized to the
/// resolver's `${NAME}` form so the documented spelling works.
///
/// Without a resolver (`sbproxy validate`, unit tests, a serve run whose
/// config declares no `proxy.secrets` backends) the environment and file
/// forms are handled here and a provider URI is a hard error. The
/// reference text is never used as the token: a literal `secret://...`
/// arriving at the authority as a bearer credential is the failure this
/// avoids.
fn resolve_credential(reference: &str) -> anyhow::Result<String> {
    crate::config_source::resolve_secret_reference(
        reference,
        "proxy.config_authority.upstream.credential",
    )
}

/// Stable display name for an apply mode, for logs.
fn format_mode(mode: BundleMode) -> &'static str {
    match mode {
        BundleMode::Overlay => "overlay",
        BundleMode::Replace => "replace",
    }
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

/// Host wall clock in unix milliseconds, saturating rather than panicking
/// on a clock set before the epoch.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_etag_carries_revision_and_digest() {
        assert_eq!(cursor_etag(&ConfigBundleCursor::default()), None);
        let cursor = ConfigBundleCursor::new(7, format!("sha256:{}", "a".repeat(64)));
        let etag = cursor_etag(&cursor).expect("etag for an applied cursor");
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
        assert!(etag.contains("7-sha256:"), "{etag}");
    }

    #[test]
    fn cursor_file_sits_beside_the_cache() {
        assert_eq!(
            cursor_path_for(Path::new("/var/lib/sbproxy/config-bundle.json")),
            PathBuf::from("/var/lib/sbproxy/config-bundle.json.cursor"),
        );
    }

    #[test]
    fn cycle_result_labels_are_the_documented_set() {
        let labels: Vec<&str> = [
            CycleResult::Applied,
            CycleResult::NotModified,
            CycleResult::Unreachable,
            CycleResult::VerifyFailed,
            CycleResult::CompileFailed,
            CycleResult::DeniedPath,
            CycleResult::ReloadBusy,
        ]
        .iter()
        .map(|result| result.as_str())
        .collect();
        assert_eq!(
            labels,
            vec![
                "ok",
                "not_modified",
                "unreachable",
                "verify_failed",
                "compile_failed",
                "denied_path",
                "reload_busy",
            ],
        );
    }

    #[test]
    fn jitter_stays_inside_the_documented_band() {
        let interval = Duration::from_secs(30);
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
    fn cached_bundle_age_floors_at_zero() {
        let signed = SignedConfigBundle {
            schema_version: sbproxy_config::CONFIG_BUNDLE_SCHEMA_VERSION,
            bundle: ConfigBundle::new(
                "authority",
                1,
                BundleMode::Overlay,
                "proxy: {}\n",
                1_000,
                None,
            )
            .expect("bundle"),
            key_id: "k".to_string(),
            algorithm: sbproxy_config::BundleAlgorithm::Ed25519,
            signature: "AA==".to_string(),
        };
        let cached = CachedBundle {
            received_at_unix_ms: 10_000,
            bundle: signed,
        };
        assert_eq!(cached.age_secs(70_000), 60);
        // A clock that stepped backwards reports fresh, not negative.
        assert_eq!(cached.age_secs(0), 0);
    }

    #[test]
    fn env_credential_spelling_resolves_through_the_environment() {
        // Deliberately not `${VAR}`: the documented config spelling is
        // `env:NAME`, and it has to reach the same place.
        let env = crate::test_env::EnvVarGuard::set(&[(
            "SB_TEST_CONFIG_AUTHORITY_TOKEN",
            Some("token-value"),
        )]);
        assert_eq!(
            resolve_credential("env:SB_TEST_CONFIG_AUTHORITY_TOKEN").expect("resolves"),
            "token-value",
        );
        assert_eq!(
            resolve_credential("${SB_TEST_CONFIG_AUTHORITY_TOKEN}").expect("resolves"),
            "token-value",
        );
        // Dropping the guard restores the variable to its previous
        // (unset) state, so the miss branch is exercised too.
        drop(env);
        assert!(resolve_credential("env:SB_TEST_CONFIG_AUTHORITY_TOKEN").is_err());
    }

    /// One ed25519 verifying-key file entry per requested id, all sharing a
    /// key. The ids are what matter here, not the key material.
    fn write_key_file(path: &Path, ids: &[&str]) {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let entries: Vec<String> = ids
            .iter()
            .map(|id| format!("  \"{id}\": {{ \"algorithm\": \"ed25519\", \"key\": \"{key}\" }}"))
            .collect();
        std::fs::write(path, format!("{{\n{}\n}}\n", entries.join(",\n"))).expect("write keys");
    }

    fn subscriber_for_keys(dir: &Path, keys_file: &Path) -> ConfigSubscriber {
        let upstream: ConfigAuthorityUpstreamConfig = serde_yaml::from_str(&format!(
            "url: http://127.0.0.1:1\n\
             mode: overlay\n\
             subscriber_id: edge-01\n\
             verifying_keys_file: {keys}\n\
             cache_path: {cache}\n\
             allow_insecure_http: true\n",
            keys = keys_file.display(),
            cache = dir.join("cache.json").display(),
        ))
        .expect("upstream config parses");
        ConfigSubscriber::new(&dir.join("sb.yml").display().to_string(), &upstream)
            .expect("subscriber constructs")
    }

    /// The verifying-key file is the trust anchor, not a snapshot of it taken
    /// at boot.
    ///
    /// Both halves of this were broken until a two-process rotation drill
    /// caught them. Keys were read once at startup and re-read only if the
    /// file had failed to load entirely, so adding an id never started
    /// verifying and removing one never stopped. The removal is the half that
    /// matters: a key revoked because it leaked kept working until every node
    /// had been restarted.
    ///
    /// Pinned here, in the required test lane, because the drill that found it
    /// is deliberately outside CI.
    #[test]
    fn refreshing_keys_picks_up_an_added_id_and_drops_a_removed_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys_file = dir.path().join("keys.json");

        write_key_file(&keys_file, &["key-1"]);
        let mut subscriber = subscriber_for_keys(dir.path(), &keys_file);
        assert_eq!(
            subscriber.keys.as_ref().map(VerifyingKeySet::len),
            Some(1),
            "the constructor loads the file once"
        );

        // Rotation, first half: a new id is trusted without a restart.
        write_key_file(&keys_file, &["key-1", "key-2"]);
        subscriber.refresh_keys();
        let keys = subscriber.keys.as_ref().expect("keys loaded");
        assert_eq!(keys.len(), 2);
        assert!(keys.get("key-2").is_some(), "the added id must be trusted");

        // Rotation, second half: retiring an id stops it verifying, also
        // without a restart. This is the security-relevant direction.
        write_key_file(&keys_file, &["key-2"]);
        subscriber.refresh_keys();
        let keys = subscriber.keys.as_ref().expect("keys loaded");
        assert_eq!(keys.len(), 1);
        assert!(
            keys.get("key-1").is_none(),
            "a retired id must stop verifying immediately, not at the next restart"
        );
    }

    /// A file being rewritten is briefly unreadable, and treating that instant
    /// as "trust nothing" would turn an ordinary rotation into a window where
    /// every bundle is refused.
    #[test]
    fn a_failed_key_reread_keeps_the_keys_already_loaded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys_file = dir.path().join("keys.json");
        write_key_file(&keys_file, &["key-1"]);
        let mut subscriber = subscriber_for_keys(dir.path(), &keys_file);

        std::fs::remove_file(&keys_file).expect("remove keys file");
        subscriber.refresh_keys();
        assert_eq!(
            subscriber.keys.as_ref().map(VerifyingKeySet::len),
            Some(1),
            "an unreadable file must not drop the trusted set"
        );

        // And a file that comes back is picked up on the next cycle.
        write_key_file(&keys_file, &["key-1", "key-3"]);
        subscriber.refresh_keys();
        assert_eq!(subscriber.keys.as_ref().map(VerifyingKeySet::len), Some(2));
    }
}
