//! Pipeline reload and process lifecycle: config hot-reload
//! (`reload_from_config_path`), the file watcher, the SIGHUP handler,
//! graceful-shutdown config, the `run` entry point, and ARDP discovery.
//!
//! Extracted from `server.rs`. Behavior-preserving move;
//! `use super::*` re-imports the parent module's items. The public
//! `run`, `GraceConfig`, `reload_from_config_path`, and
//! `install_sighup_handler` stay public and are re-exported by the
//! parent so existing paths (incl. the binary's) are unchanged.

use super::*;

static CONFIG_RELOAD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Fingerprint of the effective `proxy.secrets:` block this process
/// owns, captured the first time a config is loaded.
///
/// The secret resolver behind `proxy.secrets:` is installed into a
/// set-once slot in `sbproxy-vault` at binary boot, so a later reload
/// that changes the block cannot take effect. Recording the fingerprint
/// lets the reload path reject the change loudly instead of accepting a
/// config whose secret backends will never be honoured.
static PROCESS_SECRETS_FINGERPRINT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// One subsystem that did not apply during a reload that nonetheless
/// succeeded.
///
/// Every variant corresponds to a failure the reload path deliberately
/// tolerates: aborting on any of them would let one broken subsystem
/// pin an operator on an old config. Surfacing them here means an
/// automated config authority can tell "applied" from "applied, but
/// this part of the node is stale".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DegradedSubsystem {
    /// The AI provider catalog could not be rebuilt; the node keeps
    /// serving the catalog it had before the reload.
    AiProviderRegistry,
    /// The dynamic key plane could not be reconciled from
    /// `key_management:`; the previously installed plane stays live.
    KeyPlane,
    /// One or more `listings/*.yaml` entries failed to load; the
    /// pipeline went live without them.
    Listings,
    /// Compatibility label for older reload responses. Atomic candidate
    /// publication now rejects lifecycle failures before this can be emitted.
    PipelineLifecycleHook,
    /// The telemetry sink dispatcher could not be installed; log and
    /// event export falls back to the legacy tracing subscriber.
    SinkDispatcher,
}

impl DegradedSubsystem {
    /// Stable machine-readable identifier, suitable for a JSON body or
    /// a structured log field. Never changes for a given variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AiProviderRegistry => "ai_provider_registry",
            Self::KeyPlane => "key_plane",
            Self::Listings => "listings",
            Self::PipelineLifecycleHook => "pipeline_lifecycle_hook",
            Self::SinkDispatcher => "sink_dispatcher",
        }
    }
}

impl std::fmt::Display for DegradedSubsystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::AiProviderRegistry => "AI provider registry",
            Self::KeyPlane => "key plane",
            Self::Listings => "listings",
            Self::PipelineLifecycleHook => "pipeline lifecycle hook",
            Self::SinkDispatcher => "sink dispatcher",
        };
        formatter.write_str(text)
    }
}

/// What a reload actually accomplished.
///
/// A reload that returns `Ok` has published the new pipeline. It has
/// not necessarily applied every subsystem: the ones listed by
/// [`Self::degraded()`] failed in a way the reload path tolerates on
/// purpose. Check [`Self::is_fully_applied`] before reporting a reload
/// as clean.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Subsystems that failed to apply while the reload still succeeded.
    degraded: Vec<DegradedSubsystem>,
}

impl ReloadOutcome {
    /// Record one subsystem that failed to apply. Repeated records of
    /// the same subsystem collapse into one entry.
    fn degrade(&mut self, subsystem: DegradedSubsystem) {
        if !self.degraded.contains(&subsystem) {
            self.degraded.push(subsystem);
        }
    }

    /// Whether every subsystem this reload touched applied cleanly.
    pub fn is_fully_applied(&self) -> bool {
        self.degraded.is_empty()
    }

    /// The subsystems that failed to apply, in the order the reload
    /// reached them. Empty when [`Self::is_fully_applied`] is true.
    pub fn degraded(&self) -> &[DegradedSubsystem] {
        &self.degraded
    }
}

impl std::fmt::Display for ReloadOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.degraded.is_empty() {
            return formatter.write_str("fully applied");
        }
        for (index, subsystem) in self.degraded.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{subsystem}")?;
        }
        Ok(())
    }
}

/// Fingerprint the effective `proxy.secrets:` block.
///
/// An absent block fingerprints differently from any present one, so
/// adding or removing the block is itself a change. The serialization
/// goes through `serde_json::Value`, whose object representation is
/// key-ordered, so a `HashMap` field cannot make the fingerprint vary
/// between two runs over identical config.
fn secrets_fingerprint(secrets: Option<&sbproxy_config::types::SecretsConfig>) -> String {
    let value = match secrets {
        Some(cfg) => serde_json::to_value(cfg).unwrap_or(serde_json::Value::Null),
        None => serde_json::Value::Null,
    };
    let serialized = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    crate::identity::config_revision(serialized.as_bytes())
}

/// Record the `proxy.secrets:` block this process is going to own.
///
/// Called from `run` with the boot config. A second call is ignored, so
/// a process that boots normally pins the boot-time block and a process
/// that only ever reloads (tests, embedders) pins whatever it saw
/// first.
fn record_process_secrets_fingerprint(secrets: Option<&sbproxy_config::types::SecretsConfig>) {
    let _ = PROCESS_SECRETS_FINGERPRINT.set(secrets_fingerprint(secrets));
}

/// Reject a reload that changes the process-owned `proxy.secrets:`
/// block.
///
/// The secret resolver assembled from that block is installed into a
/// set-once slot (`sbproxy_vault::install_process_resolver`) at binary
/// boot and nothing re-installs it. Accepting a changed block would
/// leave the node resolving `secret://` references against the old
/// backends and would only surface later, as a confusing
/// handler-construction failure the first time a config referenced a
/// backend that "exists" in the YAML. Rejecting here keeps the
/// failure at the reload, where the operator can act on it.
///
/// Since WOR-2327 the same reasoning covers `rotation:` for the same
/// mechanical reason: `install_process_rotation` is the identical
/// set-once shape, so a reload that changed `re_resolve_interval_secs`
/// would be accepted and then ignored. That message named rotation
/// before rotation did anything, which was accidentally correct; it is
/// now correct on purpose.
///
/// Mirrors `cluster::reconcile_process_cluster`, which rejects
/// restart-only cluster changes the same way.
///
/// The message names only what a config can still carry. The legacy
/// `backend`, `fallback`, and `hashicorp` keys are refused by
/// `compile_config`, so a config holding one never reaches a reload and
/// they cannot be what changed.
fn reconcile_process_secrets(
    secrets: Option<&sbproxy_config::types::SecretsConfig>,
) -> anyhow::Result<()> {
    let candidate = secrets_fingerprint(secrets);
    let installed = PROCESS_SECRETS_FINGERPRINT.get_or_init(|| candidate.clone());
    if *installed == candidate {
        return Ok(());
    }
    anyhow::bail!(
        "proxy.secrets named backends, rotation, or the inline map changed; restart sbproxy to \
         apply the new process-owned secret configuration"
    )
}

/// Fingerprints of the three blocks this process owns from boot.
///
/// `agent_registry` opens a redb file and starts a refresh loop,
/// `notifications` opens a redb file and starts a delivery worker, and
/// `request_events` installs a process-global sink through a set-once slot.
/// None of the three has a rebuild path, so a reload that changed one would
/// be accepted and then ignored, which is the failure
/// `reconcile_process_secrets` already exists to prevent next door.
static PROCESS_BOOT_ONLY_FINGERPRINTS: std::sync::OnceLock<[String; 3]> =
    std::sync::OnceLock::new();

/// The three blocks, fingerprinted, in a fixed order.
fn boot_only_fingerprints(
    server: &sbproxy_config::types::ProxyServerConfig,
    request_events: Option<&sbproxy_config::types::RequestEventsConfig>,
) -> [String; 3] {
    let of = |value: serde_json::Value| {
        let serialized = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
        crate::identity::config_revision(serialized.as_bytes())
    };
    [
        of(serde_json::to_value(&server.agent_registry).unwrap_or(serde_json::Value::Null)),
        of(serde_json::to_value(&server.notifications).unwrap_or(serde_json::Value::Null)),
        of(serde_json::to_value(request_events).unwrap_or(serde_json::Value::Null)),
    ]
}

/// Record the boot-time shape of the three boot-only blocks.
fn record_boot_only_fingerprints(
    server: &sbproxy_config::types::ProxyServerConfig,
    request_events: Option<&sbproxy_config::types::RequestEventsConfig>,
) {
    let _ = PROCESS_BOOT_ONLY_FINGERPRINTS.set(boot_only_fingerprints(server, request_events));
}

/// Refuse a reload that changes a block this process can only apply at
/// boot, naming the key that changed.
///
/// Refusing is the lesser failure. An accepted reload that silently does
/// nothing is how an operator ends up reading `/admin/config` serving the
/// new `bootstrap_keys` while every refresh keeps answering `unknown_key`,
/// with nothing anywhere connecting the two.
fn reconcile_boot_only_blocks(
    server: &sbproxy_config::types::ProxyServerConfig,
    request_events: Option<&sbproxy_config::types::RequestEventsConfig>,
) -> anyhow::Result<()> {
    let candidate = boot_only_fingerprints(server, request_events);
    let installed = PROCESS_BOOT_ONLY_FINGERPRINTS.get_or_init(|| candidate.clone());
    compare_boot_only_fingerprints(installed, &candidate)
}

/// The comparison and the message, without the process-global.
///
/// Split out so a test can drive the refusal itself rather than only the
/// fingerprints feeding it: a `OnceLock` can be set once per process, so a
/// test against `reconcile_boot_only_blocks` proves whichever case it
/// happens to run first and nothing else.
fn compare_boot_only_fingerprints(
    installed: &[String; 3],
    candidate: &[String; 3],
) -> anyhow::Result<()> {
    if installed == candidate {
        return Ok(());
    }
    let keys = [
        "proxy.agent_registry",
        "proxy.notifications",
        "request_events",
    ];
    let changed: Vec<&str> = keys
        .iter()
        .zip(installed.iter().zip(candidate.iter()))
        .filter(|(_, (before, after))| before != after)
        .map(|(key, _)| *key)
        .collect();
    anyhow::bail!(
        "{} changed; restart sbproxy to apply it. That block opens its own store or installs a \
         process-global sink at boot and has no rebuild path, so accepting the reload would \
         leave the node running the old one",
        changed.join(" and ")
    )
}

/// Restores the previously live AI provider catalog when a reload that
/// already installed a new one fails before it publishes.
///
/// The catalog has to be installed before
/// [`CompiledPipeline::from_config`] runs, because AI handler
/// construction resolves provider names against the live registry. That
/// makes it the one process global the reload cannot defer to commit
/// time, so it gets an explicit undo instead. Dropping an armed guard
/// puts the old catalog back; [`Self::disarm`] at the commit point
/// keeps the new one.
struct ProviderRegistryRollback {
    /// The catalog to restore, or `None` once the reload has committed.
    snapshot: Option<sbproxy_ai::ProviderRegistrySnapshot>,
}

impl ProviderRegistryRollback {
    fn new(snapshot: sbproxy_ai::ProviderRegistrySnapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
        }
    }

    /// Keep the newly installed catalog: the reload reached its commit
    /// point and every fallible step behind it succeeded.
    fn disarm(&mut self) {
        self.snapshot = None;
    }
}

impl Drop for ProviderRegistryRollback {
    fn drop(&mut self) {
        if let Some(snapshot) = self.snapshot.take() {
            sbproxy_ai::restore_provider_registry(snapshot);
            tracing::warn!(
                "reload failed after the AI provider catalog was installed; \
                 restored the catalog that was live before the reload",
            );
        }
    }
}

/// Start a file watcher that reloads the config on changes.
///
/// Spawns a background thread that watches the config file for modifications.
/// On change, it re-reads, re-compiles, and hot-swaps the pipeline via
/// [`reload::load_pipeline`]. Parse or compile errors are logged but do not
/// crash the proxy - the previous valid config continues to serve traffic.
/// Reload the proxy pipeline from a YAML config file at `config_path`.
///
/// The single source of truth for reload semantics shared by:
///
/// - The notify-based file watcher (auto-reload on `sb.yml` change).
/// - The SIGHUP signal handler (operator-driven reload
///   via `kill -HUP $(pgrep sbproxy)`).
///
/// Reads the file, runs `compile_config` (which also drives the
/// features.* migration), constructs a fresh
/// [`CompiledPipeline`], invokes the pipeline lifecycle hook, and
/// atomically swaps the live pipeline. Returns a
/// [`ReloadOutcome`] on success; logs and returns `Err` on any step's
/// failure so the caller can decide whether to retry.
///
/// An `Err` means nothing was applied: the node keeps serving the
/// pipeline and the process globals it had before the call. An `Ok`
/// whose [`ReloadOutcome::is_fully_applied`] is false means the
/// pipeline went live but the subsystems it names did not.
///
/// Idempotent: invoking back-to-back yields the same effect as one
/// invocation. Safe to call from any thread; the global pipeline
/// `ArcSwap` handles the publish.
///
/// The `config_audit` `source` this stamps (WOR-2486) is the single
/// string `"file_watcher"` for both callers named above, notify-based
/// and SIGHUP alike, not two distinct values. That is deliberate rather
/// than an oversight: both reload the same operator-managed local file,
/// the notify path on a filesystem event and the SIGHUP path on a
/// signal, and a record that says "the local file was reloaded" is the
/// fact an auditor wants either way. Splitting the two would mean
/// threading a `source` parameter through this function's ~10 call
/// sites (both reload triggers plus the existing reload tests in
/// `server/tests.rs`) for a distinction the record's other fields
/// (timestamp, origin delta, before/after revision) already let an
/// operator correlate against their own signal-delivery or file-change
/// history if they need to tell the two apart.
pub fn reload_from_config_path(config_path: &str) -> anyhow::Result<ReloadOutcome> {
    let result = reload_from_config_path_unaudited(config_path);
    if !matches!(&result, Err(error) if is_suspended_reload(error)) {
        audit_reload_outcome("file_watcher", config_path, &result);
    }
    result
}

/// As [`reload_from_config_path`], without the `file_watcher` audit
/// record, for a caller that writes its own.
///
/// `DELETE /admin/config/fallback` applies the config file as part of
/// clearing the pin, and that is an operator action with an actor
/// attached, not a filesystem event. Letting it inherit this function's
/// record wrote *two* entries for one apply, one of them naming the
/// wrong trigger and carrying no actor. The admin handler calls this and
/// stamps its own `api` record instead (verification residual R3).
///
/// # Errors
///
/// As [`reload_from_config_path`].
pub fn reload_from_config_path_unaudited(config_path: &str) -> anyhow::Result<ReloadOutcome> {
    if let Some(refusal) = refuse_suspended_local_reload(config_path) {
        return Err(refusal);
    }
    // WOR-1101: stamp every reload outcome so operators can alert on
    // failures and watch the reload cadence from metrics, not just
    // logs. The inner function carries the original early-return body.
    let result = reload_from_config_path_inner(config_path);
    match &result {
        Ok(_) => sbproxy_observe::metrics::record_config_reload("success"),
        Err(_) => sbproxy_observe::metrics::record_config_reload("failure"),
    }
    result
}

/// Whether one reload error is the deliberate pinned-node suspension
/// rather than a refused candidate.
///
/// Callers use it to keep a suspension out of the channels a fault
/// belongs in: the ERROR log, and the `config_audit` rejection record.
#[must_use]
pub(crate) fn is_suspended_reload(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains(SUSPENDED_RELOAD_MARKER)
}

/// The phrase a suspended-reload refusal carries, so callers can tell it
/// from a refused candidate without a second error type crossing the
/// `anyhow` boundary this function's callers already live on.
const SUSPENDED_RELOAD_MARKER: &str = "pinned to a configuration its boot fallback restored";

/// Refuse a local reload while this node is pinned to a configuration its
/// boot fallback restored, counting it on its own label.
///
/// Called from both audited entry points rather than only from the
/// watcher. The transaction's own guard in [`reload_from_config_yaml`] is
/// still the enforcer and still refuses whatever reaches it, but the
/// *accounting* has to sit where the counter is stamped: with the guard
/// alone, a SIGHUP on a pinned node landed on
/// `sbproxy_config_reload_total{result="failure"}` and logged at ERROR,
/// and `logrotate` postrotate hooks send SIGHUP on a schedule, so a
/// pinned node quietly climbed the counter operators alert on. A pinned
/// node is the state the fallback is supposed to leave it in; it must not
/// be indistinguishable from a broken config (re-review, new Major 2).
///
/// Returns `None`, and costs one relaxed atomic load, on every node that
/// is not pinned, which is every node almost always.
fn refuse_suspended_local_reload(config_path: &str) -> Option<anyhow::Error> {
    if !crate::config_boot::reload_suspended("file_watcher") {
        return None;
    }
    sbproxy_observe::metrics::record_config_reload("suspended");
    // A `config_audit` record too. Returning before the transaction used
    // to mean a suspended reload produced none at all, where before
    // round 2 a SIGHUP refused on a pinned node produced one carrying
    // its reason: a silent gap in a WOR-2486 surface. It is written with
    // the suspension as its reason rather than as a rejection of the
    // document, because the document was never examined (verification
    // residual R7).
    sbproxy_observe::ConfigAuditEntry::new("file_watcher", Vec::new(), Vec::new(), Vec::new())
        .with_rejection_reason(format!(
            "not applied: this node is {SUSPENDED_RELOAD_MARKER} from the revision ring, so \
             local reloads are suspended"
        ))
        .emit();
    tracing::info!(
        path = %config_path,
        "a local config reload was skipped: this node is pinned to a configuration its boot \
         fallback restored from the revision ring. clear the pin with \
         DELETE /admin/config/fallback to apply the file",
    );
    Some(anyhow::anyhow!(
        "this node is {SUSPENDED_RELOAD_MARKER} from the revision ring; local config reloads \
         (the file watcher and SIGHUP) are suspended until an operator clears the pin with \
         DELETE /admin/config/fallback"
    ))
}

/// As [`reload_from_config_path`], for a caller that has already read the
/// file and needs the reload to use those exact bytes.
///
/// Carries the same reload metric, which is the reason this exists rather
/// than calling [`reload_from_config_yaml`] directly: a reload that skipped
/// the counter would leave the cadence operators alert on under-reporting
/// every file-watch reload.
fn reload_from_config_text(config_path: &str, yaml: &str) -> anyhow::Result<ReloadOutcome> {
    if let Some(refusal) = refuse_suspended_local_reload(config_path) {
        return Err(refusal);
    }
    let result = reload_from_config_yaml(config_path, yaml);
    match &result {
        Ok(_) => sbproxy_observe::metrics::record_config_reload("success"),
        Err(_) => sbproxy_observe::metrics::record_config_reload("failure"),
    }
    audit_reload_outcome("file_watcher", config_path, &result);
    result
}

/// Apply a document read back out of the config revision ring, through
/// the ordinary reload transaction (WOR-2460).
///
/// A rollback is an ordinary candidate. It resolves, it compiles, it
/// publishes through the same prepare-and-publish body every other
/// reload goes through, and the soak the transaction arms judges it like
/// any other revision. Treating a rollback as a privileged path that
/// skips validation is how rolling back becomes the incident: the stored
/// document published cleanly once, but "once" was possibly before an
/// upgrade tightened a validation rule, and the document that will not
/// construct on this binary has to be refused with the pipeline pointer
/// untouched rather than half-applied. `AuthorityStore::rollback` takes
/// the same position for the same reason on the publisher side.
///
/// Not [`reload_from_config_yaml`], for three reasons, each of which is
/// a behavior difference rather than a naming one:
///
/// * The **suspension guard** there refuses a pinned node's local
///   reloads. A rollback is an explicit act (an operator asking, or the
///   soak's own auto-revert acting on evidence), the same class as
///   `POST /admin/reload`, which
///   [`crate::config_boot::reload_suspended`] already keeps live. A
///   pinned node is exactly where a rollback is most likely to be needed.
/// * The **audit source** is `rollback`, not `file_watcher`. Blaming the
///   watcher for the single most consequential operator action in this
///   feature is the defect that verification residual R3 fixed next
///   door.
/// * The **ring actor** is the caller's, so `sbproxy config history`
///   shows who rolled the node back rather than a generic label.
///
/// `ring_actor` is `rollback:<operator>` for the admin route and
/// `auto_revert` for the soak's own revert. It reaches the ring entry
/// this apply appends; the stable `rollback` label the audit record
/// carries is separate, so the audit vocabulary stays closed while the
/// history column stays specific.
///
/// # Errors
///
/// Returns `Err` under exactly the conditions
/// [`reload_from_config_yaml`] does: an unresolvable `source:` pointer
/// (which a stored blob never carries, since the ring stores
/// post-resolution text), a document that does not compile on this
/// binary, or a pipeline that does not construct. The running pipeline
/// keeps serving in every one of those cases.
pub(crate) fn reload_from_stored_revision(
    config_path: &str,
    yaml: &str,
    ring_actor: &str,
) -> anyhow::Result<ReloadOutcome> {
    let result = {
        let _reload_guard = CONFIG_RELOAD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reload_from_config_yaml_locked(config_path, yaml, ring_actor, None)
    };
    match &result {
        Ok(_) => sbproxy_observe::metrics::record_config_reload("success"),
        Err(_) => sbproxy_observe::metrics::record_config_reload("failure"),
    }
    audit_reload_outcome("rollback", config_path, &result);
    if let Err(error) = &result {
        // The refused candidate is kept like any other (WOR-2462), and
        // this is the one an operator most needs to find later: a
        // rollback target that no longer constructs is a revision the
        // ring will keep offering and the node will keep refusing, and
        // the stored refusal is what says why without reproducing it.
        //
        // `CompileFailed` covers all three ways this can fail by its own
        // definition ("did not compile, could not be constructed, or
        // still carried an unresolved `${VAR}` reference"), and the
        // three are not separable here anyway: the reload transaction
        // returns one `anyhow::Error`. Which of them it was is in the
        // stored `detail`, and `stage: "rollback"` already separates
        // these from a subscriber cycle's refusals.
        crate::config_subscriber::record_refusal(
            yaml,
            &crate::config_subscriber::CycleRefusal::new(
                crate::config_subscriber::CycleResult::CompileFailed,
                crate::path_redact::sanitise_path_in_error(
                    &format!("{error:#}"),
                    std::path::Path::new(config_path),
                ),
            ),
            "rollback",
            sbproxy_config::BaseOrigin::Local,
        );
    }
    result
}

/// Emit a `config_audit` record for a reload outcome on a non-admin path
/// (WOR-2486): the file watcher, SIGHUP, the remote config-source
/// refresh poller, the config-authority bundle apply, and the
/// extension-bundle refresh poller.
///
/// The admin API records its own entry at its own call site (`admin.rs`),
/// carrying the actor and revision pair only that HTTP layer has; this
/// covers every other path, which had none for either outcome, and adds
/// the admin path's missing rejection case too. `source` is the same
/// vocabulary [`sbproxy_observe::ConfigAuditEntry::source`] already
/// documents (`"file_watcher"`, `"api"`, ...), extended with
/// `"config_authority"`, `"config_refresh_poller"`, and
/// `"extension_refresh"` for the paths that had no entry at all before
/// this.
///
/// `config_path` is the path this specific call was reloading, scrubbed
/// out of the error text the same way the admin API's HTTP response
/// already is (WOR-2486 fix round 1, I5): `{error:#}` routinely embeds
/// the full path it failed to read or resolve, and that path is this
/// node's local filesystem layout. `with_rejection_reason` additionally
/// bounds the result to 512 bytes, the same ceiling the decision-audit
/// `reason` field uses.
///
/// What this does **not** do: scrub arbitrary config *values*. A
/// compile error can legitimately echo a snippet of the offending YAML
/// (an invalid CEL expression, an unknown key) in its message, and nothing
/// here distinguishes that from ordinary error prose. See
/// [`sbproxy_observe::audit::ConfigAuditEntry::with_rejection_reason`]'s
/// own doc for the contract this actually keeps.
fn audit_reload_outcome(source: &str, config_path: &str, result: &anyhow::Result<ReloadOutcome>) {
    match result {
        Ok(_) => {
            sbproxy_observe::ConfigAuditEntry::new(source, Vec::new(), Vec::new(), Vec::new())
                .emit();
        }
        Err(error) => {
            let reason = crate::path_redact::sanitise_path_in_error(
                &format!("{error:#}"),
                std::path::Path::new(config_path),
            );
            sbproxy_observe::ConfigAuditEntry::new(source, Vec::new(), Vec::new(), Vec::new())
                .with_rejection_reason(reason)
                .emit();
        }
    }
}

/// WOR-2626: say once per opened sink file what this build can
/// actually enforce on its mode.
///
/// On Unix that is `0o600` and the line is startup evidence an operator
/// can point at. On a target with no POSIX permission bits the file
/// inherits the containing directory's ACL instead, which is a real
/// difference in what the deployment protects and belongs in the log
/// rather than only in the documentation. The path is not repeated
/// here: it is operator configuration and the failure paths below
/// already carry it.
fn log_sink_file_protection(sink: &'static str) {
    use sbproxy_util::secure_fs::{enforcement, ModeEnforcement};

    match enforcement() {
        ModeEnforcement::Posix { file_mode, .. } => {
            let mode = format!("{file_mode:04o}");
            tracing::info!(sink, mode = %mode, "sink file is owner-only");
        }
        ModeEnforcement::InheritedAcl => {
            tracing::warn!(
                sink,
                "this platform has no file permission bits; the sink file inherits its directory's ACL",
            );
        }
    }
}

/// WOR-1186: build the configured session-ledger sink and register it
/// process-wide. The `file` sink needs a `path`; a missing or
/// unopenable path falls back to the logging sink with a warning so a
/// misconfiguration still captures the ledger rather than dropping it.
fn install_session_ledger_sink(cfg: &sbproxy_config::types::SessionLedgerConfig) {
    use std::sync::Arc;

    use sbproxy_config::types::SessionLedgerSinkKind;
    use sbproxy_observe::session_ledger::{
        set_session_ledger_sink, FileLedgerSink, LoggingLedgerSink, SessionLedgerSink,
    };

    let sink: Arc<dyn SessionLedgerSink> = match cfg.sink {
        SessionLedgerSinkKind::File => match cfg.path.as_deref() {
            Some(path) => match FileLedgerSink::create(std::path::Path::new(path)) {
                Ok(s) => {
                    log_sink_file_protection("session_ledger");
                    Arc::new(s)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path,
                        "session ledger file sink could not be opened; using the logging sink",
                    );
                    Arc::new(LoggingLedgerSink)
                }
            },
            None => {
                tracing::warn!(
                    "session_ledger.sink is `file` but no `path` is set; using the logging sink",
                );
                Arc::new(LoggingLedgerSink)
            }
        },
        SessionLedgerSinkKind::Logging => Arc::new(LoggingLedgerSink),
    };

    match set_session_ledger_sink(sink) {
        Ok(()) => tracing::info!("session ledger emission enabled"),
        Err(_) => {
            tracing::warn!("session ledger sink already registered; keeping the existing one")
        }
    }
}

/// WOR-2318: open the hash-chained, signed security audit trail and
/// register it process-wide.
///
/// Fallible, and the caller propagates, which is the whole difference
/// between this and every other sink installed around it. A session
/// ledger that will not open falls back to logging and a request-event
/// sink that will not open falls back to none, because in both cases a
/// degraded record is better than a stopped proxy. An audit trail an
/// operator explicitly asked for is not in that category: the events that
/// would fall in the hole are the ones an investigator needs, and no
/// later moment recovers them. `audit.sink: memory` is how an operator
/// says they would rather have the proxy.
///
/// Startup-only and set-once, like the sinks it sits beside. A reload
/// does not reopen the chain: the file is append-only and a second one
/// opened mid-life would either continue a file the new configuration
/// does not name or start a file that reads as a gap.
///
/// The signing identity is resolved rather than re-validated.
/// `compile_config` already proved `sign_with` names
/// `proxy.web_bot_auth`, that the block is present, and that its seed is
/// 64 hex characters, so anything unresolvable here is a bug in that
/// check rather than an operator error, and it says so.
///
/// WOR-2478: when `audit.config_path`, `audit.key_path`, or
/// `audit.admin_path` is also set, that channel gets its own chain under
/// the same signing identity. Same fail-the-boot rationale: an operator
/// who named the file wants the failure loud, not a proxy that starts
/// believing it is recording a trail it never opened. The key channel's
/// fingerprint key (as opposed to the chain file itself) is a separate
/// concern installed later, once `key_management`'s master key resolves;
/// see `sbproxy_observe::audit_chain::install_key_audit_fingerprint_key`.
///
/// WOR-2598: every file the operator named is opened before any of them
/// is registered, so a boot that refuses over the fourth chain does not
/// leave the first three sitting in slots that cannot be given back.
/// That covers the whole class of failure an operator can cause, which
/// is a file that will not open. The registrations that follow are still
/// four separate calls that can bail part way, but the only thing that
/// makes one of them fail is a second boot inside one process, which no
/// configuration produces: `run` calls this once and its callers exit on
/// the error.
///
/// Each open logs as it lands, so a boot that stalls on a slow or hung
/// file says which of the four it got to. Opening replays the existing
/// chain to find its head, so on a long-lived trail that is not a
/// negligible wait.
fn install_audit_chain(
    audit: &sbproxy_config::types::AuditConfig,
    web_bot_auth: Option<&sbproxy_config::types::WebBotAuthConfig>,
) -> anyhow::Result<()> {
    use sbproxy_config::types::AuditSinkKind;
    use sbproxy_observe::audit_chain::{
        install_admin_audit_chain, install_config_audit_chain, install_key_audit_chain,
        install_security_audit_chain, AdminActionAuditChain, ConfigAuditChain, KeyAuditChain,
        SecurityAuditChain,
    };

    if audit.sink != AuditSinkKind::Chain {
        return Ok(());
    }

    let Some(path) = audit.path.as_deref() else {
        anyhow::bail!(
            "audit.sink is `chain` but audit.path is absent at boot; config compilation should \
             have refused this document"
        );
    };
    let Some(signer) = web_bot_auth else {
        anyhow::bail!(
            "audit.sink is `chain` but no signing identity resolved at boot; config compilation \
             should have refused this document"
        );
    };

    // WOR-2598: open every file this document named before registering
    // any of them, and touch no slot until all four opens have come back
    // clean. The slots are set-once, so an install that ran before a
    // later open failed cannot be undone: a boot that refused over
    // `audit.admin_path` used to leave the security, config, and key
    // chains registered anyway, a process holding three quarters of a
    // trail with no way to complete it and no way to hand the slots
    // back. It also made this function's refusal depend on what had
    // called it earlier in the same process, which under a runner that
    // shares one process across tests (`release-checks.yml` runs `cargo
    // test --workspace -- --test-threads=1`, which does not fork per
    // test the way nextest does) is what had the two boot-refusal tests
    // below taking turns failing on each other's leftovers.
    //
    // Each open announces itself on the way past. The old order proved
    // progress by side effect, because the install line for one chain
    // could only appear after the previous one had opened; batching the
    // opens would otherwise have made a boot that hangs on the fourth
    // file indistinguishable from one that hangs on the first. Worth a
    // line each because opening replays the whole existing file to find
    // its head, so on an accumulated trail this is a real wait rather
    // than an instant `open(2)`.
    let security_chain = SecurityAuditChain::open(
        std::path::Path::new(path),
        &signer.ed25519_seed_hex,
        &signer.key_id,
    )?;
    tracing::info!(path = %path, channel = "security", "audit chain file opened");
    // Opt-in second chain for `config_audit` events, same signing identity
    // as the security chain above (one proxy, one key, two files). Absent
    // `audit.config_path`, `config_audit` stays exactly what it always
    // was: a tracing stream with no durable record.
    let config_chain = audit
        .config_path
        .as_deref()
        .map(|config_path| {
            ConfigAuditChain::open(
                std::path::Path::new(config_path),
                &signer.ed25519_seed_hex,
                &signer.key_id,
            )
            .map(|chain| {
                tracing::info!(path = %config_path, channel = "config", "audit chain file opened");
                (config_path, chain)
            })
        })
        .transpose()?;
    // WOR-2478: opt-in third chain for `key_audit` mutations, same
    // signing identity.
    let key_chain = audit
        .key_path
        .as_deref()
        .map(|key_path| {
            KeyAuditChain::open(
                std::path::Path::new(key_path),
                &signer.ed25519_seed_hex,
                &signer.key_id,
            )
            .map(|chain| {
                tracing::info!(path = %key_path, channel = "key", "audit chain file opened");
                (key_path, chain)
            })
        })
        .transpose()?;
    // WOR-2478: opt-in fourth chain for admin-console actions, same
    // signing identity.
    let admin_chain = audit
        .admin_path
        .as_deref()
        .map(|admin_path| {
            AdminActionAuditChain::open(
                std::path::Path::new(admin_path),
                &signer.ed25519_seed_hex,
                &signer.key_id,
            )
            .map(|chain| {
                tracing::info!(path = %admin_path, channel = "admin", "audit chain file opened");
                (admin_path, chain)
            })
        })
        .transpose()?;

    // Every file is open. From here on the calls claim process-wide
    // slots, and a failure is a second boot inside one process rather
    // than anything an operator wrote.

    // Read before the move, and the kid rather than the seed: this is the
    // one value an auditor needs in order to ask for the right public key.
    let kid = security_chain.key_id().to_string();
    match install_security_audit_chain(security_chain) {
        Ok(()) => {
            tracing::info!(
                path = %path,
                kid = %kid,
                "security audit trail is hash-chained and signed; verify it with \
                 `sbproxy audit verify`"
            );
        }
        Err(error) => anyhow::bail!("audit.sink is `chain` but {error}"),
    }

    if let Some((config_path, config_chain)) = config_chain {
        let config_kid = config_chain.key_id().to_string();
        match install_config_audit_chain(config_chain) {
            Ok(()) => {
                tracing::info!(
                    path = %config_path,
                    kid = %config_kid,
                    "config audit trail is hash-chained and signed; verify it with \
                     `sbproxy audit verify`"
                );
            }
            Err(error) => anyhow::bail!("audit.config_path is set but {error}"),
        }
    }

    if let Some((key_path, key_chain)) = key_chain {
        let key_kid = key_chain.key_id().to_string();
        match install_key_audit_chain(key_chain) {
            Ok(()) => {
                tracing::info!(
                    path = %key_path,
                    kid = %key_kid,
                    "key audit trail is hash-chained and signed; verify it with \
                     `sbproxy audit verify`"
                );
            }
            Err(error) => anyhow::bail!("audit.key_path is set but {error}"),
        }
    }

    if let Some((admin_path, admin_chain)) = admin_chain {
        let admin_kid = admin_chain.key_id().to_string();
        match install_admin_audit_chain(admin_chain) {
            Ok(()) => {
                tracing::info!(
                    path = %admin_path,
                    kid = %admin_kid,
                    "admin audit trail is hash-chained and signed; verify it with \
                     `sbproxy audit verify`"
                );
            }
            Err(error) => anyhow::bail!("audit.admin_path is set but {error}"),
        }
    }

    Ok(())
}

/// A constructed request-event sink, ready to hand to the setter.
type RequestEventSinkHandle = std::sync::Arc<dyn sbproxy_observe::RequestEventSink>;

/// WOR-2318: build the request-event sink the config asks for, or
/// `None` when it asks for nothing.
///
/// Returned alongside the sink is the kind that was actually built,
/// which is not always the kind that was configured: an unopenable or
/// unnamed `path` falls back to the logging sink so a misconfigured
/// deployment still sees its events rather than silently discarding
/// them. Split out from [`install_request_event_sink`] so the mapping
/// can be tested without touching the process-global slot, which is
/// set-once and therefore untestable more than once per process.
fn build_request_event_sink(
    cfg: &sbproxy_config::types::RequestEventsConfig,
) -> Option<(RequestEventSinkHandle, &'static str)> {
    use std::sync::Arc;

    use sbproxy_config::types::RequestEventSinkKind;
    use sbproxy_observe::{FileEventSink, LoggingSink, RequestEventSink};

    match cfg.sink {
        // The historical behavior, and the default: dispatch stays a
        // no-op and nothing is registered at all, so the request path
        // keeps paying one atomic load and nothing else.
        RequestEventSinkKind::None => None,
        RequestEventSinkKind::Logging => Some((
            Arc::new(LoggingSink) as Arc<dyn RequestEventSink>,
            "logging",
        )),
        RequestEventSinkKind::File => match cfg.path.as_deref() {
            Some(path) => match FileEventSink::create(std::path::Path::new(path)) {
                Ok(sink) => {
                    log_sink_file_protection("request_events");
                    Some((Arc::new(sink) as Arc<dyn RequestEventSink>, "file"))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path,
                        "request event file sink could not be opened; using the logging sink",
                    );
                    Some((
                        Arc::new(LoggingSink) as Arc<dyn RequestEventSink>,
                        "logging",
                    ))
                }
            },
            None => {
                tracing::warn!(
                    "request_events.sink is `file` but no `path` is set; using the logging sink",
                );
                Some((
                    Arc::new(LoggingSink) as Arc<dyn RequestEventSink>,
                    "logging",
                ))
            }
        },
        // WOR-2674. Both fall back to the logging sink the way `file`
        // does when their own block is missing or malformed: a
        // deployment that asked for its events to go somewhere should
        // still see them locally rather than discover the typo as
        // silence in a warehouse.
        RequestEventSinkKind::Nats => match build_ingest_sink(cfg, RequestEventSinkKind::Nats) {
            Some(sink) => Some((sink, "nats")),
            None => Some((
                Arc::new(LoggingSink) as Arc<dyn RequestEventSink>,
                "logging",
            )),
        },
        RequestEventSinkKind::ClickHouse => {
            match build_ingest_sink(cfg, RequestEventSinkKind::ClickHouse) {
                Some(sink) => Some((sink, "clickhouse")),
                None => Some((
                    Arc::new(LoggingSink) as Arc<dyn RequestEventSink>,
                    "logging",
                )),
            }
        }
    }
}

/// Turn a `nats:` block into a target, or `None` when it will not work.
///
/// Takes the block rather than the whole config so the two destinations do
/// not share one function with a `kind` string deciding which half of it
/// runs, and so each names the type it reads.
fn build_nats_target(
    nats: &sbproxy_config::types::RequestEventsNatsConfig,
) -> Option<sbproxy_observe::event_ingest::IngestTarget> {
    let token = resolve_ingest_secret("request_events.nats.token", nats.token.as_deref())?;
    Some(sbproxy_observe::event_ingest::IngestTarget::Nats {
        address: nats.address.clone(),
        subject_prefix: nats.subject_prefix.clone(),
        token,
    })
}

/// Turn a `clickhouse:` block into a target, or `None` when it will not
/// work.
fn build_clickhouse_target(
    clickhouse: &sbproxy_config::types::RequestEventsClickHouseConfig,
) -> Option<sbproxy_observe::event_ingest::IngestTarget> {
    let password = resolve_ingest_secret(
        "request_events.clickhouse.password",
        clickhouse.password.as_deref(),
    )?;
    Some(sbproxy_observe::event_ingest::IngestTarget::ClickHouse {
        url: clickhouse.url.clone(),
        database: clickhouse.database.clone(),
        table: clickhouse.table.clone(),
        user: clickhouse.user.clone(),
        password,
    })
}

/// Resolve one ingest credential reference.
///
/// `Some(None)` is "no credential configured", `Some(Some(_))` is a
/// resolved one, and `None` is a reference that would not resolve, which
/// the caller turns into the logging-sink fallback.
///
/// Fail-soft here and fail-loud in the `events:` sink next door, and the
/// difference is what a failure costs. An unresolvable
/// `events.signing_secret` means a SIEM stops verifying signatures it
/// thinks it is still verifying, which is a security property quietly
/// turning off. An unresolvable broker token means the events go to the
/// local log instead of the broker, which is visible in the log the
/// operator is then reading.
fn resolve_ingest_secret(field: &'static str, reference: Option<&str>) -> Option<Option<String>> {
    let Some(reference) = reference else {
        return Some(None);
    };
    let resolver = sbproxy_vault::process_resolver();
    let resolved = match resolver.as_deref() {
        Some(resolver) => resolver.resolve(reference),
        None => sbproxy_vault::SecretResolver::new().resolve(reference),
    };
    match resolved {
        Ok(value) => Some(Some(value)),
        // The reference itself is not echoed: it can name a path or a vault
        // key an operator would rather not have in a boot log.
        Err(error) => {
            tracing::warn!(
                field,
                error = %error,
                "request_events credential would not resolve; using the logging sink"
            );
            None
        }
    }
}

/// Build one of the two optional ingest sinks, or `None` when its block is
/// missing, malformed, or its credential will not resolve.
///
/// Takes the sink kind rather than a string, and matches it exhaustively.
/// The string form had a catch-all arm that built ClickHouse for any value
/// that was not `"nats"`, so a third destination added later would have
/// been silently built as the second one.
fn build_ingest_sink(
    cfg: &sbproxy_config::types::RequestEventsConfig,
    kind: sbproxy_config::types::RequestEventSinkKind,
) -> Option<std::sync::Arc<dyn sbproxy_observe::RequestEventSink>> {
    use sbproxy_config::types::RequestEventSinkKind;
    use sbproxy_observe::event_ingest::EventIngest;

    let target = match kind {
        RequestEventSinkKind::Nats => match cfg.nats.as_ref() {
            Some(nats) => build_nats_target(nats)?,
            None => {
                tracing::warn!(
                    "request_events.sink is `nats` but no `nats` block is set; using the logging sink"
                );
                return None;
            }
        },
        RequestEventSinkKind::ClickHouse => match cfg.clickhouse.as_ref() {
            Some(clickhouse) => build_clickhouse_target(clickhouse)?,
            None => {
                tracing::warn!(
                    "request_events.sink is `clickhouse` but no `clickhouse` block is set; \
                     using the logging sink"
                );
                return None;
            }
        },
        // Not reachable from `build_request_event_sink`, which only calls
        // this for the two network destinations. Named rather than caught
        // so adding a third kind is a compile error here.
        RequestEventSinkKind::None | RequestEventSinkKind::Logging | RequestEventSinkKind::File => {
            return None
        }
    };

    let watermark = cfg.watermark_store_path.as_ref().and_then(|path| {
        match sbproxy_platform::storage::EmbeddedKvStore::open_shared(path, "event_ingest") {
            Ok(store) => Some(store as std::sync::Arc<dyn sbproxy_platform::storage::PersistentKv>),
            Err(error) => {
                // Fail-soft: the watermark is bookkeeping about delivery,
                // not delivery. Losing it costs an operator a checkpoint,
                // and refusing to deliver would cost them the events.
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "request_events watermark store could not be opened; delivering without a checkpoint"
                );
                None
            }
        }
    });

    let target_label = target.label();
    match EventIngest::start(target, cfg.queue_capacity, watermark) {
        Ok(sink) => Some(std::sync::Arc::new(sink)),
        Err(error) => {
            tracing::warn!(
                sink = target_label,
                error = %error,
                "request event ingest sink could not start; using the logging sink"
            );
            None
        }
    }
}

/// WOR-2318: register the configured request-event sink process-wide.
///
/// Without this the proxy builds a fully populated `RequestEvent` for
/// every terminating request and then hands it to the implicit no-op,
/// so the whole capture path runs and produces nothing an operator can
/// read.
fn install_request_event_sink(cfg: &sbproxy_config::types::RequestEventsConfig) {
    let Some((sink, kind)) = build_request_event_sink(cfg) else {
        return;
    };

    match sbproxy_observe::set_request_event_sink(sink) {
        Ok(()) => tracing::info!(sink = kind, "request event emission enabled"),
        Err(_) => {
            tracing::warn!("request event sink already registered; keeping the existing one")
        }
    }
}

/// WOR-2318: turn an `events:` block into a started
/// [`sbproxy_observe::EventEgress`], or `None` when it asks for nothing.
///
/// Split from [`install_event_egress`] so the mapping is testable
/// without touching the process-global slot, which is set-once and
/// therefore assertable at most once per test binary.
///
/// Fallible where the sibling sinks are not. A request-event `path` that
/// will not open falls back to the logging sink, because the operator
/// asked for records and a degraded record beats none. There is no
/// analogous fallback here: `sink: webhook` names an endpoint, and
/// quietly writing those events to a local log instead would satisfy
/// nothing the operator configured while looking like success in the
/// boot line. The caller decides whether that is fatal.
fn build_event_egress(
    cfg: &sbproxy_config::types::EventsConfig,
) -> anyhow::Result<Option<(sbproxy_observe::EventEgress, &'static str)>> {
    use sbproxy_config::types::EventSinkKind;
    use sbproxy_observe::{
        EventEgress, EventSinkTarget, EventType, EventTypeMask, DEFAULT_EVENT_QUEUE_CAPACITY,
    };

    let target = match cfg.sink {
        // The default, and the historical behavior: nothing is
        // registered, so every publish site stays one relaxed load.
        EventSinkKind::None => return Ok(None),
        EventSinkKind::File => {
            let Some(path) = cfg.path.as_deref() else {
                anyhow::bail!(
                    "events.sink is `file` but events.path is absent at boot; config \
                     compilation should have refused this document"
                );
            };
            EventSinkTarget::File {
                path: std::path::PathBuf::from(path),
            }
        }
        EventSinkKind::Webhook => {
            let Some(url) = cfg.url.as_deref() else {
                anyhow::bail!(
                    "events.sink is `webhook` but events.url is absent at boot; config \
                     compilation should have refused this document"
                );
            };
            EventSinkTarget::Webhook {
                url: url.to_string(),
                signing_secret: resolve_events_signing_secret(cfg.signing_secret.as_deref())?,
            }
        }
    };

    // An empty `types:` means every type; the config validator already
    // refused the explicit-but-empty selection that would mean none.
    let mask = if cfg.types.is_empty() {
        EventTypeMask::all()
    } else {
        let mut selected = Vec::with_capacity(cfg.types.len());
        for name in &cfg.types {
            let Some(event_type) = EventType::from_name(name) else {
                anyhow::bail!(
                    "events.types names `{name}`, which is not an event type; config \
                     compilation should have refused this document"
                );
            };
            selected.push(event_type);
        }
        EventTypeMask::from_types(&selected)
    };
    if mask.is_empty() {
        anyhow::bail!("events.types resolved to no event types, so nothing would be delivered");
    }

    let capacity = cfg.queue_capacity.unwrap_or(DEFAULT_EVENT_QUEUE_CAPACITY);
    if capacity == 0 {
        anyhow::bail!(
            "events.queue_capacity is 0 at boot; config compilation should have refused this \
             document"
        );
    }

    let label = target.label();
    Ok(Some((EventEgress::start(target, mask, capacity)?, label)))
}

/// Resolve `events.signing_secret` through the process secret resolver.
///
/// The only way the webhook sink gets a credential. A reference that
/// will not resolve fails the boot rather than being posted verbatim,
/// which is the WOR-1767 fail-loud convention the telemetry headers and
/// the alert channels already follow: a raw `vault://` string arriving
/// at a third-party endpoint is a config leak, and a silently-unsigned
/// batch is a signature check the receiver stops performing.
fn resolve_events_signing_secret(reference: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    let resolver = sbproxy_vault::process_resolver();
    let resolved = match resolver.as_deref() {
        Some(resolver) => resolver.resolve(reference),
        // No backends declared: `${VAR}` and `file:` still resolve, and a
        // provider URI fails loud pointing at proxy.secrets.backends.
        None => sbproxy_vault::SecretResolver::new().resolve(reference),
    };
    match resolved {
        Ok(value) => Ok(Some(value)),
        // The reference itself is not echoed. It can name a path or a
        // vault key an operator would rather not have in a boot log, and
        // the resolver's own error already says what it could not find.
        Err(error) => Err(anyhow::anyhow!("events.signing_secret: {error:#}")),
    }
}

/// Warn about `events.types` entries an operator selected that nothing
/// publishes yet (WOR-2486, mirroring [`warn_unwired_decision_audit_events`]
/// for the typed proxy event feed).
///
/// `events.types:` accepts every declared
/// [`sbproxy_observe::EventType`] on purpose (see `validate_events` in
/// `sbproxy-config`): refusing an unwired one would block
/// pre-configuring a type a later release wires, and would fail a
/// correct config over a gap in this crate's own instrumentation. That
/// leaves the operator with no signal at the moment the mistake is
/// made, and a silent `events:` sink reads exactly like a sink with
/// nothing to report.
///
/// Called only when `events:` is present, same as
/// [`install_event_egress`]: an absent block has no sink to warn about,
/// and `sink: none` cannot carry a non-empty `types:` past config
/// validation.
fn warn_unwired_proxy_events(cfg: &sbproxy_config::types::EventsConfig) {
    let unwired = unwired_proxy_events(cfg);
    if !unwired.is_empty() {
        tracing::warn!(
            events = %unwired.join(", "),
            "events.types selects event types that nothing publishes yet; the configured sink \
             will not see these until their emitters ship"
        );
    }
}

/// The `events.types` entries this block selects that publish nothing.
///
/// Split out of the warning so it is testable directly, the same reason
/// [`unwired_decision_audit_events`] is split from its warning: the
/// warning itself only logs, and a feed that silently names the wrong
/// types is exactly the failure this surface exists to avoid.
pub(super) fn unwired_proxy_events(cfg: &sbproxy_config::types::EventsConfig) -> Vec<&'static str> {
    use sbproxy_observe::EventType;

    // Empty `types:` means every type, the same reading
    // `build_event_egress` gives it.
    let selected: Vec<EventType> = if cfg.types.is_empty() {
        sbproxy_observe::ALL_EVENT_TYPES.to_vec()
    } else {
        cfg.types
            .iter()
            .filter_map(|name| EventType::from_name(name))
            .collect()
    };
    selected
        .iter()
        .filter(|event_type| !event_type.has_emitter())
        .map(|event_type| event_type.as_str())
        .collect()
}

/// WOR-2318: start the configured event egress and register it
/// process-wide.
///
/// Startup-only and set-once, like the sinks beside it. A reload does not
/// restart it: swapping a live egress would either strand a queue nothing
/// will drain or open a second file that reads as a gap in the first.
fn install_event_egress(cfg: &sbproxy_config::types::EventsConfig) -> anyhow::Result<()> {
    let Some((egress, sink)) = build_event_egress(cfg)? else {
        return Ok(());
    };
    match sbproxy_observe::install_event_egress(egress) {
        Ok(()) => {
            tracing::info!(sink, "proxy event egress enabled");
            Ok(())
        }
        Err(error) => {
            tracing::warn!("{error}; keeping the existing one");
            Ok(())
        }
    }
}

/// WOR-1164: (re)install the detection-singleton globals from
/// `compiled`. Runs at startup AND from the hot-reload path so a SIGHUP
/// that changed `agent_classes:`, the resolver flags, or
/// `agent_detect.rule_pack_path` / `agent_detect.onnx_model_path`
/// actually takes effect; every slot it touches is swap-backed and
/// degrades to a warn on failure rather than blocking the reload.
fn install_detection_singletons(compiled: &sbproxy_config::CompiledConfig) {
    // Registered before any origin compiles its guardrail pipeline, since
    // pipelines are built lazily on first request and need the factory.
    super::ai_classifier::install_classifier_factory();

    // --- Wave 3 / G1.4: agent-class resolver ---
    //
    // Build the process-wide `AgentClassResolver` from the parsed
    // top-level `agent_classes:` block (or from defaults when the block
    // is absent), then install it in the global slot the request
    // pipeline reads in `request_filter`. `builtin` and `inline` are
    // live. The compatibility values `hosted-feed` and `merged` warn
    // and use the embedded defaults; the OSS runtime does not fetch or
    // validate the reserved `hosted_feed` block. All paths are
    // infallible so an unsupported selection does not block serving.
    #[cfg(feature = "agent-class")]
    {
        install_agent_class_resolver(compiled.agent_classes.as_ref());
    }

    // --- Wave 5 / G5.4: TLS-fingerprint catalogue ---
    //
    // The catalogue lives behind an arc-swap so reloads can refresh it
    // without dropping in-flight detector reads. Failures degrade
    // gracefully: an empty catalogue matches everything, which is the
    // conservative direction, so nothing is accused of spoofing because
    // a file was unreadable.
    //
    // The embedded default names the agent classes and carries no
    // fingerprints (WOR-2296), so out of the box this installs a
    // catalogue that answers `true` for everything. An operator's
    // `catalog_file` replaces it wholesale rather than merging, so the
    // file they wrote is the whole truth.
    #[cfg(feature = "tls-fingerprint")]
    {
        use std::sync::Arc as TlsFingerprintArc;
        // A malformed `tls_fingerprint` block is already refused earlier
        // in config load when the operator asked for capture, so this
        // falling back to the default is the disabled-or-absent case
        // rather than a swallowed error.
        let operator_catalog =
            crate::pipeline::TlsFingerprintConfig::from_extensions(&compiled.server.extensions)
                .ok()
                .and_then(|cfg| cfg.catalog_file);
        let loaded = match operator_catalog {
            Some(path) => {
                sbproxy_security::TlsFingerprintCatalog::from_path(std::path::Path::new(&path))
            }
            None => sbproxy_security::TlsFingerprintCatalog::default_embedded(),
        };
        match loaded {
            Ok(catalog) => {
                // Also install the CEL matcher adapter so
                // `tls_fingerprint_matches(ja4, agent_class_id)`
                // resolves against the same catalogue.
                struct CatalogAdapter(sbproxy_security::TlsFingerprintCatalog);
                impl sbproxy_extension::cel::TlsFingerprintMatcher for CatalogAdapter {
                    fn matches(&self, ja4: &str, agent_class_id: &str) -> bool {
                        self.0.matches(ja4, agent_class_id)
                    }
                }
                let adapter: TlsFingerprintArc<dyn sbproxy_extension::cel::TlsFingerprintMatcher> =
                    TlsFingerprintArc::new(CatalogAdapter(catalog.clone()));
                sbproxy_extension::cel::set_tls_fingerprint_matcher(adapter);
                reload::set_tls_fingerprint_catalog(catalog);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load TLS fingerprint catalogue; headless detection disabled"
                );
            }
        }
    }

    // --- WOR-706 / WOR-592: agent-detect scorers ---
    //
    // When `proxy.extensions.agent_detect.enabled` is set, install one
    // trait-object scorer backed by the ADRF rule pack, the CatBoost
    // ONNX model, or both. A load failure degrades to whichever scorer
    // did load rather than blocking serving, matching the TLS-catalogue
    // block above.
    {
        // WOR-2181 made `from_extensions` fallible, and the pipeline
        // compile has already run it with `?` on this same block, so a
        // config that reaches here cannot produce the error arm. The
        // `tls_fingerprint` block above takes the same position on its
        // own call. Degrade rather than panic on the impossible case,
        // and warn so it is not swallowed if it ever happens.
        let agent_detect_cfg = match crate::pipeline::AgentDetectConfig::from_extensions(
            &compiled.server.extensions,
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "proxy.extensions.agent_detect unreadable after compile; \
                     no agent-detect scorer installed",
                );
                crate::pipeline::AgentDetectConfig::default()
            }
        };
        if agent_detect_cfg.enabled {
            let rule_scorer: Option<std::sync::Arc<dyn sbproxy_agent_detect::AgentScorer>> =
                match agent_detect_cfg.rule_pack_path.as_deref() {
                    Some(path) => match sbproxy_agent_detect::RulePackLoader::open(path) {
                        Ok(loader) => {
                            let loader = std::sync::Arc::new(loader);
                            reload::set_agent_detect_loader_arc(std::sync::Arc::clone(&loader));
                            Some(std::sync::Arc::new(
                                sbproxy_agent_detect::RulePackLoaderScorer::new(loader),
                            ))
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path = %path,
                                "failed to load agent-detect rule pack; rule-pack scorer disabled",
                            );
                            None
                        }
                    },
                    None => None,
                };
            let onnx_scorer: Option<std::sync::Arc<dyn sbproxy_agent_detect::AgentScorer>> =
                match agent_detect_cfg.onnx_model_path.as_deref() {
                    Some(path) => match sbproxy_agent_detect::OnnxCatBoostScorer::load(path) {
                        Ok(scorer) => Some(std::sync::Arc::new(scorer)),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path = %path,
                                "failed to load agent-detect ONNX model; ONNX scorer disabled",
                            );
                            None
                        }
                    },
                    None => None,
                };

            match (rule_scorer, onnx_scorer) {
                (Some(rule), Some(onnx)) => reload::set_agent_detect_scorer(std::sync::Arc::new(
                    sbproxy_agent_detect::FallbackAgentScorer::new(rule, onnx),
                )),
                (Some(rule), None) => reload::set_agent_detect_scorer(rule),
                (None, Some(onnx)) => reload::set_agent_detect_scorer(onnx),
                (None, None) => {
                    reload::clear_agent_detect_scorer();
                    tracing::warn!(
                        "agent_detect.enabled is set but no scorer loaded; agent detection disabled",
                    );
                }
            }
        } else {
            reload::clear_agent_detect_scorer();
        }
    }
}

/// Construct enforcing safety classifiers before a candidate pipeline can
/// become requestable.
///
/// Routing classifiers keep their inert-on-load-failure contract. The
/// enforcing toxicity, jailbreak, and content-safety paths use shipped
/// centroids bound to exact model bytes, so their construction is a required
/// startup and reload preflight.
fn preflight_default_safety_centroids(pipeline: &CompiledPipeline) -> anyhow::Result<()> {
    fn preflight_action(action: &Action) -> anyhow::Result<()> {
        if let Action::AiProxy(action) = action {
            action
                .config
                .preflight_default_safety_centroids()
                .map_err(|error| {
                    anyhow::anyhow!("AI safety classifier startup preflight failed: {error}")
                })?;
        }
        Ok(())
    }

    for action in &pipeline.actions {
        preflight_action(action)?;
    }
    for rule in pipeline.forward_rules.iter().flatten() {
        preflight_action(&rule.action)?;
    }
    Ok(())
}

fn reload_from_config_path_inner(config_path: &str) -> anyhow::Result<ReloadOutcome> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{config_path}': {e}"))?;
    reload_from_config_yaml(config_path, &yaml)
}

/// Reload one exact config payload through the same prepare and publish
/// transaction used by file-watch and SIGHUP reloads.
///
/// The transaction has three phases and the order matters:
///
/// 1. **Reject.** Compile the YAML and run every check that can refuse
///    the candidate outright, before anything observable changes.
/// 2. **Construct.** Install the AI provider catalog (the one process
///    global `CompiledPipeline::from_config` reads while it builds), then
///    build the pipeline, load listings, run the pipeline lifecycle hook, and
///    reconcile the model runtime. A failure anywhere in this phase
///    returns `Err` and rolls the catalog back, so the node is left
///    exactly as it was.
/// 3. **Commit.** Install the request-path and admin-path process
///    globals, then publish the pipeline. Nothing here can fail the
///    reload; the subsystems that can fail softly record themselves in
///    the returned [`ReloadOutcome`].
///
/// Keeping phase 3 after phase 2 is the whole point: a config that
/// compiles but cannot construct a pipeline used to leave the node
/// running new Lua sandbox limits, new redaction rules, a new key plane
/// and a new sink dispatcher against the old pipeline, while the error
/// claimed nothing had been applied.
pub(crate) fn reload_from_config_yaml(
    config_path: &str,
    yaml: &str,
) -> anyhow::Result<ReloadOutcome> {
    // WOR-2459: the guard that makes the boot fallback mean something.
    // Both production callers of this function are the file watcher and
    // SIGHUP, and both re-read the local file. A node the fallback
    // rescued from that exact file must not re-apply it on the first
    // filesystem event in its directory, which would loop straight back
    // into the state the fallback just rescued it from. Refused before
    // the reload lock is taken, so a pinned node does not even contend
    // with the config-authority poller that is deliberately still live.
    if crate::config_boot::reload_suspended("file_watcher") {
        return Err(anyhow::anyhow!(
            "this node is pinned to a configuration its boot fallback restored from the \
             revision ring; local config reloads (the file watcher and SIGHUP) are \
             suspended until an operator clears the pin with \
             DELETE /admin/config/fallback"
        ));
    }
    let _reload_guard = CONFIG_RELOAD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Every production caller of this exact function (the file watcher
    // and SIGHUP, both via `reload_from_config_path` /
    // `reload_from_config_text` below) already audits its outcome under
    // the literal source `"file_watcher"`, so that is the config
    // history actor too; see WOR-2486's reasoning for why the two
    // triggers share one label. `origin_override: None` because this
    // `yaml` is read straight off the local file and may itself carry a
    // `source:` block, which `reload_from_config_yaml_locked` resolves
    // the ordinary way.
    let result = reload_from_config_yaml_locked(config_path, yaml, "file_watcher", None);
    // WOR-2462: a local file that does not apply is a refused candidate
    // like any other, and the one an operator is most likely to be
    // staring at. Recorded here rather than in `reload_from_config_path`
    // and `reload_from_config_text` separately, for the same reason the
    // audit entry above is shared: this is where both triggers converge
    // and where the candidate bytes are in hand. A failure that never
    // reached this function (an unreadable file) has no candidate to
    // record, which is why the read error in
    // `reload_from_config_path_inner` is not funnelled through here.
    if let Err(error) = &result {
        crate::config_subscriber::record_refusal(
            yaml,
            &crate::config_subscriber::CycleRefusal::new(
                crate::config_subscriber::CycleResult::CompileFailed,
                crate::path_redact::sanitise_path_in_error(
                    &format!("{error:#}"),
                    std::path::Path::new(config_path),
                ),
            ),
            "file_watcher",
            // The stored document is this node's own file, whatever a
            // `source:` block inside it points at: pre-resolution bytes
            // only, so the pointer is what was refused and the pointer is
            // what is kept.
            sbproxy_config::BaseOrigin::Local,
        );
    }
    result
}

/// As [`reload_from_config_yaml`], for a caller that already resolved
/// the document's `source:` pointer for validation.
///
/// Exists so the admin reload path can validate the *resolved* payload
/// and classify its failures as the operator's 400, rather than
/// validating the pointer document, a near-empty file that compiles
/// trivially, and surfacing the payload's fault as the transaction's
/// 500. `original` is the on-disk text and feeds drift tracking, which
/// compares against the file, so a pointer file still reads as
/// unchanged.
///
/// For a document that names a remote source, the commit deliberately
/// **re-resolves under the lock** rather than trusting the caller's
/// text. The caller fetched before taking the lock, and in that window
/// the refresh poller can fetch and apply a newer commit; committing
/// the caller's older text afterwards would leave the poller's
/// fingerprint pointing at the newer revision while the node serves
/// the older one, and every later poll would read `NotModified` until
/// a further commit arrived. The second fetch is the freshness
/// guarantee, not waste. A local document resolves to itself with no
/// I/O, so the common case pays nothing.
pub(crate) fn reload_from_resolved_yaml(
    config_path: &str,
    resolved_text: &str,
    original: &str,
) -> anyhow::Result<ReloadOutcome> {
    let _reload_guard = CONFIG_RELOAD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let names_remote_source = sbproxy_config::source::parse_source_head(original)
        .map_err(|error| anyhow::anyhow!("config source: {error}"))?
        .is_some();
    let (commit_text, origin) = if names_remote_source {
        let resolved = crate::config_source::resolve(original)?;
        let origin = resolved.base_origin();
        (resolved.text, origin)
    } else {
        (resolved_text.to_owned(), sbproxy_config::BaseOrigin::Local)
    };
    let compiled = sbproxy_config::compile_config(&commit_text)?;
    // The actor and revision pair `crate::admin` carries for its own
    // `config_audit` entry (WOR-2094) is exactly the actor this ring
    // wants too: the authenticated operator id when the request came in
    // authenticated, `"api"` (the same fallback label
    // `audit_reload_outcome`'s doc names for this path) otherwise.
    let actor = crate::admin::current_admin_actor().unwrap_or_else(|| "api".to_string());
    reload_compiled_config_locked(
        config_path,
        compiled,
        None,
        Some(original),
        Some(RevisionRecordingInput {
            content: commit_text.as_bytes(),
            origin,
            actor: &actor,
        }),
    )
}

/// What a non-blocking reload attempt did.
///
/// The distinction exists for callers on a timer. [`Self::Busy`] is not a
/// failure and must not be reported as one: the candidate was never
/// examined, so nothing about it is known yet.
#[derive(Debug)]
pub enum TryReloadOutcome {
    /// The transaction ran. Carries what it accomplished, including any
    /// subsystem that stayed on prior state.
    Applied(ReloadOutcome),
    /// Another reload held the reload lock, so this attempt did nothing:
    /// no compile, no construct, no publish. The caller retries on its
    /// own schedule.
    Busy,
}

/// Reload one exact config payload, but only if no other reload is
/// running. See [`reload_from_config_yaml`] for the transaction itself.
///
/// The blocking entry point holds `CONFIG_RELOAD_LOCK` across the whole
/// prepare-and-publish body, which for a large config is not brief. A
/// caller on a fixed interval that waits behind it queues up: every
/// pending poll cycle wakes into the same lock, and a fleet-wide slow
/// reload turns into a backlog of reloads for a revision that has since
/// been superseded. Such a caller wants to skip this cycle and try again
/// at the next interval, which is what [`TryReloadOutcome::Busy`] says.
///
/// # Errors
///
/// Returns `Err` under exactly the conditions [`reload_from_config_yaml`]
/// does. Contention is `Ok(TryReloadOutcome::Busy)`, never an error.
// `source` is the WOR-2486 addition: `audit_reload_outcome` needs a
// `config_audit` source label, and the two callers of this function
// (the config-authority bundle apply and the remote config-source
// refresh poller) are different enough that one guessed label would be
// wrong for one of them. `origin` is the WOR-2457 addition, for the
// same reason on a different axis: both callers hand `yaml` down as an
// already-merged document with no `source:` block of its own, so
// neither can be re-resolved into a `BaseOrigin` inside the shared
// transaction the way the file-watcher and SIGHUP paths are. Both
// callers already compute the right one for their own purposes
// (`base_origin_for` / `resolved.base_origin()`) and hand it down here
// rather than it being re-derived.
pub(crate) fn try_reload_from_config_yaml(
    config_path: &str,
    yaml: &str,
    source: &str,
    origin: sbproxy_config::BaseOrigin,
) -> anyhow::Result<TryReloadOutcome> {
    let _reload_guard = match CONFIG_RELOAD_LOCK.try_lock() {
        Ok(guard) => guard,
        // Busy is not a reload attempt: nothing was examined, so there
        // is nothing to audit. The caller retries on its own schedule.
        Err(std::sync::TryLockError::WouldBlock) => return Ok(TryReloadOutcome::Busy),
        // A poisoned lock means some other reload panicked mid-flight.
        // The guarded data is `()`, so there is no corrupt state to
        // inherit, and refusing every future reload over it would be
        // worse than proceeding.
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };
    let result = reload_from_config_yaml_locked(config_path, yaml, source, Some(origin));
    audit_reload_outcome(source, config_path, &result);
    result.map(TryReloadOutcome::Applied)
}

/// What one non-blocking extension bundle refresh attempt did.
#[derive(Debug)]
pub(crate) enum TryBundleRefreshOutcome {
    /// A changed, fully validated bundle candidate followed the ordinary
    /// reload transaction to publication.
    Applied(ReloadOutcome),
    /// Every Git source resolved to the commit already serving.
    NotModified,
    /// Another reload owns the shared transaction lock.
    Busy,
}

/// Refresh Git-backed extension bundles without overlapping another reload.
///
/// The currently published compiled config is cloned only after this call owns
/// the reload lock. The complete registry candidate is then fetched and
/// validated before its source fingerprint is compared. A changed candidate
/// enters the same prepare-and-publish transaction as file watch, SIGHUP, and
/// admin reloads.
pub(crate) fn try_refresh_extension_bundles(
    config_path: &str,
) -> anyhow::Result<TryBundleRefreshOutcome> {
    let _reload_guard = match CONFIG_RELOAD_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return Ok(TryBundleRefreshOutcome::Busy),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };

    let current = reload::current_pipeline_full();
    let compiled = current.config.clone();
    let current_fingerprint = current.extension_registry().revision_fingerprint();
    let config_dir = std::path::Path::new(config_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let fetch_context =
        crate::config_source::build_extension_fetch_context(&compiled.extension_bundles)?;
    let candidate = sbproxy_extension::bundle::DynamicBundleRegistry::load_with_context(
        &compiled.extension_bundles,
        config_dir,
        &crate::extension_inventory::reserved_extension_hook_names()?,
        &fetch_context,
    )?;
    let candidate_fingerprint = candidate.revision_fingerprint();

    match crate::extension_refresh::apply_if_changed(
        &current_fingerprint,
        &candidate_fingerprint,
        || reload_for_extension_refresh(config_path, compiled, candidate),
    )? {
        crate::extension_refresh::CandidateDecision::Applied(outcome) => {
            Ok(TryBundleRefreshOutcome::Applied(outcome))
        }
        crate::extension_refresh::CandidateDecision::NotModified => {
            Ok(TryBundleRefreshOutcome::NotModified)
        }
    }
}

/// Run the shared reload transaction for a changed extension-bundle
/// candidate, auditing both outcomes (WOR-2486 fix round 1, C1).
///
/// This is the sixth reload path, and the one `config_audit` missed
/// entirely: `apply_if_changed` only calls its closure when the verified
/// Git fingerprint actually moved, so `NotModified` (nothing to apply)
/// and `Busy` (nothing examined) stay un-audited on the same grounds
/// [`audit_reload_outcome`]'s other callers already use, but an attempt
/// that reaches this function, accepted or rejected, was silent before
/// this fix. Split into its own function so the audit call is testable
/// without a live Git fetch: a candidate built from an empty
/// `ExtensionBundlesConfig` reaches this function exactly like a real
/// one would.
fn reload_for_extension_refresh(
    config_path: &str,
    compiled: sbproxy_config::CompiledConfig,
    candidate: std::sync::Arc<sbproxy_extension::bundle::DynamicBundleRegistry>,
) -> anyhow::Result<ReloadOutcome> {
    // `None`: an extension-bundle refresh republishes the same compiled
    // config under a new extension registry. No config document
    // changed, so there is nothing new for the revision ring to record.
    let result = reload_compiled_config_locked(config_path, compiled, Some(candidate), None, None);
    audit_reload_outcome("extension_refresh", config_path, &result);
    result
}

/// Hold the reload lock so a test can prove that a caller which must not
/// block on it does not.
///
/// The lock is a private static, and contention on it cannot be staged
/// from another crate without this. Not for production use: holding the
/// returned guard blocks every reload path in the process.
#[doc(hidden)]
pub fn hold_config_reload_lock_for_test() -> std::sync::MutexGuard<'static, ()> {
    CONFIG_RELOAD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What to record into the config revision ring for one reload, when
/// this path has a document to record.
///
/// Bundled into one parameter and threaded down to
/// `reload_compiled_config_locked`, the one place every reload path
/// converges: see the comment on the drift-baseline write inside it,
/// which applies the same reasoning to a different piece of state.
/// `None` reaches that function for the extension-bundle refresh path,
/// which republishes the same compiled config under a new extension
/// registry rather than applying a new document, so there is nothing
/// new to record.
struct RevisionRecordingInput<'a> {
    /// Pre-resolution document bytes: literal text, with `${VAR}` /
    /// `vault://` / `secret://` references unresolved. Never the
    /// document `compile_config` produced after interpolation; storing
    /// that would be a ring of resolved secrets on disk.
    content: &'a [u8],
    /// Where `content` came from. Computed by the caller rather than
    /// re-derived inside the shared transaction: a merged or overlaid
    /// document (the config-authority and `source:` refresh-poller
    /// paths both hand down an already-merged document) carries no
    /// `source:` block of its own, so re-resolving it there would
    /// misreport a git-sourced base as
    /// [`sbproxy_config::BaseOrigin::Local`].
    origin: sbproxy_config::BaseOrigin,
    /// Who or what produced this revision.
    ///
    /// The whole vocabulary, because a partial list here is what let
    /// `docs/config-rollback.md` document a value this field never
    /// holds: `"file_watcher"`, `"config_authority"`,
    /// `"config_refresh_poller"`, `"boot"`, `"boot_fallback"`,
    /// `"auto_revert"`, `"rollback"` or `"rollback:<operator>"`, and
    /// `"api"` or the authenticated operator's own id.
    ///
    /// Never empty. The CLI renders an absent field as `-`, which no
    /// apply path produces.
    actor: &'a str,
}

/// Host wall clock in unix milliseconds, saturating rather than
/// panicking on a clock set before the epoch.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Append one applied revision to the process-wide config history ring,
/// when a recorder is installed.
///
/// A no-op when `proxy.config_history` is absent or disabled: see
/// [`crate::config_history::current_config_history_recorder`]. Never
/// fails the reload it is called from and never blocks it on I/O beyond
/// the store's own writes: a failure to record is logged by the
/// recorder itself and swallowed there, because this ring is a
/// diagnostic and rollback aid, not a gate the request path depends on.
fn record_applied_config_revision(input: RevisionRecordingInput<'_>, outcome: &ReloadOutcome) {
    let Some(recorder) = crate::config_history::current_config_history_recorder() else {
        return;
    };
    let blast_radius = recorder.blast_radius_for(input.content);
    let metadata = sbproxy_config::AppendMetadata {
        provenance: input.origin,
        blast_radius,
        secrets_fingerprint: PROCESS_SECRETS_FINGERPRINT.get().cloned(),
        actor: Some(input.actor.to_string()),
        applied_at: now_unix_ms(),
        degraded: outcome
            .degraded()
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
    };
    let Some(entry) = recorder.record(input.content, metadata) else {
        // A byte-identical repeat of what is already running, or a write
        // that failed. Neither is a new revision, so neither arms a soak
        // window: a reload loop re-applying an unchanged file must not
        // restart the clock on a revision that already soaked.
        return;
    };

    // WOR-2458: arm the soak window. Until this landed, recording an
    // applied revision was the whole of the promotion story, which is
    // the epic's root defect. Now the pointer moves only when a window
    // closes passing, and `arm` reaches a verdict here only for the two
    // cases that need no traffic to decide: a degraded reload, and a
    // node whose operator switched the soak off.
    let soak = history_soak_config();
    if let Some(verdict) = crate::config_soak::arm(
        entry.revision,
        &entry.digest,
        &entry
            .degraded
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        &soak,
    ) {
        sbproxy_observe::metrics::record_config_soak_verdict(
            crate::config_soak::verdict_label(verdict),
            "window",
        );
        recorder.record_soak_verdict(entry.revision, verdict);
    }
}

/// The `proxy.config_history.soak` block the running config declares, or
/// its defaults when the running pipeline is not readable yet.
///
/// Read off the live pipeline rather than threaded down from the reload
/// that is publishing: by the time this runs the new pipeline is already
/// published (see the call site's position in
/// `reload_compiled_config_locked`), so this reads the soak block the
/// revision being judged actually declares, which is the right one to
/// judge it under.
fn history_soak_config() -> sbproxy_config::ConfigSoakConfig {
    crate::reload::current_pipeline()
        .config
        .server
        .config_history
        .as_ref()
        .map(|history| history.soak.clone())
        .unwrap_or_default()
}

/// Open the config history ring `history` names and record `content` as
/// this process's boot entry.
///
/// Split out of `run` so boot's own wiring is unit-testable without
/// booting a full server: `boot_path_records_a_ring_entry` (the happy
/// path) and `boot_path_marks_the_slot_failed_when_the_store_cannot_open`
/// (the unopenable-store path) both exercise this function directly.
/// The `None`/disabled-block cases are exercised indirectly, through
/// `ConfigHistoryRecorder::from_config`'s own tests in
/// `crate::config_history`: this function's `Ok(None) => {}` arm has
/// nothing of its own to test beyond what those already cover.
///
/// `ConfigHistoryRecorder::from_config` returns `None` for an absent or
/// disabled block, so this is a no-op on every node that has not opted
/// in. A store that fails to open is logged and marks the process-wide
/// slot [`crate::config_history::ConfigHistoryState::Failed`] rather
/// than propagating: a boot that has already published its pipeline
/// must not fail over its own audit trail, but the admin history routes
/// still surface the failure (`503`) instead of answering as though the
/// feature were never turned on. `"boot"` is the fixed actor; boot has
/// no degraded-subsystem concept of its own (it hard-fails via `?`
/// instead of continuing in a degraded state), so
/// `ReloadOutcome::default`'s empty, fully-applied outcome is exactly
/// right for the entry's `degraded` list.
fn record_boot_config_revision(
    history: Option<&sbproxy_config::ConfigHistoryConfig>,
    content: &[u8],
    origin: sbproxy_config::BaseOrigin,
    actor: &str,
) {
    match crate::config_history::ConfigHistoryRecorder::from_config(history) {
        Ok(Some(recorder)) => {
            // Installed before recording, not after: recording goes
            // through the process-global slot (the same path a later
            // reload uses), which is empty until this call.
            crate::config_history::install_config_history_recorder(std::sync::Arc::new(recorder));
            record_applied_config_revision(
                RevisionRecordingInput {
                    content,
                    origin,
                    actor,
                },
                &ReloadOutcome::default(),
            );
        }
        Ok(None) => {}
        Err(error) => {
            // Contained, not fatal: a boot that has already validated
            // and is about to publish its pipeline must not fail over
            // its own audit trail. The admin history routes surface
            // this explicitly (503) rather than the "not enabled" 404 a
            // node that never opted in gets, so an operator sees the
            // real cause instead of a silently missing ring.
            tracing::error!(
                error = %error,
                "config history: failed to open the revision ring at boot; the proxy is \
                 booting without one"
            );
            crate::config_history::install_config_history_failure(&error.to_string());
        }
    }
}

/// The reload transaction body. Callers hold `CONFIG_RELOAD_LOCK`.
///
/// `source` and `origin_override` name the config revision ring entry
/// this reload should record. `origin_override` is `None` for
/// the file-watcher and SIGHUP paths, whose `yaml` is read straight off
/// the local file and so is resolved into a [`sbproxy_config::BaseOrigin`]
/// the ordinary way, right below. It is `Some` for the config-authority
/// and `source:` refresh-poller paths (see `try_reload_from_config_yaml`),
/// whose `yaml` is already a merged document with no `source:` block of
/// its own to resolve.
fn reload_from_config_yaml_locked(
    config_path: &str,
    yaml: &str,
    source: &str,
    origin_override: Option<sbproxy_config::BaseOrigin>,
) -> anyhow::Result<ReloadOutcome> {
    // Honour `source:` before anything else, so the file watcher,
    // SIGHUP, and `POST /admin/reload` all reload what the source says
    // rather than the pointer at it. A document with no `source:` block
    // resolves to itself and does no I/O, which is every reload on a
    // node whose config is its local file. A document that already came
    // from a source carries no `source:` key, so an apply driven by the
    // refresh poller or by the config-authority subscriber does not
    // re-fetch.
    let resolved = crate::config_source::resolve(yaml)?;
    let compiled = sbproxy_config::compile_config(&resolved.text)?;
    let origin = origin_override.unwrap_or_else(|| resolved.base_origin());
    reload_compiled_config_locked(
        config_path,
        compiled,
        None,
        Some(yaml),
        Some(RevisionRecordingInput {
            content: resolved.text.as_bytes(),
            origin,
            actor: source,
        }),
    )
}

/// Emit one bounded WARN when the OpenAPI document this config produces
/// cannot describe part of it.
///
/// Emission never guesses. A verb OpenAPI 3.0 has no Path Item field for,
/// and a forward rule that loses a path-and-method contest to an earlier
/// one, are both published under an `x-sbproxy-` extension rather than
/// folded onto something untrue. The document is therefore right and
/// nothing is dropped, but standard tooling reads operations and not
/// extensions, so an operator can still end up with a generated client
/// that is missing a route they configured.
///
/// `sbproxy_openapi::build` cannot be the one to say so: it runs on every
/// fetch of `/.well-known/openapi.json`, which takes no credential, so a
/// warn in there is a log-flood primitive any client can pull. These are
/// properties of the config rather than of a request, which is why the
/// place to say it is here, once per config, on the boot and reload
/// paths that already emit `log_capture_header_warnings`.
///
/// One line, not one per finding: a config with many origins and many
/// paths can produce hundreds. The count carries the scale and a capped
/// sample carries enough to find the first one. The sample rides in a
/// structured field rather than the message text, so the subscriber
/// escapes the config-supplied path keys inside it.
fn log_openapi_emission_warnings(compiled: &sbproxy_config::CompiledConfig) {
    // How many findings the sample names before it stops.
    const SAMPLE_LIMIT: usize = 10;

    let findings = sbproxy_openapi::emission_warnings(compiled);
    if findings.is_empty() {
        return;
    }
    let sample = findings
        .iter()
        .take(SAMPLE_LIMIT)
        .map(sbproxy_openapi::EmissionWarning::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!(
        count = findings.len(),
        sample = %sample,
        "the emitted OpenAPI document cannot describe part of this config and publishes an \
         x-sbproxy- extension in place of the operation; a client generated from it will be \
         missing those routes",
    );
}

/// Prepare and publish one already compiled configuration. Callers hold
/// `CONFIG_RELOAD_LOCK` and may supply an already validated bundle candidate.
fn reload_compiled_config_locked(
    config_path: &str,
    compiled: sbproxy_config::CompiledConfig,
    extension_registry: Option<std::sync::Arc<sbproxy_extension::bundle::DynamicBundleRegistry>>,
    drift_yaml: Option<&str>,
    revision: Option<RevisionRecordingInput<'_>>,
) -> anyhow::Result<ReloadOutcome> {
    let config_dir = std::path::Path::new(config_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }
    log_openapi_emission_warnings(&compiled);

    // --- Phase 1: reject-only checks, before anything installs ---

    // Reconcile process-owned cluster identity and listeners before any
    // dependent subsystem observes this candidate configuration. Restart-only
    // changes reject the reload and leave the installed handle untouched.
    crate::cluster::reconcile_process_cluster(&compiled.server)?;

    // The secret resolver assembled from `proxy.secrets:` is set-once
    // for the life of the process, so a changed block can never take
    // effect. Refuse it here rather than accept a config whose secret
    // backends are silently ignored.
    reconcile_process_secrets(compiled.server.secrets.as_ref())?;
    reconcile_boot_only_blocks(&compiled.server, compiled.request_events.as_ref())?;

    // WOR-2481: the boot-only OTLP trace and metric exporters are never
    // rebuilt on reload (see `arm_egress_gates_from_config`'s doc
    // comment for why `Telemetry` is not armed there), so a candidate
    // whose `egress.telemetry:` allowlist newly denies the endpoint they
    // are still dialing must not be allowed to publish silently: refuse
    // the reload here, in the reject-only phase, before anything about
    // this candidate installs.
    sbproxy_observe::telemetry::reverify_active_boot_telemetry_endpoints(
        compiled.egress.telemetry.as_ref(),
    )?;

    let mut outcome = ReloadOutcome::default();

    // --- Phase 2: construct, with the catalog installed and undoable ---

    // WOR-173: refresh the AI provider catalog. This is the only
    // process global that has to move before the pipeline is built:
    // AI handler construction resolves provider names against the live
    // registry and hard-errors on an unknown one. Everything else waits
    // for the commit phase. The rollback guard puts the previous
    // catalog back if any later step of this function fails.
    //
    // Failures to build fall back to the embedded catalog with a
    // warn-level log inside `prepare_provider_registry`, matching the
    // startup behaviour, and leave the live catalog untouched. Note:
    // `BUDGET_TRACKER` is deliberately *not* refreshed - in-memory
    // accumulators must survive reload, see the doc comment on the
    // static.
    let mut registry_rollback = {
        let override_path = compiled
            .server
            .ai_providers_file
            .as_deref()
            .map(std::path::Path::new);
        match sbproxy_ai::prepare_provider_registry(override_path) {
            Ok(prepared) => {
                let rollback =
                    ProviderRegistryRollback::new(sbproxy_ai::provider_registry_snapshot());
                sbproxy_ai::install_prepared_provider_registry(prepared);
                Some(rollback)
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "AI provider registry reload failed; serving with the previous catalog",
                );
                outcome.degrade(DegradedSubsystem::AiProviderRegistry);
                None
            }
        }
    };

    let mut new_pipeline = match extension_registry {
        Some(registry) => {
            CompiledPipeline::from_config_at_with_extension_registry(compiled, registry)?
        }
        None => CompiledPipeline::from_config_at(compiled, config_dir)?,
    };
    preflight_default_safety_centroids(&new_pipeline)?;
    // A settlement runtime that will not start fails the reload before the
    // pipeline is swapped, so the previous generation keeps serving with its
    // store and its worker untouched.
    attach_payments_runtime(&mut new_pipeline)?;

    // WOR-196: pick up `listings/*.yaml` from the same Repo (the
    // directory the served `sb.yml` lives in) and stash the loaded
    // registry on the pipeline. The projection layer reads
    // `pipeline.listings` and renders the per-Listing Agent Skills
    // surface for the well-known endpoints. Load errors are logged
    // at warn level and the registry stays empty; the OSS surface
    // continues to serve the top-level `agent_skills:` block.
    {
        let repo_root = config_dir.to_path_buf();
        let mut load_errors: Vec<sbproxy_config::ListingLoadError> = Vec::new();
        let loaded = sbproxy_config::load_listings_from_repo(&repo_root, &mut load_errors);
        for err in &load_errors {
            tracing::warn!(error = %err, "listings load error; skipping entry");
        }
        if !load_errors.is_empty() {
            outcome.degrade(DegradedSubsystem::Listings);
        }
        if !loaded.is_empty() {
            let mut findings: Vec<sbproxy_config::PlanFinding> = Vec::new();
            new_pipeline.listings =
                sbproxy_config::ListingRegistry::from_loaded(loaded, &mut findings);
            for finding in &findings {
                tracing::warn!(
                    rule_id = %finding.rule_id,
                    path = %finding.path,
                    message = %finding.message,
                    "listing registry finding"
                );
            }
        }
    }

    // Reattach the one linked lifecycle hook before initialization.
    // Collection and initialization are part of candidate construction,
    // so either failure leaves the published pointer unchanged.
    new_pipeline.hooks.startup = crate::hook_registry::try_collect_startup_hook()?;
    if let Some(startup) = new_pipeline.hooks.startup.clone() {
        let hook_result = if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(startup.on_reload(&mut new_pipeline))
            })
        } else {
            let hook_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow::anyhow!("build reload-hook runtime: {error}"))?;
            hook_rt.block_on(startup.on_reload(&mut new_pipeline))
        };
        hook_result
            .map_err(|error| anyhow::anyhow!("pipeline lifecycle hook rejected reload: {error}"))?;
    }
    enforce_cache_at_rest_posture(&new_pipeline)?;
    super::model_host::reconcile_model_runtime_blocking(&new_pipeline, config_dir)
        .map_err(|error| anyhow::anyhow!("model runtime reconciliation failed: {error}"))?;
    // --- Phase 3: commit ---
    //
    // Every fallible step is behind us. From here the reload returns
    // `Ok`, so the process globals below are safe to move: nothing can
    // leave them applied against the previous pipeline. They are read on
    // the request path and the admin path, never during pipeline
    // construction, which is what lets them wait this long. The compiled
    // config was moved into the pipeline, so they read it back through
    // `new_pipeline.config` rather than cloning it.
    if let Some(rollback) = registry_rollback.as_mut() {
        rollback.disarm();
    }
    {
        let compiled = &new_pipeline.config;

        // Config seeds target the external system of record, whose generic
        // backend contract has no cross-record transaction. Apply them only
        // after every reject-only preflight has succeeded. A backend failure
        // degrades this generation but still publishes plane B with pipeline B,
        // never pipeline B against plane A.
        if let Err(e) = crate::key_plane::seed_prepared_key_plane(
            new_pipeline.key_plane(),
            compiled.server.key_management.as_ref(),
        ) {
            tracing::error!(error = %e, "failed to seed dynamic key plane on reload");
            outcome.degrade(DegradedSubsystem::KeyPlane);
        }

        // WOR-594: refresh the operator-configured Lua sandbox limits on
        // reload so SIGHUP / hot-reload pick up changes to
        // `proxy.scripting.lua.sandbox:` without restarting the process.
        sbproxy_extension::lua::install_sandbox_config(
            sbproxy_extension::lua::SandboxConfig::from(&compiled.server.scripting.lua.sandbox),
        );

        // WOR-2319: the JavaScript half of the same block, refreshed on
        // the same schedule.
        install_js_sandbox_limits(&compiled.server);

        // Refresh the operator-extensible log redactor on reload so
        // SIGHUP picks up changes to `proxy.observability.log.redact:`
        // (proxy scope) as well as the tenant-scope and origin-scope
        // `observability.log.redact.pii:` overrides (WOR-1043 PR2 / PR3).
        install_op_redact_state(compiled);

        // The `level:` leaf of the same block, on the same schedule.
        // Boot resolves it in the binary, ahead of the subscriber; this
        // is the only path that can change it afterwards, and it yields
        // to a `--log-level` / `RUST_LOG` override. The sibling
        // `format:` cannot follow: the output layer is fixed once.
        install_config_log_level(&compiled.server);

        // WOR-1067 PR2: refresh per-tenant cardinality caps on reload so
        // SIGHUP picks up changes to `tenants[].observability.cardinality.max_series`
        // without restarting the process. Tenants without an entry stay
        // on the proxy-wide cap.
        install_tenant_cardinality_state(&compiled.server);

        // WOR-1045 PR1 + PR2: validate the declared sinks block and (PR2)
        // build a SinkDispatcher from proxy + tenant + origin scopes so
        // every declared sink receives the matching records. When no
        // sinks block is declared, the dispatcher slot stays empty and
        // the legacy `tracing::*!` fallback continues to drive stdout.
        validate_sinks_config(&compiled.server);
        if !install_sink_dispatcher_from_config(compiled) {
            outcome.degrade(DegradedSubsystem::SinkDispatcher);
        }
        install_usage_rollups_from_config(compiled);
        warn_unwired_decision_audit_events(compiled);
        warn_legacy_policy_record_format(compiled);

        // WOR-2476: arm the AiProvider, ClassifierHook, UsageSink,
        // ModelArtifact, and TokenExchange gates from the compiled
        // `egress:` section, and rebuild the AI client so it picks up
        // `AiProvider`. The shared seam `run` (boot) also calls; see its
        // doc comment for why this is one function with two callers rather
        // than the two-call sequence it replaced.
        arm_egress_gates_from_config(compiled);

        // WOR-1164: refresh the detection singletons (agent-class resolver,
        // TLS-fingerprint catalogue + CEL matcher, agent-detect scorer) so
        // a reload that changed `agent_classes:`, the resolver flags, or
        // `agent_detect.*` takes effect.
        install_detection_singletons(compiled);

        // Publish the candidate key plane as the admin and cluster view. The
        // request path uses the same Arc pinned inside `new_pipeline`, so a
        // request that started on generation A cannot cross into B here.
        crate::key_plane::activate_key_plane(
            new_pipeline.key_plane().cloned(),
            compiled.server.key_management.as_ref(),
        );
    }

    // WOR-1835: same reasoning as the boot path above - retry starting
    // governance dissemination now that this reload's key plane is
    // installed. A no-op once the loop is already running, and a no-op
    // until both clustering and approximate governance are configured.
    crate::cluster::start_governance_dissemination();
    crate::cluster::start_rate_limit_dissemination();
    crate::cluster::start_meter_dissemination();

    reload::load_pipeline(new_pipeline);
    crate::extension_refresh::clear_health();

    // Move the drift baseline here, in the one place every reload path
    // converges, rather than in the individual callers. Only startup and
    // `POST /admin/reload` used to record it, so after a file-watcher or
    // SIGHUP reload `GET /admin/drift` compared the running config against
    // a pre-reload hash and reported drift that did not exist.
    if let Some(yaml) = drift_yaml {
        crate::admin::record_loaded_config_content_hash(&crate::identity::config_revision(
            yaml.as_bytes(),
        ));
    }

    // WOR-2457: record this applied revision into the config history
    // ring, in the same one place every reload path converges, for the
    // same reason the drift baseline moved here above. `revision` is
    // `None` only for the extension-bundle refresh path, which has no
    // new config document to record. `outcome` is complete by this
    // point: every `degrade()` call above already ran.
    if let Some(revision) = revision {
        record_applied_config_revision(revision, &outcome);
    }

    if outcome.is_fully_applied() {
        tracing::info!("config reloaded successfully");
    } else {
        tracing::warn!(
            degraded = %outcome,
            "config reloaded, but some subsystems did not apply; the node is serving the new \
             pipeline with stale state for those subsystems",
        );
    }
    Ok(outcome)
}

/// Digest of a config payload, used as the file watcher's "is this actually
/// different" baseline.
fn config_content_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// The config file's text and the digest of the exact bytes it was computed
/// from, or `None` when the file cannot be read or is not UTF-8.
///
/// One read, two results, and that pairing is the point. Hashing in one read
/// and reloading in another leaves a window for a write to land between them,
/// which records a digest for content the pipeline never loaded. Returning
/// both means the reload uses the bytes that were hashed.
///
/// `None` never compares equal to itself here, so an unreadable file always
/// attempts the reload and lets that path report the real error rather than
/// being silently swallowed as "unchanged".
fn config_file_text_and_digest(path: &std::path::Path) -> Option<([u8; 32], String)> {
    let bytes = std::fs::read(path).ok()?;
    let digest = config_content_digest(&bytes);
    Some((digest, String::from_utf8(bytes).ok()?))
}

/// How long the config watcher waits for a save's event burst to go quiet
/// before it reads the file.
///
/// Long enough that a truncate-then-write or a write-then-rename has landed,
/// short enough that a deliberate config change still applies promptly. It is
/// also the floor on how fast two genuinely different configs can be applied
/// back to back, which is not a rate anyone edits at.
const CONFIG_WATCH_QUIET_PERIOD: std::time::Duration = std::time::Duration::from_millis(250);

/// Hard ceiling on how long one burst may hold off the read.
///
/// The quiet period alone is not safe as a loop condition. The watch is on
/// the config's whole directory and reports every file in it, so a neighbour
/// written more than four times a second, which is an ordinary access log or
/// audit sink, would restart the quiet timer forever and the config would
/// never be read again. That failure is silent: the thread stays alive and
/// blocked, and an operator sees only that their edit did nothing.
///
/// With a ceiling the same busy directory costs a bounded delay instead. A
/// read taken under a still-churning directory can catch a torn file, and
/// that case is already handled: the reload either fails and leaves the
/// baseline alone, or the events still queued drive another pass.
const CONFIG_WATCH_MAX_COALESCE: std::time::Duration = std::time::Duration::from_secs(2);

pub(super) fn start_config_watcher(config_path: String, loaded_digest: [u8; 32]) {
    use notify::{RecursiveMode, Watcher};

    std::thread::spawn(move || {
        // WOR-1162: watch the PARENT directory, not the file itself.
        // inotify (and most backends) bind a file watch to the inode, so
        // an atomic-rename save (vim with backupcopy=no, `sed -i`, most
        // config-management tools) or a Kubernetes ConfigMap symlink swap
        // replaces the inode and a file-level watch never fires again.
        // Watching the directory catches the create/rename of the new
        // file. Reload re-reads `config_path`, so reacting to any relevant
        // event in the directory is correct and idempotent.
        let cfg_path = std::path::PathBuf::from(&config_path);
        let watch_dir = cfg_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "failed to create config file watcher");
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!(error = %e, dir = %watch_dir.display(), "failed to watch config directory");
            return;
        }

        tracing::info!(path = %config_path, dir = %watch_dir.display(), "config file watcher started");

        // Watching the directory is what makes an atomic-rename save visible,
        // but it also reports every unrelated file in that directory. A config
        // sharing a directory with logs, editor swap files, or a neighbouring
        // process's temp files would otherwise reload the pipeline on activity
        // that has nothing to do with it, and a reload is not free: it
        // replaces the compiled origin chain, which discards every live MCP
        // session and makes callers re-initialize.
        //
        // The filter is on content, not on the path. Filtering by path is the
        // obvious move and it is wrong here: under a Kubernetes ConfigMap
        // mount the config is a symlink into `..data`, and an update renames
        // `..data` without ever touching the config file's own name, so a
        // path filter would drop exactly the events the directory watch
        // exists to catch. Reading the file through whatever indirection it
        // has and comparing a digest answers the real question, which is
        // whether the config this process would load has actually moved.
        //
        // The baseline comes from the caller, taken from the bytes boot
        // actually loaded, rather than from a fresh read here. Re-reading is
        // the obvious move and it races: a write landing between boot's read
        // and this thread starting would seed the digest of content the
        // pipeline never loaded, and the event that same write queued would
        // then be discarded as "unchanged", leaving the node on the old
        // config for the rest of its life.
        let mut loaded_digest = Some(loaded_digest);

        while let Ok(first) = rx.recv() {
            match first {
                Err(e) => {
                    tracing::warn!(error = %e, "config file watcher error");
                    continue;
                }
                Ok(event)
                    if !(event.kind.is_modify()
                        || event.kind.is_create()
                        || event.kind.is_remove()) =>
                {
                    continue;
                }
                Ok(_) => {}
            }

            // One save is a burst of events, not an event. `fs::write`
            // truncates and then writes, an editor writes a temp file and
            // renames it, and a ConfigMap swap renames a directory and
            // deletes another. Reading on the first of those sees a file
            // mid-write, and a truncated YAML document is not reliably an
            // invalid one: a prefix that happens to end on a key boundary
            // compiles, and the node would swap to a config missing whatever
            // came after the cut. Waiting for the burst to go quiet is what
            // makes the read see a finished file.
            //
            // Errors arriving during the quiet period are dropped along with
            // everything else in the burst. That is the same trade the
            // coalescing makes everywhere else: the reload below reports any
            // problem that actually matters, from the file itself.
            let burst_deadline = std::time::Instant::now() + CONFIG_WATCH_MAX_COALESCE;
            loop {
                let remaining = burst_deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if rx
                    .recv_timeout(CONFIG_WATCH_QUIET_PERIOD.min(remaining))
                    .is_err()
                {
                    break;
                }
            }

            // WOR-2459 fix round, Major 7. Checked here, before the
            // read, rather than only inside the reload transaction. The
            // transaction's own guard returns `Err`, and every reload
            // that reached it counted as
            // `sbproxy_config_reload_total{result="failure"}` and logged
            // `reload failed; serving prior pipeline` at ERROR, forever,
            // because `loaded_digest` never advances while the pin
            // holds. A pinned node is the state the feature is supposed
            // to be in; it must not be indistinguishable from a fault.
            //
            // No early `continue` here any more: `reload_from_config_text`
            // below owns both the refusal and its accounting, so the
            // watcher and SIGHUP inherit one implementation instead of
            // two that can drift (re-review, new Major 2). What the
            // watcher still owns is not logging a deliberate suspension
            // at ERROR, which it does at the match on the result.
            let current = config_file_text_and_digest(&cfg_path);
            if let Some((digest, _)) = &current {
                if Some(*digest) == loaded_digest {
                    tracing::debug!(
                        path = %config_path,
                        "config file touched but its contents are unchanged; not reloading"
                    );
                    continue;
                }
            }
            tracing::info!(path = %config_path, "config file changed, reloading...");
            // Reload the exact bytes that were hashed, so the digest recorded
            // below describes the config now being served. The outcome's
            // degraded list is already logged by the reload itself; the
            // watcher only needs to know whether the reload was refused
            // outright.
            let (digest, result) = match current {
                Some((digest, yaml)) => {
                    (Some(digest), reload_from_config_text(&config_path, &yaml))
                }
                // Unreadable, so there are no bytes to reload from. Going
                // through the path lets that read fail and report the real
                // error.
                None => (None, reload_from_config_path(&config_path)),
            };
            match result {
                Ok(_) => loaded_digest = digest,
                // A pinned node refusing a local reload is the fallback
                // working, not a fault, and it repeats on every event in
                // that directory for as long as the pin holds. It says so
                // once per event at debug rather than filling the ERROR
                // channel operators read.
                Err(ref e) if is_suspended_reload(e) => {
                    tracing::debug!(
                        path = %config_path,
                        "the config file changed, but this node is pinned to a configuration \
                         its boot fallback restored; clear the pin with \
                         DELETE /admin/config/fallback to apply it",
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "reload failed; serving prior pipeline");
                }
            }
        }

        // Only reachable once the watcher has been dropped, which means no
        // further config change will ever be seen. Say so: without this a
        // dead watcher and a quiet one look identical from the outside, and
        // the symptom either way is an edit that does nothing.
        tracing::error!(
            path = %config_path,
            "config file watcher stopped; config changes will no longer be applied"
        );
    });
}

/// Install a SIGHUP signal handler that reloads the proxy pipeline
/// from `config_path`.
///
/// SIGHUP is the canonical "rerun bootstrap" signal in traditional
/// reverse proxies (nginx, haproxy). This function spawns a tokio
/// task that listens on the OS signal and calls
/// [`reload_from_config_path`] for each delivery. Multiple SIGHUPs
/// arriving back-to-back coalesce into multiple reloads (last write
/// wins on the `ArcSwap` inside `reload::load_pipeline`).
///
/// On non-Unix targets this is a no-op (Windows et al. have no
/// SIGHUP equivalent).
#[cfg(unix)]
pub fn install_sighup_handler(config_path: String) {
    use tokio::signal::unix::{signal, SignalKind};
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!(
            "no tokio runtime in scope; SIGHUP handler not installed (call from inside the tokio runtime)",
        );
        return;
    }
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        tracing::info!("SIGHUP handler installed; send `kill -HUP <pid>` to reload");
        while sig.recv().await.is_some() {
            tracing::info!("SIGHUP received; reloading config...");
            // WOR-618: `reload_from_config_path` does blocking config-file
            // reads, YAML parsing, pipeline rebuild, and projection refresh.
            // Run it on the blocking pool so the tokio worker that owns
            // the SIGHUP listener stays responsive to other signals.
            let path = config_path.clone();
            let result = tokio::task::spawn_blocking(move || reload_from_config_path(&path)).await;
            match result {
                // A degraded-but-applied reload already logged its own
                // warning naming the subsystems; nothing to add here.
                Ok(Ok(_outcome)) => {}
                // A pinned node refusing SIGHUP is the fallback working,
                // not a fault, and `logrotate` postrotate hooks send
                // SIGHUP on a schedule, so a healthy pinned node would
                // otherwise fill the ERROR channel once per rotation.
                // The same arm the watcher already has, four lines down
                // a different path (verification residual R4).
                Ok(Err(ref e)) if is_suspended_reload(e) => {
                    tracing::debug!(
                        "SIGHUP arrived, but this node is pinned to a configuration its boot \
                         fallback restored; clear the pin with DELETE /admin/config/fallback \
                         to apply the file",
                    );
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "SIGHUP reload failed; serving prior pipeline");
                }
                Err(join_err) => {
                    tracing::error!(
                        error = %join_err,
                        "SIGHUP reload task panicked; serving prior pipeline",
                    );
                }
            }
        }
    });
}

/// Build and publish the settlement runtime for a freshly compiled pipeline.
///
/// A no-op when `proxy.payments` is absent, which is the default and leaves
/// the existing non-settlement ledger behaviour exactly as it was.
///
/// Failure is fatal to the pipeline rather than degrading. Every other
/// subsystem in this file that fails at boot can serve without itself:
/// alerting stops evaluating, listings serve empty. Settlement cannot,
/// because the thing it would degrade to is answering a payer's credential
/// without a durable record of what was charged.
///
/// # Errors
///
/// Returns the startup failure, which names the configuration surface the
/// operator wrote.
#[cfg(feature = "payments")]
fn attach_payments_runtime(pipeline: &mut CompiledPipeline) -> anyhow::Result<()> {
    let Some(payments) = pipeline.config.server.payments.clone() else {
        return Ok(());
    };
    let clustered = pipeline.config.server.cluster.is_some();
    let extension_chain = pipeline.payment_extension_chain().cloned().ok_or_else(|| {
        anyhow::anyhow!("proxy.payments payment extension chain was not prepared")
    })?;
    let attached_inventory = if extension_chain.is_empty() {
        None
    } else {
        Some(pipeline.inventory_with_payment_extensions_attached()?)
    };
    let runtime = if extension_chain.is_empty() {
        crate::billing_runtime::install(&payments, clustered)
    } else {
        let dispatcher = std::sync::Arc::new(
            crate::payment_extensions::BundlePaymentEventDispatcher::new(extension_chain),
        );
        crate::billing_runtime::install_with_payment_dispatcher(&payments, clustered, dispatcher)
    }
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    tracing::info!(
        rails = ?runtime.rails(),
        schema_version = runtime.status().schema_version,
        "payment settlement runtime published",
    );
    if let Some(inventory) = attached_inventory {
        pipeline.mark_payment_extensions_attached(inventory);
    }
    pipeline.payments = Some(runtime);
    Ok(())
}

/// Settlement is not compiled into this build.
///
/// A configured `proxy.payments` block still fails, and names the feature,
/// rather than being parsed and quietly ignored. The configuration crate
/// carries no `cfg` of its own precisely so this check lives here.
#[cfg(not(feature = "payments"))]
fn attach_payments_runtime(pipeline: &mut CompiledPipeline) -> anyhow::Result<()> {
    if pipeline.config.server.payments.is_some() {
        anyhow::bail!(
            "proxy.payments is configured but this binary was built without the `payments` \
             cargo feature, so it has no settlement store, no authoritative service, and no \
             recovery worker. Rebuild with `--features payments` plus the flag for each rail \
             the routes advertise, or remove the block"
        );
    }
    Ok(())
}

/// SIGHUP handler is a no-op on non-Unix targets.
#[cfg(not(unix))]
pub fn install_sighup_handler(_config_path: String) {
    tracing::debug!("SIGHUP handler is unix-only; skipping on this target");
}

/// Resolve the graceful-shutdown grace period (in whole seconds) from
/// the two supported env vars. WOR-636.
///
/// Precedence (highest wins):
/// 1. `SBPROXY_SHUTDOWN_GRACE_MS` (milliseconds, current canonical
///    spelling)
/// 2. `SB_GRACE_TIME` (seconds, legacy)
/// 3. `0` (Pingora's instant-shutdown default; the binary wrapper
///    overlays a 30s default before this is called)
///
/// Pingora's `grace_period_seconds` is a whole-second field, so the
/// millisecond value rounds up to the next whole second when it does
/// not divide evenly. A value of `0` is preserved as `0`. A value
/// that fails to parse logs a warning and falls through to the next
/// source.
pub(crate) fn resolve_shutdown_grace_seconds(ms_var: Option<&str>, sec_var: Option<&str>) -> u64 {
    if let Some(v) = ms_var {
        match v.parse::<u64>() {
            Ok(ms) => {
                // Round milliseconds up to the next whole second so a
                // 500ms grace still gives an in-flight request a full
                // second to drain. Saturates at u64::MAX / 1000.
                let secs = ms.saturating_add(999) / 1000;
                return secs;
            }
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "SBPROXY_SHUTDOWN_GRACE_MS is not a non-negative integer; ignoring"
                );
            }
        }
    }
    if let Some(v) = sec_var {
        match v.parse::<u64>() {
            Ok(s) => return s,
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "SB_GRACE_TIME is not a non-negative integer; ignoring"
                );
            }
        }
    }
    0
}

/// Graceful-shutdown grace-period inputs for [`run`].
///
/// The binary (`crates/sbproxy/src/main.rs`) resolves these from its
/// CLI flags / env (`--shutdown-grace-ms` / `SBPROXY_SHUTDOWN_GRACE_MS`
/// and `--grace-time` / `SB_GRACE_TIME`) and passes them in explicitly,
/// rather than re-exporting them as process env vars for `run` to read
/// back. Both `None` means the in-process default of zero (instant
/// shutdown), which the Go e2e runner and dev loops rely on.
#[derive(Debug, Default, Clone, Copy)]
pub struct GraceConfig {
    /// Preferred source: shutdown grace in milliseconds.
    pub shutdown_grace_ms: Option<u64>,
    /// Legacy source: grace in whole seconds (`SB_GRACE_TIME`).
    pub grace_time_secs: Option<u64>,
}

/// Ask the local mesh node to tell peers it is leaving. Invoked from
/// the shutdown-phase logger so a SIGTERM announces `Left` during the
/// grace window rather than waiting for `MeshNode` drop.
fn announce_mesh_leave() {
    let Some(handle) = crate::cluster::current_cluster_handle() else {
        return;
    };
    let Some(mesh) = handle.mesh_node() else {
        return;
    };
    mesh.leave();
}

/// Spawn a background thread that subscribes to the Pingora server's
/// `execution_phase_watch` broadcast and emits structured tracing
/// events at each transition. WOR-636.
///
/// Pingora handles SIGINT (fast shutdown) and SIGTERM (graceful
/// shutdown) inside [`pingora_core::server::Server::run`].
/// The phase broadcast is the documented surface for observing those
/// transitions from outside the Pingora runtime; emitting our own
/// `tracing` events here means operators see a clear "shutdown
/// signal received" log line in the same stream as the request logs,
/// and the `shutdown.kind` / `shutdown.grace_seconds` fields make the
/// event filterable by structured-log consumers.
///
/// The subscriber must be acquired **before** `Server::run`
/// consumes the `Server` value; this function is a no-op when called
/// after that point because the broadcast sender is dropped.
pub(super) fn spawn_shutdown_phase_logger(
    mut rx: tokio::sync::broadcast::Receiver<pingora_core::server::ExecutionPhase>,
    grace_seconds: u64,
) {
    std::thread::Builder::new()
        .name("sbproxy-shutdown-log".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to build shutdown-phase logger runtime; structured shutdown logs disabled"
                    );
                    return;
                }
            };
            rt.block_on(async move {
                loop {
                    match rx.recv().await {
                        Ok(pingora_core::server::ExecutionPhase::GracefulTerminate) => {
                            tracing::info!(
                                event = "shutdown_signal_received",
                                signal = "SIGTERM",
                                kind = "graceful",
                                grace_seconds = grace_seconds,
                                "SIGTERM received; draining in-flight requests"
                            );
                            announce_mesh_leave();
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownStarted) => {
                            tracing::info!(
                                event = "shutdown_started",
                                grace_seconds = grace_seconds,
                                "shutdown started"
                            );
                            announce_mesh_leave();
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownGracePeriod) => {
                            tracing::info!(
                                event = "shutdown_grace_period",
                                grace_seconds = grace_seconds,
                                "graceful shutdown grace period started"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::ShutdownRuntimes) => {
                            tracing::info!(
                                event = "shutdown_runtimes",
                                "waiting for service runtimes to exit"
                            );
                        }
                        Ok(pingora_core::server::ExecutionPhase::Terminated) => {
                            tracing::info!(event = "shutdown_complete", "sbproxy has stopped");
                            break;
                        }
                        Ok(_) => {
                            // Earlier phases (Running, etc.) are not
                            // shutdown-related; skip them.
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped = skipped,
                                "shutdown-phase logger lagged behind Pingora's phase broadcast"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            // Sender dropped: the server is fully
                            // torn down. Nothing more to log.
                            break;
                        }
                    }
                }
            });
        })
        .ok();
}

/// Resolve the admin-operator password pepper, failing loud only when it is
/// actually needed.
///
/// Reads `key_management.crypto.pepper` straight from config (independent
/// of whether the dynamic key plane is enabled) and falls back to
/// [`crate::key_plane::default_admin_operator_pepper`] when unset, so
/// operator login works with no `key_management:` block at all.
///
/// An unresolvable pepper reference (e.g. `env:` naming an unset variable)
/// only fails boot when `operators_configured` is true: `proxy.admin.operators`
/// entries carry a `password_hash` that must verify against this pepper, so
/// a bad reference there matches the repo's resolve-at-boot-or-fail-loud
/// convention for secret references. With no operators configured, nothing
/// depends on the pepper resolving, so a bad reference degrades to a logged
/// warning and the default pepper, the same way `key_plane::init_key_plane`
/// degrades rather than aborting boot.
fn resolve_or_default_admin_operator_pepper(
    key_management: Option<&sbproxy_config::types::KeyManagementConfig>,
    operators_configured: bool,
) -> anyhow::Result<Vec<u8>> {
    match crate::key_plane::resolve_admin_operator_pepper(key_management) {
        Ok(pepper) => Ok(pepper),
        Err(e) if !operators_configured => {
            tracing::warn!(
                error = %e,
                "key_management.crypto.pepper did not resolve, but no proxy.admin.operators \
                 are configured, so nothing needs it; falling back to the default \
                 admin-operator pepper"
            );
            Ok(crate::key_plane::default_admin_operator_pepper())
        }
        Err(e) => Err(anyhow::anyhow!(
            "resolve admin operator pepper (required: proxy.admin.operators is configured, \
             and their password_hash values must verify against it): {e}"
        )),
    }
}

/// Resolve the document this process should boot on, walking the config
/// revision ring when the configured one does not work (WOR-2459).
///
/// Returns the document and, when the ring rescued the boot, which entry
/// it came from. On every node that did not ask for a fallback this is
/// exactly the read it replaced: read the file, hand it back, and let
/// the caller's own compile report any problem, so `fallback: off`
/// behavior is byte identical to what shipped before.
///
/// The "does it work" test the walk applies is `source:` resolution,
/// `compile_config`, and a construct check, the same three steps `run`
/// performs on the primary document immediately after this returns. A
/// candidate that passes them and then fails later in `run` (a port
/// already bound, a model runtime that will not start) leaves its boot
/// counter incremented, which is what makes the next boot move past it
/// after `max_attempts`.
fn boot_document(
    config_path: &str,
    fallback: Option<sbproxy_config::BootFallbackMode>,
) -> anyhow::Result<(String, Option<crate::config_boot::PinnedRevision>)> {
    let read = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", config_path, e));

    // Resolve the mode before touching the document, and hand an `off`
    // node its bytes back untouched. Pre-checking first was a real cost:
    // it ran `config_source::resolve` and `compile_config` on top of the
    // pair `run` already runs twenty lines later, so a git-sourced node
    // paid two fetches per boot, and it flattened the failure through
    // `format!("{:#}")` and re-wrapped it, losing the anyhow chain that
    // `run`'s own error carries. On the default `off` path there is now
    // no pre-check at all and the behavior is byte-identical to the
    // release before this one (WOR-2459 fix round, Major 6).
    let mode = match crate::config_boot::mode_from_flag_or_env(
        fallback,
        std::env::var("SB_CONFIG_FALLBACK").ok().as_deref(),
    ) {
        Some(mode) => mode,
        // Neither the flag nor the environment decided, so the file's
        // own `boot.fallback` does, which costs one parse of a document
        // that is about to be parsed anyway.
        None => {
            crate::config_boot::history_config_from_broken_document(
                read.as_deref().unwrap_or_default(),
            )
            .boot
            .fallback
        }
    };
    if mode == sbproxy_config::BootFallbackMode::Off {
        return read.map(|yaml| (yaml, None));
    }

    // Only a node that asked for a fallback pays the pre-check, and it
    // has to: the walk cannot know the configured document failed
    // without trying it, and it applies the same three steps to a
    // candidate so "works" means the same thing on both sides.
    // The configured document's own directory: a relative
    // extension-bundle path resolves against it at boot, so the
    // construct check has to use the same base.
    let base_dir = std::path::Path::new(config_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let primary = match &read {
        Ok(yaml) => match boot_candidate_compiles(yaml, &base_dir) {
            Ok(()) => return Ok((yaml.clone(), None)),
            Err(reason) => anyhow::anyhow!("{reason}"),
        },
        Err(_) => match read {
            Ok(_) => unreachable!("the Ok arm returned above"),
            Err(error) => error,
        },
    };
    let boot_config = crate::config_boot::history_config_from_broken_document(
        &std::fs::read_to_string(config_path).unwrap_or_default(),
    );

    // Scrubbed for the same reason the pin four lines below is: this
    // string is a compile or resolve failure over an operator-authored
    // document, and the secret resolver echoes an inlined literal
    // credential verbatim into it. The pin was scrubbed when it became a
    // product surface and this log line was left, which made the
    // unscrubbed twin the easier of the two to read.
    tracing::error!(
        error = %crate::config_boot::scrub_boot_failure(&format!("{primary:#}")),
        "the configured document did not boot; walking the config revision ring for the last \
         known good configuration",
    );
    match crate::config_boot::walk_for_bootable(
        &boot_config,
        boot_config.boot.max_attempts,
        |yaml| boot_candidate_compiles(yaml, &base_dir),
    ) {
        Ok(document) => {
            // The pin carries why the configured document failed, not
            // only which revision rescued the node. A controller that
            // suspends reconciliation on this pin has to be able to say
            // what it is waiting for (WOR-2467).
            let pinned = crate::config_boot::PinnedRevision::with_reason(
                document.pinned.revision,
                document.pinned.digest.clone(),
                &format!("{primary:#}"),
            );
            crate::config_boot::mark_on_fallback(pinned.clone());
            crate::config_boot::spawn_boot_success_timer(
                pinned.revision,
                boot_config.boot.success_secs,
            );
            Ok((document.yaml, Some(pinned)))
        }
        // An empty ring is a first boot: exit exactly the way `off`
        // does, saying the ring was empty rather than pretending a
        // fallback was attempted.
        // Scrubbed on the way out, like the pin and the log line above.
        // This error is printed by `eprintln!("Fatal: ...")`, which in
        // Kubernetes is pod logs: a wider audience than the operator's
        // own terminal, and wider than the config file they already
        // hold. `--config-fallback=off` still returns the raw error and
        // that path is not this change's to widen.
        Err(failure @ crate::config_boot::BootWalkFailure::RingEmpty)
        | Err(failure @ crate::config_boot::BootWalkFailure::StoreUnavailable(_)) => {
            Err(anyhow::anyhow!(
                "{}: {}",
                crate::config_boot::scrub_boot_failure(&format!("{primary:#}")),
                // The failure half too, not only the primary. Both end
                // up in the same `eprintln!("Fatal: ...")`, and
                // `StoreUnavailable` carries an unbounded store-open
                // string that the first argument's scrub does not reach.
                crate::config_boot::scrub_boot_failure(&format!("{failure}")),
            ))
        }
        // Every `FailedCandidate::reason` this renders was sanitized
        // when it was built, so this is bounded per candidate; the
        // wrapper text around them is this crate's own.
        Err(failure) => Err(anyhow::anyhow!("{failure}")),
    }
}

/// Whether one candidate document resolves its `source:` pointer,
/// compiles, **and constructs**.
///
/// The third step is the one that matters and the one this used to be
/// missing. `compile_config` leaves `action`, `policies`, `transforms`
/// and `authentication` as opaque JSON, so an unknown action type, a
/// policy that will not build, a bad regex, or a JSON schema that does
/// not compile all pass it and then fail in
/// `CompiledPipeline::from_config_at` well after this decision has been
/// made. Module construction is where most operator typos land, so
/// "works" without it excluded the majority of the failures a boot
/// fallback exists for.
///
/// The cost of the gap was worse on the **primary** document than on a
/// candidate. A primary that compiled returned early and skipped the
/// walk entirely, so a node whose operator had asked for a fallback
/// exited fatally with no pin, no boot counter, and no walk, and every
/// restart repeated it.
///
/// [`crate::pipeline::CompiledPipeline::from_config_for_validation_at`]
/// is the purpose-built construct check the config authority already
/// runs before it publishes a payload to a fleet, under
/// `PipelineConstructionMode::Validation` with no background tasks
/// started and no listener bound. Using it here makes the boot
/// fallback's "does this work" test the same question every other
/// pre-apply gate in this workspace asks.
///
/// # What it is not
///
/// It is **not** side-effect free, and its own documentation says so:
/// module construction reads the AI provider registry, resolves secret
/// references through the process secret resolver, populates the shared
/// JWKS cache, and loads extension bundles, which for a `Git` source is
/// a real fetch that can block for the source timeout. Those are reads
/// and idempotent inserts rather than installs, so repeated calls are
/// safe, but a caller cannot treat this as a pure function and this one
/// does not.
///
/// Two consequences worth stating rather than discovering. A
/// fallback-enabled node with a git-sourced extension bundle pays that
/// fetch here and again in `run`, and each ring candidate the walk
/// tries pays it once; the cost is bounded by the source timeout and by
/// `max_attempts`, and it is the price of knowing a candidate
/// constructs before booting onto it. And a candidate whose bundle
/// source is unreachable fails this check, so a network partition
/// during a rescue boot makes a candidate look unbootable when it is
/// only unfetchable. Both are on the fallback path only: a node with
/// `fallback: off` never reaches this function.
///
/// `base_dir` is the configured document's own directory, because a
/// relative extension-bundle path in a candidate resolves against it
/// exactly as it would at boot.
fn boot_candidate_compiles(yaml: &str, base_dir: &std::path::Path) -> Result<(), String> {
    let resolved = crate::config_source::resolve(yaml).map_err(|error| format!("{error:#}"))?;
    let compiled =
        sbproxy_config::compile_config(&resolved.text).map_err(|error| format!("{error:#}"))?;
    crate::pipeline::CompiledPipeline::from_config_for_validation_at(compiled, base_dir)
        .map_err(|error| format!("{error:#}"))?;
    Ok(())
}

/// Create and start a Pingora server with the given config file path.
///
/// This function:
/// 1. Reads and compiles the YAML config
/// 2. Compiles it into a pipeline with module instances
/// 3. Loads it into the hot-reload store
/// 4. Starts a file watcher for config hot-reload
/// 5. Creates a Pingora server with an HTTP proxy service
/// 6. Starts the server (blocks forever)
///
/// Pingora handles SIGTERM (graceful shutdown) and SIGINT (fast
/// shutdown) internally inside `Server::run`. We subscribe
/// to Pingora's execution-phase broadcast (see
/// `spawn_shutdown_phase_logger`) so a structured tracing event is
/// emitted when a shutdown signal arrives; operators can grep for
/// `shutdown_signal_received` in the logs to see the drain start.
/// The grace period comes from the [`GraceConfig`] the binary passes
/// in (preferring `shutdown_grace_ms` over `grace_time_secs`), resolved
/// to seconds by `resolve_shutdown_grace_seconds`. The file watcher
/// handles config reload on file change,
/// which is equivalent to SIGHUP-based reload in traditional
/// servers.
pub fn run(config_path: &str, grace: GraceConfig) -> anyhow::Result<()> {
    run_with_fallback(config_path, grace, None)
}

/// As [`run`], with the `--config-fallback` mode the binary resolved
/// (WOR-2459).
///
/// `fallback` is `None` when the caller has no opinion, which means the
/// mode comes from `SB_CONFIG_FALLBACK` or from
/// `proxy.config_history.boot.fallback`, in that order. The command-line
/// flag wins over both, deliberately: a rescue boot must not depend on
/// the file being right, and the file is what is broken. See
/// [`crate::config_boot`].
///
/// # Errors
///
/// As [`run`]. Additionally, when the fallback walked the whole ring and
/// nothing booted, the returned error is the one
/// the crate-private `config_boot::BootWalkFailure` renders, naming every
/// revision tried and why; the binary turns that into
/// [`crate::config_boot::EXIT_CONFIG_RING_EXHAUSTED`] rather than the
/// plain `1` every other fatal boot failure uses.
pub fn run_with_fallback(
    config_path: &str,
    grace: GraceConfig,
    fallback: Option<sbproxy_config::BootFallbackMode>,
) -> anyhow::Result<()> {
    use pingora_core::apps::HttpServerOptions;
    use pingora_core::server::configuration::ServerConf as PingoraServerConf;
    use pingora_core::server::Server;
    use pingora_proxy::http_proxy_service;

    // Recover exact engines left by a prior forced gateway exit before
    // reading desired state. This also cleans up when the replacement
    // configuration no longer contains a model host, and keeps recovery
    // ahead of listener bind and any replacement-engine spawn.
    let recovered_engines =
        sbproxy_model_host::reap_stale_managed_engines(std::time::Duration::from_secs(5))
            .map_err(|error| anyhow::anyhow!("recover stale managed engines at boot: {error}"))?;
    if recovered_engines > 0 {
        tracing::info!(
            recovered_engines,
            "recovered stale managed engines before gateway boot"
        );
    }

    // Load and compile the config. WOR-2459: when the document this node
    // was told to boot on does not work and the operator asked for a
    // fallback, walk the revision ring for one that does before giving
    // up. `boot_fallback_document` is a no-op on every node that did not
    // ask, so the historical behavior (read, fail, exit) is byte
    // identical there.
    let (yaml, fallback_pin) = boot_document(config_path, fallback)?;
    // The drift baseline is the LOCAL file, deliberately captured before
    // any authority bundle is folded in: `GET /admin/drift` answers "has
    // the file on disk changed since we read it?", and a subscriber whose
    // baseline was the merged document would report drift on every scrape
    // forever.
    let initial_content_hash = crate::identity::config_revision(yaml.as_bytes());
    // The file watcher's baseline, taken from the same local bytes and for the
    // same reason: the watcher watches the file on disk, so what it compares
    // against has to be the file this process read and not the document a
    // `source:` pointer resolved to.
    let initial_file_digest = config_content_digest(yaml.as_bytes());

    // Honour `source:` first. Resolution order is fixed and documented:
    // the source produces the base document, then the config-authority
    // overlay goes on top of it, then it compiles. A file with no
    // `source:` block resolves to itself and does no I/O, so this is
    // free on the historical path. A failure here is fatal on purpose: a
    // node whose configuration lives in a repository it cannot reach has
    // nothing to serve, and booting on the pointer file would serve an
    // empty configuration while reporting success.
    let resolved_source = crate::config_source::resolve(&yaml)?;
    if resolved_source.is_remote() {
        // Published before the subscriber is built, because the merge
        // base a subscriber uses is this document rather than the pointer
        // file on disk.
        crate::config_source::publish_resolved_base(crate::config_source::ResolvedBase {
            yaml: resolved_source.text.clone(),
            origin: resolved_source.base_origin(),
            fingerprint: resolved_source.revision_fingerprint(),
        });
    }
    let source_poller =
        crate::config_source::SourcePoller::from_boot(config_path, &yaml, &resolved_source)?;
    let yaml = resolved_source.text.clone();
    let compiled = sbproxy_config::compile_config(&yaml)?;
    // Fold a cached config-authority bundle into the boot document before
    // anything downstream reads the compiled config: listener ports, TLS
    // hostnames, and the request pipeline all have to describe the
    // configuration this node actually serves. A no-op when
    // `proxy.config_authority.upstream` is absent, and an error (so the
    // process exits) when the subscriber requires a bundle it does not
    // have. No network I/O happens here; see the module docs.
    // The drift baseline is deliberately the local file captured above,
    // not this document; `effective_yaml` is kept for the config
    // history ring (WOR-2457) below, which records what this node
    // actually booted rather than the file on disk.
    let (effective_yaml, compiled, config_subscriber) =
        crate::config_subscriber::fold_boot_bundle(config_path, yaml, compiled)?;
    // Captured before `compiled` is consumed into the pipeline below, so
    // `proxy.config_history` is available at the ring-record call site
    // near `reload::load_pipeline(pipeline)` without holding onto
    // `compiled` itself past its normal lifetime.
    let boot_history_config = compiled.server.config_history.clone();
    let boot_config_origin = resolved_source.base_origin();
    let extension_refresh_poller = crate::extension_refresh::BundleRefreshPoller::from_config(
        config_path,
        &compiled.extension_bundles,
    );

    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }
    // Boot needs this as much as reload does: an operator who starts with
    // a colliding config would otherwise hear nothing until the first
    // reload, which may never come.
    log_openapi_emission_warnings(&compiled);
    let port = compiled.server.http_bind_port;
    // WOR-2199: one address for both public listeners. Validated at
    // config compile, so formatting it into a socket address here cannot
    // produce something the listener will reject.
    let bind_address = compiled.server.effective_bind_address().to_string();

    // Extract TLS-relevant fields before compiled is consumed by from_config.
    let server_config = compiled.server.clone();
    let hostnames: Vec<String> = compiled.host_map.keys().map(|k| k.to_string()).collect();

    // Pin the `proxy.secrets:` block this process owns. The binary
    // installs the matching resolver into a set-once slot before it
    // calls `run`, so every later reload must present the same block;
    // `reconcile_process_secrets` rejects the ones that do not.
    record_process_secrets_fingerprint(server_config.secrets.as_ref());
    record_boot_only_fingerprints(&server_config, compiled.request_events.as_ref());

    if let Some(metrics_cfg) = server_config.metrics.as_ref() {
        let _ = sbproxy_observe::metrics::init_cardinality_limiter(
            sbproxy_observe::CardinalityConfig {
                max_per_label: metrics_cfg.max_cardinality_per_label,
                hostname_cap: metrics_cfg.cardinality.hostname_cap,
            },
        );
    }

    // Install operator-extensible redaction state into the global
    // log redactor. Compiled patterns + the extra field-key denylist
    // come from `proxy.observability.log.redact:`; an absent block
    // installs an empty state so the call site stays uniform across
    // single-tenant and multi-tenant deployments. The hook accepts
    // re-install so config reloads flow through. Tenant- and
    // origin-scope `observability.log.redact.pii:` overrides
    // (WOR-1043 PR2 / PR3) are composed off the proxy-scope rule set.
    install_op_redact_state(&compiled);
    install_tenant_cardinality_state(&server_config);
    validate_sinks_config(&server_config);
    // Boot has nothing to degrade into: the install result is already
    // logged and metered inside the helper.
    let _sinks_installed = install_sink_dispatcher_from_config(&compiled);
    // WOR-1875: this is the startup path (the earlier call site runs
    // on reload); the installer is set-once so both calling is safe.
    install_usage_rollups_from_config(&compiled);
    warn_unwired_decision_audit_events(&compiled);
    warn_legacy_policy_record_format(&compiled);
    // WOR-2476: this is the startup path (the earlier call site runs on
    // reload); arms the AiProvider/ClassifierHook/UsageSink/ModelArtifact/
    // TokenExchange registry and rebuilds the AI client before the pipeline
    // below is published, so a `deny_by_default` `egress:` section is live
    // from this process's very first request, not just from its first reload.
    arm_egress_gates_from_config(&compiled);

    // Walk the inventory-based plugin registry once at startup and
    // emit one `sbproxy_plugin_registered_total{kind, plugin}` row
    // per known registration. Subsequent reloads do not re-walk
    // because the inventory set is fixed at link time.
    report_plugin_registrations();

    // WOR-594: install the operator-configured Lua sandbox limits
    // into the extension crate's process-wide handle. Every
    // `LuaEngine::new()` after this point (request modifiers, response
    // modifiers, WAF custom rules, JSON transforms) picks up these
    // values; before this runs, the documented defaults are in
    // effect.
    sbproxy_extension::lua::install_sandbox_config(sbproxy_extension::lua::SandboxConfig::from(
        &server_config.scripting.lua.sandbox,
    ));

    // WOR-2319: same for `proxy.scripting.javascript.sandbox:`. Every
    // `JsEngine::new()` after this point (response modifiers, JSON and
    // body transforms, WAF custom rules, MCP adapters, custom log
    // fields) picks up these values; before this runs, the documented
    // defaults are in effect.
    install_js_sandbox_limits(&server_config);

    // Initialise the AI provider catalog from the embedded YAML, with
    // an optional override path from `proxy.ai_providers_file`: use
    // the override file when readable, fall back to the embedded
    // gzipped catalog otherwise. The registry lives behind an
    // `ArcSwap` so SIGHUP / file-watcher / admin reload paths can
    // swap in a fresh catalog via `reload_provider_registry` without
    // restarting the process.
    {
        let override_path = server_config
            .ai_providers_file
            .as_deref()
            .map(std::path::Path::new);
        if let Err(e) = sbproxy_ai::providers::init_provider_registry(override_path) {
            tracing::error!(
                error = %e,
                "failed to initialise AI provider registry; falling back to embedded defaults on first lookup"
            );
        }
    }

    // --- WOR-1130: install the workspace rate-limit budget registry ---
    //
    // Startup-only: the budget keeps accumulated state across reloads
    // (like `BUDGET_TRACKER`), so it is deliberately not refreshed from
    // the hot-reload path.
    if let Some(rl) = compiled.rate_limits.as_ref() {
        crate::rate_limit_budget::install_registry(rl);
    }

    // Install the one process-owned cluster before pipeline construction so a
    // candidate mesh-backed key plane consumes this handle instead of opening
    // duplicate listeners.
    crate::cluster::reconcile_process_cluster(&server_config)?;

    // --- WOR-2318: open the tamper-evident security audit trail ---
    //
    // Before the pipeline, and with a `?`. Every other sink around this
    // one degrades on failure; this one stops the boot, because a proxy
    // that serves traffic with the audit trail its operator configured
    // missing is the failure the trail exists to make impossible.
    if let Some(cfg) = compiled.audit.as_ref() {
        install_audit_chain(cfg, server_config.web_bot_auth.as_ref())?;
    }

    // --- WOR-1186: register the session-ledger sink when enabled ---
    //
    // Startup-only and set-once: the ledger sink is process-global like
    // the request-event sink. A reload does not re-register it.
    if let Some(cfg) = compiled.session_ledger.as_ref() {
        if cfg.enabled {
            install_session_ledger_sink(cfg);
        }
    }

    // --- WOR-2318: register the request-event sink when configured ---
    //
    // Same startup-only, set-once shape as the ledger sink above. The
    // default `sink: none` registers nothing, which keeps
    // `dispatch_request_event` a no-op exactly as it was before the
    // block existed.
    if let Some(cfg) = compiled.request_events.as_ref() {
        install_request_event_sink(cfg);
    }

    // --- WOR-2318: start the typed-proxy-event egress when configured ---
    //
    // Fatal on failure, unlike the two sinks above. `events:` names an
    // endpoint or a file an operator is relying on to see denials; a
    // proxy that starts anyway is one whose SIEM is empty for a reason
    // nobody will look for until an incident. `sink: none` (the default)
    // starts nothing and cannot fail.
    if let Some(cfg) = compiled.events.as_ref() {
        install_event_egress(cfg)?;
        warn_unwired_proxy_events(cfg);
    }

    // --- WOR-2486: bridge egress refusals onto the typed event feed ---
    //
    // Unconditional, unlike the two sinks above: `sbproxy-security` is a
    // leaf crate that cannot depend on `sbproxy-observe` (see the doc on
    // `sbproxy_security::egress::install_egress_refused_hook`), so this
    // is the one place the bridge can be wired regardless of whether
    // `events:` is configured. The hook itself is a relaxed load when no
    // egress is installed, so registering it costs nothing on a
    // deployment that never sets `events:`.
    let _ = sbproxy_security::egress::install_egress_refused_hook(
        sbproxy_observe::egress_bridge::bridge,
    );

    // WOR-1164: install the detection singletons (agent-class resolver,
    // TLS-fingerprint catalogue + CEL matcher, agent-detect scorer).
    // The same helper runs from `reload_from_config_path_inner` so a
    // SIGHUP that changed `agent_classes:`, the resolver flags, or
    // `agent_detect.*` swaps the live value instead of silently keeping
    // the boot-time value.
    install_detection_singletons(&compiled);

    // --- WOR-201 PR 1b: install policy verdict audit bus ---
    //
    // Construct a bounded mpsc channel and install the sender as the
    // process-wide audit bus before the pipeline is loaded. The queue
    // carries an `AuditRecord`: the dispatcher emits a
    // `PolicyVerdictEvent` for every policy decision, and the decision
    // family emits a `DecisionAudit` for every emitting decision point
    // an operator has enabled. One channel for both, so the two arrive
    // in the order they happened for a given request. The default drain
    // stub on the receiver prints each record to stderr as a JSON line,
    // prefixed by its record kind. An extension can replace the consumer
    // with a NATS-backed audit-chain subscriber per
    // `docs/events.md`.
    //
    // Installed here, before `CompiledPipeline::from_config_at` below,
    // so no request can reach a publish site before the bus exists.
    // `try_publish` cannot distinguish "not installed" from "queue
    // full", so a record emitted ahead of this line would count as a
    // drop and make every boot look like an audit outage.
    //
    // Spawn the drain on a dedicated single-threaded runtime in a
    // background std thread so it lives independently of Pingora's
    // worker runtimes. This mirrors the SIGHUP handler pattern below
    // and keeps the audit consumer alive for the full process
    // lifetime.
    {
        let (tx, rx) = crate::policy_bus::channel(crate::policy_bus::DEFAULT_BUS_CAPACITY);
        let _ = crate::policy_bus::init_global_bus(tx);
        std::thread::Builder::new()
            .name("sbproxy-policy-bus-drain".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build policy-bus drain runtime");
                        return;
                    }
                };
                rt.block_on(async move {
                    crate::policy_bus::drain_to_stderr(rx).await;
                });
            })
            .ok();
    }

    // Compile config into a pipeline with action/auth/policy module instances.
    let config_dir = std::path::Path::new(config_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut pipeline = CompiledPipeline::from_config_at(compiled, config_dir)?;
    preflight_default_safety_centroids(&pipeline)?;
    attach_payments_runtime(&mut pipeline)?;

    // WOR-196: pick up `listings/*.yaml` from the same Repo (the
    // directory the served `sb.yml` lives in) and stash the loaded
    // registry on the pipeline so the projection layer can serve the
    // per-Listing and aggregated agent-skills endpoints. Mirrors the
    // same wiring in `reload_from_config_path` so SIGHUP and file-
    // watcher reloads pick up listing edits too.
    {
        let repo_root = config_dir.to_path_buf();
        let mut load_errors: Vec<sbproxy_config::ListingLoadError> = Vec::new();
        let loaded = sbproxy_config::load_listings_from_repo(&repo_root, &mut load_errors);
        for err in &load_errors {
            tracing::warn!(error = %err, "listings load error; skipping entry");
        }
        if !loaded.is_empty() {
            let mut findings: Vec<sbproxy_config::PlanFinding> = Vec::new();
            pipeline.listings = sbproxy_config::ListingRegistry::from_loaded(loaded, &mut findings);
            for finding in &findings {
                tracing::warn!(
                    rule_id = %finding.rule_id,
                    path = %finding.path,
                    message = %finding.message,
                    "listing registry finding"
                );
            }
        }
    }

    // Give the linked lifecycle extension a chance to initialize the
    // candidate before it becomes requestable. Startup is synchronous here,
    // so the async hook runs on a short-lived current-thread runtime.
    pipeline.hooks.startup = crate::hook_registry::try_collect_startup_hook()?;
    if let Some(startup) = pipeline.hooks.startup.clone() {
        let hook_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build startup-hook runtime: {}", e))?;
        hook_rt
            .block_on(startup.on_startup(&mut pipeline))
            .map_err(|error| {
                anyhow::anyhow!("pipeline lifecycle hook rejected startup: {error}")
            })?;
    }

    // The lifecycle hook has now had its chance to install cache
    // backends. Anything it wired that writes plaintext somewhere
    // durable is refused here rather than discovered later by whoever
    // reads the disk.
    enforce_cache_at_rest_posture(&pipeline)?;

    // Prepare and publish the complete model desired state before the
    // pipeline becomes requestable. The permanent runtime exists even
    // when this first snapshot contains no managed deployments.
    super::model_host::reconcile_model_runtime_blocking(&pipeline, config_dir)
        .map_err(|error| anyhow::anyhow!("model runtime reconciliation failed: {error}"))?;
    let _model_runtime_shutdown = ModelRuntimeShutdownGuard;
    let model_plane_body_limit = pipeline
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::AiProxy(action) => Some(
                action
                    .config
                    .max_body_size
                    .unwrap_or(DEFAULT_MODEL_PLANE_BODY_LIMIT),
            ),
            _ => None,
        })
        .max()
        .unwrap_or(DEFAULT_MODEL_PLANE_BODY_LIMIT);
    let _model_plane_shutdown = start_process_model_plane(model_plane_body_limit)?;

    // The pipeline constructor prepared this exact generation's key plane
    // without touching global or store state. Boot has completed every other
    // fallible preflight, so apply declarative seeds and then expose the plane
    // to admin/cluster consumers immediately before publishing the matching
    // request pipeline.
    crate::key_plane::seed_prepared_key_plane(
        pipeline.key_plane(),
        pipeline.config.server.key_management.as_ref(),
    )?;
    crate::key_plane::activate_key_plane(
        pipeline.key_plane().cloned(),
        pipeline.config.server.key_management.as_ref(),
    );
    crate::cluster::start_governance_dissemination();
    crate::cluster::start_rate_limit_dissemination();
    crate::cluster::start_meter_dissemination();

    // Store in hot-reload slot.
    reload::load_pipeline(pipeline);

    // WOR-2457: open the config history ring from `proxy.config_history`
    // and record this boot as its first (or next) entry. Called here,
    // right after publish, rather than earlier alongside the other
    // boot-only process globals: opening the store is fallible, and a
    // boot that otherwise succeeded must not fail over its own audit
    // trail.
    record_boot_config_revision(
        boot_history_config.as_ref(),
        effective_yaml.as_bytes(),
        boot_config_origin,
        // WOR-2459: a boot the ring rescued is recorded under its own
        // actor, so `GET /admin/config/history` shows which entries this
        // node reached by falling back rather than by being told to.
        if fallback_pin.is_some() {
            "boot_fallback"
        } else {
            "boot"
        },
    );

    // Start file watcher for config hot-reload. It is told what boot loaded,
    // so its "has this actually changed" baseline is the served config rather
    // than whatever is on disk by the time its thread runs.
    start_config_watcher(config_path.to_string(), initial_file_digest);

    // Start the config-authority poller. Its cycles apply through the
    // non-blocking reload entry point, so a slow file-watcher or SIGHUP
    // reload never queues up poll cycles behind it. No-op when no
    // authority is configured.
    crate::config_subscriber::spawn(config_subscriber);

    // Start the config-source refresh loop. Same shape as the authority
    // poller: an interval with jitter, the resolved commit playing the
    // part an ETag plays, and the non-blocking reload entry point. No-op
    // when the config has no `source:` block or set
    // `refresh_interval_secs: 0`.
    crate::config_source::spawn(source_poller);

    // Refresh Git-backed extension bundles through the same non-blocking,
    // atomic candidate transaction. No-op when every source sets
    // `refresh_interval_secs: 0` or no Git source is configured.
    crate::extension_refresh::spawn(extension_refresh_poller);

    // Start the config-authority publisher: load the signing key, open
    // the durable revision store, and bind the bundle listener. Fatal on
    // failure, and deliberately so. A node configured to publish that
    // silently does not is a node whose whole fleet stops receiving
    // configuration with nothing in the logs saying why. `compile_config`
    // has already refused a non-loopback bind with no TLS and an
    // unreadable signing key, so reaching an error here means the address
    // is taken or the store directory is not writable.
    crate::config_authority::spawn(
        server_config
            .config_authority
            .as_ref()
            .and_then(|authority| authority.publish.as_ref()),
    )?;

    // Start the aggregation loop, when this node is the one that should
    // run it (WOR-2437). A no-op unless the document declares
    // `origin_sources` entries *and* this process installed a config
    // authority above, because a node with entries and nowhere to
    // publish has no runtime composition to do: its answer is the
    // offline `sbproxy aggregate --out`, which is an operator's decision
    // rather than something to start behind one.
    //
    // `Overlay` because what travels is an origins overlay: `origins:`
    // plus `origin_defaults`, and nothing else. A subscriber that took
    // that as `Replace` would replace its whole document with those two
    // keys, losing its listeners, its TLS, its admin surface and its
    // secrets in one publish. The one-shot `sbproxy aggregate` takes
    // `--mode` for the deployment that wants the other one.
    crate::config_aggregator::spawn(config_path, sbproxy_config::BundleMode::Overlay)?;

    // --- Wave 5 day-6 Item 4: SIGHUP re-bootstrap handler ---
    //
    // Pingora's `Server::run_forever` owns its own tokio runtime, but
    // it neither installs a SIGHUP handler nor re-runs our bootstrap
    // on receipt. Spawn a dedicated single-threaded runtime on a
    // background std thread so an operator-driven `kill -HUP $(pgrep
    // sbproxy)` re-runs `reload_from_config_path` (which threads
    // through compile_config + the day-6 features.* migration + the
    // pipeline lifecycle hook). Idempotent: each delivery atomically
    // swaps the live pipeline; multiple back-to-back SIGHUPs coalesce.
    {
        let cfg_path = config_path.to_string();
        std::thread::Builder::new()
            .name("sbproxy-sighup".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build SIGHUP runtime");
                        return;
                    }
                };
                rt.block_on(async {
                    install_sighup_handler(cfg_path);
                    // Park forever; the spawned task holds the runtime
                    // alive. A future shutdown signal will tear this
                    // down alongside Pingora's main runtime.
                    std::future::pending::<()>().await;
                });
            })
            .ok();
    }

    // --- TLS setup ---
    let tls_state = if server_config.https_bind_port.is_some()
        || server_config.tls_cert_file.is_some()
        || server_config.acme.as_ref().is_some_and(|a| a.enabled)
    {
        match sbproxy_tls::TlsState::init(&server_config, hostnames) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize TLS");
                return Err(e);
            }
        }
    } else {
        None
    };

    // Create Pingora server. The graceful-shutdown grace period is
    // resolved from three sources (preferred first):
    //
    //   1. `SBPROXY_SHUTDOWN_GRACE_MS` (milliseconds, WOR-636)
    //   2. `SB_GRACE_TIME` (seconds, legacy, kept for back-compat)
    //   3. zero (instant) for the Go e2e runner and dev loops
    //
    // The binary wrapper (`crates/sbproxy/src/main.rs`) overlays a 30s
    // default before calling in here so end users get a sane grace
    // period without setting any env var; the in-process default
    // stays zero so the Go e2e runner (which sends SIGTERM between
    // test cases and immediately tries to bind the same port for the
    // next case) does not pay a 30s port-busy penalty.
    //
    // Pingora handles SIGINT (fast shutdown) and SIGTERM (graceful
    // shutdown) inside `Server::run_forever`. We subscribe to the
    // execution-phase broadcast below so the structured shutdown log
    // line lands in operator-facing tracing output. See
    // `docs/manual.md` for the signal contract.
    //
    // Performance tuning (see sbproxy-bench/docs/TUNING.md):
    //   * threads: Pingora's default is 1 (single-threaded). Match Go's
    //     GOMAXPROCS behaviour by using all logical cores.
    //   * upstream_keepalive_pool_size: bump from 128 to 256 to match the
    //     Go http.Transport MaxIdleConnsPerHost we set on the Go side.
    // Offload upstream DNS + connect() onto a dedicated threadpool so worker
    // threads don't block on syscalls. Tier-2 tuning from
    // sbproxy-bench/docs/TUNING.md. Two pools is the Pingora-recommended
    // starting point for 8+ core machines.
    // WOR-646: grace inputs are passed in explicitly by the binary
    // rather than read back from process env. The string-taking helper
    // is reused as-is (it also tolerates malformed input from any other
    // caller); a resolved u64 always reparses cleanly.
    let grace_ms = grace.shutdown_grace_ms.map(|m| m.to_string());
    let grace_secs = grace.grace_time_secs.map(|s| s.to_string());
    let grace_seconds = resolve_shutdown_grace_seconds(grace_ms.as_deref(), grace_secs.as_deref());
    // Worker thread count. `SB_WORKER_THREADS` (when a positive
    // integer) overrides the auto-detected value; otherwise we use
    // `std::thread::available_parallelism()`, which honours cgroup
    // CPU quotas on Linux. Useful for benchmarks pinning to a known
    // worker count, or for containers where the operator wants to
    // cap the pool below the cgroup quota.
    let auto_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let threads = std::env::var("SB_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(auto_threads);
    // WOR-2699: worker stack size. Unset means the fork's
    // `DEFAULT_THREAD_STACK_SIZE`, which is 8 MiB. A worker polls the
    // whole request path on this stack, and the debug binary CI's smoke
    // lane builds needs several times what the release binary does, so
    // the ceiling has to be sized for the deeper of the two.
    //
    // Environment-only, like `SB_WORKER_THREADS` beside it: rarely
    // changed, and the right value is deployment-shaped. Raising it
    // costs reserved address space per worker thread and no resident
    // memory, because a thread stack is committed page by page as it is
    // touched. `docs/manual.md` carries the arithmetic.
    //
    let worker_stack_bytes =
        resolve_worker_stack_bytes(std::env::var("SB_WORKER_STACK_BYTES").ok().as_deref());
    let conf = PingoraServerConf {
        threads,
        upstream_keepalive_pool_size: 256,
        upstream_connect_offload_threadpools: Some(2),
        grace_period_seconds: Some(grace_seconds),
        graceful_shutdown_timeout_seconds: Some(grace_seconds),
        runtime_thread_stack_size: worker_stack_bytes,
        ..PingoraServerConf::default()
    };
    tracing::info!(
        threads = %conf.threads,
        upstream_pool = %conf.upstream_keepalive_pool_size,
        connect_offload = ?conf.upstream_connect_offload_threadpools,
        worker_stack_bytes = conf
            .runtime_thread_stack_size
            .unwrap_or(pingora_runtime::DEFAULT_THREAD_STACK_SIZE),
        "pingora server config"
    );
    let mut server = Server::new_with_opt_and_conf(None, conf);

    // Create the HTTP proxy service. Pingora 0.8's rustls upstream
    // connector unwraps native CA loading during construction; on
    // sandboxed macOS sessions without a keychain that can panic before
    // sbproxy can print a useful startup error.
    let mut proxy_service = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        http_proxy_service(&server.configuration, SbProxy)
    })) {
        Ok(service) => service,
        Err(payload) => {
            return Err(proxy_service_startup_error(payload.as_ref()));
        }
    };
    proxy_service.add_tcp(&format!("{bind_address}:{port}"));

    // --- HTTP/2 cleartext (h2c) ---
    //
    // When the operator opts in via `proxy.http2_cleartext: true`,
    // enable Pingora's `HttpServerOptions::h2c` flag so the plain TCP
    // listener peeks for the HTTP/2 connection preface and upgrades
    // matching connections to h2 transparently. Plaintext gRPC
    // clients (and any tonic Channel that has not negotiated TLS+ALPN)
    // depend on this; without it the proxy parses the h2 preface as
    // an HTTP/1.1 request line and tears the connection down with
    // `FRAME_SIZE_ERROR`. TLS+ALPN h2 on `https_bind_port` is a
    // separate path and does not need this flag.
    if server_config.http2_cleartext {
        if let Some(app) = proxy_service.app_logic_mut() {
            // `HttpServerOptions` is `#[non_exhaustive]`, so build via
            // `Default::default()` and then flip the `h2c` flag.
            let mut opts = HttpServerOptions::default();
            opts.h2c = true;
            app.server_options = Some(opts);
            tracing::info!(port = %port, "h2c enabled on plain HTTP listener");
        }
    }

    tracing::info!(port = %port, bind = %bind_address, "starting sbproxy on {}:{}", bind_address, port);

    // Add HTTPS listener if TLS configured.
    if let Some(ref tls) = tls_state {
        if let Some(https_port) = server_config.https_bind_port {
            if let (Some(cert_path), Some(key_path)) =
                (&server_config.tls_cert_file, &server_config.tls_key_file)
            {
                // Manual cert files provided.
                if let Some(mtls_cfg) = server_config.mtls.as_ref() {
                    // mTLS path: build TlsSettings, configure the
                    // rustls ClientCertVerifier wrapper that captures
                    // CN+SAN into the process-wide cert cache, then
                    // delegate chain validation to WebPkiClientVerifier.
                    let cache = crate::identity::mtls_cert_cache();
                    match build_mtls_tls_settings(cert_path, key_path, mtls_cfg, cache) {
                        Ok(settings) => {
                            proxy_service.add_tls_with_settings(
                                &format!("{bind_address}:{https_port}"),
                                None,
                                settings,
                            );
                            tracing::info!(
                                port = %https_port,
                                require = %mtls_cfg.require,
                                "HTTPS listener added (manual certs + mTLS)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "mTLS setup failed; falling back to non-mTLS HTTPS"
                            );
                            proxy_service
                                .add_tls(
                                    &format!("{bind_address}:{https_port}"),
                                    cert_path,
                                    key_path,
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!("failed to add TLS listener: {}", e)
                                })?;
                        }
                    }
                } else {
                    let settings = build_tls_settings(cert_path, key_path)?;
                    proxy_service.add_tls_with_settings(
                        &format!("{bind_address}:{https_port}"),
                        None,
                        settings,
                    );
                    tracing::info!(
                        port = %https_port,
                        "HTTPS listener added (manual certs, HTTP/2 enabled)"
                    );
                }
            } else if server_config.acme.as_ref().is_some_and(|a| a.enabled) {
                // ACME mode (WOR-1772): the forked Pingora listener reads the
                // dynamic CertResolver, so a cert the ACME task issues is served
                // live via SNI and renewals swap with no restart. Install a
                // self-signed fallback first so :443 completes a handshake
                // before the first issue and for SNI misses.
                if let Err(e) = tls.install_self_signed_fallback() {
                    tracing::warn!(
                        error = %e,
                        "failed to install self-signed fallback; HTTPS listener not started"
                    );
                } else if let Some(mtls_cfg) = server_config.mtls.as_ref() {
                    // Wire mTLS through the ACME path too, still serving the
                    // cert dynamically from the resolver.
                    let cache = crate::identity::mtls_cert_cache();
                    match build_mtls_tls_settings_with_resolver(
                        tls.resolver.clone(),
                        mtls_cfg,
                        cache,
                    ) {
                        Ok(settings) => {
                            proxy_service.add_tls_with_settings(
                                &format!("{bind_address}:{https_port}"),
                                None,
                                settings,
                            );
                            tracing::info!(
                                port = %https_port,
                                require = %mtls_cfg.require,
                                "HTTPS listener added (ACME dynamic cert via resolver + mTLS)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "mTLS setup failed on ACME path; HTTPS listener not started"
                            );
                        }
                    }
                } else {
                    match build_tls_settings_with_resolver(tls.resolver.clone()) {
                        Ok(settings) => {
                            proxy_service.add_tls_with_settings(
                                &format!("{bind_address}:{https_port}"),
                                None,
                                settings,
                            );
                            tracing::info!(
                                port = %https_port,
                                "HTTPS listener added (ACME dynamic cert via resolver, HTTP/2 enabled)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "failed to build resolver TLS settings; HTTPS listener not started"
                            );
                        }
                    }
                }
            }
        }
    }

    // Bind every public endpoint before handing the service to Pingora's
    // background runtimes. A bind failure is a startup error with an exit
    // code, not a panic in a detached listener task while the main signal
    // loop remains alive. Pingora retains these exact sockets, so there is
    // no probe/drop/rebind race between this check and `Server::run`.
    //
    // Tokio network resources retain the reactor on which they were
    // created. Keep this one-thread runtime alive and driven for the whole
    // server lifetime while Pingora's service tasks accept from the
    // prepared listeners.
    let listener_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("sbproxy-listener-reactor")
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("build public-listener runtime: {error}"))?;
    // WOR-2452: close the window between binding the public listener and
    // Pingora owning SIGTERM. Pingora registers its terminate handler
    // inside `UnixShutdownSignalWatch::recv()`, which is not polled until
    // `run()`, so every moment from here until then runs with the default
    // disposition: a SIGTERM kills the process outright.
    //
    // That matters because the socket is already accepting in the kernel
    // sense the instant it is bound. A client connect() completes into
    // the listen backlog whether or not anything has called accept(), so
    // the proxy looks up from outside while still unable to shut down
    // cleanly. A rolling deploy that signals in this window resets the
    // connections the kernel already queued.
    //
    // tokio signal streams are additive, not exclusive: "A Signal stream
    // can be created for a particular signal number multiple times. When
    // a signal is received then all the associated channels will receive
    // the signal notification." So registering here displaces the default
    // disposition immediately and does not interfere with Pingora's own
    // registration later; both receive.
    //
    // The phase subscription has to be taken here, while `server` is
    // still ours: `run` consumes it and drops the broadcast sender.
    install_early_terminate_guard(&listener_runtime, server.watch_execution_phase());

    listener_runtime
        .block_on(proxy_service.prepare_listeners())
        .map_err(|error| anyhow::anyhow!("bind public listener: {error}"))?;

    hold_open_startup_signal_window();

    server.add_service(proxy_service);

    // Spawn the embedded admin HTTP server on `proxy.admin.port`
    // when `admin.enabled: true`. The admin server lives outside
    // Pingora's service tree because its routing semantics
    // (authoritative, basic-auth gated, no upstream forwarding)
    // do not fit Pingora's reverse-proxy shape. Pingora installs
    // its own tokio runtime; we hand the admin task to that
    // runtime when it starts via `tokio::spawn` below the run-loop
    // setup.
    if server_config.admin.as_ref().is_some_and(|a| a.enabled) {
        let admin_cfg = crate::admin::AdminConfig {
            enabled: true,
            port: server_config.admin.as_ref().map(|a| a.port).unwrap_or(9090),
            // The `unwrap_or_else` arms are unreachable (this branch only
            // runs when `admin` is Some), but they must still read the
            // shared default constants rather than repeat the literals:
            // `compile_config` compares credentials against those
            // constants to refuse a reachable admin surface that still
            // carries the shipped defaults, and a second copy of the
            // string here is how the two drift apart.
            username: server_config
                .admin
                .as_ref()
                .map(|a| a.username.clone())
                .unwrap_or_else(|| sbproxy_config::types::DEFAULT_ADMIN_USERNAME.to_string()),
            password: server_config
                .admin
                .as_ref()
                .map(|a| a.password.clone())
                .unwrap_or_else(|| sbproxy_config::types::DEFAULT_ADMIN_PASSWORD.to_string()),
            max_log_entries: server_config
                .admin
                .as_ref()
                .map(|a| a.max_log_entries)
                .unwrap_or(1000),
            rate_limit_per_minute: server_config
                .admin
                .as_ref()
                .map(|a| a.rate_limit_per_minute)
                .unwrap_or(240),
            // WOR-1717: carry the operator's admin TLS cert/key paths
            // through so the admin server serves HTTPS when configured.
            tls: server_config
                .admin
                .as_ref()
                .and_then(|a| a.tls.as_ref())
                .map(|t| crate::admin::AdminTls {
                    cert: t.cert.clone(),
                    key: t.key.clone(),
                }),
            // WOR-1717: remote bind, IP allowlist, CORS origins.
            bind: server_config
                .admin
                .as_ref()
                .and_then(|a| a.bind.clone())
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            allow_ips: server_config
                .admin
                .as_ref()
                .map(|a| a.allow_ips.clone())
                .unwrap_or_default(),
            cors_origins: server_config
                .admin
                .as_ref()
                .map(|a| a.cors_origins.clone())
                .unwrap_or_default(),
            // WOR-1716: RBAC operators.
            operators: server_config
                .admin
                .as_ref()
                .map(|a| {
                    a.operators
                        .iter()
                        .map(|o| crate::admin::AdminOperator {
                            username: o.username.clone(),
                            password_hash: o.password_hash.clone(),
                            role: o.role,
                            // WOR-2131: the meter's tenant scope for this
                            // login. Carried through so the admin surface
                            // reads it from config rather than from a token.
                            tenant: o.tenant.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            // WOR-1870: trace deep-link template for the admin UI.
            trace_url_template: server_config
                .admin
                .as_ref()
                .and_then(|a| a.trace_url_template.clone()),
        };
        // Pass the same on-disk config path the file watcher uses
        // so `POST /admin/reload` re-reads the same file. The two
        // reload paths share the in-process single-flight guard on
        // the AdminState so a manual reload during a watcher reload
        // serialises cleanly.
        // WOR-800 PR5: open the prompt persistence handle when the
        // operator configured a path. Hydrating reads the existing
        // file into the in-memory overlay; subsequent admin mutators
        // write through. A failure to open is logged but does NOT
        // abort startup: an unreadable persistence file should not
        // brick the proxy. PR3-style ephemeral mutations keep
        // working on the failed path.
        // At-rest sealing for the prompt file. Resolved before the open
        // below, and a failure here is FATAL, unlike a failed open. The
        // distinction matters: an unreadable file loses saved prompts and
        // degrades to ephemeral mutations, but a key the operator asked for
        // and we cannot supply would otherwise degrade to writing records in
        // the clear, which is the one outcome the no-plaintext-fallback rule
        // exists to prevent.
        let prompt_sealer = build_prompt_sealer(server_config.admin.as_ref())?;
        let prompt_persistence = server_config
            .admin
            .as_ref()
            .and_then(|a| a.prompt_persistence_path.as_ref())
            .and_then(|path| {
                match crate::admin::PromptPersistence::open(path, prompt_sealer.clone()) {
                    Ok(p) => {
                        tracing::info!(path = %path.display(), "opened prompt persistence");
                        Some(std::sync::Arc::new(p))
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "failed to open prompt persistence; mutations will be ephemeral"
                        );
                        None
                    }
                }
            });
        // Resolve the operator-password pepper before constructing
        // AdminState, so `check_operator_login` verifies against the same
        // pepper `sbproxy admin hash-password` used to produce the stored
        // hash. See `resolve_or_default_admin_operator_pepper` for the
        // fail-loud-only-if-needed policy.
        let operator_pepper = resolve_or_default_admin_operator_pepper(
            server_config.key_management.as_ref(),
            !admin_cfg.operators.is_empty(),
        )?;
        let mut admin_state_inner = crate::admin::AdminState::new(admin_cfg)
            .with_config_path(config_path)
            .with_loaded_config_content_hash(initial_content_hash.clone())
            .with_operator_pepper(operator_pepper);
        if let Some(p) = prompt_persistence {
            admin_state_inner = admin_state_inner.with_prompt_persistence(p);
        }

        let mut agent_registry_refresher: Option<(
            std::sync::Arc<sbproxy_agent_registry::AgentRegistry>,
            std::time::Duration,
        )> = None;
        // WOR-2664: the agent registry. Construction is fail-loud rather
        // than fail-soft, unlike the prompt persistence above: a registry
        // that could not open its store would answer every approval query
        // with an empty queue, and an operator reading "no pending
        // registrations" cannot tell that from a broken store. Prompt
        // persistence degrades to ephemeral mutations, which is a smaller
        // lie, so it warns and continues.
        if let Some(registry_cfg) = server_config
            .agent_registry
            .as_ref()
            .filter(|cfg| cfg.enabled)
        {
            registry_cfg
                .validate()
                .map_err(|message| anyhow::anyhow!("{message}"))?;
            let registry = build_agent_registry(registry_cfg)?;
            // WOR-2664 review: `agent_registry` on /readyz is WOR-1743's
            // agent-class resolver and has nothing to do with this block, so
            // the registry's own probe gets a distinct name rather than
            // making one component answer for two subsystems.
            {
                let probe_registry = std::sync::Arc::clone(&registry);
                admin_state_inner
                    .health_registry
                    .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                        AGENT_CATALOG_COMPONENT,
                        move || {
                            agent_catalog_component(
                                probe_registry.catalog().health(chrono::Utc::now()),
                            )
                        },
                    )));
            }
            // Only when there is something to refresh. The registry's
            // approval queue is useful on its own and the branch's own
            // example ships exactly that shape, so installing the loop
            // unconditionally meant a queue-only deployment logged
            // "refused a catalog feed" at warn and ticked
            // `op="feed_refresh",outcome="invalid"` on boot and every
            // interval forever. An operator alerting on refresh refusals,
            // which the docs tell them to do, would page on a working
            // config. This is the same condition `RegistrySummary`
            // publishes as `feed_configured`.
            agent_registry_refresher = agent_registry_refresher_for(registry_cfg, &registry);
            admin_state_inner = admin_state_inner.with_agent_registry(registry);
        }

        // WOR-2669: the outbound notifier. Fail-loud for the same reason
        // the agent registry is: a notifier that could not open its store
        // would report an empty subscription list, and an operator reading
        // "no subscriptions" cannot tell that from a broken store.
        if let Some(notify_cfg) = server_config
            .notifications
            .as_ref()
            .filter(|cfg| cfg.enabled)
        {
            let notifier = build_notifier(notify_cfg)?;
            if !sbproxy_observe::notify::install(std::sync::Arc::clone(&notifier)) {
                tracing::warn!(
                    "a notifier was already installed in this process; the newly configured one will not receive events"
                );
            }
            admin_state_inner = admin_state_inner.with_notifier(notifier);
        }

        // WOR-27: register the synthetic-pipeline probe and spawn its
        // driver loop when the operator opted in. Registration runs
        // sync; the driver loop calls `tokio::spawn` and therefore
        // must be invoked from inside the admin thread's runtime
        // (this `pub fn run` itself has no current tokio runtime).
        let synthetic_driver = match server_config.synthetic_probe.as_ref() {
            Some(synth_cfg) if synth_cfg.enabled => {
                let state = sbproxy_observe::SyntheticProbeState::new();
                let stale_after =
                    std::time::Duration::from_secs(synth_cfg.effective_stale_after_secs());
                let registration = sbproxy_observe::SyntheticProbeRegistration {
                    name: "synthetic_pipeline".to_string(),
                    state: state.clone(),
                    stale_after,
                };
                admin_state_inner
                    .health_registry
                    .register(registration.into_probe());
                Some((synth_cfg.clone(), state))
            }
            _ => None,
        };

        // WOR-1740: replace the seeded NotConfigured health stubs with real
        // probes for the subsystems that expose a health signal. Registering
        // under the same name overrides the stub.
        //
        // agent_registry (WOR-1743): the agent-class resolver's load state.
        #[cfg(feature = "agent-class")]
        admin_state_inner
            .health_registry
            .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                "agent_registry",
                || {
                    if crate::reload::agent_class_resolver().is_some() {
                        (sbproxy_observe::ComponentStatus::Healthy, None)
                    } else {
                        (
                            sbproxy_observe::ComponentStatus::NotConfigured,
                            Some("agent-class resolver not installed".to_string()),
                        )
                    }
                },
            )));

        // bot_auth_directory (WOR-1742): freshness of the web-bot-auth key
        // directory. The directory refreshes on a timer, so recency is a
        // real signal; never-refreshed (bot_auth unused) maps to
        // NotConfigured so /readyz stays 200.
        {
            let recency = sbproxy_observe::Recency::new(std::time::Duration::from_secs(24 * 3600));
            sbproxy_modules::auth::bot_auth_directory::global().set_recency(Some(recency.clone()));
            admin_state_inner
                .health_registry
                .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                    "bot_auth_directory",
                    move || match recency.last_success() {
                        None => (
                            sbproxy_observe::ComponentStatus::NotConfigured,
                            Some("no directory refresh yet".to_string()),
                        ),
                        Some(_) if recency.is_fresh() => {
                            (sbproxy_observe::ComponentStatus::Healthy, None)
                        }
                        Some(t) => (
                            sbproxy_observe::ComponentStatus::Degraded,
                            Some(format!(
                                "directory last refreshed {}s ago",
                                t.elapsed().as_secs()
                            )),
                        ),
                    },
                )));
        }

        // usage_ledger (WOR-1741): the verifiable usage ledger's last
        // append outcome. Traffic-independent (an idle ledger reports
        // NotConfigured rather than a false stale), so this tracks the
        // append result, not recency.
        //
        // Named `usage_ledger` and not `ledger` because that is the whole
        // of what it covers (WOR-2324). The AI-crawl redeem ledger is a
        // separate HTTP dependency and nothing here probes it, so a dead
        // redeem endpoint leaves this component green; the bare name read
        // as though it did not. See `sbproxy_observe::default_registry`
        // for why redeem recency is not the signal that would close it.
        admin_state_inner
            .health_registry
            .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                "usage_ledger",
                || match sbproxy_ai::usage_ledger::ledger_health() {
                    sbproxy_ai::usage_ledger::LedgerHealth::NeverAppended => (
                        sbproxy_observe::ComponentStatus::NotConfigured,
                        Some("no ledger append yet".to_string()),
                    ),
                    sbproxy_ai::usage_ledger::LedgerHealth::Ok => {
                        (sbproxy_observe::ComponentStatus::Healthy, None)
                    }
                    sbproxy_ai::usage_ledger::LedgerHealth::Failed => (
                        sbproxy_observe::ComponentStatus::Unhealthy,
                        Some("last ledger append failed".to_string()),
                    ),
                },
            )));

        // mesh_quorum (WOR-1744): cluster peer quorum from the mesh
        // IsolationObserver. NotConfigured when the mesh is not enabled;
        // Unhealthy when the node is isolated (below its minimum peer
        // quorum), else Healthy with the live peer count.
        admin_state_inner
            .health_registry
            .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                "mesh_quorum",
                || match crate::cluster::current_cluster_handle()
                    .and_then(|handle| handle.isolation_observer())
                {
                    None => (
                        sbproxy_observe::ComponentStatus::NotConfigured,
                        Some("mesh not enabled".to_string()),
                    ),
                    Some(obs) if obs.is_isolated() => (
                        sbproxy_observe::ComponentStatus::Unhealthy,
                        Some(format!(
                            "isolated: {} of {} min peers alive",
                            obs.last_alive_count(),
                            obs.min_peers()
                        )),
                    ),
                    Some(obs) => (
                        sbproxy_observe::ComponentStatus::Healthy,
                        Some(format!("{} peers alive", obs.last_alive_count())),
                    ),
                },
            )));

        // keystore (WOR-2064): the mesh keystore's post-quarantine
        // readiness. NotConfigured when the mesh backend is not active;
        // Unhealthy while a node whose shard was quarantined after a
        // long absence has not completed its first full anti-entropy
        // round, because the backend refuses to serve authentication
        // from an unrepopulated shard in that window.
        admin_state_inner
            .health_registry
            .register(std::sync::Arc::new(sbproxy_observe::SyntheticProbe::new(
                "keystore",
                || match crate::mesh_keystore::current_readiness() {
                    None => (
                        sbproxy_observe::ComponentStatus::NotConfigured,
                        Some("mesh keystore backend not active".to_string()),
                    ),
                    Some(readiness) if !readiness.ready() => (
                        sbproxy_observe::ComponentStatus::Unhealthy,
                        Some(
                            "replica shard quarantined after long absence; holding \
                             authentication until the first complete anti-entropy round"
                                .to_string(),
                        ),
                    ),
                    Some(_) => (sbproxy_observe::ComponentStatus::Healthy, None),
                },
            )));

        let admin_state = std::sync::Arc::new(admin_state_inner);
        // Owned before the `move` closure below takes everything else:
        // the soak supervisor drives a rollback when `auto_revert` is
        // armed and a window fails, and the reload transaction needs the
        // config path to resolve relative paths inside the restored
        // document (WOR-2461).
        let soak_config_path = config_path.to_string();
        // WOR-1718: install the global handle so the pipeline's logging
        // hook can feed the request-log ring buffer + SSE tail.
        crate::admin::install_admin_log_sink(admin_state.clone());
        // Pingora's `Server::run_forever` builds its own multi-thread
        // tokio runtime; spawning before run_forever installs the
        // task on that runtime via the global handle once Pingora
        // initialises it. We use a small bootstrap task that grabs
        // the runtime handle as soon as it is available.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("admin runtime");
            rt.block_on(async move {
                if let Some((synth_cfg, state)) = synthetic_driver {
                    // Published before the driver starts, so the config
                    // soak's operator-probe signal (WOR-2458) can read
                    // the same outcome `/readyz` reads rather than
                    // introducing a second probe shape.
                    crate::synthetic::install_process_synthetic_state(
                        state.clone(),
                        std::time::Duration::from_secs(synth_cfg.effective_stale_after_secs()),
                    );
                    crate::synthetic::spawn_loop(synth_cfg, state);
                }
                // WOR-2458: the soak supervisor. One task, ticking the
                // window in flight, running the operator probe on its
                // cadence, and closing the window when it is due. A
                // no-op on every node that never arms one.
                crate::config_soak::spawn(soak_config_path);
                // WOR-2664 review: without this the configured feed was read
                // only when a human POSTed /admin/agent-registry/refresh, so
                // every restart served whatever the store had cached and a
                // republished feed never arrived. Refresh once at boot, then
                // on the interval the operator's staleness tolerance implies.
                if let Some((registry, interval)) = agent_registry_refresher {
                    tokio::spawn(async move {
                        loop {
                            // A refusal is already counted and logged at warn
                            // inside `refresh`, and the previous catalog keeps
                            // serving, so the loop does not need to react.
                            let _ = registry.refresh(chrono::Utc::now()).await;
                            tokio::time::sleep(interval).await;
                        }
                    });
                }
                // The admin server's listener task lives forever;
                // run it inline on this dedicated thread.
                if let Some(handle) = crate::admin::spawn_admin_server(admin_state) {
                    let _ = handle.await;
                }
            });
        });
    }

    // Register the ACME challenge store globally.
    if let Some(ref tls) = tls_state {
        reload::set_challenge_store(std::sync::Arc::clone(&tls.challenge_store));
    }

    // Start ACME renewal task if enabled.
    if let Some(ref tls) = tls_state {
        tls.start_acme_renewal_task();
        // Kick off OCSP stapling for the manual fallback cert.
        // No-op when no manual cert is loaded; otherwise the
        // task does an immediate fetch and refreshes every 12h,
        // calling back into the resolver to update the stapled
        // bytes on the cert.
        tls.start_ocsp_refresh_task();
    }

    server.bootstrap();

    // WOR-636: subscribe to Pingora's execution-phase broadcast
    // before `run` consumes the server so an explicit
    // structured tracing event lands when SIGINT or SIGTERM is
    // received. Pingora handles the signal itself; this just makes
    // the shutdown visible to operator-facing logs.
    spawn_shutdown_phase_logger(server.watch_execution_phase(), grace_seconds);

    // Alerting: build a dispatcher from proxy.alerting.channels (installed
    // pre-resolved by the binary) and run the evaluation loop, draining
    // in-flight deliveries on the same execution-phase broadcast. A no-op when
    // no channels are configured.
    crate::alerting::install(
        server.watch_execution_phase(),
        tls_state
            .as_ref()
            .and_then(sbproxy_tls::TlsState::acme_expiry_reader),
    );

    // `run_forever()` calls `std::process::exit(0)` after Pingora drains,
    // which skips Rust destructors and used to orphan managed engine
    // subprocesses. `run()` returns after the same signal-driven lifecycle,
    // allowing the model-runtime guard below to stop every engine first.
    // Pingora takes the signal from here. The early guard learns that
    // from the execution-phase broadcast rather than from this call site,
    // because "about to call run" and "listening for signals" are
    // different facts and a SIGTERM can land between them. See
    // `install_early_terminate_guard`.
    server.run(pingora_core::server::RunArgs::default());
    drop(listener_runtime);
    drop(_model_plane_shutdown);
    drop(_model_runtime_shutdown);
    // Flush any spans still queued in the batch span processor; export
    // runs on its own background worker that Pingora's shutdown does
    // not wait on, so spans in flight at the signal were silently
    // dropped without this.
    sbproxy_observe::telemetry::shutdown_otlp_pipeline();
    Ok(())
}

struct ModelRuntimeShutdownGuard;

const DEFAULT_MODEL_PLANE_BODY_LIMIT: usize = 64 * 1024 * 1024;

struct ModelPlaneShutdownGuard {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn start_process_model_plane(
    max_request_body_bytes: usize,
) -> anyhow::Result<Option<ModelPlaneShutdownGuard>> {
    use sbproxy_model_host::node_snapshot::ModelPlaneHealth;

    let runtime = super::model_host::model_runtime_manager();
    let Some(config) = crate::cluster::current_process_model_plane_config() else {
        runtime.set_model_plane_health(ModelPlaneHealth::Unavailable);
        return Ok(None);
    };
    runtime.set_model_plane_health(ModelPlaneHealth::Degraded);
    let local_node_id = config.cluster.identity().node_id.clone();
    let execution = crate::model_plane::WorkerModelExecution::production(
        runtime.clone(),
        local_node_id.clone(),
    );
    let security = match config.security.as_ref() {
        crate::cluster::ModelPlaneSecurity::Mtls { tls, .. } => {
            crate::model_plane::ModelPlaneServerSecurity::Mtls {
                tls: tls.clone(),
                cluster: config.cluster.clone(),
            }
        }
        crate::cluster::ModelPlaneSecurity::DevelopmentSharedKey { key } => {
            crate::model_plane::ModelPlaneServerSecurity::DevelopmentSharedKey {
                key: std::sync::Arc::from(key.as_bytes()),
            }
        }
    };
    let max_request_body_bytes = if max_request_body_bytes == 0 {
        DEFAULT_MODEL_PLANE_BODY_LIMIT
    } else {
        max_request_body_bytes.min(1024 * 1024 * 1024)
    };
    let server_config = crate::model_plane::ModelPlaneServerConfig::new(
        config.bind_addr,
        local_node_id,
        max_request_body_bytes,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let thread_runtime = runtime.clone();
    let thread = std::thread::Builder::new()
        .name("sbproxy-model-plane".to_string())
        .spawn(move || {
            let executor = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(executor) => executor,
                Err(error) => {
                    thread_runtime.set_model_plane_health(ModelPlaneHealth::Unavailable);
                    let _ = ready_tx.send(Err(format!("build model-plane runtime: {error}")));
                    return;
                }
            };
            executor.block_on(async move {
                let server = match crate::model_plane::ModelPlaneServer::start(
                    server_config,
                    security,
                    execution,
                )
                .await
                {
                    Ok(server) => server,
                    Err(error) => {
                        thread_runtime.set_model_plane_health(ModelPlaneHealth::Unavailable);
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                thread_runtime.set_model_plane_health(ModelPlaneHealth::Ready);
                let _ = ready_tx.send(Ok(server.local_addr()));
                if let Err(error) = server.shutdown_on(shutdown_rx).await {
                    tracing::error!(code = error.code(), "private model-plane listener stopped");
                }
                thread_runtime.set_model_plane_health(ModelPlaneHealth::Unavailable);
            });
        })
        .map_err(|error| anyhow::anyhow!("spawn model-plane listener: {error}"))?;
    match ready_rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(Ok(local_addr)) => {
            tracing::info!(%local_addr, "private model-plane listener ready");
            Ok(Some(ModelPlaneShutdownGuard {
                shutdown: Some(shutdown_tx),
                thread: Some(thread),
            }))
        }
        Ok(Err(error)) => {
            let _ = thread.join();
            anyhow::bail!("start private model-plane listener: {error}")
        }
        Err(error) => {
            let _ = shutdown_tx.send(());
            let _ = thread.join();
            anyhow::bail!("wait for private model-plane listener: {error}")
        }
    }
}

impl Drop for ModelPlaneShutdownGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("private model-plane listener thread panicked");
            }
        }
    }
}

impl Drop for ModelRuntimeShutdownGuard {
    fn drop(&mut self) {
        match super::model_host::shutdown_model_runtime_blocking() {
            Ok(failures) if failures.is_empty() => {
                tracing::info!("managed model runtime stopped");
            }
            Ok(failures) => {
                tracing::error!(?failures, "managed model runtime shutdown was incomplete");
            }
            Err(error) => {
                tracing::error!(%error, "managed model runtime shutdown failed");
            }
        }
    }
}

/// Render the ARDP (`/.well-known/sbproxy-agent`) capability
/// advertisement as a compact JSON string.
///
/// Pure helper so the JSON shape is unit-testable without booting the
/// Pingora pipeline. The advertised endpoint keys (`mcp`, `agent_skills`,
/// `openapi`) are emitted only when the corresponding capability is
/// actually configured on the origin; the `capabilities` array tracks the
/// same set so registry consumers can branch on a string list without
/// re-walking the endpoint map. The publisher block is constant and
/// names the project surface, not the operator.
///
/// Per draft-pioli-agent-discovery-01 §4. Wire format is JSON; this
/// function builds a `serde_json::Value` and renders it with the
/// canonical compact encoder so the body is stable across releases.
pub(super) fn render_ardp_discovery(
    agent_id: &str,
    scheme: &str,
    host_authority: Option<&str>,
    has_mcp: bool,
    has_agent_skills: bool,
    has_openapi: bool,
) -> String {
    let base = match host_authority {
        Some(auth) if !auth.is_empty() => format!("{scheme}://{auth}"),
        _ => String::new(),
    };

    let mut endpoints = serde_json::Map::new();
    let mut capabilities: Vec<&'static str> = Vec::new();
    if has_mcp {
        let url = if base.is_empty() {
            "/mcp".to_string()
        } else {
            format!("{base}/mcp")
        };
        endpoints.insert("mcp".to_string(), serde_json::Value::String(url));
        capabilities.push("mcp.tools");
    }
    if has_agent_skills {
        let url = if base.is_empty() {
            "/.well-known/agent-skills/index.json".to_string()
        } else {
            format!("{base}/.well-known/agent-skills/index.json")
        };
        endpoints.insert("agent_skills".to_string(), serde_json::Value::String(url));
        capabilities.push("agent_skills.v0_2");
    }
    if has_openapi {
        let url = if base.is_empty() {
            "/.well-known/openapi.json".to_string()
        } else {
            format!("{base}/.well-known/openapi.json")
        };
        endpoints.insert("openapi".to_string(), serde_json::Value::String(url));
        capabilities.push("openapi");
    }

    let value = serde_json::json!({
        "schema_version": "1",
        "agent_id": agent_id,
        "endpoints": endpoints,
        "capabilities": capabilities,
        "publisher": {
            "name": "sbproxy",
            "url": "https://sbproxy.dev"
        }
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Walk the inventory-based plugin registry and emit one
/// `sbproxy_plugin_registered_total{kind, plugin}` counter row per
/// known registration. Called once from `run` so an operator scraping
/// `/metrics` immediately after startup sees the registration set
/// without waiting for a request to flow.
fn report_plugin_registrations() {
    use sbproxy_plugin::{PluginKind, PluginRegistration};
    for reg in inventory::iter::<PluginRegistration>() {
        let kind = match reg.kind {
            PluginKind::Action => "action",
            PluginKind::Auth => "auth",
            PluginKind::Policy => "policy",
            PluginKind::Transform => "transform",
        };
        sbproxy_observe::metrics::record_plugin_registered(kind, reg.name);
    }
    // AuthPluginRegistration is the strongly-typed sibling channel
    // used by auth providers; report them under kind=auth too so
    // `kind=auth` matches what `build_auth_plugin` actually
    // dispatches against.
    for reg in inventory::iter::<sbproxy_plugin::AuthPluginRegistration>() {
        sbproxy_observe::metrics::record_plugin_registered("auth", reg.name);
    }
}

fn proxy_service_startup_error(payload: &(dyn std::any::Any + Send)) -> anyhow::Error {
    let message = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    };
    let hint = if message.contains("Failed to load native certificates")
        || message.contains("No keychain is available")
    {
        "failed to initialize upstream TLS trust roots. On macOS this can happen in sandboxed or non-login sessions where the system keychain is unavailable; run sbproxy from a normal login shell or set SSL_CERT_FILE to a readable CA bundle."
    } else {
        "failed to initialize Pingora proxy service"
    };
    anyhow::anyhow!("{hint}: {message}")
}

/// Shared process-global mutex any test that touches the global
/// `OP_REDACT_STATE` (directly via `install_op_redact_config` or
/// indirectly via `reload_from_config_path` -> `install_op_redact_state`)
/// must hold for the duration of its assertions. Without this guard
/// two tests in the same binary race on the global slot and one
/// clobbers the other's installed state mid-flight.
#[cfg(test)]
pub(crate) static OP_REDACT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Smallest worker stack sbproxy accepts from `SB_WORKER_STACK_BYTES`.
///
/// One 4 KiB page, matching pingora's own floor. It rules out one thing:
/// a value written in the wrong unit, `SB_WORKER_STACK_BYTES=8` meaning
/// megabytes. It is not a safe lower bound, because the real floor is
/// whatever the deepest request path needs, which is what
/// `server::stack_probe` exists to report.
const MIN_WORKER_STACK_BYTES: usize = 4 * 1024;

/// Resolve `SB_WORKER_STACK_BYTES` into pingora's
/// `runtime_thread_stack_size`.
///
/// `None` means "use pingora's default", which is 8 MiB.
///
/// A free function, not inline at the call site, for two reasons. It is
/// the only way to test the parsing without standing up a server, and
/// the config-reader guard cannot see a key read from inside a larger
/// function.
///
/// # Why a bad value is ignored rather than fatal
///
/// `SB_WORKER_THREADS` beside it ignores what it cannot parse, and an
/// environment typo should not stop a proxy from starting. But the
/// previous version ignored only unparseable values and zero, and
/// passed everything else through to a `ServerConf` struct literal.
/// `ServerConf::validate()` runs from `from_yaml` and nothing else, so
/// the below-a-page refusal that `docs/manual.md` documented never ran:
/// `SB_WORKER_STACK_BYTES=8` started a server whose workers had a stack
/// the platform rounded up to something arbitrary, and aborted on the
/// first request with no diagnosis. Refusing here is what makes the
/// documented behavior real.
pub(crate) fn resolve_worker_stack_bytes(raw: Option<&str>) -> Option<usize> {
    let raw = raw?;
    let Ok(bytes) = raw.trim().parse::<usize>() else {
        tracing::warn!(
            value = %raw,
            "SB_WORKER_STACK_BYTES is not a positive integer; using the default worker stack"
        );
        return None;
    };
    if bytes < MIN_WORKER_STACK_BYTES {
        tracing::warn!(
            value = bytes,
            minimum = MIN_WORKER_STACK_BYTES,
            "SB_WORKER_STACK_BYTES is below one page, which is a value written in the wrong \
             unit rather than a stack any thread can run on; using the default worker stack"
        );
        return None;
    }
    Some(bytes)
}

/// WOR-1067 PR2: walk `server.tenants` and install each tenant's
/// `observability.cardinality.max_series` cap on the global
/// [`sbproxy_observe::metrics::global_limiter`]. A tenant without an
/// `observability.cardinality:` block stays on the proxy-wide cap
/// (today's behaviour); a tenant that declares the block without a
/// `max_series:` value gets the
/// `TENANT_CARDINALITY_DEFAULT_MAX_SERIES` (10_000) fallback so an
/// operator can opt in to per-tenant tracking without picking a
/// number.
///
/// Called once at boot (from `run`) and on every config reload (from
/// `reload_from_config_path`) so SIGHUP picks up new tenant caps.
fn install_tenant_cardinality_state(server: &sbproxy_config::ProxyServerConfig) {
    use sbproxy_config::TENANT_CARDINALITY_DEFAULT_MAX_SERIES;
    let limiter = sbproxy_observe::metrics::global_limiter();
    for tenant in &server.tenants {
        if let Some(cardinality) = tenant
            .observability
            .as_ref()
            .and_then(|o| o.cardinality.as_ref())
        {
            let max_series = cardinality
                .max_series
                .unwrap_or(TENANT_CARDINALITY_DEFAULT_MAX_SERIES)
                as usize;
            limiter.set_tenant_cap(tenant.id.clone(), max_series);
        }
    }
}

/// Install `proxy.scripting.javascript.sandbox:` into the extension
/// crate's process-wide JavaScript handle (WOR-2319).
///
/// The Lua half of `proxy.scripting:` has been installed the same way
/// since WOR-594; the JavaScript half parsed and did nothing, so every
/// QuickJS engine ran the built-in 100 ms / 16 MB / 1 MB defaults no
/// matter what the operator wrote. This is the missing call.
///
/// Called once at boot (from `run`) and on every config reload (from
/// `reload_from_config_path`), so SIGHUP, admin reload, and the file
/// watcher all pick up new limits without restarting the process.
/// Engines are built lazily per invocation, so the next script picks up
/// the new values; engines already constructed keep their snapshot.
fn install_js_sandbox_limits(server: &sbproxy_config::ProxyServerConfig) {
    sbproxy_extension::js::install_sandbox_config(server.scripting.javascript.sandbox.clone());
}

/// The `proxy.observability.log.level` directive this config asks for,
/// or `None` when the block, the key, or its value is absent. A
/// blank value is an absent value: it is what an operator who
/// commented the line out but left the key leaves behind, and
/// installing `""` as a filter would silence the process.
fn config_log_level(server: &sbproxy_config::ProxyServerConfig) -> Option<&str> {
    server
        .observability
        .as_ref()
        .and_then(|observability| observability.log.as_ref())
        .and_then(|log| log.level.as_deref())
        .map(str::trim)
        .filter(|level| !level.is_empty())
}

/// Re-assert `proxy.observability.log.level` on the running tracing
/// filter after a config reload.
///
/// Boot does not come through here: the binary folds the YAML level
/// into the filter it resolves before the subscriber is built, which
/// is the only order that also lets `format` work. By reload time the
/// subscriber is already running the previous generation's directive,
/// so an operator who edited `level:` and sent SIGHUP needs the swap
/// the reload handle exists for.
///
/// Three cases produce no change. A config with no `level:` leaves the
/// filter alone rather than resetting it to the default, so an omitted
/// key stays omitted. A process started with `--log-level`,
/// `SB_LOG_LEVEL`, or `RUST_LOG` is pinned and keeps the operator's
/// override; `set_log_filter_from_config` reports that as `Ok(false)`.
/// An unparseable directive is warn-logged and the previous filter
/// stays live.
///
/// `format` has no equivalent: the `fmt` layer is fixed for the life
/// of the process and changing it needs a restart.
fn install_config_log_level(server: &sbproxy_config::ProxyServerConfig) {
    let Some(level) = config_log_level(server) else {
        return;
    };
    match sbproxy_observe::set_log_filter_from_config(level) {
        Ok(true) => {
            tracing::info!(filter = %level, "reload: applied proxy.observability.log.level");
        }
        // An explicit CLI or environment override outranks the file
        // for the life of the process. Silent: it is the documented
        // outcome, and a reload loop would log it on every pass.
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(
                filter = %level,
                error = %e,
                "reload: proxy.observability.log.level did not install; keeping the current filter"
            );
        }
    }
}

/// Read `proxy.observability.log.redact:` (proxy scope) and walk
/// `compiled.server.tenants` + `compiled.origins` for tenant- and
/// origin-scope `observability.log.redact.pii:` overrides
/// (WOR-1043 PR2 / PR3). Install the composed redaction state into the
/// global op-redact slot. Empty when no scope authored a block so the
/// redactor short-circuits at zero allocation. An invalid regex at the
/// proxy scope is logged at `warn` and dropped; unknown rule names at
/// any scope are warn-logged and skipped; the rest of the block still
/// installs.
fn install_op_redact_state(compiled: &sbproxy_config::CompiledConfig) {
    let server = &compiled.server;

    // Proxy-scope `redact:` block.
    let proxy_redact = server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .and_then(|l| l.redact.as_ref());

    // Compose proxy-scope fields + regex patterns. Tenant- and
    // origin-scope blocks reuse the same `ObservabilityPiiConfig`
    // shape but only the `pii:` leaf is honoured at scopes below
    // proxy; the field-key and regex passes still walk the rendered
    // JSON, which is tenant-agnostic at the emitter.
    let fields: Vec<String> = match proxy_redact {
        Some(c) => c.fields.iter().map(|f| f.to_ascii_lowercase()).collect(),
        None => Vec::new(),
    };

    let mut patterns = Vec::new();
    if let Some(cfg) = proxy_redact {
        patterns.reserve(cfg.patterns.len());
        for p in &cfg.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
    }

    // Resolve the proxy-scope PII rule set first. We need both the
    // `enabled` decision and the composed rule set because tenant-
    // scope blocks compose against the proxy's resolved values, and
    // origin-scope blocks compose against the tenant's (or proxy's
    // when the origin has no tenant block).
    let (proxy_enabled, proxy_rules) = match proxy_redact.and_then(|r| r.pii.as_ref()) {
        Some(block) => compose_pii_rules(false, &std::collections::BTreeSet::new(), block),
        None => (false, std::collections::BTreeSet::new()),
    };
    let proxy_pii = if proxy_enabled {
        build_pii_from_rule_names(&proxy_rules, "proxy")
    } else {
        None
    };

    // Build the tenant map. A tenant without a `pii:` block has no
    // entry, so resolution falls through to proxy scope.
    let mut tenant_pii: std::collections::HashMap<
        String,
        Option<sbproxy_security::pii::PiiRedactor>,
    > = std::collections::HashMap::new();
    let mut tenant_resolved: std::collections::HashMap<
        String,
        (bool, std::collections::BTreeSet<String>),
    > = std::collections::HashMap::new();
    for tenant in &server.tenants {
        let block = match tenant
            .observability
            .as_ref()
            .and_then(|o| o.log.redact.pii.as_ref())
        {
            Some(b) => b,
            None => continue,
        };
        let (enabled, rules) = compose_pii_rules(proxy_enabled, &proxy_rules, block);
        tenant_resolved.insert(tenant.id.clone(), (enabled, rules.clone()));
        let slot = if enabled {
            build_pii_from_rule_names(&rules, &format!("tenant `{}`", tenant.id))
        } else {
            None
        };
        // Note: an `enabled: false` tenant stores `None` here so the
        // resolver treats the entry as an explicit opt-out. A tenant
        // whose composed rule set is empty but `enabled: true` also
        // stores `None` (build_pii_from_rule_names returns `None` on
        // empty input), which matches the proxy-scope behaviour of
        // not running a PII pass when no rules are selected.
        tenant_pii.insert(tenant.id.clone(), slot);
    }

    // Build the origin map. Origins without a `tenant_id` (or with
    // the synthetic `__default__` tenant) compose against the proxy
    // scope; origins with a declared tenant compose against the
    // tenant's resolved state when present, falling back to proxy
    // scope when the tenant has no block of its own.
    let mut origin_pii: std::collections::HashMap<
        String,
        Option<sbproxy_security::pii::PiiRedactor>,
    > = std::collections::HashMap::new();
    for origin in &compiled.origins {
        let block = match origin
            .observability
            .as_ref()
            .and_then(|o| o.log.redact.pii.as_ref())
        {
            Some(b) => b,
            None => continue,
        };
        let tenant_id_str = origin.tenant_id.as_str();
        let (parent_enabled, parent_rules) = match tenant_resolved.get(tenant_id_str) {
            Some((e, r)) => (*e, r.clone()),
            None => (proxy_enabled, proxy_rules.clone()),
        };
        let (enabled, rules) = compose_pii_rules(parent_enabled, &parent_rules, block);
        let slot = if enabled {
            build_pii_from_rule_names(&rules, &format!("origin `{}`", origin.hostname))
        } else {
            None
        };
        // Key the origin map on the hostname so `StructuredLog.route`
        // (today: the origin's hostname) resolves at emit time. When
        // a future request_phase change starts stamping `hostname +
        // path-prefix` on `route`, mirror the same string here.
        origin_pii.insert(origin.hostname.to_string(), slot);
    }

    // WOR-1042: compose per-tenant + per-origin field-key denylists
    // and regex pattern sets. `fields:` is additive only at every
    // scope; `patterns:` is additive with a per-scope `disable:` opt
    // out keyed on the pattern name (built-in denylist + proxy
    // patterns are never disable-able by tenant/origin scope).
    let mut tenant_fields: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut tenant_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>> =
        std::collections::HashMap::new();
    // Keep the parent compiled set keyed by name so child scope
    // `disable:` lookups are O(1). Parent (proxy) names + compiled
    // entries cached for re-use by the origin walk.
    let proxy_pattern_names: Vec<String> = proxy_redact
        .map(|c| c.patterns.iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    let proxy_compiled_by_name: std::collections::HashMap<String, (regex::Regex, String)> =
        proxy_pattern_names
            .iter()
            .cloned()
            .zip(patterns.iter().cloned())
            .collect();

    for tenant in &server.tenants {
        let redact = match tenant.observability.as_ref().map(|o| &o.log.redact) {
            Some(r) => r,
            None => continue,
        };
        // Fields: additive on top of the proxy set.
        let mut merged_fields = fields.clone();
        for f in &redact.fields {
            let lower = f.to_ascii_lowercase();
            if !merged_fields.contains(&lower) {
                merged_fields.push(lower);
            }
        }
        // Patterns: start from proxy minus this tenant's `disable:`
        // set, then add tenant patterns.
        let disable: std::collections::HashSet<&str> =
            redact.disable.iter().map(|s| s.as_str()).collect();
        let mut merged_patterns: Vec<(regex::Regex, String)> = proxy_pattern_names
            .iter()
            .filter_map(|name| {
                if disable.contains(name.as_str()) {
                    None
                } else {
                    proxy_compiled_by_name.get(name).cloned()
                }
            })
            .collect();
        for p in &redact.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    merged_patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        scope = %format!("tenant `{}`", tenant.id),
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
        tenant_fields.insert(tenant.id.clone(), merged_fields);
        tenant_patterns.insert(tenant.id.clone(), merged_patterns);
    }

    let mut origin_fields: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut origin_patterns_map: std::collections::HashMap<String, Vec<(regex::Regex, String)>> =
        std::collections::HashMap::new();
    for origin in &compiled.origins {
        let redact = match origin.observability.as_ref().map(|o| &o.log.redact) {
            Some(r) => r,
            None => continue,
        };
        let tenant_id_str = origin.tenant_id.as_str();
        // Parent fields: tenant if present, else proxy.
        let parent_fields = tenant_fields
            .get(tenant_id_str)
            .cloned()
            .unwrap_or_else(|| fields.clone());
        let mut merged_fields = parent_fields;
        for f in &redact.fields {
            let lower = f.to_ascii_lowercase();
            if !merged_fields.contains(&lower) {
                merged_fields.push(lower);
            }
        }
        // Parent patterns: tenant if present, else proxy. Build a
        // name-keyed map on the fly so this scope's `disable:` can
        // remove parent entries by name.
        let parent_compiled = tenant_patterns
            .get(tenant_id_str)
            .cloned()
            .unwrap_or_else(|| patterns.clone());
        let disable: std::collections::HashSet<&str> =
            redact.disable.iter().map(|s| s.as_str()).collect();
        // We do not carry pattern names through the compiled list,
        // so origin `disable:` can only remove patterns the operator
        // re-named at the proxy scope. Honour the disable list by
        // name against proxy + tenant-declared pattern names.
        let mut tenant_pattern_names: Vec<String> = proxy_pattern_names.clone();
        if let Some(t) = server.tenants.iter().find(|t| t.id == tenant_id_str) {
            if let Some(o) = t.observability.as_ref() {
                for p in &o.log.redact.patterns {
                    tenant_pattern_names.push(p.name.clone());
                }
            }
        }
        let mut merged_patterns: Vec<(regex::Regex, String)> = parent_compiled
            .into_iter()
            .zip(tenant_pattern_names.iter())
            .filter_map(|(entry, name)| {
                if disable.contains(name.as_str()) {
                    None
                } else {
                    Some(entry)
                }
            })
            .collect();
        for p in &redact.patterns {
            match regex::Regex::new(&p.pattern) {
                Ok(re) => {
                    let replacement = p
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[REDACTED:{}]", p.name.to_ascii_uppercase()));
                    merged_patterns.push((re, replacement));
                }
                Err(e) => {
                    tracing::warn!(
                        scope = %format!("origin `{}`", origin.hostname),
                        pattern = %p.name,
                        error = %e,
                        "skipping invalid redact pattern; install continues without it"
                    );
                }
            }
        }
        origin_fields.insert(origin.hostname.to_string(), merged_fields);
        origin_patterns_map.insert(origin.hostname.to_string(), merged_patterns);
    }

    sbproxy_observe::logging::install_op_redact_config(sbproxy_observe::logging::OpRedactState {
        fields,
        patterns,
        tenant_fields,
        tenant_patterns,
        origin_fields,
        origin_patterns: origin_patterns_map,
        proxy_pii,
        tenant_pii,
        origin_pii,
    });

    // Teach every redaction path which primary headers can carry inbound
    // credentials. This union covers minted/configured carriers and native
    // provider-hint carriers; match-only `also_header` values are excluded.
    let credential_carriers = compiled
        .server
        .key_management
        .as_ref()
        .map(|km| km.inbound.credential_carrier_names())
        .unwrap_or_default();
    sbproxy_observe::logging::set_swept_header_names(credential_carriers.clone());
    sbproxy_config::types::set_extra_sensitive_headers(credential_carriers);
}

/// Compose a child scope's `(enabled, rules)` from the parent's
/// resolved values plus the child's add / disable lists. The child's
/// `enabled` overrides the parent when set; an unset `enabled` inherits
/// the parent's flag. The rules set is the parent's rules plus the
/// child's `rules:` minus the child's `disable:`.
fn compose_pii_rules(
    parent_enabled: bool,
    parent_rules: &std::collections::BTreeSet<String>,
    block: &sbproxy_config::ObservabilityPiiConfig,
) -> (bool, std::collections::BTreeSet<String>) {
    let enabled = block.enabled.unwrap_or(parent_enabled);
    let mut rules = parent_rules.clone();
    // Special case for the proxy scope: an empty `rules:` at the
    // proxy scope (no parent to inherit from) means "all defaults".
    // We model this by treating an empty parent + empty rules + no
    // disable as a sentinel and substituting the full default name
    // list. Tenant and origin scopes have a non-empty parent set
    // whenever the proxy scope enabled PII, so this branch only
    // applies at the proxy scope.
    if parent_rules.is_empty() && block.rules.is_empty() {
        for r in sbproxy_security::pii::default_rules() {
            rules.insert(r.name);
        }
    } else {
        for r in &block.rules {
            rules.insert(r.clone());
        }
    }
    for d in &block.disable {
        rules.remove(d);
    }
    (enabled, rules)
}

/// Build a `PiiRedactor` from a set of built-in rule names. Returns
/// `None` when the set is empty or every requested rule is unknown.
/// Unknown rule names are warn-logged with the `scope_label` so an
/// operator typo at any scope surfaces in the logs.
fn build_pii_from_rule_names(
    rule_names: &std::collections::BTreeSet<String>,
    scope_label: &str,
) -> Option<sbproxy_security::pii::PiiRedactor> {
    if rule_names.is_empty() {
        return None;
    }
    let defaults = sbproxy_security::pii::default_rules();
    let known: std::collections::HashSet<&str> = defaults.iter().map(|r| r.name.as_str()).collect();
    for want in rule_names {
        if !known.contains(want.as_str()) {
            tracing::warn!(
                scope = %scope_label,
                rule = %want,
                "unknown PII rule name; skipping (typo or removed default?)"
            );
        }
    }
    let selected: Vec<_> = defaults
        .into_iter()
        .filter(|r| rule_names.contains(&r.name))
        .collect();
    if selected.is_empty() {
        return None;
    }
    let pii_config = sbproxy_security::pii::PiiConfig {
        enabled: true,
        defaults: false,
        rules: selected,
        redact_request: false,
        redact_response: false,
    };
    match sbproxy_security::pii::PiiRedactor::from_config(&pii_config) {
        Ok(redactor) => Some(redactor),
        Err(e) => {
            tracing::warn!(
                scope = %scope_label,
                error = %e,
                "failed to build operator PII redactor; PII pass disabled at this scope"
            );
            None
        }
    }
}

/// WOR-1045 PR1: validate the declared `proxy.observability.log.sinks:`
/// block. PR1 does NOT wire dispatch; this is a soundness check so
/// operators see issues before PR2 lights up the fan-out.
///
/// Reports:
///
/// * Duplicate `name` within the scope (rejected by PR2; warned here).
/// * Unknown `target` (`access_log` / `error_log` / `audit_log` /
///   `trace_exporter` / `external_log`). PR2 will reject these.
/// * Unknown `profile` (`internal` / `external`). PR2 will reject these.
///
/// Per-tenant and per-origin sink scopes land alongside the
/// WOR-1051 credentials epic; this helper covers only the proxy scope
/// today.
/// Build the prompt-persistence sealer from `admin.prompt_persistence_encryption`.
///
/// Returns `Ok(None)` when the block is absent or disabled, which keeps records
/// as plaintext JSON and matches the behaviour before this existed.
///
/// Every failure is fatal by design. `enabled: true` with no key, an
/// unresolvable reference, and material under the minimum length all abort
/// startup rather than falling back to plaintext. An operator who asked for
/// encryption and did not get it must not learn that from a file they read
/// months later.
fn build_prompt_sealer(
    admin: Option<&sbproxy_config::AdminConfig>,
) -> anyhow::Result<Option<std::sync::Arc<crate::admin::PromptSealer>>> {
    use anyhow::Context as _;

    let Some(enc) = admin
        .and_then(|a| a.prompt_persistence_encryption.as_ref())
        .filter(|enc| enc.enabled)
    else {
        return Ok(None);
    };

    let reference = enc.key.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "admin.prompt_persistence_encryption.enabled is true but no `key` is set; point \
             `key` at a secret reference such as `secret://local/prompt-persistence` or set \
             `enabled: false`"
        )
    })?;

    let resolve = |reference: &str| {
        crate::pipeline::resolve_at_rest_key_material(
            reference,
            "admin.prompt_persistence_encryption",
        )
    };
    let active = resolve(reference).context("admin.prompt_persistence_encryption.key")?;
    let mut previous = Vec::with_capacity(enc.previous_keys.len());
    for (index, reference) in enc.previous_keys.iter().enumerate() {
        previous.push(resolve(reference).with_context(|| {
            format!("admin.prompt_persistence_encryption.previous_keys[{index}]")
        })?);
    }

    let sealer = crate::admin::prompt_key_ring(active, previous)
        .context("admin.prompt_persistence_encryption")?;
    tracing::info!(
        key_id = %sealer.active_key_id(),
        retired_keys = enc.previous_keys.len(),
        "prompt persistence will seal records at rest"
    );
    Ok(Some(std::sync::Arc::new(sealer)))
}

fn validate_sinks_config(server: &sbproxy_config::ProxyServerConfig) {
    let sinks = match server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .map(|l| &l.sinks)
    {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };

    const KNOWN_TARGETS: &[&str] = &[
        "access_log",
        "error_log",
        "audit_log",
        "trace_exporter",
        "external_log",
    ];
    const KNOWN_PROFILES: &[&str] = &["internal", "external"];

    let mut seen: std::collections::HashSet<&str> =
        std::collections::HashSet::with_capacity(sinks.len());
    for sink in sinks {
        if !seen.insert(sink.name.as_str()) {
            tracing::warn!(
                sink = %sink.name,
                "duplicate sink name at proxy scope; PR2 will reject (PR1 only warns)"
            );
        }
        if !KNOWN_TARGETS.contains(&sink.target.as_str()) {
            tracing::warn!(
                sink = %sink.name,
                target = %sink.target,
                "unknown sink target; PR2 will reject (PR1 only warns)"
            );
        }
        if let Some(profile) = sink.profile.as_deref() {
            if !KNOWN_PROFILES.contains(&profile) {
                tracing::warn!(
                    sink = %sink.name,
                    profile = %profile,
                    "unknown sink profile; PR2 will reject (PR1 only warns)"
                );
            }
        }
    }

    tracing::info!(
        count = sinks.len(),
        "WOR-1045 PR1: parsed sinks block; dispatch wiring lands in PR2"
    );
}

/// Environment variable that widens the startup signal window.
///
/// Deliberately not `pub`. The test that sets it lives in another crate
/// and repeats the string, which would normally be the kind of coupling
/// worth exporting a constant for; here it is not, because the test does
/// not have to trust the name. It asserts the hold actually took effect
/// (connected but not yet serving) before it signals, so a renamed or
/// broken hook fails that precondition rather than quietly turning the
/// regression test into one that measures nothing.
const STARTUP_SIGNAL_WINDOW_HOLD_ENV: &str = "SBPROXY_TEST_STARTUP_SIGNAL_HOLD_MS";

/// Hold the process inside the startup signal window, for tests only.
///
/// The window this sits in is real but short: on an unloaded machine the
/// listener is bound and Pingora owns the signal within a few
/// milliseconds. A test that tries to land a SIGTERM in it by timing
/// alone is a coin flip, and a coin-flip test cannot tell "the guard
/// works" from "the signal missed the window", which is the only thing
/// the test exists to distinguish. Widening the window on request makes
/// the same code path deterministic to hit.
///
/// The delay runs after the bind, so a client that connects sees the
/// same accepting-but-not-serving socket a real deploy would, and it
/// runs before `Server::run`, so [`install_early_terminate_guard`] is
/// the only thing standing between a SIGTERM and the default
/// disposition. Both properties are what make the resulting test
/// discriminating rather than merely green.
///
/// Unset, malformed, or `0` means no hold, so the production path is a
/// single failed `env::var` lookup.
fn hold_open_startup_signal_window() {
    let Ok(raw) = std::env::var(STARTUP_SIGNAL_WINDOW_HOLD_ENV) else {
        return;
    };
    let Ok(millis) = raw.trim().parse::<u64>() else {
        tracing::warn!(
            var = STARTUP_SIGNAL_WINDOW_HOLD_ENV,
            value = %raw,
            "startup signal-window hold is not a whole number of milliseconds; ignoring"
        );
        return;
    };
    if millis == 0 {
        return;
    }
    tracing::warn!(
        var = STARTUP_SIGNAL_WINDOW_HOLD_ENV,
        millis,
        "holding open the startup signal window; this is a test hook and must never be set in \
         production, where it delays serving by exactly this long"
    );
    std::thread::sleep(std::time::Duration::from_millis(millis));
}

/// How long the startup guard waits for Pingora to confirm it took a
/// SIGTERM before deciding that Pingora missed it.
///
/// Pingora broadcasts `GracefulTerminate` the moment its own stream
/// receives the signal, ahead of any draining, so the confirmation is a
/// scheduling delay rather than a shutdown. Generous by two orders of
/// magnitude on purpose: firing early would abandon a real drain, and
/// the cost of being late is only that a deploy waits this long in a
/// case that should never happen.
const PINGORA_TERMINATE_HANDOVER_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Handle SIGTERM during startup, before Pingora's handler exists.
///
/// Registers a terminate stream on `runtime` and exits cleanly if the
/// signal arrives while the process is still starting up. Without this
/// the default disposition applies and the process is killed outright,
/// which is what WOR-2452 caught as `SIGTERM exit was signal: 15`.
///
/// Exiting is the correct graceful shutdown for that state, not a
/// shortcut. The run loop has not started, so no request has been
/// accepted and there is nothing to drain; anything the kernel queued
/// into the listen backlog was never ours to answer.
///
/// Registering the stream **without** acting on it would be worse than
/// the bug. The default disposition would still be displaced, so the
/// process would ignore SIGTERM entirely during startup and a deploy
/// would hang until the orchestrator escalated to SIGKILL. Trading a
/// fast death for a slow one is not an improvement.
///
/// # Why the handover watches phases instead of a flag
///
/// The guard has to stand down once Pingora owns the signal, or it would
/// exit from under a real drain. The obvious way to do that is a flag set
/// just before `Server::run`, and it is wrong, because "we are about to
/// call run" is not the same fact as "Pingora is listening for signals".
///
/// Pingora sends `ExecutionPhase::Running` and *then* calls
/// `run_args.shutdown_signal.recv()`, and the terminate stream is
/// registered inside that `recv`, not before it. tokio delivers a signal
/// only to streams that already exist, so a SIGTERM landing between the
/// flag and that registration would be dropped by a guard that had
/// already stood down and never seen by a stream that did not yet exist.
/// The process would then ignore SIGTERM outright: the slow death this
/// function's whole design is trying to avoid, in a window a flag makes
/// invisible.
///
/// So the guard resolves the ambiguity after the fact instead of
/// predicting it. Before `Running` it owns the signal outright. At or
/// after `Running` it waits [`PINGORA_TERMINATE_HANDOVER_GRACE`] for the
/// `GracefulTerminate` broadcast that proves Pingora received the same
/// signal, and stands down when it arrives. If it does not arrive, the
/// signal fell in the gap and the guard exits rather than leaving the
/// process unresponsive.
fn install_early_terminate_guard(
    runtime: &tokio::runtime::Runtime,
    mut phases: tokio::sync::broadcast::Receiver<pingora_core::server::ExecutionPhase>,
) {
    use pingora_core::server::ExecutionPhase;
    use tokio::sync::broadcast::error::RecvError;

    runtime.spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(error) => {
                    // Startup continues: Pingora registers its own handler
                    // shortly and the window stays open rather than the boot
                    // failing over a signal stream.
                    tracing::warn!(
                        error = %error,
                        "could not install the startup SIGTERM guard; a signal before the run \
                         loop starts will kill the process outright"
                    );
                    return;
                }
            };

        // Track whether the run loop has reached the point where Pingora
        // is about to take the signal. `Lagged` and `Closed` both resolve
        // to "assume it has": either can mean `Running` was missed, and
        // assuming the later state only ever costs the bounded wait
        // below, while assuming the earlier one would exit from under a
        // live drain.
        let mut running = false;
        loop {
            tokio::select! {
                phase = phases.recv() => match phase {
                    Ok(ExecutionPhase::Running) => running = true,
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) | Err(RecvError::Closed) => running = true,
                },
                _ = term.recv() => break,
            }
        }

        if running {
            // Pingora is either handling this same signal or missed it by
            // a hair. Its `GracefulTerminate` broadcast is the only
            // evidence that distinguishes the two.
            let confirmed = tokio::time::timeout(PINGORA_TERMINATE_HANDOVER_GRACE, async {
                loop {
                    match phases.recv().await {
                        Ok(ExecutionPhase::GracefulTerminate) => return true,
                        Ok(_) => {}
                        Err(RecvError::Lagged(_)) => {}
                        // The server was dropped, which only happens once
                        // `run` has returned. Shutdown is already underway.
                        Err(RecvError::Closed) => return true,
                    }
                }
            })
            .await
            .unwrap_or(false);
            if confirmed {
                return;
            }
            tracing::warn!(
                event = "shutdown_signal_received",
                signal = "SIGTERM",
                kind = "handover",
                grace_ms = PINGORA_TERMINATE_HANDOVER_GRACE.as_millis() as u64,
                "SIGTERM arrived as the run loop was taking over and Pingora did not report it; \
                 exiting rather than leaving the process unresponsive to the signal"
            );
            std::process::exit(0);
        }

        tracing::info!(
            event = "shutdown_signal_received",
            signal = "SIGTERM",
            kind = "startup",
            "SIGTERM received before the run loop started; exiting cleanly with nothing to drain"
        );
        std::process::exit(0);
    });
}

/// Warn about decision-audit events an operator enabled that nothing
/// publishes yet (WOR-2446).
///
/// The config accepts every known event label on purpose: refusing an
/// unwired one would block pre-configuring an event a later release
/// wires, and would fail a correct config because of a gap in our own
/// instrumentation. That leaves the operator with no signal at the
/// moment the mistake is made, and a silent audit feed reads exactly
/// like a feed with nothing to report.
///
/// So this warns rather than refuses, once at boot, naming each event
/// so the message is actionable rather than a count.
fn warn_unwired_decision_audit_events(compiled: &sbproxy_config::CompiledConfig) {
    use sbproxy_observe::decision::EventCoverage;

    let enabled_unwired = unwired_decision_audit_events(compiled);
    let with_coverage = |want: EventCoverage| -> Vec<&str> {
        enabled_unwired
            .iter()
            .copied()
            .filter(|label| {
                sbproxy_observe::decision::DecisionEvent::from_label(label)
                    .is_some_and(|event| event.coverage() == want)
            })
            .collect()
    };
    let superseded = with_coverage(EventCoverage::SupersededByPolicy);
    let durable_elsewhere = with_coverage(EventCoverage::DurableElsewhere);
    let wrong_format = with_coverage(EventCoverage::ConfigDependent);
    let unwired = with_coverage(EventCoverage::Unwired);

    // Two messages, because they are two different problems and one
    // wording cannot be true of both. An unwired event publishes
    // nothing and the operator can only wait. A superseded one is
    // already publishing, under `policy`, and the operator has a query
    // to write today. Folding them together told an operator that `waf`
    // emits nothing while their WAF denials were on the bus the whole
    // time (WOR-2446).
    if !superseded.is_empty() {
        tracing::warn!(
            events = %superseded.join(", "),
            "decision_audit enables events whose decisions already publish as `policy` records: \
             these run in the policy chain, so enable `policy` and select on the `policy_id` \
             field instead. They will never emit under their own label"
        );
    }
    if !wrong_format.is_empty() {
        // Reached only under the legacy format: the converged one makes
        // `publishes_decision_audit` true, so the event never enters the
        // enabled-but-not-publishing set at all. Naming it as unwired
        // would be false in both formats, and saying nothing would leave
        // an operator who enabled it waiting on a feed one setting away.
        tracing::warn!(
            events = %wrong_format.join(", "),
            "decision_audit enables events that publish in a different record shape: they \
             reach the audit bus today as policy_verdict_event rather than on this feed. Set \
             policy_record_format: decision to receive them here"
        );
    }
    if !durable_elsewhere.is_empty() {
        tracing::warn!(
            events = %durable_elsewhere.join(", "),
            "decision_audit enables events that are recorded on a durable store instead of this \
             feed, and will never publish here: this queue drops records under load, which is a \
             sound trade for a security decision and the wrong one for money. Read the \
             settlement store and the billing usage sinks for payment history"
        );
    }
    if !unwired.is_empty() {
        tracing::warn!(
            events = %unwired.join(", "),
            wired = %wired_decision_audit_events(compiled).join(", "),
            "decision_audit enables events that nothing publishes yet; they emit no records until \
             their emitters ship"
        );
    }
}

/// Whether `event` lands a record on the decision-audit feed under this
/// config.
///
/// Not the same question as [`DecisionEvent::has_emitter`], and `policy`
/// is why. That event has always reached the audit bus, but until
/// `policy_record_format: decision` it arrives as a `PolicyVerdictEvent`
/// on its own prefix rather than as a decision-audit record, so whether
/// it counts as wired *here* depends on config rather than on a const
/// (WOR-2448).
///
/// Asking the const alone would tell an operator who set
/// `policy_record_format: decision` and `events: {policy: true}` that
/// nothing publishes `policy`, while the records they asked for were
/// landing on the feed they were reading. A warning that is wrong about
/// the one event an operator deliberately turned on is worse than no
/// warning.
fn publishes_decision_audit(
    event: sbproxy_observe::decision::DecisionEvent,
    compiled: &sbproxy_config::CompiledConfig,
) -> bool {
    use sbproxy_config::types::PolicyRecordFormat;
    use sbproxy_observe::decision::{DecisionEvent, EventCoverage};

    if event == DecisionEvent::Policy {
        return compiled.decision_audit.policy_record_format() == PolicyRecordFormat::Decision;
    }
    matches!(event.coverage(), EventCoverage::Emitted)
}

/// The events publishing decision-audit records under this config.
fn wired_decision_audit_events(compiled: &sbproxy_config::CompiledConfig) -> Vec<&'static str> {
    sbproxy_observe::decision::DecisionEvent::ALL
        .iter()
        .filter(|event| publishes_decision_audit(**event, compiled))
        .map(|event| event.as_label())
        .collect()
}

/// The events this config enables that publish nothing.
///
/// Split out of the warning so it can be tested directly: the warning
/// itself only logs, and a feed that silently names the wrong events is
/// exactly the failure this whole surface exists to avoid.
pub(super) fn unwired_decision_audit_events(
    compiled: &sbproxy_config::CompiledConfig,
) -> Vec<&'static str> {
    use sbproxy_observe::decision::DecisionEvent;

    let scopes = &compiled.decision_audit;
    if scopes.is_empty() {
        return Vec::new();
    }
    // Any scope enabling an event is worth naming, because the operator
    // asked for it somewhere. Reporting per scope would repeat the same
    // missing emitter once per tenant and origin.
    DecisionEvent::ALL
        .iter()
        .filter(|event| !publishes_decision_audit(**event, compiled))
        .filter(|event| {
            let label = event.as_label();
            scopes.publishes(label, None, None)
                || scopes
                    .tenants
                    .keys()
                    .any(|tenant| scopes.publishes(label, Some(tenant), None))
                || scopes
                    .origins
                    .keys()
                    .any(|origin| scopes.publishes(label, None, Some(origin)))
        })
        .map(|event| event.as_label())
        .collect()
}

/// Warn while `policy` records still ship in the legacy shape
/// (WOR-2448).
///
/// The deprecation is announced at boot rather than only in the docs,
/// because the operator who most needs to know is the one who has never
/// read that section: their consumer parses `policy_verdict_event:` and
/// will stop matching when the default flips. A line naming the setting
/// and the release is the difference between a scheduled migration and
/// an outage on upgrade.
///
/// Silent when the block is absent entirely. An operator who has not
/// configured decision audit at all has no consumer to migrate, and
/// warning them about a format they do not read is how a startup log
/// becomes noise nobody scans.
fn warn_legacy_policy_record_format(compiled: &sbproxy_config::CompiledConfig) {
    use sbproxy_config::types::PolicyRecordFormat;

    if compiled.decision_audit.is_empty() {
        return;
    }
    if compiled.decision_audit.policy_record_format() != PolicyRecordFormat::Legacy {
        return;
    }
    tracing::warn!(
        setting = "proxy.observability.log.decision_audit.policy_record_format",
        current = PolicyRecordFormat::Legacy.as_label(),
        migrate_to = PolicyRecordFormat::Decision.as_label(),
        "policy decisions still publish the legacy policy_verdict_event shape, which carries no \
         reason and cannot be joined with the other decision events; set policy_record_format: \
         decision once your consumer reads decision_audit_event. The legacy shape is deprecated \
         and this setting's default changes in the next major release"
    );
}

/// WOR-1045 PR2: build a [`sbproxy_observe::SinkDispatcher`] from the
/// compiled config and install it process-wide. The dispatcher walks
/// three scope lists:
///
/// * `proxy.observability.log.sinks:` (proxy scope, receives every record).
/// * `tenants[].observability.log.sinks:` (tenant scope, filtered by
///   `record.tenant_id`).
/// * `origins[].observability.log.sinks:` (origin scope, filtered by
///   `record.route`).
///
/// When zero sinks are declared the dispatcher installs an empty
/// snapshot so `current_sink_dispatcher()` returns `None`; the
/// `emit()` path then falls back to the legacy single `tracing::*!`
/// subscriber and stdout behaviour is preserved.
///
/// Returns whether the dispatcher was installed. `false` means the
/// dispatcher lock was poisoned and telemetry export is unavailable;
/// the reload path records that as a degraded subsystem rather than
/// failing the reload.
/// WOR-1875: open the durable usage-rollup store and install the
/// process-global writer. Default-on: an absent config block means
/// the defaults apply. Idempotent (the writer slot is set-once), so
/// the reload path calling again is a no-op. A store that cannot open
/// (missing directory, permissions) logs a warning and leaves rollups
/// off rather than failing boot; the windowed spend API then reports
/// rollups unavailable while live counters keep working.
fn install_usage_rollups_from_config(compiled: &sbproxy_config::CompiledConfig) {
    use sbproxy_observe::usage_rollup::{
        install_usage_rollup_writer, usage_rollup_writer, RollupStore, RollupWriter,
    };
    if usage_rollup_writer().is_some() {
        return;
    }
    let cfg = compiled
        .server
        .observability
        .as_ref()
        .and_then(|o| o.usage_rollups.clone())
        .unwrap_or_default();
    if !cfg.enabled {
        return;
    }
    let path = cfg
        .path
        .clone()
        .unwrap_or_else(|| "/var/lib/sbproxy/usage-rollups.redb".to_string());
    match RollupStore::open(std::path::Path::new(&path)) {
        Ok(store) => {
            let day = 86_400u64;
            let writer = RollupWriter::spawn(
                std::sync::Arc::new(store),
                u64::from(cfg.retention_hourly_days) * day,
                u64::from(cfg.retention_daily_days) * day,
            );
            install_usage_rollup_writer(writer);
            tracing::info!(path = %path, "usage rollups enabled");
        }
        Err(e) => {
            tracing::warn!(
                path = %path,
                error = %e,
                "usage rollups disabled: store could not be opened (set \
                 proxy.observability.usage_rollups.path to a writable location)"
            );
        }
    }
}

/// WOR-2476: install the compiled top-level `egress:` authorizers into
/// `sbproxy_security::egress`'s process-wide configured-gate registry,
/// then rebuild the AI client so it picks up `AiProvider` immediately.
///
/// **The one seam both [`run`] (boot) and [`reload_compiled_config_locked`]
/// (SIGHUP / file-watcher / admin reload) call.** A prior version of this
/// arming installed the registry from `reload_compiled_config_locked`
/// only; boot never called it, so `AI_CLIENT` stayed the ungated
/// `LazyLock` default and every other purpose's registry slot stayed
/// empty until the first reload landed. Splitting "install" and "one of
/// two callers rebuilds the client" back out would silently reintroduce
/// that gap the moment a future change touched one call site and not the
/// other; call this one function from both instead.
///
/// Five reload-installed sub-blocks, six purposes: `usage_sinks:` compiles one
/// allowlist under both `UsageSink` and `Webhook`, because the sinks
/// underneath it authorize under two different, pre-existing purposes.
/// The registry is an exact-key map, so both keys have to be written or
/// the reader that asks for the missing one gets `None` and dials
/// ungated. That is not hypothetical: this function named only
/// `UsageSink`, and the `events:` webhook sink, which reads `Webhook`,
/// therefore ran with no allowlist under every config anyone could
/// write while three docs said it was gated (WOR-2612). Which keys a
/// sub-block owns is now read off the compiled authorizer itself, with
/// [`sbproxy_security::egress::EgressAuthorizer::purposes`], rather
/// than spelled out here a second time where it can disagree with what
/// `compile_egress_gates` actually built.
///
/// Five of the six purposes live behind their own, separate lazy
/// reader: the classifier client, the usage-sink builder, the `events:`
/// webhook sink, the model-artifact fetcher, and the outbound-credential
/// resolver each read their own purpose out of the registry well after
/// this function returns (the model-artifact fetcher's own staleness
/// window against a registry-only reload is documented on
/// [`sbproxy_model_host::HttpArtifactTransport::with_configured_egress`]).
/// `AiProvider` is the one purpose armed synchronously, right here,
/// because `AiClient` is a process-wide `ArcSwap` this function owns
/// rebuilding, not a lazily-read handle some other call site owns.
///
/// `Telemetry` is deliberately not installed here. The OTLP trace and
/// metric exporters are built once at process boot, before either
/// caller of this function runs (see `sbproxy::main`'s
/// `runtime_telemetry_config_for_cli`, which installs `Telemetry` itself
/// from the same compiled config, ahead of `run`), and are never rebuilt
/// on reload, so re-installing this registry slot on every reload here
/// would only ever matter for a `Telemetry` sighting those exporters are
/// not built again to produce. Reload re-verification for them happens
/// as its own reject-only step instead, `reload_compiled_config_locked`
/// calling `sbproxy_observe::telemetry::reverify_active_boot_telemetry_endpoints`,
/// which checks the still-running exporters' recorded endpoints directly
/// against this reload's freshly compiled `egress.telemetry:` value
/// rather than through this registry (WOR-2481). The OTLP-logs sink is
/// unaffected either way: it is rebuilt on every reload and
/// re-authorizes itself at construction time.
fn arm_egress_gates_from_config(compiled: &sbproxy_config::CompiledConfig) {
    use sbproxy_security::egress::{install_configured_gate, EgressAuthorizer, EgressPurpose};

    /// File one compiled sub-block under every purpose it answers for.
    ///
    /// `armed` names what an *absent* sub-block clears. There is no
    /// authorizer to ask in that case, so it stays a literal here, and
    /// it has to be a superset of what the sub-block installs: a reload
    /// that drops the block would otherwise leave a stale allowlist
    /// armed under the key it forgot.
    fn arm(armed: &[EgressPurpose], compiled: Option<EgressAuthorizer>) {
        let keys: Vec<EgressPurpose> = match &compiled {
            Some(authorizer) => authorizer.purposes(),
            None => armed.to_vec(),
        };
        for purpose in keys {
            install_configured_gate(purpose, compiled.clone());
        }
    }

    arm(
        &[EgressPurpose::AiProvider],
        compiled.egress.ai_providers.clone(),
    );
    arm(
        &[EgressPurpose::AgentOrchestration],
        compiled.egress.agent_orchestration.clone(),
    );
    arm(
        &[EgressPurpose::ClassifierHook],
        compiled.egress.classifier_hooks.clone(),
    );
    arm(
        &[EgressPurpose::UsageSink, EgressPurpose::Webhook],
        compiled.egress.usage_sinks.clone(),
    );
    // WOR-2712: the events webhook SSRF guard runs before the
    // governed-egress authorizer, so `allow_private` on this
    // sub-block has to reach that earlier check too. Empty when
    // the block is absent or `allow_private` is false: deny-by-default.
    sbproxy_observe::arm_webhook_ssrf_allowlist(
        compiled
            .egress
            .usage_sinks
            .as_ref()
            .map(|authorizer| authorizer.ssrf_private_hosts(EgressPurpose::Webhook))
            .unwrap_or_default(),
    );
    arm(
        &[EgressPurpose::ModelArtifact],
        compiled.egress.model_artifacts.clone(),
    );
    arm(
        &[EgressPurpose::TokenExchange],
        compiled.egress.token_exchange.clone(),
    );
    arm(
        &[EgressPurpose::Federation],
        compiled.egress.federation.clone(),
    );
    // Rebuild the AI client immediately, in the same call, so `AiProvider`
    // is live before this function returns rather than depending on the
    // caller to remember a second call. Lives behind an `ArcSwap`, so
    // this is a lock-free atomic swap regardless of which caller (boot
    // or reload) triggered it.
    reload_ai_client();
}

fn install_sink_dispatcher_from_config(compiled: &sbproxy_config::CompiledConfig) -> bool {
    use sbproxy_observe::sink_dispatcher::{
        install_sink_dispatcher, CompiledSink, SinkDispatcher, SinkScope,
    };

    // Resolve the top-level telemetry block once so OTLP sinks
    // inherit `transport`, `service_name`, `resource_attrs` without
    // re-deriving the defaults per sink.
    let telemetry_defaults = compiled
        .server
        .observability
        .as_ref()
        .and_then(|o| o.telemetry.as_ref());

    let mut compiled_sinks: Vec<CompiledSink> = Vec::new();

    // Proxy scope.
    let proxy_sinks: &[sbproxy_config::ObservabilitySinkConfig] = compiled
        .server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .map(|l| l.sinks.as_slice())
        .unwrap_or(&[]);
    for raw in proxy_sinks {
        if let Some(sink) = compile_one_sink(raw, SinkScope::Proxy, false, telemetry_defaults) {
            compiled_sinks.push(sink);
        }
    }

    // Tenant scope.
    for tenant in &compiled.server.tenants {
        let Some(obs) = tenant.observability.as_ref() else {
            continue;
        };
        for raw in &obs.log.sinks {
            if let Some(sink) = compile_one_sink(
                raw,
                SinkScope::Tenant(tenant.id.clone()),
                true,
                telemetry_defaults,
            ) {
                compiled_sinks.push(sink);
            }
        }
    }

    // Origin scope.
    for origin in &compiled.origins {
        let Some(obs) = origin.observability.as_ref() else {
            continue;
        };
        for raw in &obs.log.sinks {
            if let Some(sink) = compile_one_sink(
                raw,
                SinkScope::Origin(origin.hostname.to_string()),
                true,
                telemetry_defaults,
            ) {
                compiled_sinks.push(sink);
            }
        }
    }

    let count = compiled_sinks.len();
    // WOR-1099: a failed install (poisoned dispatcher lock) leaves the
    // proxy serving traffic with no log/event export. Surface it
    // instead of discarding the result bool.
    let installed = install_sink_dispatcher(SinkDispatcher::new(compiled_sinks));
    if !installed {
        sbproxy_observe::metrics::record_sink_install_failure();
        tracing::error!(
            count,
            "failed to install sink dispatcher (dispatcher lock poisoned); telemetry export may be unavailable"
        );
    }
    if count > 0 {
        tracing::info!(
            count,
            "WOR-1045 PR2: installed sink dispatcher with declared sinks"
        );
    } else {
        tracing::debug!(
            "WOR-1045 PR2: no sinks declared; emit() falls back to the legacy tracing subscriber"
        );
    }
    installed
}

/// Compile a single declared sink. Returns `None` when the YAML
/// declared an unknown target or output type the dispatcher cannot
/// honour; we keep this lenient (warn + skip) rather than abort the
/// whole reload because a single misconfigured sink should not take
/// down the proxy.
fn compile_one_sink(
    raw: &sbproxy_config::ObservabilitySinkConfig,
    scope: sbproxy_observe::sink_dispatcher::SinkScope,
    default_external_profile: bool,
    telemetry: Option<&sbproxy_config::ObservabilityTelemetryConfig>,
) -> Option<sbproxy_observe::sink_dispatcher::CompiledSink> {
    use sbproxy_observe::sink_dispatcher::{
        CompiledSink, FileSink, Profile, SinkFormat, SinkOutput, StderrSink, StdoutSink,
    };
    use sbproxy_observe::Sink;

    let target = match raw.target.as_str() {
        "access_log" => Sink::AccessLog,
        "error_log" => Sink::ErrorLog,
        "audit_log" => Sink::AuditLog,
        "trace_exporter" => Sink::TraceExporter,
        "external_log" => Sink::External,
        other => {
            tracing::warn!(
                sink = %raw.name,
                target = %other,
                "unknown sink target; skipping sink"
            );
            return None;
        }
    };

    let format = match raw.format.as_deref().unwrap_or("compact") {
        "pretty" => SinkFormat::Pretty,
        "json" => SinkFormat::Json,
        _ => SinkFormat::Compact,
    };

    let profile = match raw.profile.as_deref() {
        Some("external") => Profile::External,
        Some("internal") => Profile::Internal,
        Some(other) => {
            tracing::warn!(
                sink = %raw.name,
                profile = %other,
                "unknown sink profile; defaulting to scope's default"
            );
            if default_external_profile {
                Profile::External
            } else {
                Profile::Internal
            }
        }
        None => {
            if default_external_profile {
                Profile::External
            } else {
                Profile::Internal
            }
        }
    };

    let output: Box<dyn SinkOutput> = match &raw.output {
        sbproxy_config::ObservabilitySinkOutput::Stdout => Box::new(StdoutSink),
        sbproxy_config::ObservabilitySinkOutput::Stderr => Box::new(StderrSink),
        sbproxy_config::ObservabilitySinkOutput::File {
            path,
            max_size_mb,
            max_backups,
            compress,
        } => {
            let mut fs = FileSink::new(std::path::PathBuf::from(path));
            if let Some(mb) = *max_size_mb {
                fs.max_size_bytes = mb.saturating_mul(1024 * 1024);
            }
            if let Some(b) = *max_backups {
                fs.max_backups = b as usize;
            }
            if let Some(c) = *compress {
                fs.compress = c;
            }
            Box::new(fs)
        }
        sbproxy_config::ObservabilitySinkOutput::Otlp {
            endpoint,
            transport,
            timeout_secs,
        } => {
            // The OTel BatchLogProcessor spawns a worker via
            // `tokio::spawn`, which requires an ambient runtime. The
            // first-boot install path runs before Pingora installs its
            // runtime, so we skip with a warn there; the SIGHUP and
            // file-watcher reload paths execute inside the running
            // runtime and pick the sink up. Operators who want OTLP
            // logs from the very first request can SIGHUP after boot.
            if tokio::runtime::Handle::try_current().is_err() {
                // WOR-1100: count the skip so operators can see from
                // metrics (not just a boot-time warn) that OTLP logs
                // are not exporting until the first reload.
                sbproxy_observe::metrics::record_telemetry_dropped("otlp_log", "no_runtime");
                tracing::warn!(
                    sink = %raw.name,
                    "OTLP log sink declared but no tokio runtime is active; the sink will activate after the first SIGHUP / hot reload",
                );
                return None;
            }
            let transport_default = telemetry
                .and_then(|t| t.transport.as_deref())
                .unwrap_or("grpc");
            let transport_str = transport.as_deref().unwrap_or(transport_default);
            let transport = match transport_str {
                "http" => sbproxy_observe::telemetry::OtlpTransport::Http,
                _ => sbproxy_observe::telemetry::OtlpTransport::Grpc,
            };
            let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(10).max(1));
            let service_name = telemetry
                .and_then(|t| t.service_name.clone())
                .unwrap_or_else(|| "sbproxy".to_string());
            let resource_attrs = telemetry
                .map(|t| t.resource_attrs.clone())
                .unwrap_or_default();
            let opts = sbproxy_observe::OtlpLogSinkOptions {
                endpoint: endpoint.clone(),
                transport,
                service_name,
                timeout,
                resource_attrs,
                // WOR-1869: same boot-resolved auth headers as the
                // trace/metric pipelines (empty when none configured).
                headers: sbproxy_observe::telemetry::resolved_otlp_headers(),
            };
            match sbproxy_observe::OtlpLogSink::new(opts) {
                Ok(s) => Box::new(s),
                Err(e) => {
                    tracing::warn!(
                        sink = %raw.name,
                        error = %e,
                        "failed to build OTLP log sink; skipping"
                    );
                    return None;
                }
            }
        }
    };

    Some(CompiledSink {
        name: raw.name.clone(),
        scope,
        target,
        format,
        profile,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    static HOOK_ORDER_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct ReloadHookFixture;

    #[async_trait::async_trait]
    impl crate::hooks::PipelineLifecycleHook for ReloadHookFixture {
        async fn on_startup(
            &self,
            _pipeline: &mut crate::pipeline::CompiledPipeline,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn on_reload(
            &self,
            pipeline: &mut crate::pipeline::CompiledPipeline,
        ) -> anyhow::Result<()> {
            assert!(
                pipeline.hooks.startup.is_some(),
                "the linked hook must be attached before on_reload runs"
            );
            if pipeline
                .config
                .origins
                .iter()
                .any(|origin| origin.hostname == "hook-order-fixture.test")
            {
                HOOK_ORDER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            if pipeline
                .config
                .origins
                .iter()
                .any(|origin| origin.hostname == "hook-failure-fixture.test")
            {
                anyhow::bail!("fixture reload hook rejected the candidate");
            }
            Ok(())
        }
    }

    fn reload_hook_fixture() -> std::sync::Arc<dyn crate::hooks::PipelineLifecycleHook> {
        std::sync::Arc::new(ReloadHookFixture)
    }

    crate::register_startup_hook!(reload_hook_fixture);

    #[cfg(feature = "payments")]
    fn write_payment_inventory_bundle(root: &std::path::Path) {
        let bundle = root.join("bundles").join("runtime-inventory");
        std::fs::create_dir_all(&bundle).expect("create payment inventory bundle");
        std::fs::write(
            bundle.join("entry.js"),
            r#"export function inspect() {
                return { version: "sbproxy-envelope/v1", decision: "continue" };
            }
"#,
        )
        .expect("write payment inventory artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: runtime-inventory
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: runtime_guardrail
    export: inspect
  - kind: payment
    type: runtime_payment
    export: inspect
    execution:
      body_mode: none
"#,
        )
        .expect("write payment inventory manifest");
    }

    #[cfg(feature = "payments")]
    fn payment_inventory_config(root: &std::path::Path) -> sbproxy_config::CompiledConfig {
        let secret_path = root.join("binding-key.txt");
        std::fs::write(&secret_path, "binding-secret-must-not-appear")
            .expect("write payment binding key");
        let mut config = sbproxy_config::CompiledConfig::default();
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());
        config.server.payments = Some(sbproxy_config::PaymentsConfig {
            state_path: root.join("payments.sqlite3").display().to_string(),
            challenge_binding_key: format!("file:{}", secret_path.display()),
            authorization_timeout_ms: 2_000,
            max_body_bytes: 65_536,
            failure_mode: sbproxy_config::FailureMode::Closed,
            recovery_encryption: None,
            worker: sbproxy_config::PaymentsWorkerConfig::default(),
            protocols: sbproxy_config::PaymentProtocolsConfig::default(),
            rails: sbproxy_config::PaymentRailsConfig::default(),
            usage_reporters: sbproxy_config::UsageReportersConfig::default(),
        });
        config
    }

    #[cfg(feature = "payments")]
    #[test]
    fn payment_extension_inventory_activates_only_after_dispatcher_install() {
        let directory = tempfile::tempdir().expect("temporary payment inventory directory");
        write_payment_inventory_bundle(directory.path());
        let mut pipeline = crate::pipeline::CompiledPipeline::from_config_at(
            payment_inventory_config(directory.path()),
            directory.path(),
        )
        .expect("runtime candidate should prepare payment hooks");

        assert_eq!(
            pipeline.extension_inventory().scope.mode,
            sbproxy_plugin::ExtensionScopeMode::Running
        );
        let state = |pipeline: &crate::pipeline::CompiledPipeline, kind| {
            pipeline
                .extension_inventory()
                .hooks
                .iter()
                .find(|hook| hook.kind == kind)
                .map(|hook| (hook.id.clone(), hook.state))
                .expect("runtime lifecycle hook should be inventoried")
        };
        assert_eq!(
            state(
                &pipeline,
                sbproxy_plugin::ExtensionHookKind::AiGuardrailInput
            )
            .1,
            sbproxy_plugin::ExtensionState::Active
        );
        assert_eq!(
            state(&pipeline, sbproxy_plugin::ExtensionHookKind::Payment),
            (
                "runtime-inventory:payment:runtime_payment".to_owned(),
                sbproxy_plugin::ExtensionState::Unconsumed,
            )
        );

        attach_payments_runtime(&mut pipeline).expect("payment dispatcher should install");

        assert_eq!(
            pipeline.extension_inventory().scope.mode,
            sbproxy_plugin::ExtensionScopeMode::Running
        );
        assert_eq!(
            state(&pipeline, sbproxy_plugin::ExtensionHookKind::Payment),
            (
                "runtime-inventory:payment:runtime_payment".to_owned(),
                sbproxy_plugin::ExtensionState::Active,
            )
        );
        let serialized = serde_json::to_string(pipeline.extension_inventory())
            .expect("running admin inventory should serialize");
        assert!(!serialized.contains("binding-secret-must-not-appear"));
        assert!(!serialized.contains("provider-payload-must-not-appear"));
    }

    #[test]
    fn reload_reattaches_extension_startup_hook_before_on_reload() {
        HOOK_ORDER_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        reload_from_config_yaml(
            "sb.yml",
            r#"proxy: {}
origins:
  hook-order-fixture.test:
    action:
      type: static
      body: hook ran
"#,
        )
        .expect("reload should publish");

        assert_eq!(
            HOOK_ORDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one linked hook must receive one reload callback"
        );
    }

    #[test]
    fn extension_load_failure_preserves_the_current_pipeline_pointer() {
        let directory = tempfile::tempdir().expect("temporary config directory");
        let bundle = directory.path().join("bundles").join("reload-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: reload-fixture
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: reload_fixture_policy
    export: run
"#,
        )
        .expect("write bundle manifest");
        std::fs::write(
            bundle.join("entry.js"),
            "export function run() { return { version: 'sbproxy-envelope/v1', decision: 'allow' }; }",
        )
        .expect("write valid bundle artifact");
        let config_path = directory.path().join("sb.yml");
        let yaml = "proxy: {}\nextensions:\n  bundles_dir: bundles\n";
        reload_from_config_yaml(config_path.to_str().expect("UTF-8 config path"), yaml)
            .expect("first candidate should publish");
        let current = crate::reload::current_pipeline_full();

        std::fs::write(bundle.join("entry.js"), "export function anotherName() {}")
            .expect("replace bundle artifact with an invalid export");
        let error = reload_from_config_yaml(config_path.to_str().expect("UTF-8 config path"), yaml)
            .expect_err("invalid bundle candidate must fail reload");
        let after_failure = crate::reload::current_pipeline_full();

        assert!(error.to_string().contains("export"), "{error:#}");
        assert!(Arc::ptr_eq(&current, &after_failure));
    }

    #[test]
    fn rego_bundle_digest_tamper_preserves_the_current_pipeline_pointer() {
        // WOR-2482: the same verify-then-activate contract
        // `extension_load_failure_preserves_the_current_pipeline_pointer`
        // proves for a broken JavaScript export, proved here for a
        // `.rego` module changed after the digest that pinned it was
        // computed. Tampering, not a syntax error, is the threat model
        // "the previous bundle stays active" actually describes.
        let directory = tempfile::tempdir().expect("temporary config directory");
        let bundle = directory.path().join("bundles").join("rego-tamper-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        let module: &[u8] =
            b"package sbproxy\n\ndefault allow := false\n\nallow if {\n    input.request.method == \"GET\"\n}\n";
        let digest = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(module))
        };
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: rego-tamper-fixture\nversion: 1.0.0\nruntime: rego\nentry: policy.rego\nsha256: {digest}\nhooks:\n  - kind: policy\n    type: rego_tamper_fixture_policy\n    execution:\n      body_mode: none\n"
            ),
        )
        .expect("write bundle manifest");
        std::fs::write(bundle.join("policy.rego"), module).expect("write valid rego module");
        let config_path = directory.path().join("sb.yml");
        let yaml = "proxy: {}\nextensions:\n  bundles_dir: bundles\n";
        reload_from_config_yaml(config_path.to_str().expect("UTF-8 config path"), yaml)
            .expect("first candidate should publish");
        let current = crate::reload::current_pipeline_full();

        // Tamper: change the shipped bytes without updating the pinned
        // digest, exactly the threat "activate only after verification"
        // exists to catch.
        std::fs::write(
            bundle.join("policy.rego"),
            b"package sbproxy\n\ndefault allow := true\n",
        )
        .expect("replace rego module with tampered bytes");
        let error = reload_from_config_yaml(config_path.to_str().expect("UTF-8 config path"), yaml)
            .expect_err("a tampered rego bundle candidate must fail reload");
        let after_tamper = crate::reload::current_pipeline_full();

        assert!(error.to_string().contains("digest"), "{error:#}");
        assert!(
            Arc::ptr_eq(&current, &after_tamper),
            "the previous bundle must stay active when the tampered candidate is refused"
        );
    }

    #[test]
    fn extension_refresh_failure_preserves_the_current_pipeline_pointer() {
        let directory = tempfile::tempdir().expect("temporary config directory");
        let bundle = directory.path().join("bundles").join("refresh-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: refresh-fixture
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: refresh_fixture_policy
    export: run
"#,
        )
        .expect("write bundle manifest");
        std::fs::write(
            bundle.join("entry.js"),
            "export function run() { return { version: 'sbproxy-envelope/v1', decision: 'allow' }; }",
        )
        .expect("write valid bundle artifact");
        let config_path = directory.path().join("sb.yml");
        let yaml = "proxy: {}\nextensions:\n  bundles_dir: bundles\n";
        reload_from_config_yaml(config_path.to_str().expect("UTF-8 config path"), yaml)
            .expect("first candidate should publish");
        let current = crate::reload::current_pipeline_full();

        std::fs::write(bundle.join("entry.js"), "export function anotherName() {}")
            .expect("replace bundle artifact with an invalid export");
        let error = try_refresh_extension_bundles(config_path.to_str().expect("UTF-8 config path"))
            .expect_err("invalid refresh candidate must fail");
        let after_failure = crate::reload::current_pipeline_full();

        assert!(error.to_string().contains("export"), "{error:#}");
        assert!(Arc::ptr_eq(&current, &after_failure));
    }

    #[test]
    fn extension_refresh_skips_an_unchanged_candidate() {
        reload_from_config_yaml("sb.yml", "proxy: {}\n").expect("baseline candidate publishes");
        let current = crate::reload::current_pipeline_full();

        let outcome = try_refresh_extension_bundles("sb.yml").expect("refresh evaluates");
        let after = crate::reload::current_pipeline_full();

        assert!(matches!(outcome, TryBundleRefreshOutcome::NotModified));
        assert!(Arc::ptr_eq(&current, &after));
    }

    #[test]
    fn extension_refresh_skips_instead_of_overlapping_an_active_reload() {
        let guard = hold_config_reload_lock_for_test();

        let outcome = try_refresh_extension_bundles("sb.yml").expect("busy is not a failure");

        assert!(matches!(outcome, TryBundleRefreshOutcome::Busy));
        drop(guard);
    }

    #[test]
    fn changed_extension_refresh_candidate_uses_the_atomic_reload_transaction() {
        let directory = tempfile::tempdir().expect("temporary config directory");
        let bundle = directory.path().join("bundles").join("changed-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        let write_release = |version: &str, marker: &str| {
            std::fs::write(
                bundle.join("bundle.yaml"),
                format!(
                    "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: changed-fixture\nversion: {version}\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: policy\n    type: changed_fixture_policy\n    export: run\n"
                ),
            )
            .expect("write bundle manifest");
            std::fs::write(
                bundle.join("entry.js"),
                format!(
                    "export function run() {{ return {{ version: 'sbproxy-envelope/v1', decision: 'allow', marker: '{marker}' }}; }}"
                ),
            )
            .expect("write bundle artifact");
        };
        write_release("1.0.0", "one");
        let config_path = directory.path().join("sb.yml");
        let config_path = config_path.to_str().expect("UTF-8 config path");
        let yaml = "proxy: {}\nextensions:\n  bundles_dir: bundles\n";
        reload_from_config_yaml(config_path, yaml).expect("first generation publishes");
        let first = crate::reload::current_pipeline_full();
        assert_eq!(first.extension_inventory().bundles[0].version, "1.0.0");

        write_release("2.0.0", "two");
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");
        let candidate = sbproxy_extension::bundle::DynamicBundleRegistry::load(
            &compiled.extension_bundles,
            directory.path(),
            &crate::extension_inventory::reserved_extension_hook_names()
                .expect("reserved names resolve"),
        )
        .expect("changed registry candidate validates");
        let guard = CONFIG_RELOAD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reload_compiled_config_locked(config_path, compiled, Some(candidate), None, None)
            .expect("changed registry publishes");
        drop(guard);

        let second = crate::reload::current_pipeline_full();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.extension_inventory().bundles[0].version, "2.0.0");
    }

    #[test]
    fn extension_lifecycle_failure_preserves_the_current_pipeline_pointer() {
        reload_from_config_yaml("sb.yml", "proxy: {}\n")
            .expect("baseline candidate should publish");
        let current = crate::reload::current_pipeline_full();

        let error = reload_from_config_yaml(
            "sb.yml",
            r#"proxy: {}
origins:
  hook-failure-fixture.test:
    action:
      type: static
      body: rejected
"#,
        )
        .expect_err("a lifecycle failure must reject the candidate");
        let after_failure = crate::reload::current_pipeline_full();

        assert!(
            error
                .to_string()
                .contains("fixture reload hook rejected the candidate"),
            "{error:#}"
        );
        assert!(Arc::ptr_eq(&current, &after_failure));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_reload_candidate_starts_no_health_probes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe listener");
        let port = listener
            .local_addr()
            .expect("probe listener address")
            .port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener_hits = Arc::clone(&hits);
        let listener_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                listener_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let yaml = format!(
            r#"proxy: {{}}
origins:
  hook-failure-fixture.test:
    action:
      type: load_balancer
      targets:
        - url: "http://127.0.0.1:{port}"
          health_check:
            path: /healthz
            interval_secs: 1
            timeout_ms: 100
"#
        );

        let error = reload_from_config_yaml("sb.yml", &yaml)
            .expect_err("the lifecycle hook must reject the candidate");
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

        listener_task.abort();
        let _ = listener_task.await;
        assert!(
            error
                .to_string()
                .contains("fixture reload hook rejected the candidate"),
            "{error:#}"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a rejected candidate started a health-probe task"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_reload_candidate_starts_each_health_probe_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe listener");
        let port = listener
            .local_addr()
            .expect("probe listener address")
            .port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener_hits = Arc::clone(&hits);
        let listener_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                listener_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let yaml = format!(
            r#"proxy: {{}}
origins:
  accepted-probe-fixture.test:
    action:
      type: load_balancer
      targets:
        - url: "http://127.0.0.1:{port}"
          health_check:
            path: /healthz
            interval_secs: 10
            timeout_ms: 100
"#
        );

        reload_from_config_yaml("sb.yml", &yaml).expect("the candidate must publish");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let observed_hits = hits.load(std::sync::atomic::Ordering::SeqCst);
        crate::reload::load_pipeline(crate::pipeline::CompiledPipeline::default());
        listener_task.abort();
        let _ = listener_task.await;
        assert_eq!(
            observed_hits, 1,
            "a published candidate must start exactly one task per health-checked target"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_reload_candidate_stops_health_probes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe listener");
        let port = listener
            .local_addr()
            .expect("probe listener address")
            .port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener_hits = Arc::clone(&hits);
        let listener_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                listener_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let yaml = format!(
            r#"proxy: {{}}
origins:
  replaceable-probe-fixture.test:
    action:
      type: load_balancer
      targets:
        - url: "http://127.0.0.1:{port}"
          health_check:
            path: /healthz
            interval_secs: 1
            timeout_ms: 100
"#
        );

        reload_from_config_yaml("sb.yml", &yaml).expect("the candidate must publish");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while hits.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the first health probe must run");

        crate::reload::load_pipeline(crate::pipeline::CompiledPipeline::default());
        let hits_after_replacement = hits.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(1_250)).await;

        listener_task.abort();
        let _ = listener_task.await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            hits_after_replacement,
            "a replaced generation kept its health-probe task alive"
        );
    }

    #[test]
    fn pipeline_lifecycle_hook_has_product_neutral_identifiers() {
        let subsystem = DegradedSubsystem::PipelineLifecycleHook;

        assert_eq!(subsystem.as_str(), "pipeline_lifecycle_hook");
        assert_eq!(subsystem.to_string(), "pipeline lifecycle hook");
    }

    #[test]
    fn safety_centroid_preflight_rejects_mismatched_model_before_publication() {
        super::ai_classifier::install_classifier_factory();
        let dir = tempfile::tempdir().expect("tempdir");
        let model = dir.path().join("model.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"different model generation").expect("model fixture");
        std::fs::write(&tokenizer, b"different tokenizer generation").expect("tokenizer fixture");
        let yaml = format!(
            r#"
origins:
  "ai.test":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: sk-test
      guardrails:
        input:
          - type: jailbreak
            mode: classifier
            classifier:
              backend:
                kind: embedding
                model_path: "{}"
                tokenizer_path: "{}"
"#,
            model.display(),
            tokenizer.display()
        );
        let compiled = sbproxy_config::compile_config(&yaml).expect("structurally valid config");
        let pipeline =
            CompiledPipeline::from_config(compiled).expect("action construction stays structural");

        let error = preflight_default_safety_centroids(&pipeline)
            .expect_err("mismatched default-centroid model must reject startup")
            .to_string();

        assert!(
            error.contains("startup preflight"),
            "unexpected error: {error}"
        );
        #[cfg(feature = "inprocess-classify")]
        assert!(error.contains("model pin"), "unexpected error: {error}");
        #[cfg(not(feature = "inprocess-classify"))]
        assert!(
            error.contains("without the `inprocess-classify` feature"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn safety_centroid_preflight_covers_live_forward_rule_ai_actions() {
        super::ai_classifier::install_classifier_factory();
        let dir = tempfile::tempdir().expect("tempdir");
        let model = dir.path().join("model.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"different model generation").expect("model fixture");
        std::fs::write(&tokenizer, b"different tokenizer generation").expect("tokenizer fixture");
        let yaml = format!(
            r#"
origins:
  "front.test":
    action:
      type: static
      status: 200
      text_body: ok
    forward_rules:
      - rules:
          - path:
              prefix: /ai/
        origin:
          id: inline-ai
          action:
            type: ai_proxy
            providers:
              - name: openai
                api_key: sk-test
            guardrails:
              input:
                - type: jailbreak
                  mode: classifier
                  classifier:
                    backend:
                      kind: embedding
                      model_path: "{}"
                      tokenizer_path: "{}"
"#,
            model.display(),
            tokenizer.display()
        );
        let compiled = sbproxy_config::compile_config(&yaml).expect("structurally valid config");
        let pipeline =
            CompiledPipeline::from_config(compiled).expect("forward action construction");

        let error = preflight_default_safety_centroids(&pipeline)
            .expect_err("forward-rule AI safety artifacts must be verified before publication")
            .to_string();
        assert!(
            error.contains("startup preflight"),
            "unexpected error: {error}"
        );
        #[cfg(feature = "inprocess-classify")]
        assert!(error.contains("model pin"), "unexpected error: {error}");
        #[cfg(not(feature = "inprocess-classify"))]
        assert!(
            error.contains("without the `inprocess-classify` feature"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn real_reload_seeds_replaces_clears_and_preserves_flags_on_rejection() {
        let _guard = crate::reload::FEATURE_FLAG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = sbproxy_extension::flags::global_store();
        let engine = sbproxy_extension::cel::CelEngine::new();
        let context = sbproxy_extension::cel::CelContext::new();

        reload_from_config_yaml(
            "sb.yml",
            r#"
flags:
  - name: new-auth-path
    default: false
    rules:
      allow_list: [alice]
"#,
        )
        .expect("initial flag config should reload");
        assert!(engine
            .eval_bool_source(r#"flag_enabled("new-auth-path", "alice")"#, &context)
            .expect("CEL should evaluate"));
        assert!(!engine
            .eval_bool_source(r#"flag_enabled("new-auth-path", "mallory")"#, &context)
            .expect("CEL should evaluate"));

        reload_from_config_yaml(
            "sb.yml",
            r#"
flags:
  - name: replacement
    default: true
"#,
        )
        .expect("replacement flag config should reload");
        assert!(!engine
            .eval_bool_source(r#"flag_enabled("new-auth-path", "alice")"#, &context)
            .expect("old flag should be absent after replacement"));
        assert!(engine
            .eval_bool_source(r#"flag_enabled("replacement", "any-key")"#, &context)
            .expect("replacement flag should evaluate"));

        let rejected = reload_from_config_yaml(
            "sb.yml",
            r#"
flags:
  - name: must-not-publish
    default: true
origins:
  "invalid.example":
    action:
      type: action-that-does-not-exist
"#,
        );
        assert!(
            rejected.is_err(),
            "pipeline construction must reject the invalid action"
        );
        assert!(engine
            .eval_bool_source(r#"flag_enabled("replacement", "any-key")"#, &context)
            .expect("prior flag should survive a rejected reload"));
        assert!(!engine
            .eval_bool_source(r#"flag_enabled("must-not-publish", "any-key")"#, &context)
            .expect("rejected candidate must not publish flags"));

        reload_from_config_yaml("sb.yml", "proxy: {}\n")
            .expect("config without flags should reload");
        assert!(!engine
            .eval_bool_source(r#"flag_enabled("replacement", "any-key")"#, &context)
            .expect("an absent block should clear flags"));

        sbproxy_extension::flags::set_global_store(previous);
    }

    #[test]
    fn proxy_service_startup_error_preserves_native_cert_hint() {
        let payload = "called `Result::unwrap()` on an `Err` value: Failed to load native certificates: No keychain is available";
        let err = proxy_service_startup_error(&payload);
        let text = format!("{err:#}");

        assert!(text.contains("upstream TLS trust roots"));
        assert!(text.contains("SSL_CERT_FILE"));
        assert!(text.contains("No keychain is available"));
    }

    /// WOR-1043 PR2 / PR3: installing the redact state from a compiled
    /// config that carries a proxy-scope PII block plus a tenant-scope
    /// override plus an origin-scope extension yields a tri-level
    /// `OpRedactState` the resolver can pick from. Verifies through
    /// `apply_redaction_for` because the state is process-global and
    /// the `OpRedactState` fields are exposed for inspection.
    #[test]
    fn install_op_redact_state_builds_tenant_and_origin_pii() {
        // Build a CompiledConfig with proxy + 1 tenant + 1 origin and
        // run the install. We assert against the resolver behaviour
        // because that is the user-visible contract; spying on the
        // private map would couple to representation details.
        use sbproxy_config::{
            CompiledConfig, CompiledOrigin, ObservabilityConfig, ObservabilityLogConfig,
            ObservabilityPiiConfig, ObservabilityRedactConfig, OriginObservabilityConfig,
            OriginObservabilityLogConfig, OriginObservabilityRedactConfig, ProxyServerConfig,
            ProxyTenantConfig, TenantObservabilityConfig, TenantObservabilityLogConfig,
            TenantObservabilityRedactConfig,
        };

        // Serialise the test against every other sbproxy-core test
        // that touches the process-global `OP_REDACT_STATE` (directly
        // or via `reload_from_config_path`). Without this guard,
        // `reload_from_config_path_is_idempotent_under_repeat_invocation`
        // races with us and clobbers the installed state mid-flight.
        let _guard = super::OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut server = ProxyServerConfig {
            http_bind_port: 8080,
            ..Default::default()
        };
        // Build the log block via Default and then spread the redact
        // leaf so we do not have to spell every unrelated knob
        // (level, format, sampling, sinks) by hand.
        let log_cfg = ObservabilityLogConfig {
            redact: Some(ObservabilityRedactConfig {
                fields: Vec::new(),
                patterns: Vec::new(),
                pii: Some(ObservabilityPiiConfig {
                    enabled: Some(true),
                    rules: vec!["email".to_string()],
                    disable: Vec::new(),
                }),
            }),
            ..Default::default()
        };
        server.observability = Some(ObservabilityConfig {
            log: Some(log_cfg),
            telemetry: None,
            usage_rollups: None,
        });
        server.tenants = vec![ProxyTenantConfig {
            id: "acme".to_string(),
            credentials: Vec::new(),
            observability: Some(TenantObservabilityConfig {
                cardinality: None,
                log: TenantObservabilityLogConfig {
                    decision_audit: None,
                    sinks: Vec::new(),
                    custom_fields: Vec::new(),
                    redact: TenantObservabilityRedactConfig {
                        fields: Vec::new(),
                        patterns: Vec::new(),
                        disable: Vec::new(),
                        pii: Some(ObservabilityPiiConfig {
                            enabled: Some(true),
                            rules: vec!["us_ssn".to_string()],
                            disable: Vec::new(),
                        }),
                    },
                },
            }),
        }];

        // Mint a minimal CompiledOrigin by hand. We only populate the
        // fields the install path actually reads (`hostname`,
        // `tenant_id`, `observability`); every other field uses Default
        // where Default is implemented, or an empty value otherwise.
        let origin = CompiledOrigin {
            hostname: compact_str::CompactString::new("api.acme.example.com"),
            origin_id: compact_str::CompactString::new("api-acme"),
            cache_config_fingerprint: compact_str::CompactString::default(),
            workspace_id: compact_str::CompactString::default(),
            tenant_id: compact_str::CompactString::new("acme"),
            action_config: serde_json::Value::Null,
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            filters: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::SmallVec::new(),
            request_modifiers: smallvec::SmallVec::new(),
            response_modifiers: smallvec::SmallVec::new(),
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            deprecation: None,
            message_signatures: None,
            olp: None,
            comp: None,
            web_bot_auth_publish: None,
            idempotency: None,
            timeouts: sbproxy_config::UpstreamTimeouts::default(),
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: std::collections::HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
            attestation: None,
            observability: Some(OriginObservabilityConfig {
                log: OriginObservabilityLogConfig {
                    decision_audit: None,
                    sinks: Vec::new(),
                    custom_fields: Vec::new(),
                    redact: OriginObservabilityRedactConfig {
                        fields: Vec::new(),
                        patterns: Vec::new(),
                        disable: Vec::new(),
                        pii: Some(ObservabilityPiiConfig {
                            enabled: Some(true),
                            rules: vec!["credit_card".to_string()],
                            disable: Vec::new(),
                        }),
                    },
                },
            }),
            owasp_pack_manifest: None,
        };

        let compiled = CompiledConfig {
            origin_source_entries: Default::default(),
            extension_bundles: Default::default(),
            origins: vec![origin],
            host_map: std::collections::HashMap::new(),
            server,
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
        };

        install_op_redact_state(&compiled);

        // Proxy scope: email rule fires; ssn / card do not.
        let json_email = r#"{"freeform":"ping alice@example.com please"}"#;
        let json_ssn = r#"{"freeform":"the ssn is 123-45-6789 today"}"#;
        let json_card = r#"{"freeform":"paid 4111 1111 1111 1111 yesterday"}"#;

        let proxy_email = sbproxy_observe::logging::apply_redaction_for(
            json_email,
            sbproxy_observe::logging::Sink::AccessLog,
            None,
            None,
        );
        assert!(
            proxy_email.contains("[REDACTED:EMAIL]"),
            "proxy scope should redact email: {proxy_email}"
        );

        // Tenant scope: composes email + us_ssn (tenant adds ssn).
        let tenant_ssn = sbproxy_observe::logging::apply_redaction_for(
            json_ssn,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            None,
        );
        assert!(
            tenant_ssn.contains("[REDACTED:SSN]") || tenant_ssn.contains("[REDACTED:US_SSN]"),
            "tenant scope should redact ssn (composed from proxy + tenant): {tenant_ssn}"
        );

        // Origin scope: composes email + us_ssn (from tenant) + credit_card.
        let origin_card = sbproxy_observe::logging::apply_redaction_for(
            json_card,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            Some("api.acme.example.com"),
        );
        assert!(
            origin_card.contains("[REDACTED:CARD]"),
            "origin scope should redact credit card (composed from tenant + origin): {origin_card}"
        );
        // Origin still inherits the email rule from proxy via the
        // tenant composition.
        let origin_email = sbproxy_observe::logging::apply_redaction_for(
            json_email,
            sbproxy_observe::logging::Sink::AccessLog,
            Some("acme"),
            Some("api.acme.example.com"),
        );
        assert!(
            origin_email.contains("[REDACTED:EMAIL]"),
            "origin scope should still redact email via inherited rule set: {origin_email}"
        );

        // Reset the global slot so a sibling test does not see the
        // installed state.
        sbproxy_observe::logging::install_op_redact_config(
            sbproxy_observe::logging::OpRedactState::empty(),
        );
    }

    /// WOR-2319: `proxy.scripting.javascript.sandbox:` has to reach the
    /// live QuickJS engines. Before the boot path called
    /// `install_js_sandbox_limits`, this block parsed and nothing read
    /// it, so `active_sandbox_config()` never moved off 100 / 16 / 1024
    /// however the operator authored it.
    #[test]
    fn install_js_sandbox_limits_reaches_the_process_wide_handle() {
        use sbproxy_config::types::{JsSandboxConfig, ProxyServerConfig};

        let saved = (*sbproxy_extension::js::active_sandbox_config()).clone();

        // Assign through the field path rather than spelling the two
        // wrapper structs between the server config and the sandbox
        // leaf: production reaches them the same way, and naming them
        // only here would make them look test-only to the pub-item
        // scan.
        let mut server = ProxyServerConfig {
            http_bind_port: 8080,
            ..Default::default()
        };
        server.scripting.javascript.sandbox = JsSandboxConfig {
            budget_ms: 321,
            memory_mb: 48,
            stack_kb: 4096,
        };

        install_js_sandbox_limits(&server);

        let active = sbproxy_extension::js::active_sandbox_config();
        assert_eq!(active.budget_ms, 321);
        assert_eq!(active.memory_mb, 48);
        assert_eq!(active.stack_kb, 4096);

        // Restore the prior config so sibling tests that build a
        // `JsEngine` are unaffected.
        sbproxy_extension::js::install_sandbox_config(saved);
    }

    // --- proxy.observability.log.level on reload ---

    /// Build a server config carrying `proxy.observability.log.level`.
    /// `None` leaves the whole `observability:` block absent, which is
    /// what most deployments have.
    fn server_with_log_level(level: Option<&str>) -> sbproxy_config::types::ProxyServerConfig {
        use sbproxy_config::types::{ObservabilityConfig, ObservabilityLogConfig};

        sbproxy_config::types::ProxyServerConfig {
            http_bind_port: 8080,
            observability: level.map(|level| ObservabilityConfig {
                log: Some(ObservabilityLogConfig {
                    level: Some(level.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The reload path reads the key an operator actually wrote.
    #[test]
    fn reload_reads_the_configured_log_level() {
        assert_eq!(
            config_log_level(&server_with_log_level(Some("debug"))),
            Some("debug")
        );
        assert_eq!(
            config_log_level(&server_with_log_level(Some("sbproxy_ai=trace,h2=warn"))),
            Some("sbproxy_ai=trace,h2=warn")
        );
        assert_eq!(
            config_log_level(&server_with_log_level(Some("  warn  "))),
            Some("warn")
        );
    }

    /// An absent or blank value must leave the running filter alone
    /// rather than installing an empty directive, which would silence
    /// the process on the next SIGHUP.
    #[test]
    fn reload_leaves_the_log_filter_alone_without_a_configured_level() {
        assert_eq!(config_log_level(&server_with_log_level(None)), None);
        assert_eq!(config_log_level(&server_with_log_level(Some(""))), None);
        assert_eq!(config_log_level(&server_with_log_level(Some("   "))), None);

        // No subscriber is installed in this test binary, so the
        // install call has no reload handle to swap. It must still
        // return quietly and record no filter change.
        install_config_log_level(&server_with_log_level(None));
        install_config_log_level(&server_with_log_level(Some("debug")));
        assert_eq!(sbproxy_observe::current_log_filter(), "");
    }

    // --- resolve_or_default_admin_operator_pepper ---

    fn bad_pepper_key_management() -> sbproxy_config::types::KeyManagementConfig {
        sbproxy_config::types::KeyManagementConfig {
            crypto: sbproxy_config::types::KeyCryptoConfig {
                pepper: Some(
                    "env:SBPROXY_TEST_LIFECYCLE_PEPPER_DOES_NOT_EXIST_ANYWHERE".to_string(),
                ),
                master_key: None,
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn admin_operator_pepper_falls_back_and_warns_when_no_operators_need_it() {
        let cfg = bad_pepper_key_management();
        let pepper = resolve_or_default_admin_operator_pepper(Some(&cfg), false)
            .expect("an unresolvable pepper must not fail boot with no operators configured");
        assert_eq!(pepper, crate::key_plane::default_admin_operator_pepper());
    }

    #[test]
    fn admin_operator_pepper_fails_loud_when_operators_are_configured() {
        let cfg = bad_pepper_key_management();
        let error = resolve_or_default_admin_operator_pepper(Some(&cfg), true)
            .expect_err("an unresolvable pepper must fail boot when operators depend on it");
        assert!(
            error.to_string().contains("proxy.admin.operators"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn admin_operator_pepper_resolves_with_no_key_management_regardless_of_operators() {
        assert_eq!(
            resolve_or_default_admin_operator_pepper(None, false).unwrap(),
            crate::key_plane::default_admin_operator_pepper()
        );
        assert_eq!(
            resolve_or_default_admin_operator_pepper(None, true).unwrap(),
            crate::key_plane::default_admin_operator_pepper()
        );
    }

    #[test]
    fn admin_operator_pepper_prefers_a_pinned_value_when_operators_are_configured() {
        let cfg = sbproxy_config::types::KeyManagementConfig {
            crypto: sbproxy_config::types::KeyCryptoConfig {
                pepper: Some("pinned-pepper".to_string()),
                master_key: None,
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        };
        assert_eq!(
            resolve_or_default_admin_operator_pepper(Some(&cfg), true).unwrap(),
            b"pinned-pepper".to_vec()
        );
    }

    /// WOR-2486 fix round 1, C1: the sixth reload path. Before this fix,
    /// an extension-bundle refresh that changed a verified Git fingerprint
    /// ran the full reload transaction and published (or rejected) a
    /// pipeline generation with zero trace in `config_audit`, accepted or
    /// rejected. Red first against `reload_for_extension_refresh` directly
    /// so the test does not depend on a live Git fetch: an empty
    /// `ExtensionBundlesConfig` loads its (empty) candidate with no I/O.
    #[test]
    fn extension_bundle_refresh_reaches_config_audit_on_success_and_failure() {
        let candidate = sbproxy_extension::bundle::DynamicBundleRegistry::load_with_context(
            &sbproxy_config::ExtensionBundlesConfig::default(),
            std::path::Path::new("."),
            &std::collections::BTreeSet::new(),
            &sbproxy_config::FetchContext::with_git_binary(),
        )
        .expect("an empty bundle config loads its candidate with no I/O");

        let before = sbproxy_observe::audit_ring::recent_audit_events(
            50,
            Some("config"),
            Some("extension_refresh"),
            None,
        )
        .len();

        let accepted = sbproxy_config::compile_config(
            r#"
origins:
  "extension-refresh-audit-ok.test":
    action:
      type: static
      body: ok
"#,
        )
        .expect("accepted fixture config compiles");
        let _ = reload_for_extension_refresh(
            "extension-refresh-audit-test.yml",
            accepted,
            Arc::clone(&candidate),
        );

        // WOR-2162: the same invalid-CEL shape
        // `reload_with_invalid_cel_expression_keeps_the_active_pipeline`
        // (in `server/tests.rs`) uses to fail pipeline construction after
        // `compile_config` already succeeded, so the rejection happens
        // inside the reload transaction this function wraps rather than
        // before it is ever called.
        let rejected = sbproxy_config::compile_config(
            r#"
origins:
  "extension-refresh-audit-reject.test":
    action:
      type: static
      body: ok
    policies:
      - type: expression
        expression: 'this is not valid CEL !!!'
"#,
        )
        .expect("rejected fixture config still compiles at the YAML/schema layer");
        let reject_result =
            reload_for_extension_refresh("extension-refresh-audit-test.yml", rejected, candidate);
        assert!(
            reject_result.is_err(),
            "the invalid CEL fixture must fail pipeline construction, or this test is not \
             exercising the rejection branch it claims to"
        );

        let events = sbproxy_observe::audit_ring::recent_audit_events(
            50,
            Some("config"),
            Some("extension_refresh"),
            None,
        );
        assert!(
            events.len() >= before + 2,
            "both the accepted and the rejected extension-bundle refresh must reach \
             config_audit: before={before}, after={events:?}"
        );
        assert!(
            events.iter().any(|e| e
                .detail
                .as_deref()
                .unwrap_or_default()
                .starts_with("rejected:")),
            "the rejection must be distinguishable from the accepted entry: {events:?}"
        );
    }

    /// WOR-2486 fix round 1, I5: `audit_reload_outcome`'s rejection
    /// reason must be scrubbed through the same path redaction the
    /// admin API's HTTP responses already get, not recorded verbatim.
    /// Before this fix, a compile or filesystem error that echoed the
    /// full config path (a routine `anyhow` context pattern) landed
    /// unscrubbed in a `config_audit` record, which is durable under
    /// `audit.sink: chain`.
    #[test]
    fn audit_reload_outcome_scrubs_the_config_path_from_the_rejection_reason() {
        let config_path = "/home/deploy/configs/prod/sb-secret-layout.yml";
        let err: anyhow::Result<ReloadOutcome> = Err(anyhow::anyhow!(
            "failed to parse config: {config_path}: mapping values are not allowed here"
        ));

        let before = sbproxy_observe::audit_ring::recent_audit_events(
            50,
            Some("config"),
            Some("path_redact_test"),
            None,
        )
        .len();
        audit_reload_outcome("path_redact_test", config_path, &err);
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            50,
            Some("config"),
            Some("path_redact_test"),
            None,
        );
        assert!(events.len() > before, "the rejection must reach the ring");
        let detail = events[0].detail.as_deref().unwrap_or_default();
        assert!(
            !detail.contains("/home/deploy/configs/prod"),
            "the full config path must not reach the audit record: {detail:?}"
        );
        assert!(
            detail.contains("sb-secret-layout.yml"),
            "the file name (the useful, non-sensitive half) should remain: {detail:?}"
        );
    }
}

/// Refuse a pipeline whose caches write plaintext somewhere durable.
///
/// Runs after the lifecycle hook has installed its backends, because
/// that is the only point at which the full set of cache surfaces is
/// known. The in-tree defaults are all memory-only, so this is a no-op
/// for every OSS build; it exists so that the day a persistent or
/// replicated backend is wired in, an operator hears about it at boot
/// instead of finding prompts on disk later.
///
/// # Why the response cache is not covered here
///
/// The response cache is checked, but only to warn. Running it
/// unencrypted over a file or Redis backend is a shipped, documented,
/// deliberately-chosen configuration that predates this check, and
/// turning it fatal would break working deployments on upgrade for no
/// new information: the operator already knows, because they wrote the
/// backend and left `encryption.enabled` off. An operator who wants it
/// fatal turns encryption on, which is the same edit either way.
///
/// The pluggable surfaces are different. None of them has ever had a
/// non-ephemeral backend in this repository, so nothing can break, and
/// the whole point is that the exposure must not be able to appear
/// silently.
///
/// # Why the distributed semantic cache warns rather than aborts
///
/// WOR-2099 gave the semantic cache Redis and mesh backends, so for the
/// first time a semantic cache can outlive the process on purpose. That
/// moves it into the same category as the response cache above: an
/// operator who writes `backend: redis` chose a shared store knowingly,
/// and aborting their boot on upgrade would break a documented feature
/// rather than tell them something new. The values are prompts and model
/// output, so the exposure still gets said out loud, once per backend.
///
/// This is deliberately not silent. The check that used to cover the
/// semantic cache read it through a hook that WOR-2099 deleted, and
/// leaving it at that would have turned a boot guard into a no-op in the
/// same change that introduced the backends it was written to catch.
fn enforce_cache_at_rest_posture(
    pipeline: &crate::pipeline::CompiledPipeline,
) -> anyhow::Result<()> {
    let mut exposed = Vec::new();
    for (name, posture) in pipeline.hooks.cache_surfaces() {
        if posture.stores_plaintext_at_rest() {
            exposed.push(format!(
                "{name} (backend is {}, entries are not encrypted)",
                posture.durability.as_str()
            ));
        }
    }
    if !exposed.is_empty() {
        anyhow::bail!(
            "these caches would store plaintext outside this process: {}. A cache whose \
             backend survives a restart or is shared across replicas must encrypt what it \
             writes. Configure encryption for the backend, or run it in memory.",
            exposed.join("; ")
        );
    }

    if let Some(store) = pipeline.cache_store.as_ref() {
        let posture = store.at_rest_posture();
        if posture.stores_plaintext_at_rest() {
            tracing::warn!(
                backend = store.backend_name(),
                durability = posture.durability.as_str(),
                "the response cache is storing response headers and bodies unencrypted on a \
                 backend that outlives this process; set \
                 proxy.response_cache_store.encryption.enabled to seal them"
            );
        }
    }

    warn_on_distributed_semantic_backends(pipeline);
    Ok(())
}

/// Say once per distributed backend that the semantic cache is putting
/// prompts and model output somewhere this process does not own.
///
/// Grouped by backend rather than by slot: an operator with forty origins
/// on one Redis has one fact to learn, not forty. Memory never warns,
/// because it dies with the process.
fn warn_on_distributed_semantic_backends(pipeline: &crate::pipeline::CompiledPipeline) {
    use sbproxy_ai::semantic_cache::SemanticCacheBackend;

    let mut redis = 0_usize;
    let mut mesh = 0_usize;
    for registration in pipeline.semantic_caches.registrations() {
        if registration.cache.is_none() {
            continue;
        }
        match registration.backend {
            Some(SemanticCacheBackend::Redis) => redis += 1,
            Some(SemanticCacheBackend::Mesh) => mesh += 1,
            Some(SemanticCacheBackend::Memory) | None => {}
        }
    }
    for (backend, durability, routes) in
        [("redis", "persistent", redis), ("mesh", "replicated", mesh)]
    {
        if routes > 0 {
            tracing::warn!(
                backend,
                durability,
                routes,
                "the semantic cache is storing prompts and model output unencrypted on a \
                 backend that outlives this process; treat it as sensitive operator data and \
                 secure the backend transport and storage"
            );
        }
    }
}
#[cfg(test)]
mod at_rest_posture_tests {
    use super::*;
    use sbproxy_cache::{AtRestPosture, CacheDurability};
    use std::sync::Arc;

    /// A pluggable cache surface reporting whatever posture the test asks
    /// for. WOR-2099 deleted the semantic lookup hook, so nothing in tree
    /// registers a surface today; this keeps the fatal branch covered so a
    /// future surface with a durable backend still cannot land quietly.
    fn pipeline_with_surface(
        name: &'static str,
        posture: AtRestPosture,
    ) -> crate::pipeline::CompiledPipeline {
        let mut hooks = crate::hooks::Hooks::default();
        hooks.test_cache_surfaces.push((name, posture));
        crate::pipeline::CompiledPipeline {
            hooks,
            ..Default::default()
        }
    }

    #[test]
    fn a_pipeline_with_no_cache_surfaces_passes() {
        assert!(
            enforce_cache_at_rest_posture(&crate::pipeline::CompiledPipeline::default()).is_ok()
        );
    }

    #[test]
    fn the_default_memory_only_posture_passes() {
        // Every in-tree implementation inherits this, so the check must be
        // a no-op for an OSS build.
        let pipeline = pipeline_with_surface("test surface", AtRestPosture::memory_only());
        assert!(enforce_cache_at_rest_posture(&pipeline).is_ok());
    }

    #[test]
    fn a_persistent_unencrypted_surface_aborts_boot() {
        // The whole point of the guard: a backend swap that starts writing
        // prompts to disk must not go unnoticed.
        let pipeline = pipeline_with_surface(
            "test surface",
            AtRestPosture::new(CacheDurability::Persistent, false),
        );
        let err = enforce_cache_at_rest_posture(&pipeline)
            .expect_err("an unencrypted persistent cache must fail loud");
        let message = err.to_string();
        assert!(message.contains("test surface"), "{message}");
        assert!(message.contains("persistent"), "{message}");
    }

    #[test]
    fn a_replicated_unencrypted_surface_aborts_boot() {
        let pipeline = pipeline_with_surface(
            "test surface",
            AtRestPosture::new(CacheDurability::Replicated, false),
        );
        let err = enforce_cache_at_rest_posture(&pipeline)
            .expect_err("an unencrypted replicated cache must fail loud");
        assert!(err.to_string().contains("replicated"), "{err}");
    }

    #[test]
    fn a_persistent_encrypted_surface_passes() {
        // Encryption is the fix the error message asks for, so applying it
        // has to actually clear the check.
        let pipeline = pipeline_with_surface(
            "test surface",
            AtRestPosture::new(CacheDurability::Persistent, true),
        );
        assert!(enforce_cache_at_rest_posture(&pipeline).is_ok());
    }

    #[test]
    fn an_in_memory_response_cache_is_not_flagged() {
        let pipeline = crate::pipeline::CompiledPipeline {
            cache_store: Some(Arc::new(sbproxy_cache::MemoryCacheStore::new(10))),
            ..Default::default()
        };
        assert!(enforce_cache_at_rest_posture(&pipeline).is_ok());
    }

    #[test]
    fn an_empty_semantic_registry_warns_about_nothing() {
        // A default pipeline has no semantic registrations, so the
        // distributed warning path must be a no-op rather than panicking on
        // an empty registry.
        let pipeline = crate::pipeline::CompiledPipeline::default();
        warn_on_distributed_semantic_backends(&pipeline);
        assert_eq!(pipeline.semantic_caches.registrations().count(), 0);
    }
}

/// The config blocks only the boot path reads: the agent registry, the
/// notifications sink, and the request-event sink's kind, each from YAML
/// through to what `run` would install.
///
/// Left undocumented for a while because the block above it belonged to
/// `request_event_sink_tests` and was read as this module's own.
#[cfg(test)]
mod boot_only_block_tests {
    use super::*;

    use sbproxy_config::types::{
        AgentRegistryConfig, NotificationsConfig, ProxyServerConfig, RequestEventSinkKind,
        RequestEventsConfig,
    };

    fn server(agent_registry: Option<AgentRegistryConfig>) -> ProxyServerConfig {
        ProxyServerConfig {
            agent_registry,
            ..Default::default()
        }
    }

    /// WOR-2664/2669/2674 review: all three blocks open a store or install
    /// a process-global at boot and none has a rebuild path, so a reload
    /// that changed one used to be accepted and then ignored. An operator
    /// adding a rotated `bootstrap_keys` entry would see `/admin/config`
    /// serve it back while every refresh kept answering `unknown_key`, with
    /// nothing connecting the two.
    #[test]
    fn a_reload_that_changes_a_boot_only_block_is_refused_by_name() {
        let before = server(Some(AgentRegistryConfig {
            enabled: true,
            store_path: "/tmp/a.redb".into(),
            ..Default::default()
        }));
        let after = server(Some(AgentRegistryConfig {
            enabled: true,
            store_path: "/tmp/b.redb".into(),
            ..Default::default()
        }));

        // Same shape reconciles clean whichever way round it is read.
        let installed = boot_only_fingerprints(&before, None);
        assert!(compare_boot_only_fingerprints(
            &installed,
            &boot_only_fingerprints(&server(before.agent_registry.clone()), None)
        )
        .is_ok());

        // A changed block is refused, and the refusal names the key that
        // moved rather than the set.
        let refusal =
            compare_boot_only_fingerprints(&installed, &boot_only_fingerprints(&after, None))
                .expect_err("a changed boot-only block must be refused");
        let refusal = refusal.to_string();
        assert!(refusal.contains("proxy.agent_registry"), "{refusal}");
        assert!(!refusal.contains("proxy.notifications"), "{refusal}");
        assert!(refusal.contains("restart sbproxy"), "{refusal}");

        // The other two blocks are refused the same way, so the guard is as
        // wide as the claim in docs/configuration.md.
        let notifications = compare_boot_only_fingerprints(
            &boot_only_fingerprints(&ProxyServerConfig::default(), None),
            &boot_only_fingerprints(
                &ProxyServerConfig {
                    notifications: Some(NotificationsConfig {
                        enabled: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                None,
            ),
        )
        .expect_err("proxy.notifications is boot-only too")
        .to_string();
        assert!(
            notifications.contains("proxy.notifications"),
            "{notifications}"
        );

        let events = compare_boot_only_fingerprints(
            &boot_only_fingerprints(&ProxyServerConfig::default(), None),
            &boot_only_fingerprints(
                &ProxyServerConfig::default(),
                Some(&RequestEventsConfig {
                    sink: RequestEventSinkKind::Logging,
                    ..Default::default()
                }),
            ),
        )
        .expect_err("request_events is boot-only too")
        .to_string();
        assert!(events.contains("request_events"), "{events}");
    }

    /// A config value must not reach `chrono::Duration::seconds`, which is
    /// an `expect` past `i64::MAX / 1000`, and a bare `as i64` on a large
    /// `u64` wraps negative and silently shortens the feed expiry the key
    /// is documented to extend.
    #[test]
    fn an_out_of_range_duration_is_a_named_refusal_rather_than_a_panic_or_a_wrap() {
        assert!(registry_duration("stale_grace_secs", 86_400).is_ok());
        assert!(registry_duration("stale_grace_secs", 0).is_ok());

        let refusal = registry_duration("stale_grace_secs", u64::MAX)
            .expect_err("u64::MAX is not a duration");
        assert!(
            refusal.to_string().contains("stale_grace_secs"),
            "{refusal}"
        );

        assert!(
            registry_duration("stale_grace_secs", 10_000_000_000_000_000).is_err(),
            "past chrono's own bound, where Duration::seconds panics"
        );
    }

    /// The registry's approval queue is useful on its own, and
    /// `examples/agent-registry/sb.yml` ships exactly that shape with the
    /// catalog half commented out. Installing the refresh loop on
    /// `enabled` alone meant that config logged "agent registry refused a
    /// catalog feed" at warn and ticked
    /// `op="feed_refresh",outcome="invalid"` on boot and every 300 seconds
    /// forever, so an operator alerting on refresh refusals, which
    /// `docs/agent-registry.md` tells them to do, paged on a working proxy.
    #[test]
    fn a_registry_with_no_feed_runs_no_refresh_loop() {
        // A real registry, so this drives the decision `run` makes rather
        // than only the predicate underneath it: `agent_registry_refresher_for`
        // is the whole install decision, so reverting it is reverting
        // something this test reads.
        let path = format!(
            "{}/sbproxy_refresher_test_{}.redb",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let queue_only = AgentRegistryConfig {
            enabled: true,
            store_path: path.clone().into(),
            ..Default::default()
        };
        let registry = build_agent_registry(&queue_only).expect("registry opens");

        assert!(
            agent_registry_refresher_for(&queue_only, &registry).is_none(),
            "a queue-only registry must install no refresh loop"
        );

        // Half a feed is not a feed. `validate` refuses this shape at
        // startup, and the loop must not run for it either.
        let half = AgentRegistryConfig {
            feed_path: Some("/tmp/feed.json".into()),
            ..queue_only.clone()
        };
        assert!(agent_registry_refresher_for(&half, &registry).is_none());

        let full = AgentRegistryConfig {
            key_directory_path: Some("/tmp/keys.json".into()),
            ..half
        };
        let installed = agent_registry_refresher_for(&full, &registry)
            .expect("a configured feed installs the loop");
        assert_eq!(installed.1, AGENT_REGISTRY_REFRESH_DEFAULT);

        drop(registry);
        std::fs::remove_file(&path).ok();
    }

    /// The refresh loop's interval is derived rather than configured, so
    /// the derivation is what an operator plans against.
    #[test]
    fn the_refresh_interval_is_clamped_around_the_staleness_tolerance() {
        let with = |stale_grace_secs| {
            agent_registry_refresh_interval(&AgentRegistryConfig {
                stale_grace_secs,
                ..Default::default()
            })
        };
        assert_eq!(with(0), AGENT_REGISTRY_REFRESH_DEFAULT);
        assert_eq!(with(1), AGENT_REGISTRY_REFRESH_FLOOR);
        assert_eq!(with(600), std::time::Duration::from_secs(600));
        assert_eq!(with(u64::MAX), AGENT_REGISTRY_REFRESH_CEILING);
    }
}

/// WOR-2318: the `request_events:` block, from YAML through to the sink
/// the boot path would register.
///
/// These exercise [`build_request_event_sink`] rather than
/// [`install_request_event_sink`] on purpose. The registered sink is a
/// process-global `OnceLock`, so only one test per binary could ever
/// observe an install, and `capture_envelope`'s tests already claim it
/// in this crate. The builder is where every decision is made; the
/// installer only hands its result to the setter.
#[cfg(test)]
mod request_event_sink_tests {
    use super::*;

    use sbproxy_config::types::{RequestEventSinkKind, RequestEventsConfig};
    use sbproxy_observe::{RequestEvent, RequestEventSink};

    fn sample_event() -> RequestEvent {
        RequestEvent::new_started(
            "api.example.com".to_string(),
            ulid::Ulid::new(),
            "ws_test".to_string(),
        )
    }

    /// Publish one freshly minted event through a built sink and hand
    /// back its request id, which is what the caller looks for
    /// downstream.
    fn publish_sample(sink: &std::sync::Arc<dyn RequestEventSink>) -> ulid::Ulid {
        let event = sample_event();
        let request_id = event.request_id;
        sink.publish(event);
        request_id
    }

    #[test]
    fn the_config_block_round_trips_from_yaml_to_the_compiled_snapshot() {
        let yaml = "proxy: {}\nrequest_events:\n  sink: file\n  path: /tmp/events.ndjson\n";
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");

        let cfg = compiled
            .request_events
            .as_ref()
            .expect("the block survives compilation");
        assert_eq!(cfg.sink, RequestEventSinkKind::File);
        assert_eq!(cfg.path.as_deref(), Some("/tmp/events.ndjson"));
    }

    #[test]
    fn an_absent_block_compiles_to_no_request_event_config() {
        let compiled = sbproxy_config::compile_config("proxy: {}\n").expect("config compiles");
        assert!(compiled.request_events.is_none());
    }

    #[test]
    fn the_bare_block_defaults_to_the_none_sink() {
        let compiled =
            sbproxy_config::compile_config("proxy: {}\nrequest_events: {}\n").expect("compiles");
        let cfg = compiled.request_events.expect("the block survives");
        assert_eq!(cfg.sink, RequestEventSinkKind::None);
    }

    #[test]
    fn the_default_sink_kind_installs_nothing() {
        // The pre-existing behavior: dispatch stays a no-op, so the
        // builder must decline to produce a sink at all rather than
        // registering something that quietly discards.
        assert!(build_request_event_sink(&RequestEventsConfig::default()).is_none());
    }

    #[test]
    fn a_logging_sink_is_built_when_the_config_asks_for_one() {
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::Logging,
            path: None,
            ..Default::default()
        };
        let (sink, kind) = build_request_event_sink(&cfg).expect("logging sink is built");
        assert_eq!(kind, "logging");
        // The built sink accepts a dispatched event. Tracing capture is
        // owned by the logging tests; this proves the wiring, not the
        // formatting.
        publish_sample(&sink);
    }

    #[test]
    fn a_file_sink_writes_the_published_event_to_its_configured_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("request-events.ndjson");
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::File,
            path: Some(path.display().to_string()),
            ..Default::default()
        };

        let (sink, kind) = build_request_event_sink(&cfg).expect("file sink is built");
        assert_eq!(kind, "file");

        let request_id = publish_sample(&sink);
        // Dropping the last handle drains the queue, flushes, and joins
        // the writer thread, so the read below cannot race it.
        drop(sink);

        let written = std::fs::read_to_string(&path).expect("read back the ndjson");
        assert!(
            written.contains(&request_id.to_string()),
            "the event never reached the file: {written:?}"
        );
        assert!(written.contains("api.example.com"), "{written:?}");
    }

    /// WOR-2674: the two optional ingest sinks fall back the way the file
    /// sink does. A deployment that asked for its events to go somewhere
    /// and typed the block name wrong should read them locally rather than
    /// discover the typo as silence in a warehouse.
    #[test]
    fn an_ingest_sink_without_its_block_falls_back_to_logging() {
        for sink in [RequestEventSinkKind::Nats, RequestEventSinkKind::ClickHouse] {
            let cfg = RequestEventsConfig {
                sink,
                ..Default::default()
            };
            let (_, kind) = build_request_event_sink(&cfg).expect("a fallback sink is still built");
            assert_eq!(kind, "logging", "{sink:?}");
        }
    }

    /// A malformed target is refused at build time rather than at the
    /// first request. `nats://` is the shape an operator reaches for and
    /// the shape this sink does not take.
    #[test]
    fn a_malformed_ingest_target_falls_back_to_logging() {
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::Nats,
            nats: Some(sbproxy_config::types::RequestEventsNatsConfig {
                address: "nats://broker:4222".into(),
                subject_prefix: "sb.events".into(),
                token: None,
            }),
            ..Default::default()
        };
        let (_, kind) = build_request_event_sink(&cfg).expect("a fallback sink is still built");
        assert_eq!(kind, "logging");
    }

    /// A credential reference that will not resolve must not become a
    /// verbatim token on the wire, and must not silently become an
    /// unauthenticated connection either.
    #[test]
    fn an_unresolvable_broker_token_falls_back_to_logging() {
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::Nats,
            nats: Some(sbproxy_config::types::RequestEventsNatsConfig {
                address: "127.0.0.1:4222".into(),
                subject_prefix: "sb.events".into(),
                token: Some("file:/nonexistent/sbproxy-nats-token".into()),
            }),
            ..Default::default()
        };
        let (_, kind) = build_request_event_sink(&cfg).expect("a fallback sink is still built");
        assert_eq!(kind, "logging");
    }

    /// The sink starts without dialing: a broker that is down at boot must
    /// not stop the proxy from booting.
    #[test]
    fn an_ingest_sink_starts_without_reaching_the_broker() {
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::Nats,
            nats: Some(sbproxy_config::types::RequestEventsNatsConfig {
                // Nothing listens here. Construction still succeeds.
                address: "127.0.0.1:1".into(),
                subject_prefix: "sb.events".into(),
                token: None,
            }),
            ..Default::default()
        };
        let (_, kind) = build_request_event_sink(&cfg).expect("the sink is built");
        assert_eq!(kind, "nats");
    }

    #[test]
    fn a_file_sink_without_a_path_falls_back_to_logging() {
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::File,
            path: None,
            ..Default::default()
        };
        let (_, kind) = build_request_event_sink(&cfg).expect("a fallback sink is still built");
        assert_eq!(
            kind, "logging",
            "a misconfigured path must still leave the events somewhere an operator can read"
        );
    }

    #[test]
    fn a_file_sink_whose_path_cannot_be_opened_falls_back_to_logging() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A parent directory that does not exist: the open fails at
        // build time rather than silently at the first request.
        let path = dir.path().join("missing").join("events.ndjson");
        let cfg = RequestEventsConfig {
            sink: RequestEventSinkKind::File,
            path: Some(path.display().to_string()),
            ..Default::default()
        };

        let (_, kind) = build_request_event_sink(&cfg).expect("a fallback sink is still built");
        assert_eq!(kind, "logging");
        assert!(!path.exists());
    }
}

/// WOR-2318: the `events:` block, from YAML through to the egress the
/// boot path would start.
///
/// Same reasoning as the module above: these drive
/// [`build_event_egress`] rather than [`install_event_egress`], because
/// the registered egress is a process-global `OnceLock` and only one
/// test per binary could ever observe an install.
#[cfg(test)]
mod event_egress_tests {
    use super::*;

    use sbproxy_config::types::{EventSinkKind, EventsConfig};

    fn file_config(path: &std::path::Path) -> EventsConfig {
        EventsConfig {
            sink: EventSinkKind::File,
            path: Some(path.display().to_string()),
            url: None,
            signing_secret: None,
            types: Vec::new(),
            fail_closed: Vec::new(),
            queue_capacity: None,
        }
    }

    #[test]
    fn the_config_block_round_trips_from_yaml_to_the_compiled_snapshot() {
        let yaml = "proxy: {}\nevents:\n  sink: webhook\n  url: https://siem.example.com/in\n  \
                    types:\n    - policy_denied\n";
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");

        let cfg = compiled
            .events
            .as_ref()
            .expect("the block survives compilation");
        assert_eq!(cfg.sink, EventSinkKind::Webhook);
        assert_eq!(cfg.url.as_deref(), Some("https://siem.example.com/in"));
        assert_eq!(cfg.types, vec!["policy_denied"]);
    }

    #[test]
    fn an_absent_block_compiles_to_no_events_config() {
        let compiled = sbproxy_config::compile_config("proxy: {}\n").expect("config compiles");
        assert!(compiled.events.is_none());
    }

    #[test]
    fn the_default_sink_kind_starts_nothing() {
        // The pre-existing behavior: every publish site stays one
        // relaxed load, so the builder must decline to start a worker
        // rather than starting one that discards.
        let built = build_event_egress(&EventsConfig::default()).expect("none is not an error");
        assert!(built.is_none());
    }

    #[test]
    fn a_file_egress_writes_the_published_event_to_its_configured_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("events.ndjson");

        let (egress, sink) = build_event_egress(&file_config(&path))
            .expect("file egress builds")
            .expect("file egress is started");
        assert_eq!(sink, "file");

        egress.publish(sbproxy_observe::ProxyEvent::new(
            sbproxy_observe::EventType::PolicyDenied,
            "api.example.com".to_string(),
            "acme".to_string(),
            serde_json::json!({"reason": "rate_limit"}),
        ));
        // Dropping drains, flushes, and joins the worker, so the read
        // below cannot race it.
        drop(egress);

        let written = std::fs::read_to_string(&path).expect("read back the ndjson");
        assert!(
            written.contains("policy_denied") && written.contains("api.example.com"),
            "the event never reached the file: {written:?}"
        );
    }

    #[test]
    fn a_type_filter_is_carried_onto_the_started_egress() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = file_config(&dir.path().join("events.ndjson"));
        cfg.types = vec!["policy_denied".to_string()];

        let (egress, _) = build_event_egress(&cfg)
            .expect("file egress builds")
            .expect("file egress is started");
        assert!(egress.wants(sbproxy_observe::EventType::PolicyDenied));
        assert!(!egress.wants(sbproxy_observe::EventType::CacheHit));
    }

    #[test]
    fn an_empty_type_list_means_every_type() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (egress, _) = build_event_egress(&file_config(&dir.path().join("events.ndjson")))
            .expect("file egress builds")
            .expect("file egress is started");
        for event_type in sbproxy_observe::ALL_EVENT_TYPES {
            assert!(egress.wants(event_type), "{event_type:?} was filtered out");
        }
    }

    #[test]
    fn a_file_egress_whose_path_cannot_be_opened_fails_the_boot() {
        // The deliberate difference from `request_events:`, which falls
        // back to logging here. An operator who named a file for their
        // events did not ask for them to go somewhere else.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("events.ndjson");
        std::fs::create_dir_all(&path).expect("occupy the path with a directory");

        let error = build_event_egress(&file_config(&path))
            .expect_err("a path that cannot be opened must not boot");
        assert!(
            error.to_string().contains("events.path"),
            "the failure names the key: {error}"
        );
    }

    #[test]
    fn an_unresolvable_signing_secret_fails_the_boot() {
        // WOR-1767 fail-loud: a reference that will not resolve must not
        // be posted verbatim to a third-party endpoint, and an unsigned
        // batch is a signature check the receiver stops performing.
        let cfg = EventsConfig {
            sink: EventSinkKind::Webhook,
            url: Some("https://siem.example.com/in".to_string()),
            path: None,
            signing_secret: Some("vault://nowhere/nothing".to_string()),
            types: Vec::new(),
            fail_closed: Vec::new(),
            queue_capacity: None,
        };

        let error = build_event_egress(&cfg).expect_err("an unresolvable secret must not boot");
        assert!(
            error.to_string().contains("events.signing_secret"),
            "the failure names the key: {error}"
        );
    }

    fn webhook_config(url: &str) -> EventsConfig {
        EventsConfig {
            sink: EventSinkKind::Webhook,
            url: Some(url.to_string()),
            path: None,
            signing_secret: None,
            types: Vec::new(),
            fail_closed: Vec::new(),
            queue_capacity: None,
        }
    }

    fn restore_usage_sinks_gates() {
        sbproxy_security::egress::install_configured_gate(
            sbproxy_security::egress::EgressPurpose::UsageSink,
            None,
        );
        sbproxy_security::egress::install_configured_gate(
            sbproxy_security::egress::EgressPurpose::Webhook,
            None,
        );
        sbproxy_observe::arm_webhook_ssrf_allowlist(Vec::new());
    }

    #[test]
    fn usage_sinks_allow_private_lets_a_loopback_events_webhook_start() {
        // WOR-2712: production `ssrf_allowlist()` used to return an empty
        // vec at boot, so `egress.usage_sinks.allow_private: true` plus a
        // listed host never reached the SSRF check. Arm the compiled
        // usage_sinks block the same way `run` does, then start a
        // webhook at loopback the way `install_event_egress` does.
        let yaml = r#"
proxy: {}
egress:
  usage_sinks:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    allow_private: true
"#;
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");
        arm_egress_gates_from_config(&compiled);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");
        let built = build_event_egress(&webhook_config(&format!("http://{addr}/ingest")));
        restore_usage_sinks_gates();
        let (egress, sink) = built
            .expect("loopback collector on an allow_private usage_sinks host must start")
            .expect("webhook egress is started");
        assert_eq!(sink, "webhook");
        drop(egress);
    }

    #[test]
    fn a_loopback_events_webhook_is_refused_without_usage_sinks_allow_private() {
        // Inverse of the test above: no usage_sinks arming, so the SSRF
        // guard still runs with an empty host list and must refuse the
        // same loopback URL at boot.
        let compiled = sbproxy_config::compile_config("proxy: {}\n").expect("bare config compiles");
        arm_egress_gates_from_config(&compiled);

        let error = build_event_egress(&webhook_config("http://127.0.0.1:9/ingest"))
            .expect_err("a private collector must not boot without allow_private");
        restore_usage_sinks_gates();
        let message = error.to_string();
        assert!(
            message.contains("SSRF guard"),
            "the refusal must name the SSRF guard: {message}"
        );
    }

    #[test]
    fn install_audit_chain_claims_no_slot_on_a_refused_boot_and_all_four_on_a_clean_one() {
        // WOR-2478: `audit.config_path`, `audit.key_path`, and
        // `audit.admin_path` each opt a further chain into the same boot
        // call that opens the security chain, under the same signing
        // identity. The four slots this claims
        // (`sbproxy_observe::audit_chain::CHAIN`, `CONFIG_CHAIN`,
        // `KEY_CHAIN`, `ADMIN_CHAIN`) are private and process-wide, so the
        // only externally observable proof any one installed is that a
        // second install of the same slot is refused.
        //
        // WOR-2598: which makes this deliberately the only test in this
        // binary that reaches an install at all, and the refused boot
        // below is how that stays true. `install_audit_chain` opens every
        // named file before it registers any of them, so the two
        // `fails_boot_when_..._parent_cannot_be_created` tests below stop
        // at an `open` and never claim a slot. Before that split the
        // refused boot here would have claimed three of the four on its
        // way to failing, the clean boot after it would have been refused
        // its own security slot, and the two tests below would have taken
        // turns failing on whichever ran first. Under nextest none of
        // that is visible, because every test gets its own process;
        // `release-checks.yml` runs `cargo test --workspace --locked
        // --no-fail-fast -- --test-threads=1`, which shares one.
        let dir = tempfile::tempdir().expect("temp dir");
        let signer = sbproxy_config::types::WebBotAuthConfig {
            key_id: "audit-test-kid".to_string(),
            ed25519_seed_hex: "cc".repeat(32),
            directory_url: None,
        };

        // A boot that refuses on the last of the four. Under the old
        // order the three before it were already registered by the time
        // this returned, and the clean boot below could not have run.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"occupies the path a directory needs")
            .expect("write blocker file");
        let refused = sbproxy_config::types::AuditConfig {
            sink: sbproxy_config::types::AuditSinkKind::Chain,
            path: Some(
                dir.path()
                    .join("refused-security.jsonl")
                    .display()
                    .to_string(),
            ),
            sign_with: Some("web_bot_auth".to_string()),
            config_path: Some(
                dir.path()
                    .join("refused-config.jsonl")
                    .display()
                    .to_string(),
            ),
            key_path: Some(dir.path().join("refused-key.jsonl").display().to_string()),
            admin_path: Some(blocker.join("refused-admin.jsonl").display().to_string()),
        };
        let error = install_audit_chain(&refused, Some(&signer))
            .expect_err("an admin chain whose parent cannot be created must not boot quietly");
        assert!(
            error.to_string().contains("audit.admin_path"),
            "the failure names the key that turned the chain on: {error}"
        );

        // The same call again with four openable paths. It can only
        // succeed if the refusal above registered nothing: the slots are
        // set-once, and a security slot claimed on the way to that
        // failure would refuse this one.
        let security_path = dir.path().join("security-audit.jsonl");
        let config_path = dir.path().join("config-audit.jsonl");
        let key_path = dir.path().join("key-audit.jsonl");
        let admin_path = dir.path().join("admin-audit.jsonl");
        let audit = sbproxy_config::types::AuditConfig {
            sink: sbproxy_config::types::AuditSinkKind::Chain,
            path: Some(security_path.display().to_string()),
            sign_with: Some("web_bot_auth".to_string()),
            config_path: Some(config_path.display().to_string()),
            key_path: Some(key_path.display().to_string()),
            admin_path: Some(admin_path.display().to_string()),
        };

        // Two things can put a chain in a slot before this line, and the
        // message names both, because only one of them is the property
        // this test exists to guard. If the refused boot registered
        // something, the open/install split in `install_audit_chain`
        // regressed. If some other test in this binary got here first,
        // that test is the problem: this is supposed to be the only one
        // that installs, and nothing mechanical enforces it.
        install_audit_chain(&audit, Some(&signer)).expect(
            "a clean boot installs all four chains, so either the refused boot above registered \
             something it should not have, or another test in this binary claimed a slot before \
             this one ran",
        );

        assert!(
            security_path.exists(),
            "the security chain file is opened at boot"
        );
        assert!(
            config_path.exists(),
            "the config chain file is opened alongside it"
        );
        assert!(
            key_path.exists(),
            "the key chain file is opened alongside it"
        );
        assert!(
            admin_path.exists(),
            "the admin chain file is opened alongside it"
        );

        let redundant_seed = "dd".repeat(32);
        let redundant_security = sbproxy_observe::audit_chain::SecurityAuditChain::open(
            &dir.path().join("unused-security.jsonl"),
            &redundant_seed,
            "unused",
        )
        .expect("chain opens");
        let security_reinstall =
            sbproxy_observe::audit_chain::install_security_audit_chain(redundant_security);
        assert!(
            security_reinstall.is_err(),
            "the security slot this boot call claimed is already taken"
        );

        let redundant_config = sbproxy_observe::audit_chain::ConfigAuditChain::open(
            &dir.path().join("unused-config.jsonl"),
            &redundant_seed,
            "unused",
        )
        .expect("chain opens");
        let config_reinstall =
            sbproxy_observe::audit_chain::install_config_audit_chain(redundant_config);
        assert!(
            config_reinstall.is_err(),
            "the config slot this boot call claimed is already taken"
        );

        let redundant_key = sbproxy_observe::audit_chain::KeyAuditChain::open(
            &dir.path().join("unused-key.jsonl"),
            &redundant_seed,
            "unused",
        )
        .expect("chain opens");
        let key_reinstall = sbproxy_observe::audit_chain::install_key_audit_chain(redundant_key);
        assert!(
            key_reinstall.is_err(),
            "the key slot this boot call claimed is already taken"
        );

        let redundant_admin = sbproxy_observe::audit_chain::AdminActionAuditChain::open(
            &dir.path().join("unused-admin.jsonl"),
            &redundant_seed,
            "unused",
        )
        .expect("chain opens");
        let admin_reinstall =
            sbproxy_observe::audit_chain::install_admin_audit_chain(redundant_admin);
        assert!(
            admin_reinstall.is_err(),
            "the admin slot this boot call claimed is already taken"
        );

        // The four slots outlive this test: they are set once for the
        // life of the process, and they hold open file handles to the
        // four chains installed above. Letting the `TempDir` clean up
        // would leave the rest of this binary emitting key and admin
        // audit records into unlinked files, which is a state no
        // deployment can reach and a trap for any later test that
        // asserts on the chained fields. Keep the directory instead; the
        // OS reclaims it, and the leak is bounded at one directory per
        // process.
        let _kept = dir.keep();
    }

    #[test]
    fn arm_egress_gates_from_config_is_the_seam_run_calls_at_boot() {
        // WOR-2476 regression: a prior version of this arming installed
        // the registry from `reload_compiled_config_locked` only, and
        // rebuilt `AI_CLIENT` as a second, separate call at that same
        // site. `run` (boot) never called either, so a fresh process
        // start served every purpose ungated until its first reload,
        // even with a `deny_by_default` `egress:` section. Drives the
        // shared seam directly, the exact way `run` calls it (not
        // `install_configured_gate`, which only proves the registry
        // slot, not that a live dispatch is actually gated), and checks
        // both halves of what that one call has to do: arm the
        // registry, and rebuild the process-wide `ai_client()` so a
        // real dispatch through it is denied before any reload runs.
        let yaml = r#"
proxy: {}
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
"#;
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");

        arm_egress_gates_from_config(&compiled);

        assert!(
            sbproxy_security::egress::configured_gate(
                sbproxy_security::egress::EgressPurpose::AiProvider
            )
            .is_some(),
            "the registry must carry the compiled AiProvider authorizer"
        );

        let client = crate::server::ai_client();
        let err = client
            .authorize_provider_url(
                "https://attacker.test/v1/chat",
                &sbproxy_security::egress::SystemHostResolver,
            )
            .expect_err("a host outside the configured allowlist must be denied");
        assert_eq!(err, sbproxy_security::egress::EgressDenied::UnlistedHost);

        // Restore the legacy ungated default so a later test in the same
        // process (the `cargo test` fallback path only; nextest gives
        // every test its own process) does not inherit this arming.
        sbproxy_security::egress::install_configured_gate(
            sbproxy_security::egress::EgressPurpose::AiProvider,
            None,
        );
        reload_ai_client();
    }

    #[test]
    fn every_purpose_the_compiled_egress_section_arms_is_reachable_in_the_registry() {
        // WOR-2612 regression, and the guard against the next one of its
        // shape. A sub-block can compile an allowlist for more than one
        // purpose: `usage_sinks:` builds one under both `UsageSink` and
        // `Webhook`. The registry is an exact-key map with no fallback,
        // so a purpose the compiler armed and the installer skipped
        // answers `None` for every config, forever, and the consumer
        // reading that key dials with no allowlist while the operator's
        // `deny_by_default` block says otherwise. That is what shipped:
        // `Webhook` was compiled and never installed, and the `events:`
        // webhook sink is the reader that got `None`.
        //
        // The expectation is read off the compiled authorizers rather
        // than typed out, deliberately. A literal list here would be a
        // third copy of the same fact and could go stale the same way
        // the installer's copy did; asking the value what it answers for
        // cannot. Both directions are checked, because a sub-block that
        // arms two purposes and clears one is the same bug with the
        // reload in front of it.
        let yaml = r#"
proxy: {}
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com"]
  agent_orchestration:
    mode: deny_by_default
    hosts: ["agents.internal"]
  classifier_hooks:
    mode: deny_by_default
    hosts: ["classifier.internal"]
  usage_sinks:
    mode: deny_by_default
    hosts: ["collector.internal"]
  model_artifacts:
    mode: deny_by_default
    hosts: ["artifacts.internal"]
  token_exchange:
    mode: deny_by_default
    hosts: ["idp.internal"]
  federation:
    mode: deny_by_default
    hosts: ["anchor.example"]
"#;
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");
        let armed: Vec<sbproxy_security::egress::EgressPurpose> = [
            compiled.egress.ai_providers.as_ref(),
            compiled.egress.agent_orchestration.as_ref(),
            compiled.egress.classifier_hooks.as_ref(),
            compiled.egress.usage_sinks.as_ref(),
            compiled.egress.model_artifacts.as_ref(),
            compiled.egress.token_exchange.as_ref(),
            compiled.egress.federation.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flat_map(|authorizer| authorizer.purposes())
        .collect();
        assert!(
            armed.contains(&sbproxy_security::egress::EgressPurpose::Webhook),
            "the fixture must exercise a sub-block that arms two purposes; \
             `usage_sinks:` compiling `Webhook` is the case this test is about"
        );

        arm_egress_gates_from_config(&compiled);

        for purpose in &armed {
            assert!(
                sbproxy_security::egress::configured_gate(*purpose).is_some(),
                "`{}` has a compiled allowlist but no registry slot, so every \
                 `configured_gate({})` read runs ungated",
                purpose.as_label(),
                purpose.as_label()
            );
        }

        // A reload that drops the whole `egress:` section has to give
        // every one of those purposes back to the legacy ungated
        // contract, not leave the last config's allowlist pinned.
        let dropped = sbproxy_config::compile_config("proxy: {}\n").expect("bare config compiles");
        arm_egress_gates_from_config(&dropped);
        for purpose in &armed {
            assert!(
                sbproxy_security::egress::configured_gate(*purpose).is_none(),
                "`{}` stayed armed after a reload dropped the `egress:` section",
                purpose.as_label()
            );
        }

        // `allow_by_default` is the other shape that compiles to `None`.
        // Prove it clears a previously armed classifier slot too, rather
        // than testing only a fully omitted `egress:` section.
        arm_egress_gates_from_config(&compiled);
        let classifier_ungated = sbproxy_config::compile_config(
            r#"
proxy: {}
egress:
  classifier_hooks:
    mode: allow_by_default
    hosts: ["classifier.internal"]
"#,
        )
        .expect("allow-by-default classifier config compiles");
        arm_egress_gates_from_config(&classifier_ungated);
        assert!(
            sbproxy_security::egress::configured_gate(
                sbproxy_security::egress::EgressPurpose::ClassifierHook
            )
            .is_none(),
            "an allow-by-default reload left the prior ClassifierHook gate armed"
        );

        // `arm_egress_gates_from_config` rebuilds the AI client itself,
        // and the allow-by-default config above restored the ungated one,
        // so there is nothing left for this test to undo.
    }

    // WOR-2481: the reload-time seam for the boot-only OTLP trace and
    // metric exporters. Neither test builds a real exporter (that needs
    // live network I/O and a tokio runtime); instead they seed
    // `sbproxy_observe::telemetry`'s active-endpoint registry directly
    // with `record_active_boot_telemetry_endpoint`, the exact state
    // `authorize_telemetry_endpoint_or_refuse_boot` leaves behind on its
    // allow path at real boot, then drive a real reload transaction
    // through `reload_from_config_yaml` the same way every other
    // reload-refusal test in this module does.

    #[test]
    fn reload_refuses_when_the_new_egress_telemetry_config_denies_a_running_boot_only_exporter() {
        let signal = "wor2481-lifecycle-refuses";
        let endpoint = "https://wor2481-fixture-collector.invalid:4317";
        sbproxy_observe::telemetry::record_active_boot_telemetry_endpoint(signal, endpoint);

        // A host allowlist check short-circuits before any DNS lookup
        // (see `EgressAuthorizer::authorize_inner`), so a fictional
        // `.invalid` host denies deterministically with no network I/O.
        let yaml = r#"
proxy: {}
egress:
  telemetry:
    mode: deny_by_default
    hosts: ["a-completely-different-collector.invalid"]
    ports: [4317]
"#;
        let error = reload_from_config_yaml("sb.yml", yaml).expect_err(
            "a reload whose new egress.telemetry config denies a still-running boot-only \
             exporter's endpoint must be refused, not silently keep exporting to it",
        );
        let message = error.to_string();
        assert!(
            message.contains(signal) && message.contains(endpoint),
            "the refusal must name the signal and endpoint so an operator can act on it: \
             {message}"
        );
        assert!(
            message.contains("UnlistedHost"),
            "this must be denied because the new config dropped the host, not for an \
             unrelated reason such as the explicit `ports: [4317]` this fixture also sets: \
             {message}"
        );
    }

    #[test]
    fn reload_proceeds_when_the_new_egress_telemetry_config_still_allows_a_running_boot_only_exporter(
    ) {
        let signal = "wor2481-lifecycle-proceeds";
        let endpoint = "https://127.0.0.1:4317";
        sbproxy_observe::telemetry::record_active_boot_telemetry_endpoint(signal, endpoint);

        // 127.0.0.1 resolves with no network I/O (an IP literal needs no
        // DNS lookup), same as the sibling test in
        // `sbproxy_observe::telemetry`'s own test module.
        let yaml = r#"
proxy: {}
egress:
  telemetry:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    ports: [4317]
    allow_private: true
"#;
        reload_from_config_yaml("sb.yml", yaml).expect(
            "a reload whose new egress.telemetry config still allows a running boot-only \
             exporter's endpoint must proceed",
        );
    }

    #[test]
    fn install_audit_chain_fails_boot_when_config_paths_parent_cannot_be_created() {
        // Same fail-the-boot posture as the security half above (see
        // `a_file_egress_whose_path_cannot_be_opened_fails_the_boot` for
        // the sibling case on the events sink): an operator who named
        // `audit.config_path` wants a proxy that refuses to start over one
        // that starts and silently records nothing.
        //
        // WOR-2598: this stops at an `open` and must never reach an
        // install, which is what keeps it independent of whatever else
        // ran first in this process. Do not add an assertion here that
        // claims a process-wide slot; put it in
        // `install_audit_chain_claims_no_slot_on_a_refused_boot_and_all_four_on_a_clean_one`
        // instead, which is the one test in this binary that owns them.
        let dir = tempfile::tempdir().expect("temp dir");
        let security_path = dir.path().join("security-audit.jsonl");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"occupies the path a directory needs")
            .expect("write blocker file");
        let config_path = blocker.join("config-audit.jsonl");

        let signer = sbproxy_config::types::WebBotAuthConfig {
            key_id: "audit-test-kid-2".to_string(),
            ed25519_seed_hex: "ee".repeat(32),
            directory_url: None,
        };
        let audit = sbproxy_config::types::AuditConfig {
            sink: sbproxy_config::types::AuditSinkKind::Chain,
            path: Some(security_path.display().to_string()),
            sign_with: Some("web_bot_auth".to_string()),
            config_path: Some(config_path.display().to_string()),
            key_path: None,
            admin_path: None,
        };

        let error = install_audit_chain(&audit, Some(&signer))
            .expect_err("a config chain whose parent cannot be created must not boot quietly");
        assert!(
            error.to_string().contains("audit.config_path"),
            "the failure names the key that turned the chain on: {error}"
        );
    }

    #[test]
    fn install_audit_chain_fails_boot_when_admin_paths_parent_cannot_be_created() {
        // WOR-2478: the same loud-fail posture, proved for the admin
        // channel specifically so the extension is known to be reachable
        // rather than merely mirrored in shape from the config case above.
        //
        // WOR-2598: same rule as the config twin above. This stops at an
        // `open` and claims no process-wide slot, so it does not care
        // whether it ran first or last.
        let dir = tempfile::tempdir().expect("temp dir");
        let security_path = dir.path().join("security-audit.jsonl");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"occupies the path a directory needs")
            .expect("write blocker file");
        let admin_path = blocker.join("admin-audit.jsonl");

        let signer = sbproxy_config::types::WebBotAuthConfig {
            key_id: "audit-test-kid-3".to_string(),
            ed25519_seed_hex: "ff".repeat(32),
            directory_url: None,
        };
        let audit = sbproxy_config::types::AuditConfig {
            sink: sbproxy_config::types::AuditSinkKind::Chain,
            path: Some(security_path.display().to_string()),
            sign_with: Some("web_bot_auth".to_string()),
            config_path: None,
            key_path: None,
            admin_path: Some(admin_path.display().to_string()),
        };

        let error = install_audit_chain(&audit, Some(&signer))
            .expect_err("an admin chain whose parent cannot be created must not boot quietly");
        assert!(
            error.to_string().contains("audit.admin_path"),
            "the failure names the key that turned the chain on: {error}"
        );
    }

    // --- WOR-2457: every applied config lands in the revision ring ---

    /// Opens a fresh recorder against a temp dir and installs it as the
    /// process-wide one, the way `run` and `record_boot_config_revision`
    /// do. Callers get the `Arc` back so they can inspect the ring
    /// without going through `current_config_history_recorder` again.
    fn install_history_recorder_for_test(
        dir: &std::path::Path,
    ) -> std::sync::Arc<crate::config_history::ConfigHistoryRecorder> {
        crate::config_history::clear_config_history_recorder();
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let recorder = crate::config_history::ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error opening the config history store")
            .expect("an enabled block opens a recorder");
        let recorder = std::sync::Arc::new(recorder);
        crate::config_history::install_config_history_recorder(recorder.clone());
        recorder
    }

    /// One gauge's current value, read off the process registry.
    fn gauge_value(name: &str) -> Option<f64> {
        prometheus::gather()
            .iter()
            .find(|family| family.name() == name)
            .and_then(|family| family.get_metric().first().map(|m| m.get_gauge().value()))
    }

    /// Seed a ring with one document that boots, promoted to last known
    /// good, and return the block naming it.
    fn ring_with_a_good_revision(
        dir: &std::path::Path,
        yaml: &str,
    ) -> sbproxy_config::ConfigHistoryConfig {
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut store =
            sbproxy_config::RevisionStore::open(dir, history.keep, None).expect("open ring");
        let entry = store
            .append(
                yaml.as_bytes(),
                sbproxy_config::AppendMetadata {
                    provenance: sbproxy_config::BaseOrigin::Local,
                    blast_radius: None,
                    secrets_fingerprint: None,
                    actor: Some("test".to_string()),
                    applied_at: 1,
                    degraded: Vec::new(),
                },
            )
            .expect("append");
        store
            .record_soak_verdict(entry.revision, sbproxy_config::SoakVerdict::Successful)
            .expect("promote");
        history
    }

    /// `sbproxy_config_reload_total{result}` for one label.
    fn reload_total(result: &str) -> f64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_config_reload_total" {
                continue;
            }
            for metric in family.get_metric() {
                if metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "result" && pair.value() == result)
                {
                    return metric.get_counter().value();
                }
            }
        }
        0.0
    }

    /// Re-review, new Major 2. The watcher was fixed and SIGHUP was not,
    /// while two operator docs promised that a local reload on a pinned
    /// node counts as `suspended` "rather than as failures". `logrotate`
    /// postrotate hooks send SIGHUP on a schedule, so a pinned node
    /// quietly climbed the counter operators alert on: exactly the signal
    /// the watcher fix existed to keep clean.
    #[test]
    fn a_pinned_node_counts_a_sighup_reload_as_suspended_not_as_a_failure() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        std::fs::write(&config_path, "proxy: {}\n# whatever logrotate touched\n").expect("write");
        crate::config_boot::mark_on_fallback(crate::config_boot::PinnedRevision {
            revision: 3,
            digest: "rescued".to_string(),
            reason: None,
        });

        let failures_before = reload_total("failure");
        let suspended_before = reload_total("suspended");

        // Exactly what the SIGHUP handler calls.
        let refused = reload_from_config_path(config_path.to_str().expect("utf-8"))
            .expect_err("SIGHUP is inert on a pinned node");
        assert!(format!("{refused:#}").contains("pinned"), "{refused:#}");

        let failures_after = reload_total("failure");
        let suspended_after = reload_total("suspended");
        crate::config_boot::reset_for_test();

        assert_eq!(
            failures_after, failures_before,
            "a deliberate suspension must not land on the counter operators alert on",
        );
        assert_eq!(
            suspended_after,
            suspended_before + 1.0,
            "it lands on its own label instead",
        );
    }

    /// A document that compiles and then fails to construct is a
    /// failure the boot fallback must act on.
    ///
    /// `compile_config` leaves `action`, `policies`, `transforms` and
    /// `authentication` as opaque JSON, so an unknown action type
    /// passes it and fails later at
    /// `CompiledPipeline::from_config_at`. While the pre-check stopped
    /// at `compile_config`, the primary document's early return skipped
    /// the walk entirely: the process exited fatally with no pin, no
    /// boot counter and no walk, on every restart, on a node whose
    /// operator had explicitly asked for a fallback. Module
    /// construction is where most operator typos land, so the gap
    /// covered the majority of the failures the feature exists for.
    #[test]
    fn a_document_that_compiles_but_does_not_construct_is_rescued_by_the_ring() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        // Compiles cleanly: `type` is opaque JSON to `compile_config`.
        // Fails at construction with "unknown action type".
        let will_not_construct = r#"
proxy:
  http_bind_port: 0
  config_history:
    enabled: true
    dir: RING_DIR
origins:
  "api.test":
    action:
      type: load_balancerr
"#
        .replace("RING_DIR", &temp.path().join("ring").to_string_lossy());
        std::fs::write(&config_path, &will_not_construct).expect("write");

        // The document really does pass the two steps the pre-check
        // used to stop at, so this test is measuring the third one and
        // not a parse error.
        let resolved =
            crate::config_source::resolve(&will_not_construct).expect("source: resolves");
        sbproxy_config::compile_config(&resolved.text)
            .expect("it compiles; that is the whole point");

        let good = "proxy:\n  http_bind_port: 0\n";
        let _history = ring_with_a_good_revision(&temp.path().join("ring"), good);

        let (yaml, pin) = boot_document(
            config_path.to_str().expect("utf-8"),
            Some(sbproxy_config::BootFallbackMode::LastKnownGood),
        )
        .expect("the ring holds a revision that constructs");

        assert_eq!(
            yaml, good,
            "the node boots on the ring's revision, not on the document that will not construct",
        );
        let pin = pin.expect("a rescued boot is pinned");
        let reason = pin
            .reason
            .expect("the pin names why the configured document failed");
        assert!(
            reason.contains("unknown action type"),
            "and the reason is the construction failure itself: {reason}",
        );
        crate::config_boot::reset_for_test();
    }

    /// The construct step is in the candidate walk too, not only on the
    /// primary. A ring entry that compiles and does not construct must
    /// be walked past rather than booted onto.
    #[test]
    fn the_walk_skips_a_candidate_that_compiles_but_does_not_construct() {
        let temp = tempfile::tempdir().expect("temp dir");
        assert!(
            boot_candidate_compiles(
                "origins:\n  \"api.test\":\n    action:\n      type: load_balancerr\n",
                temp.path(),
            )
            .is_err_and(|reason| reason.contains("unknown action type")),
            "the candidate test and the primary test have to be the same question",
        );
        boot_candidate_compiles("proxy:\n  http_bind_port: 0\n", temp.path())
            .expect("a document that constructs still passes");
    }

    /// WOR-2459, tightened in the fix round (Major 6). With
    /// `fallback: off` the boot path is byte-identical to the release
    /// before this one, and "byte-identical" is a stronger claim than
    /// "still fails": `boot_document` must hand the file's bytes back
    /// **untouched**, doing no `source:` resolve and no compile of its
    /// own, so a git-sourced node pays one fetch per boot rather than
    /// two and the operator sees `run`'s own error rather than a
    /// flattened, re-wrapped copy of it.
    #[test]
    fn boot_with_the_fallback_off_reads_the_file_and_does_nothing_else() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        let broken = "proxy:\n  http2_cleartextt: true\n";
        std::fs::write(&config_path, broken).expect("write");
        // A ring that could have rescued this boot, deliberately present:
        // the point is that `off` does not look at it.
        let _history = ring_with_a_good_revision(&temp.path().join("ring"), "proxy: {}\n");

        let (yaml, pin) = boot_document(
            config_path.to_str().expect("utf-8"),
            Some(sbproxy_config::BootFallbackMode::Off),
        )
        .expect("the read succeeds; the compile is the caller's, as it always was");
        assert_eq!(yaml, broken, "the bytes are handed back untouched");
        assert!(pin.is_none(), "nothing was rescued and nothing is pinned");
        assert!(!crate::config_boot::on_fallback());

        // And the error the operator sees is still the compile error,
        // raised by the same step `run` has always run on these bytes.
        let reason = boot_candidate_compiles(&yaml, std::path::Path::new("."))
            .expect_err("a misspelled key must not compile");
        assert!(
            reason.contains("http2_cleartextt"),
            "the compile error is what the operator sees: {reason}",
        );
        assert!(
            !reason.contains("revision ring"),
            "nothing about the ring is mentioned when it was never consulted: {reason}",
        );

        // An unreadable file keeps its historical message, which is the
        // one half of this path that does still produce an error here.
        let missing = temp.path().join("not-there.yml");
        let error = boot_document(
            missing.to_str().expect("utf-8"),
            Some(sbproxy_config::BootFallbackMode::Off),
        )
        .expect_err("an unreadable file still fails");
        assert!(
            format!("{error:#}").starts_with("failed to read config file"),
            "the historical read-failure message is unchanged: {error:#}",
        );
        crate::config_boot::reset_for_test();
    }

    /// WOR-2459. With `fallback: last_known_good` and a broken config,
    /// the node boots on the ring's entry, pins itself to it, and says
    /// so on the gauge.
    #[test]
    fn boot_with_the_fallback_on_uses_the_last_known_good_revision() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let ring = temp.path().join("ring");
        let rescued = "proxy: {}\n# the last known good\n";
        let history = ring_with_a_good_revision(&ring, rescued);
        let config_path = temp.path().join("sb.yml");
        std::fs::write(
            &config_path,
            format!(
                "proxy:\n  http2_cleartextt: true\n  config_history:\n    enabled: true\n    \
                 dir: {}\n    boot:\n      fallback: last_known_good\n",
                history.dir
            ),
        )
        .expect("write");

        let (yaml, pin) = boot_document(config_path.to_str().expect("utf-8"), None)
            .expect("the ring rescues the boot");
        let pin = pin.expect("the boot is pinned to a ring entry");

        assert_eq!(yaml, rescued, "the node serves the stored document");
        assert!(crate::config_boot::on_fallback());
        assert_eq!(
            crate::config_boot::pinned_revision().map(|p| p.revision),
            Some(pin.revision),
        );
        assert_eq!(
            gauge_value("sbproxy_config_fallback_active"),
            Some(1.0),
            "a node quietly serving a config nobody wrote is worse than one that is down",
        );
        crate::config_boot::reset_for_test();
    }

    /// WOR-2459, the test that proves the ticket rather than the flag.
    ///
    /// Boot on the fallback, then touch the config: the watcher's own
    /// reload path must not move the pipeline pointer. Without the
    /// suspension, the first filesystem event in the config's directory
    /// re-applies the broken file and loops straight back into the state
    /// the fallback just rescued the node from.
    #[test]
    fn a_pinned_node_does_not_move_its_pipeline_when_the_config_file_changes() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        // Establish a running pipeline first, so there is a pointer to
        // compare against.
        reload_from_config_yaml(
            config_path.to_str().expect("utf-8"),
            "proxy: {}\n# rescued\n",
        )
        .expect("the rescued config publishes");
        let before = crate::reload::current_pipeline_full();

        crate::config_boot::mark_on_fallback(crate::config_boot::PinnedRevision {
            revision: 9,
            digest: "rescued".to_string(),
            reason: None,
        });

        // Exactly what the file watcher calls once the burst it saw goes
        // quiet and the digest has moved.
        let refused = reload_from_config_text(
            config_path.to_str().expect("utf-8"),
            "proxy: {}\n# whatever landed in that directory\n",
        )
        .expect_err("a pinned node refuses a local reload");
        assert!(
            format!("{refused:#}").contains("pinned"),
            "the refusal says why: {refused:#}",
        );
        assert!(
            std::sync::Arc::ptr_eq(&before, &crate::reload::current_pipeline_full()),
            "the pipeline pointer must not move while the node is pinned",
        );

        // The SIGHUP path is the same function with a different door:
        // its handler calls `reload_from_config_path`, which reads the
        // file and lands in the same guard.
        std::fs::write(&config_path, "proxy: {}\n# a SIGHUP would read this\n").expect("write");
        let refused = reload_from_config_path(config_path.to_str().expect("utf-8"))
            .expect_err("SIGHUP is inert on a pinned node");
        assert!(format!("{refused:#}").contains("pinned"), "{refused:#}");
        assert!(
            std::sync::Arc::ptr_eq(&before, &crate::reload::current_pipeline_full()),
            "and SIGHUP does not move the pointer either",
        );

        // Clearing the pin brings the watcher back without a restart.
        crate::config_boot::clear_fallback().expect("something was pinned");
        reload_from_config_yaml(
            config_path.to_str().expect("utf-8"),
            "proxy: {}\n# after the pin was cleared\n",
        )
        .expect("a cleared node reloads again");
        assert!(
            !std::sync::Arc::ptr_eq(&before, &crate::reload::current_pipeline_full()),
            "and the reload it refused a moment ago now publishes",
        );
        assert_eq!(gauge_value("sbproxy_config_fallback_active"), Some(0.0));
        crate::config_boot::reset_for_test();
    }

    /// WOR-2459. A first boot with an empty ring exits like `off` does,
    /// and the message says the ring was empty rather than pretending a
    /// fallback was attempted.
    #[test]
    fn a_first_boot_with_an_empty_ring_exits_like_off_and_says_so() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        std::fs::write(
            &config_path,
            format!(
                "proxy:\n  http2_cleartextt: true\n  config_history:\n    enabled: true\n    \
                 dir: {}\n",
                temp.path().join("empty-ring").display()
            ),
        )
        .expect("write");

        let error = boot_document(
            config_path.to_str().expect("utf-8"),
            Some(sbproxy_config::BootFallbackMode::LastKnownGood),
        )
        .expect_err("an empty ring cannot rescue a first boot");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("http2_cleartextt"),
            "the original failure is still the headline: {rendered}",
        );
        assert!(
            rendered.contains("empty"),
            "and it says the ring was empty: {rendered}",
        );
        assert!(!crate::config_boot::on_fallback());
        crate::config_boot::reset_for_test();
    }

    /// The failure half of the fatal line is sanitized too, not only the
    /// primary.
    ///
    /// `StoreUnavailable` carries a store-open error that names the ring
    /// path, and that string is the operator's, so it can carry whatever
    /// a path can. Reverting the second `scrub_boot_failure` at the
    /// ring-empty and store-unavailable exits leaves the raw text in the
    /// error that reaches `eprintln!("Fatal: ...")`, and before this
    /// nothing noticed.
    #[test]
    fn the_store_unavailable_half_of_the_fatal_error_is_sanitized() {
        crate::config_boot::reset_for_test();
        let temp = tempfile::tempdir().expect("temp dir");

        // A real ring at a path whose own name carries a control
        // character, with a world-readable index, so `refuse_shared_files`
        // refuses and names the widened file.
        //
        // Two things about the fixture are load bearing. The control
        // byte reaches the config as a YAML `\u` sequence rather than
        // literally, because a literal one fails the parse before the
        // store is opened at all and falls back to the default ring
        // directory, which would make this test pass without the
        // production change.
        // And the store error has to be one that carries the path:
        // `RevisionStoreError::Io` renders an errno and no path, so the
        // permission-denied open this was first written against proved
        // nothing. Other store errors do carry it, including
        // `RevisionStore::open`'s own `Corrupt` arms for a missing blob
        // and an oversized file, so this is one of several routes rather
        // than the only one; `refuse_shared_files` is simply the
        // cheapest to set up.
        use std::os::unix::fs::PermissionsExt as _;
        let ring = temp.path().join("ring\u{1b}[2Jdir");
        let _history = ring_with_a_good_revision(&ring, "proxy:\n  http_bind_port: 8080\n");
        std::fs::set_permissions(
            ring.join("index.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("widen the index so the walk refuses and names the path");
        let quoted = format!(
            "{}/ring\\u001B[2Jdir",
            temp.path().display().to_string().replace('\\', "\\\\")
        );

        let config_path = temp.path().join("sb.yml");
        std::fs::write(
            &config_path,
            format!(
                "proxy:\n  http2_cleartextt: true\n  config_history:\n    enabled: true\n    \
                 dir: \"{quoted}\"\n",
            ),
        )
        .expect("write");

        let error = boot_document(
            config_path.to_str().expect("utf-8"),
            Some(sbproxy_config::BootFallbackMode::LastKnownGood),
        )
        .expect_err("a ring that will not open cannot rescue this boot");
        let rendered = format!("{error:#}");

        assert!(
            !rendered.chars().any(char::is_control),
            "no control character reaches the fatal line: {rendered:?}",
        );
        assert!(
            rendered.contains("http2_cleartextt"),
            "the original failure is still the headline: {rendered}",
        );
        assert!(
            rendered.contains("could not be opened"),
            "and this really took the store-unavailable arm, which is the one that carries an \
             operator-controlled string: {rendered}",
        );
        assert!(
            rendered.contains("2Jdir"),
            "the ring path reached this line, which is what makes the scrub load bearing \
             rather than decorative: {rendered}",
        );
        crate::config_boot::reset_for_test();
    }

    /// Re-review, WOR-2458's last partial line. "With the synthetic
    /// probe driver enabled on a node with no organic traffic, the soak
    /// reaches a real verdict rather than Inconclusive."
    ///
    /// The driver's own origin is *required* to be a non-network action
    /// (`static`, `mock`, `echo`, `noop`), so on the exact node the
    /// ticket describes the synthetic origin was landing in `unobserved`
    /// and poisoning the very signal the driver exists to feed. A
    /// non-network origin has no upstream: it cannot be unhealthy and it
    /// hides nothing, so it belongs in neither column.
    #[test]
    fn a_non_network_origin_is_not_an_upstream_this_signal_can_be_blind_to() {
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        // The shape `proxy.synthetic_probe` requires of its own origin.
        let yaml = "proxy: {}\norigins:\n  \"__synthetic.local\":\n    action:\n      \
                    type: static\n      body: ok\n";
        reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("a static origin publishes");

        let pipeline = crate::reload::current_pipeline();
        let sample = crate::config_soak::sample_upstream_health_of(
            &pipeline.actions,
            &pipeline.config.origins,
        );
        assert!(
            sample.unobserved.is_empty(),
            "a static origin has no upstream to be blind to: {sample:?}",
        );
        assert_eq!(sample.observed, 0);
        assert!(sample.unhealthy.is_empty());

        // What it must not do is promote. A config with no forwarding
        // origin at all leaves this signal with nothing examined, and in
        // this module a pass promotes, so the honest answer is an
        // abstention naming the emptiness (verification residual R1).
        let outcome = crate::config_soak::upstream_health_signal(
            &sbproxy_config::ConfigSoakConfig::default(),
            &sample,
        );
        assert!(
            matches!(outcome, crate::config_soak::SignalOutcome::Abstain(_)),
            "a signal that examined nothing must not promote: {outcome:?}",
        );
    }

    /// WOR-2458 fix round, Blocker 3, end to end. The signal claims it
    /// catches an origin repointed at a dead address; a `type: proxy`
    /// origin exposes no breaker, no health check, and no outlier
    /// detector, so the sampler has to report it as unobserved rather
    /// than skipping it. Driven against a really published pipeline
    /// rather than a hand-built sample, because the bug was in the walk.
    #[test]
    fn a_proxy_origin_pointed_at_a_dead_address_is_reported_as_unobserved() {
        let temp = tempfile::tempdir().expect("temp dir");
        let config_path = temp.path().join("sb.yml");
        // 203.0.113.1 is TEST-NET-3, reserved for documentation and
        // guaranteed not to route, so nothing here dials anything.
        let yaml = "proxy: {}\norigins:\n  \"dead.local\":\n    action:\n      type: proxy\n      \
                    url: http://203.0.113.1:9\n";
        reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("a proxy origin publishes");

        let pipeline = crate::reload::current_pipeline();
        let sample = crate::config_soak::sample_upstream_health_of(
            &pipeline.actions,
            &pipeline.config.origins,
        );
        assert!(
            sample.unhealthy.is_empty(),
            "nothing was dialled, so nothing is known to be unhealthy: {sample:?}",
        );
        assert_eq!(
            sample.observed, 0,
            "a proxy origin exposes no health signal at all: {sample:?}",
        );
        assert_eq!(
            sample.unobserved.len(),
            1,
            "and it has to be counted rather than skipped: {sample:?}",
        );

        // Which is what keeps the signal from claiming health it never
        // looked for.
        let outcome = crate::config_soak::upstream_health_signal(
            &sbproxy_config::ConfigSoakConfig::default(),
            &sample,
        );
        assert!(
            matches!(outcome, crate::config_soak::SignalOutcome::Abstain(_)),
            "{outcome:?}",
        );
    }

    /// WOR-2458. The reload transaction arms a soak window against the
    /// revision it just recorded, and recording still never promotes.
    ///
    /// Driven through `reload_from_config_yaml`, the real transaction,
    /// rather than calling `config_soak::arm` directly: the question
    /// this answers is whether the seam is wired, and a test that armed
    /// the window itself would answer a different one.
    #[test]
    fn a_committed_reload_arms_a_soak_window_and_does_not_promote() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        crate::config_soak::clear();
        let config_path = temp.path().join("sb.yml");
        let yaml = "proxy: {}\n# soak-arming fixture\n";

        reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("a valid config publishes");

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1, "one applied revision recorded");
        assert_eq!(
            crate::config_soak::in_flight_revision(),
            Some(entries[0].revision),
            "the reload armed a window against the revision it recorded",
        );
        assert!(
            recorder.lkg().is_none(),
            "recording an applied revision must never promote it: that is the defect",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2458. A window that closes with a passing signal advances the
    /// pointer exactly once, and the window is consumed by the close so
    /// it cannot advance it twice.
    #[test]
    fn a_closed_window_with_a_passing_signal_advances_the_lkg_pointer_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        crate::config_soak::clear();
        let config_path = temp.path().join("sb.yml");
        let yaml = "proxy: {}\n# promoting fixture\n";

        reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("a valid config publishes");
        let revision = recorder.entries()[0].revision;
        // The operator's own probe reporting a healthy round trip. It
        // dials a real URL the operator chose, so unlike the synthetic
        // driver's non-network origin it is evidence about the world and
        // promotes on its own. The synthetic driver cannot stand in here
        // any more: this fixture declares no upstream, so the health
        // signal abstains and a synthetic pass is discarded with it
        // (verification residual R1).
        crate::config_soak::record_probe(
            crate::config_soak::ProbeKind::Operator,
            crate::config_soak::ProbeObservation::Ok,
        );

        let closed = crate::config_soak::confirm_now().expect("a window was in flight");
        assert_eq!(closed.revision, revision);
        assert_eq!(closed.verdict, sbproxy_config::SoakVerdict::Successful);
        let lkg = recorder.lkg().expect("a passed soak promotes");
        assert_eq!(lkg.revision, revision);
        assert_eq!(lkg.state, sbproxy_config::RevisionState::Good);
        assert!(
            crate::config_soak::confirm_now().is_none(),
            "the window is consumed by the close, so it cannot promote twice",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2458. A window where every signal abstained is Inconclusive:
    /// the pointer does not move, the entry stays `applied`, and the
    /// verdict carries its own metric label so an operator can see that
    /// their soak is measuring nothing.
    #[test]
    fn a_window_where_every_signal_abstains_is_inconclusive_and_stays_applied() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        crate::config_soak::clear();
        let config_path = temp.path().join("sb.yml");
        // A forwarding origin with no health block: something the soak
        // has to admit it cannot see. A config with no origin at all now
        // passes the health signal vacuously (there is no upstream that
        // could be down), so the empty document no longer produces this
        // verdict, which is the point of that change.
        let yaml = "proxy: {}\norigins:\n  \"opaque.local\":\n    action:\n      \
                    type: proxy\n      url: http://203.0.113.2:9\n";
        let before = soak_verdict_total("inconclusive", "window");

        reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("a valid config publishes");
        // No probe, no traffic, no breakers: nothing measured anything.
        let closed = crate::config_soak::confirm_now().expect("a window was in flight");

        assert_eq!(closed.verdict, sbproxy_config::SoakVerdict::Inconclusive);
        assert!(
            closed.reports.iter().all(|(_, outcome)| matches!(
                outcome,
                crate::config_soak::SignalOutcome::Abstain(_)
            )),
            "every signal abstained: {:?}",
            closed.reports,
        );
        assert!(
            recorder.lkg().is_none(),
            "a soak that measured nothing must not promote",
        );
        assert_eq!(
            recorder.entries()[0].state,
            sbproxy_config::RevisionState::Applied,
            "the entry stays applied and never reaches good",
        );
        assert_eq!(
            recorder.entries()[0].soak_verdict,
            Some(sbproxy_config::SoakVerdict::Inconclusive),
        );
        assert_eq!(
            soak_verdict_total("inconclusive", "window"),
            before + 1.0,
            "inconclusive carries its own metric label",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// `sbproxy_config_soak_verdict_total{verdict,signal}` for one label
    /// pair, read off the process registry.
    fn soak_verdict_total(verdict: &str, signal: &str) -> f64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_config_soak_verdict_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels = metric.get_label();
                let matches_verdict = labels
                    .iter()
                    .any(|pair| pair.name() == "verdict" && pair.value() == verdict);
                let matches_signal = labels
                    .iter()
                    .any(|pair| pair.name() == "signal" && pair.value() == signal);
                if matches_verdict && matches_signal {
                    return metric.get_counter().value();
                }
            }
        }
        0.0
    }

    /// WOR-2462. A local file that does not compile is a refused
    /// candidate too, and this is the one an operator is most likely to
    /// be looking at. Driven through `reload_from_config_yaml`, the
    /// function both the file watcher and SIGHUP reach the reload
    /// transaction through (see its own doc comment for why the two
    /// triggers share one label), so this covers both paths.
    #[test]
    fn a_local_file_that_does_not_compile_is_stored_as_a_rejection() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let config_path = temp.path().join("sb.yml");

        // A misspelled nested key: the compiler refuses it rather than
        // silently taking the default.
        let broken = "proxy:\n  http2_cleartextt: true\n";
        std::fs::write(&config_path, broken).expect("write");
        let error = reload_from_config_yaml(config_path.to_str().expect("utf-8"), broken)
            .expect_err("a misspelled key must not apply");
        assert!(
            format!("{error:#}").contains("http2_cleartextt"),
            "{error:#}"
        );

        let stored = recorder.rejections();
        assert_eq!(stored.len(), 1, "one stored rejection: {stored:?}");
        assert_eq!(
            stored[0].reason,
            sbproxy_config::RejectionReason::CompileFailed
        );
        assert_eq!(stored[0].stage, "file_watcher");
        assert_eq!(stored[0].provenance, sbproxy_config::BaseOrigin::Local);
        assert_eq!(
            stored[0].document, broken,
            "the refused document is kept as written",
        );
        assert!(
            recorder.entries().is_empty(),
            "a refused candidate is not an applied revision",
        );
        crate::config_history::clear_config_history_recorder();
    }

    #[test]
    fn boot_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        crate::config_history::clear_config_history_recorder();
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: temp.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        // `record_boot_config_revision` is the exact function `run` calls
        // right after it publishes the pipeline; this drives the real
        // boot seam rather than a stand-in for it.
        record_boot_config_revision(
            Some(&history),
            b"proxy: {}\n# boot\n",
            sbproxy_config::BaseOrigin::Local,
            "boot",
        );
        let recorder =
            crate::config_history::current_config_history_recorder().expect("boot installs one");
        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("boot"));
        assert_eq!(entries[0].provenance, sbproxy_config::BaseOrigin::Local);
        assert_eq!(entries[0].state, sbproxy_config::RevisionState::Applied);
    }

    #[test]
    fn boot_path_marks_the_slot_failed_when_the_store_cannot_open() {
        crate::config_history::clear_config_history_recorder();
        // `/` is always a real directory, root-owned, and not writable
        // by an ordinary user: `RevisionStore::open`'s `create_dir_all`
        // on a subdirectory of it fails with a permission error for any
        // process that is not itself root. The same "well-known
        // unwritable root-owned directory" fixture
        // `ownership_store_rejects_a_directory_owned_by_another_uid` in
        // `sbproxy-model-host` uses, chosen over `chmod`-ing a temp
        // directory because `create_private_dir_all` self-heals a temp
        // directory it owns back to 0700 before the open would even
        // reach the permission check those tests rely on.
        let unwritable_dir = "/sbproxy-config-history-unwritable-fixture-do-not-create";
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: unwritable_dir.to_string(),
            ..Default::default()
        };

        record_boot_config_revision(
            Some(&history),
            b"proxy: {}\n# boot\n",
            sbproxy_config::BaseOrigin::Local,
            "boot",
        );

        match &*crate::config_history::current_config_history_state() {
            crate::config_history::ConfigHistoryState::Open(_) => {
                // This process can write under `/` (running as root, or
                // some other environment where the fixture's premise
                // does not hold): the failure this test exists to
                // exercise cannot be produced here. Not a false pass --
                // there is nothing to assert against in this
                // environment, so the test simply has nothing to say.
            }
            crate::config_history::ConfigHistoryState::Failed { reason } => {
                assert!(
                    !reason.is_empty(),
                    "a failed boot open must carry a non-empty reason"
                );
                // The proxy is still up: nothing here panicked or
                // propagated past `record_boot_config_revision`, which
                // returns `()` and was called exactly as `run` calls it
                // right after publishing the pipeline.
            }
            crate::config_history::ConfigHistoryState::Disabled => {
                panic!(
                    "an enabled block whose store failed to open must mark the slot Failed, \
                     not leave it Disabled"
                );
            }
        }
        crate::config_history::clear_config_history_recorder();
    }

    #[test]
    fn file_watcher_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let config_path = temp.path().join("sb.yml");
        std::fs::write(&config_path, b"proxy: {}\n# file-watcher\n").expect("write config file");

        // The real file-watcher trigger: it reads the file itself and
        // calls this exact function, the same one `install_sighup_handler`
        // below calls on a signal instead of a filesystem event.
        reload_from_config_path(config_path.to_str().expect("utf8 path"))
            .expect("file-watcher-triggered reload publishes");

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("file_watcher"));
    }

    #[test]
    fn sighup_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let config_path = temp.path().join("sb.yml");
        std::fs::write(&config_path, b"proxy: {}\n# sighup\n").expect("write config file");

        // `install_sighup_handler`'s signal loop calls exactly this
        // function on `SIGHUP` (see its body: "`reload_from_config_path`
        // does blocking config-file reads..."); a signal cannot be
        // delivered deterministically in a unit test, so this drives the
        // same call the signal handler makes rather than the signal
        // itself. The config history entry this produces is
        // indistinguishable from the file-watcher's, which is
        // deliberate: both share the `"file_watcher"` audit label
        // already (see `reload_from_config_path`'s own doc comment) on
        // the grounds that both reload the same operator-managed local
        // file, and this ring inherits that same reasoning.
        reload_from_config_path(config_path.to_str().expect("utf8 path"))
            .expect("sighup-triggered reload publishes");

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("file_watcher"));
    }

    #[test]
    fn admin_reload_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let yaml = "proxy: {}\n# admin-reload\n";

        // The exact function `POST /admin/reload` calls (`admin.rs`)
        // after it has already validated the candidate document.
        reload_from_resolved_yaml("sb.yml", yaml, yaml).expect("admin-triggered reload publishes");

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        // No admin actor is installed on this thread outside a real
        // dispatched admin request, so this exercises the documented
        // `"api"` fallback rather than an authenticated operator id.
        assert_eq!(entries[0].actor.as_deref(), Some("api"));
        assert_eq!(entries[0].provenance, sbproxy_config::BaseOrigin::Local);
    }

    #[test]
    fn config_refresh_poller_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let yaml = "proxy: {}\n# refresh-poller\n";
        let origin = sbproxy_config::BaseOrigin::Git {
            repo: "git@example.com:org/repo.git".to_string(),
            reference: "main".to_string(),
            commit: "deadbeef".to_string(),
        };

        // The exact function `config_source.rs`'s refresh poller calls,
        // with the exact label and an already-resolved origin the way
        // that caller supplies one: `effective` there carries no
        // `source:` block of its own for this function to re-derive an
        // origin from, which is why the origin has to arrive as a
        // parameter (see this function's own doc comment).
        match try_reload_from_config_yaml("sb.yml", yaml, "config_refresh_poller", origin.clone())
            .expect("non-blocking reload runs")
        {
            TryReloadOutcome::Applied(_) => {}
            TryReloadOutcome::Busy => panic!("uncontended reload must not report busy"),
        }

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("config_refresh_poller"));
        assert_eq!(
            entries[0].provenance, origin,
            "the caller-supplied git origin must survive, not fall back to Local"
        );
    }

    #[test]
    fn config_authority_path_records_a_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let yaml = "proxy: {}\n# config-authority\n";

        // The exact function `config_subscriber.rs`'s `apply` calls, with
        // its exact label and its own already-computed `base_origin`.
        match try_reload_from_config_yaml(
            "sb.yml",
            yaml,
            "config_authority",
            sbproxy_config::BaseOrigin::Local,
        )
        .expect("non-blocking reload runs")
        {
            TryReloadOutcome::Applied(_) => {}
            TryReloadOutcome::Busy => panic!("uncontended reload must not report busy"),
        }

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("config_authority"));
    }

    #[test]
    fn two_consecutive_byte_identical_reloads_produce_one_ring_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let yaml = "proxy: {}\n# dedup\n";

        reload_from_config_yaml("sb.yml", yaml).expect("first reload publishes");
        reload_from_config_yaml("sb.yml", yaml).expect("second, identical reload publishes");

        assert_eq!(
            recorder.entries().len(),
            1,
            "byte-identical back-to-back reloads must not grow the ring"
        );
    }

    #[test]
    fn lkg_pointer_does_not_move_when_reloads_commit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        assert!(recorder.lkg().is_none());

        for marker in ["one", "two", "three"] {
            reload_from_config_yaml("sb.yml", &format!("proxy: {{}}\n# {marker}\n"))
                .unwrap_or_else(|error| panic!("reload {marker} must publish: {error:#}"));
        }

        assert_eq!(recorder.entries().len(), 3);
        assert!(
            recorder.lkg().is_none(),
            "nothing in the reload transaction may promote a revision to last-known-good"
        );
    }

    #[test]
    fn a_degraded_reload_is_still_recorded_with_its_degradation_captured() {
        let temp = tempfile::tempdir().expect("temp dir");
        let recorder = install_history_recorder_for_test(temp.path());
        let mut outcome = ReloadOutcome::default();
        outcome.degrade(DegradedSubsystem::KeyPlane);
        outcome.degrade(DegradedSubsystem::SinkDispatcher);
        assert!(!outcome.is_fully_applied());

        record_applied_config_revision(
            RevisionRecordingInput {
                content: b"proxy: {}\n# degraded\n",
                origin: sbproxy_config::BaseOrigin::Local,
                actor: "test",
            },
            &outcome,
        );

        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].degraded,
            vec!["key plane".to_string(), "sink dispatcher".to_string()],
            "the degradation is recorded as its own field rather than by refusing to record \
             the revision at all: the pipeline did publish"
        );
        // WOR-2458 changed what happens next. Recording still stores the
        // revision the same way, but arming the soak now reaches a
        // verdict immediately for a degraded reload rather than waiting
        // out the window, and that verdict is what moves the entry out
        // of `Applied`. Before the soak existed, this entry stayed
        // `Applied` forever and the last-known-good pointer never moved
        // for anything, which is the defect the epic exists to fix.
        assert_eq!(
            entries[0].state,
            sbproxy_config::RevisionState::Failed,
            "a reload that published with subsystems on prior state fails its soak on the \
             spot, without waiting the window out"
        );
        assert_eq!(
            entries[0].soak_verdict,
            Some(sbproxy_config::SoakVerdict::Failed),
        );
        assert!(
            recorder.lkg().is_none(),
            "and a failed soak never advances the last-known-good pointer",
        );
        assert_eq!(
            crate::config_soak::in_flight_revision(),
            None,
            "a window that already failed does not sit armed waiting to be closed",
        );
        crate::config_history::clear_config_history_recorder();
    }
}

#[cfg(test)]
mod openapi_emission_warning_tests {
    use super::log_openapi_emission_warnings;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedLogGuard(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedLogGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("warning capture")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogWriter {
        type Writer = SharedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogGuard(Arc::clone(&self.0))
        }
    }

    /// Run the reload-time warning against one config with a subscriber
    /// of this thread's own, so the assertion reads the line rather than
    /// whatever global subscriber another test installed.
    fn captured_warnings(yaml: &str) -> String {
        let compiled = sbproxy_config::compile_config(yaml).expect("config compiles");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_openapi_emission_warnings(&compiled);
        });
        let bytes = captured.lock().expect("warning capture").clone();
        String::from_utf8(bytes).expect("warning output is UTF-8")
    }

    const COLLIDING: &str = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    allowed_methods: ["GET"]
    action: { type: proxy, url: "http://127.0.0.1:9/" }
    forward_rules:
      - rules:
          - path: { exact: /users }
        origin:
          id: api-users
          action: { type: proxy, url: "http://127.0.0.1:9/" }
  "web.example.com":
    allowed_methods: ["GET"]
    action: { type: proxy, url: "http://127.0.0.1:9/" }
    forward_rules:
      - rules:
          - path: { exact: /users }
        origin:
          id: web-users
          action: { type: proxy, url: "http://127.0.0.1:9/" }
"#;

    const CLEAN: &str = r#"
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    allowed_methods: ["GET"]
    action: { type: proxy, url: "http://127.0.0.1:9/" }
    forward_rules:
      - rules:
          - path: { exact: /users }
        origin:
          id: api-users
          action: { type: proxy, url: "http://127.0.0.1:9/" }
"#;

    #[test]
    fn a_config_whose_document_loses_an_operation_warns_once_and_names_the_path() {
        // Both hosts expose GET /users, so the all-hosts document holds
        // one of the two operations and parks the other under an
        // extension no generator reads. Silence here means the operator's
        // only signal is a missing route in a generated client.
        let logged = captured_warnings(COLLIDING);
        assert!(
            logged.contains("/users"),
            "the warn has to name the path; got {logged}"
        );
        // `operation_id` builds these from the origin id, which config
        // compilation sets to the hostname, so naming both operations
        // also names both hosts. Attribution is the point: "two rules
        // collide somewhere" is not a thing anyone can act on.
        assert!(
            logged.contains("api.example.com_get_api-users")
                && logged.contains("web.example.com_get_web-users"),
            "and both operations, so the loss is attributable; got {logged}"
        );
        assert!(
            logged.contains("count=1"),
            "one finding, reported as a count rather than as a line per finding; got {logged}"
        );
        assert_eq!(
            logged.lines().count(),
            1,
            "one line per config, however many findings; got {logged}"
        );
    }

    #[test]
    fn a_config_whose_document_says_everything_warns_not_at_all() {
        let logged = captured_warnings(CLEAN);
        assert!(logged.is_empty(), "got {logged}");
    }
}

/// The `/readyz` component name the agent catalog reports under.
///
/// Deliberately not `agent_registry`: that name is already taken by
/// WOR-1743's agent-class resolver, which is a different subsystem, so an
/// operator reading it would get either `not_configured` for a live
/// registry or the health of something unrelated.
const AGENT_CATALOG_COMPONENT: &str = "agent_catalog";

/// Render the catalog's own health verdict as a `/readyz` component.
///
/// The three states are decided in `sbproxy-agent-registry`, next to the
/// catalog and its tests; this is only the mapping onto the shared
/// component vocabulary.
fn agent_catalog_component(
    health: sbproxy_agent_registry::CatalogHealth,
) -> (sbproxy_observe::ComponentStatus, Option<String>) {
    use sbproxy_agent_registry::CatalogHealth;
    match health {
        CatalogHealth::NoCatalog => (
            sbproxy_observe::ComponentStatus::NotConfigured,
            Some("no verified catalog has been applied".to_string()),
        ),
        CatalogHealth::Expired => (
            sbproxy_observe::ComponentStatus::Degraded,
            Some("the verified catalog is past its expiry".to_string()),
        ),
        CatalogHealth::Serving(count) => (
            sbproxy_observe::ComponentStatus::Healthy,
            Some(format!("{count} agents")),
        ),
        // `CatalogHealth` is `#[non_exhaustive]`, so a variant added later
        // arrives here rather than as a compile error. Degraded rather than
        // healthy: a state this build cannot name is not one it should
        // report as fine on a readiness endpoint.
        other => (
            sbproxy_observe::ComponentStatus::Degraded,
            Some(format!("unrecognized catalog state: {other:?}")),
        ),
    }
}

/// The refresh loop to install for this registry, or `None` when there is
/// nothing to refresh from.
///
/// A function rather than an `if` at the call site, which is inside `run`
/// and therefore unreachable from a test. The decision lives here in one
/// piece, so reverting it is reverting something a test drives; a bare
/// condition at the call site left the predicate covered and the decision
/// not.
fn agent_registry_refresher_for(
    cfg: &sbproxy_config::AgentRegistryConfig,
    registry: &std::sync::Arc<sbproxy_agent_registry::AgentRegistry>,
) -> Option<(
    std::sync::Arc<sbproxy_agent_registry::AgentRegistry>,
    std::time::Duration,
)> {
    if !agent_registry_feed_configured(cfg) {
        tracing::info!(
            "the agent registry is enabled with no feed configured; the approval queue is \
             live and no catalog refresh will run"
        );
        return None;
    }
    Some((
        std::sync::Arc::clone(registry),
        agent_registry_refresh_interval(cfg),
    ))
}

/// Whether this registry has a catalog feed to refresh from.
///
/// The registry's approval queue is useful with no feed at all, and the
/// example config ships that shape, so the refresh loop has to be
/// conditional on this rather than on the block being enabled. Same
/// condition `RegistrySummary::feed_configured` publishes, deliberately: an
/// operator reading `feed_configured: false` in the summary and a refresh
/// loop that is not running have to agree.
fn agent_registry_feed_configured(cfg: &sbproxy_config::AgentRegistryConfig) -> bool {
    cfg.feed_path.is_some() && cfg.key_directory_path.is_some()
}

/// Shortest and longest the catalog refresh loop may run at.
///
/// The floor keeps a small `stale_grace_secs` from turning into a hot loop
/// over two files; the ceiling keeps a large one from meaning the feed is
/// effectively never re-read.
const AGENT_REGISTRY_REFRESH_FLOOR: std::time::Duration = std::time::Duration::from_secs(60);
const AGENT_REGISTRY_REFRESH_CEILING: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// Interval used when `stale_grace_secs` is zero, which is the fail-closed
/// default and says nothing about how often to poll.
const AGENT_REGISTRY_REFRESH_DEFAULT: std::time::Duration = std::time::Duration::from_secs(300);

/// How often to re-read the configured feed.
///
/// Derived from `stale_grace_secs` rather than from a key of its own,
/// because that value is already the operator's statement of how stale a
/// catalog may be: polling at most that often is what makes the tolerance
/// mean something. Zero means the operator wants the publisher's expiry
/// honored exactly, which is a statement about acceptance and not about
/// polling, so it falls back to the default rather than to no refresh.
fn agent_registry_refresh_interval(
    cfg: &sbproxy_config::AgentRegistryConfig,
) -> std::time::Duration {
    if cfg.stale_grace_secs == 0 {
        return AGENT_REGISTRY_REFRESH_DEFAULT;
    }
    std::time::Duration::from_secs(cfg.stale_grace_secs)
        .clamp(AGENT_REGISTRY_REFRESH_FLOOR, AGENT_REGISTRY_REFRESH_CEILING)
}

/// Turn one `agent_registry` duration key into a `chrono::Duration`.
///
/// `chrono::Duration::seconds` is `expect(try_seconds(..))` and panics past
/// `i64::MAX / 1_000`, and a bare `as i64` on a large `u64` wraps negative,
/// which would silently shorten a feed's expiry rather than extend it. Both
/// are config values, so both get a named refusal instead. The workspace's
/// unwrap ratchet cannot see the first of those, because the `expect` lives
/// in chrono.
fn registry_duration(field: &'static str, seconds: u64) -> anyhow::Result<chrono::Duration> {
    i64::try_from(seconds)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "agent_registry.{field} is {seconds}, which is not a duration sbproxy can \
                 represent; use a value below {}",
                i64::MAX / 1_000
            )
        })
}

/// Open the agent registry's embedded store and restore its cached catalog.
///
/// `open_shared` rather than `open`: a config reload builds a candidate
/// generation while the live one still holds the file, and redb locks it
/// exclusively, so an unconditional open would make every reload of a config
/// with an agent registry fail.
///
/// The restore runs on a throwaway current-thread runtime because `run` has
/// no ambient one and the store's operations now need a runtime to be in:
/// each is a synchronous redb transaction handed to `spawn_blocking`, so
/// there is a `JoinHandle` for a driver to poll. This is the reason it must
/// stay a real runtime rather than becoming a bare `block_on` on a future
/// nobody drives.
fn build_agent_registry(
    cfg: &sbproxy_config::AgentRegistryConfig,
) -> anyhow::Result<std::sync::Arc<sbproxy_agent_registry::AgentRegistry>> {
    use sbproxy_platform::storage::{EmbeddedKvStore, MemoryKv};

    let store = EmbeddedKvStore::open_shared(&cfg.store_path, "agent_registry").map_err(|e| {
        anyhow::anyhow!(
            "agent_registry.store_path {}: {e}",
            cfg.store_path.display()
        )
    })?;
    let bootstrap = sbproxy_agent_registry::BootstrapKeys::from_pairs(
        cfg.bootstrap_keys
            .iter()
            .map(|(kid, public_key)| (kid.clone(), public_key.clone())),
    )
    .map_err(|e| anyhow::anyhow!("agent_registry.bootstrap_keys: {e}"))?;

    let options = sbproxy_agent_registry::AgentRegistryOptions {
        feed_path: cfg.feed_path.clone(),
        key_directory_path: cfg.key_directory_path.clone(),
        bootstrap_keys: bootstrap,
        stale_grace: registry_duration("stale_grace_secs", cfg.stale_grace_secs)?,
        duplicate_window: registry_duration("duplicate_window_secs", cfg.duplicate_window_secs)?,
        rotation_grace: registry_duration("rotation_grace_secs", cfg.rotation_grace_secs)?,
    };
    let registry = std::sync::Arc::new(
        sbproxy_agent_registry::AgentRegistry::new(
            store,
            std::sync::Arc::new(MemoryKv::new("agent_registry")),
            options,
        )
        .map_err(|e| anyhow::anyhow!("agent_registry: {e}"))?,
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| anyhow::anyhow!("agent_registry boot runtime: {e}"))?;
    let restored = runtime
        .block_on(registry.boot())
        .map_err(|e| anyhow::anyhow!("agent_registry could not read its store: {e}"))?;
    tracing::info!(
        path = %cfg.store_path.display(),
        restored_entries = restored,
        "agent registry opened"
    );
    Ok(registry)
}

/// Open the notifier's embedded store and start its delivery worker.
///
/// `open_shared` for the same reason the agent registry uses it: a config
/// reload builds a candidate generation while the live one still holds the
/// file, and redb locks it exclusively.
fn build_notifier(
    cfg: &sbproxy_config::NotificationsConfig,
) -> anyhow::Result<std::sync::Arc<sbproxy_observe::notify::Notifier>> {
    use sbproxy_platform::storage::EmbeddedKvStore;

    let store = EmbeddedKvStore::open_shared(&cfg.store_path, "notifications").map_err(|e| {
        anyhow::anyhow!("notifications.store_path {}: {e}", cfg.store_path.display())
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("notifier boot runtime: {e}"))?;
    let notifier = runtime
        .block_on(sbproxy_observe::notify::Notifier::start(
            store,
            cfg.queue_capacity,
        ))
        .map_err(|e| anyhow::anyhow!("notifications: {e}"))?;
    tracing::info!(
        path = %cfg.store_path.display(),
        queue_capacity = cfg.queue_capacity,
        "outbound notifier opened"
    );
    Ok(std::sync::Arc::new(notifier))
}

/// `SB_WORKER_STACK_BYTES` (WOR-2699).
///
/// The knob had no test at all: the stack budget test builds its own
/// runtime, so the whole hunk that reads this key could be reverted and
/// every test still passed.
#[cfg(test)]
mod worker_stack_env_tests {
    use super::{resolve_worker_stack_bytes, MIN_WORKER_STACK_BYTES};

    #[test]
    fn an_unset_key_leaves_pingora_its_default() {
        assert_eq!(resolve_worker_stack_bytes(None), None);
    }

    #[test]
    fn a_real_size_is_passed_through() {
        assert_eq!(
            resolve_worker_stack_bytes(Some("16777216")),
            Some(16 * 1024 * 1024)
        );
        // Whitespace from a shell export or a compose file.
        assert_eq!(
            resolve_worker_stack_bytes(Some(" 16777216 ")),
            Some(16 * 1024 * 1024)
        );
    }

    /// The typo the floor exists for.
    ///
    /// `SB_WORKER_STACK_BYTES=8` reads as bytes and means megabytes.
    /// Before this, it reached a `ServerConf` struct literal, which
    /// `validate()` never sees, so the server started and aborted on its
    /// first request with nothing to say why.
    #[test]
    fn a_size_written_in_the_wrong_unit_is_refused() {
        assert_eq!(resolve_worker_stack_bytes(Some("8")), None);
        assert_eq!(
            resolve_worker_stack_bytes(Some(&(MIN_WORKER_STACK_BYTES - 1).to_string())),
            None
        );
        assert_eq!(
            resolve_worker_stack_bytes(Some(&MIN_WORKER_STACK_BYTES.to_string())),
            Some(MIN_WORKER_STACK_BYTES),
            "the floor itself is allowed; it is a floor and not an exclusion"
        );
    }

    #[test]
    fn junk_and_zero_fall_back_rather_than_stopping_the_proxy() {
        for raw in ["", "0", "-1", "8mb", "eight", "1e6"] {
            assert_eq!(
                resolve_worker_stack_bytes(Some(raw)),
                None,
                "{raw:?} has to fall back to the default, not stop startup"
            );
        }
    }
}
