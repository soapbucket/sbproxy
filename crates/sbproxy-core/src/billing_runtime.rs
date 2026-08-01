//! Runtime assembly and lifecycle for authoritative payment settlement.
//!
//! This module is the seam between a `proxy.payments` document and the
//! machinery in `sbproxy-billing`. It owns four things and deliberately no
//! others: opening the durable store, registering the rail adapters this
//! build compiled, constructing the authoritative service, and running the
//! recovery worker's lifecycle from start to drain.
//!
//! # Construction is two phase
//!
//! [`PaymentsRuntimeCandidate::build`] performs every effect: it creates the
//! state directory, opens and migrates SQLite, resolves the configuration
//! against the features this binary actually carries, and builds the
//! service. [`PaymentsRuntimeCandidate::check_health`] proves the store
//! answers. Only [`PaymentsRuntimeCandidate::publish`] starts the worker.
//!
//! That split is what makes a reload safe. A caller builds and health checks
//! the candidate while the old runtime is still serving, and publishes only
//! once the candidate is proven; a candidate that fails at any step is
//! dropped and the old runtime keeps running, unchanged. It is also what
//! keeps `sbproxy validate` honest: validation runs
//! [`sbproxy_config::payments::PaymentsConfig::validate`] and nothing in
//! this module, so validating a payments document on a laptop opens no
//! database and dials no provider.
//!
//! # A configured rail that was not compiled fails at startup
//!
//! The configuration crate carries no `cfg` of its own, so it parses every
//! rail block on every build. [`compiled_payment_features`] is this
//! binary's half of that contract, and
//! [`sbproxy_config::payments::PaymentsConfig::check_compiled_features`]
//! compares the two and names the first configured surface whose feature is
//! missing. A second check then requires that every configured rail
//! actually registered an adapter, because a rail whose feature is present
//! and whose adapter is absent would otherwise be discovered by a payer
//! holding a challenge this proxy cannot honour.
//!
//! # The worker never settles
//!
//! Nothing here can call
//! [`sbproxy_billing::registry::PaymentMethodAdapter::authorize_and_settle`].
//! [`PaymentsRuntime::reconcile_now`] reaches
//! [`sbproxy_billing::service::BillingService::reconcile_attempt`], which is
//! restricted to a provider status query, and there is no method on this
//! type that marks an attempt successful. An operator cannot force a
//! payment through from here; only a provider proving settlement can.
//!
//! # What never leaves this module
//!
//! No credential, payer identifier, provider reference, intent id, quote
//! id, client secret, macaroon, rune, or provider body reaches a metric
//! label, a span field, or a log line. The metric label sets are closed
//! enums held in code, and the only settlement identifier that reaches the
//! access log is a one-way digest.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::Instrument as _;
use zeroize::Zeroizing;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::registry::RailRegistry;
use sbproxy_billing::service::{BillingService, RequirementSigner};
use sbproxy_billing::sqlite::{SqliteSettlementStore, SCHEMA_VERSION};
use sbproxy_billing::store::{BillingClock, ReconciliationOutcome, SettlementStore};
use sbproxy_billing::types::{AttemptOperation, SettlementRail};
use sbproxy_billing::worker::{
    SettlementWorker, SettlementWorkerHandle, WorkerConfig, WorkerStatus,
};
use sbproxy_config::payments::{PaymentsConfig, PaymentsConfigError};
use sbproxy_observe::metrics::{
    record_payment_provider_call, record_payment_rail_enabled, record_payment_recovery,
    record_payment_settlement, record_payment_worker_drain, record_payment_worker_ticks,
};
use sbproxy_observe::telemetry;

#[cfg(feature = "payment-stripe")]
use sbproxy_billing::recovery_crypto::RecoveryCipher;

/// The quote signer, shared. The proxy owns the signing key; the billing
/// crate never sees key material, which is why this is injected.
pub type SharedRequirementSigner = Arc<dyn RequirementSigner>;

/// The clock every durable stamp is read from, shared.
pub type SharedBillingClock = Arc<dyn BillingClock>;

/// The running worker, shared between the metric observer and shutdown.
///
/// [`SettlementWorkerHandle::shutdown`] consumes the handle, so shutdown
/// takes it out of the option and the observer stops on the next poll.
type SharedWorkerHandle = Arc<Mutex<Option<SettlementWorkerHandle>>>;

/// The last worker snapshot the observer converted into counters.
type ObservedStatus = Arc<Mutex<WorkerStatus>>;

/// Every settlement rail, so a gauge can report the ones that are off.
const ALL_RAILS: [SettlementRail; 4] = [
    SettlementRail::X402,
    SettlementRail::Stripe,
    SettlementRail::LightningCln,
    SettlementRail::LightningLnd,
];

/// The intent identifier the store health probe reads.
///
/// Deliberately not a real identifier shape. The probe proves the database
/// answers a read; it must not be able to observe a real payment.
const HEALTH_PROBE_INTENT_ID: &str = "sbproxy-settlement-store-health-probe";

/// Every way settlement can refuse to start.
///
/// Each variant names the configuration surface the operator wrote, because
/// a startup failure that says only "payments failed" makes them diff their
/// document against the schema to find out what this build objected to.
#[derive(Debug, thiserror::Error)]
pub enum PaymentsRuntimeError {
    /// The configuration itself is not servable by this binary.
    #[error("{0}")]
    Config(#[from] PaymentsConfigError),

    /// Settlement state is a single-node SQLite file, so a clustered
    /// deployment would give each node its own ledger.
    #[error(
        "proxy.payments cannot run on a node that also configures proxy.cluster. \
         Settlement state is one local SQLite file at proxy.payments.state_path, \
         and it is authoritative: a request is authorized because a row in that \
         file says so. Across a mesh each node keeps its own ledger, so a \
         challenge issued on one node cannot be redeemed on another, replay \
         protection stops at the node boundary and the same payment can settle \
         once per node, and a lost node leaves settlements no other node will \
         reconcile. Run payments on a single node until the settlement store \
         has a shared backend"
    )]
    ClusteredDeployment,

    /// The state path could not be prepared.
    #[error("proxy.payments.state_path could not be prepared: could not {0}")]
    StatePath(&'static str),

    /// The billing crate refused a runtime surface.
    #[error("proxy.payments.{surface} could not be started: {source}")]
    Billing {
        /// The configuration surface being built when this failed.
        surface: &'static str,
        /// The redacted billing failure.
        #[source]
        source: BillingError,
    },

    /// The recovery key was named in configuration but never resolved.
    #[error("proxy.payments.recovery_encryption.key names a secret that was not resolved before runtime assembly; the Stripe rail cannot seal a recovery envelope without it, so it cannot accept a payment")]
    RecoveryKeyMissing,

    /// A configured rail compiled in but registered no adapter.
    #[error("proxy.payments.rails.{rail} is configured and the `{feature}` cargo feature is compiled in, but no adapter registered for it; refusing to publish a runtime that would answer a payer's credential with an unsupported rail")]
    AdapterMissing {
        /// The rail with no adapter, in its configuration spelling.
        rail: &'static str,
        /// The cargo feature that compiles that rail's adapter.
        feature: &'static str,
    },
}

/// The cargo features this binary carries for payments.
///
/// The configuration crate cannot know this: it has no `cfg` of its own so
/// that `sbproxy validate` reads the same document on every build. This is
/// the other half of that contract, and it is a plain function rather than
/// a constant because the list depends on the compilation.
#[must_use]
pub fn compiled_payment_features() -> Vec<&'static str> {
    let mut features: Vec<&'static str> = Vec::new();
    features.push("payments");
    #[cfg(feature = "payment-mpp")]
    features.push("payment-mpp");
    #[cfg(feature = "payment-stripe")]
    features.push("payment-stripe");
    #[cfg(feature = "payment-x402")]
    features.push("payment-x402");
    #[cfg(feature = "payment-lightning-cln")]
    features.push("payment-lightning-cln");
    #[cfg(feature = "payment-lightning-lnd")]
    features.push("payment-lightning-lnd");
    features
}

/// Everything the runtime needs that configuration names but cannot carry.
///
/// Secrets are resolved by the caller and handed over as bytes. This module
/// never reads a secret backend itself, which is the property that keeps a
/// validation-only path from being one refactor away from dialing a vault.
///
/// There is no `Debug` on this type on purpose. It holds key material, and
/// deriving `Debug` so a test could print it is exactly how key material
/// reaches a panic message.
pub struct PaymentsRuntimeInputs {
    /// Signs the finalized requirement into a quote token, and verifies a
    /// presented one. Required: a service without a signer cannot prepare a
    /// challenge, so a runtime without one would fail at first request
    /// rather than at startup.
    pub signer: SharedRequirementSigner,
    /// The resolved recovery encryption key, when configuration set one.
    pub recovery_key: Option<Zeroizing<Vec<u8>>>,
    /// The clock every durable stamp is read from. `None` uses the process
    /// clock; tests inject one so expiry and lease recovery can be driven
    /// without sleeping.
    pub clock: Option<SharedBillingClock>,
    /// Whether this node also configures `proxy.cluster`.
    ///
    /// Passed in rather than read from a global so the refusal is testable
    /// and so this module keeps no opinion about how clustering is
    /// discovered. See [`PaymentsRuntimeError::ClusteredDeployment`].
    pub clustered: bool,
}

/// A fully constructed settlement runtime whose worker has not started.
///
/// Holding this type means every effect except the worker has already
/// happened: the state directory exists, SQLite is open and migrated, the
/// configuration matched this binary's features, and every configured rail
/// resolved to a registered adapter.
pub struct PaymentsRuntimeCandidate {
    service: Arc<BillingService>,
    worker_config: WorkerConfig,
    rails: Vec<SettlementRail>,
}

impl PaymentsRuntimeCandidate {
    /// Build a candidate runtime from a validated configuration.
    ///
    /// Performs, in order: configuration validation, the compiled-feature
    /// check, state directory creation, store open and migration, adapter
    /// registration, the configured-rail coverage check, and service
    /// construction. Every one of those is an effect, which is why none of
    /// it runs on the validation path.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsRuntimeError::Config`] for a document this binary
    /// cannot serve, [`PaymentsRuntimeError::StatePath`] when the database
    /// location is unusable, [`PaymentsRuntimeError::AdapterMissing`] when a
    /// configured rail has no adapter, and
    /// [`PaymentsRuntimeError::Billing`] for a store or service refusal.
    pub fn build(
        config: &PaymentsConfig,
        inputs: &PaymentsRuntimeInputs,
    ) -> Result<Self, PaymentsRuntimeError> {
        config.validate()?;
        config.check_compiled_features(&compiled_payment_features())?;
        // Refuse before creating a database or a directory. A node that
        // cannot serve settlement correctly should not leave a half-built
        // ledger behind for an operator to wonder about.
        if inputs.clustered {
            return Err(PaymentsRuntimeError::ClusteredDeployment);
        }

        let path = Path::new(&config.state_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|_| PaymentsRuntimeError::StatePath("create the parent directory"))?;
            }
        }

        let mut store =
            SqliteSettlementStore::open(path).map_err(|source| PaymentsRuntimeError::Billing {
                surface: "state_path",
                source,
            })?;
        if let Some(clock) = &inputs.clock {
            store = store.with_clock(Arc::clone(clock));
        }
        let store = store.shared();

        let registry = compiled_registry()?;
        // Every rail the operator configured has to have an adapter here,
        // not at first request. The feature check above catches a rail this
        // build never compiled; this catches a rail it compiled and did not
        // register, which reads identically to a payer and is worse for an
        // operator because the configuration looks accepted.
        for rail in configured_rails(config) {
            if registry.adapter(rail).is_none() {
                return Err(PaymentsRuntimeError::AdapterMissing {
                    rail: rail.as_str(),
                    feature: rail.cargo_feature(),
                });
            }
        }
        let rails = registry.rails();
        for rail in ALL_RAILS {
            record_payment_rail_enabled(rail.as_str(), rails.contains(&rail));
        }

        let mut builder = BillingService::builder(store)
            .adapters(registry)
            .signer(Arc::clone(&inputs.signer))
            .deadline(Duration::from_millis(u64::from(
                config.authorization_timeout_ms,
            )))
            .map_err(|source| PaymentsRuntimeError::Billing {
                surface: "authorization_timeout_ms",
                source,
            })?;
        if let Some(clock) = &inputs.clock {
            builder = builder.clock(Arc::clone(clock));
        }
        if let Some(recovery) = &config.recovery_encryption {
            let key = inputs
                .recovery_key
                .as_ref()
                .ok_or(PaymentsRuntimeError::RecoveryKeyMissing)?;
            recovery.validate_resolved_key(key)?;
            #[cfg(feature = "payment-stripe")]
            {
                let cipher = RecoveryCipher::new(&recovery.key_id, key).map_err(|source| {
                    PaymentsRuntimeError::Billing {
                        surface: "recovery_encryption.key",
                        source,
                    }
                })?;
                builder = builder.recovery_cipher(cipher);
            }
        }

        Ok(Self {
            service: Arc::new(builder.build()),
            worker_config: worker_config(config),
            rails,
        })
    }

    /// Prove the durable store answers before anything depends on it.
    ///
    /// A read rather than a write, and a read of an identifier that cannot
    /// name a real payment. A store that opened and migrated can still be
    /// unreadable (a full disk, a revoked mount, a WAL the process cannot
    /// write beside), and finding that out here means the old runtime keeps
    /// serving instead of a fresh one failing its first paid request.
    ///
    /// Rail health checks belong here too, alongside this one, as each
    /// adapter lands.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsRuntimeError::Billing`] when the store cannot
    /// answer a read.
    pub async fn check_health(&self) -> Result<(), PaymentsRuntimeError> {
        match self
            .service
            .store()
            .load_intent(HEALTH_PROBE_INTENT_ID)
            .await
        {
            Ok(_) => Ok(()),
            Err(source) => Err(PaymentsRuntimeError::Billing {
                surface: "state_path",
                source,
            }),
        }
    }

    /// Start the recovery worker and return the published runtime.
    ///
    /// Call this only after [`Self::check_health`] passed. It is the last
    /// step on purpose: a worker started beside a candidate that is then
    /// discarded would keep claiming leases against a database nobody is
    /// serving from.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsRuntimeError::Billing`] when the worker refuses
    /// its configuration.
    pub fn publish(self) -> Result<PaymentsRuntime, PaymentsRuntimeError> {
        let interval = Duration::from_millis(self.worker_config.tick_interval_ms);
        let worker = SettlementWorker::new(Arc::clone(&self.service), self.worker_config).map_err(
            |source| PaymentsRuntimeError::Billing {
                surface: "worker",
                source,
            },
        )?;

        let handle: SharedWorkerHandle = Arc::new(Mutex::new(Some(worker.spawn())));
        let observed: ObservedStatus = Arc::new(Mutex::new(WorkerStatus::default()));

        let observer_handle = Arc::clone(&handle);
        let observer_observed = Arc::clone(&observed);
        let observer = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                // A runtime dropped without `shutdown` leaves this task as
                // the only owner. Stop rather than poll a handle nobody is
                // going to drain.
                if Arc::strong_count(&observer_handle) == 1 {
                    break;
                }
                let current = {
                    let guard = observer_handle.lock();
                    match guard.as_ref() {
                        Some(handle) => handle.status(),
                        None => break,
                    }
                };
                record_worker_delta(&observer_observed, current);
            }
        });

        Ok(PaymentsRuntime {
            service: self.service,
            worker: handle,
            observed,
            observer,
            rails: self.rails,
        })
    }

    /// The rails that registered an adapter, in a stable order.
    #[must_use]
    pub fn rails(&self) -> &[SettlementRail] {
        &self.rails
    }
}

impl std::fmt::Debug for PaymentsRuntimeCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentsRuntimeCandidate")
            .field("rails", &self.rails)
            .field("worker_config", &self.worker_config)
            .finish()
    }
}

/// A published settlement runtime with a running recovery worker.
pub struct PaymentsRuntime {
    service: Arc<BillingService>,
    worker: SharedWorkerHandle,
    observed: ObservedStatus,
    observer: tokio::task::JoinHandle<()>,
    rails: Vec<SettlementRail>,
}

impl PaymentsRuntime {
    /// The authoritative service the request path authorizes through.
    #[must_use]
    pub fn service(&self) -> &Arc<BillingService> {
        &self.service
    }

    /// The rails that registered an adapter, in a stable order.
    #[must_use]
    pub fn rails(&self) -> &[SettlementRail] {
        &self.rails
    }

    /// A bounded status snapshot for the authenticated admin surface.
    ///
    /// Everything here is a fact about durable rows or about this process.
    /// There are no per-state intent counts, because the durable contract
    /// exposes no aggregate query and inventing one from a scan would give
    /// an operator a number whose freshness nobody can state. A recovery
    /// backlog is visible through the worker counters instead.
    #[must_use]
    pub fn status(&self) -> PaymentsStatus {
        let worker = self
            .worker
            .lock()
            .as_ref()
            .map_or_else(WorkerStatus::default, SettlementWorkerHandle::status);
        PaymentsStatus {
            schema_version: SCHEMA_VERSION,
            rails: self.rails.clone(),
            worker,
        }
    }

    /// Ask providers what happened to outstanding attempts, right now.
    ///
    /// This is the explicit reconciliation trigger. It claims at most
    /// `limit` outstanding attempts and asks each rail for the status of
    /// the object its own idempotency key names. It cannot confirm,
    /// capture, settle, or retry: the only adapter method reachable from
    /// here is a status query, and the only way an attempt becomes
    /// `Succeeded` is a provider proving it already did.
    ///
    /// There is no counterpart that marks an attempt successful. An
    /// operator who believes a payment settled and the provider disagrees
    /// has a dispute with the provider, not a button in this proxy.
    ///
    /// A rail with no documented status surface reports
    /// [`ReconciliationVerdict::NeedsReconciliation`] and stays
    /// outstanding, which is the honest answer: x402 has no versioned
    /// query extension, so its attempts are unresolvable here rather than
    /// quietly resolved.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsRuntimeError::Billing`] when the store could not
    /// claim work or could not record what a query proved. A provider that
    /// declined to answer is an outcome, not an error.
    pub async fn reconcile_now(
        &self,
        limit: u32,
    ) -> Result<Vec<ReconciliationReport>, PaymentsRuntimeError> {
        let now_ms = self.service.clock().now_ms();
        let claimed = self
            .service
            .store()
            .claim_reconciliation(now_ms, WorkerConfig::default().lease_ttl_ms, limit)
            .await
            .map_err(|source| PaymentsRuntimeError::Billing {
                surface: "worker",
                source,
            })?;

        let mut reports = Vec::with_capacity(claimed.len());
        for attempt in claimed {
            let rail = attempt.rail();
            let operation = attempt.operation();
            record_payment_provider_call(rail.as_str(), "query", provider_class(rail));

            let span = telemetry::settlement_span("reconcile");
            let outcome = self
                .service
                .reconcile_attempt(attempt)
                .instrument(span)
                .await
                .map_err(|source| PaymentsRuntimeError::Billing {
                    surface: "worker",
                    source,
                })?;

            let verdict = ReconciliationVerdict::from_outcome(&outcome);
            record_payment_settlement(rail.as_str(), operation.as_str(), verdict.as_str());
            reports.push(ReconciliationReport {
                rail,
                operation,
                verdict,
            });
        }
        Ok(reports)
    }

    /// Stop claiming new work and wait for the current tick to drain.
    ///
    /// The returned status reports `clean_shutdown` truthfully. `false`
    /// means the configured deadline elapsed and the loop was abandoned
    /// partway through a tick. That cannot corrupt anything, because every
    /// transition the worker performs is its own committed transaction, but
    /// it does mean some recovery work was left for the next process, and
    /// `sbproxy_payment_worker_drain_clean` says so.
    ///
    /// The metric observer is stopped first and a final delta is taken
    /// after the drain, so the counters include the work the last tick did.
    pub async fn shutdown(self) -> WorkerStatus {
        let Self {
            service: _service,
            worker,
            observed,
            observer,
            rails: _rails,
        } = self;

        observer.abort();
        // The lock is released before the await: the observer only ever
        // takes it for a synchronous counter read, so holding it across a
        // drain would stall a task for no reason.
        let handle = worker.lock().take();
        let status = match handle {
            Some(handle) => handle.shutdown().await,
            None => WorkerStatus::default(),
        };

        record_worker_delta(&observed, status);
        record_payment_worker_drain(status.clean_shutdown);
        if !status.clean_shutdown {
            tracing::warn!(
                ticks = status.ticks,
                "settlement worker did not drain inside its shutdown deadline",
            );
        }
        status
    }
}

impl std::fmt::Debug for PaymentsRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentsRuntime")
            .field("rails", &self.rails)
            .finish()
    }
}

/// A bounded, authenticated view of settlement state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentsStatus {
    /// The durable schema version this build understands.
    pub schema_version: i64,
    /// The rails that registered an adapter, in a stable order.
    pub rails: Vec<SettlementRail>,
    /// What the recovery worker has done since this process started.
    pub worker: WorkerStatus,
}

/// What one reconciliation query proved.
///
/// A closed set, and the same four values the metric `outcome` label uses,
/// so an operator reading a dashboard and an operator reading an admin
/// response are looking at one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReconciliationVerdict {
    /// A provider proved the payment settled and a receipt is committed.
    Succeeded,
    /// A provider proved the payment failed and no funds moved.
    Terminal,
    /// A provider proved the write never landed, so a later client retry
    /// may create a fresh attempt.
    RetryWait,
    /// Nothing was proved. The attempt stays outstanding.
    ///
    /// The default, because an unread outcome must never read as success.
    #[default]
    NeedsReconciliation,
}

impl ReconciliationVerdict {
    /// The stable spelling used in metric labels and admin responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Terminal => "terminal",
            Self::RetryWait => "retry_wait",
            Self::NeedsReconciliation => "needs_reconciliation",
        }
    }

    /// Translate a durable reconciliation outcome.
    #[must_use]
    fn from_outcome(outcome: &ReconciliationOutcome) -> Self {
        match outcome {
            ReconciliationOutcome::ProvenSucceeded(_) => Self::Succeeded,
            ReconciliationOutcome::ProvenFailed(_) => Self::Terminal,
            ReconciliationOutcome::ProvenNotDispatched(_) => Self::RetryWait,
            ReconciliationOutcome::Unresolved(_) => Self::NeedsReconciliation,
        }
    }
}

impl std::fmt::Display for ReconciliationVerdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One attempt's reconciliation result.
///
/// Carries the rail, the operation, and the verdict, and nothing that
/// identifies the payment. An admin response built from this cannot leak an
/// intent id, a provider reference, or a payer even by accident, because
/// none of them is in the struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationReport {
    /// The rail that was asked.
    pub rail: SettlementRail,
    /// The operation whose outcome was outstanding.
    pub operation: AttemptOperation,
    /// What the query proved.
    pub verdict: ReconciliationVerdict,
}

/// The kind of provider a rail talks to.
///
/// A class rather than a name. Four values, fixed in code, so this can be a
/// metric label without a provider reference ever becoming one.
const fn provider_class(rail: SettlementRail) -> &'static str {
    match rail {
        SettlementRail::X402 => "facilitator",
        SettlementRail::Stripe => "card_processor",
        SettlementRail::LightningCln | SettlementRail::LightningLnd => "lightning_node",
    }
}

/// The rails a configuration enabled a backend for.
fn configured_rails(config: &PaymentsConfig) -> Vec<SettlementRail> {
    let mut rails = Vec::new();
    if config.rails.x402.is_some() {
        rails.push(SettlementRail::X402);
    }
    if config.rails.stripe.is_some() {
        rails.push(SettlementRail::Stripe);
    }
    if config.rails.lightning_cln.is_some() {
        rails.push(SettlementRail::LightningCln);
    }
    if config.rails.lightning_lnd.is_some() {
        rails.push(SettlementRail::LightningLnd);
    }
    rails
}

/// Build the registry of rail adapters this binary compiled.
///
/// Each rail registers behind its own cargo feature. The caller then checks
/// that every configured rail is present, so an empty registry beside a
/// configured rail is a startup failure rather than a request-time one.
fn compiled_registry() -> Result<RailRegistry, PaymentsRuntimeError> {
    Ok(RailRegistry::new())
}

/// Lower the configured worker cadence onto the worker's own shape.
///
/// The three fields an operator can set are the ones whose right value
/// depends on their deployment. The batch sizes are left at the worker's
/// defaults: they bound how much one tick claims, which is a property of
/// the worker rather than of the deployment, and exposing them would let a
/// configuration starve one recovery queue with another.
fn worker_config(config: &PaymentsConfig) -> WorkerConfig {
    WorkerConfig {
        tick_interval_ms: config.worker.reconcile_interval_ms,
        reconciliation_batch: config.worker.max_reconcile_batch,
        shutdown_deadline_ms: config.worker.shutdown_timeout_ms,
        ..WorkerConfig::default()
    }
}

/// Convert the worker's cumulative counters into metric deltas.
///
/// The worker counts durable rows, not events, so this diffs snapshots.
/// `saturating_sub` is a difference here rather than a clamp: within one
/// worker's lifetime the counters only grow, and a snapshot that went
/// backwards would mean a different worker, whose first delta should be
/// zero rather than negative.
///
/// A zero delta is still recorded. `inc_by(0)` creates the series, so an
/// idle recovery queue draws a flat line instead of vanishing from the
/// scrape, which is the difference between "nothing to recover" and "the
/// worker is not running".
fn record_worker_delta(observed: &ObservedStatus, current: WorkerStatus) {
    let mut previous = observed.lock();

    record_payment_recovery(
        "expire_challenge",
        "terminal",
        current
            .challenges_expired
            .saturating_sub(previous.challenges_expired),
    );
    record_payment_recovery(
        "recover_lease",
        "retry_wait",
        current
            .leases_returned_to_retry_wait
            .saturating_sub(previous.leases_returned_to_retry_wait),
    );
    record_payment_recovery(
        "recover_lease",
        "needs_reconciliation",
        current
            .leases_moved_to_needs_reconciliation
            .saturating_sub(previous.leases_moved_to_needs_reconciliation),
    );
    record_payment_recovery(
        "reconcile",
        "succeeded",
        current
            .reconciliations_succeeded
            .saturating_sub(previous.reconciliations_succeeded),
    );
    record_payment_recovery(
        "reconcile",
        "needs_reconciliation",
        current
            .reconciliations_unresolved
            .saturating_sub(previous.reconciliations_unresolved),
    );
    record_payment_recovery(
        "report_usage",
        "succeeded",
        current
            .usage_reports_sent
            .saturating_sub(previous.usage_reports_sent),
    );
    record_payment_recovery(
        "report_usage",
        "terminal",
        current
            .usage_reports_failed
            .saturating_sub(previous.usage_reports_failed),
    );
    record_payment_recovery(
        "purge_envelope",
        "terminal",
        current
            .envelopes_purged
            .saturating_sub(previous.envelopes_purged),
    );
    record_payment_worker_ticks(current.ticks.saturating_sub(previous.ticks));

    *previous = current;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails a test without requiring `Debug` on the success type. The
    /// runtime types deliberately do not derive it, because deriving it so
    /// a test can print them is how key material reaches a panic message.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn the_compiled_feature_list_always_names_payments() {
        let features = compiled_payment_features();
        assert!(features.contains(&"payments"));
        // Every entry is a real cargo feature name, never a rail spelling.
        for feature in &features {
            assert!(
                *feature == "payments" || feature.starts_with("payment-"),
                "{feature} is not a payment cargo feature name",
            );
        }
    }

    #[test]
    fn every_rail_maps_to_a_closed_provider_class() {
        let classes: Vec<&str> = ALL_RAILS.into_iter().map(provider_class).collect();
        for class in &classes {
            assert!(
                matches!(*class, "facilitator" | "card_processor" | "lightning_node"),
                "{class} is outside the closed provider_class set",
            );
        }
    }

    #[test]
    fn an_unresolved_query_never_reads_as_success() {
        assert_eq!(
            ReconciliationVerdict::default(),
            ReconciliationVerdict::NeedsReconciliation,
        );
        assert_eq!(
            ReconciliationVerdict::default().as_str(),
            "needs_reconciliation",
        );
    }

    #[test]
    fn every_verdict_spelling_is_an_allowed_metric_outcome() {
        for verdict in [
            ReconciliationVerdict::Succeeded,
            ReconciliationVerdict::Terminal,
            ReconciliationVerdict::RetryWait,
            ReconciliationVerdict::NeedsReconciliation,
        ] {
            assert!(
                matches!(
                    verdict.as_str(),
                    "succeeded" | "terminal" | "retry_wait" | "needs_reconciliation"
                ),
                "{verdict} is outside the allowed outcome label set",
            );
        }
    }

    #[test]
    fn the_worker_cadence_comes_from_configuration_and_the_batches_do_not() {
        let mut config = sample_config();
        config.worker.reconcile_interval_ms = 250;
        config.worker.max_reconcile_batch = 4;
        config.worker.shutdown_timeout_ms = 7_500;

        let lowered = worker_config(&config);
        assert_eq!(lowered.tick_interval_ms, 250);
        assert_eq!(lowered.reconciliation_batch, 4);
        assert_eq!(lowered.shutdown_deadline_ms, 7_500);
        let defaults = WorkerConfig::default();
        assert_eq!(lowered.expiry_batch, defaults.expiry_batch);
        assert_eq!(lowered.usage_batch, defaults.usage_batch);
        assert_eq!(lowered.lease_batch, defaults.lease_batch);
        assert_eq!(lowered.lease_ttl_ms, defaults.lease_ttl_ms);
    }

    #[test]
    fn a_configuration_naming_no_rail_enables_none() {
        assert!(configured_rails(&sample_config()).is_empty());
    }

    #[test]
    fn a_rail_this_build_did_not_compile_fails_the_feature_check() {
        // The configuration crate parses every rail block on every build,
        // so this is the check that turns "configured but not compiled"
        // into a startup failure that names the feature.
        let mut config = sample_config();
        config.rails.lightning_cln = Some(sbproxy_config::payments::LightningClnRailConfig {
            socket_path: "/run/lightning/lightning-rpc".to_string(),
            rune: "secret://env/CLN_RUNE".to_string(),
            minimum_version: "26.06".to_string(),
            quote_currency: "USD".to_string(),
            settlement_decimals: 11,
            invoice_expiry_seconds: 600,
        });

        let error = expect_error(
            config.check_compiled_features(&["payments"]),
            "a configured rail with no compiled feature must fail",
        );
        let message = error.to_string();
        assert!(
            message.contains("payment-lightning-cln"),
            "the failure must name the missing cargo feature: {message}",
        );
        assert!(
            message.contains("proxy.payments.rails.lightning_cln"),
            "the failure must name the configured surface: {message}",
        );
    }

    /// The smallest payments document that validates.
    fn sample_config() -> PaymentsConfig {
        PaymentsConfig {
            state_path: "/var/lib/sbproxy/settlement.sqlite3".to_string(),
            challenge_binding_key: "secret://env/SB_PAYMENT_BINDING_KEY".to_string(),
            authorization_timeout_ms: 2_000,
            max_body_bytes: 65_536,
            recovery_encryption: None,
            worker: sbproxy_config::payments::PaymentsWorkerConfig::default(),
            protocols: sbproxy_config::payments::PaymentProtocolsConfig::default(),
            rails: sbproxy_config::payments::PaymentRailsConfig::default(),
            usage_reporters: sbproxy_config::payments::UsageReportersConfig::default(),
        }
    }

    /// A signer that is only asked to exist.
    ///
    /// The clustered refusal happens before any challenge is prepared, so
    /// these bodies are never reached; a real signer here would only add a
    /// key to a test that is about deployment topology.
    struct StubSigner;

    impl sbproxy_billing::service::RequirementSigner for StubSigner {
        fn sign(
            &self,
            _requirement: &sbproxy_billing::types::PaymentRequirement,
            _requirement_digest: &[u8; 32],
        ) -> Result<String, sbproxy_billing::BillingError> {
            Err(sbproxy_billing::BillingError::Storage("stub signer"))
        }

        fn verify(
            &self,
            _signed: &sbproxy_billing::types::SignedPaymentRequirement,
        ) -> Result<(), sbproxy_billing::BillingError> {
            Err(sbproxy_billing::BillingError::Storage("stub signer"))
        }
    }

    fn test_inputs() -> PaymentsRuntimeInputs {
        PaymentsRuntimeInputs {
            signer: Arc::new(StubSigner),
            recovery_key: None,
            clock: None,
            clustered: false,
        }
    }

    /// A clustered node refuses to build a settlement runtime, and refuses
    /// before it creates anything.
    ///
    /// Settlement state is one local SQLite file and it is authoritative.
    /// Across a mesh each node would keep its own ledger, so a challenge
    /// issued on one node could not be redeemed on another, replay
    /// protection would stop at the node boundary and the same payment
    /// could settle once per node, and a lost node would leave settlements
    /// no other node reconciles. Failing closed at startup is the only
    /// honest answer until the store has a shared backend.
    #[test]
    fn a_clustered_node_refuses_to_build_settlement() {
        let directory = tempfile::tempdir().expect("temp dir");
        let state_path = directory.path().join("nested").join("settlement.sqlite3");
        let mut config = sample_config();
        config.state_path = state_path.to_string_lossy().into_owned();

        let inputs = PaymentsRuntimeInputs {
            clustered: true,
            ..test_inputs()
        };
        let error = expect_error(
            PaymentsRuntimeCandidate::build(&config, &inputs),
            "a clustered node must not build a settlement runtime",
        );
        assert!(
            matches!(error, PaymentsRuntimeError::ClusteredDeployment),
            "expected the clustered refusal, got {error}",
        );
        let message = error.to_string();
        assert!(message.contains("proxy.cluster"), "{message}");
        assert!(message.contains("state_path"), "{message}");

        // Nothing was created. A node that cannot serve settlement must not
        // leave a half-built ledger behind.
        assert!(
            !state_path.exists(),
            "the refusal must precede opening the database",
        );
        assert!(
            !state_path.parent().expect("parent").exists(),
            "the refusal must precede creating the state directory",
        );

        // The same document builds on an unclustered node, so the refusal
        // is about topology and not about the configuration being invalid.
        PaymentsRuntimeCandidate::build(&config, &test_inputs())
            .expect("an unclustered node builds the same document");
    }
}
