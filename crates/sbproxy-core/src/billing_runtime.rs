//! Runtime assembly and lifecycle for authoritative payment settlement.
//!
//! This module is the seam between a `proxy.payments` document and the
//! machinery in `sbproxy-billing`. It owns five things and deliberately no
//! others: opening the durable store, registering the rail adapters this
//! build compiled, constructing the authoritative service, attaching the
//! request path's single-serve nonce ledger to that same store, and running
//! the recovery worker's lifecycle from start to drain.
//!
//! # The nonce ledger is not a choice
//!
//! Single serve is durable, and no caller picks the backend. A caller fills
//! in a [`SettlementGateSeamPlan`], which has no ledger field, and
//! [`PaymentsRuntimeCandidate::build`] turns it into a
//! [`SettlementGateSeam`] carrying a ledger over the store it has just
//! opened. WOR-2317 shipped the other shape: an in-memory set went into the
//! production seam, and because a burn lived only in that process, a restart
//! let an already-settled quote token serve one more response per restart.
//! Nothing downstream could see the difference, which is why the fix is
//! structural rather than a swapped constructor.
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
use sbproxy_billing::store::{BillingClock, ReconciliationOutcome, SharedSettlementStore};
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

use crate::settlement_gate::{OP_CHALLENGE, OP_REDEEM, OUTCOME_PREPARED, OUTCOME_SUCCEEDED};

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

/// The description Core Lightning invoices are created with.
///
/// Fixed rather than configurable, and deliberately says nothing about the
/// request. An invoice description is visible to the payer and to anyone who
/// can read the node's invoice list, so a route, a tenant, or a quote in this
/// string would put request metadata somewhere the proxy does not control.
#[cfg(all(feature = "payment-lightning-cln", unix))]
const CLN_INVOICE_DESCRIPTION: &str = "SBProxy metered request";

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

    /// The Stripe key was named in configuration but never resolved.
    #[error("proxy.payments.rails.stripe.api_key names a secret that resolved to nothing usable before runtime assembly; the Stripe rail cannot authenticate a PaymentIntent call without it, so it cannot accept a payment")]
    StripeKeyMissing,

    /// Usage reporting was configured without the rail it reports through.
    #[error("proxy.payments.usage_reporters.stripe_meter is configured but proxy.payments.rails.stripe is not; the reporter authenticates with that rail's api_key and api_version, so there is no account to report usage against. Configure the stripe rail, or remove the reporter")]
    MeterWithoutStripeRail,

    /// A configured rail compiled in but registered no adapter.
    #[error("proxy.payments.rails.{rail} is configured and the `{feature}` cargo feature is compiled in, but no adapter registered for it; refusing to publish a runtime that would answer a payer's credential with an unsupported rail")]
    AdapterMissing {
        /// The rail with no adapter, in its configuration spelling.
        rail: &'static str,
        /// The cargo feature that compiles that rail's adapter.
        feature: &'static str,
    },

    /// A secret reference in the document could not be resolved.
    ///
    /// Carries the field, never the reference and never the value. A
    /// startup error that echoed the reference would put the vault path in
    /// a log; one that echoed the value would put the credential there.
    #[error("proxy.payments.{field} names a secret that could not be resolved; settlement will not start with a credential it cannot read")]
    SecretUnresolved {
        /// Dotted path of the field whose secret failed, relative to
        /// `proxy.payments`.
        field: &'static str,
    },
}

/// The key id settlement quote tokens are signed under.
///
/// Distinct from any `ai_crawl_control.quote_token.key_id` an operator
/// configures, so the two keyspaces cannot be confused by a verifier holding
/// both.
const QUOTE_KEY_ID: &str = "sbproxy-payments";

/// The `iss` claim used when no Payment Auth realm is configured.
const DEFAULT_QUOTE_ISSUER: &str = "sbproxy-payments";

/// Salt for the quote signing key derivation.
///
/// Fixed and source-visible. HKDF's salt is not required to be secret; the
/// input keying material is, and that is the operator's configured
/// `challenge_binding_key`.
const QUOTE_SEED_SALT: &[u8] = b"sbproxy-payments-v1";

/// How long a settlement quote token stays valid by default.
///
/// The requirement carries its own expiry and the signer stamps `exp` from
/// it, so this only bounds the signer's own default for a caller that does
/// not supply one. Settlement always supplies one.
const QUOTE_DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Build, health check, and publish a settlement runtime.
///
/// The whole two-phase construction in one call, for the boot and reload
/// paths that want a running runtime rather than a candidate. Secrets are
/// resolved here, once, and handed to the assembly as bytes; nothing below
/// this function reads a secret backend.
///
/// The old runtime, if any, is the caller's to drain. This function either
/// returns a fully proven runtime or fails without leaving one behind, which
/// is what lets a reload keep serving on the previous generation.
///
/// # Errors
///
/// Returns [`PaymentsRuntimeError::SecretUnresolved`] when a configured
/// secret cannot be read, and whatever
/// [`PaymentsRuntimeCandidate::build`], [`PaymentsRuntimeCandidate::check_health`],
/// and [`PaymentsRuntimeCandidate::publish`] return.
pub async fn build_payments_runtime(
    config: &PaymentsConfig,
    clustered: bool,
) -> Result<PaymentsRuntime, PaymentsRuntimeError> {
    build_payments_runtime_with_observer(config, clustered, None).await
}

/// Build a settlement runtime with one compiled pipeline's payment observer.
///
/// The observer is captured by the immutable billing service generation, so
/// reload cannot route a payment event through hooks from another pipeline.
///
/// # Errors
///
/// Returns the same failures as [`build_payments_runtime`].
pub async fn build_payments_runtime_with_observer(
    config: &PaymentsConfig,
    clustered: bool,
    payment_observer: Option<Arc<dyn sbproxy_billing::PaymentLifecycleObserver>>,
) -> Result<PaymentsRuntime, PaymentsRuntimeError> {
    // One configured secret, two derived keys. `challenge_binding_key` is
    // the operator's single settlement secret; the Payment Auth challenge id
    // is a MAC under it and quote tokens are signed under a key derived from
    // it here. The purpose enum is what keeps those two keyspaces apart, so
    // a weakness found in one primitive cannot be carried into the other.
    let binding_key = resolve_secret(&config.challenge_binding_key, "challenge_binding_key")?;
    let seed_bytes = Zeroizing::new(sbproxy_security::hkdf_derive_purpose(
        binding_key.as_bytes(),
        QUOTE_SEED_SALT,
        sbproxy_security::HkdfPurpose::Signing,
        32,
    ));
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let quote_signer = sbproxy_modules::policy::quote_token::QuoteTokenSigner::from_seed_bytes(
        &seed,
        QUOTE_KEY_ID,
        quote_issuer(config),
        QUOTE_DEFAULT_TTL,
    );
    let verifying = quote_signer.verifying_key();
    // The verifier's ledger is the refusing one, not the durable one. Its
    // constructor requires a store because its legacy `verify` consumes, and
    // the settlement path deliberately never calls that: it authenticates
    // with `verify_authenticity` and lets the durable intent and proof
    // transaction own single use, because burning a quote while parsing a
    // signature leaves an interrupted payment unresumable. Handing it a
    // ledger that refuses makes that a property of the value rather than of
    // today's call graph.
    let verifier = sbproxy_modules::policy::quote_token::QuoteTokenVerifier::single_key(
        QUOTE_KEY_ID,
        verifying,
        Arc::new(crate::payment_nonce::RefusingNonceStore::new()),
    );
    let requirement_signer = Arc::new(crate::payment_signer::QuoteRequirementSigner::new(
        quote_signer,
        verifier,
    ));

    // The Payment HTTP Authentication binder shares the operator's one
    // settlement secret with the quote key derivation above; the two
    // keyspaces stay apart because the quote key is an HKDF output and the
    // binder MACs under the raw material with its own fixed slot layout.
    #[cfg(feature = "payment-mpp")]
    let challenge_binder = match &config.protocols.payment_auth {
        Some(protocol) => Some(Arc::new(
            sbproxy_billing::payment_auth::ChallengeBinder::new(
                &protocol.realm,
                binding_key.as_bytes(),
            )
            .map_err(|source| PaymentsRuntimeError::Billing {
                surface: "protocols.payment_auth.realm",
                source: source.into(),
            })?,
        )),
        None => None,
    };

    // No nonce ledger here. `PaymentsRuntimeCandidate::build` attaches one
    // backed by the settlement store it opens, which is the only way the
    // burn and the settlement can be guaranteed to land in the same file.
    let gate = SettlementGateSeamPlan {
        quote_signer: Arc::clone(&requirement_signer),
        #[cfg(feature = "payment-mpp")]
        challenge_binder,
        failure_mode: config.failure_mode,
    };

    let inputs = PaymentsRuntimeInputs {
        signer: requirement_signer,
        gate: Some(gate),
        payment_observer,
        recovery_key: match &config.recovery_encryption {
            Some(recovery) => Some(Zeroizing::new(
                resolve_secret(&recovery.key, "recovery_encryption.key")?
                    .as_bytes()
                    .to_vec(),
            )),
            None => None,
        },
        stripe_api_key: match &config.rails.stripe {
            Some(stripe) => Some(resolve_secret(&stripe.api_key, "rails.stripe.api_key")?),
            None => None,
        },
        cln_rune: match &config.rails.lightning_cln {
            Some(cln) => Some(resolve_secret(&cln.rune, "rails.lightning_cln.rune")?),
            None => None,
        },
        clock: None,
        clustered,
    };

    let candidate = PaymentsRuntimeCandidate::build(config, &inputs)?;
    candidate.check_health().await?;
    candidate.publish()
}

/// A dedicated, process-lifetime runtime for the settlement worker.
///
/// Independent of the Pingora service runtimes, mirroring `alerting`,
/// `key_plane`, and `cluster`. The recovery worker has to outlive whatever
/// task started it: a worker spawned onto a temporary runtime would stop the
/// moment that runtime dropped, and the first thing an operator would notice
/// is that ambiguous payments stopped reconciling, silently, with the proxy
/// still serving.
fn payments_worker_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("sbproxy-payments")
            .enable_all()
            .build()
            .expect("build payments runtime")
    })
}

/// Build and publish a settlement runtime from the synchronous boot path.
///
/// Blocks the caller until the store is open, migrated, proven readable, and
/// the recovery worker is running, then hands back the published runtime.
/// Blocking is the point: a proxy that cannot open its settlement ledger must
/// not reach the point of accepting a paid request, and boot is where an
/// operator can still see why.
///
/// # Errors
///
/// Returns whatever [`build_payments_runtime`] returns.
pub fn install(
    config: &PaymentsConfig,
    clustered: bool,
) -> Result<Arc<PaymentsRuntime>, PaymentsRuntimeError> {
    payments_worker_runtime()
        .block_on(build_payments_runtime(config, clustered))
        .map(Arc::new)
}

/// Build and publish settlement with one compiled pipeline's payment hooks.
///
/// The observer and its terminal drain are created on the process-lifetime
/// payment runtime. This keeps the drain alive after the synchronous boot
/// caller returns and avoids depending on a caller-owned Tokio runtime.
///
/// # Errors
///
/// Returns whatever [`build_payments_runtime_with_observer`] returns.
pub fn install_with_payment_dispatcher(
    config: &PaymentsConfig,
    clustered: bool,
    dispatcher: Arc<dyn crate::payment_extensions::PaymentEventDispatcher>,
) -> Result<Arc<PaymentsRuntime>, PaymentsRuntimeError> {
    payments_worker_runtime()
        .block_on(async {
            let observer = crate::payment_extensions::PaymentExtensionObserver::new(dispatcher);
            build_payments_runtime_with_observer(config, clustered, Some(observer)).await
        })
        .map(Arc::new)
}

/// The `iss` claim settlement quotes carry.
///
/// The Payment Auth realm when one is configured, because that is the
/// protection space the operator already published to payers, and a fixed
/// fallback otherwise. It is only ever read back by this proxy's own
/// verifier, so it needs to be stable rather than resolvable.
fn quote_issuer(config: &PaymentsConfig) -> &str {
    config
        .protocols
        .payment_auth
        .as_ref()
        .map_or(DEFAULT_QUOTE_ISSUER, |protocol| protocol.realm.as_str())
}

/// Resolve one secret reference into a zeroizing buffer.
///
/// The underlying error is dropped on purpose. It names the reference, and a
/// reference is a vault path; the field name is enough for an operator to
/// find the line they wrote.
fn resolve_secret(
    reference: &str,
    field: &'static str,
) -> Result<Zeroizing<String>, PaymentsRuntimeError> {
    crate::config_source::resolve_secret_reference(reference, field)
        .map(Zeroizing::new)
        .map_err(|_| PaymentsRuntimeError::SecretUnresolved { field })
}

/// The cargo features this binary carries for payments.
///
/// The configuration crate cannot know this: it has no `cfg` of its own so
/// that `sbproxy validate` reads the same document on every build. This is
/// the other half of that contract, and it is a plain function rather than
/// a constant because the list depends on the compilation.
// `vec![]` cannot express this: which entries exist is decided by `cfg`, and
// an attribute on a macro element is not the same thing as an attribute on a
// statement.
#[allow(clippy::vec_init_then_push)]
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

/// Everything the gate needs that does not depend on the durable store.
///
/// This exists so the nonce ledger cannot be chosen by whoever assembles the
/// runtime. The seam is built in two steps: the caller resolves secrets and
/// fills in this plan, and [`PaymentsRuntimeCandidate::build`] completes it
/// into a [`SettlementGateSeam`] by attaching the ledger backed by the
/// settlement store it has just opened.
///
/// The ordering is the point. The store cannot be opened before secrets are
/// resolved, and the ledger cannot exist before the store, so a single-step
/// seam would have had to carry a placeholder ledger past the store open. A
/// placeholder is exactly how WOR-2317 shipped: an in-memory set went into
/// the production seam, and nothing downstream could tell it apart from a
/// durable one. There is now no field to place it in.
#[derive(Clone)]
pub struct SettlementGateSeamPlan {
    /// Parses and authenticates presented quote tokens. Held concretely so
    /// the gate can read claims; the service only ever sees the
    /// [`RequirementSigner`] trait.
    pub quote_signer: Arc<crate::payment_signer::QuoteRequirementSigner>,
    /// Issues and verifies `WWW-Authenticate: Payment` challenges. `None`
    /// when `proxy.payments.protocols.payment_auth` is absent, in which
    /// case the gate never advertises the `mpp` rail.
    #[cfg(feature = "payment-mpp")]
    pub challenge_binder: Option<Arc<sbproxy_billing::payment_auth::ChallengeBinder>>,
    /// What the gate does when settlement infrastructure cannot answer.
    /// Payment refusals are never subject to it.
    pub failure_mode: sbproxy_config::types::FailureMode,
}

impl SettlementGateSeamPlan {
    /// Completes the plan with the ledger the opened store backs.
    fn into_seam(
        self,
        nonce_store: Arc<dyn sbproxy_modules::policy::quote_token::NonceStore>,
    ) -> SettlementGateSeam {
        SettlementGateSeam {
            quote_signer: self.quote_signer,
            nonce_store,
            #[cfg(feature = "payment-mpp")]
            challenge_binder: self.challenge_binder,
            failure_mode: self.failure_mode,
        }
    }
}

impl std::fmt::Debug for SettlementGateSeamPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("SettlementGateSeamPlan");
        debug.field("failure_mode", &self.failure_mode);
        #[cfg(feature = "payment-mpp")]
        debug.field("challenge_binder", &self.challenge_binder.is_some());
        debug.finish()
    }
}

/// Request-path material the settlement origin gate reads beside the service.
///
/// Built in [`PaymentsRuntimeCandidate::build`] from the same configuration
/// generation as the service, so the signer that parses a presented quote
/// token, the nonce ledger that makes one settled challenge serve exactly
/// once, the Payment HTTP Authentication binder, and the operator's
/// infrastructure-failure posture can never disagree with the store that
/// issued the challenge.
#[derive(Clone)]
pub struct SettlementGateSeam {
    /// Parses and authenticates presented quote tokens. Held concretely so
    /// the gate can read claims; the service only ever sees the
    /// [`RequirementSigner`] trait.
    pub quote_signer: Arc<crate::payment_signer::QuoteRequirementSigner>,
    /// Single-serve ledger for settled challenges. The durable store keeps
    /// a settled intent redeemable so an interrupted payment can resume;
    /// this is the request-path consumption on top, burned only after a
    /// committed receipt authorized a response.
    ///
    /// On the production path this is
    /// [`crate::payment_nonce::DurableNonceStore`], writing into the same
    /// SQLite file as the settlement it authorizes, and there is no
    /// configuration surface that can select anything else. Tests construct
    /// this struct directly and may put a process-local ledger here.
    pub nonce_store: Arc<dyn sbproxy_modules::policy::quote_token::NonceStore>,
    /// Issues and verifies `WWW-Authenticate: Payment` challenges. `None`
    /// when `proxy.payments.protocols.payment_auth` is absent, in which
    /// case the gate never advertises the `mpp` rail.
    #[cfg(feature = "payment-mpp")]
    pub challenge_binder: Option<Arc<sbproxy_billing::payment_auth::ChallengeBinder>>,
    /// What the gate does when settlement infrastructure cannot answer.
    /// Payment refusals are never subject to it.
    pub failure_mode: sbproxy_config::types::FailureMode,
}

impl std::fmt::Debug for SettlementGateSeam {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("SettlementGateSeam");
        debug.field("failure_mode", &self.failure_mode);
        #[cfg(feature = "payment-mpp")]
        debug.field("challenge_binder", &self.challenge_binder.is_some());
        debug.finish()
    }
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
    /// Request-path gate material, when this runtime will serve requests.
    ///
    /// A plan rather than a finished seam: the nonce ledger is attached by
    /// [`PaymentsRuntimeCandidate::build`] from the store it opens, so no
    /// caller can supply one.
    ///
    /// `None` is a valid assembly and simply leaves the request path on the
    /// legacy ledger behaviour: the admin and worker surfaces never need
    /// it, and tests that exercise topology or lifecycle rules build
    /// candidates without a real signer.
    pub gate: Option<SettlementGateSeamPlan>,
    /// Generation-scoped payment extension observer, when the compiled
    /// pipeline carries payment hooks.
    pub payment_observer: Option<Arc<dyn sbproxy_billing::PaymentLifecycleObserver>>,
    /// The resolved recovery encryption key, when configuration set one.
    pub recovery_key: Option<Zeroizing<Vec<u8>>>,
    /// The resolved Stripe secret key, when a Stripe rail is configured.
    ///
    /// Required by both Stripe surfaces, which is why it is one value: the
    /// settlement rail and the usage reporter address the same account, and
    /// letting them carry different keys would let usage be billed to one
    /// account while payment settles on another.
    pub stripe_api_key: Option<Zeroizing<String>>,
    /// The resolved Core Lightning rune, when one is configured.
    ///
    /// Optional even when the CLN rail is: a node without rune
    /// authentication accepts an unadorned request, and the settler puts the
    /// rune in the JSON-RPC object only when it has one.
    pub cln_rune: Option<Zeroizing<String>>,
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
    gate: Option<SettlementGateSeam>,
    usage_bridge: Option<Arc<crate::usage_bridge::UsageBridgeRuntime>>,
}

impl PaymentsRuntimeCandidate {
    /// Build a candidate runtime from a validated configuration.
    ///
    /// Performs, in order: configuration validation, the compiled-feature
    /// check, state directory creation, store open and migration, nonce
    /// ledger attachment, adapter registration, the configured-rail coverage
    /// check, and service construction. Every one of those is an effect,
    /// which is why none of it runs on the validation path.
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
        // One handle, held twice. The service reaches the store through the
        // trait object and the nonce ledger reaches the same open connection
        // directly, so a nonce burn and the settlement it records cannot end
        // up in two files, and both read the same injected clock.
        let opened = Arc::new(store);
        let nonce_store: Arc<dyn sbproxy_modules::policy::quote_token::NonceStore> = Arc::new(
            crate::payment_nonce::DurableNonceStore::new(Arc::clone(&opened)),
        );
        let store: SharedSettlementStore = opened;

        let registry = compiled_registry(config, inputs)?;
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
        seed_settlement_series(&rails);

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
        if let Some(observer) = &inputs.payment_observer {
            builder = builder.payment_observer(Arc::clone(observer));
        }
        if let Some(recovery) = &config.recovery_encryption {
            let key = inputs
                .recovery_key
                .as_ref()
                .ok_or(PaymentsRuntimeError::RecoveryKeyMissing)?;
            recovery.validate_resolved_key(key)?;
            #[cfg(feature = "payment-stripe")]
            {
                builder = builder.recovery_cipher(recovery_cipher(config, inputs)?);
            }
        }

        Ok(Self {
            service: Arc::new(builder.build()),
            worker_config: worker_config(config),
            rails,
            gate: inputs.gate.clone().map(|plan| plan.into_seam(nonce_store)),
            // WOR-2169. Built here, from the same document generation as
            // the service and the reporter registry, so the meter event a
            // request queues and the reporter that drains it can never come
            // from two different configurations.
            usage_bridge: crate::usage_bridge::UsageBridgeRuntime::from_config(config),
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
            gate: self.gate,
            usage_bridge: self.usage_bridge,
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
    gate: Option<SettlementGateSeam>,
    usage_bridge: Option<Arc<crate::usage_bridge::UsageBridgeRuntime>>,
}

impl PaymentsRuntime {
    /// The authoritative service the request path authorizes through.
    #[must_use]
    pub fn service(&self) -> &Arc<BillingService> {
        &self.service
    }

    /// The producer that turns served requests into queued billable units.
    ///
    /// `None` when `proxy.payments.usage_reporters` is empty, which is what
    /// makes "no reporter configured does no billing work" a property of
    /// the shape rather than of a check on the request path. See
    /// [`crate::usage_bridge`].
    #[must_use]
    pub fn usage_bridge(&self) -> Option<&Arc<crate::usage_bridge::UsageBridgeRuntime>> {
        self.usage_bridge.as_ref()
    }

    /// Request-path gate material, when this runtime was built for serving.
    ///
    /// `None` means the runtime was assembled without a gate (tests,
    /// hand-built candidates) and the request path keeps its legacy
    /// challenge behaviour.
    #[must_use]
    pub fn gate(&self) -> Option<&SettlementGateSeam> {
        self.gate.as_ref()
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
        reconcile_with(Arc::clone(&self.service), limit).await
    }

    /// Run a reconciliation sweep from a synchronous caller.
    ///
    /// The admin dispatch is synchronous and may itself be running inside a
    /// tokio runtime, so this spawns onto the settlement runtime and waits on
    /// a plain channel rather than calling `block_on`, which panics when
    /// entered from within another runtime.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::reconcile_now`] returns, and
    /// [`PaymentsRuntimeError::Billing`] if the sweep task disappeared
    /// without answering.
    pub fn reconcile_now_blocking(
        &self,
        limit: u32,
    ) -> Result<Vec<ReconciliationReport>, PaymentsRuntimeError> {
        let service = Arc::clone(&self.service);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        payments_worker_runtime().spawn(async move {
            let _ = sender.send(reconcile_with(service, limit).await);
        });
        receiver
            .recv()
            .unwrap_or(Err(PaymentsRuntimeError::Billing {
                surface: "worker",
                source: BillingError::StoreUnavailable,
            }))
    }
}

/// The reconciliation sweep, over a service handle rather than a runtime.
///
/// Separated so both the async and the synchronous entry points run exactly
/// the same code: an operator triggering a sweep from the admin surface must
/// not get different behaviour from the one the worker performs.
async fn reconcile_with(
    service: Arc<BillingService>,
    limit: u32,
) -> Result<Vec<ReconciliationReport>, PaymentsRuntimeError> {
    {
        let now_ms = service.clock().now_ms();
        let claimed = service
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
            let outcome = service
                .reconcile_attempt(attempt)
                .instrument(span)
                .await
                .map_err(|source| PaymentsRuntimeError::Billing {
                    surface: "worker",
                    source,
                })?;

            let verdict = ReconciliationVerdict::from_outcome(&outcome);
            record_payment_settlement(rail.as_str(), operation.as_str(), verdict.as_str(), 1);
            reports.push(ReconciliationReport {
                rail,
                operation,
                verdict,
            });
        }
        Ok(reports)
    }
}

impl PaymentsRuntime {
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
            gate: _gate,
            usage_bridge: _usage_bridge,
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
/// Each rail registers behind its own cargo feature and only when the
/// operator configured it. The caller then checks that every configured rail
/// is present, so a rail this build compiled but could not construct is a
/// startup failure rather than a request-time one.
///
/// # Every bound comes from the document
///
/// Nothing here invents a timeout, a breaker threshold, a capture mode, or a
/// mode switch. The values an operator wrote are lowered onto each adapter's
/// own configuration struct, and where an adapter has a bound the
/// configuration crate also validates, the adapter re-checks it: the
/// constructors are the runtime backstop for the loader, not a second source
/// of truth.
///
/// `direct_payment_intent.enabled` in particular is threaded through to
/// [`StripeSettlerConfig`] rather than defaulted. Direct mode charges a card
/// the proxy holds no credential for, so it has to arrive because an operator
/// asked for it and never because a struct filled in a field.
///
/// # LND is compiled but has no transport
///
/// The LND settler and its contract tests are complete, but the generated
/// gRPC client is a separate slice, so there is nothing to give
/// [`LndSettler`](sbproxy_billing::lightning::lnd::LndSettler) to talk
/// through. A build that compiles `payment-lightning-lnd` and configures
/// `proxy.payments.rails.lightning_lnd` therefore registers no adapter and
/// fails startup through [`PaymentsRuntimeError::AdapterMissing`], naming the
/// rail. Failing there is the point: the alternative is a proxy that
/// advertises a Lightning challenge it has no way to settle.
// A build with `payments` and no rail feature reads neither argument. That
// is a real configuration: the store, the service, and the recovery worker
// all work, and every configured rail then fails the coverage check by name.
#[allow(unused_variables, unused_mut)]
fn compiled_registry(
    config: &PaymentsConfig,
    inputs: &PaymentsRuntimeInputs,
) -> Result<RailRegistry, PaymentsRuntimeError> {
    let mut registry = RailRegistry::new();

    #[cfg(feature = "payment-x402")]
    if let Some(rail) = &config.rails.x402 {
        registry
            .register_adapter(build_x402_adapter(rail, config.authorization_timeout_ms)?)
            .map_err(billing_error("rails.x402"))?;
    }

    #[cfg(feature = "payment-stripe")]
    if let Some(rail) = &config.rails.stripe {
        registry
            .register_adapter(build_stripe_adapter(rail, config, inputs)?)
            .map_err(billing_error("rails.stripe"))?;
    }

    #[cfg(all(feature = "payment-lightning-cln", unix))]
    if let Some(rail) = &config.rails.lightning_cln {
        registry
            .register_adapter(build_cln_adapter(rail, config, inputs)?)
            .map_err(billing_error("rails.lightning_cln"))?;
    }

    #[cfg(feature = "payment-stripe")]
    if let Some(reporter) = &config.usage_reporters.stripe_meter {
        let stripe = config
            .rails
            .stripe
            .as_ref()
            .ok_or(PaymentsRuntimeError::MeterWithoutStripeRail)?;
        registry
            .register_reporter(build_stripe_meter_reporter(
                reporter, stripe, config, inputs,
            )?)
            .map_err(billing_error("usage_reporters.stripe_meter"))?;
    }

    Ok(registry)
}

/// Curries a configuration surface onto the billing failure wrapper.
///
/// Every construction below names the block an operator would go and edit,
/// because a startup failure that says only "payments failed" makes them diff
/// their whole document to find out what this build objected to.
#[cfg(any(
    feature = "payment-x402",
    feature = "payment-stripe",
    all(feature = "payment-lightning-cln", unix)
))]
fn billing_error(surface: &'static str) -> impl Fn(BillingError) -> PaymentsRuntimeError {
    move |source| PaymentsRuntimeError::Billing { surface, source }
}

/// Build the x402 rail, one settler per configured facilitator.
///
/// The facilitators are an ordered list and each keeps its own breaker, so
/// one unhealthy facilitator cannot open the breaker guarding another. Which
/// one a payment uses was decided when its requirement was signed; this only
/// makes each of them reachable.
#[cfg(feature = "payment-x402")]
fn build_x402_adapter(
    rail: &sbproxy_config::payments::X402RailConfig,
    authorization_timeout_ms: u32,
) -> Result<Arc<dyn sbproxy_billing::registry::PaymentMethodAdapter>, PaymentsRuntimeError> {
    use sbproxy_billing::transport::HttpFacilitatorTransport;
    use sbproxy_billing::x402::{FacilitatorBreaker, FacilitatorEndpoints, X402ExactSettler};
    use sbproxy_billing::x402_adapter::X402Adapter;

    let surface = billing_error("rails.x402");
    // One client, cloned per facilitator, so the connection pool is shared
    // while the breakers stay independent.
    let transport = HttpFacilitatorTransport::new().map_err(&surface)?;

    let mut settlers = Vec::with_capacity(rail.facilitators.len());
    for facilitator in &rail.facilitators {
        let endpoints =
            FacilitatorEndpoints::from_api_root(&facilitator.facilitator_url).map_err(|error| {
                PaymentsRuntimeError::Billing {
                    surface: "rails.x402.facilitators",
                    source: error.into(),
                }
            })?;
        let breaker = FacilitatorBreaker::new(
            rail.breaker.failure_threshold,
            rail.breaker.open_ms,
            rail.breaker.half_open_max,
        )
        .map_err(|error| PaymentsRuntimeError::Billing {
            surface: "rails.x402.breaker",
            source: error.into(),
        })?;
        let settler = X402ExactSettler::new(
            endpoints,
            transport.clone(),
            Arc::new(breaker),
            u64::from(rail.verify_timeout_ms),
            u64::from(rail.settle_timeout_ms),
            u64::from(authorization_timeout_ms),
        )
        .map_err(|error| PaymentsRuntimeError::Billing {
            surface: "rails.x402",
            source: error.into(),
        })?;
        settlers.push(Arc::new(settler));
    }

    let adapter = X402Adapter::new(settlers).map_err(|error| PaymentsRuntimeError::Billing {
        surface: "rails.x402.facilitators",
        source: error.into(),
    })?;
    Ok(Arc::new(adapter))
}

/// Build the Stripe settlement rail.
///
/// The recovery cipher is required rather than optional here. A Stripe create
/// that is dispatched and then lost is recoverable only by replaying its
/// exact sealed bytes under the same idempotency key, so a Stripe rail
/// without a cipher would have one unrecoverable failure mode by
/// construction. The configuration crate already requires the block; this
/// turns the resolved key into the cipher that uses it.
#[cfg(feature = "payment-stripe")]
fn build_stripe_adapter(
    rail: &sbproxy_config::payments::StripeRailConfig,
    config: &PaymentsConfig,
    inputs: &PaymentsRuntimeInputs,
) -> Result<Arc<dyn sbproxy_billing::registry::PaymentMethodAdapter>, PaymentsRuntimeError> {
    use sbproxy_billing::stripe_payment::{
        StripeEndpoints, StripePaymentIntentSettler, StripeSettlerConfig, STRIPE_API_ROOT,
    };
    use sbproxy_billing::transport::HttpStripeTransport;

    let surface = billing_error("rails.stripe");
    let transport = HttpStripeTransport::new(stripe_api_key(inputs)?).map_err(&surface)?;
    let endpoints = StripeEndpoints::from_api_root(STRIPE_API_ROOT).map_err(|error| {
        PaymentsRuntimeError::Billing {
            surface: "rails.stripe",
            source: error.into(),
        }
    })?;

    let settler = StripePaymentIntentSettler::new(
        endpoints,
        transport,
        recovery_cipher(config, inputs)?,
        &rail.api_version,
        StripeSettlerConfig {
            call_timeout_ms: u64::from(config.authorization_timeout_ms),
            total_deadline_ms: u64::from(config.authorization_timeout_ms),
            recovery_ttl_ms: recovery_ttl_ms(config),
            // The operator's switch, carried to the one place that can
            // honor it. Absent means off, which matches the config default.
            direct_payment_intent_enabled: rail
                .direct_payment_intent
                .as_ref()
                .is_some_and(|direct| direct.enabled),
        },
    )
    .map_err(|error| PaymentsRuntimeError::Billing {
        surface: "rails.stripe",
        source: error.into(),
    })?;
    Ok(Arc::new(settler))
}

/// Build the Stripe usage reporter.
///
/// It shares the settlement rail's key and API version, because it is the
/// same account, and shares nothing else. It registers in the reporter
/// namespace, cannot build a receipt, and cannot move an intent to
/// `Succeeded`.
#[cfg(feature = "payment-stripe")]
fn build_stripe_meter_reporter(
    reporter: &sbproxy_config::payments::StripeMeterReporterConfig,
    rail: &sbproxy_config::payments::StripeRailConfig,
    config: &PaymentsConfig,
    inputs: &PaymentsRuntimeInputs,
) -> Result<Arc<dyn sbproxy_billing::registry::UsageReporter>, PaymentsRuntimeError> {
    use sbproxy_billing::stripe_meter::{StripeMeterEndpoints, StripeMeterReporter};
    use sbproxy_billing::stripe_payment::STRIPE_API_ROOT;
    use sbproxy_billing::transport::HttpStripeTransport;

    let _ = reporter;
    let surface = billing_error("usage_reporters.stripe_meter");
    let transport = HttpStripeTransport::new(stripe_api_key(inputs)?).map_err(&surface)?;
    let endpoints = StripeMeterEndpoints::from_api_root(STRIPE_API_ROOT).map_err(|error| {
        PaymentsRuntimeError::Billing {
            surface: "usage_reporters.stripe_meter",
            source: error.into(),
        }
    })?;

    let built = StripeMeterReporter::new(
        endpoints,
        transport,
        &rail.api_version,
        u64::from(config.authorization_timeout_ms),
    )
    .map_err(|error| PaymentsRuntimeError::Billing {
        surface: "usage_reporters.stripe_meter",
        source: error.into(),
    })?;
    Ok(Arc::new(built))
}

/// Build the Core Lightning rail.
///
/// The socket is not dialed here. `check_health` proves the node answers and
/// meets the pinned version floor before anything is published, so a node
/// that is down or too old fails the whole runtime rather than one paid
/// request.
#[cfg(all(feature = "payment-lightning-cln", unix))]
fn build_cln_adapter(
    rail: &sbproxy_config::payments::LightningClnRailConfig,
    config: &PaymentsConfig,
    inputs: &PaymentsRuntimeInputs,
) -> Result<Arc<dyn sbproxy_billing::registry::PaymentMethodAdapter>, PaymentsRuntimeError> {
    use sbproxy_billing::lightning::cln::ClnSettler;
    use sbproxy_billing::transport::UnixClnTransport;

    let surface = billing_error("rails.lightning_cln");
    let transport = UnixClnTransport::new(Path::new(&rail.socket_path)).map_err(&surface)?;
    let settler = ClnSettler::new(
        transport,
        inputs
            .cln_rune
            .as_ref()
            .map(|rune| rune.as_str().to_owned()),
        CLN_INVOICE_DESCRIPTION,
        u64::from(config.authorization_timeout_ms),
        u64::from(config.authorization_timeout_ms),
    )
    .map_err(|error| PaymentsRuntimeError::Billing {
        surface: "rails.lightning_cln",
        source: error.into(),
    })?;
    Ok(Arc::new(settler))
}

/// The resolved Stripe secret key, or the error naming what is missing.
#[cfg(feature = "payment-stripe")]
fn stripe_api_key(
    inputs: &PaymentsRuntimeInputs,
) -> Result<Zeroizing<String>, PaymentsRuntimeError> {
    let key = inputs
        .stripe_api_key
        .as_ref()
        .ok_or(PaymentsRuntimeError::StripeKeyMissing)?;
    if key.trim().is_empty() {
        return Err(PaymentsRuntimeError::StripeKeyMissing);
    }
    Ok(key.clone())
}

/// The recovery cipher the Stripe rail seals its replay envelopes with.
#[cfg(feature = "payment-stripe")]
fn recovery_cipher(
    config: &PaymentsConfig,
    inputs: &PaymentsRuntimeInputs,
) -> Result<RecoveryCipher, PaymentsRuntimeError> {
    let recovery = config
        .recovery_encryption
        .as_ref()
        .ok_or(PaymentsRuntimeError::RecoveryKeyMissing)?;
    let key = inputs
        .recovery_key
        .as_ref()
        .ok_or(PaymentsRuntimeError::RecoveryKeyMissing)?;
    recovery.validate_resolved_key(key)?;
    RecoveryCipher::new(&recovery.key_id, key).map_err(|source| PaymentsRuntimeError::Billing {
        surface: "recovery_encryption.key",
        source,
    })
}

/// How long a sealed envelope stays replayable, in milliseconds.
///
/// Configuration bounds `max_age_hours` at 23, below Stripe's documented
/// 24-hour idempotency retention, so the arithmetic cannot overflow and the
/// window cannot outlive the provider's memory of the original request.
#[cfg(feature = "payment-stripe")]
fn recovery_ttl_ms(config: &PaymentsConfig) -> i64 {
    config
        .recovery_encryption
        .as_ref()
        .map_or(0, |recovery| i64::from(recovery.max_age_hours) * 3_600_000)
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

/// Create the settlement series for every rail this build registered.
///
/// The same `inc_by(0)` trick `record_worker_delta` uses below, for the
/// same reason and one step earlier: a counter family that springs into
/// existence on its first payment cannot tell an operator whether nothing
/// has settled yet or this deployment records nothing at all, and the
/// second is a bug the first one hides. Seeded from the registered rails
/// rather than from `ALL_RAILS`, so the presence of a series still answers
/// "is this rail configured" the way `sbproxy_payment_rail_enabled` does.
///
/// Only the two series an operator alerts on are seeded: challenges
/// prepared, and payments that bought origin access. The refusal
/// vocabulary is left to appear when a refusal happens, because a flat zero
/// line for every payment problem code is noise, and a refusal that has
/// never occurred is not a question anybody asks.
fn seed_settlement_series(rails: &[SettlementRail]) {
    for rail in rails {
        record_payment_settlement(rail.as_str(), OP_CHALLENGE, OUTCOME_PREPARED, 0);
        record_payment_settlement(rail.as_str(), OP_REDEEM, OUTCOME_SUCCEEDED, 0);
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
    // WOR-2317. Reuses `sbproxy_payment_recovery_total` rather than adding a
    // family: this is a durable row the recovery worker moved, which is
    // exactly what that counter is for, and it already carries the two labels
    // the event needs. Both values are new and neither collides with an
    // existing one, so a dashboard summing the family picks this up and every
    // query written against a specific `operation` keeps selecting the rows
    // it always did.
    //
    // `stranded` is its own outcome rather than a share of `terminal`. The
    // whole point of the state is that it is not `terminal`: terminal means a
    // provider proved no funds moved, and folding these rows into it would
    // hide unaccounted money inside the series an operator reads as "clean
    // failures". Alert on this one.
    record_payment_recovery(
        "strand_intent",
        "stranded",
        current
            .intents_stranded
            .saturating_sub(previous.intents_stranded),
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
    fn seeding_creates_a_settlement_series_for_every_registered_rail() {
        // The defect this guards is an absence, so the assertion is about a
        // series existing rather than about a value. Without the seed, a
        // scrape cannot separate "nothing has settled yet" from "this
        // deployment records no settlements at all", and the second is a
        // bug that hides behind the first for as long as traffic is quiet.
        seed_settlement_series(&[SettlementRail::LightningCln]);

        let seeded = |operation: &str, outcome: &str| {
            prometheus::gather()
                .into_iter()
                .find(|family| family.name() == "sbproxy_payment_settlement_total")
                .is_some_and(|family| {
                    family.get_metric().iter().any(|metric| {
                        let labelled = |name: &str, want: &str| {
                            metric
                                .get_label()
                                .iter()
                                .any(|label| label.name() == name && label.value() == want)
                        };
                        labelled("rail", "lightning_cln")
                            && labelled("operation", operation)
                            && labelled("outcome", outcome)
                    })
                })
        };

        assert!(
            seeded("challenge", "prepared"),
            "a configured rail draws a flat line for challenges before its first one",
        );
        assert!(
            seeded("redeem", "succeeded"),
            "a configured rail draws a flat line for settlements before its first one",
        );
    }

    /// One `sbproxy_payment_recovery_total` series, or 0 when it is absent.
    fn recovery_count(operation: &str, outcome: &str) -> f64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_payment_recovery_total")
            .and_then(|family| {
                family
                    .get_metric()
                    .iter()
                    .find(|metric| {
                        let labelled = |name: &str, want: &str| {
                            metric
                                .get_label()
                                .iter()
                                .any(|label| label.name() == name && label.value() == want)
                        };
                        labelled("operation", operation) && labelled("outcome", outcome)
                    })
                    .map(|metric| metric.get_counter().value())
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn an_aged_out_hold_is_counted_once_on_the_recovery_family() {
        // WOR-2317. Reuse rather than a new family: this is a durable row the
        // recovery worker moved, which is what `sbproxy_payment_recovery_total`
        // already means, and it needs no label the family does not have.
        let before = recovery_count("strand_intent", "stranded");
        let clean_failures_before = recovery_count("expire_challenge", "terminal");
        let observed: ObservedStatus = Arc::new(Mutex::new(WorkerStatus::default()));

        record_worker_delta(
            &observed,
            WorkerStatus {
                intents_stranded: 1,
                ..WorkerStatus::default()
            },
        );
        assert!(
            (recovery_count("strand_intent", "stranded") - before - 1.0).abs() < f64::EPSILON,
            "one payment ageing out is one observation",
        );

        // The worker's counter is cumulative, so a later tick reporting the
        // same total must add nothing. Without the diff an idle worker would
        // re-report every retired payment once a second and an alert on this
        // series would fire forever over one stuck intent.
        record_worker_delta(
            &observed,
            WorkerStatus {
                intents_stranded: 1,
                ..WorkerStatus::default()
            },
        );
        assert!(
            (recovery_count("strand_intent", "stranded") - before - 1.0).abs() < f64::EPSILON,
            "a repeated snapshot is not a second aged-out payment",
        );

        // Its own outcome, never folded into an existing one. `terminal`
        // means a provider proved no funds moved, and hiding unaccounted
        // money inside the series an operator reads as clean failures is
        // exactly the reporting bug worth avoiding.
        assert!(
            (recovery_count("expire_challenge", "terminal") - clean_failures_before).abs()
                < f64::EPSILON,
            "an aged-out hold must not land in the clean-failure series",
        );
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
        // The reconciliation deadline is not an operator knob either. Its
        // right value follows from the reconciliation cadence and from the
        // challenge TTL, both of which this crate owns.
        assert_eq!(
            lowered.reconciliation_grace_ms,
            defaults.reconciliation_grace_ms
        );
        assert_eq!(lowered.strand_batch, defaults.strand_batch);
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
            failure_mode: sbproxy_config::types::FailureMode::Closed,
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

    #[derive(Default)]
    struct RejectPaymentObserver {
        events: Mutex<
            Vec<(
                sbproxy_billing::PaymentLifecyclePhase,
                sbproxy_billing::PaymentLifecycleOutcome,
            )>,
        >,
    }

    #[async_trait::async_trait]
    impl sbproxy_billing::PaymentLifecycleObserver for RejectPaymentObserver {
        async fn started(
            &self,
            event: &sbproxy_billing::PaymentLifecycleEvent,
        ) -> sbproxy_billing::PaymentLifecycleDecision {
            self.events.lock().push((event.phase(), event.outcome()));
            sbproxy_billing::PaymentLifecycleDecision::Reject
        }

        fn terminal(&self, event: sbproxy_billing::PaymentLifecycleEvent) {
            self.events.lock().push((event.phase(), event.outcome()));
        }
    }

    fn observer_test_draft() -> sbproxy_billing::PaymentRequirementDraft {
        let mut draft = sbproxy_billing::PaymentRequirementDraft {
            requirement_id: "req-0123456789abcdef".to_owned(),
            protocol: sbproxy_billing::PaymentProtocol::X402V2,
            advertised_rail: sbproxy_billing::AdvertisedRail::X402,
            settlement_rail: sbproxy_billing::SettlementRail::X402,
            method: "exact".to_owned(),
            intent: "exact".to_owned(),
            network: Some("base-sepolia".to_owned()),
            asset: Some("usdc".to_owned()),
            pay_to: Some("recipient-fixture".to_owned()),
            amount: sbproxy_billing::Money::new(10_000, "USD").unwrap(),
            settlement_amount: String::new(),
            settlement_decimals: 6,
            terms: sbproxy_billing::RequirementTerms::X402Exact {
                facilitator_url: "https://facilitator.example/api".to_owned(),
                max_timeout_seconds: 60,
                extra: std::collections::BTreeMap::new(),
            },
            quote_id: "quote-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            origin_id: "origin-1".to_owned(),
            route: "/paid".to_owned(),
            expires_at_ms: 9_000_000_000_000,
            request_digest: None,
        };
        draft.canonicalize().unwrap();
        draft
    }

    fn test_inputs() -> PaymentsRuntimeInputs {
        PaymentsRuntimeInputs {
            signer: Arc::new(StubSigner),
            gate: None,
            payment_observer: None,
            recovery_key: None,
            stripe_api_key: None,
            cln_rune: None,
            clock: None,
            clustered: false,
        }
    }

    #[tokio::test]
    async fn candidate_installs_the_generation_payment_observer() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut config = sample_config();
        config.state_path = directory
            .path()
            .join("settlement.sqlite3")
            .to_string_lossy()
            .into_owned();
        let observer = Arc::new(RejectPaymentObserver::default());
        let mut inputs = test_inputs();
        inputs.payment_observer = Some(observer.clone());
        let candidate = PaymentsRuntimeCandidate::build(&config, &inputs).expect("candidate");

        let error = expect_error(
            candidate
                .service
                .prepare_requirement(sbproxy_billing::service::RequirementInput {
                    draft: observer_test_draft(),
                    request_idempotency_key: "request-key".to_owned(),
                    payer_hash: None,
                })
                .await,
            "the generation observer rejects before runtime payment work",
        );

        assert_eq!(error, sbproxy_billing::BillingError::ExtensionRejected);
        assert_eq!(
            *observer.events.lock(),
            [
                (
                    sbproxy_billing::PaymentLifecyclePhase::Challenge,
                    sbproxy_billing::PaymentLifecycleOutcome::Started,
                ),
                (
                    sbproxy_billing::PaymentLifecyclePhase::Challenge,
                    sbproxy_billing::PaymentLifecycleOutcome::Rejected,
                ),
            ]
        );
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
