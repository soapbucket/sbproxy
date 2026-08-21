//! Leader election via a Kubernetes `Lease` resource.
//!
//! `kube-runtime` 0.95 ships no `leader_election` helper, so this module
//! drives the well-trodden `coordination.k8s.io/v1.Lease` pattern by hand.
//! The shape mirrors `sbproxy-k8s-controller`'s, which arrived at it first:
//!
//! 1. **Acquire**: [`acquire_lease`] blocks until this pod owns the Lease.
//!    Creation uses POST, and takeover of an expired Lease uses a
//!    `resourceVersion`-checked replace, so two candidates racing the same
//!    stale Lease see exactly one winner. Server-side apply is deliberately
//!    not used anywhere here: SSA's force-ownership semantics would let a
//!    non-holder steal the holder field.
//! 2. **Renew**: [`renew_loop`] re-reads the Lease every [`RENEW_PERIOD`],
//!    confirms the holder is still us, and replaces it under the
//!    `resourceVersion` that read returned.
//! 3. **Fence**: the [`WriteGate`] closes *before* [`renew_loop`] returns,
//!    and the reconcile path refuses every apply while the gate is closed.
//!    Aborting the controller task is not a fence on its own: a request
//!    already dispatched to the apiserver still lands, and a task is only
//!    cancelled at its next await point.
//! 4. **Step down**: the caller cancels the controller and exits with code 0
//!    so the pod is restarted by the Deployment and re-races for the lock.
//!    That is the posture client-go's leader election defaults to.
//!
//! # Why the takeover is conditional
//!
//! An unconditional merge PATCH constrains nothing at the API server. The
//! holder check that precedes it runs against a value read seconds earlier,
//! so with two standbys polling the same expired Lease both read it, both
//! compute "expired", and both write themselves in. Both then believe they
//! are the leader, and for as long as it takes the loser to notice, two
//! operators server-side-apply the same Deployment under the same field
//! manager and fan `/admin/reload` out to the same pods. Carrying the read's
//! `resourceVersion` into the write is what turns that into one 200 and one
//! 409.
//!
//! # The deadline arithmetic
//!
//! | Field | Value |
//! | --- | --- |
//! | [`LEASE_DURATION`] | 15s |
//! | [`RENEW_PERIOD`] | 5s |
//! | [`RETRY_PERIOD`] | 2s |
//! | [`RENEW_DEADLINE`] | 5s |
//! | [`SAFETY_DEADLINE`] | 10s |
//!
//! Three properties make the fence sound, and all three are arithmetic both
//! sides have to agree on:
//!
//! * The successor's clock starts at the Lease's `renewTime`, which is
//!   stamped when a renewal *begins*, before the API call. So the incumbent
//!   measures its own deadline from that same instant rather than from when
//!   the call returned. Measuring from the return would under-count the
//!   elapsed time by the call's whole latency. The one anchor the hold loop
//!   cannot take itself is the acquisition's, so it renews once immediately
//!   on entry rather than riding an inherited one for a whole
//!   [`RENEW_PERIOD`].
//! * The deadline is absolute and is enforced from *inside* the wait, not
//!   checked after it. An apiserver that hangs rather than erroring never
//!   returns, so a check placed after the call runs late by however long the
//!   hang lasted.
//! * [`SAFETY_DEADLINE`] is strictly less than [`LEASE_DURATION`], by a full
//!   [`RENEW_PERIOD`]. That margin is what absorbs clock skew between the two
//!   replicas and the successor's own read latency.
//!
//! A single transient apiserver error is *not* a step-down. It used to be:
//! one 500 on one GET, which an apiserver rollout or an etcd leader election
//! produces routinely, restarted the pod and cost 15s of no reconciliation.
//! Renewals are now retried until [`SAFETY_DEADLINE`] and only then fenced.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::Client;

/// How long a held lease is considered valid before another candidate may
/// take it over. Matches client-go's default.
pub const LEASE_DURATION: Duration = Duration::from_secs(15);

/// How long the holder waits between renew attempts. Three renewal windows
/// fit inside one [`LEASE_DURATION`], so a single failed renewal is
/// survivable.
pub const RENEW_PERIOD: Duration = Duration::from_secs(5);

/// How long a contender waits between acquire attempts when the lease is held
/// by someone else.
pub const RETRY_PERIOD: Duration = Duration::from_secs(2);

/// Per-renew API call timeout. A renewal that stalls longer than this is
/// counted as a failure rather than awaited indefinitely.
///
/// No longer than one [`RENEW_PERIOD`], so one hung call cannot eat the
/// window the next attempt needs. It used to be 10s, which combined with the
/// period to put the step-down as late as 5s + 10s = 15s: exactly
/// [`LEASE_DURATION`], which is to say not inside it at all. It is now a
/// retry cadence rather than a safety property, because the fence deadline in
/// [`renew_loop`] is absolute and caps this one.
pub const RENEW_DEADLINE: Duration = Duration::from_secs(5);

/// How long renewals may keep failing, measured from the *start* of the last
/// successful one, before the holder fences itself.
///
/// Strictly less than [`LEASE_DURATION`], by a full [`RENEW_PERIOD`]. A
/// standby may only take over once the whole lease duration has elapsed since
/// the `renewTime` stamped on the Lease, and that stamp is taken at the start
/// of a renewal, which is the same instant this deadline is measured from.
pub const SAFETY_DEADLINE: Duration = Duration::from_secs(10);

/// Configuration for a leader-election session.
#[derive(Debug, Clone)]
pub struct LeaderConfig {
    /// The Lease name, e.g. `sbproxy-operator-leader`.
    pub lease_name: String,

    /// Namespace the Lease lives in.
    pub namespace: String,

    /// Stable holder identity. Pod name is conventional; we suffix a short
    /// random tag to avoid stale-acquire races when a Deployment re-creates a
    /// pod with the same name in quick succession.
    pub identity: String,
}

/// Shared gate between leadership and every write the reconciler makes.
///
/// The reconcile path checks this before it patches status, applies a
/// ConfigMap or Service, applies a workload, or fans `/admin/reload` out to
/// the proxy pods. [`WriteGate::always`] (also the `Default`) is the
/// no-election, single-replica posture: always open. An election gate starts
/// closed, opens on acquisition, and closes the moment leadership is lost, so
/// the fence does not wait for a task to be scheduled.
///
/// This exists because `controller_handle.abort()` is not a fence.
/// Cancellation only takes effect at the task's next await point, and an
/// apply already in flight at the apiserver lands regardless.
#[derive(Debug, Clone, Default)]
pub struct WriteGate(Option<Arc<AtomicBool>>);

impl WriteGate {
    /// A gate that always allows writes: the `--no-leader-election` posture.
    pub fn always() -> Self {
        Self(None)
    }

    /// A gate bound to leader election. Closed until leadership is acquired.
    pub fn for_election() -> Self {
        Self(Some(Arc::new(AtomicBool::new(false))))
    }

    /// Whether writes are currently allowed.
    pub fn allows(&self) -> bool {
        self.0
            .as_ref()
            .map(|held| held.load(Ordering::Acquire))
            .unwrap_or(true)
    }

    pub(crate) fn open(&self) {
        if let Some(held) = &self.0 {
            held.store(true, Ordering::Release);
        }
    }

    pub(crate) fn close(&self) {
        if let Some(held) = &self.0 {
            held.store(false, Ordering::Release);
        }
    }
}

/// Holder-identity helper. Builds `<hostname>_<8 hex chars>` so multiple
/// candidates on the same host (kind, mac docker desktop) get distinct ids.
pub fn build_identity(hostname: &str) -> String {
    use rand::Rng;
    let suffix: u32 = rand::thread_rng().gen();
    format!("{hostname}_{suffix:08x}")
}

/// Discover the namespace the operator pod is running in.
///
/// Resolution order, matching the controller-runtime convention:
///
/// 1. `K8S_NAMESPACE` environment variable (chart-set or operator-set).
/// 2. `/var/run/secrets/kubernetes.io/serviceaccount/namespace`, present on
///    every pod that mounts the default service-account token.
/// 3. The fallback string `"default"`. Only ever hit when running outside a
///    pod (e.g. `cargo run` against a kind cluster).
///
/// Pure function over inputs so it can be unit-tested without a filesystem.
pub fn discover_namespace<F>(env_lookup: impl Fn(&str) -> Option<String>, file_read: F) -> String
where
    F: FnOnce() -> Option<String>,
{
    if let Some(ns) = env_lookup("K8S_NAMESPACE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return ns;
    }
    if let Some(ns) = file_read()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return ns;
    }
    "default".to_string()
}

/// Default service-account namespace path. Pulled out so tests don't need to
/// monkey-patch the filesystem.
pub const SERVICE_ACCOUNT_NS_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Convenience wrapper used by `main.rs`: discover the namespace using the
/// real environment + service-account file.
///
/// WOR-618: the caller (`async fn run` in `main.rs`) is on a tokio runtime,
/// so the service-account file read goes through `tokio::fs` to avoid
/// stalling the runtime worker on a slow `read_to_string`.
pub async fn discover_namespace_default() -> String {
    let file_value = tokio::fs::read_to_string(SERVICE_ACCOUNT_NS_PATH)
        .await
        .ok();
    discover_namespace(|k| std::env::var(k).ok(), || file_value.clone())
}

// --- Lease state, decoupled from kube for testability ---------------------

/// What one read of the Lease told us, plus the version token a conditional
/// write must present back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseState {
    pub(crate) holder: Option<String>,
    pub(crate) duration_secs: i32,
    pub(crate) acquire_time: Option<DateTime<Utc>>,
    pub(crate) renew_time: Option<DateTime<Utc>>,
    pub(crate) transitions: i32,
    pub(crate) resource_version: Option<String>,
}

impl LeaseState {
    fn fresh(identity: &str, now: DateTime<Utc>) -> Self {
        Self {
            holder: Some(identity.to_string()),
            duration_secs: LEASE_DURATION.as_secs() as i32,
            acquire_time: Some(now),
            renew_time: Some(now),
            transitions: 0,
            resource_version: None,
        }
    }

    fn renewed_by(&self, identity: &str, now: DateTime<Utc>) -> Self {
        Self {
            holder: Some(identity.to_string()),
            duration_secs: LEASE_DURATION.as_secs() as i32,
            acquire_time: self.acquire_time,
            renew_time: Some(now),
            transitions: self.transitions,
            resource_version: self.resource_version.clone(),
        }
    }

    fn taken_over_by(&self, identity: &str, now: DateTime<Utc>) -> Self {
        Self {
            holder: Some(identity.to_string()),
            duration_secs: LEASE_DURATION.as_secs() as i32,
            acquire_time: Some(now),
            renew_time: Some(now),
            transitions: self.transitions.saturating_add(1),
            resource_version: self.resource_version.clone(),
        }
    }
}

/// Whether the Lease may be taken over at `now`. A missing renew time or an
/// empty holder means nobody holds it. A renew time in the future (clock
/// skew) is treated as held, so skew makes takeover later, never earlier.
pub(crate) fn is_expired(state: &LeaseState, now: DateTime<Utc>) -> bool {
    let Some(renew) = state.renew_time else {
        return true;
    };
    if state.holder.as_deref().unwrap_or("").is_empty() {
        return true;
    }
    let age = now.signed_duration_since(renew);
    age.to_std()
        .map(|age| age > Duration::from_secs(state.duration_secs.max(0) as u64))
        .unwrap_or(false)
}

/// Result of a conditional Lease write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteResult {
    /// The write landed; here is the stored state including its new version
    /// token.
    Applied(LeaseState),
    /// The precondition failed: the object changed since it was read (or
    /// already existed, for a create). Losing here is the point.
    Conflict,
    /// The Lease is gone.
    Missing,
}

/// The three Lease operations the lifecycle needs, so the engine can run
/// against the real apiserver or an in-memory fake with the same
/// conditional-write semantics.
pub(crate) trait LeaseApi: Send + Sync {
    /// Read the current Lease, `None` when it does not exist.
    fn read(&self) -> impl Future<Output = anyhow::Result<Option<LeaseState>>> + Send;
    /// Create the Lease. Conflict when it already exists.
    fn create(
        &self,
        state: &LeaseState,
    ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send;
    /// Replace the Lease, conditional on `state.resource_version`.
    fn replace(
        &self,
        state: &LeaseState,
    ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send;
}

/// One acquisition attempt. `Ok(Some(state))` means we now hold the Lease.
async fn try_acquire_once<A: LeaseApi>(
    api: &A,
    identity: &str,
) -> anyhow::Result<Option<LeaseState>> {
    let now = Utc::now();
    match api.read().await? {
        None => match api.create(&LeaseState::fresh(identity, now)).await? {
            WriteResult::Applied(state) => Ok(Some(state)),
            // A peer created it between our read and our write.
            WriteResult::Conflict | WriteResult::Missing => Ok(None),
        },
        Some(state) => {
            if state.holder.as_deref() == Some(identity) {
                // Already ours (a previous attempt's write landed but its
                // response was lost). Refresh and carry on.
                match api.replace(&state.renewed_by(identity, now)).await? {
                    WriteResult::Applied(state) => Ok(Some(state)),
                    WriteResult::Conflict | WriteResult::Missing => Ok(None),
                }
            } else if is_expired(&state, now) {
                // Expired: take it over, conditional on the exact version the
                // staleness decision was made on. Two candidates racing this
                // see one Applied and one Conflict.
                match api.replace(&state.taken_over_by(identity, now)).await? {
                    WriteResult::Applied(state) => Ok(Some(state)),
                    WriteResult::Conflict | WriteResult::Missing => Ok(None),
                }
            } else {
                Ok(None)
            }
        }
    }
}

/// What one renewal concluded.
#[derive(Debug, PartialEq, Eq)]
enum RenewOutcome {
    /// Still ours; deadline extended.
    Renewed,
    /// The Lease is now held by someone else, or is gone.
    Lost,
    /// The conditional write raced something; not fatal by itself.
    Contended,
}

/// One renewal attempt: re-read, confirm we still hold it, replace under the
/// fresh `resourceVersion`.
async fn renew_once<A: LeaseApi>(api: &A, identity: &str) -> anyhow::Result<RenewOutcome> {
    let now = Utc::now();
    let Some(state) = api.read().await? else {
        return Ok(RenewOutcome::Lost);
    };
    if state.holder.as_deref() != Some(identity) {
        return Ok(RenewOutcome::Lost);
    }
    match api.replace(&state.renewed_by(identity, now)).await? {
        WriteResult::Applied(_) => Ok(RenewOutcome::Renewed),
        WriteResult::Conflict => Ok(RenewOutcome::Contended),
        WriteResult::Missing => Ok(RenewOutcome::Lost),
    }
}

/// Engine behind [`acquire_lease`]: poll until the Lease is ours. Transient
/// API errors are logged and retried; they do not kill a candidate.
pub(crate) async fn acquire_via<A: LeaseApi>(api: &A, cfg: &LeaderConfig, gate: &WriteGate) {
    loop {
        match try_acquire_once(api, &cfg.identity).await {
            Ok(Some(_)) => {
                // Open the gate before announcing, so no reconcile can see a
                // leader that is not yet allowed to write.
                gate.open();
                tracing::info!(
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    identity = %cfg.identity,
                    "acquired leader lease"
                );
                sbproxy_observe::metrics::record_operator_leader_transition("elected");
                sbproxy_observe::metrics::set_operator_leader_is_leader(true);
                return;
            }
            Ok(None) => {
                tracing::debug!(
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    "lease held by another candidate; retrying"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    "acquire attempt failed; retrying"
                );
            }
        }
        tokio::time::sleep(RETRY_PERIOD).await;
    }
}

/// Engine behind [`renew_loop`]: renew until leadership ends. The gate is
/// closed before this returns, on every path.
pub(crate) async fn hold_via<A: LeaseApi>(api: &A, cfg: &LeaderConfig, gate: &WriteGate) {
    // The instant the last renewal we can prove *started*, which is the
    // instant its `renewTime` stamp was taken and therefore the instant a
    // successor measures the lease from. Not the instant it returned: the
    // difference is the API call's latency, and counting from the return
    // would give this holder that much longer than the successor gives it.
    let mut last_ok = tokio::time::Instant::now();
    // The anchor above is inherited, not measured: `acquire_lease` stamped
    // its `renewTime` before its API call was even sent, so by the time this
    // loop starts the successor's clock is already the whole acquire round
    // trip ahead of `last_ok`. Renew once immediately to replace the
    // inherited anchor with a stamp this loop took itself, and only then
    // settle into `RENEW_PERIOD`. Without it a slow acquire silently spends
    // its own latency out of the margin between the fence and the earliest
    // legal takeover.
    let mut anchor_is_inherited = true;
    loop {
        // Absolute. Every wait below is capped at it, so it is a deadline the
        // gate closes on rather than a condition that gets checked whenever
        // the apiserver next decides to answer.
        let fence_at = last_ok + SAFETY_DEADLINE;
        let wake_at = if std::mem::take(&mut anchor_is_inherited) {
            tokio::time::Instant::now()
        } else {
            std::cmp::min(tokio::time::Instant::now() + RENEW_PERIOD, fence_at)
        };
        tokio::time::sleep_until(wake_at).await;

        // The last attempt is allowed to start exactly at the deadline and is
        // cut off there. A renewal that lands at that instant is a real
        // renewal: its `renewTime` stamp moves the successor's clock along
        // with ours, so continuing is correct. One that does not land reaches
        // the fence below without any further waiting.
        let attempt_started = tokio::time::Instant::now();
        // Capped at the fence: an apiserver that hangs instead of erroring
        // would otherwise hold this await open past the moment a successor
        // becomes legal, and the incumbent would still be applying workloads
        // and POSTing /admin/reload when the successor started.
        let deadline = std::cmp::min(attempt_started + RENEW_DEADLINE, fence_at);
        match tokio::time::timeout_at(deadline, renew_once(api, &cfg.identity)).await {
            Ok(Ok(RenewOutcome::Renewed)) => {
                last_ok = attempt_started;
                sbproxy_observe::metrics::record_operator_leader_transition("renewed");
            }
            Ok(Ok(RenewOutcome::Lost)) => {
                fence(
                    gate,
                    cfg,
                    last_ok,
                    "the lease is held by another pod or is gone",
                );
                return;
            }
            // A single transient error is survivable and deliberately is not
            // a step-down. Only the absolute deadline ends the hold.
            Ok(Ok(RenewOutcome::Contended)) | Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    lease = %cfg.lease_name,
                    identity = %cfg.identity,
                    since_last_renewal_secs = last_ok.elapsed().as_secs(),
                    "leader lease renewal did not complete; retrying until the safety deadline"
                );
                if tokio::time::Instant::now() >= fence_at {
                    fence(
                        gate,
                        cfg,
                        last_ok,
                        "ownership could not be proven within the safety deadline",
                    );
                    return;
                }
            }
        }
    }
}

/// Close the write gate and report the loss. Split out so every path that
/// gives up leadership closes the gate the same way, in the same order,
/// before the caller can observe the return.
fn fence(gate: &WriteGate, cfg: &LeaderConfig, last_ok: tokio::time::Instant, reason: &str) {
    gate.close();
    sbproxy_observe::metrics::record_operator_leader_transition("lost");
    sbproxy_observe::metrics::set_operator_leader_is_leader(false);
    tracing::warn!(
        lease = %cfg.lease_name,
        namespace = %cfg.namespace,
        identity = %cfg.identity,
        reason = %reason,
        since_last_renewal_secs = last_ok.elapsed().as_secs(),
        safety_deadline_secs = SAFETY_DEADLINE.as_secs(),
        lease_duration_secs = LEASE_DURATION.as_secs(),
        "fencing every operator write and stepping down before a successor can act"
    );
}

// --- kube-backed LeaseApi -------------------------------------------------

/// The real `coordination.k8s.io/v1` Lease, via kube.
pub(crate) struct KubeLeaseApi {
    api: Api<Lease>,
    name: String,
    namespace: String,
}

impl KubeLeaseApi {
    pub(crate) fn new(client: Client, cfg: &LeaderConfig) -> Self {
        Self {
            api: Api::namespaced(client, &cfg.namespace),
            name: cfg.lease_name.clone(),
            namespace: cfg.namespace.clone(),
        }
    }

    fn to_lease(&self, state: &LeaseState) -> Lease {
        Lease {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                namespace: Some(self.namespace.clone()),
                // The whole point. An empty resourceVersion on a replace is
                // an unconditional overwrite; a populated one makes the
                // apiserver reject a write whose read is out of date.
                resource_version: state.resource_version.clone(),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: state.holder.clone(),
                lease_duration_seconds: Some(state.duration_secs),
                acquire_time: state.acquire_time.map(MicroTime),
                renew_time: state.renew_time.map(MicroTime),
                lease_transitions: Some(state.transitions),
            }),
        }
    }
}

fn from_lease(lease: &Lease) -> LeaseState {
    let spec = lease.spec.clone().unwrap_or_default();
    LeaseState {
        holder: spec.holder_identity,
        duration_secs: spec
            .lease_duration_seconds
            .unwrap_or(LEASE_DURATION.as_secs() as i32),
        acquire_time: spec.acquire_time.map(|t| t.0),
        renew_time: spec.renew_time.map(|t| t.0),
        transitions: spec.lease_transitions.unwrap_or(0),
        resource_version: lease.metadata.resource_version.clone(),
    }
}

impl LeaseApi for KubeLeaseApi {
    async fn read(&self) -> anyhow::Result<Option<LeaseState>> {
        Ok(self
            .api
            .get_opt(&self.name)
            .await
            .map_err(anyhow::Error::from)?
            .as_ref()
            .map(from_lease))
    }

    fn create(
        &self,
        state: &LeaseState,
    ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send {
        let body = self.to_lease(state);
        async move {
            match self.api.create(&PostParams::default(), &body).await {
                Ok(stored) => Ok(WriteResult::Applied(from_lease(&stored))),
                Err(kube::Error::Api(e)) if e.code == 409 => Ok(WriteResult::Conflict),
                Err(e) => Err(e.into()),
            }
        }
    }

    fn replace(
        &self,
        state: &LeaseState,
    ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send {
        let body = self.to_lease(state);
        async move {
            match self
                .api
                .replace(&self.name, &PostParams::default(), &body)
                .await
            {
                Ok(stored) => Ok(WriteResult::Applied(from_lease(&stored))),
                Err(kube::Error::Api(e)) if e.code == 409 => Ok(WriteResult::Conflict),
                Err(kube::Error::Api(e)) if e.code == 404 => Ok(WriteResult::Missing),
                Err(e) => Err(e.into()),
            }
        }
    }
}

// --- Public entry points --------------------------------------------------

/// Block until this pod owns the Lease, then open `gate`.
///
/// Polls every [`RETRY_PERIOD`]. The function only returns once we are the
/// holder; the caller then enters [`renew_loop`].
pub async fn acquire_lease(client: &Client, cfg: &LeaderConfig, gate: &WriteGate) {
    let api = KubeLeaseApi::new(client.clone(), cfg);
    acquire_via(&api, cfg, gate).await;
}

/// Stay holder by renewing every [`RENEW_PERIOD`], and return once
/// leadership has ended.
///
/// Returns only after `gate` has been closed, so by the time the caller sees
/// this future resolve the reconcile path is already refusing writes. The
/// caller then cancels the controller task and exits with code 0 so the pod
/// restarts and re-races for the lock.
pub async fn renew_loop(client: Client, cfg: LeaderConfig, gate: WriteGate) {
    let api = KubeLeaseApi::new(client, &cfg);
    hold_via(&api, &cfg, &gate).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(identity: &str) -> LeaderConfig {
        LeaderConfig {
            lease_name: "sbproxy-operator-leader".to_string(),
            namespace: "sbproxy-system".to_string(),
            identity: identity.to_string(),
        }
    }

    /// In-memory Lease with the apiserver's conditional-write semantics:
    /// create fails when present, replace fails unless the presented
    /// resourceVersion matches the stored one.
    #[derive(Default)]
    struct FakeLease {
        state: std::sync::Mutex<Option<(LeaseState, u64)>>,
        fail_reads: AtomicBool,
        fail_writes: AtomicBool,
        /// An apiserver that stops answering rather than erroring. This is
        /// the failure mode that separates a deadline enforced from inside
        /// the wait from one checked after it: a call that never returns
        /// never reaches a check placed after it.
        hang: AtomicBool,
    }

    impl FakeLease {
        fn stored(&self) -> Option<LeaseState> {
            self.state
                .lock()
                .unwrap()
                .as_ref()
                .map(|(state, _)| state.clone())
        }

        fn seed(&self, state: LeaseState) {
            let mut slot = self.state.lock().unwrap();
            let version = slot.as_ref().map(|(_, v)| v + 1).unwrap_or(1);
            let mut state = state;
            state.resource_version = Some(version.to_string());
            *slot = Some((state, version));
        }
    }

    impl LeaseApi for FakeLease {
        fn read(&self) -> impl Future<Output = anyhow::Result<Option<LeaseState>>> + Send {
            let hang = self.hang.load(Ordering::SeqCst);
            let out = if self.fail_reads.load(Ordering::SeqCst) {
                Err(anyhow::anyhow!("injected read outage"))
            } else {
                Ok(self.stored())
            };
            async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                out
            }
        }

        fn create(
            &self,
            state: &LeaseState,
        ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send {
            let out = if self.fail_writes.load(Ordering::SeqCst) {
                Err(anyhow::anyhow!("injected write outage"))
            } else {
                let mut slot = self.state.lock().unwrap();
                if slot.is_some() {
                    Ok(WriteResult::Conflict)
                } else {
                    let mut stored = state.clone();
                    stored.resource_version = Some("1".to_string());
                    *slot = Some((stored.clone(), 1));
                    Ok(WriteResult::Applied(stored))
                }
            };
            async move { out }
        }

        fn replace(
            &self,
            state: &LeaseState,
        ) -> impl Future<Output = anyhow::Result<WriteResult>> + Send {
            let hang = self.hang.load(Ordering::SeqCst);
            let out = if self.fail_writes.load(Ordering::SeqCst) {
                Err(anyhow::anyhow!("injected write outage"))
            } else {
                let mut slot = self.state.lock().unwrap();
                match slot.as_mut() {
                    None => Ok(WriteResult::Missing),
                    Some((stored, version)) => {
                        if state.resource_version.as_deref() != Some(version.to_string().as_str()) {
                            Ok(WriteResult::Conflict)
                        } else {
                            *version += 1;
                            let mut next = state.clone();
                            next.resource_version = Some(version.to_string());
                            *stored = next.clone();
                            Ok(WriteResult::Applied(next))
                        }
                    }
                }
            };
            async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                out
            }
        }
    }

    fn expired_lease(holder: &str) -> LeaseState {
        LeaseState {
            holder: Some(holder.to_string()),
            duration_secs: 15,
            acquire_time: Some(Utc::now() - chrono::Duration::seconds(120)),
            renew_time: Some(Utc::now() - chrono::Duration::seconds(60)),
            transitions: 3,
            resource_version: None,
        }
    }

    #[tokio::test]
    async fn two_standbys_racing_one_expired_lease_admit_exactly_one_leader() {
        // The H24 seam. The evicted leader's Lease went stale, and both
        // standbys are mid-poll. Before this fix the takeover was a plain
        // merge PATCH with no resourceVersion in the body, so the apiserver
        // applied both writes and both `try_acquire` calls reported
        // Acquired: two operators then server-side-applied the same
        // Deployment and fanned /admin/reload out to the same pods.
        let fake = FakeLease::default();
        fake.seed(expired_lease("evicted-leader"));

        // Both candidates read the same stale Lease before either writes.
        let read_a = fake.read().await.unwrap().unwrap();
        let read_b = fake.read().await.unwrap().unwrap();
        assert_eq!(read_a.resource_version, read_b.resource_version);

        let now = Utc::now();
        let a_takeover = read_a.taken_over_by("a", now);
        let b_takeover = read_b.taken_over_by("b", now);
        let a = fake.replace(&a_takeover).await.unwrap();
        let b = fake.replace(&b_takeover).await.unwrap();

        assert!(
            matches!(a, WriteResult::Applied(_)),
            "the first stealer wins"
        );
        assert_eq!(b, WriteResult::Conflict, "the second stealer must lose");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("a"));
        assert_eq!(
            fake.stored().unwrap().transitions,
            4,
            "a takeover records a leadership transition"
        );
    }

    #[tokio::test]
    async fn a_lost_takeover_reports_not_acquired_rather_than_acquired() {
        // The same race through the real entry point: the loser must see
        // `Ok(None)` and keep polling, not conclude it is the leader.
        let fake = FakeLease::default();
        fake.seed(expired_lease("evicted-leader"));
        let stale_read = fake.read().await.unwrap().unwrap();

        let winner = try_acquire_once(&fake, "a").await.unwrap();
        assert!(winner.is_some(), "the first stealer acquires");

        // Contender B decided "expired" off `stale_read` and writes late.
        let loser = fake
            .replace(&stale_read.taken_over_by("b", Utc::now()))
            .await
            .unwrap();
        assert_eq!(loser, WriteResult::Conflict);
        // And a full attempt after the takeover sees a fresh lease.
        assert!(
            try_acquire_once(&fake, "b").await.unwrap().is_none(),
            "a live lease must be respected"
        );
    }

    #[tokio::test]
    async fn creation_race_admits_exactly_one_candidate() {
        let fake = FakeLease::default();
        let a = try_acquire_once(&fake, "a").await.unwrap();
        let b = try_acquire_once(&fake, "b").await.unwrap();
        assert!(a.is_some(), "the first candidate creates the Lease");
        assert!(b.is_none(), "the second candidate must lose the create");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("a"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_transient_api_error_does_not_cost_leadership() {
        // The H28 availability half. One 500 on one GET used to return Err
        // immediately, which restarted the pod and cost 15s of no
        // reconciliation for a blip that cost one request.
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        acquire_via(&*fake, &cfg, &gate).await;
        assert!(gate.allows(), "acquisition opens the gate");

        fake.fail_reads.store(true, Ordering::SeqCst);
        let holder = tokio::spawn({
            let fake = std::sync::Arc::clone(&fake);
            let gate = gate.clone();
            let cfg = cfg.clone();
            async move { hold_via(&*fake, &cfg, &gate).await }
        });
        // One renewal fails, then the apiserver recovers well inside the
        // safety deadline.
        tokio::time::sleep(RENEW_PERIOD + Duration::from_secs(1)).await;
        fake.fail_reads.store(false, Ordering::SeqCst);
        tokio::time::sleep(RENEW_PERIOD * 2).await;

        assert!(gate.allows(), "a recovered holder keeps writing");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("a"));
        assert!(
            !holder.is_finished(),
            "the holder must not have stepped down"
        );
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_keeps_leadership_past_many_lease_durations() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        assert!(!gate.allows(), "an election gate starts closed");
        acquire_via(&*fake, &cfg, &gate).await;

        let holder = tokio::spawn({
            let fake = std::sync::Arc::clone(&fake);
            let gate = gate.clone();
            let cfg = cfg.clone();
            async move { hold_via(&*fake, &cfg, &gate).await }
        });
        tokio::time::sleep(LEASE_DURATION * 4).await;

        let state = fake.stored().unwrap();
        assert_eq!(state.holder.as_deref(), Some("a"));
        assert!(gate.allows(), "the holder still writes");
        assert!(
            state.resource_version.unwrap().parse::<u64>().unwrap() > 1,
            "renewals must actually write the Lease"
        );
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_hold_loop_re_anchors_before_spending_any_of_the_margin() {
        // `acquire_lease` stamps `renewTime` before its API call is sent, so
        // the instant `hold_via` starts is already that call's whole latency
        // past the instant a successor measures the lease from. Inheriting
        // that anchor for a full RENEW_PERIOD spends the acquire's latency
        // out of the margin between the fence and the earliest legal
        // takeover, which is the one number the two sides have to agree on.
        // So the first renewal happens straight away.
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        acquire_via(&*fake, &cfg, &gate).await;
        let at_acquisition = fake.stored().unwrap().resource_version;

        let holder = tokio::spawn({
            let fake = std::sync::Arc::clone(&fake);
            let gate = gate.clone();
            let cfg = cfg.clone();
            async move { hold_via(&*fake, &cfg, &gate).await }
        });
        // Far short of one renewal period: the point is that no wait happens.
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert_ne!(
            fake.stored().unwrap().resource_version,
            at_acquisition,
            "the hold loop must replace the inherited anchor with a stamp it \
             took itself, not wait a full renewal period on it"
        );
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_apiserver_fences_strictly_inside_the_lease_duration() {
        // The H28 correctness half. The old shape checked the deadline only
        // after `timeout(RENEW_DEADLINE, ..)` returned, so a call that never
        // answers put the step-down at RENEW_PERIOD + RENEW_DEADLINE =
        // 5s + 10s = 15s = LEASE_DURATION: the exact instant a standby's
        // `is_expired` starts returning true, not before it.
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        acquire_via(&*fake, &cfg, &gate).await;

        // The successor measures from the `renewTime` the acquisition just
        // stamped, so its clock starts here.
        let successor_clock_starts = tokio::time::Instant::now();
        fake.hang.store(true, Ordering::SeqCst);

        hold_via(&*fake, &cfg, &gate).await;

        assert!(!gate.allows(), "an unprovable lease is a fenced lease");
        let elapsed = successor_clock_starts.elapsed();
        assert!(
            elapsed >= SAFETY_DEADLINE,
            "the holder rides out transient failures up to the deadline, took {elapsed:?}"
        );
        assert!(
            elapsed <= SAFETY_DEADLINE + Duration::from_millis(2),
            "a hung API call must not push the fence past the deadline it is \
             measured from; took {elapsed:?}"
        );
        assert!(
            elapsed < LEASE_DURATION,
            "the gate must close strictly before a successor may take over; \
             took {elapsed:?} against a {LEASE_DURATION:?} lease"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_erroring_apiserver_fences_on_the_same_absolute_deadline() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        acquire_via(&*fake, &cfg, &gate).await;

        let successor_clock_starts = tokio::time::Instant::now();
        fake.fail_reads.store(true, Ordering::SeqCst);
        fake.fail_writes.store(true, Ordering::SeqCst);

        hold_via(&*fake, &cfg, &gate).await;

        assert!(!gate.allows());
        let elapsed = successor_clock_starts.elapsed();
        assert!(elapsed >= SAFETY_DEADLINE, "took {elapsed:?}");
        assert!(
            elapsed <= SAFETY_DEADLINE + Duration::from_millis(2),
            "the fence deadline is absolute, not one attempt past it; took {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn losing_the_holder_field_fences_writes_before_returning() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let gate = WriteGate::for_election();
        let cfg = cfg("a");
        acquire_via(&*fake, &cfg, &gate).await;

        // A peer takes the Lease over, as it legitimately may once it
        // observes expiry; the fake stands in for that moment.
        let stolen = fake.stored().unwrap().taken_over_by("b", Utc::now());
        fake.seed(stolen);

        hold_via(&*fake, &cfg, &gate).await;

        assert!(
            !gate.allows(),
            "the gate must be closed by the time the loss is observable"
        );
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("b"));
    }

    #[test]
    fn the_self_fence_deadline_is_strictly_inside_the_takeover_threshold() {
        // These numbers are claimed in this module's docs, in
        // docs/kubernetes.md, and in the Helm chart. Pin them so a constant
        // cannot drift out from under the prose.
        assert!(
            SAFETY_DEADLINE < LEASE_DURATION,
            "the gate has to close before a successor may take over"
        );
        assert!(
            LEASE_DURATION - SAFETY_DEADLINE >= RENEW_PERIOD,
            "the margin has to be a real one: a full renewal period between \
             the fence and the earliest legal takeover"
        );
        assert!(
            RENEW_DEADLINE <= RENEW_PERIOD,
            "one hung call must not consume the window the next attempt needs"
        );
    }

    #[test]
    fn write_gate_default_always_allows() {
        assert!(WriteGate::default().allows());
        assert!(WriteGate::always().allows());
        let gate = WriteGate::for_election();
        assert!(!gate.allows());
        gate.open();
        assert!(gate.allows());
        gate.close();
        assert!(!gate.allows());
    }

    #[test]
    fn discover_namespace_prefers_env() {
        let ns = discover_namespace(
            |k| {
                if k == "K8S_NAMESPACE" {
                    Some("from-env".to_string())
                } else {
                    None
                }
            },
            || Some("from-file".to_string()),
        );
        assert_eq!(ns, "from-env");
    }

    #[test]
    fn discover_namespace_falls_back_to_service_account_file() {
        let ns = discover_namespace(|_| None, || Some("from-file".to_string()));
        assert_eq!(ns, "from-file");
    }

    #[test]
    fn discover_namespace_falls_back_to_default() {
        let ns = discover_namespace(|_| None, || None);
        assert_eq!(ns, "default");
    }

    #[test]
    fn discover_namespace_treats_empty_env_as_unset() {
        // An empty K8S_NAMESPACE (chart sets the env var but values.yaml is
        // missing the field) must not be returned as `""`.
        let ns = discover_namespace(
            |k| (k == "K8S_NAMESPACE").then(|| "   ".to_string()),
            || Some("from-file".to_string()),
        );
        assert_eq!(ns, "from-file");
    }

    #[test]
    fn discover_namespace_treats_empty_file_as_unset() {
        let ns = discover_namespace(|_| None, || Some(String::new()));
        assert_eq!(ns, "default");
    }

    #[test]
    fn build_identity_is_unique_per_call() {
        let a = build_identity("pod-1");
        let b = build_identity("pod-1");
        assert!(a.starts_with("pod-1_"));
        assert!(b.starts_with("pod-1_"));
        assert_ne!(a, b, "random suffix should disambiguate");
    }

    #[test]
    fn is_expired_true_for_missing_renew_time() {
        let mut state = expired_lease("someone");
        state.renew_time = None;
        assert!(is_expired(&state, Utc::now()));
    }

    #[test]
    fn is_expired_true_for_old_renew() {
        assert!(is_expired(&expired_lease("someone"), Utc::now()));
    }

    #[test]
    fn is_expired_false_for_recent_renew() {
        let mut state = expired_lease("someone");
        state.renew_time = Some(Utc::now() - chrono::Duration::seconds(2));
        assert!(!is_expired(&state, Utc::now()));
    }

    #[test]
    fn is_expired_false_for_future_renew() {
        // Clock skew: a renew time slightly ahead of "now" must not flag as
        // expired, or the pair would flap-step-down.
        let mut state = expired_lease("someone");
        state.renew_time = Some(Utc::now() + chrono::Duration::seconds(5));
        assert!(!is_expired(&state, Utc::now()));
    }

    #[test]
    fn is_expired_true_for_a_released_lease() {
        let mut state = expired_lease("someone");
        state.holder = Some(String::new());
        state.renew_time = Some(Utc::now());
        assert!(is_expired(&state, Utc::now()));
    }
}
