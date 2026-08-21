// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Leader-election lifecycle for the Gateway controller (WOR-2614).
//!
//! The previous shape acquired a `coordination.k8s.io/v1` Lease once and
//! returned a boolean. Nothing ever renewed it, so fifteen seconds later a
//! standby could legitimately take it over while the original leader kept
//! reconciling, and two controllers then fought over one `sb.yml` and one
//! set of Gateway API status fields. This module replaces the boolean with
//! a lifecycle:
//!
//! 1. **Acquire** ([`acquire`]): block until this replica holds the Lease
//!    (or shutdown arrives first). Creation uses POST, takeover of an
//!    expired Lease uses a `resourceVersion`-checked replace, so two
//!    candidates racing the same stale Lease see exactly one winner.
//!    Force-apply is deliberately not used anywhere: SSA's ownership
//!    semantics would let a non-holder steal the holder field.
//! 2. **Hold** ([`hold`]): renew every [`RENEW_PERIOD`]. Renewal re-reads
//!    the Lease, confirms the holder is still us, and replaces it under
//!    its `resourceVersion`. Losing the holder field, a deleted Lease, or
//!    renewals failing past [`SAFETY_DEADLINE`] ends the hold.
//! 3. **Fence**: the [`WriteGate`] closes *before* `hold` returns, and the
//!    reconciler refuses config and status writes while the gate is
//!    closed. The deadline arithmetic is what makes the fence sound, and
//!    it has to be arithmetic both sides agree on:
//!
//!    * The successor's clock starts at the Lease's `renew_time`, which
//!      is stamped when a renewal *begins*, before the API call. So the
//!      incumbent measures its own deadline from the same instant, the
//!      start of its last successful renewal, rather than from when that
//!      call returned. Measuring from the return would under-count the
//!      elapsed time by the call's whole latency.
//!    * The deadline is absolute and is enforced from *inside* the wait,
//!      not checked after it. An API server that hangs rather than
//!      erroring never returns, so a check that runs after the call has
//!      returned runs late by however long the hang lasted. Both the
//!      inter-renewal sleep and the per-call timeout are capped at the
//!      absolute deadline, so the gate closes at exactly
//!      [`SAFETY_DEADLINE`] whatever the API server does.
//!    * [`SAFETY_DEADLINE`] is strictly less than [`LEASE_DURATION`], by
//!      a margin of a full [`RENEW_PERIOD`], which is what is left over
//!      for clock skew between the two replicas and for the successor's
//!      own read latency.
//! 4. **Step down**: on loss the caller marks readiness false and triggers
//!    shutdown; the Deployment restarts the pod, which re-races for the
//!    Lease as a standby. On graceful shutdown the Lease is released
//!    (holder cleared) so the next candidate does not wait out the TTL.
//!    Exiting on loss instead of re-acquiring in place is the same posture
//!    client-go's leader election defaults to, and the same one the
//!    sbproxy-k8s-operator ships.
//!
//! The timings match upstream client-go defaults so anyone who has read
//! kubelet or kube-controller-manager leader election can read these
//! without surprise.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::Client;

use crate::shutdown::ShutdownSignal;

/// How long a held Lease is considered valid before another candidate may
/// take it over. Matches client-go's default.
pub const LEASE_DURATION: Duration = Duration::from_secs(15);

/// How long the holder waits between renewals. Three renewal windows fit
/// inside one [`LEASE_DURATION`], so a single failed renewal is survivable.
pub const RENEW_PERIOD: Duration = Duration::from_secs(5);

/// How long a contender waits between acquire attempts while the Lease is
/// held by someone else.
pub const RETRY_PERIOD: Duration = Duration::from_secs(2);

/// Per-renewal API call timeout. A renewal that stalls longer than this is
/// counted as a failure rather than awaited indefinitely.
///
/// No longer than one [`RENEW_PERIOD`], so a single hung call cannot eat
/// the window the next attempt needs. It used to be 10s, which combined
/// with the period to put the old post-timeout fence check as late as
/// 15s: exactly [`LEASE_DURATION`], which is to say not inside it at all.
/// It is now a retry cadence rather than a safety property, because the
/// fence deadline in [`hold`] is absolute and caps this one.
pub const RENEW_DEADLINE: Duration = Duration::from_secs(5);

/// How long renewals may keep failing, measured from the *start* of the
/// last successful one, before the holder fences itself.
///
/// Strictly less than [`LEASE_DURATION`], by a full [`RENEW_PERIOD`]. A
/// standby may only take over once the whole lease duration has elapsed
/// since the `renew_time` stamped on the Lease, and that stamp is taken at
/// the start of a renewal, which is the same instant this deadline is
/// measured from. So the gate closes at least one renewal period before
/// any successor may legally act, and that margin is what absorbs clock
/// skew between the two replicas.
pub const SAFETY_DEADLINE: Duration = Duration::from_secs(10);

/// Shared gate between leadership and every config/status write.
///
/// The reconciler checks this before writing `sb.yml` and before
/// publishing status. [`WriteGate::always`] (also the `Default`) is the
/// single-replica posture with no election: always open. An election gate
/// starts closed, opens on acquisition, and closes the moment leadership
/// is lost, so the fence does not wait for a task to be polled.
#[derive(Debug, Clone, Default)]
pub struct WriteGate(Option<Arc<AtomicBool>>);

impl WriteGate {
    /// A gate that always allows writes: the no-election, single-replica
    /// deployment.
    pub fn always() -> Self {
        Self(None)
    }

    /// A gate bound to leader election. Closed until leadership is
    /// acquired.
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

/// Why [`hold`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeadershipEnd {
    /// Graceful shutdown; the Lease was released best-effort.
    Shutdown,
    /// Leadership was lost. The write gate is already closed; the caller
    /// stops reconciling and exits so the pod restarts as a standby.
    Lost,
}

/// Stable holder identity: hostname, process id, and startup nanos, so a
/// container restart inside the same pod never mistakes the previous
/// incarnation's Lease for its own.
pub fn build_identity() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "controller".to_string());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{host}-{}-{nanos:08x}", std::process::id())
}

// --- Lease state, decoupled from kube for testability -------------------

/// What one read of the Lease told us, plus the version token a
/// conditional write must present.
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

    fn released(&self) -> Self {
        Self {
            holder: None,
            duration_secs: LEASE_DURATION.as_secs() as i32,
            acquire_time: self.acquire_time,
            renew_time: None,
            transitions: self.transitions,
            resource_version: self.resource_version.clone(),
        }
    }
}

/// Whether the Lease may be taken over at `now`. Missing renew time means
/// nobody is holding it. A renew time in the future (clock skew) is
/// treated as held, so skew makes takeover later, never earlier.
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
    /// The write landed; here is the stored state including its new
    /// version token.
    Applied(LeaseState),
    /// The precondition failed: the object changed since it was read (or
    /// already existed, for a create). Losing here is the point.
    Conflict,
    /// The Lease is gone.
    Missing,
}

/// The three Lease operations the lifecycle needs, so the engine can run
/// against the real API server or an in-memory fake with the same
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
                // Expired: take it over, conditional on the exact version
                // the staleness decision was made on. Two candidates
                // racing this see one Applied and one Conflict.
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
    Renewed(LeaseState),
    /// The Lease is now held by someone else, or is gone.
    Lost,
    /// The conditional write raced something; not fatal by itself.
    Contended,
}

/// One renewal attempt: re-read, confirm we still hold it, replace under
/// the fresh `resourceVersion`.
async fn renew_once<A: LeaseApi>(api: &A, identity: &str) -> anyhow::Result<RenewOutcome> {
    let now = Utc::now();
    let Some(state) = api.read().await? else {
        return Ok(RenewOutcome::Lost);
    };
    if state.holder.as_deref() != Some(identity) {
        return Ok(RenewOutcome::Lost);
    }
    match api.replace(&state.renewed_by(identity, now)).await? {
        WriteResult::Applied(state) => Ok(RenewOutcome::Renewed(state)),
        WriteResult::Conflict => Ok(RenewOutcome::Contended),
        WriteResult::Missing => Ok(RenewOutcome::Lost),
    }
}

/// Engine behind [`acquire`]: poll until the Lease is ours or shutdown
/// arrives. Transient API errors are logged and retried; they do not kill
/// a candidate.
pub(crate) async fn acquire_via<A: LeaseApi>(
    api: &A,
    identity: &str,
    gate: &WriteGate,
    shutdown: &ShutdownSignal,
) -> bool {
    loop {
        match try_acquire_once(api, identity).await {
            Ok(Some(_)) => {
                gate.open();
                tracing::info!(
                    target: "k8s_audit",
                    identity,
                    "acquired the leader Lease; this replica reconciles"
                );
                return true;
            }
            Ok(None) => {
                tracing::debug!(target: "k8s_audit", "leader Lease held by a peer; retrying");
            }
            Err(e) => {
                tracing::warn!(
                    target: "k8s_audit",
                    error = %e,
                    "leader Lease acquire attempt failed; retrying"
                );
            }
        }
        tokio::select! {
            _ = shutdown.wait() => return false,
            _ = tokio::time::sleep(RETRY_PERIOD) => {}
        }
    }
}

/// Engine behind [`hold`]: renew until leadership ends. The gate is closed
/// before this returns, on every path.
pub(crate) async fn hold_via<A: LeaseApi>(
    api: &A,
    identity: &str,
    gate: &WriteGate,
    shutdown: &ShutdownSignal,
) -> LeadershipEnd {
    // The instant the last renewal we can prove *started*, which is the
    // instant its `renew_time` stamp was taken and therefore the instant a
    // successor measures the lease from. Not the instant it returned: the
    // difference is the API call's latency, and counting from the return
    // would give this holder that much longer than the successor gives it.
    let mut last_ok = tokio::time::Instant::now();
    loop {
        // Absolute. Every wait below is capped at it, so it is a deadline
        // the gate closes on rather than a condition that gets checked
        // whenever the API server next decides to answer.
        let fence_at = last_ok + SAFETY_DEADLINE;
        let wake_at = std::cmp::min(tokio::time::Instant::now() + RENEW_PERIOD, fence_at);
        tokio::select! {
            _ = shutdown.wait() => {
                // Fence first, then release best-effort so the next
                // candidate does not wait out the TTL.
                gate.close();
                if let Ok(Some(state)) = api.read().await {
                    if state.holder.as_deref() == Some(identity) {
                        let _ = api.replace(&state.released()).await;
                    }
                }
                tracing::info!(target: "k8s_audit", identity, "released the leader Lease on shutdown");
                return LeadershipEnd::Shutdown;
            }
            _ = tokio::time::sleep_until(wake_at) => {}
        }

        // The last attempt is allowed to start exactly at the deadline and
        // is cut off there. A renewal that lands at that instant is a real
        // renewal: its `renew_time` stamp moves the successor's clock along
        // with ours, so continuing is correct. One that does not land
        // reaches the fence below without any further waiting.
        let attempt_started = tokio::time::Instant::now();
        // Capped at the fence: an API server that hangs instead of erroring
        // would otherwise hold this await open past the moment a successor
        // becomes legal, and the incumbent would still be writing `sb.yml`
        // and Gateway status when the successor started.
        let deadline = std::cmp::min(attempt_started + RENEW_DEADLINE, fence_at);
        match tokio::time::timeout_at(deadline, renew_once(api, identity)).await {
            Ok(Ok(RenewOutcome::Renewed(_))) => {
                last_ok = attempt_started;
                tracing::debug!(target: "k8s_audit", identity, "leader Lease renewed");
            }
            Ok(Ok(RenewOutcome::Lost)) => {
                gate.close();
                tracing::warn!(
                    target: "k8s_audit",
                    identity,
                    "leader Lease is no longer ours; fencing all writes and stepping down"
                );
                return LeadershipEnd::Lost;
            }
            Ok(Ok(RenewOutcome::Contended)) | Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    target: "k8s_audit",
                    identity,
                    since_last_renewal_secs = last_ok.elapsed().as_secs(),
                    "leader Lease renewal did not complete"
                );
                if tokio::time::Instant::now() >= fence_at {
                    return fence(gate, identity, last_ok);
                }
            }
        }
    }
}

/// Close the write gate and report the loss. Split out so every path that
/// reaches the safety deadline closes the gate the same way, in the same
/// order, before the caller can see the return value.
fn fence(gate: &WriteGate, identity: &str, last_ok: tokio::time::Instant) -> LeadershipEnd {
    gate.close();
    tracing::warn!(
        target: "k8s_audit",
        identity,
        since_last_renewal_secs = last_ok.elapsed().as_secs(),
        safety_deadline_secs = SAFETY_DEADLINE.as_secs(),
        lease_duration_secs = LEASE_DURATION.as_secs(),
        "could not prove Lease ownership within the safety deadline; \
         fencing all writes and stepping down before a successor can act"
    );
    LeadershipEnd::Lost
}

// --- kube-backed LeaseApi -------------------------------------------------

/// The real `coordination.k8s.io/v1` Lease, via kube.
pub(crate) struct KubeLeaseApi {
    api: Api<Lease>,
    name: String,
    namespace: String,
}

impl KubeLeaseApi {
    pub(crate) fn new(client: Client, namespace: &str, name: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            name: name.to_string(),
            namespace: namespace.to_string(),
        }
    }

    fn to_lease(&self, state: &LeaseState) -> Lease {
        Lease {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                namespace: Some(self.namespace.clone()),
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
    fn read(&self) -> impl Future<Output = anyhow::Result<Option<LeaseState>>> + Send {
        async move {
            Ok(self
                .api
                .get_opt(&self.name)
                .await
                .map_err(anyhow::Error::from)?
                .as_ref()
                .map(from_lease))
        }
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

// --- Public entry points ---------------------------------------------------

/// Block until this replica holds the Lease (returns `true`, gate open) or
/// shutdown arrives first (returns `false`).
pub async fn acquire(
    client: &Client,
    namespace: &str,
    name: &str,
    identity: &str,
    gate: &WriteGate,
    shutdown: &ShutdownSignal,
) -> bool {
    let api = KubeLeaseApi::new(client.clone(), namespace, name);
    acquire_via(&api, identity, gate, shutdown).await
}

/// Renew the Lease until leadership ends. Closes `gate` before returning,
/// on every path; releases the Lease on graceful shutdown.
pub async fn hold(
    client: Client,
    namespace: String,
    name: String,
    identity: String,
    gate: WriteGate,
    shutdown: ShutdownSignal,
) -> LeadershipEnd {
    let api = KubeLeaseApi::new(client, &namespace, &name);
    hold_via(&api, &identity, &gate, &shutdown).await
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown;

    /// In-memory Lease with the API server's conditional-write semantics:
    /// create fails when present, replace fails unless the presented
    /// resourceVersion matches the stored one.
    #[derive(Default)]
    struct FakeLease {
        state: std::sync::Mutex<Option<(LeaseState, u64)>>,
        fail_reads: AtomicBool,
        fail_writes: AtomicBool,
        /// An API server that stops answering rather than erroring. This is
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
    async fn creation_race_admits_exactly_one_candidate() {
        let fake = FakeLease::default();
        let a = try_acquire_once(&fake, "a").await.unwrap();
        let b = try_acquire_once(&fake, "b").await.unwrap();
        assert!(a.is_some(), "the first candidate acquires");
        assert!(b.is_none(), "the second candidate must lose the create");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn stale_takeover_is_version_checked_so_exactly_one_stealer_wins() {
        // Both contenders decide "expired" from the same read. The replace
        // is conditional on that read's resourceVersion, so the second
        // write must conflict. Before WOR-2614 the takeover was a forced
        // apply and both returned success.
        let fake = FakeLease::default();
        fake.seed(expired_lease("crashed"));
        let read_b = fake.read().await.unwrap().unwrap();
        // Contender C wins the takeover first.
        let c = try_acquire_once(&fake, "c").await.unwrap();
        assert!(c.is_some(), "the first stealer wins");
        // Contender B still holds the pre-takeover version token.
        let b = fake
            .replace(&read_b.taken_over_by("b", Utc::now()))
            .await
            .unwrap();
        assert_eq!(b, WriteResult::Conflict, "the second stealer must lose");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("c"));
        assert_eq!(
            fake.stored().unwrap().transitions,
            4,
            "a takeover records a leadership transition"
        );
    }

    #[tokio::test]
    async fn a_fresh_lease_is_not_taken_over() {
        let fake = FakeLease::default();
        let mut fresh = expired_lease("healthy");
        fresh.renew_time = Some(Utc::now());
        fake.seed(fresh);
        let b = try_acquire_once(&fake, "b").await.unwrap();
        assert!(b.is_none(), "a live lease must be respected");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("healthy"));
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_keeps_leadership_past_many_lease_durations() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let (shutdown_sig, shutdown_trig) = shutdown::channel();
        let gate = WriteGate::for_election();
        assert!(!gate.allows(), "an election gate starts closed");
        assert!(acquire_via(&*fake, "a", &gate, &shutdown_sig).await);
        assert!(gate.allows(), "acquisition opens the gate");

        let holder = tokio::spawn({
            let fake = std::sync::Arc::clone(&fake);
            let gate = gate.clone();
            let shutdown_sig = shutdown_sig.clone();
            async move { hold_via(&*fake, "a", &gate, &shutdown_sig).await }
        });

        // Four full lease durations elapse; a one-shot acquire would have
        // let a standby take over three times by now.
        tokio::time::sleep(LEASE_DURATION * 4).await;
        let state = fake.stored().unwrap();
        assert_eq!(state.holder.as_deref(), Some("a"));
        let renew_age = Utc::now().signed_duration_since(state.renew_time.unwrap());
        assert!(gate.allows(), "the holder still writes");
        // Paused tokio time does not advance chrono, so the renew stamp
        // assertion is that renewals happened at all: the version moved.
        assert!(renew_age.num_seconds() <= 60);
        assert!(
            state.resource_version.unwrap().parse::<u64>().unwrap() > 1,
            "renewals must actually write the Lease"
        );

        shutdown_trig.trigger();
        let end = holder.await.unwrap();
        assert_eq!(end, LeadershipEnd::Shutdown);
        assert!(!gate.allows(), "shutdown closes the gate");
        assert_eq!(
            fake.stored().unwrap().holder,
            None,
            "graceful shutdown releases the Lease for the next candidate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn losing_the_holder_field_fences_writes_before_returning() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let (shutdown_sig, _shutdown_trig) = shutdown::channel();
        let gate = WriteGate::for_election();
        assert!(acquire_via(&*fake, "a", &gate, &shutdown_sig).await);

        // A peer takes the Lease over (as it may, once it observes
        // expiry; the fake stands in for that moment).
        let stolen = fake.stored().unwrap().taken_over_by("b", Utc::now());
        fake.seed(stolen);

        let end = hold_via(&*fake, "a", &gate, &shutdown_sig).await;
        assert_eq!(end, LeadershipEnd::Lost);
        assert!(
            !gate.allows(),
            "the gate must be closed by the time the loss is reported"
        );
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("b"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_api_outage_past_the_safety_deadline_fences_the_holder() {
        // An API server that HANGS, which is the case the old shape got
        // wrong. The safety-deadline check ran only after
        // `timeout(RENEW_DEADLINE, ..)` returned, so with a call that never
        // answers the worst case was RENEW_PERIOD + RENEW_DEADLINE, which
        // was 5s + 10s = 15s = LEASE_DURATION: the gate closed at the exact
        // moment the standby's takeover became legal, not before it. Two
        // writers of `sb.yml` and of Gateway status, for as long as the
        // deposed leader took to notice.
        //
        // The old version of this test injected fast errors only and
        // asserted `< LEASE_DURATION + RENEW_PERIOD` (20s) under a message
        // that claimed 15s, so it could not have caught any of that.
        let fake = std::sync::Arc::new(FakeLease::default());
        let (shutdown_sig, _shutdown_trig) = shutdown::channel();
        let gate = WriteGate::for_election();
        assert!(acquire_via(&*fake, "a", &gate, &shutdown_sig).await);

        // The successor measures from the `renew_time` stamped by the
        // acquisition that just landed, so its clock starts here.
        let successor_clock_starts = tokio::time::Instant::now();
        fake.hang.store(true, Ordering::SeqCst);

        let end = hold_via(&*fake, "a", &gate, &shutdown_sig).await;
        assert_eq!(end, LeadershipEnd::Lost);
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
             took {elapsed:?} against a {:?} lease",
            LEASE_DURATION
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_erroring_api_fences_on_the_same_absolute_deadline() {
        // The same bound with the other failure mode, so the deadline is
        // pinned as absolute rather than as "one attempt after the last
        // successful one".
        let fake = std::sync::Arc::new(FakeLease::default());
        let (shutdown_sig, _shutdown_trig) = shutdown::channel();
        let gate = WriteGate::for_election();
        assert!(acquire_via(&*fake, "a", &gate, &shutdown_sig).await);

        let successor_clock_starts = tokio::time::Instant::now();
        fake.fail_reads.store(true, Ordering::SeqCst);
        fake.fail_writes.store(true, Ordering::SeqCst);

        let end = hold_via(&*fake, "a", &gate, &shutdown_sig).await;
        assert_eq!(end, LeadershipEnd::Lost);
        assert!(!gate.allows());
        let elapsed = successor_clock_starts.elapsed();
        assert!(elapsed >= SAFETY_DEADLINE, "took {elapsed:?}");
        assert!(
            elapsed <= SAFETY_DEADLINE + Duration::from_millis(2),
            "the fence deadline is absolute, not one attempt past it; took {elapsed:?}"
        );
    }

    #[test]
    fn the_self_fence_deadline_is_strictly_inside_the_takeover_threshold() {
        // Three claims are made about these numbers in four places (this
        // module's docs, docs/gateway-api.md, the Deployment manifest, and
        // the CHANGELOG). Pin them here so a constant cannot drift out from
        // under the prose.
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

    #[tokio::test(start_paused = true)]
    async fn a_short_api_outage_does_not_cost_leadership() {
        let fake = std::sync::Arc::new(FakeLease::default());
        let (shutdown_sig, shutdown_trig) = shutdown::channel();
        let gate = WriteGate::for_election();
        assert!(acquire_via(&*fake, "a", &gate, &shutdown_sig).await);

        fake.fail_writes.store(true, Ordering::SeqCst);
        let holder = tokio::spawn({
            let fake = std::sync::Arc::clone(&fake);
            let gate = gate.clone();
            let shutdown_sig = shutdown_sig.clone();
            async move { hold_via(&*fake, "a", &gate, &shutdown_sig).await }
        });
        // One renewal fails, then the API recovers well inside the
        // safety deadline.
        tokio::time::sleep(RENEW_PERIOD + Duration::from_secs(1)).await;
        fake.fail_writes.store(false, Ordering::SeqCst);
        tokio::time::sleep(RENEW_PERIOD * 2).await;
        assert!(gate.allows(), "a recovered holder keeps writing");
        assert_eq!(fake.stored().unwrap().holder.as_deref(), Some("a"));

        shutdown_trig.trigger();
        assert_eq!(holder.await.unwrap(), LeadershipEnd::Shutdown);
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
    fn identity_is_distinct_across_calls() {
        // Two incarnations in the same pod (same HOSTNAME, maybe even the
        // same pid after a container restart) must not collide.
        let a = build_identity();
        std::thread::sleep(Duration::from_nanos(50));
        let b = build_identity();
        assert_ne!(a, b);
    }
}
