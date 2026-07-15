//! Request-lifetime ownership for accepted governance reservations.

use std::{fmt, sync::Arc, time::Duration};

use sbproxy_ai::governance::{
    GovernanceError, GovernanceStore, Release, ReleaseRequest, RenewRequest, Reservation,
    SettleRequest, Settlement,
};

/// Terminal state already reached by a governance lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceLeaseTerminal {
    /// Actual usage was charged successfully.
    Settled,
    /// Reserved units were returned without charging usage.
    Released,
}

/// Result of attempting a terminal lease transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceLeaseTransition<T> {
    /// This call completed the transition and carries the backend result.
    Applied(T),
    /// An earlier call already completed this lease.
    AlreadyTerminal(GovernanceLeaseTerminal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    Active,
    Settled,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropAction {
    Release,
    Settle {
        actual_tokens: u64,
        actual_micro_usd: u64,
    },
}

impl LeaseState {
    fn terminal(self) -> Option<GovernanceLeaseTerminal> {
        match self {
            Self::Active => None,
            Self::Settled => Some(GovernanceLeaseTerminal::Settled),
            Self::Released => Some(GovernanceLeaseTerminal::Released),
        }
    }
}

/// Drop-safe owner of one accepted governance reservation.
///
/// A successful settlement or release is terminal. Backend errors leave the
/// lease active so the caller can retry the idempotent operation. If an active
/// lease reaches `Drop`, it schedules a best-effort terminal repair on the
/// current Tokio runtime. The repair releases an unused reservation or settles
/// the bounded usage most recently armed by the request path.
pub struct GovernanceLease {
    store: Arc<dyn GovernanceStore>,
    reservation: Reservation,
    state: LeaseState,
    drop_action: Option<DropAction>,
}

/// Request-owned reservation plus the immutable rate selected at admission.
///
/// Keeping the rate with the lease makes settlement stable across config
/// reloads and lets streaming and buffered response paths share one charge.
pub struct GovernanceCharge {
    lease: GovernanceLease,
    price: Option<sbproxy_ai::budget::ModelPrice>,
    renewal_task: Option<tokio::task::JoinHandle<()>>,
}

impl GovernanceCharge {
    /// Pair an accepted lease with its resolved token price. `None` represents
    /// the explicit zero-cost missing-rate policy.
    pub fn new(lease: GovernanceLease, price: Option<sbproxy_ai::budget::ModelPrice>) -> Self {
        let renewal_task = spawn_renewal_task(&lease);
        Self {
            lease,
            price,
            renewal_task,
        }
    }

    /// Secret-free reservation metadata for response and audit handling.
    pub fn reservation(&self) -> &Reservation {
        self.lease.reservation()
    }

    /// Extend the active lease without changing held units.
    pub async fn renew(
        &mut self,
    ) -> Result<GovernanceLeaseTransition<Reservation>, GovernanceError> {
        self.lease.renew().await
    }

    /// Arm the full admitted ceiling for a drop after provider output begins.
    pub fn arm_conservative_drop_settlement(&mut self) -> GovernanceLeaseTransition<()> {
        let reserved = self.lease.reservation().reserved;
        self.lease
            .arm_drop_settlement(reserved.tokens, reserved.micro_usd)
    }

    /// Return whether provider work has armed conservative settlement for an
    /// unknown outcome or request drop.
    pub fn conservative_drop_settlement_armed(&self) -> bool {
        matches!(self.lease.drop_action, Some(DropAction::Settle { .. }))
    }

    /// Settle exact provider token usage with deterministic micro-USD rounding.
    pub async fn settle_tokens(
        &mut self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<GovernanceLeaseTransition<Settlement>, GovernanceError> {
        let actual_tokens =
            input_tokens
                .checked_add(output_tokens)
                .ok_or(GovernanceError::ArithmeticOverflow {
                    field: "actual_tokens",
                })?;
        let actual_micro_usd = match self.price {
            Some(price) => {
                sbproxy_ai::budget::governance_micro_usd(price, input_tokens, output_tokens).ok_or(
                    GovernanceError::ArithmeticOverflow {
                        field: "actual_micro_usd",
                    },
                )?
            }
            None => 0,
        };
        let result = self.lease.settle(actual_tokens, actual_micro_usd).await;
        if result.is_ok() {
            self.stop_renewal().await;
        }
        result
    }

    /// Settle the conservative admitted ceiling when output was emitted but
    /// the provider supplied no parseable usage block.
    pub async fn settle_ceiling(
        &mut self,
    ) -> Result<GovernanceLeaseTransition<Settlement>, GovernanceError> {
        let reserved = self.lease.reservation().reserved;
        let result = self.lease.settle(reserved.tokens, reserved.micro_usd).await;
        if result.is_ok() {
            self.stop_renewal().await;
        }
        result
    }

    /// Release an unused reservation without charging provider usage.
    pub async fn release(&mut self) -> Result<GovernanceLeaseTransition<Release>, GovernanceError> {
        let result = self.lease.release().await;
        if result.is_ok() {
            self.stop_renewal().await;
        }
        result
    }

    async fn stop_renewal(&mut self) {
        if let Some(task) = self.renewal_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

fn spawn_renewal_task(lease: &GovernanceLease) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    let reservation = lease.reservation();
    let lease_millis = reservation
        .expires_at_millis
        .saturating_sub(reservation.created_at_millis)
        .max(2);
    let delay = Duration::from_millis((lease_millis / 2).max(1));
    let store = Arc::clone(&lease.store);
    let request = RenewRequest {
        reservation_id: reservation.reservation_id.clone(),
        key_id: reservation.key_id.clone(),
    };
    Some(runtime.spawn(async move {
        let ttl = Duration::from_millis(lease_millis);
        let retry_delay = Duration::from_millis((lease_millis / 10).clamp(1, 1_000));
        let mut next_delay = delay;
        let mut known_deadline = tokio::time::Instant::now() + ttl;
        loop {
            // Sleeping after every completed renewal avoids Tokio interval
            // catch-up bursts and keeps the healthy Redis path bounded at two
            // calls per lease TTL even when the runtime is briefly stalled.
            tokio::time::sleep(next_delay).await;
            match store.renew(request.clone()).await {
                Ok(_) => {
                    known_deadline = tokio::time::Instant::now() + ttl;
                    next_delay = delay;
                }
                Err(error) => {
                    let now = tokio::time::Instant::now();
                    if now + retry_delay >= known_deadline {
                        tracing::warn!(
                            error = %error,
                            "AI governance lease renewal failed until its known expiry"
                        );
                        break;
                    }
                    tracing::warn!(
                        error = %error,
                        "AI governance lease renewal failed; retrying before expiry"
                    );
                    next_delay = retry_delay;
                }
            }
        }
    }))
}

impl Drop for GovernanceCharge {
    fn drop(&mut self) {
        if let Some(task) = self.renewal_task.take() {
            task.abort();
        }
    }
}

impl fmt::Debug for GovernanceCharge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernanceCharge")
            .field("lease", &self.lease)
            .field("priced", &self.price.is_some())
            .finish()
    }
}

impl GovernanceLease {
    /// Take ownership of an accepted reservation and its backing store.
    pub fn new(store: Arc<dyn GovernanceStore>, reservation: Reservation) -> Self {
        Self {
            store,
            reservation,
            state: LeaseState::Active,
            drop_action: Some(DropAction::Release),
        }
    }

    /// Return whether this reservation still needs settlement or release.
    pub fn is_active(&self) -> bool {
        self.state == LeaseState::Active
    }

    /// Return the secret-free reservation metadata owned by this lease.
    pub fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    /// Extend an active reservation lease without changing held units.
    pub async fn renew(
        &mut self,
    ) -> Result<GovernanceLeaseTransition<Reservation>, GovernanceError> {
        if let Some(terminal) = self.state.terminal() {
            return Ok(GovernanceLeaseTransition::AlreadyTerminal(terminal));
        }
        let renewed = self
            .store
            .renew(RenewRequest {
                reservation_id: self.reservation.reservation_id.clone(),
                key_id: self.reservation.key_id.clone(),
            })
            .await?;
        self.reservation = renewed.clone();
        Ok(GovernanceLeaseTransition::Applied(renewed))
    }

    /// Arm bounded usage for best-effort settlement if this lease is dropped.
    ///
    /// Call this when provider work may already be billable. A later explicit
    /// release replaces the fallback with release because it declares that the
    /// request finished without usage.
    pub fn arm_drop_settlement(
        &mut self,
        actual_tokens: u64,
        actual_micro_usd: u64,
    ) -> GovernanceLeaseTransition<()> {
        if let Some(terminal) = self.state.terminal() {
            return GovernanceLeaseTransition::AlreadyTerminal(terminal);
        }
        self.drop_action = Some(DropAction::Settle {
            actual_tokens,
            actual_micro_usd,
        });
        GovernanceLeaseTransition::Applied(())
    }

    /// Charge actual token and micro-USD usage at most once for this lease.
    pub async fn settle(
        &mut self,
        actual_tokens: u64,
        actual_micro_usd: u64,
    ) -> Result<GovernanceLeaseTransition<Settlement>, GovernanceError> {
        if let Some(terminal) = self.state.terminal() {
            return Ok(GovernanceLeaseTransition::AlreadyTerminal(terminal));
        }
        self.drop_action = Some(DropAction::Settle {
            actual_tokens,
            actual_micro_usd,
        });

        let settlement = self
            .store
            .settle(SettleRequest {
                reservation_id: self.reservation.reservation_id.clone(),
                key_id: self.reservation.key_id.clone(),
                actual_tokens,
                actual_micro_usd,
            })
            .await?;
        self.state = LeaseState::Settled;
        self.drop_action = None;
        Ok(GovernanceLeaseTransition::Applied(settlement))
    }

    /// Return held units without charging usage at most once for this lease.
    pub async fn release(&mut self) -> Result<GovernanceLeaseTransition<Release>, GovernanceError> {
        if let Some(terminal) = self.state.terminal() {
            return Ok(GovernanceLeaseTransition::AlreadyTerminal(terminal));
        }
        self.drop_action = Some(DropAction::Release);

        let release = self
            .store
            .release(ReleaseRequest {
                reservation_id: self.reservation.reservation_id.clone(),
                key_id: self.reservation.key_id.clone(),
            })
            .await?;
        self.state = LeaseState::Released;
        self.drop_action = None;
        Ok(GovernanceLeaseTransition::Applied(release))
    }
}

impl fmt::Debug for GovernanceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernanceLease")
            .field("reservation_id", &self.reservation.reservation_id)
            .field("key_id", &self.reservation.key_id)
            .field("policy_revision", &self.reservation.policy_revision)
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for GovernanceLease {
    fn drop(&mut self) {
        if !self.is_active() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(action) = self.drop_action else {
            return;
        };
        let store = Arc::clone(&self.store);
        let reservation_id = self.reservation.reservation_id.clone();
        let key_id = self.reservation.key_id.clone();
        drop(runtime.spawn(async move {
            match action {
                DropAction::Release => {
                    let _ = store
                        .release(ReleaseRequest {
                            reservation_id,
                            key_id,
                        })
                        .await;
                }
                DropAction::Settle {
                    actual_tokens,
                    actual_micro_usd,
                } => {
                    let _ = store
                        .settle(SettleRequest {
                            reservation_id,
                            key_id,
                            actual_tokens,
                            actual_micro_usd,
                        })
                        .await;
                }
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use parking_lot::Mutex;
    use sbproxy_ai::governance::{
        CounterSnapshot, GovernanceBackendHealth, GovernanceBackendStatus, GovernanceConsistency,
        GovernanceError, GovernanceSnapshot, GovernanceStore, GovernanceUsage, Release,
        ReleaseRequest, RenewRequest, Reservation, ReserveRequest, SettleRequest, Settlement,
        SnapshotKey,
    };
    use tokio::sync::mpsc;

    use super::{
        GovernanceCharge, GovernanceLease, GovernanceLeaseTerminal, GovernanceLeaseTransition,
    };

    const STORE_CREDENTIAL: &str = "redis://operator:top-secret@example.invalid";

    #[derive(Default)]
    struct FakeState {
        renew_requests: Vec<RenewRequest>,
        settle_requests: Vec<SettleRequest>,
        release_requests: Vec<ReleaseRequest>,
        settle_failures_remaining: usize,
        release_failures_remaining: usize,
    }

    struct FakeStore {
        reservation: Reservation,
        state: Mutex<FakeState>,
        settle_tx: Option<mpsc::UnboundedSender<SettleRequest>>,
        release_tx: Option<mpsc::UnboundedSender<ReleaseRequest>>,
        credential: String,
    }

    impl FakeStore {
        fn new(reservation: Reservation) -> Self {
            Self {
                reservation,
                state: Mutex::new(FakeState::default()),
                settle_tx: None,
                release_tx: None,
                credential: STORE_CREDENTIAL.to_string(),
            }
        }

        fn with_settle_tx(mut self, tx: mpsc::UnboundedSender<SettleRequest>) -> Self {
            self.settle_tx = Some(tx);
            self
        }

        fn with_release_tx(mut self, tx: mpsc::UnboundedSender<ReleaseRequest>) -> Self {
            self.release_tx = Some(tx);
            self
        }

        fn fail_next_settle(&self) {
            self.state.lock().settle_failures_remaining += 1;
        }

        fn fail_next_release(&self) {
            self.state.lock().release_failures_remaining += 1;
        }

        fn settle_requests(&self) -> Vec<SettleRequest> {
            self.state.lock().settle_requests.clone()
        }

        fn renew_requests(&self) -> Vec<RenewRequest> {
            self.state.lock().renew_requests.clone()
        }

        fn release_requests(&self) -> Vec<ReleaseRequest> {
            self.state.lock().release_requests.clone()
        }
    }

    #[async_trait]
    impl GovernanceStore for FakeStore {
        async fn reserve(&self, _request: ReserveRequest) -> Result<Reservation, GovernanceError> {
            Ok(self.reservation.clone())
        }

        async fn renew(&self, request: RenewRequest) -> Result<Reservation, GovernanceError> {
            self.state.lock().renew_requests.push(request);
            Ok(self.reservation.clone())
        }

        async fn settle(&self, request: SettleRequest) -> Result<Settlement, GovernanceError> {
            let mut state = self.state.lock();
            state.settle_requests.push(request.clone());
            if state.settle_failures_remaining > 0 {
                state.settle_failures_remaining -= 1;
                return Err(GovernanceError::InternalInvariant {
                    field: "injected_settle_failure",
                });
            }
            drop(state);

            if let Some(tx) = &self.settle_tx {
                let _ = tx.send(request.clone());
            }
            Ok(Settlement {
                reservation_id: request.reservation_id,
                key_id: request.key_id,
                policy_revision: self.reservation.policy_revision,
                reserved: self.reservation.reserved,
                actual: GovernanceUsage {
                    requests: 1,
                    tokens: request.actual_tokens,
                    micro_usd: request.actual_micro_usd,
                },
                tokens_exceeded_reservation: request.actual_tokens
                    > self.reservation.reserved.tokens,
                micro_usd_exceeded_reservation: request.actual_micro_usd
                    > self.reservation.reserved.micro_usd,
                settled_at_millis: 1_100,
            })
        }

        async fn release(&self, request: ReleaseRequest) -> Result<Release, GovernanceError> {
            let mut state = self.state.lock();
            state.release_requests.push(request.clone());
            if state.release_failures_remaining > 0 {
                state.release_failures_remaining -= 1;
                return Err(GovernanceError::InternalInvariant {
                    field: "injected_release_failure",
                });
            }
            drop(state);

            if let Some(tx) = &self.release_tx {
                let _ = tx.send(request.clone());
            }
            Ok(Release {
                reservation_id: request.reservation_id,
                key_id: request.key_id,
                policy_revision: self.reservation.policy_revision,
                released: self.reservation.reserved,
                released_at_millis: 1_100,
            })
        }

        async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
            let empty_counter = || CounterSnapshot {
                limit: None,
                used: 0,
                reserved: 0,
                remaining: None,
                reset_at_millis: None,
            };
            Ok(GovernanceSnapshot {
                key_id: key.key_id,
                policy_revision: key.policy_revision,
                requests_per_window: empty_counter(),
                tokens_per_window: empty_counter(),
                total_tokens: empty_counter(),
                total_micro_usd: empty_counter(),
                backend: self.health().await,
            })
        }

        async fn health(&self) -> GovernanceBackendHealth {
            GovernanceBackendHealth {
                backend: "fake".to_string(),
                consistency: GovernanceConsistency::Approximate,
                status: GovernanceBackendStatus::Healthy,
                checked_at_millis: 1_000,
            }
        }
    }

    fn reservation() -> Reservation {
        Reservation {
            reservation_id: "reservation-01".to_string(),
            key_id: "key-01".to_string(),
            policy_revision: 7,
            reserved: GovernanceUsage {
                requests: 1,
                tokens: 100,
                micro_usd: 250,
            },
            created_at_millis: 1_000,
            expires_at_millis: 2_000,
            window_reset_at_millis: 60_000,
        }
    }

    fn lease(store: &Arc<FakeStore>) -> GovernanceLease {
        let store: Arc<dyn GovernanceStore> = store.clone();
        GovernanceLease::new(store, reservation())
    }

    #[tokio::test]
    async fn charge_renews_from_admission_until_the_terminal_transition() {
        let mut short = reservation();
        short.expires_at_millis = short.created_at_millis + 20;
        let store = Arc::new(FakeStore::new(short.clone()));
        let dyn_store: Arc<dyn GovernanceStore> = store.clone();
        let lease = GovernanceLease::new(dyn_store, short);
        let mut charge = GovernanceCharge::new(lease, None);

        tokio::time::sleep(Duration::from_millis(45)).await;
        let renewals = store.renew_requests().len();
        assert!(
            (2..=6).contains(&renewals),
            "renewal loop must be active and bounded, got {renewals} calls"
        );

        charge.release().await.expect("terminal release succeeds");
        let terminal_count = store.renew_requests().len();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(store.renew_requests().len(), terminal_count);
    }

    #[tokio::test]
    async fn failed_terminal_transition_keeps_renewal_alive_for_retry() {
        let mut short = reservation();
        short.expires_at_millis = short.created_at_millis + 20;
        let store = Arc::new(FakeStore::new(short.clone()));
        store.fail_next_settle();
        let dyn_store: Arc<dyn GovernanceStore> = store.clone();
        let lease = GovernanceLease::new(dyn_store, short);
        let mut charge = GovernanceCharge::new(lease, None);

        assert!(charge.settle_tokens(5, 7).await.is_err());
        let before_retry = store.renew_requests().len();
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(store.renew_requests().len() > before_retry);

        charge
            .settle_tokens(5, 7)
            .await
            .expect("idempotent settlement retry succeeds");
        let terminal_count = store.renew_requests().len();
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(store.renew_requests().len(), terminal_count);
    }

    #[tokio::test]
    async fn settle_forwards_actual_usage_once_and_disarms_drop_release() {
        let store = Arc::new(FakeStore::new(reservation()));
        let mut lease = lease(&store);

        let transition = lease.settle(42, 90).await.expect("settlement succeeds");

        let GovernanceLeaseTransition::Applied(settlement) = transition else {
            panic!("first settlement must apply");
        };
        assert_eq!(settlement.actual.tokens, 42);
        assert_eq!(settlement.actual.micro_usd, 90);
        assert_eq!(
            store.settle_requests(),
            vec![SettleRequest {
                reservation_id: "reservation-01".to_string(),
                key_id: "key-01".to_string(),
                actual_tokens: 42,
                actual_micro_usd: 90,
            }]
        );

        drop(lease);
        tokio::task::yield_now().await;
        assert!(store.release_requests().is_empty());
    }

    #[tokio::test]
    async fn explicit_release_runs_once_and_disarms_drop_release() {
        let store = Arc::new(FakeStore::new(reservation()));
        let mut lease = lease(&store);

        let transition = lease.release().await.expect("release succeeds");

        assert!(matches!(transition, GovernanceLeaseTransition::Applied(_)));
        drop(lease);
        tokio::task::yield_now().await;
        assert_eq!(store.release_requests().len(), 1);
        assert!(store.settle_requests().is_empty());
    }

    #[tokio::test]
    async fn duplicate_and_cross_terminal_calls_are_typed_without_backend_calls() {
        let store = Arc::new(FakeStore::new(reservation()));
        let mut lease = lease(&store);
        assert!(matches!(
            lease.settle(10, 20).await,
            Ok(GovernanceLeaseTransition::Applied(_))
        ));

        assert_eq!(
            lease.settle(10, 20).await,
            Ok(GovernanceLeaseTransition::AlreadyTerminal(
                GovernanceLeaseTerminal::Settled
            ))
        );
        assert_eq!(
            lease.release().await,
            Ok(GovernanceLeaseTransition::AlreadyTerminal(
                GovernanceLeaseTerminal::Settled
            ))
        );
        assert_eq!(store.settle_requests().len(), 1);
        assert!(store.release_requests().is_empty());
    }

    #[tokio::test]
    async fn backend_failure_keeps_lease_active_for_an_idempotent_retry() {
        let store = Arc::new(FakeStore::new(reservation()));
        store.fail_next_settle();
        let mut lease = lease(&store);

        assert!(matches!(
            lease.settle(10, 20).await,
            Err(GovernanceError::InternalInvariant {
                field: "injected_settle_failure"
            })
        ));
        assert!(lease.is_active());
        assert!(matches!(
            lease.settle(10, 20).await,
            Ok(GovernanceLeaseTransition::Applied(_))
        ));
        assert_eq!(store.settle_requests().len(), 2);
    }

    #[tokio::test]
    async fn failed_explicit_release_is_repaired_by_drop() {
        let (release_tx, mut release_rx) = mpsc::unbounded_channel();
        let store = Arc::new(FakeStore::new(reservation()).with_release_tx(release_tx));
        store.fail_next_release();
        let mut lease = lease(&store);

        assert!(lease.release().await.is_err());
        assert!(lease.is_active());
        drop(lease);

        let request = tokio::time::timeout(std::time::Duration::from_secs(1), release_rx.recv())
            .await
            .expect("drop release is scheduled")
            .expect("drop release request is sent");
        assert_eq!(request.reservation_id, "reservation-01");
        assert_eq!(store.release_requests().len(), 2);
    }

    #[tokio::test]
    async fn dropping_an_active_lease_schedules_best_effort_release() {
        let (release_tx, mut release_rx) = mpsc::unbounded_channel();
        let store = Arc::new(FakeStore::new(reservation()).with_release_tx(release_tx));

        drop(lease(&store));

        let request = tokio::time::timeout(std::time::Duration::from_secs(1), release_rx.recv())
            .await
            .expect("drop release is scheduled")
            .expect("drop release request is sent");
        assert_eq!(
            request,
            ReleaseRequest {
                reservation_id: "reservation-01".to_string(),
                key_id: "key-01".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn dropping_an_armed_lease_schedules_best_effort_settlement() {
        let (settle_tx, mut settle_rx) = mpsc::unbounded_channel();
        let store = Arc::new(FakeStore::new(reservation()).with_settle_tx(settle_tx));
        let mut lease = lease(&store);
        assert_eq!(
            lease.arm_drop_settlement(37, 81),
            GovernanceLeaseTransition::Applied(())
        );

        drop(lease);

        let request = tokio::time::timeout(std::time::Duration::from_secs(1), settle_rx.recv())
            .await
            .expect("drop settlement is scheduled")
            .expect("drop settlement request is sent");
        assert_eq!(
            request,
            SettleRequest {
                reservation_id: "reservation-01".to_string(),
                key_id: "key-01".to_string(),
                actual_tokens: 37,
                actual_micro_usd: 81,
            }
        );
        assert!(store.release_requests().is_empty());
    }

    #[tokio::test]
    async fn failed_settlement_is_repaired_by_drop_settlement() {
        let (settle_tx, mut settle_rx) = mpsc::unbounded_channel();
        let store = Arc::new(FakeStore::new(reservation()).with_settle_tx(settle_tx));
        store.fail_next_settle();
        let mut lease = lease(&store);

        assert!(lease.settle(29, 63).await.is_err());
        assert!(lease.is_active());
        drop(lease);

        let request = tokio::time::timeout(std::time::Duration::from_secs(1), settle_rx.recv())
            .await
            .expect("failed settlement is retried by drop")
            .expect("drop settlement request is sent");
        assert_eq!(request.actual_tokens, 29);
        assert_eq!(request.actual_micro_usd, 63);
        assert_eq!(store.settle_requests().len(), 2);
        assert!(store.release_requests().is_empty());
    }

    #[test]
    fn debug_output_is_secret_free_and_does_not_format_the_store() {
        let store = Arc::new(FakeStore::new(reservation()));
        assert_eq!(store.credential, STORE_CREDENTIAL);
        let lease = lease(&store);

        let debug = format!("{lease:?}");

        assert!(debug.contains("reservation-01"));
        assert!(debug.contains("key-01"));
        assert!(!debug.contains(STORE_CREDENTIAL));
        assert!(!debug.contains("top-secret"));
    }
}
