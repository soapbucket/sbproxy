//! Request-lifetime ownership for accepted governance reservations.

use std::{fmt, sync::Arc};

use sbproxy_ai::governance::{
    GovernanceError, GovernanceStore, Release, ReleaseRequest, Reservation, SettleRequest,
    Settlement,
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use parking_lot::Mutex;
    use sbproxy_ai::governance::{
        CounterSnapshot, GovernanceBackendHealth, GovernanceBackendStatus, GovernanceConsistency,
        GovernanceError, GovernanceSnapshot, GovernanceStore, GovernanceUsage, Release,
        ReleaseRequest, Reservation, ReserveRequest, SettleRequest, Settlement, SnapshotKey,
    };
    use tokio::sync::mpsc;

    use super::{GovernanceLease, GovernanceLeaseTerminal, GovernanceLeaseTransition};

    const STORE_CREDENTIAL: &str = "redis://operator:top-secret@example.invalid";

    #[derive(Default)]
    struct FakeState {
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

        fn release_requests(&self) -> Vec<ReleaseRequest> {
            self.state.lock().release_requests.clone()
        }
    }

    #[async_trait]
    impl GovernanceStore for FakeStore {
        async fn reserve(&self, _request: ReserveRequest) -> Result<Reservation, GovernanceError> {
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
