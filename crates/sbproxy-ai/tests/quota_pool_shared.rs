use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::future::join_all;
use sbproxy_ai::{
    governance::{
        GovernanceBackendHealth, GovernanceError, GovernanceLimits, GovernanceSnapshot,
        GovernanceStore, InMemoryGovernanceStore, Release, ReleaseRequest, RenewRequest,
        Reservation, ReserveRequest, SettleRequest, Settlement, SnapshotKey,
    },
    governance_crdt::{merge_contributions, GovernanceContribution},
    quota_pool::{
        LocalQuotaPool, PoolDeny, PoolError, PoolUsage, QuotaPoolAdmission, QuotaPoolConfig,
        QuotaPoolConsistency, QuotaPoolDimension, QuotaPoolFailureMode, QuotaPoolPolicy,
        QuotaPoolStore, SharedQuotaPool,
    },
};

struct ObservedGovernance {
    inner: InMemoryGovernanceStore,
    fail_reserve: bool,
    fail_settle: bool,
    fail_release: bool,
    settled_keys: std::sync::Mutex<Vec<String>>,
    released_keys: std::sync::Mutex<Vec<String>>,
}

impl ObservedGovernance {
    fn available() -> Self {
        Self {
            inner: InMemoryGovernanceStore::default(),
            fail_reserve: false,
            fail_settle: false,
            fail_release: false,
            settled_keys: std::sync::Mutex::new(Vec::new()),
            released_keys: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn unavailable() -> Self {
        Self {
            inner: InMemoryGovernanceStore::default(),
            fail_reserve: true,
            fail_settle: false,
            fail_release: false,
            settled_keys: std::sync::Mutex::new(Vec::new()),
            released_keys: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn release_unavailable() -> Self {
        Self {
            inner: InMemoryGovernanceStore::default(),
            fail_reserve: false,
            fail_settle: false,
            fail_release: true,
            settled_keys: std::sync::Mutex::new(Vec::new()),
            released_keys: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn settle_unavailable() -> Self {
        Self {
            inner: InMemoryGovernanceStore::default(),
            fail_reserve: false,
            fail_settle: true,
            fail_release: false,
            settled_keys: std::sync::Mutex::new(Vec::new()),
            released_keys: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl GovernanceStore for ObservedGovernance {
    async fn reserve(&self, request: ReserveRequest) -> Result<Reservation, GovernanceError> {
        if self.fail_reserve {
            return Err(GovernanceError::BackendUnavailable { backend: "test" });
        }
        self.inner.reserve(request).await
    }

    async fn renew(&self, request: RenewRequest) -> Result<Reservation, GovernanceError> {
        self.inner.renew(request).await
    }

    async fn settle(&self, request: SettleRequest) -> Result<Settlement, GovernanceError> {
        if self.fail_settle {
            return Err(GovernanceError::BackendUnavailable { backend: "test" });
        }
        self.settled_keys
            .lock()
            .expect("settlement recorder lock")
            .push(request.key_id.clone());
        self.inner.settle(request).await
    }

    async fn release(&self, request: ReleaseRequest) -> Result<Release, GovernanceError> {
        if self.fail_release {
            return Err(GovernanceError::BackendUnavailable { backend: "test" });
        }
        self.released_keys
            .lock()
            .expect("release recorder lock")
            .push(request.key_id.clone());
        self.inner.release(request).await
    }

    async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
        self.inner.snapshot(key).await
    }

    async fn health(&self) -> GovernanceBackendHealth {
        self.inner.health().await
    }
}

fn config(
    name: &str,
    total_limit: u64,
    weights: &[(&str, u32)],
    policy: QuotaPoolPolicy,
) -> QuotaPoolConfig {
    QuotaPoolConfig {
        name: name.to_string(),
        window: Duration::from_secs(86_400),
        total_limit,
        weights: weights
            .iter()
            .map(|(member, weight)| ((*member).to_string(), *weight))
            .collect::<HashMap<_, _>>(),
        policy,
        dimension: QuotaPoolDimension::Request,
        consistency: QuotaPoolConsistency::Approximate,
        failure_mode: QuotaPoolFailureMode::Closed,
        failure_posture: None,
    }
}

fn quota_pool_counter(name: &str, pool: &str) -> f64 {
    prometheus::gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.get_metric().iter().find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "pool" && label.value() == pool)
            })
        })
        .map(|metric| metric.get_counter().value())
        .unwrap_or(0.0)
}

#[tokio::test]
async fn backend_unavailability_remains_distinct_from_a_pool_denial() {
    let governance: Arc<dyn GovernanceStore> = Arc::new(ObservedGovernance::unavailable());
    let pool = SharedQuotaPool::new(
        vec![config(
            "unavailable",
            2,
            &[("virtual-key-a", 1)],
            QuotaPoolPolicy::Burst,
        )],
        governance,
    )
    .expect("valid shared pool");

    assert_eq!(
        pool.reserve("unavailable", "virtual-key-a", 1, "unavailable-attempt")
            .await,
        Err(PoolError::BackendUnavailable)
    );
}

#[tokio::test]
async fn disabled_quota_admission_is_a_noop_even_when_binding_failed() {
    let admission = QuotaPoolAdmission::new(
        None,
        Err(PoolError::BackendUnavailable),
        Err(PoolError::InvalidState),
    );

    admission
        .consume("")
        .await
        .expect("disabled quota admission is a no-op");
}

#[tokio::test]
async fn quota_admission_consumes_once_and_only_fails_open_backend_errors() {
    let pool_name = "admission-context";
    let mut pool_config = config(pool_name, 1, &[("virtual-key-a", 1)], QuotaPoolPolicy::Hard);
    pool_config.failure_mode = QuotaPoolFailureMode::AllowUnreserved;
    let store: Arc<dyn QuotaPoolStore> =
        Arc::new(LocalQuotaPool::new(vec![pool_config.clone()]).expect("valid local pool"));
    let admission = QuotaPoolAdmission::new(
        Some(pool_config.clone()),
        Ok(Some(store)),
        Ok("virtual-key-a".to_string()),
    );

    admission
        .consume("admission-accounted")
        .await
        .expect("first attempt consumes the only unit");
    assert!(matches!(
        admission.consume("admission-denied").await,
        Err(PoolError::Denied(_))
    ));

    let fail_open_name = "admission-fail-open";
    pool_config.name = fail_open_name.to_string();
    let before = quota_pool_counter("sbproxy_ai_quota_pool_fail_open_total", fail_open_name);
    let unavailable = QuotaPoolAdmission::new(
        Some(pool_config),
        Err(PoolError::BackendUnavailable),
        Ok("virtual-key-a".to_string()),
    );
    unavailable
        .clone()
        .consume("admission-unreserved-1")
        .await
        .expect("backend failure may fail open");
    unavailable
        .consume("admission-unreserved-2")
        .await
        .expect("each backend-failed attempt may fail open");
    assert_eq!(
        quota_pool_counter("sbproxy_ai_quota_pool_fail_open_total", fail_open_name) - before,
        2.0,
        "fail-open increments once per actual unreserved attempt"
    );

    let mut invalid_config = config(
        "admission-invalid",
        1,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    );
    invalid_config.failure_mode = QuotaPoolFailureMode::AllowUnreserved;
    let invalid_store: Arc<dyn QuotaPoolStore> =
        Arc::new(LocalQuotaPool::new(vec![invalid_config.clone()]).expect("valid local pool"));
    let invalid = QuotaPoolAdmission::new(
        Some(invalid_config),
        Ok(Some(invalid_store)),
        Err(PoolError::InvalidState),
    );
    assert_eq!(
        invalid.consume("admission-invalid").await,
        Err(PoolError::InvalidState),
        "invalid member state never fails open"
    );

    let mut conflicting_state_config = config(
        "admission-conflicting-state",
        1,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    );
    conflicting_state_config.failure_mode = QuotaPoolFailureMode::AllowUnreserved;
    let before = quota_pool_counter(
        "sbproxy_ai_quota_pool_fail_open_total",
        "admission-conflicting-state",
    );
    let conflicting = QuotaPoolAdmission::new(
        Some(conflicting_state_config),
        Err(PoolError::BackendUnavailable),
        Err(PoolError::InvalidState),
    );
    assert_eq!(
        conflicting.consume("admission-conflicting-state").await,
        Err(PoolError::InvalidState),
        "invalid state takes precedence over a simultaneous backend failure"
    );
    assert_eq!(
        quota_pool_counter(
            "sbproxy_ai_quota_pool_fail_open_total",
            "admission-conflicting-state",
        ) - before,
        0.0
    );
}

#[tokio::test]
async fn quota_admission_fails_open_reserve_and_settle_backend_errors_per_attempt() {
    for (pool_name, governance) in [
        (
            "admission-reserve-unavailable",
            Arc::new(ObservedGovernance::unavailable()),
        ),
        (
            "admission-settle-unavailable",
            Arc::new(ObservedGovernance::settle_unavailable()),
        ),
    ] {
        let mut pool_config = config(
            pool_name,
            2,
            &[("virtual-key-a", 1)],
            QuotaPoolPolicy::Burst,
        );
        pool_config.failure_mode = QuotaPoolFailureMode::AllowUnreserved;
        let shared: Arc<dyn QuotaPoolStore> = Arc::new(
            SharedQuotaPool::new(
                vec![pool_config.clone()],
                governance as Arc<dyn GovernanceStore>,
            )
            .expect("valid shared pool"),
        );
        let admission = QuotaPoolAdmission::new(
            Some(pool_config),
            Ok(Some(shared)),
            Ok("virtual-key-a".to_string()),
        );
        let before = quota_pool_counter("sbproxy_ai_quota_pool_fail_open_total", pool_name);

        admission
            .consume(&format!("{pool_name}:attempt"))
            .await
            .expect("backend-unavailable attempt follows allow_unreserved");

        assert_eq!(
            quota_pool_counter("sbproxy_ai_quota_pool_fail_open_total", pool_name) - before,
            1.0
        );
    }
}

#[tokio::test]
async fn local_active_reservation_is_idempotent_by_caller_id() {
    let pool = LocalQuotaPool::new(vec![config(
        "local-idempotent",
        2,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    )])
    .expect("valid local pool");

    let first = pool
        .reserve("local-idempotent", "virtual-key-a", 1, "same-active")
        .await
        .expect("first reservation succeeds");
    let duplicate = pool
        .reserve("local-idempotent", "virtual-key-a", 1, "same-active")
        .await
        .expect("identical active reservation is idempotent");

    assert_eq!(duplicate, first);
    assert_eq!(
        pool.member_loads("local-idempotent").get("virtual-key-a"),
        Some(&1)
    );
}

#[tokio::test]
async fn local_reservation_id_conflicts_across_pool_inputs() {
    let pool = LocalQuotaPool::new(vec![
        config("local-a", 2, &[("virtual-key-a", 1)], QuotaPoolPolicy::Hard),
        config("local-b", 2, &[("virtual-key-a", 1)], QuotaPoolPolicy::Hard),
    ])
    .expect("valid local pools");

    pool.reserve("local-a", "virtual-key-a", 1, "cross-pool-id")
        .await
        .expect("first reservation succeeds");
    assert_eq!(
        pool.reserve("local-b", "virtual-key-a", 1, "cross-pool-id")
            .await,
        Err(PoolError::InvalidState)
    );
    assert_eq!(
        pool.member_loads("local-b").get("virtual-key-a"),
        Some(&0),
        "conflicting id must not reserve the second pool"
    );
}

#[tokio::test]
async fn local_terminal_transition_rejects_forged_reservation_fields() {
    let pool = LocalQuotaPool::new(vec![config(
        "local-forgery",
        4,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    )])
    .expect("valid local pool");
    let reservation = pool
        .reserve("local-forgery", "virtual-key-a", 2, "forgery-id")
        .await
        .expect("reservation succeeds");
    let mut forged = reservation.clone();
    forged.units = 1;

    assert_eq!(
        pool.reconcile(forged, PoolUsage { units: 1 }).await,
        Err(PoolError::InvalidState)
    );
    assert_eq!(
        pool.member_loads("local-forgery").get("virtual-key-a"),
        Some(&2),
        "forged terminal call must not alter the hold"
    );
    pool.release(reservation)
        .await
        .expect("authentic reservation still releases");
}

#[tokio::test]
async fn local_duplicate_terminal_calls_do_not_double_account() {
    let pool = LocalQuotaPool::new(vec![config(
        "local-terminal-idempotence",
        4,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    )])
    .expect("valid local pool");

    let settled = pool
        .reserve(
            "local-terminal-idempotence",
            "virtual-key-a",
            2,
            "settled-id",
        )
        .await
        .expect("settled reservation succeeds");
    pool.reconcile(settled.clone(), PoolUsage { units: 1 })
        .await
        .expect("first settlement succeeds");
    pool.reconcile(settled, PoolUsage { units: 1 })
        .await
        .expect("duplicate identical settlement is idempotent");
    assert_eq!(
        pool.member_loads("local-terminal-idempotence")
            .get("virtual-key-a"),
        Some(&1)
    );

    let released = pool
        .reserve(
            "local-terminal-idempotence",
            "virtual-key-a",
            2,
            "released-id",
        )
        .await
        .expect("released reservation succeeds");
    pool.release(released.clone())
        .await
        .expect("first release succeeds");
    pool.release(released)
        .await
        .expect("duplicate release is idempotent");
    assert_eq!(
        pool.member_loads("local-terminal-idempotence")
            .get("virtual-key-a"),
        Some(&1)
    );
}

#[tokio::test]
async fn local_window_rollover_expires_old_ids_without_mutating_new_holds() {
    let mut pool_config = config(
        "local-rollover",
        4,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Hard,
    );
    pool_config.window = Duration::from_millis(1);
    let pool = LocalQuotaPool::new(vec![pool_config]).expect("valid local pool");

    let old = pool
        .reserve("local-rollover", "virtual-key-a", 2, "old-window-id")
        .await
        .expect("old-window reservation succeeds");
    tokio::time::sleep(Duration::from_millis(5)).await;
    pool.reserve("local-rollover", "virtual-key-a", 1, "new-window-id")
        .await
        .expect("new-window reservation triggers rollover");

    assert_eq!(pool.release(old).await, Err(PoolError::InvalidState));
    assert_eq!(
        pool.member_loads("local-rollover").get("virtual-key-a"),
        Some(&1),
        "expired terminal call must not release the new-window hold"
    );
}

#[tokio::test]
async fn local_soft_overshare_is_bounded_and_metered_without_member_labels() {
    let pool_name = "local-soft-bounded";
    let pool = LocalQuotaPool::new(vec![config(
        pool_name,
        4,
        &[("private-member-a", 1), ("private-member-b", 1)],
        QuotaPoolPolicy::Soft,
    )])
    .expect("valid local soft pool");
    let before = quota_pool_counter("sbproxy_ai_quota_pool_overshare_total", pool_name);

    for attempt in 0..4 {
        let reservation = pool
            .reserve(
                pool_name,
                "private-member-a",
                1,
                &format!("local-soft-{attempt}"),
            )
            .await
            .expect("soft policy admits through aggregate capacity");
        pool.reconcile(reservation, PoolUsage { units: 1 })
            .await
            .expect("soft usage settles");
    }

    assert_eq!(
        pool.over_shares(pool_name),
        vec![sbproxy_ai::quota_pool::OverShareRecord {
            member: "private-member-a".to_string(),
            excess: 2,
        }],
        "test-facing observations retain one bounded latest record per member"
    );
    assert_eq!(
        quota_pool_counter("sbproxy_ai_quota_pool_overshare_total", pool_name) - before,
        2.0,
        "each over-entitlement admission increments the pool-only counter"
    );
}

#[tokio::test]
async fn hard_settlement_commits_the_pool_total_before_the_member_digest() {
    let governance = Arc::new(ObservedGovernance::available());
    let pool = SharedQuotaPool::new(
        vec![config(
            "settlement-order",
            2,
            &[("virtual-key-a", 1)],
            QuotaPoolPolicy::Hard,
        )],
        governance.clone() as Arc<dyn GovernanceStore>,
    )
    .expect("valid hard shared pool");
    let reservation = pool
        .reserve(
            "settlement-order",
            "virtual-key-a",
            1,
            "settlement-order-attempt",
        )
        .await
        .expect("hard reservation succeeds");

    pool.reconcile(reservation, PoolUsage { units: 1 })
        .await
        .expect("both counters settle");

    assert_eq!(
        governance
            .settled_keys
            .lock()
            .expect("settlement recorder lock")
            .as_slice(),
        [
            "sbproxy:quota-pool:settlement-order:global",
            concat!(
                "sbproxy:quota-pool:settlement-order:member:",
                "6bcc6cf114a6f53408ae3defe86034fc4af350ede1d390a6228de819a59b98f8"
            ),
        ]
    );
}

#[tokio::test]
async fn shared_soft_handles_settle_entitlement_and_overflow_lanes_and_meter_overshare() {
    let pool_name = "soft-lanes";
    let private_member = "private-member-a";
    let governance = Arc::new(ObservedGovernance::available());
    let pool_config = config(
        pool_name,
        6,
        &[(private_member, 1), ("private-member-b", 1)],
        QuotaPoolPolicy::Soft,
    );
    let handles = [
        SharedQuotaPool::new(
            vec![pool_config.clone()],
            governance.clone() as Arc<dyn GovernanceStore>,
        )
        .expect("valid first shared soft pool"),
        SharedQuotaPool::new(
            vec![pool_config],
            governance.clone() as Arc<dyn GovernanceStore>,
        )
        .expect("valid second shared soft pool"),
    ];
    let before = quota_pool_counter("sbproxy_ai_quota_pool_overshare_total", pool_name);

    for attempt in 0..4 {
        let handle = &handles[attempt % handles.len()];
        let reservation = handle
            .reserve(
                pool_name,
                private_member,
                1,
                &format!("soft-lane-{attempt}"),
            )
            .await
            .expect("soft admits beyond the three-unit entitlement");
        handle
            .reconcile(reservation, PoolUsage { units: 1 })
            .await
            .expect("soft reservation settles through its selected lane");
    }

    let settled = governance
        .settled_keys
        .lock()
        .expect("settlement recorder lock");
    let global = format!("sbproxy:quota-pool:{pool_name}:global");
    let member = concat!(
        "sbproxy:quota-pool:soft-lanes:member:",
        "5af118c34107e570b3e0a60dd025f921616e50c1c9cc56abe32995b15f124bec"
    );
    let overflow = format!("{member}:overflow");
    assert_eq!(settled.iter().filter(|key| *key == &global).count(), 4);
    assert_eq!(settled.iter().filter(|key| *key == member).count(), 3);
    assert_eq!(settled.iter().filter(|key| *key == &overflow).count(), 1);
    assert!(
        settled.iter().all(|key| !key.contains(private_member)),
        "shared accounting keys must not expose caller identity"
    );
    drop(settled);
    assert_eq!(
        quota_pool_counter("sbproxy_ai_quota_pool_overshare_total", pool_name) - before,
        1.0
    );
}

#[tokio::test]
async fn shared_soft_release_uses_the_recorded_overflow_lane() {
    let pool_name = "soft-release-lane";
    let private_member = "private-member-a";
    let governance = Arc::new(ObservedGovernance::available());
    let pool = SharedQuotaPool::new(
        vec![config(
            pool_name,
            4,
            &[(private_member, 1), ("private-member-b", 1)],
            QuotaPoolPolicy::Soft,
        )],
        governance.clone() as Arc<dyn GovernanceStore>,
    )
    .expect("valid shared soft pool");

    for attempt in 0..2 {
        let reservation = pool
            .reserve(
                pool_name,
                private_member,
                1,
                &format!("soft-release-fill-{attempt}"),
            )
            .await
            .expect("member entitlement fills");
        pool.reconcile(reservation, PoolUsage { units: 1 })
            .await
            .expect("member reservation settles");
    }
    let overflow = pool
        .reserve(pool_name, private_member, 1, "soft-release-overflow")
        .await
        .expect("soft overflow reservation succeeds");
    pool.release(overflow)
        .await
        .expect("overflow reservation releases");

    let released = governance
        .released_keys
        .lock()
        .expect("release recorder lock");
    let global = "sbproxy:quota-pool:soft-release-lane:global";
    let overflow = concat!(
        "sbproxy:quota-pool:soft-release-lane:member:",
        "5af118c34107e570b3e0a60dd025f921616e50c1c9cc56abe32995b15f124bec",
        ":overflow"
    );
    assert_eq!(released.len(), 2);
    assert!(released.iter().any(|key| key == global));
    assert!(released.iter().any(|key| key == overflow));
}

#[tokio::test]
async fn shared_soft_release_cleans_its_lane_when_global_is_already_settled() {
    let pool_name = "soft-partial-terminal";
    let private_member = "private-member-a";
    let governance = Arc::new(ObservedGovernance::available());
    let pool = SharedQuotaPool::new(
        vec![config(
            pool_name,
            4,
            &[(private_member, 1), ("private-member-b", 1)],
            QuotaPoolPolicy::Soft,
        )],
        governance.clone() as Arc<dyn GovernanceStore>,
    )
    .expect("valid shared soft pool");

    for attempt in 0..2 {
        let reservation = pool
            .reserve(
                pool_name,
                private_member,
                1,
                &format!("soft-partial-fill-{attempt}"),
            )
            .await
            .expect("member entitlement fills");
        pool.reconcile(reservation, PoolUsage { units: 1 })
            .await
            .expect("member reservation settles");
    }
    let reservation = pool
        .reserve(pool_name, private_member, 1, "soft-partial-overflow")
        .await
        .expect("overflow reservation succeeds");
    governance
        .settle(SettleRequest {
            reservation_id: "soft-partial-overflow:quota-pool:global".to_string(),
            key_id: "sbproxy:quota-pool:soft-partial-terminal:global".to_string(),
            actual_tokens: 1,
            actual_micro_usd: 0,
        })
        .await
        .expect("simulate global-first partial settlement");

    assert_eq!(
        pool.release(reservation).await,
        Err(PoolError::InvalidState)
    );

    let overflow_key = concat!(
        "sbproxy:quota-pool:soft-partial-terminal:member:",
        "5af118c34107e570b3e0a60dd025f921616e50c1c9cc56abe32995b15f124bec",
        ":overflow"
    );
    let snapshot = governance
        .snapshot(SnapshotKey {
            key_id: overflow_key.to_string(),
            policy_revision: 0,
            limits: GovernanceLimits {
                requests_per_window: None,
                tokens_per_window: Some(4),
                total_tokens: None,
                total_micro_usd: None,
                window_millis: 86_400_000,
            },
        })
        .await
        .expect("overflow snapshot");
    assert_eq!(
        snapshot.tokens_per_window.reserved, 0,
        "lane hold must be cleaned even though the global transition conflicts"
    );
    assert_eq!(
        pool.reserve(pool_name, private_member, 1, "soft-partial-overflow",)
            .await,
        Err(PoolError::InvalidState),
        "completed partial cleanup must not leave active soft metadata"
    );
}

#[tokio::test]
async fn three_handles_never_admit_more_than_one_shared_pool_limit() {
    let governance: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
    let pool_config = config(
        "cluster-total",
        5,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Burst,
    );
    let handles: Vec<Arc<dyn QuotaPoolStore>> = (0..3)
        .map(|_| {
            Arc::new(
                SharedQuotaPool::new(vec![pool_config.clone()], governance.clone())
                    .expect("valid shared pool"),
            ) as Arc<dyn QuotaPoolStore>
        })
        .collect();

    let attempts = (0..12).map(|attempt| {
        let handle = handles[attempt % handles.len()].clone();
        async move {
            handle
                .reserve(
                    "cluster-total",
                    "virtual-key-a",
                    1,
                    &format!("shared-attempt-{attempt}"),
                )
                .await
        }
    });
    let results = join_all(attempts).await;
    let admitted = results.iter().filter(|result| result.is_ok()).count();

    assert_eq!(admitted, 5, "combined admissions must stop at the limit");
    assert!(results
        .iter()
        .filter(|result| result.is_err())
        .all(|result| matches!(
            result,
            Err(PoolError::Denied(PoolDeny::PoolExhausted {
                total_limit: 5,
                ..
            }))
        )));
}

#[tokio::test]
async fn hard_member_denial_releases_the_pool_wide_reservation() {
    let governance: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
    let pool = SharedQuotaPool::new(
        vec![config(
            "hard-members",
            4,
            &[("virtual-key-a", 3), ("virtual-key-b", 1)],
            QuotaPoolPolicy::Hard,
        )],
        governance,
    )
    .expect("valid hard pool");

    pool.reserve("hard-members", "virtual-key-b", 1, "hard-b-1")
        .await
        .expect("B fits its one-unit entitlement");
    let denied = pool
        .reserve("hard-members", "virtual-key-b", 1, "hard-b-2")
        .await
        .expect_err("B cannot exceed its hard entitlement");
    assert!(matches!(
        denied,
        PoolError::Denied(PoolDeny::OverShare {
            member,
            entitlement: 1,
            ..
        }) if member == "virtual-key-b"
    ));

    for attempt in 0..3 {
        pool.reserve(
            "hard-members",
            "virtual-key-a",
            1,
            &format!("hard-a-{attempt}"),
        )
        .await
        .expect("A must retain all three units after B's denied attempt");
    }
}

#[tokio::test]
async fn hard_member_denial_survives_a_failed_global_cleanup() {
    let governance = Arc::new(ObservedGovernance::release_unavailable());
    let pool = SharedQuotaPool::new(
        vec![config(
            "hard-cleanup",
            2,
            &[("virtual-key-a", 1), ("virtual-key-b", 1)],
            QuotaPoolPolicy::Hard,
        )],
        governance as Arc<dyn GovernanceStore>,
    )
    .expect("valid hard pool");

    let first = pool
        .reserve("hard-cleanup", "virtual-key-a", 1, "hard-cleanup-a-1")
        .await
        .expect("A fits its one-unit entitlement");
    pool.reconcile(first, PoolUsage { units: 1 })
        .await
        .expect("first reservation settles");

    let error = pool
        .reserve("hard-cleanup", "virtual-key-a", 1, "hard-cleanup-a-2")
        .await
        .expect_err("A remains denied when global cleanup is unavailable");
    assert!(matches!(
        error,
        PoolError::Denied(PoolDeny::OverShare {
            member,
            entitlement: 1,
            ..
        }) if member == "virtual-key-a"
    ));
}

#[tokio::test]
async fn burst_member_borrows_all_idle_aggregate_capacity() {
    let governance: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
    let pool = SharedQuotaPool::new(
        vec![config(
            "burst-borrow",
            4,
            &[("virtual-key-a", 1), ("virtual-key-b", 1)],
            QuotaPoolPolicy::Burst,
        )],
        governance,
    )
    .expect("valid burst pool");

    for attempt in 0..4 {
        pool.reserve(
            "burst-borrow",
            "virtual-key-a",
            1,
            &format!("burst-a-{attempt}"),
        )
        .await
        .expect("A may borrow B's idle entitlement");
    }
    assert!(matches!(
        pool.reserve("burst-borrow", "virtual-key-a", 1, "burst-a-full")
            .await,
        Err(PoolError::Denied(PoolDeny::PoolExhausted {
            total_limit: 4,
            ..
        }))
    ));
}

#[tokio::test]
async fn merged_peer_usage_is_enforced_by_another_approximate_store() {
    let governance_a = Arc::new(InMemoryGovernanceStore::default());
    let governance_b = Arc::new(InMemoryGovernanceStore::default());
    let pool_config = config(
        "converged",
        3,
        &[("virtual-key-a", 1)],
        QuotaPoolPolicy::Burst,
    );
    let pool_a = SharedQuotaPool::new(
        vec![pool_config.clone()],
        governance_a.clone() as Arc<dyn GovernanceStore>,
    )
    .expect("valid first pool");
    let pool_b = SharedQuotaPool::new(
        vec![pool_config],
        governance_b.clone() as Arc<dyn GovernanceStore>,
    )
    .expect("valid second pool");

    let reservation = pool_a
        .reserve("converged", "virtual-key-a", 2, "converged-a")
        .await
        .expect("first node admits two units");
    pool_a
        .reconcile(reservation, PoolUsage { units: 2 })
        .await
        .expect("first node publishes settled usage");

    governance_b.set_peer_counters(merge_contributions([GovernanceContribution {
        node_id: "node-a".to_string(),
        generation: 1,
        slots: governance_a.local_slots(),
    }]));

    pool_b
        .reserve("converged", "virtual-key-a", 1, "converged-b-1")
        .await
        .expect("the final cluster-wide unit fits");
    assert!(matches!(
        pool_b
            .reserve("converged", "virtual-key-a", 1, "converged-b-2")
            .await,
        Err(PoolError::Denied(PoolDeny::PoolExhausted {
            total_load: 3,
            total_limit: 3,
        }))
    ));
}
