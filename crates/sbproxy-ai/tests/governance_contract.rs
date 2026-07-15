use sbproxy_ai::governance::{
    GovernanceError, GovernanceLimits, GovernanceStore, InMemoryGovernanceConfig,
    InMemoryGovernanceStore, ReleaseRequest, RenewRequest, ReservationTerminalState,
    ReserveRequest, SettleRequest, SnapshotKey,
};

#[tokio::test]
async fn renewal_keeps_a_long_running_ingress_reservation_active_without_double_charge() {
    let store = InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
        reservation_ttl_millis: 100,
        terminal_retention_millis: 1_000,
    })
    .expect("valid store");
    let limits = GovernanceLimits {
        requests_per_window: Some(1),
        tokens_per_window: Some(100),
        total_tokens: Some(100),
        total_micro_usd: Some(100),
        window_millis: 60_000,
    };
    let reservation = store
        .reserve(ReserveRequest {
            reservation_id: "request-1".into(),
            key_id: "key-1".into(),
            policy_revision: 7,
            limits: limits.clone(),
            token_ceiling: 80,
            micro_usd_ceiling: 50,
        })
        .await
        .expect("reserve");

    let renewed = store
        .renew(RenewRequest {
            reservation_id: reservation.reservation_id.clone(),
            key_id: reservation.key_id.clone(),
        })
        .await
        .expect("renew");
    assert!(renewed.expires_at_millis >= reservation.expires_at_millis);

    store
        .settle(SettleRequest {
            reservation_id: reservation.reservation_id,
            key_id: reservation.key_id,
            actual_tokens: 60,
            actual_micro_usd: 40,
        })
        .await
        .expect("settle");

    let snapshot = store
        .snapshot(SnapshotKey {
            key_id: "key-1".into(),
            policy_revision: 7,
            limits,
        })
        .await
        .expect("snapshot");
    assert_eq!(snapshot.total_tokens.used, 60);
    assert_eq!(snapshot.total_tokens.reserved, 0);
    assert_eq!(snapshot.total_micro_usd.used, 40);
}

fn unbounded_limits() -> GovernanceLimits {
    GovernanceLimits {
        requests_per_window: None,
        tokens_per_window: None,
        total_tokens: None,
        total_micro_usd: None,
        window_millis: 60_000,
    }
}

fn request(id: &str, key_id: &str, tokens: u64) -> ReserveRequest {
    ReserveRequest {
        reservation_id: id.to_string(),
        key_id: key_id.to_string(),
        policy_revision: 1,
        limits: unbounded_limits(),
        token_ceiling: tokens,
        micro_usd_ceiling: tokens,
    }
}

#[tokio::test]
async fn renewal_rejects_expired_settled_released_and_cross_key_reservations() {
    let store = InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
        reservation_ttl_millis: 20,
        terminal_retention_millis: 500,
    })
    .expect("valid store");
    for reservation in [
        request("expired", "expired-key", 1),
        request("settled", "settled-key", 1),
        request("released", "released-key", 1),
        request("private", "private-key", 1),
    ] {
        store.reserve(reservation).await.expect("reserve test case");
    }
    store
        .settle(SettleRequest {
            reservation_id: "settled".to_string(),
            key_id: "settled-key".to_string(),
            actual_tokens: 1,
            actual_micro_usd: 1,
        })
        .await
        .expect("settle test case");
    store
        .release(ReleaseRequest {
            reservation_id: "released".to_string(),
            key_id: "released-key".to_string(),
        })
        .await
        .expect("release test case");
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;

    for (reservation_id, key_id, expected) in [
        ("expired", "expired-key", ReservationTerminalState::Expired),
        ("settled", "settled-key", ReservationTerminalState::Settled),
        (
            "released",
            "released-key",
            ReservationTerminalState::Released,
        ),
    ] {
        assert!(matches!(
            store
                .renew(RenewRequest {
                    reservation_id: reservation_id.to_string(),
                    key_id: key_id.to_string(),
                })
                .await,
            Err(GovernanceError::TerminalConflict { state, .. }) if state == expected
        ));
    }
    assert!(matches!(
        store
            .renew(RenewRequest {
                reservation_id: "private".to_string(),
                key_id: "different-key".to_string(),
            })
            .await,
        Err(GovernanceError::ReservationNotFound { .. })
    ));
}

#[tokio::test]
async fn duplicate_terminal_operations_return_the_original_result_once() {
    let store = InMemoryGovernanceStore::default();
    store
        .reserve(request("settled", "settled-key", 100))
        .await
        .expect("reserve settlement");
    let settle_request = SettleRequest {
        reservation_id: "settled".to_string(),
        key_id: "settled-key".to_string(),
        actual_tokens: 80,
        actual_micro_usd: 60,
    };
    let first_settlement = store
        .settle(settle_request.clone())
        .await
        .expect("settle once");
    assert_eq!(
        store
            .settle(SettleRequest {
                actual_tokens: 99,
                actual_micro_usd: 98,
                ..settle_request
            })
            .await
            .expect("the first settlement remains authoritative"),
        first_settlement
    );

    store
        .reserve(request("released", "released-key", 100))
        .await
        .expect("reserve release");
    let release_request = ReleaseRequest {
        reservation_id: "released".to_string(),
        key_id: "released-key".to_string(),
    };
    let first_release = store
        .release(release_request.clone())
        .await
        .expect("release once");
    assert_eq!(
        store
            .release(release_request)
            .await
            .expect("release duplicate"),
        first_release
    );
}

#[tokio::test]
async fn in_memory_integer_overflow_is_rejected_without_partial_mutation() {
    let store = InMemoryGovernanceStore::default();
    let key_id = "integer-boundary";
    store
        .reserve(request("maximum", key_id, u64::MAX))
        .await
        .expect("reserve u64 maximum exactly");
    assert!(matches!(
        store.reserve(request("overflow", key_id, 1)).await,
        Err(GovernanceError::ArithmeticOverflow { .. })
    ));
    let snapshot = store
        .snapshot(SnapshotKey {
            key_id: key_id.to_string(),
            policy_revision: 1,
            limits: unbounded_limits(),
        })
        .await
        .expect("snapshot exact boundary");
    assert_eq!(snapshot.requests_per_window.reserved, 1);
    assert_eq!(snapshot.total_tokens.reserved, u64::MAX);
    assert_eq!(snapshot.total_micro_usd.reserved, u64::MAX);
}
