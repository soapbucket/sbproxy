//! Contract tests for strict Redis governance accounting.

use std::{sync::Arc, time::Duration};

use sbproxy_ai::governance::{
    GovernanceDenial, GovernanceDimension, GovernanceError, GovernanceLimits, GovernanceStore,
    ReleaseRequest, RenewRequest, ReserveRequest, SettleRequest, SnapshotKey,
};
use sbproxy_ai::governance_redis::{
    redis_governance_key, RedisGovernanceConfig, RedisGovernanceStore,
};
use sbproxy_platform::storage::{AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore};

const LUA_MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
const GOVERNANCE_REDIS_RS: &str = include_str!("../src/governance_redis.rs");
const COMMON_LUA: &str = include_str!("../src/governance_redis/common.lua");
const RESERVE_LUA: &str = include_str!("../src/governance_redis/reserve.lua");
const RENEW_LUA: &str = include_str!("../src/governance_redis/renew.lua");
const SETTLE_LUA: &str = include_str!("../src/governance_redis/settle.lua");
const RELEASE_LUA: &str = include_str!("../src/governance_redis/release.lua");
const SNAPSHOT_LUA: &str = include_str!("../src/governance_redis/snapshot.lua");

fn limits() -> GovernanceLimits {
    GovernanceLimits {
        requests_per_window: Some(1),
        tokens_per_window: Some(100),
        total_tokens: Some(100),
        total_micro_usd: Some(1_000),
        window_millis: 60_000,
    }
}

fn reserve_request(id: &str, key_id: &str) -> ReserveRequest {
    ReserveRequest {
        reservation_id: id.to_string(),
        key_id: key_id.to_string(),
        policy_revision: 9,
        limits: limits(),
        token_ceiling: 80,
        micro_usd_ceiling: 600,
    }
}

fn snapshot_key(key_id: &str) -> SnapshotKey {
    SnapshotKey {
        key_id: key_id.to_string(),
        policy_revision: 9,
        limits: limits(),
    }
}

fn unique_prefix(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must follow the Unix epoch")
        .as_nanos();
    format!(
        "sbproxy:test:governance:{label}:{}:{nanos}",
        std::process::id()
    )
}

fn redis_hash_tag(candidate: &str) -> &str {
    candidate
        .split_once('{')
        .expect("cluster hash tag starts")
        .1
        .split_once('}')
        .expect("cluster hash tag ends")
        .0
}

fn redis_config(prefix: String, ttl_millis: u64) -> RedisGovernanceConfig {
    RedisGovernanceConfig {
        key_prefix: prefix,
        reservation_ttl_millis: ttl_millis,
        terminal_retention_millis: ttl_millis.saturating_mul(4),
    }
}

fn redis_store(
    url: &str,
    prefix: String,
    ttl_millis: u64,
) -> (Arc<AsyncRedisKVStore>, RedisGovernanceStore) {
    let redis = AsyncRedisKVStore::new(AsyncRedisConfig::new(url));
    let store = RedisGovernanceStore::new(redis.clone(), redis_config(prefix, ttl_millis))
        .expect("valid Redis governance config");
    (redis, store)
}

fn governance_keys(prefix: &str, key_id: &str) -> [String; 3] {
    let governance_key = redis_governance_key(prefix, key_id);
    [
        governance_key.clone(),
        format!("{governance_key}:active-expiry"),
        format!("{governance_key}:terminal-expiry"),
    ]
}

async fn delete_governance_key(redis: &AsyncRedisKVStore, prefix: &str, key_id: &str) {
    for disposable_key in governance_keys(prefix, key_id) {
        redis
            .delete(disposable_key.as_bytes())
            .await
            .expect("delete disposable governance key");
    }
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn wrong_storage_types_fail_closed_before_reservation_mutation() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("wrong-types");

    for (index, expected_field) in [
        (0, "governance_key_type"),
        (1, "active_expiry_key_type"),
        (2, "terminal_expiry_key_type"),
    ] {
        let key_id = format!("wrong-type-{index}-{}", std::process::id());
        let (redis, store) = redis_store(&url, prefix.clone(), 2_000);
        let keys = governance_keys(&prefix, &key_id);
        redis
            .put(keys[index].as_bytes(), b"wrong-type")
            .await
            .expect("seed wrong Redis storage type");

        assert!(matches!(
            store.reserve(reserve_request("must-not-reserve", &key_id)).await,
            Err(GovernanceError::InternalInvariant { field }) if field == expected_field
        ));
        for (candidate_index, candidate) in keys.iter().enumerate() {
            let value = redis
                .get(candidate.as_bytes())
                .await
                .expect("read string or missing disposable key");
            if candidate_index == index {
                assert_eq!(value.as_deref(), Some(&b"wrong-type"[..]));
            } else {
                assert!(value.is_none(), "reserve must not create {candidate}");
            }
        }

        delete_governance_key(&redis, &prefix, &key_id).await;
    }
}

#[test]
fn state_scripts_use_expiry_indexes_instead_of_scanning_retained_reservations() {
    assert!(COMMON_LUA.contains("redis.call('TIME')"));
    assert!(COMMON_LUA.contains("local governance_key = KEYS[1]"));
    assert!(COMMON_LUA.contains("local active_expiry_key = KEYS[2]"));
    assert!(COMMON_LUA.contains("local terminal_expiry_key = KEYS[3]"));
    assert!(COMMON_LUA.contains("cleanup_expired"));
    assert!(COMMON_LUA.contains("terminal_retention_millis"));
    assert!(!COMMON_LUA.contains("HGETALL"));
    assert!(COMMON_LUA.contains("ZRANGEBYSCORE"));
    assert!(COMMON_LUA.contains("ZADD"));
    assert!(COMMON_LUA.contains("ZREM"));
    assert!(COMMON_LUA.contains("HDEL"));
    assert!(COMMON_LUA.contains("local function validate_storage_types"));
    assert!(COMMON_LUA.contains("local function read_required_number"));
    assert!(COMMON_LUA.contains("local max_exact_integer = 9007199254740991"));
    assert!(COMMON_LUA.contains("local function format_integer"));
    assert!(COMMON_LUA.contains("local function checked_add"));
    assert!(COMMON_LUA.contains("local function checked_sub"));

    for operation in [
        RESERVE_LUA,
        RENEW_LUA,
        SETTLE_LUA,
        RELEASE_LUA,
        SNAPSHOT_LUA,
    ] {
        assert!(operation.contains("#KEYS ~= 3"));
        assert!(operation.contains("validate_storage_types"));
        assert!(!operation.contains("KEYS[4]"));
        assert!(!operation.contains("redis.call('EVAL'"));
    }
    assert!(RESERVE_LUA.contains("cleanup_expired"));
    assert!(RESERVE_LUA.contains("index_active_reservation"));
    assert!(RESERVE_LUA.contains("checked_add"));
    assert!(RESERVE_LUA.contains("'overflow'"));
    assert!(RENEW_LUA.contains("cleanup_expired"));
    assert!(RENEW_LUA.contains("index_active_reservation"));
    assert!(RENEW_LUA.contains("checked_add"));
    assert!(SETTLE_LUA.contains("'settled'"));
    assert!(SETTLE_LUA.contains("index_terminal_reservation"));
    assert!(SETTLE_LUA.contains("checked_add"));
    assert!(SETTLE_LUA.contains("checked_sub"));
    assert!(RELEASE_LUA.contains("'released'"));
    assert!(RELEASE_LUA.contains("index_terminal_reservation"));
    assert!(RELEASE_LUA.contains("checked_sub"));
    assert!(SNAPSHOT_LUA.contains("cleanup_expired"));
    assert!(GOVERNANCE_REDIS_RS.contains(":active-expiry"));
    assert!(GOVERNANCE_REDIS_RS.contains(":terminal-expiry"));
}

#[test]
fn redis_key_uses_only_a_secret_free_cluster_hash_tag() {
    let key_id = "immutable-key-id-not-a-bearer";
    let key = redis_governance_key("sbproxy:governance", key_id);
    let repeated = redis_governance_key("sbproxy:governance", key_id);
    let different = redis_governance_key("sbproxy:governance", "different-id");

    assert_eq!(key, repeated);
    assert_ne!(key, different);
    assert!(key.starts_with("sbproxy:governance:{"));
    assert!(key.ends_with('}'));
    assert!(!key.contains(key_id));
    let active_expiry_key = format!("{key}:active-expiry");
    let terminal_expiry_key = format!("{key}:terminal-expiry");
    let tag = redis_hash_tag(&key);
    assert_eq!(tag.len(), 64);
    assert!(tag.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(redis_hash_tag(&active_expiry_key), tag);
    assert_eq!(redis_hash_tag(&terminal_expiry_key), tag);
}

#[tokio::test]
async fn redis_rejects_values_outside_the_exact_lua_integer_range_without_connecting() {
    let too_large = LUA_MAX_EXACT_INTEGER + 1;
    assert!(matches!(
        RedisGovernanceStore::new(
            AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1")),
            RedisGovernanceConfig {
                key_prefix: ":::".to_string(),
                ..RedisGovernanceConfig::default()
            },
        ),
        Err(GovernanceError::InvalidRequest {
            field: "key_prefix",
            ..
        })
    ));
    assert!(matches!(
        RedisGovernanceStore::new(
            AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1")),
            RedisGovernanceConfig {
                key_prefix: "sbproxy:test:range".to_string(),
                reservation_ttl_millis: too_large,
                terminal_retention_millis: too_large,
            },
        ),
        Err(GovernanceError::InvalidRequest {
            field: "reservation_ttl_millis",
            ..
        })
    ));

    RedisGovernanceStore::new(
        AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1")),
        RedisGovernanceConfig {
            key_prefix: "sbproxy:test:range".to_string(),
            reservation_ttl_millis: LUA_MAX_EXACT_INTEGER,
            terminal_retention_millis: LUA_MAX_EXACT_INTEGER,
        },
    )
    .expect("the largest exactly represented Lua integer remains valid");

    let store = RedisGovernanceStore::new(
        AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1")),
        RedisGovernanceConfig::default(),
    )
    .expect("valid disconnected store");
    let mut request = reserve_request("range-reservation", "range-key");
    request.token_ceiling = too_large;
    assert!(matches!(
        store.reserve(request).await,
        Err(GovernanceError::InvalidRequest {
            field: "token_ceiling",
            ..
        })
    ));
    assert!(matches!(
        store
            .settle(SettleRequest {
                reservation_id: "range-reservation".to_string(),
                key_id: "range-key".to_string(),
                actual_tokens: too_large,
                actual_micro_usd: 0,
            })
            .await,
        Err(GovernanceError::InvalidRequest {
            field: "actual_tokens",
            ..
        })
    ));
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn two_clients_never_oversubscribe_a_strict_request_limit() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("concurrency");
    let key_id = format!("key-{}", std::process::id());
    let (redis, store_a) = redis_store(&url, prefix.clone(), 5_000);
    let (_, store_b) = redis_store(&url, prefix.clone(), 5_000);
    let mut strict_limits = limits();
    strict_limits.requests_per_window = Some(25);
    strict_limits.tokens_per_window = None;
    strict_limits.total_tokens = None;
    strict_limits.total_micro_usd = None;
    let barrier = Arc::new(tokio::sync::Barrier::new(101));
    let mut attempts = Vec::with_capacity(100);

    for index in 0..100 {
        let store = if index % 2 == 0 {
            store_a.clone()
        } else {
            store_b.clone()
        };
        let gate = barrier.clone();
        let request = ReserveRequest {
            reservation_id: format!("reservation-{index}"),
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: strict_limits.clone(),
            token_ceiling: 1,
            micro_usd_ceiling: 1,
        };
        attempts.push(tokio::spawn(async move {
            gate.wait().await;
            store.reserve(request).await
        }));
    }
    barrier.wait().await;

    let mut admitted = 0;
    for attempt in attempts {
        match attempt.await.expect("admission task joins") {
            Ok(_) => admitted += 1,
            Err(GovernanceError::LimitExceeded(GovernanceDenial {
                dimension: GovernanceDimension::RequestsPerWindow,
                ..
            })) => {}
            other => panic!("unexpected admission result: {other:?}"),
        }
    }
    assert_eq!(admitted, 25);
    let snapshot = store_a
        .snapshot(SnapshotKey {
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: strict_limits,
        })
        .await
        .expect("snapshot strict concurrency result");
    assert_eq!(snapshot.requests_per_window.reserved, 25);

    delete_governance_key(&redis, &prefix, &key_id).await;
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn another_client_repairs_an_expired_lease_before_admission() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("expiry");
    let key_id = format!("key-{}", std::process::id());
    let (redis, store_a) = redis_store(&url, prefix.clone(), 50);
    let (_, store_b) = redis_store(&url, prefix.clone(), 50);

    store_a
        .reserve(reserve_request("expired-reservation", &key_id))
        .await
        .expect("initial reserve");
    tokio::time::sleep(Duration::from_millis(100)).await;
    store_b
        .reserve(reserve_request("replacement-reservation", &key_id))
        .await
        .expect("replacement reserve");

    let snapshot = store_b
        .snapshot(snapshot_key(&key_id))
        .await
        .expect("snapshot repaired lease");
    assert_eq!(snapshot.requests_per_window.reserved, 1);
    assert_eq!(snapshot.tokens_per_window.reserved, 80);
    assert_eq!(snapshot.total_tokens.reserved, 80);

    delete_governance_key(&redis, &prefix, &key_id).await;
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn another_client_can_renew_settle_and_release_without_local_state() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("cross-client-terminal");
    let settle_key_id = format!("settle-key-{}", std::process::id());
    let release_key_id = format!("release-key-{}", std::process::id());
    let (redis_a, store_a) = redis_store(&url, prefix.clone(), 2_000);
    let (redis_b, store_b) = redis_store(&url, prefix.clone(), 2_000);

    let original = store_a
        .reserve(reserve_request("cross-client-settle", &settle_key_id))
        .await
        .expect("cross-client settlement reserve");
    let renewed = store_b
        .renew(RenewRequest {
            reservation_id: original.reservation_id.clone(),
            key_id: original.key_id.clone(),
        })
        .await
        .expect("cross-client renew");
    assert!(renewed.expires_at_millis >= original.expires_at_millis);
    let settlement = store_b
        .settle(SettleRequest {
            reservation_id: original.reservation_id,
            key_id: settle_key_id.clone(),
            actual_tokens: 55,
            actual_micro_usd: 400,
        })
        .await
        .expect("cross-client settle");
    assert_eq!(settlement.actual.tokens, 55);

    store_a
        .reserve(reserve_request("cross-client-release", &release_key_id))
        .await
        .expect("cross-client release reserve");
    let release = store_b
        .release(ReleaseRequest {
            reservation_id: "cross-client-release".to_string(),
            key_id: release_key_id.clone(),
        })
        .await
        .expect("cross-client release");
    assert_eq!(release.released.tokens, 80);

    delete_governance_key(&redis_a, &prefix, &settle_key_id).await;
    delete_governance_key(&redis_b, &prefix, &release_key_id).await;
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn renewal_rejects_expired_and_terminal_reservations() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("renew-terminal");
    let expired_key = format!("expired-key-{}", std::process::id());
    let settled_key = format!("settled-key-{}", std::process::id());
    let released_key = format!("released-key-{}", std::process::id());
    let (redis, store) = redis_store(&url, prefix.clone(), 50);

    for (reservation_id, key_id) in [
        ("expired", &expired_key),
        ("settled", &settled_key),
        ("released", &released_key),
    ] {
        store
            .reserve(reserve_request(reservation_id, key_id))
            .await
            .expect("reserve terminal renewal case");
    }
    store
        .settle(SettleRequest {
            reservation_id: "settled".to_string(),
            key_id: settled_key.clone(),
            actual_tokens: 50,
            actual_micro_usd: 300,
        })
        .await
        .expect("settle renewal case");
    store
        .release(ReleaseRequest {
            reservation_id: "released".to_string(),
            key_id: released_key.clone(),
        })
        .await
        .expect("release renewal case");
    tokio::time::sleep(Duration::from_millis(100)).await;

    for (reservation_id, key_id, expected) in [
        (
            "expired",
            &expired_key,
            sbproxy_ai::governance::ReservationTerminalState::Expired,
        ),
        (
            "settled",
            &settled_key,
            sbproxy_ai::governance::ReservationTerminalState::Settled,
        ),
        (
            "released",
            &released_key,
            sbproxy_ai::governance::ReservationTerminalState::Released,
        ),
    ] {
        assert!(matches!(
            store
                .renew(RenewRequest {
                    reservation_id: reservation_id.to_string(),
                    key_id: key_id.clone(),
                })
                .await,
            Err(GovernanceError::TerminalConflict { state, .. }) if state == expected
        ));
    }

    for key_id in [&expired_key, &settled_key, &released_key] {
        delete_governance_key(&redis, &prefix, key_id).await;
    }
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn duplicate_terminal_operations_return_the_first_outcome_without_double_charge() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("terminal-idempotency");
    let settle_key_id = format!("settle-key-{}", std::process::id());
    let release_key_id = format!("release-key-{}", std::process::id());
    let (redis, store) = redis_store(&url, prefix.clone(), 2_000);

    store
        .reserve(reserve_request("settle", &settle_key_id))
        .await
        .expect("settlement reserve");
    let settle_request = SettleRequest {
        reservation_id: "settle".to_string(),
        key_id: settle_key_id.clone(),
        actual_tokens: 55,
        actual_micro_usd: 400,
    };
    let first_settlement = store
        .settle(settle_request.clone())
        .await
        .expect("first settlement");
    let duplicate_settlement = store
        .settle(SettleRequest {
            actual_tokens: 99,
            actual_micro_usd: 98,
            ..settle_request
        })
        .await
        .expect("the first settlement remains authoritative");
    assert_eq!(duplicate_settlement, first_settlement);

    store
        .reserve(reserve_request("release", &release_key_id))
        .await
        .expect("release reserve");
    let release_request = ReleaseRequest {
        reservation_id: "release".to_string(),
        key_id: release_key_id.clone(),
    };
    let first_release = store
        .release(release_request.clone())
        .await
        .expect("first release");
    let duplicate_release = store
        .release(release_request)
        .await
        .expect("duplicate release");
    assert_eq!(duplicate_release, first_release);

    let settled = store
        .snapshot(snapshot_key(&settle_key_id))
        .await
        .expect("settled snapshot");
    assert_eq!(settled.total_tokens.used, 55);
    assert_eq!(settled.total_tokens.reserved, 0);
    let released = store
        .snapshot(snapshot_key(&release_key_id))
        .await
        .expect("released snapshot");
    assert_eq!(released.total_tokens.used, 0);
    assert_eq!(released.total_tokens.reserved, 0);

    delete_governance_key(&redis, &prefix, &settle_key_id).await;
    delete_governance_key(&redis, &prefix, &release_key_id).await;
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn exact_integer_boundary_is_preserved_and_next_unit_fails_atomically() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("exact-integer");
    let key_id = format!("key-{}", std::process::id());
    let (redis, store) = redis_store(&url, prefix.clone(), 2_000);
    let unbounded = GovernanceLimits {
        requests_per_window: Some(2),
        tokens_per_window: None,
        total_tokens: None,
        total_micro_usd: None,
        window_millis: 60_000,
    };

    store
        .reserve(ReserveRequest {
            reservation_id: "exact-max".to_string(),
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: unbounded.clone(),
            token_ceiling: LUA_MAX_EXACT_INTEGER,
            micro_usd_ceiling: LUA_MAX_EXACT_INTEGER,
        })
        .await
        .expect("reserve exact integer maximum");
    let before_overflow = store
        .snapshot(SnapshotKey {
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: unbounded.clone(),
        })
        .await
        .expect("snapshot exact integer maximum");
    assert_eq!(before_overflow.total_tokens.reserved, LUA_MAX_EXACT_INTEGER);

    assert!(matches!(
        store
            .reserve(ReserveRequest {
                reservation_id: "overflow".to_string(),
                key_id: key_id.clone(),
                policy_revision: 9,
                limits: unbounded.clone(),
                token_ceiling: 1,
                micro_usd_ceiling: 0,
            })
            .await,
        Err(GovernanceError::ArithmeticOverflow {
            field: "prospective_usage"
        }) | Err(GovernanceError::ArithmeticOverflow {
            field: "total_reserved_tokens"
        })
    ));
    let after_overflow = store
        .snapshot(SnapshotKey {
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: unbounded,
        })
        .await
        .expect("snapshot after rejected overflow");
    assert_eq!(after_overflow.requests_per_window.reserved, 1);
    assert_eq!(after_overflow.total_tokens.reserved, LUA_MAX_EXACT_INTEGER);

    delete_governance_key(&redis, &prefix, &key_id).await;
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn settlement_overflow_keeps_the_reservation_active_and_counters_unchanged() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("settlement-overflow");
    let key_id = format!("key-{}", std::process::id());
    let (redis, store) = redis_store(&url, prefix.clone(), 2_000);
    let unbounded = GovernanceLimits {
        requests_per_window: Some(2),
        tokens_per_window: None,
        total_tokens: None,
        total_micro_usd: None,
        window_millis: 60_000,
    };

    for (reservation_id, token_ceiling) in [
        ("settled-max", LUA_MAX_EXACT_INTEGER),
        ("settlement-overflow", 0),
    ] {
        store
            .reserve(ReserveRequest {
                reservation_id: reservation_id.to_string(),
                key_id: key_id.clone(),
                policy_revision: 9,
                limits: unbounded.clone(),
                token_ceiling,
                micro_usd_ceiling: token_ceiling,
            })
            .await
            .expect("reserve settlement overflow case");
    }
    store
        .settle(SettleRequest {
            reservation_id: "settled-max".to_string(),
            key_id: key_id.clone(),
            actual_tokens: LUA_MAX_EXACT_INTEGER,
            actual_micro_usd: LUA_MAX_EXACT_INTEGER,
        })
        .await
        .expect("settle exact integer maximum");
    assert!(matches!(
        store
            .settle(SettleRequest {
                reservation_id: "settlement-overflow".to_string(),
                key_id: key_id.clone(),
                actual_tokens: 1,
                actual_micro_usd: 1,
            })
            .await,
        Err(GovernanceError::ArithmeticOverflow {
            field: "window_used_tokens"
        }) | Err(GovernanceError::ArithmeticOverflow {
            field: "total_used_tokens"
        })
    ));

    let snapshot = store
        .snapshot(SnapshotKey {
            key_id: key_id.clone(),
            policy_revision: 9,
            limits: unbounded,
        })
        .await
        .expect("snapshot after settlement overflow");
    assert_eq!(snapshot.requests_per_window.used, 1);
    assert_eq!(snapshot.requests_per_window.reserved, 1);
    assert_eq!(snapshot.total_tokens.used, LUA_MAX_EXACT_INTEGER);
    assert_eq!(snapshot.total_tokens.reserved, 0);

    delete_governance_key(&redis, &prefix, &key_id).await;
}
