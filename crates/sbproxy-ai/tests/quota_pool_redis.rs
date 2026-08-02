use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::future::join_all;
use sbproxy_ai::{
    governance::GovernanceStore,
    governance_redis::{redis_governance_key, RedisGovernanceConfig, RedisGovernanceStore},
    quota_pool::{
        PoolDeny, PoolError, QuotaPoolConfig, QuotaPoolConsistency, QuotaPoolDimension,
        QuotaPoolFailureMode, QuotaPoolPolicy, QuotaPoolStore, SharedQuotaPool,
    },
};
use sbproxy_platform::storage::{AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore};

fn unique_prefix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock follows the Unix epoch")
        .as_nanos();
    format!("sbproxy:test:quota-pool:{}:{nanos}", std::process::id())
}

fn pool_config() -> QuotaPoolConfig {
    QuotaPoolConfig {
        name: "redis-shared".to_string(),
        window: Duration::from_secs(60),
        total_limit: 5,
        weights: HashMap::from([("virtual-key-a".to_string(), 1)]),
        policy: QuotaPoolPolicy::Burst,
        dimension: QuotaPoolDimension::Request,
        consistency: QuotaPoolConsistency::Strong,
        failure_mode: QuotaPoolFailureMode::Closed,
        failure_posture: None,
    }
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn three_redis_stores_atomically_enforce_one_pool_total() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix();
    let redis_for_cleanup = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let handles: Vec<Arc<dyn QuotaPoolStore>> = (0..3)
        .map(|_| {
            let redis = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
            let governance: Arc<dyn GovernanceStore> = Arc::new(
                RedisGovernanceStore::new(
                    redis,
                    RedisGovernanceConfig {
                        key_prefix: prefix.clone(),
                        reservation_ttl_millis: 2_000,
                        terminal_retention_millis: 4_000,
                    },
                )
                .expect("valid Redis governance config"),
            );
            Arc::new(
                SharedQuotaPool::new(vec![pool_config()], governance)
                    .expect("valid strong shared pool"),
            ) as Arc<dyn QuotaPoolStore>
        })
        .collect();

    let attempts = (0..12).map(|attempt| {
        let handle = handles[attempt % handles.len()].clone();
        async move {
            handle
                .reserve(
                    "redis-shared",
                    "virtual-key-a",
                    1,
                    &format!("redis-shared-attempt-{attempt}"),
                )
                .await
        }
    });
    let results = join_all(attempts).await;

    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        5,
        "all Redis-backed handles must share one five-unit limit"
    );
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

    let key = redis_governance_key(&prefix, "sbproxy:quota-pool:redis-shared:global");
    redis_for_cleanup
        .delete(key.as_bytes())
        .await
        .expect("test key cleanup succeeds");
}
