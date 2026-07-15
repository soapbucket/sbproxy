//! Strict Redis implementation of the governance accounting contract.
//!
//! Every governed key uses one Redis hash whose name contains a SHA-256
//! cluster hash tag. Lua scripts own admission, terminal transitions, lease
//! repair, and snapshots so no counter mutation crosses a script boundary.

use std::{sync::Arc, time::UNIX_EPOCH};

use async_trait::async_trait;
use sbproxy_platform::storage::AsyncRedisKVStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::governance::{
    CounterSnapshot, GovernanceBackendHealth, GovernanceBackendStatus, GovernanceConsistency,
    GovernanceDenial, GovernanceDimension, GovernanceError, GovernanceLimits, GovernanceSnapshot,
    GovernanceStore, GovernanceUsage, Release, ReleaseRequest, Reservation,
    ReservationTerminalState, ReserveRequest, SettleRequest, Settlement, SnapshotKey,
};

const LUA_MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
const COMMON_LUA: &str = include_str!("governance_redis/common.lua");
const RESERVE_LUA: &str = include_str!("governance_redis/reserve.lua");
const SETTLE_LUA: &str = include_str!("governance_redis/settle.lua");
const RELEASE_LUA: &str = include_str!("governance_redis/release.lua");
const SNAPSHOT_LUA: &str = include_str!("governance_redis/snapshot.lua");
const HEALTH_LUA: &str = r#"
local value = redis.call('TIME')
local now = (tonumber(value[1]) * 1000) + math.floor(tonumber(value[2]) / 1000)
return {'ok', tostring(now)}
"#;

/// Connection-independent settings for strict Redis governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisGovernanceConfig {
    /// Prefix placed before the per-key Redis Cluster hash tag.
    pub key_prefix: String,
    /// Maximum lease lifetime for an active reservation in milliseconds.
    pub reservation_ttl_millis: u64,
    /// Retention for settled, released, and expired tombstones in milliseconds.
    pub terminal_retention_millis: u64,
}

impl Default for RedisGovernanceConfig {
    fn default() -> Self {
        Self {
            key_prefix: "sbproxy:governance".to_string(),
            reservation_ttl_millis: 120_000,
            terminal_retention_millis: 300_000,
        }
    }
}

/// Redis-backed strict governance accounting store.
#[derive(Clone)]
pub struct RedisGovernanceStore {
    redis: Arc<AsyncRedisKVStore>,
    config: RedisGovernanceConfig,
}

impl RedisGovernanceStore {
    /// Build a strict store over a shared async Redis connection.
    pub fn new(
        redis: Arc<AsyncRedisKVStore>,
        config: RedisGovernanceConfig,
    ) -> Result<Self, GovernanceError> {
        validate_config(&config)?;
        Ok(Self { redis, config })
    }

    async fn invoke(
        &self,
        operation: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<Vec<String>, GovernanceError> {
        let mut source = String::with_capacity(COMMON_LUA.len() + operation.len() + 1);
        source.push_str(COMMON_LUA);
        source.push('\n');
        source.push_str(operation);
        self.redis
            .evalsha_with_reload(&source, keys, args)
            .await
            .map_err(|_| GovernanceError::BackendUnavailable { backend: "redis" })
    }
}

/// Derive the single Redis Cluster key used for a non-secret key identifier.
///
/// The hash tag contains only a SHA-256 digest. A validated prefix contains no
/// braces, so every governance operation has exactly one unambiguous slot tag.
pub fn redis_governance_key(key_prefix: &str, key_id: &str) -> String {
    let digest = Sha256::digest(key_id.as_bytes());
    format!(
        "{}:{{{}}}",
        key_prefix.trim_end_matches(':'),
        hex::encode(digest)
    )
}

#[async_trait]
impl GovernanceStore for RedisGovernanceStore {
    async fn reserve(&self, request: ReserveRequest) -> Result<Reservation, GovernanceError> {
        validate_reserve_request(&request)?;
        let redis_key = redis_governance_key(&self.config.key_prefix, &request.key_id);
        let reservation_prefix = reservation_prefix(&request.reservation_id);
        let fingerprint = request_fingerprint(&request)?;
        let keys = vec![redis_key.clone()];
        let args = vec![
            reservation_prefix,
            fingerprint,
            request.policy_revision.to_string(),
            request.limits.window_millis.to_string(),
            optional_limit(request.limits.requests_per_window),
            optional_limit(request.limits.tokens_per_window),
            optional_limit(request.limits.total_tokens),
            optional_limit(request.limits.total_micro_usd),
            request.token_ceiling.to_string(),
            request.micro_usd_ceiling.to_string(),
            self.config.reservation_ttl_millis.to_string(),
            self.config.terminal_retention_millis.to_string(),
        ];
        let response = self.invoke(RESERVE_LUA, &keys, &args).await?;

        match response.first().map(String::as_str) {
            Some("reserved") => {
                let reservation = Reservation {
                    reservation_id: request.reservation_id.clone(),
                    key_id: request.key_id.clone(),
                    policy_revision: request.policy_revision,
                    reserved: GovernanceUsage {
                        requests: 1,
                        tokens: request.token_ceiling,
                        micro_usd: request.micro_usd_ceiling,
                    },
                    created_at_millis: response_u64(&response, 1, "reserve_created_at")?,
                    expires_at_millis: response_u64(&response, 2, "reserve_expires_at")?,
                    window_reset_at_millis: response_u64(&response, 3, "reserve_window_reset")?,
                };
                Ok(reservation)
            }
            Some("denied") => Err(GovernanceError::LimitExceeded(parse_denial(&response)?)),
            Some("conflict") => Err(GovernanceError::ReservationConflict {
                reservation_id: request.reservation_id,
            }),
            Some("terminal") => Err(GovernanceError::TerminalConflict {
                reservation_id: request.reservation_id,
                state: response_terminal_state(&response, 1)?,
            }),
            _ => Err(protocol_error()),
        }
    }

    async fn settle(&self, request: SettleRequest) -> Result<Settlement, GovernanceError> {
        validate_reservation_id(&request.reservation_id)?;
        validate_key_id(&request.key_id)?;
        validate_lua_integer(request.actual_tokens, "actual_tokens")?;
        validate_lua_integer(request.actual_micro_usd, "actual_micro_usd")?;
        let keys = vec![redis_governance_key(
            &self.config.key_prefix,
            &request.key_id,
        )];
        let args = vec![
            reservation_prefix(&request.reservation_id),
            request.actual_tokens.to_string(),
            request.actual_micro_usd.to_string(),
            self.config.terminal_retention_millis.to_string(),
        ];
        let response = self.invoke(SETTLE_LUA, &keys, &args).await?;

        match response.first().map(String::as_str) {
            Some("settled") => Ok(Settlement {
                reservation_id: request.reservation_id,
                key_id: request.key_id,
                policy_revision: response_u64(&response, 1, "settle_policy_revision")?,
                reserved: GovernanceUsage {
                    requests: 1,
                    tokens: response_u64(&response, 2, "settle_reserved_tokens")?,
                    micro_usd: response_u64(&response, 3, "settle_reserved_micro_usd")?,
                },
                actual: GovernanceUsage {
                    requests: 1,
                    tokens: response_u64(&response, 4, "settle_actual_tokens")?,
                    micro_usd: response_u64(&response, 5, "settle_actual_micro_usd")?,
                },
                tokens_exceeded_reservation: response_bool(&response, 6, "settle_tokens_exceeded")?,
                micro_usd_exceeded_reservation: response_bool(
                    &response,
                    7,
                    "settle_micro_usd_exceeded",
                )?,
                settled_at_millis: response_u64(&response, 8, "settle_terminal_at")?,
            }),
            Some("terminal") => Err(GovernanceError::TerminalConflict {
                reservation_id: request.reservation_id,
                state: response_terminal_state(&response, 1)?,
            }),
            Some("not_found") => Err(GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id,
            }),
            _ => Err(protocol_error()),
        }
    }

    async fn release(&self, request: ReleaseRequest) -> Result<Release, GovernanceError> {
        validate_reservation_id(&request.reservation_id)?;
        validate_key_id(&request.key_id)?;
        let keys = vec![redis_governance_key(
            &self.config.key_prefix,
            &request.key_id,
        )];
        let args = vec![
            reservation_prefix(&request.reservation_id),
            self.config.terminal_retention_millis.to_string(),
        ];
        let response = self.invoke(RELEASE_LUA, &keys, &args).await?;

        match response.first().map(String::as_str) {
            Some("released") => Ok(Release {
                reservation_id: request.reservation_id,
                key_id: request.key_id,
                policy_revision: response_u64(&response, 1, "release_policy_revision")?,
                released: GovernanceUsage {
                    requests: 1,
                    tokens: response_u64(&response, 2, "release_reserved_tokens")?,
                    micro_usd: response_u64(&response, 3, "release_reserved_micro_usd")?,
                },
                released_at_millis: response_u64(&response, 4, "release_terminal_at")?,
            }),
            Some("terminal") => Err(GovernanceError::TerminalConflict {
                reservation_id: request.reservation_id,
                state: response_terminal_state(&response, 1)?,
            }),
            Some("not_found") => Err(GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id,
            }),
            _ => Err(protocol_error()),
        }
    }

    async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
        validate_snapshot_key(&key)?;
        let redis_key = redis_governance_key(&self.config.key_prefix, &key.key_id);
        let keys = vec![redis_key];
        let args = vec![
            key.limits.window_millis.to_string(),
            self.config.terminal_retention_millis.to_string(),
        ];
        let response = self.invoke(SNAPSHOT_LUA, &keys, &args).await?;
        if response.first().map(String::as_str) != Some("snapshot") {
            return Err(protocol_error());
        }
        let checked_at_millis = response_u64(&response, 1, "snapshot_checked_at")?;
        let reset_at_millis = response_u64(&response, 2, "snapshot_window_reset")?;

        Ok(GovernanceSnapshot {
            key_id: key.key_id,
            policy_revision: key.policy_revision,
            requests_per_window: counter_snapshot(
                key.limits.requests_per_window,
                response_u64(&response, 3, "snapshot_window_used_requests")?,
                response_u64(&response, 4, "snapshot_window_reserved_requests")?,
                Some(reset_at_millis),
            ),
            tokens_per_window: counter_snapshot(
                key.limits.tokens_per_window,
                response_u64(&response, 5, "snapshot_window_used_tokens")?,
                response_u64(&response, 6, "snapshot_window_reserved_tokens")?,
                Some(reset_at_millis),
            ),
            total_tokens: counter_snapshot(
                key.limits.total_tokens,
                response_u64(&response, 7, "snapshot_total_used_tokens")?,
                response_u64(&response, 8, "snapshot_total_reserved_tokens")?,
                None,
            ),
            total_micro_usd: counter_snapshot(
                key.limits.total_micro_usd,
                response_u64(&response, 9, "snapshot_total_used_micro_usd")?,
                response_u64(&response, 10, "snapshot_total_reserved_micro_usd")?,
                None,
            ),
            backend: GovernanceBackendHealth {
                backend: "redis".to_string(),
                consistency: GovernanceConsistency::Strict,
                status: GovernanceBackendStatus::Healthy,
                checked_at_millis,
            },
        })
    }

    async fn health(&self) -> GovernanceBackendHealth {
        match self.redis.evalsha_with_reload(HEALTH_LUA, &[], &[]).await {
            Ok(response) if response.first().map(String::as_str) == Some("ok") => {
                GovernanceBackendHealth {
                    backend: "redis".to_string(),
                    consistency: GovernanceConsistency::Strict,
                    status: GovernanceBackendStatus::Healthy,
                    checked_at_millis: response
                        .get(1)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(system_now_millis),
                }
            }
            _ => GovernanceBackendHealth {
                backend: "redis".to_string(),
                consistency: GovernanceConsistency::Strict,
                status: GovernanceBackendStatus::Unavailable,
                checked_at_millis: system_now_millis(),
            },
        }
    }
}

fn validate_config(config: &RedisGovernanceConfig) -> Result<(), GovernanceError> {
    if config.key_prefix.trim().is_empty() {
        return Err(invalid("key_prefix", "must not be empty"));
    }
    if config.key_prefix.contains('{') || config.key_prefix.contains('}') {
        return Err(invalid(
            "key_prefix",
            "must not contain cluster hash tag braces",
        ));
    }
    if config.reservation_ttl_millis == 0 {
        return Err(invalid(
            "reservation_ttl_millis",
            "must be greater than zero",
        ));
    }
    if config.terminal_retention_millis < config.reservation_ttl_millis {
        return Err(invalid(
            "terminal_retention_millis",
            "must be at least reservation_ttl_millis",
        ));
    }
    validate_lua_integer(config.reservation_ttl_millis, "reservation_ttl_millis")?;
    validate_lua_integer(
        config.terminal_retention_millis,
        "terminal_retention_millis",
    )
}

fn validate_reserve_request(request: &ReserveRequest) -> Result<(), GovernanceError> {
    validate_reservation_id(&request.reservation_id)?;
    validate_key_id(&request.key_id)?;
    validate_limits(&request.limits)?;
    validate_lua_integer(request.token_ceiling, "token_ceiling")?;
    validate_lua_integer(request.micro_usd_ceiling, "micro_usd_ceiling")
}

fn validate_snapshot_key(key: &SnapshotKey) -> Result<(), GovernanceError> {
    validate_key_id(&key.key_id)?;
    validate_limits(&key.limits)
}

fn validate_key_id(key_id: &str) -> Result<(), GovernanceError> {
    if key_id.trim().is_empty() {
        return Err(invalid("key_id", "must not be empty"));
    }
    Ok(())
}

fn validate_limits(limits: &GovernanceLimits) -> Result<(), GovernanceError> {
    if limits.window_millis == 0 {
        return Err(invalid("window_millis", "must be greater than zero"));
    }
    validate_lua_integer(limits.window_millis, "window_millis")?;
    for (value, field) in [
        (limits.requests_per_window, "requests_per_window"),
        (limits.tokens_per_window, "tokens_per_window"),
        (limits.total_tokens, "total_tokens"),
        (limits.total_micro_usd, "total_micro_usd"),
    ] {
        if let Some(value) = value {
            validate_lua_integer(value, field)?;
        }
    }
    Ok(())
}

fn validate_reservation_id(reservation_id: &str) -> Result<(), GovernanceError> {
    if reservation_id.trim().is_empty() {
        return Err(invalid("reservation_id", "must not be empty"));
    }
    Ok(())
}

fn validate_lua_integer(value: u64, field: &'static str) -> Result<(), GovernanceError> {
    if value > LUA_MAX_EXACT_INTEGER {
        return Err(invalid(field, "exceeds the exact Redis Lua integer range"));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> GovernanceError {
    GovernanceError::InvalidRequest { field, reason }
}

fn protocol_error() -> GovernanceError {
    GovernanceError::InternalInvariant {
        field: "redis_protocol",
    }
}

fn optional_limit(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn reservation_prefix(reservation_id: &str) -> String {
    format!(
        "r:{}",
        hex::encode(Sha256::digest(reservation_id.as_bytes()))
    )
}

fn request_fingerprint(request: &ReserveRequest) -> Result<String, GovernanceError> {
    let encoded = serde_json::to_vec(request).map_err(|_| GovernanceError::InternalInvariant {
        field: "reservation_fingerprint",
    })?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn parse_denial(response: &[String]) -> Result<GovernanceDenial, GovernanceError> {
    Ok(GovernanceDenial {
        dimension: match response_field(response, 1)? {
            "requests_per_window" => GovernanceDimension::RequestsPerWindow,
            "tokens_per_window" => GovernanceDimension::TokensPerWindow,
            "total_tokens" => GovernanceDimension::TotalTokens,
            "total_micro_usd" => GovernanceDimension::TotalMicroUsd,
            _ => return Err(protocol_error()),
        },
        limit: response_u64(response, 2, "denial_limit")?,
        used: response_u64(response, 3, "denial_used")?,
        reserved: response_u64(response, 4, "denial_reserved")?,
        requested: response_u64(response, 5, "denial_requested")?,
        remaining: response_u64(response, 6, "denial_remaining")?,
        reset_at_millis: match response_field(response, 7)? {
            "" => None,
            value => Some(value.parse().map_err(|_| protocol_error())?),
        },
    })
}

fn response_terminal_state(
    response: &[String],
    index: usize,
) -> Result<ReservationTerminalState, GovernanceError> {
    match response_field(response, index)? {
        "settled" => Ok(ReservationTerminalState::Settled),
        "released" => Ok(ReservationTerminalState::Released),
        "expired" => Ok(ReservationTerminalState::Expired),
        _ => Err(protocol_error()),
    }
}

fn response_field(response: &[String], index: usize) -> Result<&str, GovernanceError> {
    response
        .get(index)
        .map(String::as_str)
        .ok_or_else(protocol_error)
}

fn response_u64(
    response: &[String],
    index: usize,
    _field: &'static str,
) -> Result<u64, GovernanceError> {
    response_field(response, index)?
        .parse()
        .map_err(|_| protocol_error())
}

fn response_bool(
    response: &[String],
    index: usize,
    _field: &'static str,
) -> Result<bool, GovernanceError> {
    match response_field(response, index)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(protocol_error()),
    }
}

fn counter_snapshot(
    limit: Option<u64>,
    used: u64,
    reserved: u64,
    reset_at_millis: Option<u64>,
) -> CounterSnapshot {
    CounterSnapshot {
        limit,
        used,
        reserved,
        remaining: limit.map(|limit| limit.saturating_sub(used.saturating_add(reserved))),
        reset_at_millis,
    }
}

fn system_now_millis() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
