//! Atomic governance accounting contracts and the approximate in-memory store.

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Consistency guarantee offered by a governance backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceConsistency {
    /// Process-local accounting intended for single-node or best-effort use.
    Approximate,
    /// Shared accounting that serializes admission across gateway nodes.
    Strict,
}

/// Current availability of a governance backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceBackendStatus {
    /// The backend is available for admission and settlement.
    Healthy,
    /// The backend is available with a reduced guarantee.
    Degraded,
    /// The backend cannot currently serve governance operations.
    Unavailable,
}

/// Secret-free health information suitable for admin and key introspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceBackendHealth {
    /// Stable backend kind, such as `memory` or `redis`.
    pub backend: String,
    /// Consistency guarantee currently offered by the backend.
    pub consistency: GovernanceConsistency,
    /// Current backend availability.
    pub status: GovernanceBackendStatus,
    /// Unix time in milliseconds when the health value was produced.
    pub checked_at_millis: u64,
}

/// Integer limits applied to one governed key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLimits {
    /// Maximum admitted requests in one fixed window.
    pub requests_per_window: Option<u64>,
    /// Maximum admitted tokens in one fixed window.
    pub tokens_per_window: Option<u64>,
    /// Maximum settled and reserved tokens over the process lifetime.
    pub total_tokens: Option<u64>,
    /// Maximum settled and reserved cost in micro-USD over the process lifetime.
    pub total_micro_usd: Option<u64>,
    /// Fixed request and token window length in milliseconds.
    pub window_millis: u64,
}

impl Default for GovernanceLimits {
    fn default() -> Self {
        Self {
            requests_per_window: None,
            tokens_per_window: None,
            total_tokens: None,
            total_micro_usd: None,
            window_millis: 60_000,
        }
    }
}

/// Integer request, token, and monetary units associated with one operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceUsage {
    /// Number of logical ingress requests.
    pub requests: u64,
    /// Number of input and output tokens combined.
    pub tokens: u64,
    /// Cost in micro-USD.
    pub micro_usd: u64,
}

/// Input for an atomic admission attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRequest {
    /// Server-generated idempotency identifier for this logical request.
    pub reservation_id: String,
    /// Immutable, non-secret identifier of the authenticated key.
    pub key_id: String,
    /// Policy revision used to calculate the reservation.
    pub policy_revision: u64,
    /// Limits resolved from the effective key policy.
    pub limits: GovernanceLimits,
    /// Conservative maximum tokens this request may settle.
    pub token_ceiling: u64,
    /// Conservative maximum cost in micro-USD this request may settle.
    pub micro_usd_ceiling: u64,
}

/// Successful time-bounded admission returned by [`GovernanceStore::reserve`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// Server-generated reservation identifier.
    pub reservation_id: String,
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Policy revision used for admission.
    pub policy_revision: u64,
    /// Units held until settlement, release, or lease expiry.
    pub reserved: GovernanceUsage,
    /// Unix time in milliseconds when admission succeeded.
    pub created_at_millis: u64,
    /// Unix time in milliseconds when the reservation lease expires.
    pub expires_at_millis: u64,
    /// End of the fixed request and token window used for admission.
    pub window_reset_at_millis: u64,
}

/// Input for settling a reservation with actual usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleRequest {
    /// Identifier returned by [`GovernanceStore::reserve`].
    pub reservation_id: String,
    /// Immutable, non-secret governed key identifier used to locate shared state.
    pub key_id: String,
    /// Actual input and output tokens combined.
    pub actual_tokens: u64,
    /// Actual cost in micro-USD.
    pub actual_micro_usd: u64,
}

/// Idempotent result of converting reserved units into actual usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    /// Reservation that was settled.
    pub reservation_id: String,
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Policy revision used for the original admission.
    pub policy_revision: u64,
    /// Units originally held by the reservation.
    pub reserved: GovernanceUsage,
    /// Units charged by settlement.
    pub actual: GovernanceUsage,
    /// Whether actual tokens exceeded the admitted token ceiling.
    pub tokens_exceeded_reservation: bool,
    /// Whether actual micro-USD exceeded the admitted monetary ceiling.
    pub micro_usd_exceeded_reservation: bool,
    /// Unix time in milliseconds when settlement won the terminal transition.
    pub settled_at_millis: u64,
}

/// Input for releasing a reservation without billable usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// Identifier returned by [`GovernanceStore::reserve`].
    pub reservation_id: String,
    /// Immutable, non-secret governed key identifier used to locate shared state.
    pub key_id: String,
}

/// Idempotent result of releasing all held units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// Reservation that was released.
    pub reservation_id: String,
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Policy revision used for the original admission.
    pub policy_revision: u64,
    /// Units returned to the available balance.
    pub released: GovernanceUsage,
    /// Unix time in milliseconds when release won the terminal transition.
    pub released_at_millis: u64,
}

/// Secret-free key and limits used to obtain a governance snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotKey {
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Current effective policy revision.
    pub policy_revision: u64,
    /// Current effective governance limits.
    pub limits: GovernanceLimits,
}

/// Usage and reservation values for one limit dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSnapshot {
    /// Configured hard limit, or `None` when unlimited.
    pub limit: Option<u64>,
    /// Units charged by completed settlements.
    pub used: u64,
    /// Units held by active reservations.
    pub reserved: u64,
    /// Units available before the hard limit, or `None` when unlimited.
    pub remaining: Option<u64>,
    /// Fixed-window reset instant, or `None` for lifetime dimensions.
    pub reset_at_millis: Option<u64>,
}

impl CounterSnapshot {
    fn new(limit: Option<u64>, used: u64, reserved: u64, reset_at_millis: Option<u64>) -> Self {
        Self {
            limit,
            used,
            reserved,
            remaining: limit.map(|value| value.saturating_sub(used.saturating_add(reserved))),
            reset_at_millis,
        }
    }
}

/// Complete usage view for one governed key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSnapshot {
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Current effective policy revision.
    pub policy_revision: u64,
    /// Request usage in the current fixed window.
    pub requests_per_window: CounterSnapshot,
    /// Token usage in the current fixed window.
    pub tokens_per_window: CounterSnapshot,
    /// Lifetime token usage in this store.
    pub total_tokens: CounterSnapshot,
    /// Lifetime monetary usage in micro-USD in this store.
    pub total_micro_usd: CounterSnapshot,
    /// Backend health and consistency associated with this snapshot.
    pub backend: GovernanceBackendHealth,
}

/// Limit dimension that rejected an atomic admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDimension {
    /// Request count in the current fixed window.
    RequestsPerWindow,
    /// Token count in the current fixed window.
    TokensPerWindow,
    /// Total token budget.
    TotalTokens,
    /// Total monetary budget in micro-USD.
    TotalMicroUsd,
}

/// Structured denial returned without reserving any units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDenial {
    /// Limit dimension that rejected the request.
    pub dimension: GovernanceDimension,
    /// Configured hard limit.
    pub limit: u64,
    /// Units already charged.
    pub used: u64,
    /// Units held by active reservations.
    pub reserved: u64,
    /// Units requested by this admission attempt.
    pub requested: u64,
    /// Units available before this attempt.
    pub remaining: u64,
    /// Fixed-window reset instant, or `None` for lifetime dimensions.
    pub reset_at_millis: Option<u64>,
}

/// Existing terminal state that prevented a different transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationTerminalState {
    /// Actual usage has already been charged.
    Settled,
    /// Held units have already been released.
    Released,
    /// The reservation lease expired and held units were reclaimed.
    Expired,
}

/// Failure returned by a governance backend operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceError {
    /// A request contains an empty identifier, invalid window, or invalid store bound.
    #[error("invalid governance field '{field}': {reason}")]
    InvalidRequest {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason suitable for logs.
        reason: &'static str,
    },
    /// A hard limit rejected admission without mutating counters.
    #[error("governance limit exceeded: {0:?}")]
    LimitExceeded(GovernanceDenial),
    /// A reservation identifier was reused for different admission input.
    #[error("reservation '{reservation_id}' was reused with different input")]
    ReservationConflict {
        /// Conflicting reservation identifier.
        reservation_id: String,
    },
    /// No active or retained terminal record has this identifier.
    #[error("reservation '{reservation_id}' was not found")]
    ReservationNotFound {
        /// Missing reservation identifier.
        reservation_id: String,
    },
    /// A remote governance backend could not execute the operation.
    #[error("governance backend '{backend}' is unavailable")]
    BackendUnavailable {
        /// Stable backend kind. Never contains a connection URL.
        backend: &'static str,
    },
    /// A different terminal transition already won.
    #[error("reservation '{reservation_id}' is already {state:?}")]
    TerminalConflict {
        /// Reservation identifier.
        reservation_id: String,
        /// Existing terminal state.
        state: ReservationTerminalState,
    },
    /// Integer arithmetic could not represent a counter or timestamp.
    #[error("governance arithmetic overflow in '{field}'")]
    ArithmeticOverflow {
        /// Counter or timestamp that overflowed.
        field: &'static str,
    },
    /// Internal reservation and counter state diverged.
    #[error("governance invariant failed for '{field}'")]
    InternalInvariant {
        /// Counter whose invariant failed.
        field: &'static str,
    },
}

/// Storage contract for governance admission, settlement, and introspection.
#[async_trait]
pub trait GovernanceStore: Send + Sync {
    /// Atomically check every limit and hold the requested ceilings.
    async fn reserve(&self, request: ReserveRequest) -> Result<Reservation, GovernanceError>;

    /// Atomically replace a reservation with actual usage exactly once.
    async fn settle(&self, request: SettleRequest) -> Result<Settlement, GovernanceError>;

    /// Atomically release a reservation without charging usage exactly once.
    async fn release(&self, request: ReleaseRequest) -> Result<Release, GovernanceError>;

    /// Return current used, reserved, remaining, reset, and backend values.
    async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError>;

    /// Return current backend health without exposing backend credentials.
    async fn health(&self) -> GovernanceBackendHealth;
}

/// Time and retention bounds for [`InMemoryGovernanceStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InMemoryGovernanceConfig {
    /// Maximum lifetime of an unsettled reservation in milliseconds.
    pub reservation_ttl_millis: u64,
    /// Retention for idempotent terminal outcomes in milliseconds.
    pub terminal_retention_millis: u64,
}

impl Default for InMemoryGovernanceConfig {
    fn default() -> Self {
        Self {
            reservation_ttl_millis: 120_000,
            terminal_retention_millis: 300_000,
        }
    }
}

trait Clock: Send + Sync {
    fn now_millis(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}

/// Process-local approximate governance store with atomic in-process updates.
#[derive(Clone)]
pub struct InMemoryGovernanceStore {
    inner: Arc<InMemoryInner>,
}

struct InMemoryInner {
    config: InMemoryGovernanceConfig,
    clock: Arc<dyn Clock>,
    state: Mutex<MemoryState>,
}

#[derive(Debug, Clone, Default)]
struct MemoryState {
    keys: HashMap<String, KeyState>,
    reservations: HashMap<String, ReservationRecord>,
}

#[derive(Debug, Clone, Default)]
struct KeyState {
    window_millis: u64,
    window_start_millis: u64,
    window_reset_at_millis: u64,
    window_used_requests: u64,
    window_reserved_requests: u64,
    window_used_tokens: u64,
    window_reserved_tokens: u64,
    total_used_tokens: u64,
    total_reserved_tokens: u64,
    total_used_micro_usd: u64,
    total_reserved_micro_usd: u64,
}

#[derive(Debug, Clone)]
struct ReservationRecord {
    request: ReserveRequest,
    reservation: Reservation,
    window_start_millis: u64,
    outcome: ReservationOutcome,
}

#[derive(Debug, Clone)]
enum ReservationOutcome {
    Active,
    Settled(Settlement),
    Released(Release),
    Expired { expired_at_millis: u64 },
}

impl ReservationOutcome {
    fn terminal_state(&self) -> Option<ReservationTerminalState> {
        match self {
            Self::Active => None,
            Self::Settled(_) => Some(ReservationTerminalState::Settled),
            Self::Released(_) => Some(ReservationTerminalState::Released),
            Self::Expired { .. } => Some(ReservationTerminalState::Expired),
        }
    }

    fn terminal_at_millis(&self) -> Option<u64> {
        match self {
            Self::Active => None,
            Self::Settled(value) => Some(value.settled_at_millis),
            Self::Released(value) => Some(value.released_at_millis),
            Self::Expired { expired_at_millis } => Some(*expired_at_millis),
        }
    }
}

impl InMemoryGovernanceStore {
    /// Create an empty approximate store with bounded reservation retention.
    pub fn new(config: InMemoryGovernanceConfig) -> Result<Self, GovernanceError> {
        Self::with_clock_inner(config, Arc::new(SystemClock))
    }

    #[cfg(test)]
    fn with_clock(
        config: InMemoryGovernanceConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GovernanceError> {
        Self::with_clock_inner(config, clock)
    }

    fn with_clock_inner(
        config: InMemoryGovernanceConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GovernanceError> {
        if config.reservation_ttl_millis == 0 {
            return Err(GovernanceError::InvalidRequest {
                field: "reservation_ttl_millis",
                reason: "must be greater than zero",
            });
        }
        if config.terminal_retention_millis == 0 {
            return Err(GovernanceError::InvalidRequest {
                field: "terminal_retention_millis",
                reason: "must be greater than zero",
            });
        }
        if config.terminal_retention_millis < config.reservation_ttl_millis {
            return Err(GovernanceError::InvalidRequest {
                field: "terminal_retention_millis",
                reason: "must be at least reservation_ttl_millis",
            });
        }
        Ok(Self {
            inner: Arc::new(InMemoryInner {
                config,
                clock,
                state: Mutex::new(MemoryState::default()),
            }),
        })
    }

    fn backend_health(&self, now_millis: u64) -> GovernanceBackendHealth {
        GovernanceBackendHealth {
            backend: "memory".to_string(),
            consistency: GovernanceConsistency::Approximate,
            status: GovernanceBackendStatus::Healthy,
            checked_at_millis: now_millis,
        }
    }
}

impl Default for InMemoryGovernanceStore {
    fn default() -> Self {
        Self::new(InMemoryGovernanceConfig::default())
            .expect("default in-memory governance bounds are valid")
    }
}

#[async_trait]
impl GovernanceStore for InMemoryGovernanceStore {
    async fn reserve(&self, request: ReserveRequest) -> Result<Reservation, GovernanceError> {
        validate_reserve_request(&request)?;
        let now_millis = self.inner.clock.now_millis();
        let expires_at_millis = now_millis
            .checked_add(self.inner.config.reservation_ttl_millis)
            .ok_or(GovernanceError::ArithmeticOverflow {
                field: "expires_at_millis",
            })?;
        let mut state = self.inner.state.lock();
        cleanup_expired(
            &mut state,
            now_millis,
            self.inner.config.terminal_retention_millis,
        )?;

        if let Some(existing) = state.reservations.get(&request.reservation_id) {
            if existing.request != request {
                return Err(GovernanceError::ReservationConflict {
                    reservation_id: request.reservation_id,
                });
            }
            if let Some(terminal_state) = existing.outcome.terminal_state() {
                return Err(GovernanceError::TerminalConflict {
                    reservation_id: request.reservation_id,
                    state: terminal_state,
                });
            }
            return Ok(existing.reservation.clone());
        }

        let (next_key_state, window_start_millis, window_reset_at_millis) = {
            let key_state = state.keys.entry(request.key_id.clone()).or_default();
            ensure_window(key_state, now_millis, request.limits.window_millis)?;
            let next_key_state = reserve_units(key_state, &request)?;
            (
                next_key_state,
                key_state.window_start_millis,
                key_state.window_reset_at_millis,
            )
        };

        let reserved = GovernanceUsage {
            requests: 1,
            tokens: request.token_ceiling,
            micro_usd: request.micro_usd_ceiling,
        };
        let reservation = Reservation {
            reservation_id: request.reservation_id.clone(),
            key_id: request.key_id.clone(),
            policy_revision: request.policy_revision,
            reserved,
            created_at_millis: now_millis,
            expires_at_millis,
            window_reset_at_millis,
        };
        state.keys.insert(request.key_id.clone(), next_key_state);
        state.reservations.insert(
            request.reservation_id.clone(),
            ReservationRecord {
                request,
                reservation: reservation.clone(),
                window_start_millis,
                outcome: ReservationOutcome::Active,
            },
        );
        Ok(reservation)
    }

    async fn settle(&self, request: SettleRequest) -> Result<Settlement, GovernanceError> {
        validate_reservation_id(&request.reservation_id)?;
        validate_key_id(&request.key_id)?;
        let now_millis = self.inner.clock.now_millis();
        let mut state = self.inner.state.lock();
        cleanup_expired(
            &mut state,
            now_millis,
            self.inner.config.terminal_retention_millis,
        )?;
        let record = state
            .reservations
            .get(&request.reservation_id)
            .cloned()
            .ok_or_else(|| GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id.clone(),
            })?;
        if record.reservation.key_id != request.key_id {
            return Err(GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id,
            });
        }

        match &record.outcome {
            ReservationOutcome::Settled(value) => return Ok(value.clone()),
            ReservationOutcome::Released(_) | ReservationOutcome::Expired { .. } => {
                return Err(GovernanceError::TerminalConflict {
                    reservation_id: request.reservation_id,
                    state: record
                        .outcome
                        .terminal_state()
                        .expect("outcome is terminal"),
                });
            }
            ReservationOutcome::Active => {}
        }

        let actual = GovernanceUsage {
            requests: 1,
            tokens: request.actual_tokens,
            micro_usd: request.actual_micro_usd,
        };
        let next_key_state = {
            let key_state = state.keys.get_mut(&record.reservation.key_id).ok_or(
                GovernanceError::InternalInvariant {
                    field: "reservation_key",
                },
            )?;
            ensure_window(key_state, now_millis, record.request.limits.window_millis)?;
            settle_units(key_state, &record, actual)?
        };
        let settlement = Settlement {
            reservation_id: record.reservation.reservation_id.clone(),
            key_id: record.reservation.key_id.clone(),
            policy_revision: record.reservation.policy_revision,
            reserved: record.reservation.reserved,
            actual,
            tokens_exceeded_reservation: actual.tokens > record.reservation.reserved.tokens,
            micro_usd_exceeded_reservation: actual.micro_usd
                > record.reservation.reserved.micro_usd,
            settled_at_millis: now_millis,
        };
        state
            .keys
            .insert(record.reservation.key_id.clone(), next_key_state);
        state
            .reservations
            .get_mut(&record.reservation.reservation_id)
            .expect("reservation record remains present while locked")
            .outcome = ReservationOutcome::Settled(settlement.clone());
        Ok(settlement)
    }

    async fn release(&self, request: ReleaseRequest) -> Result<Release, GovernanceError> {
        validate_reservation_id(&request.reservation_id)?;
        validate_key_id(&request.key_id)?;
        let now_millis = self.inner.clock.now_millis();
        let mut state = self.inner.state.lock();
        cleanup_expired(
            &mut state,
            now_millis,
            self.inner.config.terminal_retention_millis,
        )?;
        let record = state
            .reservations
            .get(&request.reservation_id)
            .cloned()
            .ok_or_else(|| GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id.clone(),
            })?;
        if record.reservation.key_id != request.key_id {
            return Err(GovernanceError::ReservationNotFound {
                reservation_id: request.reservation_id,
            });
        }

        match &record.outcome {
            ReservationOutcome::Released(value) => return Ok(value.clone()),
            ReservationOutcome::Settled(_) | ReservationOutcome::Expired { .. } => {
                return Err(GovernanceError::TerminalConflict {
                    reservation_id: request.reservation_id,
                    state: record
                        .outcome
                        .terminal_state()
                        .expect("outcome is terminal"),
                });
            }
            ReservationOutcome::Active => {}
        }

        let next_key_state = {
            let key_state = state.keys.get(&record.reservation.key_id).ok_or(
                GovernanceError::InternalInvariant {
                    field: "reservation_key",
                },
            )?;
            release_units(key_state, &record)?
        };
        let release = Release {
            reservation_id: record.reservation.reservation_id.clone(),
            key_id: record.reservation.key_id.clone(),
            policy_revision: record.reservation.policy_revision,
            released: record.reservation.reserved,
            released_at_millis: now_millis,
        };
        state
            .keys
            .insert(record.reservation.key_id.clone(), next_key_state);
        state
            .reservations
            .get_mut(&record.reservation.reservation_id)
            .expect("reservation record remains present while locked")
            .outcome = ReservationOutcome::Released(release.clone());
        Ok(release)
    }

    async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
        validate_snapshot_key(&key)?;
        let now_millis = self.inner.clock.now_millis();
        let mut state = self.inner.state.lock();
        cleanup_expired(
            &mut state,
            now_millis,
            self.inner.config.terminal_retention_millis,
        )?;
        let key_state = state.keys.entry(key.key_id.clone()).or_default();
        ensure_window(key_state, now_millis, key.limits.window_millis)?;

        Ok(GovernanceSnapshot {
            key_id: key.key_id,
            policy_revision: key.policy_revision,
            requests_per_window: CounterSnapshot::new(
                key.limits.requests_per_window,
                key_state.window_used_requests,
                key_state.window_reserved_requests,
                Some(key_state.window_reset_at_millis),
            ),
            tokens_per_window: CounterSnapshot::new(
                key.limits.tokens_per_window,
                key_state.window_used_tokens,
                key_state.window_reserved_tokens,
                Some(key_state.window_reset_at_millis),
            ),
            total_tokens: CounterSnapshot::new(
                key.limits.total_tokens,
                key_state.total_used_tokens,
                key_state.total_reserved_tokens,
                None,
            ),
            total_micro_usd: CounterSnapshot::new(
                key.limits.total_micro_usd,
                key_state.total_used_micro_usd,
                key_state.total_reserved_micro_usd,
                None,
            ),
            backend: self.backend_health(now_millis),
        })
    }

    async fn health(&self) -> GovernanceBackendHealth {
        self.backend_health(self.inner.clock.now_millis())
    }
}

fn validate_reserve_request(request: &ReserveRequest) -> Result<(), GovernanceError> {
    validate_reservation_id(&request.reservation_id)?;
    validate_key_id(&request.key_id)?;
    validate_window(request.limits.window_millis)
}

fn validate_snapshot_key(key: &SnapshotKey) -> Result<(), GovernanceError> {
    validate_key_id(&key.key_id)?;
    validate_window(key.limits.window_millis)
}

fn validate_reservation_id(reservation_id: &str) -> Result<(), GovernanceError> {
    if reservation_id.trim().is_empty() {
        return Err(GovernanceError::InvalidRequest {
            field: "reservation_id",
            reason: "must not be empty",
        });
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), GovernanceError> {
    if key_id.trim().is_empty() {
        return Err(GovernanceError::InvalidRequest {
            field: "key_id",
            reason: "must not be empty",
        });
    }
    Ok(())
}

fn validate_window(window_millis: u64) -> Result<(), GovernanceError> {
    if window_millis == 0 {
        return Err(GovernanceError::InvalidRequest {
            field: "window_millis",
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn ensure_window(
    state: &mut KeyState,
    now_millis: u64,
    window_millis: u64,
) -> Result<(), GovernanceError> {
    let window_start_millis = now_millis - (now_millis % window_millis);
    let window_reset_at_millis = window_start_millis.checked_add(window_millis).ok_or(
        GovernanceError::ArithmeticOverflow {
            field: "window_reset_at_millis",
        },
    )?;
    if state.window_millis != window_millis || state.window_start_millis != window_start_millis {
        state.window_millis = window_millis;
        state.window_start_millis = window_start_millis;
        state.window_reset_at_millis = window_reset_at_millis;
        state.window_used_requests = 0;
        state.window_reserved_requests = 0;
        state.window_used_tokens = 0;
        state.window_reserved_tokens = 0;
    }
    Ok(())
}

fn reserve_units(state: &KeyState, request: &ReserveRequest) -> Result<KeyState, GovernanceError> {
    check_limit(
        GovernanceDimension::RequestsPerWindow,
        request.limits.requests_per_window,
        state.window_used_requests,
        state.window_reserved_requests,
        1,
        Some(state.window_reset_at_millis),
    )?;
    check_limit(
        GovernanceDimension::TokensPerWindow,
        request.limits.tokens_per_window,
        state.window_used_tokens,
        state.window_reserved_tokens,
        request.token_ceiling,
        Some(state.window_reset_at_millis),
    )?;
    check_limit(
        GovernanceDimension::TotalTokens,
        request.limits.total_tokens,
        state.total_used_tokens,
        state.total_reserved_tokens,
        request.token_ceiling,
        None,
    )?;
    check_limit(
        GovernanceDimension::TotalMicroUsd,
        request.limits.total_micro_usd,
        state.total_used_micro_usd,
        state.total_reserved_micro_usd,
        request.micro_usd_ceiling,
        None,
    )?;

    let mut next = state.clone();
    next.window_reserved_requests = checked_add(
        state.window_reserved_requests,
        1,
        "window_reserved_requests",
    )?;
    next.window_reserved_tokens = checked_add(
        state.window_reserved_tokens,
        request.token_ceiling,
        "window_reserved_tokens",
    )?;
    next.total_reserved_tokens = checked_add(
        state.total_reserved_tokens,
        request.token_ceiling,
        "total_reserved_tokens",
    )?;
    next.total_reserved_micro_usd = checked_add(
        state.total_reserved_micro_usd,
        request.micro_usd_ceiling,
        "total_reserved_micro_usd",
    )?;
    Ok(next)
}

fn check_limit(
    dimension: GovernanceDimension,
    limit: Option<u64>,
    used: u64,
    reserved: u64,
    requested: u64,
    reset_at_millis: Option<u64>,
) -> Result<(), GovernanceError> {
    let occupied = checked_add(used, reserved, "used_and_reserved")?;
    let prospective = checked_add(occupied, requested, "prospective_usage")?;
    if let Some(limit) = limit {
        if prospective > limit {
            return Err(GovernanceError::LimitExceeded(GovernanceDenial {
                dimension,
                limit,
                used,
                reserved,
                requested,
                remaining: limit.saturating_sub(occupied),
                reset_at_millis,
            }));
        }
    }
    Ok(())
}

fn settle_units(
    state: &KeyState,
    record: &ReservationRecord,
    actual: GovernanceUsage,
) -> Result<KeyState, GovernanceError> {
    let mut next = release_units(state, record)?;
    if same_window(&next, record) {
        next.window_used_requests = checked_add(
            next.window_used_requests,
            actual.requests,
            "window_used_requests",
        )?;
        next.window_used_tokens =
            checked_add(next.window_used_tokens, actual.tokens, "window_used_tokens")?;
    }
    next.total_used_tokens =
        checked_add(next.total_used_tokens, actual.tokens, "total_used_tokens")?;
    next.total_used_micro_usd = checked_add(
        next.total_used_micro_usd,
        actual.micro_usd,
        "total_used_micro_usd",
    )?;
    Ok(next)
}

fn release_units(
    state: &KeyState,
    record: &ReservationRecord,
) -> Result<KeyState, GovernanceError> {
    let mut next = state.clone();
    if same_window(&next, record) {
        next.window_reserved_requests = checked_sub(
            next.window_reserved_requests,
            record.reservation.reserved.requests,
            "window_reserved_requests",
        )?;
        next.window_reserved_tokens = checked_sub(
            next.window_reserved_tokens,
            record.reservation.reserved.tokens,
            "window_reserved_tokens",
        )?;
    }
    next.total_reserved_tokens = checked_sub(
        next.total_reserved_tokens,
        record.reservation.reserved.tokens,
        "total_reserved_tokens",
    )?;
    next.total_reserved_micro_usd = checked_sub(
        next.total_reserved_micro_usd,
        record.reservation.reserved.micro_usd,
        "total_reserved_micro_usd",
    )?;
    Ok(next)
}

fn same_window(state: &KeyState, record: &ReservationRecord) -> bool {
    state.window_millis == record.request.limits.window_millis
        && state.window_start_millis == record.window_start_millis
}

fn cleanup_expired(
    state: &mut MemoryState,
    now_millis: u64,
    terminal_retention_millis: u64,
) -> Result<(), GovernanceError> {
    let expired = state
        .reservations
        .values()
        .filter(|record| {
            matches!(&record.outcome, ReservationOutcome::Active)
                && record.reservation.expires_at_millis <= now_millis
        })
        .cloned()
        .collect::<Vec<_>>();

    for record in expired {
        let key_state = state.keys.get(&record.reservation.key_id).ok_or(
            GovernanceError::InternalInvariant {
                field: "reservation_key",
            },
        )?;
        let next_key_state = release_units(key_state, &record)?;
        state
            .keys
            .insert(record.reservation.key_id.clone(), next_key_state);
        state
            .reservations
            .get_mut(&record.reservation.reservation_id)
            .expect("expired reservation remains present while locked")
            .outcome = ReservationOutcome::Expired {
            expired_at_millis: record.reservation.expires_at_millis,
        };
    }

    state.reservations.retain(|_, record| {
        record
            .outcome
            .terminal_at_millis()
            .is_none_or(|terminal_at| {
                now_millis < terminal_at.saturating_add(terminal_retention_millis)
            })
    });
    Ok(())
}

fn checked_add(left: u64, right: u64, field: &'static str) -> Result<u64, GovernanceError> {
    left.checked_add(right)
        .ok_or(GovernanceError::ArithmeticOverflow { field })
}

fn checked_sub(left: u64, right: u64, field: &'static str) -> Result<u64, GovernanceError> {
    left.checked_sub(right)
        .ok_or(GovernanceError::InternalInvariant { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    #[derive(Default)]
    struct ManualClock {
        now_millis: AtomicU64,
    }

    impl ManualClock {
        fn at(now_millis: u64) -> Self {
            Self {
                now_millis: AtomicU64::new(now_millis),
            }
        }

        fn set(&self, now_millis: u64) {
            self.now_millis.store(now_millis, Ordering::SeqCst);
        }

        fn advance(&self, millis: u64) {
            self.now_millis.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_millis(&self) -> u64 {
            self.now_millis.load(Ordering::SeqCst)
        }
    }

    fn limits() -> GovernanceLimits {
        GovernanceLimits {
            requests_per_window: Some(2),
            tokens_per_window: Some(100),
            total_tokens: Some(150),
            total_micro_usd: Some(1_000),
            window_millis: 60_000,
        }
    }

    fn reservation(id: &str, tokens: u64, micro_usd: u64) -> ReserveRequest {
        ReserveRequest {
            reservation_id: id.to_string(),
            key_id: "key-id-1".to_string(),
            policy_revision: 7,
            limits: limits(),
            token_ceiling: tokens,
            micro_usd_ceiling: micro_usd,
        }
    }

    fn snapshot_key() -> SnapshotKey {
        SnapshotKey {
            key_id: "key-id-1".to_string(),
            policy_revision: 7,
            limits: limits(),
        }
    }

    fn store_with_clock(
        now_millis: u64,
        reservation_ttl_millis: u64,
        terminal_retention_millis: u64,
    ) -> (InMemoryGovernanceStore, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(now_millis));
        let store = InMemoryGovernanceStore::with_clock(
            InMemoryGovernanceConfig {
                reservation_ttl_millis,
                terminal_retention_millis,
            },
            clock.clone(),
        )
        .unwrap();
        (store, clock)
    }

    #[tokio::test]
    async fn denial_on_one_axis_does_not_mutate_any_counter() {
        let store = InMemoryGovernanceStore::new(InMemoryGovernanceConfig::default()).unwrap();

        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();
        let error = store
            .reserve(reservation("request-2", 30, 300))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GovernanceError::LimitExceeded(GovernanceDenial {
                dimension: GovernanceDimension::TokensPerWindow,
                ..
            })
        ));

        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.reserved, 1);
        assert_eq!(snapshot.tokens_per_window.reserved, 80);
        assert_eq!(snapshot.total_tokens.reserved, 80);
        assert_eq!(snapshot.total_micro_usd.reserved, 600);
        assert_eq!(snapshot.requests_per_window.used, 0);
        assert_eq!(snapshot.tokens_per_window.used, 0);
    }

    #[tokio::test]
    async fn duplicate_reserve_is_idempotent_but_changed_reuse_conflicts() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        let request = reservation("request-1", 80, 600);

        let first = store.reserve(request.clone()).await.unwrap();
        let duplicate = store.reserve(request).await.unwrap();
        assert_eq!(duplicate, first);

        let mut changed = reservation("request-1", 79, 600);
        changed.policy_revision = 8;
        assert!(matches!(
            store.reserve(changed).await.unwrap_err(),
            GovernanceError::ReservationConflict { .. }
        ));

        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.reserved, 1);
        assert_eq!(snapshot.tokens_per_window.reserved, 80);
    }

    #[tokio::test]
    async fn settle_is_idempotent_and_charges_actual_usage_once() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();
        let request = SettleRequest {
            reservation_id: "request-1".to_string(),
            key_id: "key-id-1".to_string(),
            actual_tokens: 60,
            actual_micro_usd: 450,
        };

        let first = store.settle(request.clone()).await.unwrap();
        let duplicate = store.settle(request).await.unwrap();
        assert_eq!(duplicate, first);
        assert!(!first.tokens_exceeded_reservation);
        assert!(!first.micro_usd_exceeded_reservation);

        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.used, 1);
        assert_eq!(snapshot.requests_per_window.reserved, 0);
        assert_eq!(snapshot.tokens_per_window.used, 60);
        assert_eq!(snapshot.tokens_per_window.reserved, 0);
        assert_eq!(snapshot.total_tokens.used, 60);
        assert_eq!(snapshot.total_micro_usd.used, 450);

        assert!(matches!(
            store
                .release(ReleaseRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                })
                .await
                .unwrap_err(),
            GovernanceError::TerminalConflict {
                state: ReservationTerminalState::Settled,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn terminal_operations_do_not_reveal_cross_key_reservations() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();

        for error in [
            store
                .settle(SettleRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "different-key".to_string(),
                    actual_tokens: 60,
                    actual_micro_usd: 450,
                })
                .await
                .unwrap_err(),
            store
                .release(ReleaseRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "different-key".to_string(),
                })
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(error, GovernanceError::ReservationNotFound { .. }));
        }

        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.reserved, 1);
        assert_eq!(snapshot.total_tokens.reserved, 80);
    }

    #[tokio::test]
    async fn settlement_charges_and_flags_usage_above_reserved_ceilings() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();

        let settlement = store
            .settle(SettleRequest {
                reservation_id: "request-1".to_string(),
                key_id: "key-id-1".to_string(),
                actual_tokens: 90,
                actual_micro_usd: 601,
            })
            .await
            .unwrap();

        assert!(settlement.tokens_exceeded_reservation);
        assert!(settlement.micro_usd_exceeded_reservation);
        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.tokens_per_window.used, 90);
        assert_eq!(snapshot.tokens_per_window.reserved, 0);
        assert_eq!(snapshot.total_tokens.used, 90);
        assert_eq!(snapshot.total_tokens.reserved, 0);
        assert_eq!(snapshot.total_micro_usd.used, 601);
        assert_eq!(snapshot.total_micro_usd.reserved, 0);
    }

    #[tokio::test]
    async fn release_is_idempotent_and_never_charges_usage() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();
        let request = ReleaseRequest {
            reservation_id: "request-1".to_string(),
            key_id: "key-id-1".to_string(),
        };

        let first = store.release(request.clone()).await.unwrap();
        let duplicate = store.release(request).await.unwrap();
        assert_eq!(duplicate, first);

        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.limit, Some(2));
        assert_eq!(snapshot.requests_per_window.used, 0);
        assert_eq!(snapshot.requests_per_window.reserved, 0);
        assert_eq!(snapshot.requests_per_window.remaining, Some(2));
        assert_eq!(snapshot.tokens_per_window.used, 0);
        assert_eq!(snapshot.tokens_per_window.reserved, 0);
        assert_eq!(snapshot.total_tokens.used, 0);
        assert_eq!(snapshot.total_tokens.reserved, 0);
        assert_eq!(snapshot.total_micro_usd.used, 0);
        assert_eq!(snapshot.total_micro_usd.reserved, 0);

        assert!(matches!(
            store
                .settle(SettleRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                    actual_tokens: 60,
                    actual_micro_usd: 450,
                })
                .await
                .unwrap_err(),
            GovernanceError::TerminalConflict {
                state: ReservationTerminalState::Released,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn settle_and_release_race_has_exactly_one_terminal_winner() {
        let (store, _) = store_with_clock(1_000, 100, 500);
        store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let settle_store = store.clone();
        let settle_barrier = barrier.clone();
        let settle = tokio::spawn(async move {
            settle_barrier.wait().await;
            settle_store
                .settle(SettleRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                    actual_tokens: 60,
                    actual_micro_usd: 450,
                })
                .await
        });

        let release_store = store.clone();
        let release_barrier = barrier.clone();
        let release = tokio::spawn(async move {
            release_barrier.wait().await;
            release_store
                .release(ReleaseRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                })
                .await
        });

        barrier.wait().await;
        let settle_result = settle.await.unwrap();
        let release_result = release.await.unwrap();
        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.reserved, 0);
        assert_eq!(snapshot.tokens_per_window.reserved, 0);
        assert_eq!(snapshot.total_tokens.reserved, 0);
        assert_eq!(snapshot.total_micro_usd.reserved, 0);

        match (settle_result, release_result) {
            (Ok(_), Err(GovernanceError::TerminalConflict { state, .. })) => {
                assert_eq!(state, ReservationTerminalState::Settled);
                assert_eq!(snapshot.requests_per_window.used, 1);
                assert_eq!(snapshot.total_tokens.used, 60);
                assert_eq!(snapshot.total_micro_usd.used, 450);
            }
            (Err(GovernanceError::TerminalConflict { state, .. }), Ok(_)) => {
                assert_eq!(state, ReservationTerminalState::Released);
                assert_eq!(snapshot.requests_per_window.used, 0);
                assert_eq!(snapshot.total_tokens.used, 0);
                assert_eq!(snapshot.total_micro_usd.used, 0);
            }
            other => panic!("unexpected terminal race result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn expired_reservation_is_cleaned_and_tombstone_is_bounded() {
        let (store, clock) = store_with_clock(1_000, 100, 500);
        let reserved = store
            .reserve(reservation("request-1", 80, 600))
            .await
            .unwrap();
        assert_eq!(reserved.expires_at_millis, 1_100);

        clock.advance(100);
        let snapshot = store.snapshot(snapshot_key()).await.unwrap();
        assert_eq!(snapshot.requests_per_window.reserved, 0);
        assert_eq!(snapshot.total_tokens.reserved, 0);
        assert_eq!(snapshot.total_micro_usd.reserved, 0);
        assert!(matches!(
            store
                .release(ReleaseRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                })
                .await
                .unwrap_err(),
            GovernanceError::TerminalConflict {
                state: ReservationTerminalState::Expired,
                ..
            }
        ));

        clock.advance(500);
        store.snapshot(snapshot_key()).await.unwrap();
        assert!(matches!(
            store
                .settle(SettleRequest {
                    reservation_id: "request-1".to_string(),
                    key_id: "key-id-1".to_string(),
                    actual_tokens: 1,
                    actual_micro_usd: 1,
                })
                .await
                .unwrap_err(),
            GovernanceError::ReservationNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn fixed_window_resets_without_erasing_lifetime_usage() {
        let (store, clock) = store_with_clock(1_000, 10_000, 10_000);
        let window_limits = GovernanceLimits {
            requests_per_window: Some(1),
            tokens_per_window: Some(100),
            total_tokens: Some(200),
            total_micro_usd: Some(1_000),
            window_millis: 1_000,
        };
        let request = |id: &str| ReserveRequest {
            reservation_id: id.to_string(),
            key_id: "key-id-1".to_string(),
            policy_revision: 7,
            limits: window_limits.clone(),
            token_ceiling: 100,
            micro_usd_ceiling: 500,
        };
        let key = SnapshotKey {
            key_id: "key-id-1".to_string(),
            policy_revision: 7,
            limits: window_limits.clone(),
        };

        store.reserve(request("request-1")).await.unwrap();
        store
            .settle(SettleRequest {
                reservation_id: "request-1".to_string(),
                key_id: "key-id-1".to_string(),
                actual_tokens: 50,
                actual_micro_usd: 100,
            })
            .await
            .unwrap();
        assert!(matches!(
            store.reserve(request("request-2")).await.unwrap_err(),
            GovernanceError::LimitExceeded(GovernanceDenial {
                dimension: GovernanceDimension::RequestsPerWindow,
                ..
            })
        ));

        clock.set(2_000);
        let reset = store.snapshot(key.clone()).await.unwrap();
        assert_eq!(reset.requests_per_window.used, 0);
        assert_eq!(reset.tokens_per_window.used, 0);
        assert_eq!(reset.total_tokens.used, 50);
        assert_eq!(reset.total_micro_usd.used, 100);

        store.reserve(request("request-2")).await.unwrap();
        let reserved = store.snapshot(key).await.unwrap();
        assert_eq!(reserved.requests_per_window.reserved, 1);
        assert_eq!(reserved.total_tokens.reserved, 100);
        assert_eq!(reserved.total_tokens.remaining, Some(50));
    }

    #[tokio::test]
    async fn health_reports_the_approximate_memory_backend() {
        let (store, _) = store_with_clock(1_234, 100, 500);

        assert_eq!(
            store.health().await,
            GovernanceBackendHealth {
                backend: "memory".to_string(),
                consistency: GovernanceConsistency::Approximate,
                status: GovernanceBackendStatus::Healthy,
                checked_at_millis: 1_234,
            }
        );
    }

    #[test]
    fn reservation_and_terminal_retention_must_be_bounded() {
        assert!(matches!(
            InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
                reservation_ttl_millis: 0,
                terminal_retention_millis: 500,
            }),
            Err(GovernanceError::InvalidRequest { .. })
        ));
        assert!(matches!(
            InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
                reservation_ttl_millis: 100,
                terminal_retention_millis: 0,
            }),
            Err(GovernanceError::InvalidRequest { .. })
        ));
        assert!(matches!(
            InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
                reservation_ttl_millis: 501,
                terminal_retention_millis: 500,
            }),
            Err(GovernanceError::InvalidRequest {
                field: "terminal_retention_millis",
                ..
            })
        ));
    }
}
