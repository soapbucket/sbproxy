//! Fair-share quota pools (WOR-1880, WOR-1993).
//!
//! Tracks `consumed + reserved` per pool member within a rolling window and
//! admits provider attempts under Hard, Soft, or Burst policy.

use crate::governance::{
    GovernanceDenial, GovernanceError, GovernanceLimits, GovernanceStore, ReleaseRequest,
    ReserveRequest, SettleRequest,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How a pool distributes capacity across members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPoolPolicy {
    /// Enforce each member's weighted entitlement. Over-share is denied.
    Hard,
    /// Enforce the pool total only. Over-share is recorded, not denied.
    Soft,
    /// Work-conserving: idle entitlement may be borrowed by busy members.
    Burst,
}

/// Unit of accounting for pool reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPoolDimension {
    /// One unit per provider attempt / request.
    #[default]
    Request,
}

/// Process-local vs cross-replica consistency for pool counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPoolConsistency {
    /// In-process counters only. No mesh or multi-replica coherence.
    #[default]
    Local,
    /// Eventually convergent shared accounting.
    Approximate,
    /// Atomic shared accounting.
    Strong,
}

/// Behavior when a configured shared accounting backend is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPoolFailureMode {
    /// Reject the attempt while accounting is unavailable.
    #[default]
    Closed,
    /// Admit without a reservation only when the backend is unavailable.
    AllowUnreserved,
}

/// Static configuration for one fair-share pool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaPoolConfig {
    /// Operator-facing pool name (also the store key).
    pub name: String,
    /// Rolling window length. Defaults to one minute when omitted.
    #[serde(default = "default_window", with = "humantime_serde_opt")]
    pub window: Duration,
    /// Aggregate capacity (in [`QuotaPoolDimension`] units) across all members.
    pub total_limit: u64,
    /// Relative weights keyed by immutable virtual-key member id.
    pub weights: HashMap<String, u32>,
    /// Admission policy.
    pub policy: QuotaPoolPolicy,
    /// Accounting dimension. Only [`QuotaPoolDimension::Request`] is enabled.
    #[serde(default)]
    pub dimension: QuotaPoolDimension,
    /// Consistency mode.
    #[serde(default)]
    pub consistency: QuotaPoolConsistency,
    /// Behavior when a shared backend cannot execute an operation.
    #[serde(default)]
    pub failure_mode: QuotaPoolFailureMode,
}

fn default_window() -> Duration {
    Duration::from_secs(60)
}

/// Why a pool reservation was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolDeny {
    /// Member would exceed its Hard entitlement.
    OverShare {
        /// Member that was denied.
        member: String,
        /// Units already consumed + reserved for the member.
        load: u64,
        /// Weighted entitlement for the member in this window.
        entitlement: u64,
    },
    /// Pool total capacity is exhausted.
    PoolExhausted {
        /// Aggregate consumed + reserved across members.
        total_load: u64,
        /// Configured pool total.
        total_limit: u64,
    },
    /// Member is not listed in the pool weights.
    UnknownMember {
        /// Requested member name.
        member: String,
    },
    /// Pool name does not match any configured store.
    UnknownPool {
        /// Requested pool name.
        pool: String,
    },
}

/// Typed quota storage failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    /// Admission was rejected by the configured quota policy.
    #[error("quota pool admission denied: {0:?}")]
    Denied(PoolDeny),
    /// The shared accounting backend could not execute the operation.
    #[error("quota pool backend is unavailable")]
    BackendUnavailable,
    /// Reservation state was missing, conflicting, or otherwise invalid.
    #[error("quota pool reservation state is invalid")]
    InvalidState,
}

impl From<PoolDeny> for PoolError {
    fn from(deny: PoolDeny) -> Self {
        Self::Denied(deny)
    }
}

/// A held reservation against a pool member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaReservation {
    /// Pool that issued the reservation.
    pub pool: String,
    /// Immutable caller identity the units were reserved for.
    pub member: String,
    /// Reserved units.
    pub units: u64,
    /// Opaque id for reconcile / release pairing.
    pub reservation_id: String,
}

/// Actual usage observed after a provider attempt completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolUsage {
    /// Units actually consumed (typically 1 for request dimension).
    pub units: u64,
}

/// Soft-policy over-share observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverShareRecord {
    /// Member that exceeded its entitlement.
    pub member: String,
    /// Units over the weighted entitlement at the time of recording.
    pub excess: u64,
}

/// Config validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaPoolConfigError {
    /// Empty pool name.
    EmptyName,
    /// Zero-duration accounting window.
    ZeroWindow,
    /// Zero or missing total limit.
    InvalidTotalLimit,
    /// No member weights configured.
    EmptyWeights,
    /// A weight is zero.
    ZeroWeight {
        /// Member with a zero weight.
        member: String,
    },
    /// Token/cost dimensions are gated until reconcile coverage exists.
    DimensionNotEnabled {
        /// Requested dimension label.
        dimension: &'static str,
    },
}

impl std::fmt::Display for QuotaPoolConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => write!(f, "quota pool name must not be empty"),
            Self::ZeroWindow => write!(f, "quota pool window must be > 0"),
            Self::InvalidTotalLimit => write!(f, "quota pool total_limit must be > 0"),
            Self::EmptyWeights => write!(f, "quota pool weights must not be empty"),
            Self::ZeroWeight { member } => {
                write!(f, "quota pool weight for member {member} must be > 0")
            }
            Self::DimensionNotEnabled { dimension } => {
                write!(f, "quota pool dimension {dimension} is not enabled yet")
            }
        }
    }
}

impl std::error::Error for QuotaPoolConfigError {}

/// Validate the backend-independent quota pool configuration.
pub fn validate_quota_pool_config(config: &QuotaPoolConfig) -> Result<(), QuotaPoolConfigError> {
    if config.name.trim().is_empty() {
        return Err(QuotaPoolConfigError::EmptyName);
    }
    if config.window.is_zero() {
        return Err(QuotaPoolConfigError::ZeroWindow);
    }
    if config.total_limit == 0 {
        return Err(QuotaPoolConfigError::InvalidTotalLimit);
    }
    if config.weights.is_empty() {
        return Err(QuotaPoolConfigError::EmptyWeights);
    }
    for (member, weight) in &config.weights {
        if *weight == 0 {
            return Err(QuotaPoolConfigError::ZeroWeight {
                member: member.clone(),
            });
        }
    }
    // Request is the only enabled dimension; keep the match exhaustive for
    // future Token/Cost variants so they fail validation until tests land.
    match config.dimension {
        QuotaPoolDimension::Request => {}
    }
    Ok(())
}

/// Reservation store for a fair-share pool.
#[async_trait]
pub trait QuotaPoolStore: Send + Sync {
    /// Reserve `units` for `member` in `pool`, or deny.
    async fn reserve(
        &self,
        pool: &str,
        member: &str,
        units: u64,
        reservation_id: &str,
    ) -> Result<QuotaReservation, PoolError>;

    /// Settle a reservation to actual usage (refund over-reserve, add debt on under).
    async fn reconcile(
        &self,
        reservation: QuotaReservation,
        actual: PoolUsage,
    ) -> Result<(), PoolError>;

    /// Drop a reservation without consuming (error / skip path).
    async fn release(&self, reservation: QuotaReservation) -> Result<(), PoolError>;
}

/// Rank candidates by load/weight (ascending) for fair selection.
pub fn rank_by_fair_share(
    loads: &HashMap<String, u64>,
    weights: &HashMap<String, u32>,
    candidates: &[String],
) -> Vec<String> {
    let mut ranked: Vec<(String, f64)> = candidates
        .iter()
        .filter_map(|name| {
            let weight = *weights.get(name)? as f64;
            if weight <= 0.0 {
                return None;
            }
            let load = *loads.get(name).unwrap_or(&0) as f64;
            Some((name.clone(), load / weight))
        })
        .collect();
    ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().map(|(name, _)| name).collect()
}

/// Try candidates in order; on [`PoolDeny`] advance to the next member.
///
/// Returns the first successful reservation and the index into `candidates`.
/// When every candidate is denied, returns the last deny reason.
pub async fn reserve_next_candidate(
    store: &dyn QuotaPoolStore,
    pool: &str,
    candidates: &[&str],
    units: u64,
    reservation_id: &str,
) -> Result<(usize, QuotaReservation), PoolError> {
    let mut last_deny = PoolDeny::PoolExhausted {
        total_load: 0,
        total_limit: 0,
    };
    for (idx, member) in candidates.iter().enumerate() {
        let candidate_reservation_id = format!("{reservation_id}:{idx}");
        match store
            .reserve(pool, member, units, &candidate_reservation_id)
            .await
        {
            Ok(reservation) => return Ok((idx, reservation)),
            Err(PoolError::Denied(deny)) => last_deny = deny,
            Err(error) => return Err(error),
        }
    }
    Err(PoolError::Denied(last_deny))
}

#[derive(Debug)]
struct MemberState {
    consumed: u64,
    reserved: u64,
}

impl MemberState {
    fn load(&self) -> u64 {
        self.consumed.saturating_add(self.reserved)
    }
}

#[derive(Debug, Clone)]
enum LocalReservationOutcome {
    Active,
    Settled(PoolUsage),
    Released,
}

#[derive(Debug, Clone)]
struct LocalReservationRecord {
    reservation: QuotaReservation,
    outcome: LocalReservationOutcome,
}

#[derive(Debug)]
struct PoolState {
    config: QuotaPoolConfig,
    members: HashMap<String, MemberState>,
    reservations: HashMap<String, LocalReservationRecord>,
    window_started: Instant,
    over_shares: HashMap<String, OverShareRecord>,
}

impl PoolState {
    fn new(config: QuotaPoolConfig) -> Self {
        let members = config
            .weights
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    MemberState {
                        consumed: 0,
                        reserved: 0,
                    },
                )
            })
            .collect();
        Self {
            config,
            members,
            reservations: HashMap::new(),
            window_started: Instant::now(),
            over_shares: HashMap::new(),
        }
    }

    fn maybe_roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_started) >= self.config.window {
            for state in self.members.values_mut() {
                state.consumed = 0;
                state.reserved = 0;
            }
            self.reservations.clear();
            self.over_shares.clear();
            self.window_started = now;
        }
    }

    fn total_weight(&self) -> u64 {
        self.config.weights.values().map(|w| u64::from(*w)).sum()
    }

    fn entitlement(&self, member: &str) -> Option<u64> {
        let weight = u64::from(*self.config.weights.get(member)?);
        let total_weight = self.total_weight();
        if total_weight == 0 {
            return None;
        }
        Some(self.config.total_limit.saturating_mul(weight) / total_weight)
    }

    fn total_load(&self) -> u64 {
        self.members.values().map(MemberState::load).sum()
    }

    fn idle_capacity(&self) -> u64 {
        self.config.total_limit.saturating_sub(self.total_load())
    }
}

/// Process-local fair-share pool store.
#[derive(Debug)]
pub struct LocalQuotaPool {
    pools: Mutex<HashMap<String, PoolState>>,
}

impl LocalQuotaPool {
    /// Build a store from validated pool configs.
    pub fn new(configs: Vec<QuotaPoolConfig>) -> Result<Self, QuotaPoolConfigError> {
        let mut pools = HashMap::new();
        for config in configs {
            validate_quota_pool_config(&config)?;
            let name = config.name.clone();
            pools.insert(name, PoolState::new(config));
        }
        Ok(Self {
            pools: Mutex::new(pools),
        })
    }

    /// Soft-policy over-share observations for a pool (test / observability).
    pub fn over_shares(&self, pool: &str) -> Vec<OverShareRecord> {
        let guard = self.pools.lock();
        let mut records: Vec<_> = guard
            .get(pool)
            .map(|state| state.over_shares.values().cloned().collect())
            .unwrap_or_default();
        records.sort_by(|left, right| left.member.cmp(&right.member));
        records
    }

    /// Current consumed + reserved load per member.
    pub fn member_loads(&self, pool: &str) -> HashMap<String, u64> {
        let guard = self.pools.lock();
        guard
            .get(pool)
            .map(|state| {
                state
                    .members
                    .iter()
                    .map(|(name, member)| (name.clone(), member.load()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn admit_locked(state: &mut PoolState, member: &str, units: u64) -> Result<(), PoolDeny> {
        let Some(entitlement) = state.entitlement(member) else {
            return Err(PoolDeny::UnknownMember {
                member: member.to_string(),
            });
        };
        let member_state = state
            .members
            .get(member)
            .ok_or_else(|| PoolDeny::UnknownMember {
                member: member.to_string(),
            })?;
        let member_load = member_state.load();
        let total_load = state.total_load();

        if total_load.saturating_add(units) > state.config.total_limit {
            return Err(PoolDeny::PoolExhausted {
                total_load,
                total_limit: state.config.total_limit,
            });
        }

        match state.config.policy {
            QuotaPoolPolicy::Hard => {
                if member_load.saturating_add(units) > entitlement {
                    return Err(PoolDeny::OverShare {
                        member: member.to_string(),
                        load: member_load,
                        entitlement,
                    });
                }
            }
            QuotaPoolPolicy::Soft => {
                let projected = member_load.saturating_add(units);
                if projected > entitlement {
                    state.over_shares.insert(
                        member.to_string(),
                        OverShareRecord {
                            member: member.to_string(),
                            excess: projected.saturating_sub(entitlement),
                        },
                    );
                    crate::ai_metrics::record_quota_pool_overshare(&state.config.name);
                }
            }
            QuotaPoolPolicy::Burst => {
                // Work-conserving: allow over entitlement while idle
                // capacity remains (already checked against total above).
                // Ranking / rebalance is handled by callers via
                // [`rank_by_fair_share`].
                let _ = entitlement;
                let _ = state.idle_capacity();
            }
        }

        let member_state = state.members.get_mut(member).expect("member checked");
        member_state.reserved = member_state.reserved.saturating_add(units);
        Ok(())
    }
}

#[async_trait]
impl QuotaPoolStore for LocalQuotaPool {
    async fn reserve(
        &self,
        pool: &str,
        member: &str,
        units: u64,
        reservation_id: &str,
    ) -> Result<QuotaReservation, PoolError> {
        if reservation_id.trim().is_empty() {
            return Err(PoolError::InvalidState);
        }
        let reservation = QuotaReservation {
            pool: pool.to_string(),
            member: member.to_string(),
            units,
            reservation_id: reservation_id.to_string(),
        };
        let mut guard = self.pools.lock();
        let now = Instant::now();
        for pool_state in guard.values_mut() {
            pool_state.maybe_roll_window(now);
        }
        if let Some(existing) = guard
            .values()
            .find_map(|pool_state| pool_state.reservations.get(reservation_id))
        {
            return match &existing.outcome {
                LocalReservationOutcome::Active if existing.reservation == reservation => {
                    Ok(existing.reservation.clone())
                }
                _ => Err(PoolError::InvalidState),
            };
        }
        let state = guard.get_mut(pool).ok_or_else(|| PoolDeny::UnknownPool {
            pool: pool.to_string(),
        })?;
        Self::admit_locked(state, member, units)?;
        state.reservations.insert(
            reservation_id.to_string(),
            LocalReservationRecord {
                reservation: reservation.clone(),
                outcome: LocalReservationOutcome::Active,
            },
        );
        Ok(reservation)
    }

    async fn reconcile(
        &self,
        reservation: QuotaReservation,
        actual: PoolUsage,
    ) -> Result<(), PoolError> {
        let mut guard = self.pools.lock();
        let state = guard
            .get_mut(&reservation.pool)
            .ok_or(PoolError::InvalidState)?;
        state.maybe_roll_window(Instant::now());
        let record = state
            .reservations
            .get(&reservation.reservation_id)
            .cloned()
            .ok_or(PoolError::InvalidState)?;
        if record.reservation != reservation {
            return Err(PoolError::InvalidState);
        }
        match record.outcome {
            LocalReservationOutcome::Settled(existing) if existing == actual => return Ok(()),
            LocalReservationOutcome::Active => {}
            LocalReservationOutcome::Settled(_) | LocalReservationOutcome::Released => {
                return Err(PoolError::InvalidState);
            }
        }
        let member = state
            .members
            .get_mut(&reservation.member)
            .ok_or(PoolError::InvalidState)?;
        if member.reserved < reservation.units {
            return Err(PoolError::InvalidState);
        }
        member.reserved = member.reserved.saturating_sub(reservation.units);
        member.consumed = member.consumed.saturating_add(actual.units);
        state
            .reservations
            .get_mut(&reservation.reservation_id)
            .expect("reservation remains present while pool is locked")
            .outcome = LocalReservationOutcome::Settled(actual);
        Ok(())
    }

    async fn release(&self, reservation: QuotaReservation) -> Result<(), PoolError> {
        let mut guard = self.pools.lock();
        let state = guard
            .get_mut(&reservation.pool)
            .ok_or(PoolError::InvalidState)?;
        state.maybe_roll_window(Instant::now());
        let record = state
            .reservations
            .get(&reservation.reservation_id)
            .cloned()
            .ok_or(PoolError::InvalidState)?;
        if record.reservation != reservation {
            return Err(PoolError::InvalidState);
        }
        match record.outcome {
            LocalReservationOutcome::Released => return Ok(()),
            LocalReservationOutcome::Active => {}
            LocalReservationOutcome::Settled(_) => return Err(PoolError::InvalidState),
        }
        let member = state
            .members
            .get_mut(&reservation.member)
            .ok_or(PoolError::InvalidState)?;
        if member.reserved < reservation.units {
            return Err(PoolError::InvalidState);
        }
        member.reserved = member.reserved.saturating_sub(reservation.units);
        state
            .reservations
            .get_mut(&reservation.reservation_id)
            .expect("reservation remains present while pool is locked")
            .outcome = LocalReservationOutcome::Released;
        Ok(())
    }
}

#[derive(Clone)]
struct SharedPoolState {
    config: QuotaPoolConfig,
    policy_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedSoftLane {
    Entitlement,
    Overflow,
}

#[derive(Debug, Clone)]
struct SharedSoftReservation {
    reservation: QuotaReservation,
    lane: SharedSoftLane,
}

/// Fair-share pool store backed by the installed governance accounting plane.
#[derive(Clone)]
pub struct SharedQuotaPool {
    pools: HashMap<String, SharedPoolState>,
    governance: Arc<dyn GovernanceStore>,
    soft_reservations: Arc<Mutex<HashMap<(String, String), SharedSoftReservation>>>,
}

impl SharedQuotaPool {
    /// Build shared pool handles over one approximate or strict governance store.
    pub fn new(
        configs: Vec<QuotaPoolConfig>,
        governance: Arc<dyn GovernanceStore>,
    ) -> Result<Self, QuotaPoolConfigError> {
        let mut pools = HashMap::new();
        for config in configs {
            validate_quota_pool_config(&config)?;
            let name = config.name.clone();
            pools.insert(
                name,
                SharedPoolState {
                    policy_revision: shared_policy_revision(&config),
                    config,
                },
            );
        }
        Ok(Self {
            pools,
            governance,
            soft_reservations: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn pool(&self, pool: &str) -> Result<&SharedPoolState, PoolError> {
        self.pools
            .get(pool)
            .ok_or_else(|| PoolDeny::UnknownPool {
                pool: pool.to_string(),
            })
            .map_err(PoolError::Denied)
    }

    fn entitlement(state: &SharedPoolState, member: &str) -> Result<u64, PoolError> {
        let weight = state.config.weights.get(member).ok_or_else(|| {
            PoolError::Denied(PoolDeny::UnknownMember {
                member: member.to_string(),
            })
        })?;
        let total_weight: u64 = state
            .config
            .weights
            .values()
            .map(|weight| u64::from(*weight))
            .sum();
        if total_weight == 0 {
            return Err(PoolError::InvalidState);
        }
        Ok(state.config.total_limit.saturating_mul(u64::from(*weight)) / total_weight)
    }

    fn reserve_request(
        state: &SharedPoolState,
        key_id: String,
        reservation_id: String,
        limit: u64,
        units: u64,
    ) -> ReserveRequest {
        ReserveRequest {
            reservation_id,
            key_id,
            policy_revision: state.policy_revision,
            limits: GovernanceLimits {
                requests_per_window: None,
                tokens_per_window: Some(limit),
                total_tokens: None,
                total_micro_usd: None,
                window_millis: duration_millis(state.config.window),
            },
            token_ceiling: units,
            micro_usd_ceiling: 0,
        }
    }

    async fn release_global_after_member_failure(
        &self,
        pool: &str,
        reservation_id: &str,
    ) -> Result<(), PoolError> {
        self.governance
            .release(ReleaseRequest {
                reservation_id: global_reservation_id(reservation_id),
                key_id: global_governance_key(pool),
            })
            .await
            .map(|_| ())
            .map_err(map_terminal_error)
    }

    fn soft_reservation(
        &self,
        reservation: &QuotaReservation,
    ) -> Result<SharedSoftReservation, PoolError> {
        let key = (reservation.pool.clone(), reservation.reservation_id.clone());
        let record = self
            .soft_reservations
            .lock()
            .get(&key)
            .cloned()
            .ok_or(PoolError::InvalidState)?;
        if record.reservation != *reservation {
            return Err(PoolError::InvalidState);
        }
        Ok(record)
    }

    fn remove_soft_reservation(&self, reservation: &QuotaReservation) {
        self.soft_reservations
            .lock()
            .remove(&(reservation.pool.clone(), reservation.reservation_id.clone()));
    }
}

#[async_trait]
impl QuotaPoolStore for SharedQuotaPool {
    async fn reserve(
        &self,
        pool: &str,
        member: &str,
        units: u64,
        reservation_id: &str,
    ) -> Result<QuotaReservation, PoolError> {
        if reservation_id.trim().is_empty() {
            return Err(PoolError::InvalidState);
        }
        let state = self.pool(pool)?;
        let entitlement = Self::entitlement(state, member)?;
        let reservation = QuotaReservation {
            pool: pool.to_string(),
            member: member.to_string(),
            units,
            reservation_id: reservation_id.to_string(),
        };
        if state.config.policy == QuotaPoolPolicy::Soft {
            let key = (pool.to_string(), reservation_id.to_string());
            if let Some(existing) = self.soft_reservations.lock().get(&key) {
                return if existing.reservation == reservation {
                    Ok(existing.reservation.clone())
                } else {
                    Err(PoolError::InvalidState)
                };
            }
        }

        let global_request = Self::reserve_request(
            state,
            global_governance_key(pool),
            global_reservation_id(reservation_id),
            state.config.total_limit,
            units,
        );
        self.governance
            .reserve(global_request)
            .await
            .map_err(|error| map_global_reserve_error(error, state.config.total_limit))?;

        match state.config.policy {
            QuotaPoolPolicy::Hard => {
                let member_request = Self::reserve_request(
                    state,
                    member_governance_key(pool, member),
                    member_reservation_id(reservation_id),
                    entitlement,
                    units,
                );
                if let Err(error) = self.governance.reserve(member_request).await {
                    let member_error = map_member_reserve_error(error, member, entitlement);
                    let _ = self
                        .release_global_after_member_failure(pool, reservation_id)
                        .await;
                    return Err(member_error);
                }
            }
            QuotaPoolPolicy::Soft => {
                let member_request = Self::reserve_request(
                    state,
                    member_governance_key(pool, member),
                    member_reservation_id(reservation_id),
                    entitlement,
                    units,
                );
                let lane = match self.governance.reserve(member_request).await {
                    Ok(_) => SharedSoftLane::Entitlement,
                    Err(GovernanceError::LimitExceeded(_)) => {
                        let overflow_request = Self::reserve_request(
                            state,
                            member_overflow_governance_key(pool, member),
                            member_overflow_reservation_id(reservation_id),
                            state.config.total_limit,
                            units,
                        );
                        if let Err(error) = self.governance.reserve(overflow_request).await {
                            let overflow_error = map_soft_overflow_reserve_error(error);
                            let _ = self
                                .release_global_after_member_failure(pool, reservation_id)
                                .await;
                            return Err(overflow_error);
                        }
                        SharedSoftLane::Overflow
                    }
                    Err(error) => {
                        let member_error = map_member_reserve_error(error, member, entitlement);
                        let _ = self
                            .release_global_after_member_failure(pool, reservation_id)
                            .await;
                        return Err(member_error);
                    }
                };
                let inserted = self
                    .soft_reservations
                    .lock()
                    .insert(
                        (pool.to_string(), reservation_id.to_string()),
                        SharedSoftReservation {
                            reservation: reservation.clone(),
                            lane,
                        },
                    )
                    .is_none();
                if inserted && lane == SharedSoftLane::Overflow {
                    crate::ai_metrics::record_quota_pool_overshare(pool);
                }
            }
            QuotaPoolPolicy::Burst => {}
        }

        Ok(reservation)
    }

    async fn reconcile(
        &self,
        reservation: QuotaReservation,
        actual: PoolUsage,
    ) -> Result<(), PoolError> {
        let state = self
            .pools
            .get(&reservation.pool)
            .ok_or(PoolError::InvalidState)?;
        if !state.config.weights.contains_key(&reservation.member) {
            return Err(PoolError::InvalidState);
        }
        let soft_reservation = if state.config.policy == QuotaPoolPolicy::Soft {
            Some(self.soft_reservation(&reservation)?)
        } else {
            None
        };

        self.governance
            .settle(SettleRequest {
                reservation_id: global_reservation_id(&reservation.reservation_id),
                key_id: global_governance_key(&reservation.pool),
                actual_tokens: actual.units,
                actual_micro_usd: 0,
            })
            .await
            .map_err(map_terminal_error)?;

        match state.config.policy {
            QuotaPoolPolicy::Hard => {
                self.governance
                    .settle(SettleRequest {
                        reservation_id: member_reservation_id(&reservation.reservation_id),
                        key_id: member_governance_key(&reservation.pool, &reservation.member),
                        actual_tokens: actual.units,
                        actual_micro_usd: 0,
                    })
                    .await
                    .map_err(map_terminal_error)?;
            }
            QuotaPoolPolicy::Soft => {
                let soft_reservation =
                    soft_reservation.expect("soft reservation was resolved before settlement");
                let (reservation_id, key_id) = match soft_reservation.lane {
                    SharedSoftLane::Entitlement => (
                        member_reservation_id(&reservation.reservation_id),
                        member_governance_key(&reservation.pool, &reservation.member),
                    ),
                    SharedSoftLane::Overflow => (
                        member_overflow_reservation_id(&reservation.reservation_id),
                        member_overflow_governance_key(&reservation.pool, &reservation.member),
                    ),
                };
                self.governance
                    .settle(SettleRequest {
                        reservation_id,
                        key_id,
                        actual_tokens: actual.units,
                        actual_micro_usd: 0,
                    })
                    .await
                    .map_err(map_terminal_error)?;
                self.remove_soft_reservation(&reservation);
            }
            QuotaPoolPolicy::Burst => {}
        }
        Ok(())
    }

    async fn release(&self, reservation: QuotaReservation) -> Result<(), PoolError> {
        let state = self
            .pools
            .get(&reservation.pool)
            .ok_or(PoolError::InvalidState)?;
        if !state.config.weights.contains_key(&reservation.member) {
            return Err(PoolError::InvalidState);
        }

        match state.config.policy {
            QuotaPoolPolicy::Hard => {
                let member_result = self
                    .governance
                    .release(ReleaseRequest {
                        reservation_id: member_reservation_id(&reservation.reservation_id),
                        key_id: member_governance_key(&reservation.pool, &reservation.member),
                    })
                    .await
                    .map(|_| ())
                    .map_err(map_terminal_error);
                self.governance
                    .release(ReleaseRequest {
                        reservation_id: global_reservation_id(&reservation.reservation_id),
                        key_id: global_governance_key(&reservation.pool),
                    })
                    .await
                    .map_err(map_terminal_error)?;
                member_result
            }
            QuotaPoolPolicy::Soft => {
                let soft_reservation = self.soft_reservation(&reservation)?;
                let (reservation_id, key_id) = match soft_reservation.lane {
                    SharedSoftLane::Entitlement => (
                        member_reservation_id(&reservation.reservation_id),
                        member_governance_key(&reservation.pool, &reservation.member),
                    ),
                    SharedSoftLane::Overflow => (
                        member_overflow_reservation_id(&reservation.reservation_id),
                        member_overflow_governance_key(&reservation.pool, &reservation.member),
                    ),
                };
                let member_result = self
                    .governance
                    .release(ReleaseRequest {
                        reservation_id,
                        key_id,
                    })
                    .await
                    .map(|_| ())
                    .map_err(map_terminal_error);
                let global_result = self
                    .governance
                    .release(ReleaseRequest {
                        reservation_id: global_reservation_id(&reservation.reservation_id),
                        key_id: global_governance_key(&reservation.pool),
                    })
                    .await;
                if member_result.is_ok()
                    && matches!(
                        &global_result,
                        Err(GovernanceError::TerminalConflict {
                            state: crate::governance::ReservationTerminalState::Settled,
                            ..
                        })
                    )
                {
                    self.remove_soft_reservation(&reservation);
                }
                let global_result = global_result.map(|_| ()).map_err(map_terminal_error);
                global_result?;
                member_result?;
                self.remove_soft_reservation(&reservation);
                Ok(())
            }
            QuotaPoolPolicy::Burst => self
                .governance
                .release(ReleaseRequest {
                    reservation_id: global_reservation_id(&reservation.reservation_id),
                    key_id: global_governance_key(&reservation.pool),
                })
                .await
                .map(|_| ())
                .map_err(map_terminal_error),
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn global_governance_key(pool: &str) -> String {
    format!("sbproxy:quota-pool:{pool}:global")
}

fn member_governance_key(pool: &str, member: &str) -> String {
    let digest = Sha256::digest(member.as_bytes());
    format!("sbproxy:quota-pool:{pool}:member:{}", hex::encode(digest))
}

fn member_overflow_governance_key(pool: &str, member: &str) -> String {
    format!("{}:overflow", member_governance_key(pool, member))
}

fn global_reservation_id(reservation_id: &str) -> String {
    format!("{reservation_id}:quota-pool:global")
}

fn member_reservation_id(reservation_id: &str) -> String {
    format!("{reservation_id}:quota-pool:member")
}

fn member_overflow_reservation_id(reservation_id: &str) -> String {
    format!("{reservation_id}:quota-pool:overflow")
}

fn shared_policy_revision(config: &QuotaPoolConfig) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"sbproxy:quota-pool-policy:v1\0");
    hasher.update(config.name.as_bytes());
    hasher.update([0]);
    hasher.update(config.total_limit.to_be_bytes());
    hasher.update(duration_millis(config.window).to_be_bytes());
    hasher.update(match config.policy {
        QuotaPoolPolicy::Hard => b"hard".as_slice(),
        QuotaPoolPolicy::Soft => b"soft".as_slice(),
        QuotaPoolPolicy::Burst => b"burst".as_slice(),
    });
    let mut weights: Vec<_> = config
        .weights
        .iter()
        .map(|(member, weight)| (member.as_str(), *weight))
        .collect();
    weights.sort_unstable();
    for (member, weight) in weights {
        hasher.update([0]);
        hasher.update(member.as_bytes());
        hasher.update(weight.to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut revision = [0_u8; 8];
    revision.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(revision)
}

fn map_global_reserve_error(error: GovernanceError, total_limit: u64) -> PoolError {
    match error {
        GovernanceError::LimitExceeded(denial) => PoolError::Denied(PoolDeny::PoolExhausted {
            total_load: denial_load(&denial),
            total_limit,
        }),
        GovernanceError::BackendUnavailable { .. } => PoolError::BackendUnavailable,
        _ => PoolError::InvalidState,
    }
}

fn map_member_reserve_error(error: GovernanceError, member: &str, entitlement: u64) -> PoolError {
    match error {
        GovernanceError::LimitExceeded(denial) => PoolError::Denied(PoolDeny::OverShare {
            member: member.to_string(),
            load: denial_load(&denial),
            entitlement,
        }),
        GovernanceError::BackendUnavailable { .. } => PoolError::BackendUnavailable,
        _ => PoolError::InvalidState,
    }
}

fn map_soft_overflow_reserve_error(error: GovernanceError) -> PoolError {
    match error {
        GovernanceError::BackendUnavailable { .. } => PoolError::BackendUnavailable,
        _ => PoolError::InvalidState,
    }
}

fn map_terminal_error(error: GovernanceError) -> PoolError {
    match error {
        GovernanceError::BackendUnavailable { .. } => PoolError::BackendUnavailable,
        _ => PoolError::InvalidState,
    }
}

fn denial_load(denial: &GovernanceDenial) -> u64 {
    denial.used.saturating_add(denial.reserved)
}

/// Cloneable quota-pool context reused by every attempt-producing transport.
#[derive(Clone)]
pub struct QuotaPoolAdmission {
    config: Option<QuotaPoolConfig>,
    store: Result<Option<Arc<dyn QuotaPoolStore>>, PoolError>,
    member: Result<String, PoolError>,
}

impl QuotaPoolAdmission {
    /// Pin the optional pool config, resolved store, and caller member identity.
    pub fn new(
        config: Option<QuotaPoolConfig>,
        store: Result<Option<Arc<dyn QuotaPoolStore>>, PoolError>,
        member: Result<String, PoolError>,
    ) -> Self {
        Self {
            config,
            store,
            member,
        }
    }

    /// Reserve one request attempt without settling it.
    ///
    /// The returned guard releases its reservation when dropped before
    /// [`QuotaPoolAttemptGuard::commit`]. Disabled admission and an
    /// `allow_unreserved` backend failure return a no-op guard.
    pub async fn reserve_attempt(
        &self,
        reservation_id: &str,
    ) -> Result<QuotaPoolAttemptGuard, PoolError> {
        let Some(config) = self.config.as_ref() else {
            return Ok(QuotaPoolAttemptGuard::no_op());
        };
        if let Err(error) = &self.member {
            if !matches!(error, PoolError::BackendUnavailable) {
                return Err(error.clone());
            }
        }
        if let Err(error) = &self.store {
            if !matches!(error, PoolError::BackendUnavailable) {
                return Err(error.clone());
            }
        }
        let store = match &self.store {
            Ok(Some(store)) => Arc::clone(store),
            Ok(None) => {
                return self.finish_reserve_error(config, PoolError::BackendUnavailable);
            }
            Err(error) => return self.finish_reserve_error(config, error.clone()),
        };
        let member = match &self.member {
            Ok(member) => member,
            Err(error) => return self.finish_reserve_error(config, error.clone()),
        };

        match QuotaReservationGuard::reserve(store, &config.name, member, 1, reservation_id).await {
            Ok(reservation) => Ok(QuotaPoolAttemptGuard::reserved(reservation, config)),
            Err(error) => self.finish_reserve_error(config, error),
        }
    }

    /// Reserve and settle one request attempt under the pinned pool policy.
    ///
    /// Disabled admission is a no-op. An enabled `allow_unreserved` pool only
    /// bypasses a [`PoolError::BackendUnavailable`]; denials and invalid state
    /// remain closed.
    pub async fn consume(&self, reservation_id: &str) -> Result<(), PoolError> {
        self.reserve_attempt(reservation_id).await?.commit().await
    }

    fn finish_reserve_error(
        &self,
        config: &QuotaPoolConfig,
        error: PoolError,
    ) -> Result<QuotaPoolAttemptGuard, PoolError> {
        if error == PoolError::BackendUnavailable
            && config.failure_mode == QuotaPoolFailureMode::AllowUnreserved
        {
            crate::ai_metrics::record_quota_pool_fail_open(&config.name);
            Ok(QuotaPoolAttemptGuard::no_op())
        } else {
            Err(error)
        }
    }
}

/// One reserved quota unit that settles only when the transport commits.
///
/// Dropping the guard before [`Self::commit`] releases the underlying
/// reservation. A no-op guard represents disabled admission or a configured
/// `allow_unreserved` backend failure.
pub struct QuotaPoolAttemptGuard {
    reservation: Option<QuotaReservationGuard>,
    fail_open_pool: Option<String>,
}

impl QuotaPoolAttemptGuard {
    fn no_op() -> Self {
        Self {
            reservation: None,
            fail_open_pool: None,
        }
    }

    fn reserved(reservation: QuotaReservationGuard, config: &QuotaPoolConfig) -> Self {
        Self {
            reservation: Some(reservation),
            fail_open_pool: (config.failure_mode == QuotaPoolFailureMode::AllowUnreserved)
                .then(|| config.name.clone()),
        }
    }

    /// Settle one unit immediately and disarm drop-time release.
    ///
    /// Only a backend-unavailable settle error may follow the configured
    /// `allow_unreserved` path. Denials and invalid state remain closed.
    pub async fn commit(mut self) -> Result<(), PoolError> {
        let Some(reservation) = self.reservation.take() else {
            return Ok(());
        };
        match reservation.settle(PoolUsage { units: 1 }).await {
            Ok(()) => Ok(()),
            Err(PoolError::BackendUnavailable) if self.fail_open_pool.is_some() => {
                crate::ai_metrics::record_quota_pool_fail_open(
                    self.fail_open_pool
                        .as_deref()
                        .expect("fail-open pool was checked"),
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

/// RAII guard that releases a reservation on drop unless settled.
pub struct QuotaReservationGuard {
    store: Arc<dyn QuotaPoolStore>,
    reservation: Option<QuotaReservation>,
}

impl QuotaReservationGuard {
    /// Reserve against `store` and return a guard that auto-releases on drop.
    pub async fn reserve(
        store: Arc<dyn QuotaPoolStore>,
        pool: &str,
        member: &str,
        units: u64,
        reservation_id: &str,
    ) -> Result<Self, PoolError> {
        let reservation = store.reserve(pool, member, units, reservation_id).await?;
        Ok(Self {
            store,
            reservation: Some(reservation),
        })
    }

    /// Commit the reservation as consumed and disarm auto-release.
    pub async fn settle(mut self, actual: PoolUsage) -> Result<(), PoolError> {
        let reservation = self
            .reservation
            .as_ref()
            .cloned()
            .ok_or(PoolError::InvalidState)?;
        self.store.reconcile(reservation, actual).await?;
        self.reservation.take();
        Ok(())
    }

    /// Release without consuming and disarm drop cleanup.
    pub async fn release(mut self) -> Result<(), PoolError> {
        let reservation = self
            .reservation
            .as_ref()
            .cloned()
            .ok_or(PoolError::InvalidState)?;
        self.store.release(reservation).await?;
        self.reservation.take();
        Ok(())
    }
}

impl Drop for QuotaReservationGuard {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            let store = self.store.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = store.release(reservation).await;
                });
            } else {
                let _ = futures::executor::block_on(store.release(reservation));
            }
        }
    }
}

/// Optional humantime-compatible duration serde helper for `Option`-free field.
mod humantime_serde_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs().max(1)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_duration(&raw).map_err(serde::de::Error::custom)
    }

    fn parse_duration(raw: &str) -> Result<Duration, String> {
        let trimmed = raw.trim();
        if let Ok(secs) = trimmed.parse::<u64>() {
            return Ok(Duration::from_secs(secs));
        }
        let (num, suffix) = trimmed.split_at(
            trimmed
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(trimmed.len()),
        );
        let value: u64 = num
            .parse()
            .map_err(|_| format!("invalid duration: {raw}"))?;
        match suffix {
            "s" | "sec" | "secs" | "second" | "seconds" => Ok(Duration::from_secs(value)),
            "m" | "min" | "mins" | "minute" | "minutes" => Ok(Duration::from_secs(value * 60)),
            "h" | "hr" | "hrs" | "hour" | "hours" => Ok(Duration::from_secs(value * 3600)),
            "" => Ok(Duration::from_secs(value)),
            _ => Err(format!("invalid duration suffix in {raw}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn weights_50_30_20() -> HashMap<String, u32> {
        let mut weights = HashMap::new();
        weights.insert("alpha".to_string(), 50);
        weights.insert("beta".to_string(), 30);
        weights.insert("gamma".to_string(), 20);
        weights
    }

    fn hard_pool_config() -> QuotaPoolConfig {
        QuotaPoolConfig {
            name: "shared".to_string(),
            window: Duration::from_secs(60),
            total_limit: 100,
            weights: weights_50_30_20(),
            policy: QuotaPoolPolicy::Hard,
            dimension: QuotaPoolDimension::Request,
            consistency: QuotaPoolConsistency::Local,
            failure_mode: QuotaPoolFailureMode::Closed,
        }
    }

    #[test]
    fn config_defaults_to_local_consistency_and_closed_failure_mode() {
        let config: QuotaPoolConfig = serde_json::from_value(serde_json::json!({
            "name": "defaulted",
            "total_limit": 10,
            "weights": {"virtual-key-a": 1},
            "policy": "hard"
        }))
        .expect("literal quota config parses");

        assert_eq!(config.consistency, QuotaPoolConsistency::Local);
        assert_eq!(config.failure_mode, QuotaPoolFailureMode::Closed);
    }

    #[test]
    fn config_parses_approximate_strong_and_allow_unreserved() {
        let approximate: QuotaPoolConfig = serde_json::from_value(serde_json::json!({
            "name": "approximate",
            "total_limit": 10,
            "weights": {"virtual-key-a": 1},
            "policy": "soft",
            "consistency": "approximate",
            "failure_mode": "allow_unreserved"
        }))
        .expect("approximate quota config parses");
        let strong: QuotaPoolConfig = serde_json::from_value(serde_json::json!({
            "name": "strong",
            "total_limit": 10,
            "weights": {"virtual-key-a": 1},
            "policy": "burst",
            "consistency": "strong"
        }))
        .expect("strong quota config parses");

        assert_eq!(approximate.consistency, QuotaPoolConsistency::Approximate);
        assert_eq!(
            approximate.failure_mode,
            QuotaPoolFailureMode::AllowUnreserved
        );
        assert_eq!(strong.consistency, QuotaPoolConsistency::Strong);
        assert_eq!(strong.failure_mode, QuotaPoolFailureMode::Closed);
    }

    #[test]
    fn config_rejects_a_zero_duration_window() {
        let mut config = hard_pool_config();
        config.window = Duration::ZERO;

        assert_eq!(
            validate_quota_pool_config(&config),
            Err(QuotaPoolConfigError::ZeroWindow)
        );
    }

    #[tokio::test]
    async fn local_store_returns_the_caller_supplied_reservation_id_and_typed_denial() {
        let pool = LocalQuotaPool::new(vec![hard_pool_config()]).expect("valid local pool");

        let reservation = pool
            .reserve("shared", "alpha", 50, "request-7:attempt-2")
            .await
            .expect("alpha fits its exact entitlement");
        assert_eq!(reservation.reservation_id, "request-7:attempt-2");
        pool.reconcile(reservation, PoolUsage { units: 50 })
            .await
            .expect("valid reservation settles");

        let error = pool
            .reserve("shared", "alpha", 1, "request-8:attempt-1")
            .await
            .expect_err("alpha is now over its hard entitlement");
        assert!(matches!(
            error,
            PoolError::Denied(PoolDeny::OverShare {
                entitlement: 50,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn local_active_reservation_is_idempotent_by_caller_id() {
        let mut config = hard_pool_config();
        config.total_limit = 2;
        config.weights = HashMap::from([("alpha".to_string(), 1)]);
        let pool = LocalQuotaPool::new(vec![config]).expect("valid local pool");

        let first = pool
            .reserve("shared", "alpha", 1, "same-active")
            .await
            .expect("first reservation succeeds");
        let duplicate = pool
            .reserve("shared", "alpha", 1, "same-active")
            .await
            .expect("identical active reservation is idempotent");

        assert_eq!(duplicate, first);
        assert_eq!(pool.member_loads("shared").get("alpha"), Some(&1));
    }

    #[derive(Default)]
    struct RecordingStore {
        released: tokio::sync::Mutex<Vec<String>>,
        settled: tokio::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl QuotaPoolStore for RecordingStore {
        async fn reserve(
            &self,
            pool: &str,
            member: &str,
            units: u64,
            reservation_id: &str,
        ) -> Result<QuotaReservation, PoolError> {
            Ok(QuotaReservation {
                pool: pool.to_string(),
                member: member.to_string(),
                units,
                reservation_id: reservation_id.to_string(),
            })
        }

        async fn reconcile(
            &self,
            reservation: QuotaReservation,
            _actual: PoolUsage,
        ) -> Result<(), PoolError> {
            self.settled.lock().await.push(reservation.reservation_id);
            Ok(())
        }

        async fn release(&self, reservation: QuotaReservation) -> Result<(), PoolError> {
            self.released.lock().await.push(reservation.reservation_id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn dropping_an_unsettled_guard_releases_through_an_async_trait_object() {
        let recording = Arc::new(RecordingStore::default());
        let store: Arc<dyn QuotaPoolStore> = recording.clone();

        {
            let _guard = QuotaReservationGuard::reserve(
                store,
                "shared",
                "virtual-key-a",
                1,
                "request-9:attempt-3",
            )
            .await
            .expect("fake store admits");
        }

        for _ in 0..16 {
            if !recording.released.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            recording.released.lock().await.as_slice(),
            ["request-9:attempt-3"]
        );
    }

    #[tokio::test]
    async fn quota_attempt_defers_settlement_until_commit() {
        let recording = Arc::new(RecordingStore::default());
        let store: Arc<dyn QuotaPoolStore> = recording.clone();
        let admission = QuotaPoolAdmission::new(
            Some(hard_pool_config()),
            Ok(Some(store)),
            Ok("alpha".to_string()),
        );

        let attempt = admission
            .reserve_attempt("request-10:attempt-1")
            .await
            .expect("quota attempt reserves");

        assert!(
            recording.settled.lock().await.is_empty(),
            "reservation must remain unsettled while local transport construction runs"
        );

        attempt.commit().await.expect("attempt settles");
        assert_eq!(
            recording.settled.lock().await.as_slice(),
            ["request-10:attempt-1"]
        );
        assert!(recording.released.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dropping_a_quota_attempt_before_commit_releases_without_settling() {
        let recording = Arc::new(RecordingStore::default());
        let store: Arc<dyn QuotaPoolStore> = recording.clone();
        let admission = QuotaPoolAdmission::new(
            Some(hard_pool_config()),
            Ok(Some(store)),
            Ok("alpha".to_string()),
        );

        let attempt = admission
            .reserve_attempt("request-11:attempt-1")
            .await
            .expect("quota attempt reserves");
        drop(attempt);

        for _ in 0..16 {
            if !recording.released.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            recording.released.lock().await.as_slice(),
            ["request-11:attempt-1"]
        );
        assert!(recording.settled.lock().await.is_empty());
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn weighted_hard_pool_blocks_over_share() {
        let pool = LocalQuotaPool::new(vec![hard_pool_config()]).expect("valid local pool");

        // Entitlements: alpha=50, beta=30, gamma=20.
        for attempt in 0..50 {
            let reservation_id = format!("hard-alpha-{attempt}");
            let reservation = pool
                .reserve("shared", "alpha", 1, &reservation_id)
                .await
                .expect("alpha within entitlement");
            pool.reconcile(reservation, PoolUsage { units: 1 })
                .await
                .expect("alpha usage settles");
        }

        let error = pool
            .reserve("shared", "alpha", 1, "hard-alpha-denied")
            .await
            .expect_err("alpha over-share must be blocked");
        assert!(
            matches!(
                error,
                PoolError::Denied(PoolDeny::OverShare {
                    entitlement: 50,
                    ..
                })
            ),
            "expected OverShare at entitlement 50, got {error:?}"
        );

        pool.reserve("shared", "beta", 1, "hard-beta")
            .await
            .expect("beta still has headroom");
        pool.reserve("shared", "gamma", 1, "hard-gamma")
            .await
            .expect("gamma still has headroom");
    }

    #[tokio::test]
    async fn burst_lends_idle_capacity_then_rebalances() {
        let mut weights = HashMap::new();
        weights.insert("alpha".to_string(), 50);
        weights.insert("beta".to_string(), 50);
        let config = QuotaPoolConfig {
            name: "burst".to_string(),
            window: Duration::from_secs(60),
            total_limit: 10,
            weights: weights.clone(),
            policy: QuotaPoolPolicy::Burst,
            dimension: QuotaPoolDimension::Request,
            consistency: QuotaPoolConsistency::Local,
            failure_mode: QuotaPoolFailureMode::Closed,
        };
        let pool = LocalQuotaPool::new(vec![config]).expect("valid burst pool");

        // Alpha idle: beta may borrow past its entitlement of 5.
        let mut beta_held = Vec::new();
        for attempt in 0..8 {
            let reservation_id = format!("burst-beta-{attempt}");
            let reservation = pool
                .reserve("burst", "beta", 1, &reservation_id)
                .await
                .expect("burst lends idle alpha capacity");
            beta_held.push(reservation);
        }

        // Fairness ranking prefers the idle member once capacity frees.
        for reservation in beta_held.drain(..4) {
            pool.release(reservation)
                .await
                .expect("held capacity releases");
        }
        let loads = pool.member_loads("burst");
        let ranked =
            rank_by_fair_share(&loads, &weights, &["alpha".to_string(), "beta".to_string()]);
        assert_eq!(
            ranked.first().map(String::as_str),
            Some("alpha"),
            "idle alpha must rank ahead of loaded beta after rebalance"
        );

        let (idx, reservation) =
            reserve_next_candidate(&pool, "burst", &["alpha", "beta"], 1, "burst-rebalance")
                .await
                .expect("alpha should admit after rebalance");
        assert_eq!(idx, 0);
        assert_eq!(reservation.member, "alpha");
    }

    #[tokio::test]
    async fn soft_records_over_share_without_blocking() {
        let config = QuotaPoolConfig {
            name: "soft".to_string(),
            window: Duration::from_secs(60),
            total_limit: 100,
            weights: weights_50_30_20(),
            policy: QuotaPoolPolicy::Soft,
            dimension: QuotaPoolDimension::Request,
            consistency: QuotaPoolConsistency::Local,
            failure_mode: QuotaPoolFailureMode::Closed,
        };
        let pool = LocalQuotaPool::new(vec![config]).expect("valid soft pool");

        for attempt in 0..60 {
            let reservation_id = format!("soft-alpha-{attempt}");
            let reservation = pool
                .reserve("soft", "alpha", 1, &reservation_id)
                .await
                .expect("soft admits over entitlement while total remains");
            pool.reconcile(reservation, PoolUsage { units: 1 })
                .await
                .expect("soft usage settles");
        }

        let records = pool.over_shares("soft");
        assert!(!records.is_empty(), "soft policy must record over-share");
        assert!(
            records.iter().any(|r| r.member == "alpha" && r.excess > 0),
            "alpha over-share missing: {records:?}"
        );
    }

    #[test]
    fn backend_independent_validation_accepts_shared_consistency_modes() {
        for consistency in [
            QuotaPoolConsistency::Approximate,
            QuotaPoolConsistency::Strong,
        ] {
            let mut config = hard_pool_config();
            config.consistency = consistency;
            validate_quota_pool_config(&config)
                .expect("backend selection validates consistency at runtime");
        }
    }

    #[tokio::test]
    async fn denied_reservation_advances_to_next_candidate() {
        let pool = LocalQuotaPool::new(vec![hard_pool_config()]).expect("valid pool");

        for attempt in 0..50 {
            let reservation_id = format!("candidate-fill-{attempt}");
            let reservation = pool
                .reserve("shared", "alpha", 1, &reservation_id)
                .await
                .expect("fill alpha");
            pool.reconcile(reservation, PoolUsage { units: 1 })
                .await
                .expect("filled usage settles");
        }

        let (idx, reservation) = reserve_next_candidate(
            &pool,
            "shared",
            &["alpha", "beta", "gamma"],
            1,
            "candidate-next",
        )
        .await
        .expect("must advance past denied alpha");
        assert_eq!(idx, 1, "beta is the first admissible candidate");
        assert_eq!(reservation.member, "beta");
    }
}
