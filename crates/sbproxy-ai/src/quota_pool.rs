//! Fair-share quota pools (WOR-1880).
//!
//! Tracks `consumed + reserved` per pool member within a rolling window and
//! admits provider attempts under Hard, Soft, or Burst policy. Local process
//! accounting is fully supported. `consistency: strong` requires an atomic
//! backend that is not wired in this lane; config validation rejects it.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Requires an atomic shared backend. Not available without Redis wiring.
    Strong,
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
    /// Relative weights keyed by member (provider) name.
    pub weights: HashMap<String, u32>,
    /// Admission policy.
    pub policy: QuotaPoolPolicy,
    /// Accounting dimension. Only [`QuotaPoolDimension::Request`] is enabled.
    #[serde(default)]
    pub dimension: QuotaPoolDimension,
    /// Consistency mode. [`QuotaPoolConsistency::Strong`] is rejected until
    /// an atomic backend is wired.
    #[serde(default)]
    pub consistency: QuotaPoolConsistency,
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

/// A held reservation against a pool member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaReservation {
    /// Pool that issued the reservation.
    pub pool: String,
    /// Member (provider) the units were reserved for.
    pub member: String,
    /// Reserved units.
    pub units: u64,
    /// Opaque id for reconcile / release pairing.
    pub reservation_id: u64,
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
    /// `consistency: strong` without an atomic backend.
    StrongConsistencyUnavailable,
    /// Empty pool name.
    EmptyName,
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
            Self::StrongConsistencyUnavailable => write!(
                f,
                "quota pool consistency strong requires an atomic backend (not wired)"
            ),
            Self::EmptyName => write!(f, "quota pool name must not be empty"),
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

/// Validate pool config. Strong consistency fails closed without an atomic backend.
pub fn validate_quota_pool_config(config: &QuotaPoolConfig) -> Result<(), QuotaPoolConfigError> {
    if config.name.trim().is_empty() {
        return Err(QuotaPoolConfigError::EmptyName);
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
    match config.consistency {
        QuotaPoolConsistency::Local => Ok(()),
        QuotaPoolConsistency::Strong => Err(QuotaPoolConfigError::StrongConsistencyUnavailable),
    }
}

/// Atomic reservation store for a fair-share pool.
pub trait QuotaPoolStore: Send + Sync {
    /// Reserve `units` for `member` in `pool`, or deny.
    fn reserve(&self, pool: &str, member: &str, units: u64) -> Result<QuotaReservation, PoolDeny>;

    /// Settle a reservation to actual usage (refund over-reserve, add debt on under).
    fn reconcile(&self, reservation: QuotaReservation, actual: PoolUsage);

    /// Drop a reservation without consuming (error / skip path).
    fn release(&self, reservation: QuotaReservation);
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
pub fn reserve_next_candidate(
    store: &dyn QuotaPoolStore,
    pool: &str,
    candidates: &[&str],
    units: u64,
) -> Result<(usize, QuotaReservation), PoolDeny> {
    let mut last_deny = PoolDeny::PoolExhausted {
        total_load: 0,
        total_limit: 0,
    };
    for (idx, member) in candidates.iter().enumerate() {
        match store.reserve(pool, member, units) {
            Ok(reservation) => return Ok((idx, reservation)),
            Err(deny) => last_deny = deny,
        }
    }
    Err(last_deny)
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

#[derive(Debug)]
struct PoolState {
    config: QuotaPoolConfig,
    members: HashMap<String, MemberState>,
    window_started: Instant,
    over_shares: Vec<OverShareRecord>,
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
            window_started: Instant::now(),
            over_shares: Vec::new(),
        }
    }

    fn maybe_roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_started) >= self.config.window {
            for state in self.members.values_mut() {
                state.consumed = 0;
                state.reserved = 0;
            }
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
    next_reservation_id: AtomicU64,
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
            next_reservation_id: AtomicU64::new(1),
        })
    }

    /// Soft-policy over-share observations for a pool (test / observability).
    pub fn over_shares(&self, pool: &str) -> Vec<OverShareRecord> {
        let guard = self.pools.lock();
        guard
            .get(pool)
            .map(|state| state.over_shares.clone())
            .unwrap_or_default()
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
                    state.over_shares.push(OverShareRecord {
                        member: member.to_string(),
                        excess: projected.saturating_sub(entitlement),
                    });
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

impl QuotaPoolStore for LocalQuotaPool {
    fn reserve(&self, pool: &str, member: &str, units: u64) -> Result<QuotaReservation, PoolDeny> {
        let mut guard = self.pools.lock();
        let state = guard.get_mut(pool).ok_or_else(|| PoolDeny::UnknownPool {
            pool: pool.to_string(),
        })?;
        state.maybe_roll_window(Instant::now());
        Self::admit_locked(state, member, units)?;
        let reservation_id = self.next_reservation_id.fetch_add(1, Ordering::Relaxed);
        Ok(QuotaReservation {
            pool: pool.to_string(),
            member: member.to_string(),
            units,
            reservation_id,
        })
    }

    fn reconcile(&self, reservation: QuotaReservation, actual: PoolUsage) {
        let mut guard = self.pools.lock();
        let Some(state) = guard.get_mut(&reservation.pool) else {
            return;
        };
        let Some(member) = state.members.get_mut(&reservation.member) else {
            return;
        };
        member.reserved = member.reserved.saturating_sub(reservation.units);
        member.consumed = member.consumed.saturating_add(actual.units);
    }

    fn release(&self, reservation: QuotaReservation) {
        let mut guard = self.pools.lock();
        let Some(state) = guard.get_mut(&reservation.pool) else {
            return;
        };
        let Some(member) = state.members.get_mut(&reservation.member) else {
            return;
        };
        member.reserved = member.reserved.saturating_sub(reservation.units);
    }
}

impl QuotaPoolStore for Arc<LocalQuotaPool> {
    fn reserve(&self, pool: &str, member: &str, units: u64) -> Result<QuotaReservation, PoolDeny> {
        (**self).reserve(pool, member, units)
    }

    fn reconcile(&self, reservation: QuotaReservation, actual: PoolUsage) {
        (**self).reconcile(reservation, actual)
    }

    fn release(&self, reservation: QuotaReservation) {
        (**self).release(reservation)
    }
}

/// RAII guard that releases a reservation on drop unless settled.
pub struct QuotaReservationGuard {
    store: Arc<LocalQuotaPool>,
    reservation: Option<QuotaReservation>,
}

impl QuotaReservationGuard {
    /// Reserve against `store` and return a guard that auto-releases on drop.
    pub fn reserve(
        store: Arc<LocalQuotaPool>,
        pool: &str,
        member: &str,
        units: u64,
    ) -> Result<Self, PoolDeny> {
        let reservation = store.reserve(pool, member, units)?;
        Ok(Self {
            store,
            reservation: Some(reservation),
        })
    }

    /// Commit the reservation as consumed and disarm auto-release.
    pub fn settle(mut self, actual: PoolUsage) {
        if let Some(reservation) = self.reservation.take() {
            self.store.reconcile(reservation, actual);
        }
    }
}

impl Drop for QuotaReservationGuard {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            self.store.release(reservation);
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
        }
    }

    #[test]
    fn weighted_hard_pool_blocks_over_share() {
        let pool = LocalQuotaPool::new(vec![hard_pool_config()]).expect("valid local pool");

        // Entitlements: alpha=50, beta=30, gamma=20.
        for _ in 0..50 {
            pool.reserve("shared", "alpha", 1)
                .expect("alpha within entitlement")
                .pipe(|r| pool.reconcile(r, PoolUsage { units: 1 }));
        }

        let deny = pool
            .reserve("shared", "alpha", 1)
            .expect_err("alpha over-share must be blocked");
        assert!(
            matches!(
                deny,
                PoolDeny::OverShare {
                    entitlement: 50,
                    ..
                }
            ),
            "expected OverShare at entitlement 50, got {deny:?}"
        );

        pool.reserve("shared", "beta", 1)
            .expect("beta still has headroom");
        pool.reserve("shared", "gamma", 1)
            .expect("gamma still has headroom");
    }

    #[test]
    fn burst_lends_idle_capacity_then_rebalances() {
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
        };
        let pool = LocalQuotaPool::new(vec![config]).expect("valid burst pool");

        // Alpha idle: beta may borrow past its entitlement of 5.
        let mut beta_held = Vec::new();
        for _ in 0..8 {
            let reservation = pool
                .reserve("burst", "beta", 1)
                .expect("burst lends idle alpha capacity");
            beta_held.push(reservation);
        }

        // Fairness ranking prefers the idle member once capacity frees.
        for reservation in beta_held.drain(..4) {
            pool.release(reservation);
        }
        let loads = pool.member_loads("burst");
        let ranked =
            rank_by_fair_share(&loads, &weights, &["alpha".to_string(), "beta".to_string()]);
        assert_eq!(
            ranked.first().map(String::as_str),
            Some("alpha"),
            "idle alpha must rank ahead of loaded beta after rebalance"
        );

        let (idx, reservation) = reserve_next_candidate(&pool, "burst", &["alpha", "beta"], 1)
            .expect("alpha should admit after rebalance");
        assert_eq!(idx, 0);
        assert_eq!(reservation.member, "alpha");
    }

    #[test]
    fn soft_records_over_share_without_blocking() {
        let config = QuotaPoolConfig {
            name: "soft".to_string(),
            window: Duration::from_secs(60),
            total_limit: 100,
            weights: weights_50_30_20(),
            policy: QuotaPoolPolicy::Soft,
            dimension: QuotaPoolDimension::Request,
            consistency: QuotaPoolConsistency::Local,
        };
        let pool = LocalQuotaPool::new(vec![config]).expect("valid soft pool");

        for _ in 0..60 {
            let reservation = pool
                .reserve("soft", "alpha", 1)
                .expect("soft admits over entitlement while total remains");
            pool.reconcile(reservation, PoolUsage { units: 1 });
        }

        let records = pool.over_shares("soft");
        assert!(!records.is_empty(), "soft policy must record over-share");
        assert!(
            records.iter().any(|r| r.member == "alpha" && r.excess > 0),
            "alpha over-share missing: {records:?}"
        );
    }

    #[test]
    fn strong_consistency_without_atomic_backend_is_rejected() {
        let config = QuotaPoolConfig {
            name: "mesh".to_string(),
            window: Duration::from_secs(60),
            total_limit: 10,
            weights: weights_50_30_20(),
            policy: QuotaPoolPolicy::Hard,
            dimension: QuotaPoolDimension::Request,
            consistency: QuotaPoolConsistency::Strong,
        };
        let err = validate_quota_pool_config(&config)
            .expect_err("strong mode must fail without atomic backend");
        assert_eq!(err, QuotaPoolConfigError::StrongConsistencyUnavailable);

        let build_err = LocalQuotaPool::new(vec![config]).expect_err("store build must fail");
        assert_eq!(
            build_err,
            QuotaPoolConfigError::StrongConsistencyUnavailable
        );
    }

    #[test]
    fn denied_reservation_advances_to_next_candidate() {
        let pool = LocalQuotaPool::new(vec![hard_pool_config()]).expect("valid pool");

        for _ in 0..50 {
            let reservation = pool.reserve("shared", "alpha", 1).expect("fill alpha");
            pool.reconcile(reservation, PoolUsage { units: 1 });
        }

        let (idx, reservation) =
            reserve_next_candidate(&pool, "shared", &["alpha", "beta", "gamma"], 1)
                .expect("must advance past denied alpha");
        assert_eq!(idx, 1, "beta is the first admissible candidate");
        assert_eq!(reservation.member, "beta");
    }

    /// Tiny helper so reconcile chains read clearly in Hard fill loops.
    trait Pipe: Sized {
        fn pipe<F, R>(self, f: F) -> R
        where
            F: FnOnce(Self) -> R;
    }

    impl<T> Pipe for T {
        fn pipe<F, R>(self, f: F) -> R
        where
            F: FnOnce(Self) -> R,
        {
            f(self)
        }
    }
}
