//! Governed-key admission at the ingress gateway.

use std::sync::Arc;

use sbproxy_ai::effective_key_policy::EffectiveKeyPolicy;
use sbproxy_ai::governance::{
    GovernanceDenial, GovernanceDimension, GovernanceError, GovernanceLimits, GovernanceStore,
    ReserveRequest,
};
use sbproxy_config::{GovernanceConfig, GovernanceFailureMode, MissingRatePolicy};

use crate::governance_runtime::{GovernanceCharge, GovernanceLease};

const GOVERNANCE_WINDOW_MILLIS: u64 = 60_000;

/// Successful governed admission result.
pub enum GovernanceAdmission {
    /// The policy carries no request, token, or monetary limit.
    NotLimited,
    /// The shared or process-local backend accepted one reservation.
    Reserved(GovernanceCharge),
    /// An explicitly configured outage mode admitted without a reservation.
    Unreserved { backend: &'static str },
}

/// Stable HTTP failure returned before any provider or replica is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceAdmissionError {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
    pub denial: Option<GovernanceDenial>,
}

/// Convert one effective key policy into the integer limits stored atomically.
pub fn limits_for_policy(
    policy: &EffectiveKeyPolicy,
) -> Result<GovernanceLimits, GovernanceAdmissionError> {
    let total_micro_usd = policy
        .budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .map(usd_limit_to_micro)
        .transpose()?;
    Ok(GovernanceLimits {
        requests_per_window: policy.max_requests_per_minute,
        tokens_per_window: policy.max_tokens_per_minute,
        total_tokens: policy.budget.as_ref().and_then(|budget| budget.max_tokens),
        total_micro_usd,
        window_millis: GOVERNANCE_WINDOW_MILLIS,
    })
}

fn usd_limit_to_micro(value: f64) -> Result<u64, GovernanceAdmissionError> {
    let micro = value * 1_000_000.0;
    if !micro.is_finite() || micro < 0.0 || micro > u64::MAX as f64 {
        return Err(internal_error("governance_budget_invalid"));
    }
    Ok(micro.floor() as u64)
}

fn has_any_limit(limits: &GovernanceLimits) -> bool {
    limits.requests_per_window.is_some()
        || limits.tokens_per_window.is_some()
        || limits.total_tokens.is_some()
        || limits.total_micro_usd.is_some()
}

/// Reserve all governed dimensions exactly once before route selection.
pub async fn reserve(
    config: &GovernanceConfig,
    store: Arc<dyn GovernanceStore>,
    policy: &EffectiveKeyPolicy,
    model: &str,
    resolved_price: Option<sbproxy_ai::budget::ModelPrice>,
    prompt_token_ceiling: u64,
    output_token_ceiling: u64,
) -> Result<GovernanceAdmission, GovernanceAdmissionError> {
    let limits = limits_for_policy(policy)?;
    if !has_any_limit(&limits) {
        return Ok(GovernanceAdmission::NotLimited);
    }
    let token_ceiling = prompt_token_ceiling
        .checked_add(output_token_ceiling)
        .ok_or_else(|| internal_error("governance_token_ceiling_overflow"))?;
    let price = if model.is_empty() {
        None
    } else {
        resolved_price
    };
    if price.is_none() && !model.is_empty() && config.missing_rate == MissingRatePolicy::RequireRate
    {
        return Err(GovernanceAdmissionError {
            status: 503,
            code: "governance_rate_missing",
            message: "governed model rate is required",
            denial: None,
        });
    }
    let micro_usd_ceiling = match price {
        Some(price) => sbproxy_ai::budget::governance_micro_usd(
            price,
            prompt_token_ceiling,
            output_token_ceiling,
        )
        .ok_or_else(|| internal_error("governance_cost_ceiling_overflow"))?,
        None => 0,
    };
    // Correlation IDs are intentionally client-propagated and therefore must
    // never be an accounting idempotency key. Mint an unforgeable identifier
    // for this ingress attempt so concurrent requests that reuse
    // `X-Request-Id` still reserve independently.
    let reservation_id = format!("governance:{}", crate::identity::new_request_id());
    match store
        .reserve(ReserveRequest {
            reservation_id,
            key_id: policy.key_id.clone(),
            policy_revision: policy.policy_revision,
            limits,
            token_ceiling,
            micro_usd_ceiling,
        })
        .await
    {
        Ok(reservation) => Ok(GovernanceAdmission::Reserved(GovernanceCharge::new(
            GovernanceLease::new(store, reservation),
            price,
        ))),
        Err(GovernanceError::BackendUnavailable { backend })
            if config.failure_mode == GovernanceFailureMode::AllowUnreserved =>
        {
            Ok(GovernanceAdmission::Unreserved { backend })
        }
        Err(error) => Err(map_store_error(error)),
    }
}

fn map_store_error(error: GovernanceError) -> GovernanceAdmissionError {
    match error {
        GovernanceError::LimitExceeded(denial) => {
            let (status, code, message) = match denial.dimension {
                GovernanceDimension::RequestsPerWindow | GovernanceDimension::TokensPerWindow => (
                    429,
                    "governance_rate_limit_exceeded",
                    "governed rate limit exceeded",
                ),
                GovernanceDimension::TotalTokens | GovernanceDimension::TotalMicroUsd => (
                    402,
                    "governance_budget_exceeded",
                    "governed budget exceeded",
                ),
            };
            GovernanceAdmissionError {
                status,
                code,
                message,
                denial: Some(denial),
            }
        }
        GovernanceError::BackendUnavailable { .. } => GovernanceAdmissionError {
            status: 503,
            code: "governance_backend_unavailable",
            message: "governance backend unavailable",
            denial: None,
        },
        GovernanceError::ReservationConflict { .. } | GovernanceError::TerminalConflict { .. } => {
            GovernanceAdmissionError {
                status: 409,
                code: "governance_reservation_conflict",
                message: "governance request identifier conflict",
                denial: None,
            }
        }
        GovernanceError::InvalidRequest { .. }
        | GovernanceError::ReservationNotFound { .. }
        | GovernanceError::ArithmeticOverflow { .. }
        | GovernanceError::InternalInvariant { .. } => internal_error("governance_internal_error"),
    }
}

fn internal_error(code: &'static str) -> GovernanceAdmissionError {
    GovernanceAdmissionError {
        status: 500,
        code,
        message: "governance accounting failed",
        denial: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sbproxy_ai::budget::ModelPrice;
    use sbproxy_ai::effective_key_policy::KeyBudgetPolicy;
    use sbproxy_ai::governance::{GovernanceStore, InMemoryGovernanceStore};
    use sbproxy_config::{GovernanceConfig, MissingRatePolicy};

    use super::*;

    fn policy() -> EffectiveKeyPolicy {
        let key: sbproxy_ai::identity::VirtualKeyConfig =
            serde_json::from_value(serde_json::json!({
                "key": "unused-secret",
                "key_id": "key-1",
                "max_requests_per_minute": 2,
                "max_tokens_per_minute": 100
            }))
            .unwrap();
        let mut policy = EffectiveKeyPolicy::from_configured_key(&key, "tenant-a").unwrap();
        policy.budget = Some(KeyBudgetPolicy {
            max_tokens: Some(1_000),
            max_cost_usd: Some(0.50),
        });
        policy
    }

    #[test]
    fn policy_limits_are_integer_and_budget_is_lifetime() {
        let limits = limits_for_policy(&policy()).unwrap();
        assert_eq!(limits.requests_per_window, Some(2));
        assert_eq!(limits.tokens_per_window, Some(100));
        assert_eq!(limits.total_tokens, Some(1_000));
        assert_eq!(limits.total_micro_usd, Some(500_000));
        assert_eq!(limits.window_millis, 60_000);
    }

    #[tokio::test]
    async fn admission_reserves_every_dimension_atomically() {
        let store: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
        let admitted = reserve(
            &GovernanceConfig::default(),
            store,
            &policy(),
            "gpt-4o-mini",
            Some(ModelPrice::tokens(0.15, 0.60)),
            20,
            30,
        )
        .await
        .unwrap();
        let GovernanceAdmission::Reserved(charge) = admitted else {
            panic!("expected reservation");
        };
        assert_eq!(charge.reservation().reserved.requests, 1);
        assert_eq!(charge.reservation().reserved.tokens, 50);
        assert_eq!(charge.reservation().reserved.micro_usd, 21);
    }

    #[tokio::test]
    async fn admission_uses_the_explicit_origin_price() {
        let store: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
        let admitted = reserve(
            &GovernanceConfig::default(),
            store,
            &policy(),
            "shared-local-model",
            Some(ModelPrice::tokens(7.0, 11.0)),
            2,
            3,
        )
        .await
        .unwrap();
        let GovernanceAdmission::Reserved(charge) = admitted else {
            panic!("expected reservation");
        };

        assert_eq!(charge.reservation().reserved.micro_usd, 47);
    }

    #[tokio::test]
    async fn admission_mints_a_unique_accounting_id_for_each_ingress_attempt() {
        let store: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
        let first = reserve(
            &GovernanceConfig::default(),
            Arc::clone(&store),
            &policy(),
            "gpt-4o-mini",
            Some(ModelPrice::tokens(0.15, 0.60)),
            20,
            30,
        )
        .await
        .unwrap();
        let second = reserve(
            &GovernanceConfig::default(),
            store,
            &policy(),
            "gpt-4o-mini",
            Some(ModelPrice::tokens(0.15, 0.60)),
            20,
            30,
        )
        .await
        .unwrap();
        let GovernanceAdmission::Reserved(first) = first else {
            panic!("first attempt must reserve");
        };
        let GovernanceAdmission::Reserved(second) = second else {
            panic!("second attempt must reserve");
        };

        assert_ne!(
            first.reservation().reservation_id,
            second.reservation().reservation_id
        );
    }

    #[tokio::test]
    async fn require_rate_rejects_unknown_model_before_dispatch() {
        let mut config = GovernanceConfig::default();
        config.missing_rate = MissingRatePolicy::RequireRate;
        let store: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
        let error = reserve(
            &config,
            store,
            &policy(),
            "unpriced-local-model",
            None,
            20,
            30,
        )
        .await
        .err()
        .expect("missing rate must reject");
        assert_eq!(error.status, 503);
        assert_eq!(error.code, "governance_rate_missing");
    }

    #[tokio::test]
    async fn require_rate_rejects_unpriced_token_only_local_models() {
        let mut config = GovernanceConfig::default();
        config.missing_rate = MissingRatePolicy::RequireRate;
        let mut token_only = policy();
        token_only.budget = Some(KeyBudgetPolicy {
            max_tokens: Some(1_000),
            max_cost_usd: None,
        });
        let store: Arc<dyn GovernanceStore> = Arc::new(InMemoryGovernanceStore::default());
        let error = reserve(
            &config,
            store,
            &token_only,
            "unpriced-local-model",
            None,
            20,
            30,
        )
        .await
        .err()
        .expect("require_rate applies to every governed model dispatch");
        assert_eq!(error.status, 503);
        assert_eq!(error.code, "governance_rate_missing");
    }
}
