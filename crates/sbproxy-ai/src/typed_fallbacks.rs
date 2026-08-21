//! Typed fallback triggers: trigger-specific candidate lists (WOR-2556).
//!
//! The generic failover chain answers "the provider is unavailable, try
//! the next one". Two failure classes deserve a different next: a prompt
//! that overflows the model's context window should go to a provider
//! serving a *larger-window* model, and a content-policy refusal should
//! go to a provider serving a *more permissive* model. Neither property
//! is expressed by priority order, so each trigger gets its own list
//! (`context_window_fallbacks:` / `content_policy_fallbacks:` on the
//! `ai_proxy` action), mirroring the LiteLLM vocabulary of the same
//! names.
//!
//! This module holds the pure candidate arithmetic; the dispatch loop in
//! `sbproxy-core` owns the wiring. Three operations:
//!
//! - [`resolve_candidates`] turns the authored name list into provider
//!   indices, constrained to the request's already-filtered eligible set
//!   (credential provider policy, `enabled`, model eligibility,
//!   training opt-out). A typed list can never widen what a request may
//!   reach, only re-aim it.
//! - [`preflight_context_window_reroute`] applies the context-window
//!   trigger *before dispatch*, from the same token estimate the
//!   compression levers use. A pre-flight estimate is more portable
//!   across OpenAI-passthrough providers than scraping vendor error
//!   prose, and it happens before a streaming response opens, which is
//!   what keeps streaming requests inside the trigger.
//! - [`splice_after_failure`] applies a trigger *after* a classified
//!   upstream failure: the not-yet-tried tail of the attempt order is
//!   replaced by the trigger's own list, so the next attempt comes from
//!   the aimed candidates rather than from whatever the generic chain
//!   had queued.

use crate::context_window::model_context_window;
use crate::provider::ProviderConfig;

/// Resolve an authored typed-fallback name list to provider indices.
///
/// Keeps the authored order, drops duplicates, and keeps only names
/// whose index is in `eligible` (the request's post-filter candidate
/// set). Unknown names cannot occur here: config load refuses them
/// (`AiHandlerConfig::from_config`).
pub fn resolve_candidates(
    names: &[String],
    providers: &[ProviderConfig],
    eligible: &[usize],
) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::with_capacity(names.len());
    for name in names {
        let Some(idx) = providers
            .iter()
            .position(|provider| provider.name.as_str() == name.as_str())
        else {
            continue;
        };
        if eligible.contains(&idx) && !out.contains(&idx) {
            out.push(idx);
        }
    }
    out
}

/// What a pre-flight context-window reroute decided, for logging and
/// metrics at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReroute {
    /// The provider the strategy had put first, whose model the
    /// estimate overflows.
    pub from_idx: usize,
    /// The typed-list provider now attempted first.
    pub to_idx: usize,
    /// The pre-flight prompt token estimate.
    pub estimated_tokens: u64,
    /// The overflowed model's context window.
    pub primary_window: u64,
}

/// The context window of the model `provider` would dispatch for
/// `requested_model`, after the provider's own `model_map`. Falls back
/// to a lowercase lookup the same way `routing_base_data` does, so a
/// caller-cased model id still resolves.
fn mapped_model_window(provider: &ProviderConfig, requested_model: &str) -> Option<u64> {
    let mapped = provider.map_model(requested_model);
    model_context_window(&mapped).or_else(|| model_context_window(&mapped.to_lowercase()))
}

/// Apply the context-window trigger before dispatch.
///
/// When the prompt estimate exceeds the primary provider's mapped-model
/// window and a typed candidate's mapped model has a strictly larger
/// window that the estimate fits, the fitting typed candidates move to
/// the front of `order` (authored list order preserved, remaining
/// original order behind them). Returns what happened, or `None` when
/// nothing changed: no estimate (non-chat surfaces), an unlisted primary
/// model (no window to overflow), an estimate that fits, or a typed list
/// with no candidate that fits.
///
/// The fit rule is the one the deleted WOR-1524-era `check_overflow`
/// used: a candidate counts only when its window is larger than the
/// primary's *and* the estimate fits it. A same-size or unknown-window
/// candidate would fail the same way the primary was about to.
pub fn preflight_context_window_reroute(
    order: &mut Vec<usize>,
    providers: &[ProviderConfig],
    requested_model: &str,
    estimated_tokens: Option<u64>,
    typed: &[usize],
) -> Option<PreflightReroute> {
    if typed.is_empty() || requested_model.is_empty() {
        return None;
    }
    let estimated = estimated_tokens?;
    let &primary_idx = order.first()?;
    let primary_window = mapped_model_window(providers.get(primary_idx)?, requested_model)?;
    if estimated <= primary_window {
        return None;
    }
    let fitting: Vec<usize> = typed
        .iter()
        .copied()
        .filter(|&idx| idx != primary_idx)
        .filter(|&idx| {
            providers
                .get(idx)
                .and_then(|provider| mapped_model_window(provider, requested_model))
                .is_some_and(|window| window > primary_window && estimated <= window)
        })
        .collect();
    let &to_idx = fitting.first()?;
    let mut rerouted = fitting.clone();
    rerouted.extend(order.iter().copied().filter(|idx| !fitting.contains(idx)));
    *order = rerouted;
    Some(PreflightReroute {
        from_idx: primary_idx,
        to_idx,
        estimated_tokens: estimated,
        primary_window,
    })
}

/// Replace the untried tail of `order` with a trigger's typed list.
///
/// `attempt` is the zero-based index of the attempt that just failed;
/// entries up to and including it are kept (they were really tried and
/// the admin ring already saw them), everything after is replaced by the
/// typed candidates that have not been tried yet. Returns the provider
/// index the next attempt will use, or `None` when every typed candidate
/// was already tried, in which case `order` is left untouched and the
/// caller falls through to its no-candidates-left handling.
///
/// The typed list *takes over* rather than being merged: once a trigger
/// has classified the failure, the generic tail is queued for the wrong
/// question ("who is up" rather than "who can take this prompt"), so it
/// is dropped.
pub fn splice_after_failure(
    order: &mut Vec<usize>,
    attempt: usize,
    typed: &[usize],
) -> Option<usize> {
    let tried = order.get(..=attempt)?;
    let additions: Vec<usize> = typed
        .iter()
        .copied()
        .filter(|idx| !tried.contains(idx))
        .collect();
    let &next = additions.first()?;
    order.truncate(attempt + 1);
    order.extend(additions);
    Some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, model_map: serde_json::Value) -> ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "api_key": "k",
            "model_map": model_map,
        }))
        .expect("test provider parses")
    }

    /// Providers: 0 = small (gpt-4 at 8k), 1 = big (maps gpt-4 to
    /// gpt-4-turbo at 128k), 2 = spare (no map, same 8k window).
    fn fixture() -> Vec<ProviderConfig> {
        vec![
            provider("small", serde_json::json!({})),
            provider("big", serde_json::json!({"gpt-4": "gpt-4-turbo"})),
            provider("spare", serde_json::json!({})),
        ]
    }

    #[test]
    fn resolve_keeps_authored_order_and_respects_eligibility() {
        let providers = fixture();
        let names = vec!["big".to_string(), "spare".to_string(), "big".to_string()];
        assert_eq!(
            resolve_candidates(&names, &providers, &[0, 1, 2]),
            vec![1, 2],
            "authored order, duplicates dropped"
        );
        assert_eq!(
            resolve_candidates(&names, &providers, &[0, 2]),
            vec![2],
            "a typed list cannot widen the eligible set"
        );
        assert!(resolve_candidates(&names, &providers, &[]).is_empty());
    }

    #[test]
    fn preflight_reroutes_an_overflowing_estimate_to_the_larger_window() {
        let providers = fixture();
        let mut order = vec![0, 2, 1];
        let reroute = preflight_context_window_reroute(
            &mut order,
            &providers,
            "gpt-4",
            Some(20_000), // over gpt-4's 8_192, fits gpt-4-turbo's 128_000
            &[1],
        )
        .expect("an overflowing estimate with a fitting candidate reroutes");
        assert_eq!(reroute.from_idx, 0);
        assert_eq!(reroute.to_idx, 1);
        assert_eq!(reroute.primary_window, 8_192);
        assert_eq!(
            order,
            vec![1, 0, 2],
            "typed candidate first, rest keep order"
        );
    }

    #[test]
    fn preflight_leaves_a_fitting_estimate_alone() {
        let providers = fixture();
        let mut order = vec![0, 1];
        assert!(preflight_context_window_reroute(
            &mut order,
            &providers,
            "gpt-4",
            Some(4_000),
            &[1],
        )
        .is_none());
        assert_eq!(order, vec![0, 1]);
    }

    #[test]
    fn preflight_skips_candidates_that_would_overflow_too() {
        let providers = fixture();
        let mut order = vec![0, 2];
        // `spare` maps nothing, so its window equals the primary's: not
        // a larger window, no reroute.
        assert!(preflight_context_window_reroute(
            &mut order,
            &providers,
            "gpt-4",
            Some(20_000),
            &[2],
        )
        .is_none());
        assert_eq!(order, vec![0, 2]);
        // An estimate too large even for the typed candidate: no reroute.
        let mut order = vec![0, 1];
        assert!(preflight_context_window_reroute(
            &mut order,
            &providers,
            "gpt-4",
            Some(500_000),
            &[1],
        )
        .is_none());
    }

    #[test]
    fn preflight_needs_an_estimate_and_a_known_primary_window() {
        let providers = fixture();
        let mut order = vec![0, 1];
        assert!(
            preflight_context_window_reroute(&mut order, &providers, "gpt-4", None, &[1]).is_none(),
            "no estimate (non-chat surface): no reroute"
        );
        assert!(
            preflight_context_window_reroute(
                &mut order,
                &providers,
                "some-unlisted-model",
                Some(1_000_000),
                &[1],
            )
            .is_none(),
            "an unlisted primary model has no window to overflow"
        );
    }

    #[test]
    fn splice_replaces_the_untried_tail_with_the_typed_list() {
        let mut order = vec![0, 2, 1];
        let next = splice_after_failure(&mut order, 0, &[1]).expect("candidate available");
        assert_eq!(next, 1);
        assert_eq!(
            order,
            vec![0, 1],
            "generic tail dropped, typed list takes over"
        );
    }

    #[test]
    fn splice_skips_already_tried_candidates_and_can_exhaust() {
        let mut order = vec![1, 0];
        assert!(
            splice_after_failure(&mut order, 0, &[1]).is_none(),
            "the only typed candidate already failed as the primary"
        );
        assert_eq!(
            order,
            vec![1, 0],
            "an exhausted splice leaves the order alone"
        );

        let mut order = vec![1, 0, 2];
        let next = splice_after_failure(&mut order, 1, &[1, 2]).expect("one untried");
        assert_eq!(next, 2);
        assert_eq!(order, vec![1, 0, 2]);
    }
}
