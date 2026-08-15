// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The `route.decide` decision event: return a plan, not a model name.
//!
//! Neither LiteLLM nor Envoy exposes the routing decision itself as an
//! operator-authored policy. Both ship a fixed strategy menu plus knobs.
//! This is one of the two places in the extension surface with no
//! competitor equivalent, which makes it a differentiator rather than a
//! catch-up.
//!
//! ## Why the existing seam was not enough
//!
//! `AiPolicyAction::RouteTo(String)` already existed and CEL already
//! drove it, so this extends a capability rather than inventing one. Two
//! limits made it insufficient.
//!
//! **One expression for the whole plane.** `AiPolicyConfig` holds a
//! single `expression`, so multiple routing conditions collapse into one
//! nested ternary.
//!
//! **A single model name cannot express a plan.** `FallbackChain` and
//! `Cascade` already carry ordered fallbacks and per-tier quality
//! thresholds internally. A policy that returns one string is strictly
//! less expressive than the built-in strategies it is meant to extend,
//! which is backwards.
//!
//! ## Declining is the common path
//!
//! Most operators want a rule for a few cases and the built-in strategy
//! for everything else. A policy that returns nothing
//! ([`RouteDecision::Decline`]) falls through to the configured
//! [`crate::routing::RoutingStrategy`] rather than failing. Forcing a
//! policy to reimplement `LeastTokenUsage` to handle its default case
//! would be a design failure, so declining is the cheapest thing to
//! write: an empty document, a `null`, or no `candidates` key at all.
//!
//! ## No I/O
//!
//! Everything the decision needs is assembled before it runs. That is
//! what keeps every engine eligible, and it is why a classifier call
//! does not belong in this event: the prompt fingerprint and any
//! classification already computed are passed in.
//!
//! ## CEL's ceiling, stated rather than worked around
//!
//! CEL returns a scalar, which is exactly why `route_to:gpt-4o-mini`
//! became a string mini-language. Rather than growing a second token
//! grammar, a CEL `route_to` action is lifted into a one-candidate plan
//! by [`RoutePlan::from_route_to`]. CEL keeps working, expresses exactly
//! what it could always express, and the document engines get the rest.

use serde::Serialize;

/// Upper bound on candidates in one plan.
///
/// A plan is tried in order, so its length is a latency budget as much
/// as a memory one. Eight is past any real fallback chain and well short
/// of a policy bug that returns the whole provider catalog.
pub const MAX_ROUTE_CANDIDATES: usize = 8;

/// Upper bound on a model or provider id, in bytes.
///
/// These are the strings that *leave* this module: `model` reaches the
/// request body sent upstream, the access log, and the `model` metric
/// label, whose accepted values the cardinality limiter retains for the
/// process lifetime. An unbounded name is therefore retained memory that
/// no scrape or reload releases, which is a worse failure than the
/// bounded `reason` this module was already careful about.
pub const MAX_ROUTE_NAME_BYTES: usize = 256;

/// Upper bound on a `reason` string, in bytes.
///
/// The reason reaches the access log, a metric label, and the audit
/// record, so it is bounded at the edge rather than at each consumer.
pub const MAX_ROUTE_REASON_BYTES: usize = 512;

/// One candidate in a routing plan.
///
/// Mirrors [`crate::routing::CascadeTier`] deliberately: a plan should
/// be able to express what the built-in cascade already expresses, or it
/// is again less capable than the thing it extends.
///
/// Both limit fields read a JSON `null` as absent, which is worth knowing
/// when the limit is computed rather than written literally: JSON cannot
/// spell NaN or infinity, so a CEL expression whose arithmetic goes
/// non-finite arrives here as `null` and produces a candidate with no
/// limit rather than a refusal. An operator computing a cap should guard
/// the expression against NaN and infinity, because the decoder cannot
/// tell that null from the one every guest encoder emits for an unset
/// optional.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteCandidate {
    /// Name of the provider in `AiHandlerConfig::providers`.
    pub provider_id: String,
    /// Model id to send to that provider.
    pub model: String,
    /// Minimum acceptable confidence score for this candidate's
    /// response, matching `CascadeTier::quality_threshold`. `None`
    /// accepts any response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_threshold: Option<f32>,
    /// Optional per-candidate cost cap in micro-USD, matching
    /// `CascadeTier::cost_cap`. `None` disables the cap. The unit is the
    /// same micro-USD scale the cost catalog uses, so a plan expresses a
    /// cap the built-in cascade already understands rather than a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_cap: Option<u64>,
}

/// An ordered routing plan plus the reason it was chosen.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct RoutePlan {
    /// Candidates in preference order. Never empty: an empty list is a
    /// decline, which is a different thing and has its own variant.
    pub candidates: Vec<RouteCandidate>,
    /// Why this plan was chosen.
    ///
    /// Not decoration: it is what makes a routing decision diagnosable,
    /// and `release_max_level_info` compiles `debug!` out of release
    /// builds, so a reason that lives only in a debug line does not
    /// exist where an operator needs it.
    ///
    /// **Its destination is the audit record, not a metric label.** This
    /// is operator- or guest-authored free text, so as a label value it
    /// is an unbounded-cardinality primitive: it would burn the label's
    /// whole budget with distinct strings and pin every accepted one in
    /// the limiter for the process lifetime.
    ///
    /// **It must go through the redactor before it is emitted anywhere.**
    /// A hook is free to explain itself with
    /// `"prompt looked like " + prompt.slice(0, 100)`, and nothing on
    /// this path scrubs that today, which is why
    /// [`sbproxy_observe::decision::DecisionAudit`] documents `reason` as
    /// already-redacted on arrival.
    ///
    /// Nothing reads this field yet. The routing event records its
    /// outcome but not its reason, so wiring it to the audit record is
    /// outstanding rather than done.
    pub reason: String,
}

impl RoutePlan {
    /// Lift a CEL `route_to:<model>` action into a one-candidate plan.
    ///
    /// The provider is left to the built-in resolver, which is what
    /// `route_to` always did: it names a model and lets model-to-provider
    /// resolution find the rest. This is CEL's ceiling expressed as a
    /// plan rather than as a second code path.
    pub fn from_route_to(model: impl Into<String>) -> Self {
        Self {
            candidates: vec![RouteCandidate {
                provider_id: String::new(),
                model: model.into(),
                quality_threshold: None,
                cost_cap: None,
            }],
            reason: "route_to policy action".to_owned(),
        }
    }

    /// The first candidate, or `None` for a plan with no candidates.
    ///
    /// `decode_route_plan` never produces an empty plan, and neither
    /// does [`Self::from_route_to`]. This still returns an `Option`
    /// rather than indexing, because [`Self::candidates`] is a public
    /// field: anything outside this module can build
    /// `RoutePlan { candidates: vec![], .. }`, and an invariant that
    /// holds only by construction discipline is one panic away from
    /// being wrong on the response path.
    pub fn primary(&self) -> Option<&RouteCandidate> {
        self.candidates.first()
    }

    /// Candidates after the first, in order. These are the fallbacks.
    /// Empty for a plan with one candidate or none.
    pub fn fallbacks(&self) -> &[RouteCandidate] {
        self.candidates.get(1..).unwrap_or_default()
    }

    /// Refuse a plan naming a provider that is not configured.
    ///
    /// A `provider_id` naming nothing in `AiHandlerConfig::providers` is
    /// a config error when it can be caught at load. At runtime a policy
    /// can still return one, and that needs a defined outcome rather
    /// than a panic or a silent skip: the plan is refused whole and the
    /// caller falls back to the configured strategy, which is the same
    /// path a decline takes.
    ///
    /// An empty `provider_id` is allowed and means "resolve the provider
    /// from the model", matching `route_to`.
    pub fn validate_providers(&self, configured: &[String]) -> Result<(), RouteEventError> {
        for candidate in &self.candidates {
            if candidate.provider_id.is_empty() {
                continue;
            }
            if !configured.iter().any(|p| p == &candidate.provider_id) {
                return Err(RouteEventError::UnknownProvider {
                    provider_id: candidate.provider_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Refuse a plan unless every candidate names a configured provider.
    ///
    /// Stricter than [`Self::validate_providers`]: an empty `provider_id`
    /// is a [`RouteEventError::MissingProvider`] rather than the "resolve
    /// from the model" sentinel. A plan headed into the cascade executor
    /// dispatches each candidate at a named provider, so a blank one has
    /// nothing to dispatch to; the lenient form exists for the `route_to`
    /// lift, which does resolve a bare model, and must not be reused here.
    pub fn require_known_providers(&self, configured: &[String]) -> Result<(), RouteEventError> {
        for (index, candidate) in self.candidates.iter().enumerate() {
            if candidate.provider_id.is_empty() {
                return Err(RouteEventError::MissingProvider { index });
            }
            if !configured.iter().any(|p| p == &candidate.provider_id) {
                return Err(RouteEventError::UnknownProvider {
                    provider_id: candidate.provider_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Drop the candidates that name no configured provider; keep the rest.
    ///
    /// The runtime disposition for a plan naming unconfigured providers
    /// (WOR-2366 D6): drop the dead tiers and continue on the survivors.
    /// The caller errors only when nothing survives; a partially wrong
    /// plan still routes on the tiers that can dispatch, which is strictly
    /// better for the request than refusing the whole plan over one typo.
    ///
    /// Removed candidates' provider ids are returned in plan order so the
    /// caller can warn with them. A blank `provider_id` is dropped too,
    /// for the reason [`Self::require_known_providers`] refuses it: a plan
    /// headed into the cascade executor has nothing to dispatch a blank
    /// provider to.
    pub fn retain_known_providers(&mut self, configured: &[String]) -> Vec<String> {
        let mut dropped = Vec::new();
        self.candidates.retain(|candidate| {
            if !candidate.provider_id.is_empty()
                && configured.iter().any(|p| p == &candidate.provider_id)
            {
                return true;
            }
            dropped.push(candidate.provider_id.clone());
            false
        });
        dropped
    }

    /// Convert this plan into a [`crate::routing::CascadeConfig`] so it
    /// dispatches through the same cascade executor the built-in
    /// `Cascade` strategy uses, rather than a parallel path.
    ///
    /// A candidate's absent `quality_threshold` becomes `0.0`
    /// (accept-any): an operator plan is a preference order, not
    /// necessarily a quality cascade, and `CascadeTier::quality_threshold`
    /// is non-optional. `max_total_cost` carries the cascade-wide cap the
    /// caller already computes for the built-in strategy.
    #[must_use]
    pub fn to_cascade_config(&self, max_total_cost: Option<u64>) -> crate::routing::CascadeConfig {
        crate::routing::CascadeConfig {
            tiers: self
                .candidates
                .iter()
                .map(|candidate| crate::routing::CascadeTier {
                    provider_id: candidate.provider_id.clone(),
                    model: candidate.model.clone(),
                    quality_threshold: candidate.quality_threshold.unwrap_or(0.0),
                    cost_cap: candidate.cost_cap,
                })
                .collect(),
            max_total_cost,
        }
    }
}

/// What a `route.decide` event returned.
#[derive(Debug, Clone, PartialEq)]
pub enum RouteDecision {
    /// No opinion. The configured routing strategy applies unchanged.
    ///
    /// The common path, and deliberately the cheapest to express.
    Decline,
    /// Use this plan.
    Plan(RoutePlan),
}

/// Why a returned routing document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteEventError {
    /// The document was not an object.
    NotAnObject,
    /// `candidates` was present but not an array.
    CandidatesNotAnArray,
    /// A candidate was missing `model`, or it was empty.
    CandidateMissingModel {
        /// Position of the offending candidate.
        index: usize,
    },
    /// More candidates than [`MAX_ROUTE_CANDIDATES`].
    TooManyCandidates {
        /// How many were returned.
        count: usize,
    },
    /// A candidate field had the wrong JSON type.
    CandidateFieldType {
        /// Position of the offending candidate.
        index: usize,
        /// Which field.
        field: &'static str,
    },
    /// A candidate's model or provider id exceeded
    /// [`MAX_ROUTE_NAME_BYTES`].
    CandidateNameTooLong {
        /// Position of the offending candidate.
        index: usize,
    },
    /// A candidate named a provider that is not configured.
    UnknownProvider {
        /// The name that did not resolve.
        provider_id: String,
    },
    /// A candidate headed into the cascade executor left `provider_id`
    /// empty. The lenient `route_to` resolve-from-model sentinel is not
    /// valid for a plan that dispatches at a named provider per tier.
    MissingProvider {
        /// Position of the offending candidate.
        index: usize,
    },
}

impl std::fmt::Display for RouteEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => {
                write!(f, "route.decide must return an object or null")
            }
            Self::CandidatesNotAnArray => {
                write!(f, "route.decide `candidates` must be an array")
            }
            Self::CandidateMissingModel { index } => {
                write!(f, "route.decide candidate {index} has no `model`")
            }
            Self::TooManyCandidates { count } => write!(
                f,
                "route.decide returned {count} candidates, the cap is {MAX_ROUTE_CANDIDATES}"
            ),
            Self::CandidateFieldType { index, field } => write!(
                f,
                "route.decide candidate {index} has a wrongly typed `{field}`"
            ),
            Self::CandidateNameTooLong { index } => write!(
                f,
                "route.decide candidate {index} has a model or provider id over \
                 {MAX_ROUTE_NAME_BYTES} bytes"
            ),
            Self::UnknownProvider { provider_id } => write!(
                f,
                "route.decide named provider `{provider_id}`, which is not configured"
            ),
            Self::MissingProvider { index } => write!(
                f,
                "route.decide candidate {index} has an empty `provider_id`, which a \
                 cascade plan cannot dispatch"
            ),
        }
    }
}

impl std::error::Error for RouteEventError {}

/// Decode whatever an engine returned into a routing decision.
///
/// Every document engine (Lua, JavaScript, WASM, Proxy-Wasm, and Rego if
/// it lands) returns JSON, so one decoder serves all of them. That is
/// the point of defining the event rather than the engine.
///
/// Declining has three spellings, all of which mean the same thing,
/// because an operator writing a rule for one case should not have to
/// look up how to say "not this time":
///
/// - `null`
/// - `{}`
/// - `{"candidates": []}`
pub fn decode_route_plan(value: &serde_json::Value) -> Result<RouteDecision, RouteEventError> {
    if value.is_null() {
        return Ok(RouteDecision::Decline);
    }
    let object = value.as_object().ok_or(RouteEventError::NotAnObject)?;
    let Some(raw) = object.get("candidates") else {
        return Ok(RouteDecision::Decline);
    };
    if raw.is_null() {
        return Ok(RouteDecision::Decline);
    }
    let array = raw
        .as_array()
        .ok_or(RouteEventError::CandidatesNotAnArray)?;
    if array.is_empty() {
        return Ok(RouteDecision::Decline);
    }
    if array.len() > MAX_ROUTE_CANDIDATES {
        return Err(RouteEventError::TooManyCandidates { count: array.len() });
    }

    let mut candidates = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let model = entry
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .ok_or(RouteEventError::CandidateMissingModel { index })?;
        // A wrong-typed `provider_id` must not silently become the empty
        // "resolve from the model" sentinel: that would turn a malformed
        // provider into an opt-out of the provider check rather than a
        // failure of it.
        let provider_id = match entry.get("provider_id") {
            None | Some(serde_json::Value::Null) => "",
            Some(serde_json::Value::String(provider)) => provider.trim(),
            Some(_) => {
                return Err(RouteEventError::CandidateFieldType {
                    index,
                    field: "provider_id",
                })
            }
        };
        if model.len() > MAX_ROUTE_NAME_BYTES || provider_id.len() > MAX_ROUTE_NAME_BYTES {
            return Err(RouteEventError::CandidateNameTooLong { index });
        }
        // A threshold *outside* 0.0..=1.0 is a policy bug rather than a
        // refusal-worthy one: clamp it and let the plan run. A
        // wrong-*typed* one is different and is refused, because
        // dropping it to `None` reads as "accepts any response", so a
        // quality gate the operator wrote silently becomes no gate. A
        // stringified number is the ordinary way a Lua or JS bridge
        // produces this.
        //
        // `as_f64` cannot yield NaN: `serde_json::Number` has no
        // non-finite representation and `arbitrary_precision` is off, so
        // `clamp` never sees the one input that would pass NaN through.
        let quality_threshold = match entry.get("quality_threshold") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(number)) => {
                number.as_f64().map(|value| value.clamp(0.0, 1.0) as f32)
            }
            Some(_) => {
                return Err(RouteEventError::CandidateFieldType {
                    index,
                    field: "quality_threshold",
                })
            }
        };
        // A `cost_cap` is an unsigned micro-USD integer. A wrong-typed one
        // is refused for the same reason a wrong-typed threshold is: a cap
        // dropped to `None` silently removes a limit the operator wrote. A
        // negative or fractional number is not a valid cap, so it is a
        // type error rather than a value to clamp.
        let cost_cap = match entry.get("cost_cap") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(number)) => {
                Some(number.as_u64().ok_or(RouteEventError::CandidateFieldType {
                    index,
                    field: "cost_cap",
                })?)
            }
            Some(_) => {
                return Err(RouteEventError::CandidateFieldType {
                    index,
                    field: "cost_cap",
                })
            }
        };
        candidates.push(RouteCandidate {
            provider_id: provider_id.to_owned(),
            model: model.to_owned(),
            quality_threshold,
            cost_cap,
        });
    }

    let reason = object
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(|reason| bounded_reason(reason.trim()))
        .unwrap_or_default();

    Ok(RouteDecision::Plan(RoutePlan { candidates, reason }))
}

/// What the dispatcher should do with a decoded routing decision,
/// given the model already in play.
///
/// Extracted from the dispatch site so the mapping is testable without
/// standing up a request. The dispatcher is long enough that a decision
/// buried inside it can only be exercised end to end, which is how a
/// wrong outcome label survives review.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RouteApplication<'a> {
    /// Leave the request alone; the configured strategy applies.
    ///
    /// Covers an explicit decline, a plan naming the model already in
    /// play, and a plan with no candidates. The second one matters:
    /// counting a no-op as a route change makes the routing panel show
    /// churn that never happened, and an operator chasing it finds
    /// nothing.
    LeaveAlone,
    /// Switch to this candidate.
    ///
    /// Carrying the candidate rather than a bare "yes" is deliberate.
    /// A caller that has to look the primary up again needs a branch
    /// for the `None` case it has already been told cannot happen, and
    /// that branch is where a silent early return or a panic gets
    /// written.
    Apply(&'a RouteCandidate),
}

impl<'a> RouteApplication<'a> {
    /// Decide what to do, without doing it.
    pub fn resolve(decision: &'a RouteDecision, current_model: &str) -> Self {
        let RouteDecision::Plan(plan) = decision else {
            return Self::LeaveAlone;
        };
        // A plan with no candidates says nothing, so it decides nothing.
        match plan.primary() {
            Some(candidate) if candidate.model != current_model => Self::Apply(candidate),
            _ => Self::LeaveAlone,
        }
    }
}

/// Truncate a reason on a character boundary.
fn bounded_reason(reason: &str) -> String {
    if reason.len() <= MAX_ROUTE_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_ROUTE_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_spelling_of_declining_is_accepted() {
        // Declining is the common path, so it has to be the cheapest
        // thing to write. An operator adding a rule for one case should
        // not have to look up how to say "not this time".
        for value in [
            json!(null),
            json!({}),
            json!({"candidates": []}),
            json!({"candidates": null}),
            json!({"reason": "nothing matched"}),
        ] {
            assert_eq!(
                decode_route_plan(&value),
                Ok(RouteDecision::Decline),
                "{value} must decline"
            );
        }
    }

    #[test]
    fn a_plan_decodes_in_order_with_its_reason() {
        let decision = decode_route_plan(&json!({
            "candidates": [
                {"provider_id": "anthropic", "model": "claude-sonnet-5", "quality_threshold": 0.7},
                {"provider_id": "openai", "model": "gpt-4o-mini"},
            ],
            "reason": "code-generation prompt on paid tier",
        }))
        .unwrap();
        let RouteDecision::Plan(plan) = decision else {
            panic!("expected a plan");
        };
        assert_eq!(plan.candidates.len(), 2);
        let primary = plan
            .primary()
            .expect("a decoded plan always has a candidate");
        assert_eq!(primary.provider_id, "anthropic");
        assert_eq!(primary.model, "claude-sonnet-5");
        assert_eq!(primary.quality_threshold, Some(0.7));
        assert_eq!(plan.fallbacks().len(), 1);
        assert_eq!(plan.fallbacks()[0].model, "gpt-4o-mini");
        assert_eq!(plan.reason, "code-generation prompt on paid tier");
    }

    #[test]
    fn order_is_preserved_because_it_is_the_whole_point() {
        // A plan is a preference order. If decoding reordered it the
        // fallback chain would be silently wrong and nothing would say
        // so.
        let models = ["a", "b", "c", "d"];
        let decision = decode_route_plan(&json!({
            "candidates": models.iter().map(|m| json!({"model": m})).collect::<Vec<_>>(),
        }))
        .unwrap();
        let RouteDecision::Plan(plan) = decision else {
            panic!("expected a plan");
        };
        let decoded: Vec<_> = plan.candidates.iter().map(|c| c.model.as_str()).collect();
        assert_eq!(decoded, models);
    }

    #[test]
    fn a_candidate_without_a_model_is_refused_and_names_its_position() {
        let error = decode_route_plan(&json!({
            "candidates": [{"model": "ok"}, {"provider_id": "openai"}],
        }))
        .unwrap_err();
        assert_eq!(error, RouteEventError::CandidateMissingModel { index: 1 });
        assert!(
            error.to_string().contains('1'),
            "the operator needs to know which one: {error}"
        );
    }

    #[test]
    fn an_empty_or_whitespace_model_is_not_a_model() {
        for model in ["", "   "] {
            assert_eq!(
                decode_route_plan(&json!({"candidates": [{"model": model}]})),
                Err(RouteEventError::CandidateMissingModel { index: 0 })
            );
        }
    }

    #[test]
    fn a_wrongly_typed_field_is_refused_rather_than_coerced() {
        // Dropping a bad `quality_threshold` to `None` reads as "accepts
        // any response", so a quality gate the operator wrote silently
        // becomes no gate. A stringified number is what a Lua or JS
        // bridge produces when anything on the path stringifies.
        assert_eq!(
            decode_route_plan(&json!({
                "candidates": [{"model": "m", "quality_threshold": "0.8"}]
            })),
            Err(RouteEventError::CandidateFieldType {
                index: 0,
                field: "quality_threshold"
            })
        );
        // A wrongly typed provider is worse: coerced to the empty string
        // it becomes the "resolve from the model" sentinel, so it would
        // opt out of the provider check rather than fail it.
        assert_eq!(
            decode_route_plan(&json!({
                "candidates": [{"model": "m", "provider_id": 42}]
            })),
            Err(RouteEventError::CandidateFieldType {
                index: 0,
                field: "provider_id"
            })
        );
    }

    #[test]
    fn an_explicit_null_is_absent_rather_than_wrongly_typed() {
        // JSON encoders emit null for an absent optional constantly, so
        // refusing it would reject documents nobody considers malformed.
        // The limit fields are where that bites hardest: a guest written
        // in Rust serializes an unset `Option<u64>` as `"cost_cap": null`
        // on every candidate, as do a Go pointer field and Python's
        // `json.dumps(None)`, so refusing a present null would make every
        // plan those guests return an error and the policy silently inert.
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [
                {"model": "m", "provider_id": null, "quality_threshold": null, "cost_cap": null}
            ]
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(plan.candidates[0].provider_id, "");
        assert_eq!(plan.candidates[0].quality_threshold, None);
        assert_eq!(plan.candidates[0].cost_cap, None);
    }

    #[test]
    fn a_runaway_model_name_is_refused_before_it_leaves_the_module() {
        // `model` reaches the upstream request body, the access log, and
        // the `model` metric label, whose accepted values the cardinality
        // limiter retains for the process lifetime. An unbounded name is
        // retained memory nothing releases.
        let long = "x".repeat(MAX_ROUTE_NAME_BYTES + 1);
        assert_eq!(
            decode_route_plan(&json!({"candidates": [{"model": long}]})),
            Err(RouteEventError::CandidateNameTooLong { index: 0 })
        );
    }

    #[test]
    fn a_runaway_plan_is_capped() {
        let candidates: Vec<_> = (0..MAX_ROUTE_CANDIDATES + 1)
            .map(|i| json!({"model": format!("m{i}")}))
            .collect();
        assert_eq!(
            decode_route_plan(&json!({"candidates": candidates})),
            Err(RouteEventError::TooManyCandidates {
                count: MAX_ROUTE_CANDIDATES + 1
            })
        );
    }

    #[test]
    fn a_non_object_document_is_refused() {
        for value in [json!("gpt-4o-mini"), json!(7), json!([])] {
            assert_eq!(
                decode_route_plan(&value),
                Err(RouteEventError::NotAnObject),
                "{value} is not a plan"
            );
        }
    }

    #[test]
    fn an_unknown_provider_is_refused_rather_than_silently_skipped() {
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [{"provider_id": "typo-here", "model": "gpt-4o-mini"}],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        let error = plan
            .validate_providers(&["openai".to_owned(), "anthropic".to_owned()])
            .unwrap_err();
        assert_eq!(
            error,
            RouteEventError::UnknownProvider {
                provider_id: "typo-here".to_owned()
            }
        );
        assert!(error.to_string().contains("typo-here"));
    }

    #[test]
    fn an_empty_provider_means_resolve_from_the_model() {
        // This is what `route_to` always did: name a model and let
        // model-to-provider resolution find the rest. Validation must
        // not treat it as a typo.
        let plan = RoutePlan::from_route_to("gpt-4o-mini");
        assert!(plan.validate_providers(&["openai".to_owned()]).is_ok());
        assert!(plan.validate_providers(&[]).is_ok());
    }

    #[test]
    fn a_cel_route_to_becomes_a_one_candidate_plan() {
        // CEL returns a scalar. Rather than growing a second token
        // grammar for plans, its ceiling is expressed as the plan it
        // could always express.
        let plan = RoutePlan::from_route_to("gpt-4o-mini");
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(
            plan.primary().map(|c| c.model.as_str()),
            Some("gpt-4o-mini")
        );
        assert!(plan.fallbacks().is_empty());
        assert!(
            !plan.reason.is_empty(),
            "even the lifted path must be diagnosable"
        );
    }

    #[test]
    fn a_quality_threshold_outside_the_range_is_clamped_not_refused() {
        // A malformed optional field is a policy bug, but refusing the
        // whole plan over it would silently send the request to the
        // built-in strategy, which is a bigger behavior change than the
        // operator asked for.
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [
                {"model": "a", "quality_threshold": 4.2},
                {"model": "b", "quality_threshold": -1.0},
            ],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(plan.candidates[0].quality_threshold, Some(1.0));
        assert_eq!(plan.candidates[1].quality_threshold, Some(0.0));
    }

    #[test]
    fn declining_leaves_the_request_alone() {
        assert_eq!(
            RouteApplication::resolve(&RouteDecision::Decline, "gpt-4o-mini"),
            RouteApplication::LeaveAlone
        );
    }

    #[test]
    fn a_plan_naming_the_current_model_is_a_no_op_not_a_route_change() {
        // Counting this as a route change makes the routing panel show
        // churn that never happened, and an operator chasing it finds
        // nothing. It is the same request either way.
        let decision = RouteDecision::Plan(RoutePlan::from_route_to("gpt-4o-mini"));
        assert_eq!(
            RouteApplication::resolve(&decision, "gpt-4o-mini"),
            RouteApplication::LeaveAlone
        );
    }

    #[test]
    fn a_plan_naming_a_different_model_applies() {
        let decision = RouteDecision::Plan(RoutePlan::from_route_to("claude-sonnet-5"));
        let RouteApplication::Apply(candidate) =
            RouteApplication::resolve(&decision, "gpt-4o-mini")
        else {
            panic!("a plan naming a different model must apply");
        };
        assert_eq!(
            candidate.model, "claude-sonnet-5",
            "Apply must carry the candidate so the call site never looks it up again"
        );
    }

    #[test]
    fn a_hand_built_empty_plan_decides_nothing_instead_of_panicking() {
        // `candidates` is a public field, so an empty plan is
        // constructible from outside this module even though no decoder
        // produces one. Indexing it would panic on the response path.
        let empty = RoutePlan {
            candidates: Vec::new(),
            reason: String::new(),
        };
        assert!(empty.primary().is_none());
        assert!(empty.fallbacks().is_empty());
        assert_eq!(
            RouteApplication::resolve(&RouteDecision::Plan(empty), "gpt-4o-mini"),
            RouteApplication::LeaveAlone
        );
    }

    #[test]
    fn an_overlong_reason_is_truncated_on_a_character_boundary() {
        // A 3-byte character on purpose. With a 2-byte one the cap
        // divides evenly, `is_char_boundary` is already true, the
        // back-up loop never executes, and the test passes against a
        // naive `reason[..CAP]` that would panic here.
        let reason = "\u{20ac}".repeat(MAX_ROUTE_REASON_BYTES);
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [{"model": "a"}],
            "reason": reason,
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(
            plan.reason.len(),
            MAX_ROUTE_REASON_BYTES - (MAX_ROUTE_REASON_BYTES % 3),
            "truncation must back up to the nearest character boundary"
        );
        assert!(
            plan.reason.chars().all(|c| c == '\u{20ac}'),
            "truncation must not split a character"
        );
    }

    #[test]
    fn cost_cap_decodes_as_micro_usd_and_refuses_a_wrong_type() {
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [{"model": "a", "provider_id": "openai", "cost_cap": 1500}],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(plan.candidates[0].cost_cap, Some(1500));
        // A negative or fractional cap is not a valid micro-USD integer,
        // and a string is not a number, so both are refused rather than
        // silently dropping the operator's cap.
        for bad in [json!(-5), json!(1.5), json!("1500")] {
            assert_eq!(
                decode_route_plan(&json!({
                    "candidates": [{"model": "a", "provider_id": "openai", "cost_cap": bad}],
                })),
                Err(RouteEventError::CandidateFieldType {
                    index: 0,
                    field: "cost_cap",
                })
            );
        }
    }

    #[test]
    fn to_cascade_config_carries_fields_and_defaults_absent_threshold_to_zero() {
        let RouteDecision::Plan(plan) = decode_route_plan(&json!({
            "candidates": [
                {"provider_id": "anthropic", "model": "claude-sonnet-5", "quality_threshold": 0.7, "cost_cap": 2000},
                {"provider_id": "openai", "model": "gpt-4o-mini"},
            ],
            "reason": "x",
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        let cascade = plan.to_cascade_config(Some(9000));
        assert_eq!(cascade.max_total_cost, Some(9000));
        assert_eq!(cascade.tiers.len(), 2);
        assert_eq!(cascade.tiers[0].provider_id, "anthropic");
        assert_eq!(cascade.tiers[0].quality_threshold, 0.7);
        assert_eq!(cascade.tiers[0].cost_cap, Some(2000));
        // An absent threshold becomes accept-any (0.0), because a plan is a
        // preference order and `CascadeTier::quality_threshold` is non-optional.
        assert_eq!(cascade.tiers[1].quality_threshold, 0.0);
        assert_eq!(cascade.tiers[1].cost_cap, None);
    }

    #[test]
    fn require_known_providers_is_stricter_than_validate_providers() {
        // The `route_to` lift leaves `provider_id` empty to mean "resolve
        // from the model", which `validate_providers` accepts. A plan
        // headed into the cascade executor has nothing to dispatch a blank
        // provider to, so `require_known_providers` refuses it.
        let lifted = RoutePlan::from_route_to("gpt-4o-mini");
        assert!(lifted.validate_providers(&["openai".to_owned()]).is_ok());
        assert_eq!(
            lifted.require_known_providers(&["openai".to_owned()]),
            Err(RouteEventError::MissingProvider { index: 0 })
        );

        // A named-but-unconfigured provider is refused by both.
        let RouteDecision::Plan(ghost) = decode_route_plan(&json!({
            "candidates": [{"provider_id": "ghost", "model": "m"}],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(
            ghost.require_known_providers(&["openai".to_owned()]),
            Err(RouteEventError::UnknownProvider {
                provider_id: "ghost".to_owned(),
            })
        );

        // A fully configured plan passes.
        let RouteDecision::Plan(ok) = decode_route_plan(&json!({
            "candidates": [{"provider_id": "openai", "model": "m"}],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert!(ok.require_known_providers(&["openai".to_owned()]).is_ok());
    }

    #[test]
    fn retain_known_providers_keeps_order_and_returns_the_dropped_ids() {
        // WOR-2366 D6: dead tiers drop, survivors run, and the caller
        // gets the dropped ids in plan order so its warning reads the
        // way the operator wrote the plan.
        let RouteDecision::Plan(mut plan) = decode_route_plan(&json!({
            "candidates": [
                {"provider_id": "ghost", "model": "m1"},
                {"provider_id": "openai", "model": "m2"},
                {"provider_id": "phantom", "model": "m3"},
                {"provider_id": "anthropic", "model": "m4"},
            ],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        let dropped = plan.retain_known_providers(&["openai".to_owned(), "anthropic".to_owned()]);
        assert_eq!(dropped, vec!["ghost".to_owned(), "phantom".to_owned()]);
        let survivors: Vec<_> = plan
            .candidates
            .iter()
            .map(|c| c.provider_id.as_str())
            .collect();
        assert_eq!(survivors, ["openai", "anthropic"]);
        assert_eq!(
            plan.candidates
                .iter()
                .map(|c| c.model.as_str())
                .collect::<Vec<_>>(),
            ["m2", "m4"],
            "each survivor keeps its own model"
        );
    }

    #[test]
    fn retaining_against_no_match_leaves_an_empty_plan() {
        // Nothing survives: the plan empties and every id comes back, so
        // the caller can take its error path naming all of them.
        let RouteDecision::Plan(mut plan) = decode_route_plan(&json!({
            "candidates": [
                {"provider_id": "ghost", "model": "m1"},
                {"provider_id": "phantom", "model": "m2"},
            ],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        let dropped = plan.retain_known_providers(&["openai".to_owned()]);
        assert_eq!(dropped, vec!["ghost".to_owned(), "phantom".to_owned()]);
        assert!(plan.candidates.is_empty());
        assert!(plan.primary().is_none());
    }
}
