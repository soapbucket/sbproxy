//! Named model groups: one public model name over several deployments.
//!
//! A `model_groups:` entry binds one name callers send as `model` to a
//! list of members, each naming a provider on the same action and the
//! upstream model id that provider serves. The group carries its own
//! routing strategy and its members carry their own weights, so a group
//! load-balances independently of the action's `routing:`.
//!
//! A group resolves on the dispatch path at the same seam a
//! [`crate::model_alias`] entry does, before every model gate and before
//! provider selection. That ordering is what makes members with
//! different upstream model ids safe: `blocked_models`, the credential's
//! allowlist, the per-model rate limiter, the budget scope, and the
//! price ceiling all judge the member's real model id, never the group
//! name.
//!
//! Groups differ from the same-model-name pool an operator can already
//! build by declaring one model in several providers' `models:` lists.
//! That pool fronts one model id and inherits the action's strategy. A
//! group fronts a mix of model ids and picks among them with a strategy
//! of its own.
//!
//! Groups do not chain: a member's `model` is an upstream model id and
//! is never looked up again as a group or an alias.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::ids::{ModelId, ProviderName};
use crate::model_alias::ModelAlias;
use crate::provider::ProviderConfig;
use crate::routing::RoutingStrategy;

/// A public model name served by several deployments.
///
/// Callers address the group's `name` in the request's `model` field and
/// never see which member served it. The group resolves before every
/// gate, exactly as a model alias does, so `blocked_models`, the virtual
/// key's allowlist, the per-model rate limiter, and the budget scope all
/// judge the member's real model id and not the group name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelGroup {
    /// The name callers send as `model`.
    ///
    /// Must not collide with a model a provider declares in `models:`, a
    /// `model_map` key, a `default_model`, or a `model_aliases` entry: a
    /// group that shadows a real name would silently rewrite every
    /// request asking for it.
    pub name: ModelId,
    /// Strategy used to pick among this group's members, independent of
    /// the action's own `routing:`.
    ///
    /// Accepts the selection strategies: `round_robin`, `weighted`,
    /// `fallback_chain`, `random`, `lowest_latency`, `peak_ewma`,
    /// `least_connections`, `cost_optimized`, `least_token_usage`,
    /// `sticky`, `outcome_aware`, `headroom`, and `reset_aware`.
    /// `cascade`, `cost_quality`, `race`, `semantic_route`,
    /// `prefix_affinity`, and `token_rate` are refused at config load:
    /// each of those runs through its own action-level dispatch path
    /// that a per-group pick never reaches, so a group naming one would
    /// quietly get a plain rotation instead. Set those on the action.
    ///
    /// Defaults to `round_robin`.
    #[serde(
        default = "default_group_strategy",
        deserialize_with = "crate::handler::deserialize_routing"
    )]
    pub routing: RoutingStrategy,
    /// The group's deployments, in declared order.
    ///
    /// At least one is required, and no two may name the same provider:
    /// a member is addressed by the provider that serves it, so two
    /// members on one provider would be indistinguishable to the pick.
    /// Declare a second provider entry for a second deployment.
    pub members: Vec<GroupMember>,
}

impl ModelGroup {
    /// The group's routing strategy as the same snake_case name the
    /// load balancer's `strategy` telemetry label uses, for the
    /// read-only group listing.
    #[must_use]
    pub fn routing_name(&self) -> &'static str {
        crate::routing::strategy_name(&self.routing)
    }
}

/// One deployment inside a [`ModelGroup`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    /// Name of a provider configured on this action.
    pub provider: ProviderName,
    /// Upstream model id this member serves.
    ///
    /// Sent verbatim in place of the group name, so members may serve
    /// different model ids: one group can front an Azure deployment name
    /// and an OpenAI model id at once.
    pub model: ModelId,
    /// Share of traffic under `routing: weighted`, relative to the other
    /// members. Ignored by every other strategy.
    ///
    /// Defaults to 1. A weighted group whose members all weigh 0 is
    /// refused at config load, because a zero total collapses the split
    /// onto the first member without saying so.
    #[serde(default = "default_member_weight")]
    pub weight: u32,
}

fn default_group_strategy() -> RoutingStrategy {
    RoutingStrategy::RoundRobin
}

const fn default_member_weight() -> u32 {
    1
}

/// Registry of an origin's model groups, built once per config load.
///
/// Immutable after construction, so the dispatch path shares one
/// instance across requests and resolution is a single map lookup.
#[derive(Debug, Default)]
pub struct ModelGroupRegistry {
    groups: HashMap<String, ModelGroup>,
}

impl ModelGroupRegistry {
    /// Build a registry from the configured group list.
    ///
    /// [`validate_model_groups`] has already rejected duplicate names at
    /// config load, so the last entry winning here is unreachable rather
    /// than a documented rule.
    pub fn from_config(groups: Vec<ModelGroup>) -> Self {
        let groups = groups
            .into_iter()
            .map(|group| (group.name.as_str().to_string(), group))
            .collect();
        Self { groups }
    }

    /// Whether this origin configured no groups at all.
    ///
    /// The dispatch path checks this before touching the request body so
    /// an origin without groups pays nothing for the feature.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Resolve a requested model name to its group.
    ///
    /// Returns `None` when the name is not a group, which the caller
    /// treats as an alias or a literal model id.
    pub fn resolve(&self, name: &str) -> Option<&ModelGroup> {
        self.groups.get(name)
    }

    /// Every configured group, in name order, for the read-only
    /// management listings.
    pub fn groups(&self) -> impl Iterator<Item = &ModelGroup> {
        let mut names: Vec<&String> = self.groups.keys().collect();
        names.sort_unstable();
        names.into_iter().filter_map(|name| self.groups.get(name))
    }
}

/// Why a routing strategy cannot be scoped to one group, or `None` when
/// it can.
///
/// The refused six are not unresolvable: every strategy has an arm in
/// the router's shared candidate pick. They are refused because each one
/// carries a *second* dispatch branch at the action level, keyed off the
/// action's own router (the cascade tier walk, the cost/quality prompt
/// score, the race fan-out, the semantic embedding pass, the prefix
/// digest). A group naming one of those would reach only the shared
/// pick, which is a deterministic rotation and not the strategy the
/// operator wrote. `token_rate` is refused origin-wide already.
#[must_use]
fn group_strategy_refusal(strategy: &RoutingStrategy) -> Option<&'static str> {
    match strategy {
        RoutingStrategy::Cascade(_) => Some("cascade"),
        RoutingStrategy::CostQuality(_) => Some("cost_quality"),
        RoutingStrategy::Race => Some("race"),
        RoutingStrategy::SemanticRoute(_) => Some("semantic_route"),
        RoutingStrategy::PrefixAffinity(_) => Some("prefix_affinity"),
        RoutingStrategy::TokenRate => Some("token_rate"),
        _ => None,
    }
}

/// Validate an origin's group list against its providers and aliases at
/// config load.
///
/// The checks that matter operationally are the shadowing ones. A group
/// that reuses a name a provider already serves, or a name an alias
/// already binds, silently rewrites every request that asks for the real
/// thing, and nothing downstream can tell that happened. Refusing the
/// config is the only point where an operator still sees it.
///
/// # Errors
///
/// Returns the human-readable reason the group list was rejected.
pub fn validate_model_groups(
    groups: &[ModelGroup],
    providers: &[ProviderConfig],
    aliases: &[ModelAlias],
) -> Result<(), String> {
    let mut names: HashSet<&str> = HashSet::new();
    for (index, group) in groups.iter().enumerate() {
        let name = group.name.as_str();
        if name.trim().is_empty() {
            return Err(format!("model_groups[{index}]: name must not be empty"));
        }
        if name.trim() != name {
            return Err(format!(
                "model_groups[{index}]: name {name:?} has leading or trailing whitespace, \
                 which no caller can send"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "model_groups[{index}]: name {name:?} is configured more than once"
            ));
        }
    }

    for (index, group) in groups.iter().enumerate() {
        let name = group.name.as_str();

        if let Some(strategy) = group_strategy_refusal(&group.routing) {
            return Err(format!(
                "model_groups[{index}] ({name:?}): routing {strategy:?} cannot be scoped to one \
                 group. It dispatches through its own action-level path, so a group naming it \
                 would silently get a plain rotation instead. Set `routing: {strategy}` on the \
                 action and give the group one of the selection strategies."
            ));
        }

        for provider in providers {
            if provider.models.iter().any(|model| model.as_str() == name) {
                return Err(format!(
                    "model_groups[{index}]: name {name:?} shadows a model provider {:?} serves. \
                     Every request asking for the real {name:?} would be spread across the \
                     group instead; rename the group.",
                    provider.name.as_str()
                ));
            }
            if provider.model_map.contains_key(name) {
                return Err(format!(
                    "model_groups[{index}]: name {name:?} shadows a model_map entry on provider \
                     {:?}, which would never be reached. Keep one of the two.",
                    provider.name.as_str()
                ));
            }
            if provider
                .default_model
                .as_ref()
                .is_some_and(|default| default.as_str() == name)
            {
                return Err(format!(
                    "model_groups[{index}]: name {name:?} shadows provider {:?}'s \
                     default_model; rename the group.",
                    provider.name.as_str()
                ));
            }
        }
        if aliases.iter().any(|alias| alias.alias.as_str() == name) {
            return Err(format!(
                "model_groups[{index}]: name {name:?} is also a model_aliases entry. One name \
                 cannot be both a group and an alias; keep one of the two."
            ));
        }
        // An alias pointing at a group would be a two-step resolution,
        // and aliases resolve in one pass by design (see
        // `validate_model_aliases`, which refuses an alias whose target
        // is another alias for the same reason). Left accepted, the
        // alias would rewrite the caller's name to the group name and
        // then send the group name upstream as a literal model id.
        if let Some(alias) = aliases.iter().find(|alias| alias.model_id.as_str() == name) {
            return Err(format!(
                "model_groups[{index}]: model_alias {:?} resolves to {name:?}, which is a model \
                 group. Aliases resolve in one pass, so the group would never be looked up; \
                 point the alias at an upstream model id, or delete it and let callers address \
                 the group directly.",
                alias.alias.as_str()
            ));
        }

        if group.members.is_empty() {
            return Err(format!(
                "model_groups[{index}] ({name:?}): members must not be empty; a group with no \
                 members would refuse every request that names it"
            ));
        }

        let mut member_providers: HashSet<&str> = HashSet::new();
        for (member_index, member) in group.members.iter().enumerate() {
            let provider_name = member.provider.as_str();
            let model = member.model.as_str();
            if model.trim().is_empty() {
                return Err(format!(
                    "model_groups[{index}] ({name:?}).members[{member_index}]: model must not \
                     be empty"
                ));
            }
            if !member_providers.insert(provider_name) {
                return Err(format!(
                    "model_groups[{index}] ({name:?}).members[{member_index}]: provider \
                     {provider_name:?} is already a member of this group. A member is addressed \
                     by the provider that serves it, so two members on one provider cannot be \
                     told apart; declare a second provider entry for the second deployment."
                ));
            }
            let Some(provider) = providers
                .iter()
                .find(|provider| provider.name.as_str() == provider_name)
            else {
                return Err(format!(
                    "model_groups[{index}] ({name:?}).members[{member_index}]: provider \
                     {provider_name:?} is not configured on this origin"
                ));
            };
            // An empty `models:` list defers to the upstream catalog and
            // accepts anything, so there is nothing to check against. A
            // populated one is a claim about what the provider serves,
            // and a member outside it dispatches a request the upstream
            // rejects.
            let serves = provider.models.is_empty()
                || provider.models.iter().any(|known| known.as_str() == model)
                || provider.model_map.contains_key(model);
            if !serves {
                return Err(format!(
                    "model_groups[{index}] ({name:?}).members[{member_index}]: provider \
                     {provider_name:?} does not serve {model:?}. Add it to that provider's \
                     models: list, or point the member at a provider that serves it."
                ));
            }
        }

        if matches!(group.routing, RoutingStrategy::Weighted) {
            let total: u64 = group.members.iter().map(|m| u64::from(m.weight)).sum();
            if total == 0 {
                return Err(format!(
                    "model_groups[{index}] ({name:?}): every member weighs 0 under \
                     `routing: weighted`, which would send all traffic to the first member \
                     without saying so. Give at least one member a non-zero weight."
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, models: &[&str]) -> ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "api_key": "test-key",
            "models": models,
        }))
        .expect("provider fixture")
    }

    fn member(provider: &str, model: &str, weight: u32) -> GroupMember {
        GroupMember {
            provider: provider.into(),
            model: model.into(),
            weight,
        }
    }

    fn group(name: &str, routing: RoutingStrategy, members: Vec<GroupMember>) -> ModelGroup {
        ModelGroup {
            name: name.into(),
            routing,
            members,
        }
    }

    fn two_providers() -> Vec<ProviderConfig> {
        vec![
            provider("openai-a", &["gpt-4o-mini"]),
            provider("azure-b", &["gpt-4o-mini-deployment"]),
        ]
    }

    fn pool() -> ModelGroup {
        group(
            "pool",
            RoutingStrategy::Weighted,
            vec![
                member("openai-a", "gpt-4o-mini", 9),
                member("azure-b", "gpt-4o-mini-deployment", 1),
            ],
        )
    }

    #[test]
    fn a_plain_group_validates_and_resolves() {
        assert_eq!(
            validate_model_groups(&[pool()], &two_providers(), &[]),
            Ok(())
        );
        let registry = ModelGroupRegistry::from_config(vec![pool()]);
        assert!(!registry.is_empty());
        let resolved = registry.resolve("pool").expect("group resolves");
        assert_eq!(resolved.members.len(), 2);
        assert_eq!(resolved.members[0].model, "gpt-4o-mini");
        assert!(registry.resolve("gpt-4o-mini").is_none());
    }

    #[test]
    fn members_may_serve_different_model_ids() {
        // The whole point of the abstraction: the two members do not
        // share a model id, which is what the same-model-name pool
        // cannot express.
        let validated = validate_model_groups(&[pool()], &two_providers(), &[]);
        assert_eq!(validated, Ok(()));
        assert_ne!(pool().members[0].model, pool().members[1].model);
    }

    #[test]
    fn a_group_naming_cascade_is_refused() {
        let cascade = crate::routing::RoutingStrategy::Cascade(crate::routing::CascadeConfig {
            tiers: vec![crate::routing::CascadeTier {
                provider_id: "openai-a".to_string(),
                model: "gpt-4o-mini".to_string(),
                quality_threshold: 0.5,
                cost_cap: None,
            }],
            max_total_cost: None,
        });
        let groups = vec![group(
            "pool",
            cascade,
            vec![member("openai-a", "gpt-4o-mini", 1)],
        )];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("cascade is refused per group");
        assert!(
            error.contains("pool") && error.contains("cascade"),
            "{error}"
        );
        assert!(error.contains("action-level path"), "{error}");
    }

    #[test]
    fn every_action_only_strategy_is_refused_and_every_other_one_is_accepted() {
        // The refusal list is the claim this test defends: exactly six
        // strategies carry an action-level dispatch branch a per-group
        // pick never reaches. A seventh added to the router without a
        // decision here would silently degrade to a rotation.
        for name in [
            "round_robin",
            "weighted",
            "fallback_chain",
            "random",
            "lowest_latency",
            "peak_ewma",
            "least_connections",
            "cost_optimized",
            "least_token_usage",
            "sticky",
            "outcome_aware",
            "headroom",
            "reset_aware",
        ] {
            let strategy: RoutingStrategy = serde_json::from_value(serde_json::json!(name))
                .unwrap_or_else(|error| panic!("{name} parses: {error}"));
            assert!(
                group_strategy_refusal(&strategy).is_none(),
                "{name} must be accepted per group"
            );
        }
        for name in ["race", "token_rate", "prefix_affinity"] {
            let strategy: RoutingStrategy = serde_json::from_value(serde_json::json!(name))
                .unwrap_or_else(|error| panic!("{name} parses: {error}"));
            assert_eq!(
                group_strategy_refusal(&strategy),
                Some(name),
                "{name} must be refused per group"
            );
        }
    }

    #[test]
    fn a_group_shadowing_a_served_model_is_refused() {
        let groups = vec![group(
            "gpt-4o-mini",
            RoutingStrategy::RoundRobin,
            vec![member("openai-a", "gpt-4o-mini", 1)],
        )];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("shadowing a served model is refused");
        assert!(error.contains("shadows a model provider"), "{error}");
    }

    #[test]
    fn a_group_shadowing_a_model_map_key_is_refused() {
        let mut openai = provider("openai-a", &["gpt-4o-mini"]);
        openai.model_map.insert("pool".into(), "gpt-4o-mini".into());
        let error = validate_model_groups(&[pool()], &[openai, provider("azure-b", &[])], &[])
            .expect_err("shadowing a model_map key is refused");
        assert!(error.contains("shadows a model_map entry"), "{error}");
    }

    #[test]
    fn a_group_shadowing_a_default_model_is_refused() {
        let mut openai = provider("openai-a", &["gpt-4o-mini"]);
        openai.default_model = Some("pool".into());
        let error = validate_model_groups(&[pool()], &[openai, provider("azure-b", &[])], &[])
            .expect_err("shadowing a default_model is refused");
        assert!(error.contains("default_model"), "{error}");
    }

    #[test]
    fn a_group_that_shadows_an_alias_is_refused() {
        let alias: ModelAlias = serde_json::from_value(serde_json::json!({
            "alias": "pool",
            "model_id": "gpt-4o-mini",
        }))
        .expect("alias fixture");
        let error = validate_model_groups(&[pool()], &two_providers(), &[alias])
            .expect_err("a group that shadows an alias is refused");
        assert!(error.contains("also a model_aliases entry"), "{error}");
    }

    #[test]
    fn an_alias_that_resolves_to_a_group_is_refused() {
        let alias: ModelAlias = serde_json::from_value(serde_json::json!({
            "alias": "fast",
            "model_id": "pool",
        }))
        .expect("alias fixture");
        let error = validate_model_groups(&[pool()], &two_providers(), &[alias])
            .expect_err("an alias pointing at a group is refused");
        assert!(error.contains("resolve in one pass"), "{error}");
    }

    #[test]
    fn a_duplicate_group_name_is_refused() {
        let error = validate_model_groups(&[pool(), pool()], &two_providers(), &[])
            .expect_err("a duplicate group name is refused");
        assert!(error.contains("configured more than once"), "{error}");
    }

    #[test]
    fn an_empty_member_list_is_refused() {
        let groups = vec![group("pool", RoutingStrategy::RoundRobin, Vec::new())];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("an empty group is refused");
        assert!(error.contains("members must not be empty"), "{error}");
    }

    #[test]
    fn a_member_at_an_unconfigured_provider_is_refused() {
        let groups = vec![group(
            "pool",
            RoutingStrategy::RoundRobin,
            vec![member("openai-typo", "gpt-4o-mini", 1)],
        )];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("a member at an unconfigured provider is refused");
        assert!(
            error.contains("is not configured on this origin"),
            "{error}"
        );
    }

    #[test]
    fn a_member_the_provider_does_not_serve_is_refused() {
        let groups = vec![group(
            "pool",
            RoutingStrategy::RoundRobin,
            vec![member("azure-b", "gpt-4o-mini", 1)],
        )];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("a member outside the provider's models: list is refused");
        assert!(error.contains("does not serve"), "{error}");
    }

    #[test]
    fn a_provider_named_twice_in_one_group_is_refused() {
        // Two members on one provider are indistinguishable to the pick,
        // which selects a provider index, so the second member's weight
        // and model id would be unreachable.
        let mut openai = provider("openai-a", &["gpt-4o-mini", "gpt-4o"]);
        openai.models.push("gpt-4o".into());
        let groups = vec![group(
            "pool",
            RoutingStrategy::RoundRobin,
            vec![
                member("openai-a", "gpt-4o-mini", 1),
                member("openai-a", "gpt-4o", 1),
            ],
        )];
        let error = validate_model_groups(&groups, &[openai], &[])
            .expect_err("two members on one provider are refused");
        assert!(error.contains("already a member of this group"), "{error}");
    }

    #[test]
    fn an_all_zero_weighted_group_is_refused() {
        let groups = vec![group(
            "pool",
            RoutingStrategy::Weighted,
            vec![
                member("openai-a", "gpt-4o-mini", 0),
                member("azure-b", "gpt-4o-mini-deployment", 0),
            ],
        )];
        let error = validate_model_groups(&groups, &two_providers(), &[])
            .expect_err("an all-zero weighted group is refused");
        assert!(error.contains("weighs 0"), "{error}");

        // Zero weights are only a bug under `weighted`: every other
        // strategy ignores the field, so refusing there would reject a
        // config that behaves exactly as written.
        let rotating = vec![group(
            "pool",
            RoutingStrategy::RoundRobin,
            vec![
                member("openai-a", "gpt-4o-mini", 0),
                member("azure-b", "gpt-4o-mini-deployment", 0),
            ],
        )];
        assert_eq!(
            validate_model_groups(&rotating, &two_providers(), &[]),
            Ok(())
        );
    }

    #[test]
    fn a_member_weight_defaults_to_one_and_unknown_fields_are_refused() {
        let parsed: ModelGroup = serde_json::from_value(serde_json::json!({
            "name": "pool",
            "members": [{"provider": "openai-a", "model": "gpt-4o-mini"}],
        }))
        .expect("a group with defaults parses");
        assert_eq!(parsed.members[0].weight, 1);
        assert!(matches!(parsed.routing, RoutingStrategy::RoundRobin));

        let error = serde_json::from_value::<ModelGroup>(serde_json::json!({
            "name": "pool",
            "members": [{"provider": "openai-a", "model_id": "gpt-4o-mini"}],
        }))
        .expect_err("a misspelled member key is refused");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}
