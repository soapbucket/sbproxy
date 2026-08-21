//! Provider eligibility by declared data-handling posture (WOR-2557).
//!
//! Every catalog entry in `data/ai_providers.yml` declares a
//! [`crate::providers::CatalogDataPosture`]: whether the vendor's API retains prompt data
//! under its published data-processing terms, and whether the vendor
//! offers a zero-data-retention (ZDR) arrangement at all. An origin (or
//! a single request, via header) can then constrain the routing
//! candidate set to providers that satisfy a posture requirement,
//! before any [`crate::routing::RoutingStrategy`] sees the set. A
//! request whose constraint excludes every configured provider fails
//! closed with an error naming the constraint and the excluded
//! providers, never silently rerouting to a non-compliant upstream.
//!
//! The shape follows OpenRouter's `provider.zdr` / `data_collection`
//! routing filters: an eligibility gate over provider metadata, not a
//! spend control. Like the catalog itself, the posture fields record
//! what each vendor's published terms say, not the result of auditing
//! an account; an operator whose own agreement differs overrides the
//! declaration per provider entry (`data_posture:` on the provider
//! config) or ships a custom catalog via `proxy.ai_providers_file`.

use serde::Deserialize;

use crate::provider::ProviderConfig;
use crate::providers::get_provider_info;

fn default_true() -> bool {
    true
}

/// Origin-level posture requirement: the `data_posture:` block of an
/// `ai_proxy` action.
///
/// Both fields compose with the per-request headers
/// `x-sbproxy-require-zdr` and `x-sbproxy-disallow-data-collection`;
/// the most restrictive union wins, mirroring how OpenRouter ORs a
/// request's `provider.zdr` with the account-wide ZDR policy.
// The action block and the provider-entry block are both spelled
// `data_posture:` and their fields are disjoint, so the two are easy to
// confuse in either direction. Unknown keys are refused rather than
// ignored: `data_posture: {zdr: true}` written at the action level
// would otherwise parse clean, constrain nothing, and boot green while
// prompts kept flowing to retaining providers, which is the exact
// fail-open this control exists to prevent. Only the provider block is
// in the generated JSON schema; the action body is free-form there, so
// serde is the only thing that can catch it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPostureRequirement {
    /// Route only to providers whose effective posture declares a
    /// zero-data-retention arrangement (`zdr_available` in the catalog,
    /// or an operator `data_posture.zdr` declaration on the provider
    /// entry). Defaults to `false`.
    #[serde(default)]
    pub require_zdr: bool,
    /// When `false`, providers whose effective posture declares
    /// `retains_data: true` are ineligible. Defaults to `true`
    /// (retaining providers stay eligible).
    #[serde(default = "default_true")]
    pub allow_data_collection: bool,
}

impl Default for DataPostureRequirement {
    fn default() -> Self {
        Self {
            require_zdr: false,
            allow_data_collection: true,
        }
    }
}

/// Operator posture declaration on one provider entry, overriding the
/// catalog's per-vendor default.
///
/// The catalog records what a vendor's published terms say about a
/// stock account. A specific deployment can differ in both directions:
/// an operator with a signed ZDR agreement declares `zdr: true` on
/// their entry; an operator pointing an `openai`-typed entry at a
/// retaining third-party endpoint declares `retains_data: true`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataPostureOverride {
    /// Override the catalog's `retains_data` declaration for this
    /// entry. Unset keeps the catalog value, except that setting
    /// `zdr: true` alone implies `false`.
    #[serde(default)]
    pub retains_data: Option<bool>,
    /// Declare that this deployment operates under a zero-data-retention
    /// arrangement with the vendor. This is what makes a provider whose
    /// stock terms retain prompt data eligible for `require_zdr`; the
    /// catalog's `zdr_available` records only that the vendor sells such
    /// an arrangement, never that you hold one. Unset falls back to the
    /// catalog's retention declaration (a vendor that stores nothing on a
    /// stock account is zero data retention as it stands).
    #[serde(default)]
    pub zdr: Option<bool>,
}

/// The resolved posture of one configured provider, after the
/// catalog declaration, the operator override, and the local-serving
/// special case are composed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveDataPosture {
    /// Whether prompt data sent to this provider is retained.
    pub retains_data: bool,
    /// Whether this provider destination counts as zero-data-retention.
    pub zdr: bool,
}

/// Resolve the effective posture of a configured provider.
///
/// Resolution order:
///
/// 1. A locally served (`serve:`) or SBproxy-managed (`managed_model`)
///    provider never sends the prompt off this deployment, so it is
///    zero-data-retention by construction.
/// 2. The provider catalog entry for
///    [`ProviderConfig::effective_provider_type`] supplies the vendor
///    default. Its `retains_data` carries straight through, and a stock
///    account the vendor's published terms say does not retain prompt
///    data *is* zero data retention, so `zdr` is `!retains_data`.
///
///    The catalog's `zdr_available` is deliberately **not** consulted
///    here. It records that the vendor sells a zero-data-retention
///    arrangement to somebody, not that this deployment holds one:
///    OpenAI, Anthropic, Azure, and Vertex all offer one and all retain
///    by default. Reading "the vendor offers ZDR" as "we have ZDR" would
///    make `require_zdr` pass for a stock retaining account, which is the
///    exact misroute this filter exists to prevent. `zdr_available` is
///    what an operator reads to know an agreement is available to go and
///    sign (it is reported by `GET /admin/ai-data-posture` and listed in
///    docs/providers.md); holding one is the operator's declaration,
///    made in step 4.
/// 3. A provider type with no catalog entry is pessimistic:
///    `retains_data: true, zdr: false`, matching the catalog's own
///    default for an entry that declares nothing.
/// 4. The operator's `data_posture:` override on the provider entry
///    wins over all of the above, field by field. Declaring
///    `zdr: true` implies `retains_data: false` unless `retains_data`
///    is itself overridden.
pub fn effective_data_posture(provider: &ProviderConfig) -> EffectiveDataPosture {
    let base = if provider.serve.is_some() || provider.is_managed_model() {
        EffectiveDataPosture {
            retains_data: false,
            zdr: true,
        }
    } else {
        match get_provider_info(provider.effective_provider_type()) {
            Some(info) => EffectiveDataPosture {
                retains_data: info.data_posture.retains_data,
                zdr: !info.data_posture.retains_data,
            },
            None => EffectiveDataPosture {
                retains_data: true,
                zdr: false,
            },
        }
    };
    let Some(overrides) = provider.data_posture.as_ref() else {
        return base;
    };
    // The two declarations imply each other, and they have to imply it
    // the same way in both layers. The catalog layer above derives
    // `zdr` as `!retains_data`; an override that says `retains_data:
    // false` and nothing else has therefore declared a destination that
    // stores nothing, which is a zero-data-retention posture by the
    // same reading. Deriving it here only from an explicit `zdr:` left
    // the two layers disagreeing, so an operator following the
    // blackhole refusal's own advice (`data_posture.retains_data:
    // false`) was refused again with the identical message.
    let zdr = overrides.zdr.unwrap_or(match overrides.retains_data {
        Some(false) => true,
        Some(true) => false,
        None => base.zdr,
    });
    let retains_data = overrides.retains_data.unwrap_or(match overrides.zdr {
        Some(true) => false,
        _ => base.retains_data,
    });
    EffectiveDataPosture { retains_data, zdr }
}

/// The active posture constraint of one request: the union of the
/// origin's [`DataPostureRequirement`] and the per-request headers.
///
/// Constructed through [`DataPostureConstraint::from_parts`], which
/// returns `None` when nothing constrains the request, so an
/// unconstrained request never pays for (or observes) the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPostureConstraint {
    /// Providers must have an effective zero-data-retention posture.
    pub require_zdr: bool,
    /// Providers with an effective `retains_data: true` posture are
    /// ineligible.
    pub deny_data_collection: bool,
}

impl DataPostureConstraint {
    /// Compose the origin block and the request headers into the
    /// active constraint. Returns `None` when neither constrains
    /// anything, which is the byte-for-byte-unchanged fast path.
    pub fn from_parts(
        origin: Option<&DataPostureRequirement>,
        header_require_zdr: bool,
        header_disallow_data_collection: bool,
    ) -> Option<Self> {
        let require_zdr = header_require_zdr || origin.is_some_and(|block| block.require_zdr);
        let deny_data_collection = header_disallow_data_collection
            || origin.is_some_and(|block| !block.allow_data_collection);
        (require_zdr || deny_data_collection).then_some(Self {
            require_zdr,
            deny_data_collection,
        })
    }

    /// Whether one configured provider satisfies this constraint.
    pub fn provider_eligible(&self, provider: &ProviderConfig) -> bool {
        let posture = effective_data_posture(provider);
        (!self.require_zdr || posture.zdr) && (!self.deny_data_collection || !posture.retains_data)
    }

    /// Bounded-cardinality label for the exclusion metric.
    pub fn label(&self) -> &'static str {
        match (self.require_zdr, self.deny_data_collection) {
            (true, true) => "require_zdr+deny_data_collection",
            (true, false) => "require_zdr",
            (false, true) => "deny_data_collection",
            (false, false) => "none",
        }
    }

    /// Human-readable name of the constraint, in config spelling, for
    /// refusal messages and the routing-trace detail field.
    pub fn describe(&self) -> String {
        match (self.require_zdr, self.deny_data_collection) {
            (true, true) => "require_zdr, allow_data_collection: false".to_string(),
            (true, false) => "require_zdr".to_string(),
            (false, true) => "allow_data_collection: false".to_string(),
            (false, false) => "unconstrained".to_string(),
        }
    }
}

/// Names of the enabled providers `constraint` excludes, in config
/// declaration order.
pub fn posture_excluded_provider_names(
    constraint: &DataPostureConstraint,
    providers: &[ProviderConfig],
) -> Vec<String> {
    providers
        .iter()
        .filter(|provider| provider.enabled && !constraint.provider_eligible(provider))
        .map(|provider| provider.name.to_string())
        .collect()
}

/// Upper bound on provider names spelled out in one refusal message or
/// log line. Past this the message carries a count instead, so a large
/// catalog cannot balloon an error body or a SIEM record.
pub const MAX_NAMED_EXCLUSIONS: usize = 8;

/// Render a bounded, comma-separated list of excluded provider names.
pub fn bounded_exclusion_list(excluded: &[String]) -> String {
    if excluded.len() <= MAX_NAMED_EXCLUSIONS {
        return excluded.join(", ");
    }
    format!(
        "{} (and {} more)",
        excluded[..MAX_NAMED_EXCLUSIONS].join(", "),
        excluded.len() - MAX_NAMED_EXCLUSIONS
    )
}

/// The fail-closed refusal body text: names the constraint and the
/// providers it excluded, bounded by [`MAX_NAMED_EXCLUSIONS`].
pub fn posture_refusal_message(constraint: &DataPostureConstraint, excluded: &[String]) -> String {
    format!(
        "no eligible provider under the data-handling posture constraint ({}); \
         excluded by posture: {}",
        constraint.describe(),
        bounded_exclusion_list(excluded)
    )
}

/// Refuse at config-compile time a `data_posture:` block that can never
/// route.
///
/// An origin whose own posture requirement excludes every enabled
/// provider it configures is not a strict policy, it is a blackholed
/// origin: every request it ever serves is refused, and the operator
/// finds out from production traffic rather than from the config load.
/// The same disposition `routing.strategy: token_rate` and
/// `pii.redact_response: true` get, for the same reason: a knob that
/// boots green and then silently denies everything is worse than a
/// refusal naming the key.
///
/// Only the origin block is judged here. The per-request headers
/// (`x-sbproxy-require-zdr`,
/// `x-sbproxy-disallow-data-collection`) tighten one request at a
/// time and are not knowable at load, so a header that empties the
/// candidate set stays a runtime fail-closed refusal. A config with no
/// enabled provider at all is a different misconfiguration and is left
/// to the checks that own it.
pub fn validate_posture_requirement(
    requirement: Option<&DataPostureRequirement>,
    providers: &[ProviderConfig],
) -> Result<(), String> {
    let Some(constraint) = DataPostureConstraint::from_parts(requirement, false, false) else {
        return Ok(());
    };
    let enabled = providers.iter().filter(|provider| provider.enabled).count();
    if enabled == 0 {
        return Ok(());
    }
    let excluded = posture_excluded_provider_names(&constraint, providers);
    if excluded.len() < enabled {
        return Ok(());
    }
    Err(format!(
        "`data_posture` ({}) excludes every configured provider ({}), so this origin \
         could never route a request. Declare the posture you hold on a provider entry \
         (`data_posture.zdr: true` for a signed zero-data-retention agreement, or \
         `data_posture.retains_data: false`), add a provider that satisfies the \
         constraint, or relax the block. The provider catalog records what each vendor's \
         published terms say about a stock account, not what your own agreement says. To \
         constrain a single request instead of the whole origin, send \
         `x-sbproxy-require-zdr: true` or `x-sbproxy-disallow-data-collection: true`.",
        constraint.describe(),
        bounded_exclusion_list(&excluded)
    ))
}

/// Whether `constraint` excludes every provider a cascade's tiers name.
///
/// The cascade executor does not route over the candidate order: each
/// tier names its own provider, and a tier whose provider the posture
/// exclusion put on the blocked list is skipped. When *every* tier is
/// skipped the cascade exhausts with a generic dispatch failure, which
/// tells an operator nothing about why. This predicate lets the caller
/// refuse first, with the same typed message the ordinary selection
/// paths use.
pub fn cascade_tiers_all_posture_excluded(
    constraint: &DataPostureConstraint,
    tiers: &[crate::routing::CascadeTier],
    providers: &[ProviderConfig],
) -> bool {
    !tiers.is_empty()
        && !tiers.iter().any(|tier| {
            providers.iter().any(|provider| {
                provider.name == tier.provider_id
                    && provider.enabled
                    && constraint.provider_eligible(provider)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(yaml: &str) -> ProviderConfig {
        serde_yaml::from_str(yaml).expect("provider yaml parses")
    }

    fn constraint(require_zdr: bool, deny: bool) -> DataPostureConstraint {
        DataPostureConstraint {
            require_zdr,
            deny_data_collection: deny,
        }
    }

    #[test]
    fn a_non_retention_override_alone_is_a_zdr_posture() {
        // The blackhole refusal offers `data_posture.retains_data:
        // false` as one of its two remedies, so it has to actually be
        // one: this is the same rule the catalog layer applies.
        let p = provider(
            "{name: self_hosted, provider_type: openai, data_posture: {retains_data: false}}",
        );
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: false,
                zdr: true
            }
        );
        assert!(constraint(true, false).provider_eligible(&p));
    }

    #[test]
    fn an_explicit_retention_override_is_not_zdr() {
        // The other direction of the same rule: an operator pointing an
        // openai-typed entry at a retaining endpoint loses ZDR
        // eligibility even where the catalog would have granted it.
        let p = provider(
            "{name: third_party, provider_type: bedrock, data_posture: {retains_data: true}}",
        );
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: true,
                zdr: false
            }
        );
        assert!(!constraint(true, false).provider_eligible(&p));
    }

    #[test]
    fn the_provider_spelling_of_the_block_is_refused_on_the_action() {
        // `zdr:` belongs on a provider entry, `require_zdr:` on the
        // action. Confusing them must be an error, not a constraint
        // that silently does nothing.
        let err = serde_yaml::from_str::<DataPostureRequirement>("{zdr: true}")
            .expect_err("the provider spelling must not parse as an action block");
        assert!(
            err.to_string().contains("zdr"),
            "the refusal has to name the offending key; got: {err}"
        );
        let err = serde_yaml::from_str::<DataPostureOverride>("{require_zdr: true}")
            .expect_err("the action spelling must not parse as a provider override");
        assert!(
            err.to_string().contains("require_zdr"),
            "the refusal has to name the offending key; got: {err}"
        );
    }

    #[test]
    fn unknown_provider_type_is_pessimistic() {
        let p = provider("{name: mystery, provider_type: not_in_catalog}");
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: true,
                zdr: false
            }
        );
    }

    #[test]
    fn catalog_posture_flows_through_the_effective_provider_type() {
        // Bedrock's catalog entry declares it does not store prompts.
        let p = provider("{name: aws, provider_type: bedrock}");
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: false,
                zdr: true
            }
        );
        // OpenAI's entry declares default retention *and* that a ZDR
        // arrangement is available. Available is not held: a stock entry
        // with no operator declaration is not zero-data-retention, so
        // `require_zdr` must not pass on the catalog flag alone.
        let p = provider("{name: openai}");
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: true,
                zdr: false
            }
        );
        assert!(
            crate::providers::get_provider_info("openai")
                .expect("openai is in the catalog")
                .data_posture
                .zdr_available,
            "the catalog still records that the vendor offers one"
        );
        assert!(
            !constraint(true, false).provider_eligible(&p),
            "a stock retaining account must not satisfy require_zdr"
        );
    }

    #[test]
    fn operator_override_wins_over_the_catalog() {
        // An operator with a signed ZDR agreement flips the entry, and
        // `zdr: true` implies the prompt is not retained.
        let p = provider("{name: openai, data_posture: {zdr: true}}");
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: false,
                zdr: true
            }
        );
        // The implication is only a default: an explicit retains_data
        // declaration stands on its own.
        let p = provider("{name: openai, data_posture: {zdr: true, retains_data: true}}");
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: true,
                zdr: true
            }
        );
        // And the pessimistic direction works on a non-retaining entry.
        let p = provider(
            "{name: aws, provider_type: bedrock, data_posture: {retains_data: true, zdr: false}}",
        );
        assert_eq!(
            effective_data_posture(&p),
            EffectiveDataPosture {
                retains_data: true,
                zdr: false
            }
        );
    }

    #[test]
    fn constraint_composes_origin_and_headers_most_restrictive_wins() {
        assert_eq!(DataPostureConstraint::from_parts(None, false, false), None);
        let relaxed = DataPostureRequirement::default();
        assert_eq!(
            DataPostureConstraint::from_parts(Some(&relaxed), false, false),
            None,
            "a default block constrains nothing"
        );
        assert_eq!(
            DataPostureConstraint::from_parts(Some(&relaxed), true, false),
            Some(constraint(true, false)),
            "the header tightens past a relaxed origin block"
        );
        let strict = DataPostureRequirement {
            require_zdr: true,
            allow_data_collection: false,
        };
        assert_eq!(
            DataPostureConstraint::from_parts(Some(&strict), false, false),
            Some(constraint(true, true)),
            "headers cannot relax an origin constraint"
        );
    }

    #[test]
    fn eligibility_checks_each_axis_independently() {
        let zdr = provider("{name: a, data_posture: {zdr: true}}");
        let retaining = provider("{name: b, data_posture: {zdr: false, retains_data: true}}");
        let non_retaining_non_zdr =
            provider("{name: c, data_posture: {zdr: false, retains_data: false}}");

        let require_zdr = constraint(true, false);
        assert!(require_zdr.provider_eligible(&zdr));
        assert!(!require_zdr.provider_eligible(&retaining));
        assert!(!require_zdr.provider_eligible(&non_retaining_non_zdr));

        let deny_collection = constraint(false, true);
        assert!(deny_collection.provider_eligible(&zdr));
        assert!(!deny_collection.provider_eligible(&retaining));
        assert!(deny_collection.provider_eligible(&non_retaining_non_zdr));
    }

    #[test]
    fn locally_served_and_managed_providers_are_zdr_by_construction() {
        let managed = provider("{name: local, provider_type: managed_model, deployment: dep-1}");
        assert_eq!(
            effective_data_posture(&managed),
            EffectiveDataPosture {
                retains_data: false,
                zdr: true
            }
        );
        assert!(constraint(true, true).provider_eligible(&managed));
    }

    #[test]
    fn excluded_names_are_enabled_providers_in_declaration_order() {
        let providers = vec![
            provider("{name: a, data_posture: {zdr: true}}"),
            provider("{name: b, data_posture: {zdr: false, retains_data: true}}"),
            provider("{name: c, enabled: false, data_posture: {zdr: false, retains_data: true}}"),
            provider("{name: d, data_posture: {zdr: false, retains_data: true}}"),
        ];
        let excluded = posture_excluded_provider_names(&constraint(true, false), &providers);
        assert_eq!(excluded, vec!["b".to_string(), "d".to_string()]);
    }

    #[test]
    fn config_compile_refuses_a_block_that_excludes_every_provider() {
        let strict = DataPostureRequirement {
            require_zdr: true,
            allow_data_collection: true,
        };
        let providers = vec![
            provider("{name: alpha, data_posture: {zdr: false, retains_data: true}}"),
            provider("{name: beta, data_posture: {zdr: false, retains_data: true}}"),
        ];
        let error = validate_posture_requirement(Some(&strict), &providers)
            .expect_err("a blackholed origin must be refused at config compile");
        assert!(
            error.contains("`data_posture`"),
            "the message must name the key: {error}"
        );
        assert!(
            error.contains("require_zdr") && error.contains("alpha") && error.contains("beta"),
            "the message must name the constraint and the excluded providers: {error}"
        );
    }

    #[test]
    fn config_compile_accepts_a_block_one_provider_satisfies() {
        let strict = DataPostureRequirement {
            require_zdr: true,
            allow_data_collection: false,
        };
        let providers = vec![
            provider("{name: alpha, data_posture: {zdr: false, retains_data: true}}"),
            provider("{name: beta, data_posture: {zdr: true}}"),
        ];
        assert!(validate_posture_requirement(Some(&strict), &providers).is_ok());
    }

    #[test]
    fn config_compile_ignores_a_disabled_provider_and_an_empty_fleet() {
        let strict = DataPostureRequirement {
            require_zdr: true,
            allow_data_collection: true,
        };
        // A disabled provider is not a candidate either way, so an origin
        // whose only *enabled* provider qualifies still compiles.
        let providers = vec![
            provider(
                "{name: alpha, enabled: false, data_posture: {zdr: false, retains_data: true}}",
            ),
            provider("{name: beta, data_posture: {zdr: true}}"),
        ];
        assert!(validate_posture_requirement(Some(&strict), &providers).is_ok());
        // No enabled provider at all is a different misconfiguration and
        // belongs to the checks that own it, not to this one.
        assert!(validate_posture_requirement(Some(&strict), &[]).is_ok());
    }

    #[test]
    fn config_compile_accepts_an_unconstraining_block_and_no_block() {
        let relaxed = DataPostureRequirement::default();
        let providers = vec![provider(
            "{name: alpha, data_posture: {retains_data: true}}",
        )];
        assert!(validate_posture_requirement(Some(&relaxed), &providers).is_ok());
        assert!(validate_posture_requirement(None, &providers).is_ok());
    }

    fn tier(provider_id: &str) -> crate::routing::CascadeTier {
        crate::routing::CascadeTier {
            provider_id: provider_id.to_string(),
            model: "gpt-4o".to_string(),
            quality_threshold: 0.5,
            cost_cap: None,
        }
    }

    #[test]
    fn cascade_tier_partition_sees_past_the_candidate_order() {
        // The cascade executor dispatches by tier name, not over the
        // candidate order, so the partition is asked about the tiers.
        let providers = vec![
            provider("{name: retainer, data_posture: {zdr: false, retains_data: true}}"),
            provider("{name: zdr, data_posture: {zdr: true}}"),
            provider("{name: off, enabled: false, data_posture: {zdr: true}}"),
        ];
        let require_zdr = constraint(true, false);

        assert!(
            cascade_tiers_all_posture_excluded(&require_zdr, &[tier("retainer")], &providers),
            "a tier list naming only excluded providers is fully excluded"
        );
        assert!(
            !cascade_tiers_all_posture_excluded(
                &require_zdr,
                &[tier("retainer"), tier("zdr")],
                &providers
            ),
            "one eligible tier is enough to dispatch"
        );
        assert!(
            cascade_tiers_all_posture_excluded(&require_zdr, &[tier("off")], &providers),
            "a disabled provider is not an eligible tier"
        );
        assert!(
            cascade_tiers_all_posture_excluded(&require_zdr, &[tier("nowhere")], &providers),
            "a tier naming no configured provider is not eligible"
        );
        assert!(
            !cascade_tiers_all_posture_excluded(&require_zdr, &[], &providers),
            "an empty tier list is the cascade's own error, not a posture refusal"
        );
    }

    #[test]
    fn refusal_message_names_the_constraint_and_is_bounded() {
        let excluded: Vec<String> = (0..12).map(|i| format!("p{i}")).collect();
        let message = posture_refusal_message(&constraint(true, true), &excluded);
        assert!(message.contains("require_zdr, allow_data_collection: false"));
        assert!(message.contains("p0"));
        assert!(message.contains("(and 4 more)"));
        assert!(
            !message.contains("p9"),
            "names past the bound must not be spelled out"
        );

        let short = posture_refusal_message(&constraint(false, true), &["only".to_string()]);
        assert!(short.contains("allow_data_collection: false"));
        assert!(short.ends_with("excluded by posture: only"));
    }
}
