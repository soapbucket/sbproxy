// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The route-weight resolver: units the operator priced in advance.
//!
//! An operator says `POST /v1/search` costs five units and every matching
//! call bills five. Nothing is observed and nothing is asked of the origin,
//! so the number is a pure function of the route and the configuration that
//! was live. That is a weaker claim than [`crate::measured`] makes, and a
//! much stronger one than [`crate::origin_header`] makes, and the middle
//! position is why this resolver exists: an operator who wants a flat price
//! per endpoint should not have to teach their upstream to report anything.
//!
//! # Provability comes from the config bundle, for free
//!
//! Because the weight is written down rather than counted, the interesting
//! dispute is never "did you count right". It is "you priced my call under a
//! config I never agreed to". So every unit this resolver produces carries
//! the revision of the document the weight was read from, and a buyer
//! holding the signed config bundle can look the number up themselves. No
//! separate proof mechanism was needed: the config was already signed, and
//! naming the revision is what makes that signature reach the invoice.
//!
//! # A reload must not reprice a call already in flight
//!
//! [`RouteWeightTable`] owns its revision rather than reading one from a
//! global at resolve time, and a table is immutable once built. A pipeline
//! generation builds one table, and a request holds the generation that
//! admitted it until it finishes, so a config swapped in halfway through a
//! response cannot change what that response costs. The alternative, looking
//! the current revision up when the unit is written, produces receipts whose
//! evidence names a document that did not price the call, which is worse
//! than no evidence because it reads as proof.
//!
//! # Absence is not zero here
//!
//! [`crate::measured`] emits a zero for a rule that observed nothing,
//! because a measured rule applies to every request and silence would be
//! indistinguishable from metering having stopped. A route weight is the
//! other case. It applies only to the routes it names, so a request on some
//! other route produces no unit at all, and that is not ambiguous: which
//! routes the rule covers is itself in the config the receipt's
//! `config_revision` points at. Emitting a zero instead would put "this
//! route is free" on the invoice, which is a claim the operator never made.

use crate::event::{Evidence, Unit};
use serde::{Deserialize, Serialize};

/// The suffix that turns a path into a prefix match.
///
/// Written out rather than inlined because both the matcher and the
/// specificity ranking have to agree on it.
const PREFIX_SUFFIX: &str = "/*";

/// One route the operator priced.
///
/// The unit name is deliberately not unique across rules. An operator
/// pricing `search_call` at five for `POST /v1/search` and at one for
/// everything under `/v1/search/` is writing two rules for one invoice line,
/// and [`RouteWeightTable::resolve`] picks the more specific of them rather
/// than billing both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteWeightRule {
    /// Unit name that appears on the invoice line, for example
    /// `search_call`.
    pub name: String,
    /// HTTP method this rule is limited to, or `None` for any method.
    ///
    /// Compared case-insensitively. Methods are case-sensitive in RFC 9110,
    /// but an operator who writes `post` in YAML means `POST`, and refusing
    /// to price their call over the difference would be pedantry that costs
    /// them money.
    pub method: Option<String>,
    /// The path this rule matches.
    ///
    /// Either an exact path (`/v1/search`) or a prefix ending in `/*`
    /// (`/v1/search/*`), which matches everything below that segment and,
    /// deliberately, not the segment itself. `/v1/search/*` and
    /// `/v1/search` are different routes to a router, so treating them as
    /// one here would price a request under a rule the operator did not
    /// write for it.
    pub path: String,
    /// What one matching call costs.
    ///
    /// Zero is allowed and is a real statement: the route is metered and
    /// free. It is not the same as having no rule, which says the route is
    /// not priced by this line at all.
    pub weight: u64,
}

impl RouteWeightRule {
    /// A rule that prices one route.
    pub fn new(
        name: impl Into<String>,
        method: Option<String>,
        path: impl Into<String>,
        weight: u64,
    ) -> Self {
        Self {
            name: name.into(),
            method,
            path: path.into(),
            weight,
        }
    }

    /// How specifically this rule matches, or `None` when it does not.
    ///
    /// The ordering the returned value sorts under is the precedence rule:
    /// a rule that names a method beats one that does not, an exact path
    /// beats a prefix, and a longer prefix beats a shorter one. That is the
    /// order an operator writing these expects, and pinning it here means
    /// the answer does not depend on the order the rules happen to appear
    /// in the file.
    fn specificity(&self, method: &str, path: &str) -> Option<RouteSpecificity> {
        if let Some(required) = self.method.as_deref() {
            if !required.eq_ignore_ascii_case(method) {
                return None;
            }
        }

        match self.path.strip_suffix(PREFIX_SUFFIX) {
            Some(prefix) => {
                // The trailing slash stays in the comparison, so `/v1/a/*`
                // matches `/v1/a/b` and not `/v1/absolute`.
                let with_slash = &self.path[..prefix.len() + 1];
                path.starts_with(with_slash).then_some(RouteSpecificity {
                    method_named: self.method.is_some(),
                    exact_path: false,
                    path_len: with_slash.len(),
                })
            }
            None => (self.path == path).then_some(RouteSpecificity {
                method_named: self.method.is_some(),
                exact_path: true,
                path_len: self.path.len(),
            }),
        }
    }
}

/// How specifically one rule matched, ordered least to most specific.
///
/// Field order is the precedence order: `Ord` is derived, so it compares
/// `method_named` first and `path_len` last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RouteSpecificity {
    method_named: bool,
    exact_path: bool,
    path_len: usize,
}

/// Every route weight one pipeline generation declared, bound to the
/// revision of the document that declared them.
///
/// The revision lives on the table rather than being supplied per call, and
/// that is the whole design. A table and a revision that travel separately
/// can be paired wrongly by any caller who has both in scope, and the
/// pairing that gets it wrong (current revision, older weights) produces a
/// receipt that looks like proof and is not. Here there is nothing to pair:
/// building a table is the only way to get one, and it takes the revision
/// then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteWeightTable {
    config_revision: String,
    rules: Vec<RouteWeightRule>,
}

impl RouteWeightTable {
    /// Bind a set of rules to the config revision they were read from.
    pub fn new(config_revision: impl Into<String>, rules: Vec<RouteWeightRule>) -> Self {
        Self {
            config_revision: config_revision.into(),
            rules,
        }
    }

    /// An empty table bound to a revision.
    ///
    /// What a deployment that declared an attestation role and no route
    /// weights gets. Empty rather than absent so the request path has one
    /// shape to handle.
    pub fn empty(config_revision: impl Into<String>) -> Self {
        Self::new(config_revision, Vec::new())
    }

    /// The revision every unit from this table cites.
    pub fn config_revision(&self) -> &str {
        &self.config_revision
    }

    /// Whether this table prices anything.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The evidence every unit from this table carries.
    pub fn evidence(&self) -> Evidence {
        Evidence::RouteWeight {
            config_revision: self.config_revision.clone(),
        }
    }

    /// Resolve every rule that matches one route.
    ///
    /// One unit per distinct unit name, taking the most specific matching
    /// rule for that name. Two different names both matching produce two
    /// units, never one summed number: which line item cost what is the
    /// thing an operator gets asked about, and adding them together throws
    /// the answer away for the sake of a smaller receipt.
    ///
    /// Returns an empty vector when nothing matches. See the module docs for
    /// why that is not a zero.
    pub fn resolve(&self, method: &str, path: &str) -> Vec<Unit> {
        let mut chosen: Vec<(&RouteWeightRule, RouteSpecificity)> = Vec::new();

        for rule in &self.rules {
            let Some(specificity) = rule.specificity(method, path) else {
                continue;
            };
            // Resolved to an index before the match so the borrow the
            // search takes is over by the time the miss arm pushes.
            let existing = chosen
                .iter()
                .position(|(current, _)| current.name == rule.name);
            match existing {
                // Strictly greater, so the first rule written wins a tie and
                // the outcome does not depend on a stable sort somewhere
                // else.
                Some(index) if specificity > chosen[index].1 => {
                    chosen[index] = (rule, specificity);
                }
                Some(_) => {}
                None => chosen.push((rule, specificity)),
            }
        }

        chosen
            .into_iter()
            .map(|(rule, _)| Unit::new(rule.name.clone(), rule.weight, self.evidence()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::UnitSource;

    const REVISION: &str = "9f2c41a0be77";

    fn table(rules: Vec<RouteWeightRule>) -> RouteWeightTable {
        RouteWeightTable::new(REVISION, rules)
    }

    fn rule(name: &str, method: Option<&str>, path: &str, weight: u64) -> RouteWeightRule {
        RouteWeightRule::new(name, method.map(str::to_string), path, weight)
    }

    #[test]
    fn a_priced_route_bills_its_declared_weight() {
        let table = table(vec![rule("search_call", Some("POST"), "/v1/search", 5)]);

        let units = table.resolve("POST", "/v1/search");

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "search_call");
        assert_eq!(units[0].count, 5);
        assert_eq!(units[0].source, UnitSource::RouteWeight);
        assert!(units[0].provenance_is_consistent());
    }

    #[test]
    fn every_unit_cites_the_revision_that_priced_it() {
        let table = table(vec![rule("search_call", None, "/v1/search", 5)]);

        let units = table.resolve("GET", "/v1/search");

        assert_eq!(
            units[0].evidence,
            Evidence::RouteWeight {
                config_revision: REVISION.to_string(),
            },
            "a buyer holding the signed bundle has to be able to look the weight up"
        );
    }

    #[test]
    fn a_reload_cannot_reprice_a_call_the_old_table_is_still_serving() {
        // Two generations exist at once, which is what a reload looks like
        // from the inside. The request that was admitted under the old one
        // keeps resolving against the old one, and the evidence says so.
        let admitted_under = table(vec![rule("search_call", None, "/v1/search", 5)]);
        let live_now = RouteWeightTable::new(
            "0011223344ff",
            vec![rule("search_call", None, "/v1/search", 50)],
        );

        let in_flight = admitted_under.resolve("POST", "/v1/search");
        let fresh = live_now.resolve("POST", "/v1/search");

        assert_eq!(in_flight[0].count, 5, "an in-flight call keeps its price");
        assert_eq!(fresh[0].count, 50);
        assert_eq!(
            in_flight[0].evidence,
            Evidence::RouteWeight {
                config_revision: REVISION.to_string(),
            },
            "and the receipt names the document that actually priced it"
        );
    }

    #[test]
    fn an_unpriced_route_produces_no_unit_rather_than_a_zero() {
        let table = table(vec![rule("search_call", Some("POST"), "/v1/search", 5)]);

        assert!(
            table.resolve("POST", "/v1/embeddings").is_empty(),
            "a route this line does not price is not a route priced at zero"
        );
        assert!(
            table.resolve("GET", "/v1/search").is_empty(),
            "the method is part of the route"
        );
    }

    #[test]
    fn a_declared_weight_of_zero_is_a_metered_free_route() {
        let table = table(vec![rule("search_call", None, "/v1/health", 0)]);

        let units = table.resolve("GET", "/v1/health");

        assert_eq!(units.len(), 1, "the operator did price this route");
        assert_eq!(units[0].count, 0);
    }

    #[test]
    fn the_most_specific_rule_for_one_name_wins() {
        let rules = vec![
            rule("search_call", None, "/v1/search/*", 1),
            rule("search_call", None, "/v1/search/deep/*", 2),
            rule("search_call", None, "/v1/search/deep/one", 3),
            rule("search_call", Some("POST"), "/v1/search/deep/one", 4),
        ];
        let table = table(rules);

        // Longer prefix beats shorter, exact beats prefix, and a named
        // method beats an unnamed one.
        assert_eq!(table.resolve("GET", "/v1/search/x")[0].count, 1);
        assert_eq!(table.resolve("GET", "/v1/search/deep/x")[0].count, 2);
        assert_eq!(table.resolve("GET", "/v1/search/deep/one")[0].count, 3);
        assert_eq!(table.resolve("POST", "/v1/search/deep/one")[0].count, 4);

        for method in ["GET", "POST"] {
            assert_eq!(
                table.resolve(method, "/v1/search/deep/one").len(),
                1,
                "four rules for one invoice line still bill one line"
            );
        }
    }

    #[test]
    fn two_names_matching_one_route_produce_two_units_and_never_a_sum() {
        let table = table(vec![
            rule("api_call", None, "/v1/search", 1),
            rule("search_credit", None, "/v1/search", 5),
        ]);

        let units = table.resolve("POST", "/v1/search");

        let lines: Vec<(&str, u64)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count))
            .collect();
        assert_eq!(
            lines,
            vec![("api_call", 1), ("search_credit", 5)],
            "the per-line breakdown is the product; six is not an answer"
        );
    }

    #[test]
    fn a_prefix_rule_does_not_match_the_segment_it_hangs_off() {
        let table = table(vec![rule("search_call", None, "/v1/search/*", 1)]);

        assert_eq!(table.resolve("GET", "/v1/search/x").len(), 1);
        assert!(
            table.resolve("GET", "/v1/search").is_empty(),
            "`/v1/search/*` names what is below `/v1/search`, not `/v1/search`"
        );
        assert!(
            table.resolve("GET", "/v1/searching").is_empty(),
            "the separator is part of the prefix, so a longer word is not a child"
        );
    }

    #[test]
    fn method_matching_ignores_case_because_yaml_does_not() {
        let table = table(vec![rule("search_call", Some("post"), "/v1/search", 5)]);

        assert_eq!(table.resolve("POST", "/v1/search").len(), 1);
        assert_eq!(table.resolve("post", "/v1/search").len(), 1);
        assert!(table.resolve("PUT", "/v1/search").is_empty());
    }

    #[test]
    fn an_empty_table_prices_nothing_and_still_names_its_revision() {
        let table = RouteWeightTable::empty(REVISION);

        assert!(table.is_empty());
        assert!(table.resolve("POST", "/v1/search").is_empty());
        assert_eq!(table.config_revision(), REVISION);
    }
}
