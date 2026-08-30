// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Rego evaluation for `policy: rego`, on the Regorus interpreter.
//!
//! Rego is a second decision language, offered because some operators
//! already have Rego and would rather not rewrite it. It is not a
//! replacement for CEL and not a wider surface: it decides, and it
//! cannot transform, act, or authenticate. That boundary is a property
//! of the language rather than of our sandbox, because Rego performs no
//! I/O during evaluation, so what reaches a policy is whatever the host
//! established first.
//!
//! # Why Regorus and not OPA compiled to WASM
//!
//! OPA's WASM ABI requires the host to allocate inside the guest and
//! the guest to call back into host functions mid-evaluation. Our
//! sandbox holds the opposite invariant: a guest owns its linear memory
//! and the host never reaches in, which is what makes a fresh `Store`
//! per call a complete reset. Supporting OPA's ABI would mean running a
//! second, weaker isolation model beside the first. Regorus evaluates
//! in process against Rust values, so there is no linear memory to
//! cross and no marshalling to pay for.
//!
//! # The input contract
//!
//! `input` is built from the same [`CelContext`]
//! that `policy: expression` evaluates against, converted to JSON. That
//! is deliberate and is the whole reason [`context_to_input`] exists
//! rather than a second assembly path.
//!
//! An operator moving a decision between the two engines should be
//! porting syntax, not vocabulary. `request.trust_tier` in CEL is
//! `input.request.trust_tier` in Rego, and the set of things that exist
//! is identical because it is literally the same map. A second
//! assembler would drift the moment either engine gained a binding, and
//! the drift would be invisible until someone's policy silently read
//! undefined.
//!
//! # What Rego does not inherit
//!
//! The config-load check that [`crate::cel::surface`] performs does not
//! transfer. A CEL expression names its bindings as identifiers, so an
//! unavailable one is detectable before the first request. In Rego,
//! `input.request.nonsense` is simply undefined, which is a legal value
//! the language is built to handle. There is nothing to refuse at load,
//! so a typo degrades to a rule that never fires rather than to a
//! config error.
//!
//! That asymmetry is real and is the strongest argument for preferring
//! CEL where either would do. It is called out in `docs/scripting.md`
//! rather than papered over.
//!
//! # Coverage
//!
//! [`CompiledRego::set_enable_coverage`] and
//! [`CompiledRego::coverage_report`] are thin wrappers over Regorus's
//! own `set_enable_coverage`/`get_coverage_report`, which this crate
//! already pays for (the `coverage` Cargo feature is part of Regorus's
//! `full-opa` default). Nothing on the request path calls either: the
//! sole caller is `sbproxy rego test`, the offline fixture-driven test
//! loop, which enables coverage before running a fixture's cases and
//! reads the report back to print a summary and enforce
//! `--min-coverage`. A production `policy: rego` or `ai_routing_policy`
//! engine never turns this on, so evaluating real traffic pays no
//! coverage-tracking cost.
//!
//! # Rego v0 and `print()`
//!
//! Regorus defaults to Rego v1 (`if`/`contains` required), matching OPA
//! 1.0. `compile`'s `rego_v0` parameter is the escape hatch for a module
//! authored before that switch: it calls
//! [`regorus::Engine::set_rego_v0`] before the module is parsed, so a
//! bare `allow { ... }` rule body compiles the way it did on OPA before
//! 1.0. Leave it `false` for anything written against current OPA.
//!
//! `print()` inside a module never reaches stderr here.
//! [`regorus::Engine::set_gather_prints`] is enabled once, in `compile`,
//! and [`CompiledRego::eval_bool`] / [`CompiledRego::eval_value`] drain
//! whatever the evaluation gathered into one `tracing` event per call,
//! at INFO under the `rego_print` target, naming the site, the query,
//! and the tenant when the caller has one. A print during the one-time
//! load-time evaluability trial that `compile` runs is discarded rather
//! than logged: that trial runs against an empty input for every module
//! regardless of whether an operator's traffic ever reaches it, so
//! treating it as a request-time signal would manufacture an event
//! nothing real produced.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result};
use regorus::unstable::{Expr, Literal, Query, Rule, RuleHead};

use crate::cel::{CelContext, CelValue};

/// Work units between deadline checks during evaluation.
///
/// Regorus checks the clock every N units rather than continuously, so
/// this trades deadline precision against the cost of the check. A
/// thousand is fine grained enough that a runaway rule is stopped in
/// well under a millisecond of overshoot.
const EXECUTION_CHECK_INTERVAL: std::num::NonZeroU32 = match std::num::NonZeroU32::new(1_000) {
    Some(interval) => interval,
    None => unreachable!(),
};

/// Largest `print()` message written to one log event, in bytes.
///
/// A transform hook's input is the complete buffered response body, so
/// an unbounded print is a copy of every response into whatever
/// consumes the log. Enough to carry a debugging message; not enough to
/// carry a payload.
const MAX_PRINT_MESSAGE_BYTES: usize = 512;

/// Most `print()` events emitted from one evaluation.
///
/// A rule can print inside a comprehension, which turns one request into
/// as many log lines as the input has elements. The remainder is
/// reported as a single count rather than emitted.
const MAX_PRINTS_PER_EVALUATION: usize = 8;

/// Truncate a print message to [`MAX_PRINT_MESSAGE_BYTES`] on a char
/// boundary, returning the message and whether it was shortened.
fn truncate_print_message(message: &str) -> (&str, bool) {
    if message.len() <= MAX_PRINT_MESSAGE_BYTES {
        return (message, false);
    }
    let mut end = MAX_PRINT_MESSAGE_BYTES;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    (&message[..end], true)
}

/// A compiled Rego policy, parsed once at config load.
///
/// Holds the engine with its module already added. Per-request work is
/// setting `input` and evaluating the query, which the spike measured
/// at roughly 57 µs against a policy with a role check, a numeric cap,
/// and an ownership rule.
pub struct CompiledRego {
    /// Operator-facing identity, for diagnostics.
    site: String,
    /// The rule reference evaluated per request, for example
    /// `data.sbproxy.allow`.
    query: String,
    engine: regorus::Engine,
}

impl std::fmt::Debug for CompiledRego {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledRego")
            .field("site", &self.site)
            .field("query", &self.query)
            .finish()
    }
}

/// A rule path below the `data` root, as its literal components.
///
/// `package sbproxy` with an `allow` rule gives `["sbproxy", "allow"]`.
/// The root is implicit and deliberately so: Regorus indexes the base
/// document by exactly these components when it decides whether to keep
/// a rule's computed value, so a path in this form compares against an
/// operator's `data` object with no string parsing in between.
type RulePath = Vec<String>;

/// Render a [`RulePath`] the way an operator writes it in a query.
fn render_rule_path(path: &[String]) -> String {
    format!("data.{}", path.join("."))
}

/// The path components of a query, or `None` when the query is not
/// rooted at `data`.
fn query_rule_path(query: &str) -> Option<RulePath> {
    query
        .strip_prefix("data.")
        .map(|path| path.split('.').map(str::to_owned).collect())
}

/// Whether a base-data document already defines a value at the rule
/// path a query names.
///
/// The query is `data.<seg>.<seg>...`; the data document is rooted at
/// `data`, so the query's path after the `data.` prefix indexes
/// straight into it. A defined value there is the shadowing Regorus
/// resolves in the base document's favor.
///
/// A JSON `null` counts. Regorus keeps the base document's value for
/// anything other than *undefined*, and `add_data`'s deep merge carries
/// a `null` through as a defined value, so `{"sbproxy": {"allow": null}}`
/// shadows an `allow` rule exactly the way `true` does.
fn data_defines_query_path(data: &serde_json::Value, query: &str) -> bool {
    let Some(path) = query_rule_path(query) else {
        // A query not rooted at `data` (rare) cannot be shadowed by a
        // `data` document; nothing to refuse.
        return false;
    };
    let mut cursor = data;
    for segment in &path {
        match cursor.get(segment.as_str()) {
            Some(next) => cursor = next,
            None => return false,
        }
    }
    true
}

/// One component of a reference expression.
///
/// `roles["admin"]` is two literals; `roles[name]` is a literal and a
/// component whose value exists only during evaluation. The distinction
/// bounds how much of a path can be compared against base data at config
/// load: everything up to the first dynamic component is known from the
/// source text, and nothing after it is.
enum RefComponent {
    /// A key that is written in the source.
    Key(String),
    /// A key computed per evaluation.
    Dynamic,
}

/// Break a reference expression into its components, or `None` when the
/// expression is not a reference.
///
/// This is deliberately not Regorus's own `get_path_ref_components`,
/// which flattens a variable index to its source text and so reports
/// `roles[name]` as the literal path `roles.name`. A rule with a
/// variable key resolves to a different path on every evaluation, and
/// treating the variable's spelling as a key would both miss the real
/// collisions and invent one against a `data` key that happened to be
/// spelled the same as the variable.
fn ref_components(expr: &Expr) -> Option<Vec<RefComponent>> {
    match expr {
        Expr::Var { span, .. } => Some(vec![RefComponent::Key(span.text().to_owned())]),
        Expr::RefDot { refr, field, .. } => {
            let mut components = ref_components(refr)?;
            components.push(RefComponent::Key(field.0.text().to_owned()));
            Some(components)
        }
        Expr::RefBrack { refr, index, .. } => {
            let mut components = ref_components(refr)?;
            components.push(match index.as_ref() {
                Expr::String { value, .. } | Expr::RawString { value, .. } => {
                    value.as_string().map_or(RefComponent::Dynamic, |key| {
                        RefComponent::Key(key.to_string())
                    })
                }
                _ => RefComponent::Dynamic,
            });
            Some(components)
        }
        _ => None,
    }
}

/// Everything up to the first component whose key is not in the source.
fn literal_prefix(components: &[RefComponent]) -> RulePath {
    components
        .iter()
        .map_while(|component| match component {
            RefComponent::Key(key) => Some(key.clone()),
            RefComponent::Dynamic => None,
        })
        .collect()
}

/// What a rule head's literal path means, which is not the same thing
/// for every head shape.
///
/// A head with no dynamic component resolves to exactly one path, and
/// Regorus compares the base document against that path. A head like
/// `limits[method]` resolves to a *different* path on every evaluation,
/// and the only thing known at load is the part before the variable.
/// Treating that prefix as the rule's own path is what made the guard
/// refuse a base table whose keys the rule never produces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HeadPath {
    /// The whole path is in the source, so it is the path Regorus
    /// indexes the base document by.
    Exact,
    /// The head carried a component computed per evaluation, so this is
    /// the path the rule's keys land *under*, one segment above
    /// anything Regorus actually compares.
    ComputedKeys,
}

/// Resolve a reference inside a rule to the `data` path it reads.
///
/// Rego resolves a bare name against the enclosing package first, which
/// is how `trusted` inside `package sbproxy` reads `data.sbproxy.trusted`.
/// An explicit `data.` root is taken as written and `input` is not a
/// rule at all. A local variable resolves here the same way a rule name
/// does; the caller keeps only paths that are rules the module defines,
/// so a local never becomes an edge.
fn resolve_reference(package: &[String], components: &[RefComponent]) -> Option<RulePath> {
    let RefComponent::Key(root) = components.first()? else {
        return None;
    };
    match root.as_str() {
        "data" => Some(literal_prefix(components.get(1..)?)),
        "input" => None,
        _ => {
            let mut path = package.to_vec();
            path.extend(literal_prefix(components));
            Some(path)
        }
    }
}

/// Collect every reference expression inside `expr`.
///
/// A reference chain is collected whole rather than one component at a
/// time, since `data.sbproxy.trusted` names one rule and not three.
/// Bracket indices are still walked, because `roles[helper]` reads
/// `helper` as well as `roles`.
fn collect_references(expr: &Expr, out: &mut Vec<Vec<RefComponent>>) {
    match expr {
        Expr::Var { .. } | Expr::RefDot { .. } | Expr::RefBrack { .. } => {
            if let Some(components) = ref_components(expr) {
                out.push(components);
            }
            collect_index_references(expr, out);
        }
        Expr::Array { items, .. } | Expr::Set { items, .. } => {
            for item in items {
                collect_references(item, out);
            }
        }
        Expr::Object { fields, .. } => {
            for (_, key, value) in fields {
                collect_references(key, out);
                collect_references(value, out);
            }
        }
        Expr::ArrayCompr { term, query, .. } | Expr::SetCompr { term, query, .. } => {
            collect_references(term, out);
            collect_query_references(query, out);
        }
        Expr::ObjectCompr {
            key, value, query, ..
        } => {
            collect_references(key, out);
            collect_references(value, out);
            collect_query_references(query, out);
        }
        Expr::Call { fcn, params, .. } => {
            // The callee is a reference too: a call to a helper function
            // defined in the same package is how a chain reaches one.
            if let Some(components) = ref_components(fcn) {
                out.push(components);
            }
            for param in params {
                collect_references(param, out);
            }
        }
        Expr::UnaryExpr { expr: inner, .. } => collect_references(inner, out),
        Expr::BinExpr { lhs, rhs, .. }
        | Expr::BoolExpr { lhs, rhs, .. }
        | Expr::ArithExpr { lhs, rhs, .. }
        | Expr::AssignExpr { lhs, rhs, .. } => {
            collect_references(lhs, out);
            collect_references(rhs, out);
        }
        Expr::Membership {
            key,
            value,
            collection,
            ..
        } => {
            if let Some(key) = key {
                collect_references(key, out);
            }
            collect_references(value, out);
            collect_references(collection, out);
        }
        // A scalar carries no reference. The catch-all also covers
        // Regorus's feature-gated expression forms, which this build
        // does not enable. Missing one costs a dependency edge in a
        // diagnostic and never a missed collision, because detection
        // enumerates rule heads rather than following references.
        _ => {}
    }
}

/// Walk the bracket indices inside a reference chain.
fn collect_index_references(expr: &Expr, out: &mut Vec<Vec<RefComponent>>) {
    match expr {
        Expr::RefBrack { refr, index, .. } => {
            collect_index_references(refr, out);
            collect_references(index, out);
        }
        Expr::RefDot { refr, .. } => collect_index_references(refr, out),
        _ => {}
    }
}

/// Collect every reference expression inside a query body.
fn collect_query_references(query: &Query, out: &mut Vec<Vec<RefComponent>>) {
    for statement in &query.stmts {
        match &statement.literal {
            Literal::SomeVars { .. } => {}
            Literal::SomeIn {
                key,
                value,
                collection,
                ..
            } => {
                if let Some(key) = key {
                    collect_references(key, out);
                }
                collect_references(value, out);
                collect_references(collection, out);
            }
            Literal::Expr { expr, .. } | Literal::NotExpr { expr, .. } => {
                collect_references(expr, out);
            }
            Literal::Every {
                domain,
                query: inner,
                ..
            } => {
                collect_references(domain, out);
                collect_query_references(inner, out);
            }
        }
        // A `with` modifier's target is an override rather than a read,
        // so only the replacement value is walked.
        for modifier in &statement.with_mods {
            collect_references(&modifier.r#as, out);
        }
    }
}

/// The rule paths a module defines and the references between them.
struct RuleGraph {
    /// Every rule path the module defines. Identical to
    /// [`Self::edges`]'s key set, kept separately because resolving the
    /// *query* to the rules it reads runs the same match as resolving a
    /// reference does, and that resolution reads heads while `edges` is
    /// being written.
    heads: BTreeSet<RulePath>,
    /// Every rule path in the module, mapped to the rule paths that rule
    /// reads. A function is a key here so a chain can pass through a
    /// helper function, and is absent from [`Self::shadowable`].
    edges: BTreeMap<RulePath, BTreeSet<RulePath>>,
    /// The rule paths Regorus stores under `data`, which is every rule
    /// except a function that takes parameters: such a function lives in
    /// the function table and nothing indexes the base document for it,
    /// so base data cannot shadow one. The value says whether the path
    /// is the rule's own or only the literal prefix of a head whose keys
    /// are computed, which decides what a value found there means.
    shadowable: BTreeMap<RulePath, HeadPath>,
}

/// Enumerate the rule paths the engine's parsed modules define, with the
/// references between them.
///
/// Call this after `add_policy` and before `add_data`, which is the
/// window where the engine holds the parsed module and an empty base
/// document.
///
/// Every rule head is enumerated, not only the ones the query names,
/// because Regorus resolves a rule against the base document by *that
/// rule's* own path: `update_rule_value` returns early for any rule
/// whose path is already defined in `init_data`, so a helper four hops
/// from the query is shadowed exactly as readily as the query's own
/// rule. Walking heads is also strictly wider than walking the query's
/// dependency closure, which would need to resolve references through
/// comprehensions, `with` overrides, and dynamic refs to be sound, and
/// would go stale the moment somebody edited the policy to call a rule
/// it had not called before.
fn rule_graph(engine: &mut regorus::Engine) -> RuleGraph {
    let mut heads: BTreeSet<RulePath> = BTreeSet::new();
    let mut shadowable: BTreeMap<RulePath, HeadPath> = BTreeMap::new();
    let mut references: Vec<(RulePath, RulePath)> = Vec::new();

    for module in engine.get_modules() {
        let Some(components) = ref_components(&module.package.refr) else {
            continue;
        };
        let package = literal_prefix(&components);
        if package.is_empty() {
            continue;
        }
        for rule in &module.policy {
            let mut found: Vec<Vec<RefComponent>> = Vec::new();
            let (refr, is_function) = match rule.as_ref() {
                Rule::Spec { head, bodies, .. } => {
                    let (refr, is_function) = match head {
                        RuleHead::Compr { refr, assign, .. } => {
                            if let Some(assign) = assign {
                                collect_references(&assign.value, &mut found);
                            }
                            (refr, false)
                        }
                        RuleHead::Set { refr, key, .. } => {
                            if let Some(key) = key {
                                collect_references(key, &mut found);
                            }
                            (refr, false)
                        }
                        RuleHead::Func {
                            refr, args, assign, ..
                        } => {
                            if let Some(assign) = assign {
                                collect_references(&assign.value, &mut found);
                            }
                            // A zero-argument function is not in the
                            // function table: Regorus's `Func` arm calls
                            // `update_data` for it, which honors the
                            // base document exactly the way a rule does,
                            // so it is shadowable and a function with
                            // parameters is not.
                            (refr, !args.is_empty())
                        }
                    };
                    for body in bodies {
                        if let Some(assign) = &body.assign {
                            collect_references(&assign.value, &mut found);
                        }
                        collect_query_references(&body.query, &mut found);
                    }
                    (refr, is_function)
                }
                Rule::Default {
                    refr, args, value, ..
                } => {
                    collect_references(value, &mut found);
                    (refr, !args.is_empty())
                }
            };

            let Some(components) = ref_components(refr) else {
                continue;
            };
            let head = literal_prefix(&components);
            if head.is_empty() {
                // A head whose very first component is computed names no
                // path that can be compared at load.
                continue;
            }
            let shape = if head.len() == components.len() {
                HeadPath::Exact
            } else {
                HeadPath::ComputedKeys
            };
            let mut path = package.clone();
            path.extend(head);
            heads.insert(path.clone());
            if !is_function {
                // Two heads can land on the same path, `denies := {...}`
                // beside `denies[k] := ...`. The exact one is the
                // stricter reading, so it wins.
                let entry = shadowable.entry(path.clone()).or_insert(shape);
                if shape == HeadPath::Exact {
                    *entry = HeadPath::Exact;
                }
            }
            for components in &found {
                if let Some(target) = resolve_reference(&package, components) {
                    references.push((path.clone(), target));
                }
            }
        }
    }

    let mut edges: BTreeMap<RulePath, BTreeSet<RulePath>> = heads
        .iter()
        .map(|head| (head.clone(), BTreeSet::new()))
        .collect();
    for (from, target) in references {
        for resolved in reached_heads(&heads, &target) {
            if resolved != from {
                edges.entry(from.clone()).or_default().insert(resolved);
            }
        }
    }

    RuleGraph {
        heads,
        edges,
        shadowable,
    }
}

/// The rule heads a read of `target` evaluates.
///
/// Two directions, and both are real reads. A reference *at or below* a
/// head names that rule: `roles.admin` reads the `roles` rule, so the
/// longest head that prefixes the reference is the rule it points at. A
/// reference *above* a head reads every rule beneath it, because
/// resolving `data.sbproxy.denies` evaluates every `denies[...]` rule in
/// the package to build the object it returns. Following only the first
/// direction is what let the guard call a live collision latent: a
/// policy that iterates a parent path reaches every rule under it, and
/// no edge said so.
///
/// A reference that matches in neither direction (a base-data lookup, a
/// builtin, a local variable) reaches nothing and is not an edge.
fn reached_heads(heads: &BTreeSet<RulePath>, target: &[String]) -> BTreeSet<RulePath> {
    let mut reached: BTreeSet<RulePath> = heads
        .iter()
        .filter(|head| head.starts_with(target))
        .cloned()
        .collect();
    if let Some(nearest) = heads
        .iter()
        .filter(|head| target.starts_with(head.as_slice()))
        .max_by_key(|head| head.len())
    {
        reached.insert(nearest.clone());
    }
    reached
}

/// The shortest reference chain from `from` to `to`, both included.
///
/// Breadth first over sorted collections, so the chain an operator is
/// shown for a given module is the same on every boot.
fn reference_chain(
    edges: &BTreeMap<RulePath, BTreeSet<RulePath>>,
    from: &[String],
    to: &[String],
) -> Option<Vec<RulePath>> {
    if from == to {
        return Some(vec![to.to_vec()]);
    }
    let mut previous: BTreeMap<RulePath, RulePath> = BTreeMap::new();
    let mut seen: BTreeSet<RulePath> = BTreeSet::new();
    let mut queue: VecDeque<RulePath> = VecDeque::new();
    seen.insert(from.to_vec());
    queue.push_back(from.to_vec());
    while let Some(node) = queue.pop_front() {
        let Some(neighbors) = edges.get(&node) else {
            continue;
        };
        for neighbor in neighbors {
            if !seen.insert(neighbor.clone()) {
                continue;
            }
            previous.insert(neighbor.clone(), node.clone());
            if neighbor.as_slice() == to {
                let mut chain = vec![to.to_vec()];
                let mut cursor = to.to_vec();
                while let Some(parent) = previous.get(&cursor) {
                    chain.push(parent.clone());
                    cursor = parent.clone();
                }
                chain.reverse();
                return Some(chain);
            }
            queue.push_back(neighbor.clone());
        }
    }
    None
}

/// How a base-data document collides with one rule path.
enum DataCollision {
    /// Base data carries a value at the rule's own path, so Regorus
    /// keeps the base value and the rule never contributes one.
    Shadows(RulePath),
    /// Base data carries an object at the path a rule computes its keys
    /// under. Which keys collide is not knowable at load, so this says
    /// only what is true: any key the base object already defines beats
    /// the rule's.
    ShadowsComputedKeys(RulePath),
    /// Base data carries a value that is not an object above the rule's
    /// path, leaving the rule nowhere under `data` to land.
    Blocks {
        /// The path holding the non-object value.
        at: RulePath,
        /// The rule underneath it.
        rule: RulePath,
    },
    /// Base data carries a value that is not an object at the path a
    /// rule computes its keys under, so no key it produces can land.
    BlocksComputedKeys(RulePath),
}

/// Whether a base-data document collides with one rule path.
///
/// Base data at a *shallower* path is only a collision when the value
/// there is not an object: an object merges with the rules beneath it,
/// which is what makes a `data.sbproxy.roles` table legal beside a
/// `data.sbproxy.allow` rule. Base data at the rule's own path, or at
/// any path *below* it (which makes the rule's own path an object),
/// shadows.
///
/// `shape` decides what a value at the end of the path means, and this
/// is where a partial rule stops being comparable. For an
/// [`HeadPath::Exact`] head the path is the one Regorus indexes, so a
/// value there is a whole-rule shadow. For a
/// [`HeadPath::ComputedKeys`] head (`limits[method] := ...`) Regorus
/// indexes `data.sbproxy.limits.GET`, one segment deeper than anything
/// the source names, so the three cases split:
///
/// - A non-object at the prefix blocks every key the rule computes.
///   `update_rule_value` walks the path with `as_object_mut` and fails
///   with "previous value is not an object" mid evaluation.
/// - An **empty** object merges and can shadow nothing: no key exists
///   to win against a computed one. Not a collision, and saying so is
///   the one case where a dynamic head compares precisely.
/// - A non-empty object merges too, and there the keys are what
///   collide. `{"POST": "no"}` beside a rule that only ever produces
///   `GET` is a working config; `{"GET": "no"}` beside the same rule
///   silently kills the rule's only output. Which one it is depends on
///   values the rule computes per evaluation, so load time cannot tell
///   them apart.
///
/// That last case is refused rather than warned or skipped, and it is
/// deliberately the conservative side of a call that costs real false
/// refusals. The two directions are not symmetric: refusing a working
/// config is loud, arrives at boot, and is fixed by renaming a key,
/// while admitting a shadowed one is silent, arrives as a `deny` rule
/// that stopped contributing its key, and fails open. WOR-2428 is that
/// second failure, so the refusal keeps the wide side. The message it
/// carries says only what is knowable, because a refusal that overstates
/// what the detector saw sends the operator looking for a bug that is
/// not there.
fn rule_collision(
    data: &serde_json::Value,
    rule: &[String],
    shape: HeadPath,
) -> Option<DataCollision> {
    let mut cursor = data;
    for (index, segment) in rule.iter().enumerate() {
        match cursor.get(segment.as_str()) {
            Some(next) => cursor = next,
            None => {
                return (index > 0 && !cursor.is_object()).then(|| DataCollision::Blocks {
                    at: rule[..index].to_vec(),
                    rule: rule.to_vec(),
                });
            }
        }
    }
    match shape {
        HeadPath::Exact => Some(DataCollision::Shadows(rule.to_vec())),
        HeadPath::ComputedKeys => match cursor.as_object() {
            Some(keys) if keys.is_empty() => None,
            Some(_) => Some(DataCollision::ShadowsComputedKeys(rule.to_vec())),
            None => Some(DataCollision::BlocksComputedKeys(rule.to_vec())),
        },
    }
}

/// The base-data collision to refuse on, and how the query reaches it.
///
/// A collision the query demonstrably reaches wins over one it does not,
/// because that is the one whose decision is already wrong. Ties break
/// on sorted rule-path order, so the same config refuses with the same
/// message on every boot.
fn base_data_collision(
    data: &serde_json::Value,
    graph: &RuleGraph,
    query: &str,
) -> Option<(DataCollision, Option<Vec<RulePath>>)> {
    // The query is a reference like any other, so it resolves to rules
    // the same way one inside a module does. A query naming a path
    // above the heads (`data.sbproxy` against a package of rules) or
    // below one (`data.sbproxy.limits.GET` against a `limits[m]` rule)
    // starts the walk at the rules it reads rather than at a node the
    // graph does not hold.
    let starts = query_rule_path(query)
        .map(|path| reached_heads(&graph.heads, &path))
        .unwrap_or_default();
    let mut latent = None;
    for (rule, shape) in &graph.shadowable {
        let Some(collision) = rule_collision(data, rule, *shape) else {
            continue;
        };
        // Shortest chain wins, and ties break on path order, so the
        // same config prints the same walk on every boot.
        let chain = starts
            .iter()
            .filter_map(|start| reference_chain(&graph.edges, start, rule))
            .min_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
        if chain.is_some() {
            return Some((collision, chain));
        }
        if latent.is_none() {
            latent = Some((collision, None));
        }
    }
    latent
}

/// The operator-facing explanation of a base-data collision.
///
/// Names the data path, the rule it hit, and the reference chain that
/// carries the query to that rule, because "something collided" leaves
/// an operator staring at a module whose logic looks correct.
///
/// Every clause here is bounded by what the detector actually saw. The
/// no-chain wording reports a failed search rather than an absence,
/// because the walk does not resolve an import alias, a reference built
/// by a builtin, or a query that is not rooted at `data`, so "nothing
/// reaches it" is a claim the search cannot support. Naming the wrong
/// reason costs more than naming none: an operator told the collision is
/// latent stops looking at the rule that is already dead.
fn describe_collision(
    collision: &DataCollision,
    chain: Option<&[RulePath]>,
    query: &str,
) -> String {
    let reach = match chain {
        Some(chain) => {
            let hops: Vec<String> = chain
                .iter()
                .map(|path| render_rule_path(path.as_slice()))
                .collect();
            format!("The query `{query}` reaches it: {}.", hops.join(" -> "))
        }
        None => format!(
            "No reference chain from the query `{query}` was found, so the collision may be \
             latent; an aliased import or a reference built at evaluation time is not traced."
        ),
    };
    match collision {
        DataCollision::Shadows(rule) => format!(
            "base data defines `{}`, and the module defines a rule at that path, so Rego resolves \
             the base document there and the rule never evaluates. {reach} Move the base data \
             under a key no rule in the module produces.",
            render_rule_path(rule)
        ),
        DataCollision::ShadowsComputedKeys(rule) => format!(
            "base data defines keys under `{}`, and the module defines a rule that computes its \
             own keys at that path, so every key the base document already carries wins over the \
             rule's and the rule cannot replace it. Which keys collide depends on values the rule \
             computes per request, so this cannot be narrowed at config load. {reach} Move the \
             base data under a key no rule in the module produces.",
            render_rule_path(rule)
        ),
        DataCollision::Blocks { at, rule } => format!(
            "base data sets `{}` to a value that is not an object, and the module defines a rule \
             at `{}` beneath it, so the rule has nowhere to resolve. {reach} Move the base data \
             under a key that does not sit above a rule the module defines.",
            render_rule_path(at),
            render_rule_path(rule)
        ),
        DataCollision::BlocksComputedKeys(rule) => format!(
            "base data sets `{}` to a value that is not an object, and the module defines a rule \
             that computes its own keys at that path, so no key the rule produces has anywhere to \
             land. {reach} Move the base data under a key no rule in the module produces.",
            render_rule_path(rule)
        ),
    }
}

/// One source file's line coverage from a [`CompiledRego`] engine, read
/// back via [`CompiledRego::coverage_report`].
///
/// Wraps Regorus's own `coverage::Report`/`coverage::File` (line
/// granularity: Regorus does not track which named rule a line belongs
/// to, only whether the interpreter executed it) in a type that does
/// not leak the `regorus` crate through this module's public surface.
#[derive(Debug, Clone)]
pub struct RegoCoverage {
    /// The name `compile` registered the module under (its `site`
    /// argument, with `.rego` appended, since that is the string
    /// `compile` passes to `add_policy`).
    pub path: String,
    /// Source line numbers the interpreter executed at least once.
    pub covered: Vec<u32>,
    /// Source line numbers the interpreter never reached.
    pub not_covered: Vec<u32>,
}

impl RegoCoverage {
    /// Percentage of `covered ∪ not_covered` lines that were covered.
    ///
    /// `100.0` when the module has no lines Regorus tracks coverage for
    /// at all (for example a comment-only file), since there is nothing
    /// for a case to have missed.
    pub fn percent(&self) -> f64 {
        let total = self.covered.len() + self.not_covered.len();
        if total == 0 {
            100.0
        } else {
            (self.covered.len() as f64 / total as f64) * 100.0
        }
    }
}

impl CompiledRego {
    /// Parse `module` and pin `query` as the rule this policy evaluates.
    ///
    /// `rego_v0` selects the parser dialect: `false` (the default
    /// everywhere this is called from config) requires current Rego v1
    /// syntax (`if`/`contains`), matching Regorus's own default and OPA
    /// 1.0. `true` calls [`regorus::Engine::set_rego_v0`] first, so a
    /// module written before that switch (`allow { ... }` with no `if`)
    /// parses. Set it per policy for a pasted-in legacy module rather
    /// than rewriting it; a module authored fresh should not need it.
    ///
    /// # Errors
    ///
    /// Returns an error naming the site when the module does not parse.
    /// A malformed policy is a config error, so boot and reload both
    /// refuse it, matching every other engine that compiles from static
    /// config.
    pub fn compile(
        site: impl Into<String>,
        module: &str,
        query: impl Into<String>,
        budget_ms: u64,
        data: Option<serde_json::Value>,
        rego_v0: bool,
    ) -> Result<Self> {
        let site = site.into();
        let query = query.into();
        let mut engine = regorus::Engine::new();
        // Dialect selection has to precede parsing: v0/v1 changes what
        // the parser accepts, not a post-parse pass.
        engine.set_rego_v0(rego_v0);
        // Gathered rather than left at Regorus's default of stderr, so a
        // `print()` inside a policy lands in the same structured
        // tracing every other engine's script signal goes through
        // rather than on the process's raw stderr. `eval_bool` and
        // `eval_value` drain this per evaluation; the trial run below
        // drains and discards it before the engine ever serves a
        // request.
        engine.set_gather_prints(true);
        engine
            .add_policy(format!("{site}.rego"), module.to_owned())
            .inspect_err(|_| {
                sbproxy_observe::metrics::record_script_compile("rego", "parse_error");
            })
            .with_context(|| format!("{site}: invalid Rego module"))?;

        // Base data (the OPA `data` document, WOR-2420): a static
        // allowlist, role table, or routing map the rule reads as
        // `data.<name>`, kept separate from the module so an operator
        // edits the table without touching the policy logic. Added once
        // here, not per request: the document is fixed for the life of
        // this engine (a config reload rebuilds it), so evaluation pays
        // no clone. A malformed document is a config-load error, not a
        // runtime one.
        if let Some(data) = data {
            // A base-data document that defines a value at the queried
            // rule's own path silently overrides the rule: Regorus
            // prefers the base document over a rule's computed value at
            // the same path, so `data.sbproxy.allow: true` would clobber
            // the `allow` rule and make every request identical while
            // the rule body still runs and spends the budget. Refuse it
            // at load, because nothing downstream can tell the operator
            // their policy logic is dead.
            //
            // Counted on the way out, on `semantic_error`, the same
            // label `prove_evaluable`'s refusal carries. An operator
            // rolling out an upgrade watches
            // `sbproxy_script_compile_total{engine="rego"}` to see
            // whether their policies still compile, and a refusal that
            // exists only as a returned error is a fleet-wide failure
            // showing as a flat series. The label is reused rather than
            // extended: a `base_data_conflict` value would be a wider
            // closed set than `metrics.rs`, `metric_registry.rs`,
            // `docs/observability.md`, and `docs/metrics-stability.md`
            // all publish, and this refusal belongs to the category
            // those already name, a module that parsed and then failed
            // analysis. Which analysis failed is in the error text.
            if data_defines_query_path(&data, &query) {
                sbproxy_observe::metrics::record_script_compile("rego", "semantic_error");
                return Err(anyhow::anyhow!(
                    "{site}: base data defines `{query}`, the rule the query names, so it \
                     would override the rule's own value; put base data under a different \
                     key than the queried rule"
                ));
            }

            // The same override applies to every *other* rule the module
            // defines, and that case is worse: a shadowed helper leaves
            // the query evaluating normally against a constant, so the
            // top-level decision changes with no error and nothing in
            // the logs saying the rule stopped running rather than
            // stopped matching. A `deny` that quietly stops evaluating
            // fails open. Refuse at load rather than warn at evaluation:
            // an operator can rename a data key at author time, and a
            // shadow that only surfaces on the request that trips it is
            // a decision already made wrongly. Base data at a sibling
            // path (`data.sbproxy.roles` next to an `allow` rule) is
            // still fine, since it collides with no rule head.
            let graph = rule_graph(&mut engine);
            if let Some((collision, chain)) = base_data_collision(&data, &graph, &query) {
                sbproxy_observe::metrics::record_script_compile("rego", "semantic_error");
                return Err(anyhow::anyhow!(
                    "{site}: {}",
                    describe_collision(&collision, chain.as_deref(), &query)
                ));
            }
            let value = regorus::Value::from_json_str(&data.to_string())
                .with_context(|| format!("{site}: base data is not valid JSON"))?;
            engine
                .add_data(value)
                .with_context(|| format!("{site}: base data could not be loaded"))?;
        }

        // Bound evaluation before anything is evaluated, including the
        // trial below. Without this a policy is unbounded on the request
        // path: `net.cidr_expand` over an attacker-supplied header can
        // allocate millions of strings, and it would do so while holding
        // this engine's lock on a runtime worker.
        engine.set_execution_timer_config(regorus::utils::limits::ExecutionTimerConfig {
            limit: std::time::Duration::from_millis(budget_ms),
            check_interval: EXECUTION_CHECK_INTERVAL,
        });

        let mut compiled = Self {
            site,
            query,
            engine,
        };

        // `add_policy` parses and stops. Scheduling, safety analysis,
        // and rule resolution happen on the first evaluation, so a
        // module with an unsafe variable, or a `query` naming no rule,
        // parses clean and then fails every request forever. Force that
        // work now, against an empty input, so it is a config error at
        // boot and reload rather than an origin that 403s permanently
        // with only a warn line to explain it.
        compiled.prove_evaluable().inspect_err(|_| {
            sbproxy_observe::metrics::record_script_compile("rego", "semantic_error");
        })?;
        sbproxy_observe::metrics::record_script_compile("rego", "ok");
        Ok(compiled)
    }

    /// Run the query once against an empty input so deferred analysis
    /// happens at config load.
    ///
    /// An empty input is enough: the analyzer's work does not depend on
    /// input values, and a rule that reads a missing binding yields
    /// `undefined` rather than an error. So this catches the structural
    /// faults and does not reject a policy for reading a field a real
    /// request would carry.
    fn prove_evaluable(&mut self) -> Result<()> {
        self.engine
            .set_input_json("{}")
            .with_context(|| format!("{}: empty input rejected", self.site))?;
        let result = self.engine.eval_rule(self.query.clone());
        // Discard rather than log: this trial runs against an empty
        // input for every module at every boot and reload, whether or
        // not the policy ever sees real traffic, so a `print()` here
        // describes the trial, not a request. Draining still matters,
        // otherwise a print from this call would sit in the buffer and
        // get attributed to whatever the first real evaluation is.
        let _ = self.engine.take_prints();
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                // A trial that only ran out of `budget_ms` is
                // inconclusive, not damning. The module parsed and the
                // analyzer got far enough to start evaluating; it did
                // not finish inside the same wall-clock bound the
                // request path uses. Refusing compile here called a
                // timeout an unsafe-variable / missing-rule fault and
                // blocked boot of a policy that is still well-formed
                // (WOR-2708). Log and proceed. The request path still
                // denies when the same budget is exceeded for real.
                if let Some(regorus::LimitError::TimeLimitExceeded { elapsed, limit }) =
                    error.downcast_ref()
                {
                    tracing::warn!(
                        site = %self.site,
                        rule = %self.query,
                        elapsed_ms = elapsed.as_millis(),
                        limit_ms = limit.as_millis(),
                        "Rego load-time trial exceeded budget_ms; compile proceeds, but this \
                         policy may deny requests under the same budget at runtime"
                    );
                    return Ok(());
                }
                Err(error).with_context(|| {
                    format!(
                        "{}: rule `{}` could not be evaluated. The module parsed, so this is a \
                         semantic fault: an unsafe variable, or a query naming a rule the module \
                         does not define",
                        self.site, self.query
                    )
                })
            }
        }
    }

    /// Drain `print()` output gathered during the last evaluation into
    /// tracing, one event per call, and never to stderr.
    ///
    /// `compile` turns on [`regorus::Engine::set_gather_prints`] once;
    /// this is the only place that buffer is read. Called after every
    /// per-request evaluation attempt, on both the success and the
    /// error path, since a rule can print before a later line in the
    /// same evaluation faults. `tenant` is the empty string when the
    /// caller has none to attribute the event to.
    ///
    /// Bounded and redacted on the way out. A transform hook's input is
    /// the complete buffered response body, so `print(input.body.body_base64)`
    /// is a copy of every response into the log, at `info`, on the hot
    /// path. Each message is passed through the secret redactor and
    /// truncated to [`MAX_PRINT_MESSAGE_BYTES`], and at most
    /// [`MAX_PRINTS_PER_EVALUATION`] events are emitted per evaluation
    /// with one summary line for the remainder.
    fn drain_prints(&mut self, tenant: &str) {
        let Ok(prints) = self.engine.take_prints() else {
            // Only errors when gathering was never enabled, which
            // `compile` always does; nothing to drain either way.
            return;
        };
        let gathered = prints.len();
        for message in prints.into_iter().take(MAX_PRINTS_PER_EVALUATION) {
            let redacted = sbproxy_observe::redact::redact_secrets(&message);
            let (message, truncated) = truncate_print_message(&redacted);
            tracing::info!(
                target: "rego_print",
                site = %self.site,
                query = %self.query,
                tenant_id = tenant,
                truncated,
                "{message}"
            );
        }
        if gathered > MAX_PRINTS_PER_EVALUATION {
            tracing::warn!(
                target: "rego_print",
                site = %self.site,
                query = %self.query,
                tenant_id = tenant,
                dropped = gathered - MAX_PRINTS_PER_EVALUATION,
                "rego print output dropped: more print() calls in one evaluation than the cap"
            );
        }
    }

    /// The config site this policy came from.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The rule reference this policy evaluates.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Enable or disable Regorus's line-coverage instrumentation on this
    /// engine.
    ///
    /// Off by default, matching Regorus's own default, and nothing on
    /// the request path calls this; see the module's "Coverage" section.
    /// Toggling clears whatever coverage the engine has gathered so far
    /// (Regorus's own documented behavior for `set_enable_coverage`).
    pub fn set_enable_coverage(&mut self, enable: bool) {
        self.engine.set_enable_coverage(enable);
    }

    /// Line coverage gathered across every evaluation since coverage was
    /// last enabled or cleared, one entry per source file `compile`
    /// registered (in practice exactly one: this type parses a single
    /// module).
    ///
    /// # Errors
    ///
    /// Returns an error if Regorus cannot assemble the report. The
    /// public API offers no way to trigger this deliberately; the
    /// underlying call is fallible so this mirrors it rather than
    /// hiding a failure behind an empty report.
    pub fn coverage_report(&self) -> Result<Vec<RegoCoverage>> {
        let report = self.engine.get_coverage_report()?;
        Ok(report
            .files
            .into_iter()
            .map(|file| RegoCoverage {
                path: file.path,
                covered: file.covered.into_iter().collect(),
                not_covered: file.not_covered.into_iter().collect(),
            })
            .collect())
    }

    /// Evaluate the pinned query against `ctx`.
    ///
    /// Returns the rule's boolean result. A non-boolean result is an
    /// error rather than a coerced truthy value: a policy whose rule
    /// returns a document has not answered the question this surface
    /// asked, and guessing which way it meant would be worse than
    /// saying so.
    ///
    /// # Errors
    ///
    /// Returns an error when `input` cannot be set, the rule does not
    /// evaluate, or the result is not a boolean. Every one of those is
    /// a fail-closed condition at the call site.
    pub fn eval_bool(&mut self, ctx: &CelContext) -> Result<bool> {
        let start = std::time::Instant::now();
        let outcome = self.eval_bool_inner(ctx);
        sbproxy_observe::metrics::record_script_duration("rego", start.elapsed().as_secs_f64());
        sbproxy_observe::metrics::record_script_invocation(
            "rego",
            if outcome.is_ok() {
                "ok"
            } else {
                "runtime_error"
            },
        );
        outcome
    }

    /// Evaluate the pinned query against an arbitrary JSON `input`
    /// document and return the rule's boolean result.
    ///
    /// The JSON-input twin of [`Self::eval_bool`], for a caller that
    /// does not carry a [`CelContext`] (a signed extension bundle's
    /// Rego policy hook, WOR-2482, whose input is the same JSON
    /// envelope a JavaScript or WASM bundle policy hook reads, not the
    /// CEL-context vocabulary `policy: rego` shares with
    /// `policy: expression`). Stamps the same script metrics and the
    /// same "non-boolean is an error" contract as [`Self::eval_bool`].
    ///
    /// `tenant` attributes any `print()` output from this evaluation;
    /// pass the empty string when the caller has none.
    ///
    /// # Errors
    ///
    /// Returns an error when `input` cannot be set, the rule does not
    /// evaluate, or the result is not a boolean.
    pub fn eval_bool_json(&mut self, input: serde_json::Value, tenant: &str) -> Result<bool> {
        let start = std::time::Instant::now();
        let outcome = self.eval_bool_from_value(input, tenant);
        sbproxy_observe::metrics::record_script_duration("rego", start.elapsed().as_secs_f64());
        sbproxy_observe::metrics::record_script_invocation(
            "rego",
            if outcome.is_ok() {
                "ok"
            } else {
                "runtime_error"
            },
        );
        outcome
    }

    /// Evaluate the query against an arbitrary JSON `input` document and
    /// return the rule's value as JSON.
    ///
    /// The document form of [`Self::eval_bool`], for callers whose rule
    /// returns a structured decision (the AI routing plan, WOR-2366)
    /// rather than an allow/deny. A rule that is defined but undefined for
    /// this input returns JSON `null`, which such callers read as "the
    /// policy declined"; it is not an error. Stamps the same script
    /// metrics as the boolean form.
    ///
    /// `tenant` attributes any `print()` output from this evaluation;
    /// pass the empty string when the caller has none.
    pub fn eval_value(
        &mut self,
        input: serde_json::Value,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let outcome = self.eval_value_inner(input, tenant);
        sbproxy_observe::metrics::record_script_duration("rego", start.elapsed().as_secs_f64());
        sbproxy_observe::metrics::record_script_invocation(
            "rego",
            if outcome.is_ok() {
                "ok"
            } else {
                "runtime_error"
            },
        );
        outcome
    }

    fn eval_value_inner(
        &mut self,
        input: serde_json::Value,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        use serde::Deserialize;
        let input = regorus::Value::deserialize(input)
            .with_context(|| format!("{}: input document rejected", self.site))?;
        self.engine.set_input(input);
        let result = self.engine.eval_rule(self.query.clone());
        self.drain_prints(tenant);
        let value = result
            .with_context(|| format!("{}: rule `{}` did not evaluate", self.site, self.query))?;
        if value == regorus::Value::Undefined {
            // An undefined rule value is the policy having no opinion for
            // this input, not a fault.
            return Ok(serde_json::Value::Null);
        }
        serde_json::to_value(&value)
            .with_context(|| format!("{}: rule `{}` value is not JSON", self.site, self.query))
    }

    fn eval_bool_inner(&mut self, ctx: &CelContext) -> Result<bool> {
        // Feed regorus the tree directly rather than serialising to a
        // string it immediately reparses; the conversion is the only
        // pass over the context this way.
        self.eval_bool_from_value(context_to_input(ctx), tenant_from_context(ctx))
    }

    /// Shared tail of [`Self::eval_bool_inner`] and
    /// [`Self::eval_bool_json`]: set `input`, evaluate the pinned
    /// query, drain any `print()` output, and require a boolean
    /// result.
    fn eval_bool_from_value(&mut self, input: serde_json::Value, tenant: &str) -> Result<bool> {
        use serde::Deserialize;
        let input = regorus::Value::deserialize(input)
            .with_context(|| format!("{}: input document rejected", self.site))?;
        self.engine.set_input(input);
        let result = self.engine.eval_rule(self.query.clone());
        self.drain_prints(tenant);
        let value = result
            .with_context(|| format!("{}: rule `{}` did not evaluate", self.site, self.query))?;
        match value {
            regorus::Value::Bool(allowed) => Ok(allowed),
            other => anyhow::bail!(
                "{}: rule `{}` returned {other:?} rather than a boolean",
                self.site,
                self.query
            ),
        }
    }
}

/// The tenant a `policy: expression`-shaped [`CelContext`] resolved to,
/// for attributing a `print()` event to the request that produced it.
///
/// Mirrors the `principal.tenant_id` binding `populate_principal_namespace`
/// sets (see [`crate::cel::context`]): the empty string when no principal
/// namespace was populated, or when it was populated with no tenant.
fn tenant_from_context(ctx: &CelContext) -> &str {
    match ctx.variables.get("principal") {
        Some(CelValue::Map(fields)) => match fields.get("tenant_id") {
            Some(CelValue::String(tenant)) => tenant.as_str(),
            _ => "",
        },
        _ => "",
    }
}

/// Convert the shared CEL context into Rego's `input` document.
///
/// This is the parity seam. Both engines read the same map, so the
/// bindings available to a Rego policy are exactly those available to a
/// CEL expression on the same surface, and adding a binding to one adds
/// it to the other without anybody remembering to.
pub fn context_to_input(ctx: &CelContext) -> serde_json::Value {
    let mut root = serde_json::Map::with_capacity(ctx.variables.len());
    for (name, value) in &ctx.variables {
        root.insert(name.clone(), cel_to_json(value));
    }
    serde_json::Value::Object(root)
}

/// Convert one [`CelValue`] to JSON.
///
/// A non-finite float becomes `null` rather than panicking, because
/// `serde_json::Number::from_f64` refuses NaN and infinity and a
/// decision path must not fail on a value it can represent as absent.
fn cel_to_json(value: &CelValue) -> serde_json::Value {
    match value {
        CelValue::String(text) => serde_json::Value::String(text.clone()),
        CelValue::Int(number) => serde_json::Value::from(*number),
        CelValue::Float(number) => serde_json::Number::from_f64(*number)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        CelValue::Bool(flag) => serde_json::Value::Bool(*flag),
        CelValue::Null => serde_json::Value::Null,
        CelValue::List(items) => serde_json::Value::Array(items.iter().map(cel_to_json).collect()),
        CelValue::Map(entries) => convert_map(entries),
        // A pre-converted shared value: materialize it (an Arc walk, not a
        // document copy at the top) and convert the owned form.
        CelValue::Shared(_) => cel_to_json(&value.clone().into_owned()),
    }
}

/// Convert a CEL map. The source is a `HashMap` with no order of its
/// own; the resulting object's key order is therefore unspecified
/// (`serde_json::Map`'s own order depends on whether the workspace has
/// serde_json's `preserve_order` feature on, which cedar-policy-core
/// forces regardless of this crate's own manifest). That is fine here:
/// [`context_to_input`]'s only consumer is `regorus`, which reads a
/// Rego input document by field name, never by iteration order.
fn convert_map(entries: &HashMap<String, CelValue>) -> serde_json::Value {
    let mut object = serde_json::Map::with_capacity(entries.len());
    for (key, value) in entries {
        object.insert(key.clone(), cel_to_json(value));
    }
    serde_json::Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW_ENGINEERS: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.trust_tier == "strong"
}

allow if {
    input.request.method == "GET"
    input.request.path == "/health"
}
"#;

    fn context() -> CelContext {
        let mut ctx = crate::cel::context::build_request_context(
            "GET",
            "/v1/chat",
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "anonymous");
        ctx
    }

    /// Like [`context`], with the method and path under the caller's
    /// control, for coverage tests that need to steer which branch of a
    /// rule body a request takes.
    fn ctx_for(method: &str, path: &str) -> CelContext {
        let mut ctx = crate::cel::context::build_request_context(
            method,
            path,
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "anonymous");
        ctx
    }

    #[test]
    fn a_malformed_module_is_a_config_error_naming_the_site() {
        let error = CompiledRego::compile(
            "policy `rego` (authz)",
            "this is not rego !!!",
            "data.x",
            50,
            None,
            false,
        )
        .expect_err("a malformed module must not compile");
        assert!(error.to_string().contains("policy `rego` (authz)"));
    }

    #[test]
    fn a_rule_decides_from_the_shared_context() {
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let mut ctx = context();
        assert!(
            !policy.eval_bool(&ctx).expect("evaluates"),
            "an anonymous request to /v1/chat matches neither rule"
        );

        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "strong");
        assert!(
            policy.eval_bool(&ctx).expect("evaluates"),
            "a strong trust tier matches the first rule"
        );
    }

    #[test]
    fn a_rule_reads_a_base_data_document() {
        // The OPA data/input split: the module logic references
        // `data.allowed_methods` while the table lives in a separate
        // config value. A request whose method is in the table passes;
        // one that is not is denied.
        const METHOD_ALLOWLIST: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == data.allowed_methods[_]
}
"#;
        let data = serde_json::json!({ "allowed_methods": ["GET", "HEAD"] });
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            METHOD_ALLOWLIST,
            "data.sbproxy.allow",
            50,
            Some(data),
            false,
        )
        .expect("a module reading base data compiles");
        // context() builds a GET, which is in the table.
        let ctx = context();
        assert!(
            policy.eval_bool(&ctx).expect("evaluates"),
            "GET is in the base-data allowlist"
        );

        // A method not in the table is denied, proving the rule really
        // consulted `data` rather than passing everything.
        let mut post_ctx = crate::cel::context::build_request_context(
            "POST",
            "/v1/chat",
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut post_ctx, "anonymous");
        assert!(
            !policy.eval_bool(&post_ctx).expect("evaluates"),
            "POST is not in the base-data allowlist"
        );
    }

    #[test]
    fn base_data_shadowing_the_queried_rule_refuses_at_load() {
        // The Regorus base-over-virtual override: a data key at the
        // query path silently clobbers the rule. Refuse it at load.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "allow": true } })),
            false,
        )
        .expect_err("base data at the query path must refuse");
        assert!(
            error.to_string().contains("would override the rule"),
            "{error}"
        );
    }

    #[test]
    fn base_data_at_a_sibling_path_is_allowed() {
        // Data under the same package but a different leaf than the
        // queried rule does not shadow it and must load.
        CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "roles": ["admin"] } })),
            false,
        )
        .expect("sibling base data does not shadow the rule");
    }

    /// The query's rule is one hop from the shadowed helper: `allow`
    /// reads `trusted`, and `trusted` is what base data defines.
    const ALLOW_VIA_TRUSTED: &str = r#"
package sbproxy

default trusted := false

trusted if {
    input.request.trust_tier == "strong"
}

default allow := false

allow if {
    trusted
}
"#;

    #[test]
    fn base_data_shadowing_a_helper_rule_refuses_at_load() {
        // WOR-2428, the whole ticket. The base document names no rule
        // the query names, so the query-path check passes it, and then
        // Regorus resolves `data.sbproxy.trusted` out of the base
        // document instead of running the `trusted` rule. `allow` keeps
        // evaluating and keeps returning true for every request,
        // including the anonymous one the rule was written to deny.
        // Without the rule-head enumeration this compiles and
        // `eval_bool` returns true for an anonymous request.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_VIA_TRUSTED,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "trusted": true } })),
            false,
        )
        .expect_err("base data at a helper rule's path must refuse");
        let message = error.to_string();
        assert!(
            message.contains("base data defines `data.sbproxy.trusted`"),
            "the refusal names the shadowing data path: {message}"
        );
        assert!(
            message.contains("data.sbproxy.allow -> data.sbproxy.trusted"),
            "the refusal shows how the query reaches the shadowed rule: {message}"
        );
    }

    #[test]
    fn the_shadow_check_follows_more_than_one_hop() {
        // The direct case is one comparison; the transitive case is a
        // graph. Three rules deep, so a fix that only looked at the
        // query's immediate references would still miss this.
        const THREE_HOPS: &str = r#"
package sbproxy

default strong_tier := false

strong_tier if {
    input.request.trust_tier == "strong"
}

default trusted := false

trusted if {
    strong_tier
}

default allow := false

allow if {
    trusted
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            THREE_HOPS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "strong_tier": true } })),
            false,
        )
        .expect_err("base data two hops from the query must refuse");
        assert!(
            error
                .to_string()
                .contains("data.sbproxy.allow -> data.sbproxy.trusted -> data.sbproxy.strong_tier"),
            "the refusal walks the whole chain: {error}"
        );
    }

    #[test]
    fn a_shadowed_helper_the_query_does_not_reach_still_refuses() {
        // Regorus resolves the base document against a rule's own path,
        // not the query's, so an unreferenced rule is shadowed just as
        // readily. It is dead config either way, and it goes live the
        // moment somebody calls it, so it refuses with the reachability
        // stated rather than implied. Stated as a failed search, not as
        // an absence: see the parent-path test below for why the walk
        // cannot claim nothing reaches a rule.
        const UNREFERENCED_HELPER: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
}

default audited := false

audited if {
    input.request.method == "POST"
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            UNREFERENCED_HELPER,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "audited": true } })),
            false,
        )
        .expect_err("a shadowed rule refuses whether or not the query reaches it");
        let message = error.to_string();
        assert!(
            message.contains("base data defines `data.sbproxy.audited`"),
            "{message}"
        );
        assert!(
            message.contains("No reference chain from the query `data.sbproxy.allow` was found"),
            "the refusal reports a failed search rather than inventing a chain: {message}"
        );
        assert!(
            !message.contains("No reference in the module reaches it"),
            "the refusal does not assert an absence the walk cannot prove: {message}"
        );
    }

    #[test]
    fn a_reference_to_a_parent_path_reaches_every_rule_under_it() {
        // Reading `data.sbproxy.denies` evaluates every `denies[...]`
        // rule in the package, so the query does reach the shadowed one.
        // Following only references at or below a head made this print
        // "the collision is latent until a rule calls it" about a deny
        // the base document had already neutralized, which sends the
        // operator looking for the bug in the wrong module.
        const EVERY_OVER_A_PARENT: &str = r#"
package sbproxy

default allow := false

allow if {
    every _, v in data.sbproxy.denies {
        v == false
    }
}

denies["path_traversal"] := true if {
    contains(input.request.path, "..")
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            EVERY_OVER_A_PARENT,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({
                "sbproxy": { "denies": { "path_traversal": false } }
            })),
            false,
        )
        .expect_err("base data at a rule under a read parent path must refuse");
        let message = error.to_string();
        assert!(
            message.contains("base data defines `data.sbproxy.denies.path_traversal`"),
            "{message}"
        );
        assert!(
            message.contains("data.sbproxy.allow -> data.sbproxy.denies.path_traversal"),
            "the refusal shows the query reaching the rule through the parent path: {message}"
        );
    }

    #[test]
    fn a_query_deeper_than_a_rule_head_still_gets_a_chain() {
        // The query is a reference too, so it resolves to the rules it
        // reads the same way one inside a module does. Querying a key of
        // a partial rule starts the walk at a path no head equals, and
        // the walk used to miss on the first pop and print no chain at
        // all for a collision it was refusing.
        const PARTIAL_OBJECT: &str = r#"
package sbproxy

limits[method] := "yes" if {
    method := input.request.method
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            PARTIAL_OBJECT,
            "data.sbproxy.limits.GET",
            50,
            Some(serde_json::json!({ "sbproxy": { "limits": { "POST": "no" } } })),
            false,
        )
        .expect_err("base data at the partial rule's prefix must refuse");
        let message = error.to_string();
        assert!(
            message.contains("The query `data.sbproxy.limits.GET` reaches it: data.sbproxy.limits"),
            "the refusal resolves the query to the rule it reads: {message}"
        );
    }

    #[test]
    fn a_json_null_shadows_a_rule_the_same_way_a_value_does() {
        // Regorus keeps the base document's value for anything other
        // than undefined, and `add_data`'s merge carries a JSON null
        // through as defined. A check that skipped nulls would let the
        // cheapest possible shadow straight past.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_VIA_TRUSTED,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "trusted": null } })),
            false,
        )
        .expect_err("a null at a rule path must refuse");
        assert!(
            error.to_string().contains("data.sbproxy.trusted"),
            "{error}"
        );
    }

    #[test]
    fn base_data_below_a_rule_path_shadows_it() {
        // The rule's path is what Regorus compares, so a document that
        // only defines something *under* the rule still makes the rule's
        // own path defined, and the rule loses.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_VIA_TRUSTED,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "trusted": { "reason": "vendor" } } })),
            false,
        )
        .expect_err("base data below a rule path must refuse");
        assert!(
            error.to_string().contains("data.sbproxy.trusted"),
            "{error}"
        );
    }

    #[test]
    fn a_non_object_above_a_rule_path_refuses_with_that_reason() {
        // The other prefix direction. An object at `data.sbproxy` merges
        // with the rules beneath it, which is the sibling case above; a
        // scalar there leaves them nowhere to land, and Regorus reports
        // it as an opaque "previous value is not an object" mid
        // evaluation if it reports it at all.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": 5 })),
            false,
        )
        .expect_err("a scalar above a rule path must refuse");
        let message = error.to_string();
        assert!(
            message.contains("base data sets `data.sbproxy` to a value that is not an object"),
            "{message}"
        );
        assert!(message.contains("data.sbproxy.allow"), "{message}");
    }

    #[test]
    fn a_partial_rule_is_compared_by_its_literal_prefix() {
        // `limits[method]` resolves to a different path on every
        // evaluation, so only `data.sbproxy.limits` is known at load.
        // Regorus's own `get_path_ref_components` would report the path
        // as `limits.method`, taking the variable's spelling for a key,
        // and would miss this document entirely.
        const PARTIAL_OBJECT: &str = r#"
package sbproxy

default allow := false

allow if {
    limits[input.request.method] == "yes"
}

limits[method] := "yes" if {
    method := "GET"
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            PARTIAL_OBJECT,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "limits": { "GET": "no" } } })),
            false,
        )
        .expect_err("base data over a partial rule's own path must refuse");
        let message = error.to_string();
        assert!(
            message.contains("base data defines keys under `data.sbproxy.limits`"),
            "{message}"
        );
        assert!(
            !message.contains("the rule never evaluates"),
            "a computed-key head cannot be said to never evaluate: {message}"
        );
    }

    /// `limits[method]` with the key computed from the request, so
    /// nothing at load knows which keys the rule produces.
    const COMPUTED_KEYS: &str = r#"
package sbproxy

default allow := false

allow if {
    limits[input.request.method] == "yes"
}

limits[method] := "yes" if {
    method := input.request.method
}
"#;

    #[test]
    fn a_computed_key_head_refuses_even_when_the_base_keys_are_disjoint() {
        // The deliberate false refusal, pinned so it stays deliberate.
        // Regorus indexes `data.sbproxy.limits.POST`, one segment deeper
        // than the head names, so base `POST` merges with a computed
        // `GET` and this config would have worked. Load time cannot tell
        // it from base `GET` beside the same rule, which kills the
        // rule's only output silently, so the refusal keeps the wide
        // side and the message stops at what the detector saw: it says
        // the base keys win, not that the rule never runs.
        let error = CompiledRego::compile(
            "policy `rego`",
            COMPUTED_KEYS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "limits": { "POST": "no" } } })),
            false,
        )
        .expect_err("a computed-key head refuses on any key the base document defines");
        let message = error.to_string();
        assert!(
            message.contains(
                "the module defines a rule that computes its own keys at that path, so every key \
                 the base document already carries wins over the rule's"
            ),
            "{message}"
        );
        assert!(
            message.contains("cannot be narrowed at config load"),
            "the refusal says why it cannot be precise: {message}"
        );
        assert!(
            !message.contains("the rule never evaluates"),
            "the refusal claims nothing about the rule not running: {message}"
        );
    }

    #[test]
    fn an_empty_base_object_over_a_computed_key_head_loads() {
        // The one sub-case a computed-key head compares precisely: an
        // empty object holds no key that can beat a computed one, so it
        // merges and nothing is shadowed. Comparing the literal prefix
        // alone refused this.
        CompiledRego::compile(
            "policy `rego`",
            COMPUTED_KEYS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "limits": {} } })),
            false,
        )
        .expect("an empty base object cannot shadow a computed key");
    }

    #[test]
    fn a_scalar_over_a_computed_key_head_says_the_keys_cannot_land() {
        // `update_rule_value` walks the full path with `as_object_mut`
        // and fails with "previous value is not an object" mid
        // evaluation, so the rule is blocked rather than shadowed. The
        // prefix comparison called this a shadow and told the operator
        // the base document resolves in the rule's place, which is not
        // what happens.
        let error = CompiledRego::compile(
            "policy `rego`",
            COMPUTED_KEYS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "limits": 5 } })),
            false,
        )
        .expect_err("a scalar at a computed-key head's path must refuse");
        let message = error.to_string();
        assert!(
            message.contains(
                "base data sets `data.sbproxy.limits` to a value that is not an object, and the \
                 module defines a rule that computes its own keys at that path, so no key the \
                 rule produces has anywhere to land"
            ),
            "{message}"
        );
    }

    #[test]
    fn base_data_beside_a_function_of_the_same_name_is_allowed() {
        // A function that takes parameters lives in the function table,
        // not under `data`, so nothing resolves the base document
        // against its name. Refusing this would be the detector running
        // wider than the behavior it guards.
        const FUNCTION_HELPER: &str = r#"
package sbproxy

default allow := false

allow if {
    permitted(input.request.method)
}

permitted(method) if {
    method == "GET"
}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            FUNCTION_HELPER,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "permitted": "not a rule path" } })),
            false,
        )
        .expect("base data cannot shadow a function that takes parameters");
        assert!(
            policy
                .eval_bool(&ctx_for("GET", "/v1/chat"))
                .expect("evaluates"),
            "the function still decides"
        );
    }

    #[test]
    fn base_data_over_a_zero_argument_function_refuses() {
        // The other side of `!args.is_empty()`. A function with no
        // parameters is not in the function table: Regorus's `Func` arm
        // routes it through `update_data`, which keeps the base
        // document's value at the same path, so it is shadowable exactly
        // like a rule. Simplifying the arm to a plain `RuleHead::Func`
        // match reads as a cleanup and drops every zero-argument
        // function out of `shadowable`, which is WOR-2428 reintroduced
        // for that one rule shape.
        const ZERO_ARG_FUNCTION: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
}

audit_enabled() := true
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            ZERO_ARG_FUNCTION,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "audit_enabled": false } })),
            false,
        )
        .expect_err("base data at a zero-argument function's path must refuse");
        assert!(
            error
                .to_string()
                .contains("base data defines `data.sbproxy.audit_enabled`"),
            "{error}"
        );
    }

    #[test]
    fn base_data_beside_a_default_function_of_the_same_name_is_allowed() {
        // `Rule::Default` carries its own `args`, and a default with
        // parameters is a function default: `eval_default_rule` returns
        // early for it and the value is served from the function table,
        // never written under `data`. Every other default-rule test in
        // this file uses a parameterless default, so nothing else pins
        // this arm and a detector that treated a default function as
        // shadowable would refuse a config Regorus runs correctly.
        const DEFAULT_FUNCTION: &str = r#"
package sbproxy

default allow := false

allow if {
    permitted(input.request.method)
}

default permitted(_) := false

permitted(method) if {
    method == "GET"
}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            DEFAULT_FUNCTION,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "permitted": "not a rule path" } })),
            false,
        )
        .expect("base data cannot shadow a default function that takes parameters");
        assert!(
            policy
                .eval_bool(&ctx_for("GET", "/v1/chat"))
                .expect("evaluates"),
            "the function still decides"
        );
        assert!(
            !policy
                .eval_bool(&ctx_for("POST", "/v1/chat"))
                .expect("evaluates"),
            "the default answers for a method the function does not permit"
        );
    }

    #[test]
    fn a_base_data_refusal_is_counted_on_the_compile_metric() {
        // A refusal that exists only as a returned error is invisible to
        // an operator watching whether their rego policies still
        // compile: the fleet goes to zero working policies and the
        // series stays flat. Both base-data refusals count on the same
        // family every other compile outcome uses.
        let before = compile_result_count("rego", "semantic_error");

        CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "allow": true } })),
            false,
        )
        .expect_err("base data at the query path must refuse");

        CompiledRego::compile(
            "policy `rego`",
            ALLOW_VIA_TRUSTED,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "trusted": true } })),
            false,
        )
        .expect_err("base data at a helper rule's path must refuse");

        // At least, not exactly: the counter is process wide, and under
        // a threaded `cargo test` another rego test can land between the
        // two reads. Under nextest's process per test it is exactly two.
        assert!(
            compile_result_count("rego", "semantic_error") >= before + 2.0,
            "both base-data refusals count on sbproxy_script_compile_total"
        );
    }

    /// The current value of `sbproxy_script_compile_total` for one
    /// engine and result, or zero before the series exists.
    fn compile_result_count(engine: &str, result: &str) -> f64 {
        sbproxy_observe::metrics::metrics()
            .render()
            .lines()
            .find_map(|line| {
                if !line.starts_with("sbproxy_script_compile_total")
                    || !line.contains(&format!("engine=\"{engine}\""))
                    || !line.contains(&format!("result=\"{result}\""))
                {
                    return None;
                }
                line.split_whitespace().nth(1)?.parse().ok()
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn the_input_document_is_the_cel_context_verbatim() {
        // The parity guarantee. If these drift, a policy moved between
        // engines reads undefined where it used to read a value, and
        // Rego will not say so.
        let ctx = context();
        let input = context_to_input(&ctx);
        let object = input.as_object().expect("input is an object");
        for root in ctx.variables.keys() {
            assert!(
                object.contains_key(root),
                "`{root}` is in the CEL context but missing from the Rego input"
            );
        }
        assert_eq!(
            object.len(),
            ctx.variables.len(),
            "the input document must not invent roots the CEL context does not have"
        );
        assert_eq!(
            input["request"]["trust_tier"],
            serde_json::json!("anonymous"),
            "a nested binding must survive the conversion"
        );
    }

    #[test]
    fn a_non_boolean_rule_is_an_error_rather_than_a_guess() {
        const RETURNS_A_DOCUMENT: &str = r#"
package sbproxy

allow := {"reason": "because"}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            RETURNS_A_DOCUMENT,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let error = policy
            .eval_bool(&context())
            .expect_err("a document is not a verdict");
        assert!(
            error.to_string().contains("rather than a boolean"),
            "{error}"
        );
    }

    #[test]
    fn eval_bool_json_evaluates_the_pinned_query_against_arbitrary_json() {
        // The JSON-input twin `RegoPolicyAdapter` (a bundled Rego
        // policy hook, WOR-2482) calls instead of `eval_bool`: no
        // `CelContext` involved, just the JSON envelope a bundle hook
        // already builds.
        let mut policy = CompiledRego::compile(
            "bundle `rego-authz` policy `rego_authz`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let denied = policy
            .eval_bool_json(
                serde_json::json!({"request": {"method": "POST", "path": "/v1/chat"}}),
                "",
            )
            .expect("evaluates");
        assert!(!denied, "no rule matches a bare POST with no trust_tier");

        let allowed = policy
            .eval_bool_json(
                serde_json::json!({"request": {"method": "GET", "path": "/health"}}),
                "",
            )
            .expect("evaluates");
        assert!(allowed, "GET /health matches the health-check rule");
    }

    #[test]
    fn eval_bool_json_rejects_a_non_boolean_rule_the_same_as_eval_bool() {
        const RETURNS_A_DOCUMENT: &str = r#"
package sbproxy

allow := {"reason": "because"}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            RETURNS_A_DOCUMENT,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let error = policy
            .eval_bool_json(serde_json::json!({}), "")
            .expect_err("a document is not a verdict");
        assert!(
            error.to_string().contains("rather than a boolean"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_rule_is_refused_at_load_rather_than_denying_forever() {
        // Now a *load* error rather than a runtime one: a query naming
        // no rule used to parse clean and then deny every request
        // forever, with a warn line as the only explanation.
        CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.nonexistent",
            50,
            None,
            false,
        )
        .expect_err("a query naming no rule must not load");
    }

    #[test]
    fn a_module_that_parses_but_cannot_be_analysed_is_refused_at_load() {
        // `add_policy` parses and stops; scheduling and safety analysis
        // run on first evaluation. Without the trial evaluation in
        // `compile`, this module booted fine and then denied every
        // request to its origin permanently.
        const UNSAFE_VAR: &str = r#"
package sbproxy

allow if {
    x == 1
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            UNSAFE_VAR,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect_err("an unsafe variable must not load");
        let message = format!("{error:#}");
        assert!(message.contains("semantic fault"), "{message}");
        assert!(
            !message.contains("time limit"),
            "a semantic fault must not be described as a time-limit miss: {message}"
        );
    }

    #[test]
    fn a_load_time_trial_timeout_is_inconclusive_not_a_semantic_fault() {
        // WOR-2708: `prove_evaluable` used to wrap every `eval_rule`
        // error as an unsafe-variable / missing-rule fault and refuse
        // compile. A trial that only ran out of `budget_ms` is not that
        // fault. The module is evaluable; the trial did not finish. Boot
        // must proceed, and the same budget still denies at request time.
        const SLOW_ALLOW: &str = r#"
package sbproxy

allow if {
    count([x | x := numbers.range(1, 3000000)[_]]) > 0
}
"#;
        let compiled = CompiledRego::compile(
            "policy `rego`",
            SLOW_ALLOW,
            "data.sbproxy.allow",
            5,
            None,
            false,
        );
        assert!(
            compiled.is_ok(),
            "a trial that exceeds budget_ms must not refuse compile: {}",
            compiled
                .err()
                .map(|error| format!("{error:#}"))
                .unwrap_or_default()
        );

        const UNSAFE_VAR: &str = r#"
package sbproxy

allow if {
    x == 1
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            UNSAFE_VAR,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect_err("an unsafe variable must still refuse at load");
        let message = format!("{error:#}");
        assert!(message.contains("semantic fault"), "{message}");
        assert!(
            !message.contains("time limit"),
            "a semantic fault must not be described as a time-limit miss: {message}"
        );
    }

    #[test]
    fn a_non_finite_float_becomes_null_rather_than_panicking() {
        let mut ctx = CelContext::new();
        ctx.set("score", CelValue::Float(f64::NAN));
        assert_eq!(context_to_input(&ctx)["score"], serde_json::Value::Null);
    }

    // --- rego_v0 ---

    #[test]
    fn rego_v0_true_accepts_pre_v1_syntax_the_v1_default_refuses() {
        // The exact shape Regorus's own `set_rego_v0` doctest uses: a
        // rule body with no `if`, valid before OPA 1.0 and rejected by
        // Regorus's v1 default the same way current OPA is.
        const V0_STYLE: &str = r#"
package sbproxy

allow {
    input.request.method == "GET"
}
"#;
        CompiledRego::compile(
            "policy `rego`",
            V0_STYLE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect_err("v0 syntax must not compile under the v1 default");

        let mut accepted = CompiledRego::compile(
            "policy `rego`",
            V0_STYLE,
            "data.sbproxy.allow",
            50,
            None,
            true,
        )
        .expect("rego_v0: true compiles the same module");
        assert!(
            accepted.eval_bool(&context()).expect("evaluates"),
            "the v0 rule still decides once it parses"
        );
    }

    // --- coverage ---

    #[test]
    fn coverage_report_reflects_which_branch_a_case_took() {
        // Two comparisons in one rule body, AND-joined, so Rego's own
        // short-circuit semantics (not a Regorus implementation detail)
        // guarantee the second is skipped whenever the first fails.
        // That guarantee is what this test leans on, rather than a
        // hardcoded line number for what Regorus's coverage attributes
        // to a bare `allow if {` declaration line.
        const MODULE: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
    input.request.path == "/health"
}
"#;
        let method_line = MODULE
            .lines()
            .position(|line| line.contains("input.request.method"))
            .map(|index| index as u32 + 1)
            .expect("fixture has a method comparison line");
        let path_line = MODULE
            .lines()
            .position(|line| line.contains("input.request.path"))
            .map(|index| index as u32 + 1)
            .expect("fixture has a path comparison line");
        assert_ne!(method_line, path_line);

        let mut both_match = CompiledRego::compile(
            "coverage test",
            MODULE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        both_match.set_enable_coverage(true);
        assert!(
            both_match
                .eval_bool(&ctx_for("GET", "/health"))
                .expect("evaluates"),
            "a GET to /health matches both conditions"
        );
        let report = both_match.coverage_report().expect("coverage report");
        assert_eq!(report.len(), 1, "one module was compiled");
        assert_eq!(report[0].path, "coverage test.rego");
        assert!(
            report[0].covered.contains(&method_line) && report[0].covered.contains(&path_line),
            "both comparisons execute when both match: {:?}",
            report[0]
        );

        let mut short_circuits = CompiledRego::compile(
            "coverage test",
            MODULE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        short_circuits.set_enable_coverage(true);
        assert!(
            !short_circuits
                .eval_bool(&ctx_for("POST", "/health"))
                .expect("evaluates"),
            "a POST never matches"
        );
        let report = short_circuits.coverage_report().expect("coverage report");
        assert!(
            report[0].covered.contains(&method_line),
            "the method comparison still runs and fails: {:?}",
            report[0]
        );
        assert!(
            report[0].not_covered.contains(&path_line),
            "the path comparison is never reached once the method check fails: {:?}",
            report[0]
        );
        assert!(
            report[0].percent() < 100.0,
            "an unreached line must pull coverage below full: {:?}",
            report[0]
        );
    }

    // --- print() capture ---
    //
    // A hand-rolled `tracing::Subscriber` rather than `tracing-subscriber`,
    // which this crate does not depend on; mirrors
    // `bundle::proxy_wasm::tests::GuestLogLevelCapture`, the existing
    // in-crate tracing-capture pattern. Installed via
    // `tracing::subscriber::with_default` around the one evaluation under
    // test, with `rebuild_interest_cache` forced afterward so a callsite
    // whose Interest cached `Never` under an earlier no-subscriber run
    // cannot stay stuck (see the span-metadata test landmine: a callsite's
    // Interest is cached process-wide, not per test).

    #[derive(Debug, Default, Clone)]
    struct CapturedPrint {
        level: Option<tracing::Level>,
        site: String,
        query: String,
        tenant_id: String,
        message: String,
    }

    impl CapturedPrint {
        fn set(&mut self, name: &str, value: String) {
            match name {
                "site" => self.site = value,
                "query" => self.query = value,
                "tenant_id" => self.tenant_id = value,
                "message" => self.message = value,
                _ => {}
            }
        }
    }

    impl tracing::field::Visit for CapturedPrint {
        // `tenant_id` is passed as a bare `&str`, which tracing routes
        // through `record_str`.
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.set(field.name(), value.to_owned());
        }

        // `site`, `query` (`%`-prefixed) and the format-string `message`
        // field all route through `record_debug`; the `%` wrapper's
        // `Debug` impl is defined in terms of the wrapped type's
        // `Display`, so this renders identically to `record_str` would.
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.set(field.name(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct RegoPrintCapture {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedPrint>>>,
    }

    impl tracing::Subscriber for RegoPrintCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "rego_print"
        }

        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "rego_print" {
                return;
            }
            let mut captured = CapturedPrint {
                level: Some(*event.metadata().level()),
                ..Default::default()
            };
            event.record(&mut captured);
            self.events.lock().unwrap().push(captured);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[test]
    fn print_reaches_tracing_at_info_under_rego_print_never_stderr() {
        const PRINTS_WHEN_CHECKED: &str = r#"
package sbproxy

default allow := false

allow if {
    print("checking method:", input.request.method)
    input.request.method == "GET"
}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego` (print-test)",
            PRINTS_WHEN_CHECKED,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");

        let mut ctx = context();
        crate::cel::context::populate_principal_namespace(
            &mut ctx,
            &crate::cel::context::PrincipalView {
                tenant_id: Some("acme"),
                ..Default::default()
            },
        );

        let capture = RegoPrintCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            assert!(
                policy.eval_bool(&ctx).expect("evaluates"),
                "a GET from api.example.com still decides true"
            );
        });

        let events = capture.events.lock().expect("capture lock");
        assert_eq!(
            events.len(),
            1,
            "one print() call must produce exactly one event: {events:?}"
        );
        let event = &events[0];
        assert_eq!(event.level, Some(tracing::Level::INFO), "{event:?}");
        assert_eq!(event.site, "policy `rego` (print-test)", "{event:?}");
        assert_eq!(event.query, "data.sbproxy.allow", "{event:?}");
        assert_eq!(
            event.tenant_id, "acme",
            "the tenant on the evaluated context reaches the event: {event:?}"
        );
        assert!(
            event.message.contains("checking method"),
            "the print() text reaches the event: {event:?}"
        );
    }

    #[test]
    fn trial_evaluation_prints_are_discarded_not_logged() {
        // `compile`'s load-time trial (`prove_evaluable`) runs this same
        // query against an empty input at every boot and reload, whether
        // or not the policy ever sees real traffic. The print here does
        // not depend on `input`, so it fires identically on the trial
        // and on a real evaluation; only the trial's `take_prints()` is
        // discarded rather than drained through `tracing`. This pins
        // that split so a future refactor cannot fold the trial into
        // `drain_prints` and start misattributing boot-time trial prints
        // as request-scoped `rego_print` events.
        const ALWAYS_PRINTS: &str = r#"
package sbproxy

default allow := false

allow if {
    print("trial or real, always prints")
    true
}
"#;
        let capture = RegoPrintCapture::default();

        let mut policy = tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            CompiledRego::compile(
                "policy `rego` (trial-print-test)",
                ALWAYS_PRINTS,
                "data.sbproxy.allow",
                50,
                None,
                false,
            )
            .expect("module compiles")
        });
        assert!(
            capture.events.lock().expect("capture lock").is_empty(),
            "compile's load-time trial must not produce a rego_print event: {:?}",
            capture.events.lock().expect("capture lock")
        );

        tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            assert!(
                policy.eval_bool(&context()).expect("evaluates"),
                "the rule decides true on a real evaluation too"
            );
        });
        let events = capture.events.lock().expect("capture lock");
        assert_eq!(
            events.len(),
            1,
            "a real evaluation of the same print() must produce exactly one event: {events:?}"
        );
        assert!(
            events[0].message.contains("trial or real, always prints"),
            "{:?}",
            events[0]
        );
    }

    /// Regorus's `http.send` is a stub returning `Undefined`
    /// (`regorus-0.11.0/src/builtins/http.rs`), so a bundled Rego module
    /// has no network primitive. `Engine::new()` is bare: no builtin
    /// denylist, no strict mode, nothing in this repository that pins
    /// that stub.
    ///
    /// This test is that pin. If it fails, `http.send` now reaches the
    /// network from inside operator-supplied policy code, and none of
    /// the calls go through sbproxy's SSRF guard, its grant system, or
    /// its egress logging.
    ///
    /// Deliberately not paired with an exact `=0.11.0` version pin:
    /// freezing the dependency would trade a silent behavior change for
    /// silently missing regorus's own security patches, and this test
    /// catches a patch release that implements the builtin exactly as
    /// well as it catches a minor bump.
    #[test]
    fn http_send_is_not_a_network_primitive_for_bundled_rego() {
        const PROBE: &str = r#"
package sbproxy

probe := http.send({"method": "get", "url": "http://127.0.0.1:1/"})
"#;
        let mut compiled =
            CompiledRego::compile("ssrf-pin", PROBE, "data.sbproxy.probe", 1_000, None, false)
                .expect("the probe module compiles");

        let value = compiled
            .eval_value(serde_json::json!({}), "")
            .expect("the probe evaluates");

        assert_eq!(
            value,
            serde_json::Value::Null,
            "regorus implemented `http.send`. Every installed Rego bundle can now make \
             outbound HTTP calls from inside policy evaluation, and none of them pass \
             through sbproxy's SSRF guard, its `net:outbound` grants, or its egress \
             logging. Do not ship this dependency bump: either hold the version, or add \
             a builtin denylist to `CompiledRego::compile` before it lands. Observed: \
             {value:?}"
        );
    }

    #[test]
    fn a_print_message_is_truncated_on_a_char_boundary() {
        // A transform hook's input is the complete response body, so an
        // unbounded print is a copy of every response into the log.
        let long = "x".repeat(MAX_PRINT_MESSAGE_BYTES * 4);
        let (message, truncated) = truncate_print_message(&long);
        assert!(truncated);
        assert_eq!(message.len(), MAX_PRINT_MESSAGE_BYTES);

        // A multibyte char straddling the cut must not panic or split.
        let multibyte = "\u{00e9}".repeat(MAX_PRINT_MESSAGE_BYTES);
        let (message, truncated) = truncate_print_message(&multibyte);
        assert!(truncated);
        assert!(message.len() <= MAX_PRINT_MESSAGE_BYTES);
        assert!(multibyte.starts_with(message));

        let short = "under the cap";
        assert_eq!(truncate_print_message(short), (short, false));
    }

    #[test]
    fn a_print_message_carrying_a_credential_is_redacted() {
        let redacted = sbproxy_observe::redact::redact_secrets(
            "leaking sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA now",
        );
        let (message, _) = truncate_print_message(&redacted);
        assert!(
            !message.contains("api03-AAAA"),
            "a print() of a body carrying a credential must not reach the log: {message}"
        );
    }
}
