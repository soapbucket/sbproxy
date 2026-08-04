// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Build-time coverage for configuration keys.
//!
//! The generated JSON Schema is the authoritative list of accepted key paths.
//! This module walks that schema, then looks for a production Rust field read
//! for every path. Keys consumed indirectly through generic deserialization
//! may use a reviewed stable override; deliberately inert keys use a
//! `ConfigOnly` override with an operator-facing reason.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use syn::visit::Visit;

use crate::scan::{
    attributes_exclude_production, production_cfg_condition_possibility, SourceFile,
};
use crate::{validate_config_keys, ConfigKeyCapability, RegistryError, SupportLevel};

/// One leaf key reached from the root of the generated configuration schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigSchemaKey {
    /// Canonical dotted path. Dynamic map keys use `*`; array elements use
    /// `[]`, for example `origins.*.routes[].path`.
    pub path: String,
    /// Best-effort Rust field name derived from the serialized property.
    pub rust_field: String,
    /// Rust type that owns the field, derived from the schema definition that
    /// declares the property.
    pub rust_owner: Option<String>,
}

/// Walk a generated JSON Schema and return every leaf property reachable from
/// its root.
///
/// Local references, object maps, arrays, and schema compositions are
/// followed. Definitions are not listed on their own: a definition contributes
/// keys only when the root configuration actually references it.
pub fn schema_key_paths(schema: &Value) -> Vec<ConfigSchemaKey> {
    let mut out = BTreeSet::new();
    let mut refs = Vec::new();
    let owner = schema.get("title").and_then(Value::as_str);
    collect_schema(schema, schema, "", owner, None, &mut refs, &mut out);
    out.into_iter().collect()
}

#[derive(Clone, Copy)]
struct LeafOwner<'a> {
    rust_field: &'a str,
    rust_owner: Option<&'a str>,
}

fn collect_schema(
    root: &Value,
    node: &Value,
    path: &str,
    owner: Option<&str>,
    leaf_owner: Option<LeafOwner<'_>>,
    refs: &mut Vec<String>,
    out: &mut BTreeSet<ConfigSchemaKey>,
) {
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        if !refs.iter().any(|active| active == reference) {
            if let Some(target) = local_ref(root, reference) {
                refs.push(reference.to_string());
                collect_schema(
                    root,
                    target,
                    path,
                    ref_owner(reference),
                    leaf_owner,
                    refs,
                    out,
                );
                refs.pop();
            }
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(parts) = node.get(keyword).and_then(Value::as_array) {
            for part in parts {
                collect_schema(root, part, path, owner, leaf_owner, refs, out);
            }
        }
    }
    for keyword in ["if", "then", "else", "not"] {
        if let Some(part) = node.get(keyword) {
            collect_schema(root, part, path, owner, leaf_owner, refs, out);
        }
    }

    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            let child_path = join_path(path, name);
            let rust_field = rust_field_name(name);
            let child_leaf_owner = LeafOwner {
                rust_field: &rust_field,
                rust_owner: owner,
            };
            let mut descendants = BTreeSet::new();
            collect_schema(
                root,
                child,
                &child_path,
                owner,
                Some(child_leaf_owner),
                refs,
                &mut descendants,
            );
            if descendants.is_empty() {
                out.insert(ConfigSchemaKey {
                    path: child_path,
                    rust_field,
                    rust_owner: owner.map(str::to_string),
                });
            } else {
                out.extend(descendants);
            }
        }
    }

    if let Some(items) = node.get("items") {
        let item_path = format!("{path}[]");
        match items {
            Value::Array(variants) => {
                for variant in variants {
                    collect_schema_or_leaf(root, variant, &item_path, owner, leaf_owner, refs, out);
                }
            }
            _ => collect_schema_or_leaf(root, items, &item_path, owner, leaf_owner, refs, out),
        }
    }

    if let Some(additional) = node.get("additionalProperties") {
        if additional.is_object() || additional == &Value::Bool(true) {
            let value_path = if path.is_empty() {
                "*".to_string()
            } else {
                format!("{path}.*")
            };
            collect_schema_or_leaf(root, additional, &value_path, owner, leaf_owner, refs, out);
        }
    }

    if let Some(patterns) = node.get("patternProperties").and_then(Value::as_object) {
        let value_path = if path.is_empty() {
            "*".to_string()
        } else {
            format!("{path}.*")
        };
        for child in patterns.values() {
            collect_schema_or_leaf(root, child, &value_path, owner, leaf_owner, refs, out);
        }
    }
}

fn collect_schema_or_leaf(
    root: &Value,
    node: &Value,
    path: &str,
    owner: Option<&str>,
    leaf_owner: Option<LeafOwner<'_>>,
    refs: &mut Vec<String>,
    out: &mut BTreeSet<ConfigSchemaKey>,
) {
    let mut descendants = BTreeSet::new();
    collect_schema(root, node, path, owner, leaf_owner, refs, &mut descendants);
    if descendants.is_empty() {
        if let Some(leaf_owner) = leaf_owner {
            descendants.insert(ConfigSchemaKey {
                path: path.to_string(),
                rust_field: leaf_owner.rust_field.to_string(),
                rust_owner: leaf_owner.rust_owner.map(str::to_string),
            });
        }
    }
    out.extend(descendants);
}

fn ref_owner(reference: &str) -> Option<&str> {
    reference
        .rsplit('/')
        .next()
        .filter(|owner| !owner.is_empty())
}

fn local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let fragment = reference.strip_prefix('#')?;
    if fragment.is_empty() {
        return Some(root);
    }
    root.pointer(fragment)
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}.{name}")
    }
}

fn rust_field_name(serialized: &str) -> String {
    serialized.replace('-', "_")
}

/// How much of a declared module root this guard enforces today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleRootEnforcement {
    /// A key under this root with no production read fails the build.
    Enforced,
    /// Findings under this root are reported but not fatal.
    ///
    /// The string says why, in the same voice the `ConfigOnly` notes use,
    /// and names the work that will make the root `Enforced`. A root lands
    /// here when nobody has triaged its existing findings yet: turning it
    /// fatal on day one would fail the build on debt this change did not
    /// create, and a check that does that gets reverted rather than fixed.
    ReportOnly(&'static str),
}

/// One configuration subtree the generated JSON Schema cannot describe.
///
/// `ConfigFile` types `action`, `authentication`, `policies` and
/// `transforms` as `serde_json::Value`, deliberately: modules are pluggable
/// and the config crate must not need to name their types. The cost is that
/// `schemars::schema_for!(ConfigFile)` emits no leaf below any of them, so
/// the entire module and AI-gateway surface is invisible to
/// [`schema_key_paths`] and therefore to [`verify_config_readers`].
///
/// A root closes that hole for one subtree by naming the Rust type the
/// subtree deserializes into. The walk that follows reads the same `syn`
/// index the reader side reads, so the key list and the read list come from
/// one parse of one file rather than from two toolchains that can disagree.
#[derive(Debug, Clone, Copy)]
pub struct ModuleConfigRoot {
    /// Dotted path of the subtree, in the same shape [`ConfigSchemaKey`]
    /// uses: `*` for a map key, `[]` for an array element. This is the
    /// operator's YAML path, because the boot-time `ConfigOnly` warning
    /// matches registry paths against raw YAML.
    pub path: &'static str,
    /// Fully qualified Rust type, as `crate_name::module::Type`.
    pub rust_type: &'static str,
    /// Whether findings under this root fail the build.
    pub enforcement: ModuleRootEnforcement,
}

/// What a reader-coverage run found.
#[derive(Debug, Default)]
pub struct ConfigReaderReport {
    /// Findings that must fail the build.
    pub errors: Vec<RegistryError>,
    /// Findings under a [`ModuleRootEnforcement::ReportOnly`] root, each
    /// carrying that root's reason for not being fatal yet.
    ///
    /// Real, and not yet fatal. Print them; do not assert on them.
    pub reported: Vec<RegistryError>,
    /// Every key the declared module roots produced.
    pub module_keys: Vec<ConfigSchemaKey>,
}

/// Walk the Rust config type graph from one root and collect its leaf keys.
///
/// This is the module-surface twin of [`collect_schema`], and it emits the
/// same [`ConfigSchemaKey`] shape so both key sources feed one check. The
/// difference is the input: [`collect_schema`] reads a generated JSON
/// Schema, this reads the `Deserialize` types themselves, because the types
/// under a module root never reach a schema at all.
///
/// A leaf is emitted for any field whose type this scan cannot descend
/// into: a primitive, a type from outside `crates/`, an opaque
/// `serde_json::Value`, or an enum serde does not tag internally.
fn collect_module_keys(
    index: &RustTypeIndex,
    owner: &str,
    path: &str,
    active: &mut Vec<String>,
    out: &mut BTreeSet<ConfigSchemaKey>,
) {
    // A config type that contains itself (a rule that nests rules, say)
    // repeats key names forever without naming a new field, so the cycle is
    // cut at the first repeat rather than unrolled to some arbitrary depth.
    if active.iter().any(|entry| entry == owner) {
        return;
    }
    active.push(owner.to_string());

    // A flattened field contributes no path segment of its own: serde lifts
    // its fields into the parent object, so an operator writes them at the
    // parent's level. Walked first so the parent's own fields cannot shadow
    // the decision.
    for flattened_field in index.flattened_fields.get(owner).into_iter().flatten() {
        let Some(reference) = index
            .declared_fields
            .get(owner)
            .and_then(|fields| fields.get(flattened_field))
            .and_then(Option::as_ref)
        else {
            continue;
        };
        let (suffix, inner) = peel_config_containers(reference);
        // A flattened map is serde's catch-all for unknown keys. It has no
        // fixed key surface, so there is nothing to enumerate.
        if !suffix.is_empty() {
            continue;
        }
        let Some(child_owner) = index.resolve_type_reference(inner) else {
            continue;
        };
        if walkable_config_type(index, &child_owner) {
            collect_module_keys(index, &child_owner, path, active, out);
        }
    }

    let no_fields = BTreeMap::new();
    let schema_fields = index.schema_fields.get(owner).unwrap_or(&no_fields);
    for (schema_field, rust_fields) in schema_fields {
        // Two Rust fields serializing under one name means the reader check
        // cannot say which one a read proves, and `rust_field_for_schema_field`
        // refuses the same pair. Emitting the key anyway would produce a
        // finding nobody can clear.
        if rust_fields.len() != 1 {
            continue;
        }
        let Some(rust_field) = rust_fields.first() else {
            continue;
        };
        if index
            .flattened_fields
            .get(owner)
            .is_some_and(|flattened| flattened.contains(rust_field))
        {
            continue;
        }

        let child_path = join_path(path, schema_field);
        // No declared type means a serde-only pseudo-field: the internal tag
        // of a tagged enum, which is a real config key (`type:`) with no Rust
        // field behind it. It is a leaf, and it needs a reviewed override
        // naming the compiler that reads the discriminator.
        let Some(declared) = index
            .declared_fields
            .get(owner)
            .and_then(|fields| fields.get(rust_field))
            .and_then(Option::as_ref)
        else {
            out.insert(module_leaf_key(&child_path, schema_field, owner));
            continue;
        };

        let (suffix, inner) = peel_config_containers(declared);
        let child_path = format!("{child_path}{suffix}");
        let Some(child_owner) = index.resolve_type_reference(inner) else {
            out.insert(module_leaf_key(&child_path, schema_field, owner));
            continue;
        };
        if !walkable_config_type(index, &child_owner) {
            out.insert(module_leaf_key(&child_path, schema_field, owner));
            continue;
        }

        // Same rule the schema walk uses: a node with descendants is not a
        // key, its leaves are. A walkable type that yields nothing is still
        // one key, so the parent's field does not go unchecked.
        let before = out.len();
        collect_module_keys(index, &child_owner, &child_path, active, out);
        if out.len() == before {
            out.insert(module_leaf_key(&child_path, schema_field, owner));
        }
    }

    active.pop();
}

fn module_leaf_key(path: &str, schema_field: &str, owner: &str) -> ConfigSchemaKey {
    ConfigSchemaKey {
        path: path.to_string(),
        rust_field: schema_field.to_string(),
        rust_owner: Some(owner.to_string()),
    }
}

/// Strip the container wrappers off a declared field type.
///
/// Returns the path suffix the containers contribute and the innermost
/// nominal reference. A sequence adds `[]` and a map adds `.*`, matching the
/// shape [`collect_schema`] produces from `items` and `additionalProperties`.
/// `Option`, `Box` and `Arc` add nothing, because none of them adds a level
/// to the document an operator writes.
fn peel_config_containers(reference: &TypeReference) -> (String, &TypeReference) {
    let mut suffix = String::new();
    let mut current = reference;
    loop {
        let Some(argument) = syntactic_transparent_wrapper_argument_index(current, true) else {
            return (suffix, current);
        };
        let Some(GenericArgumentReference::Type(inner)) = current.generic_arguments.get(argument)
        else {
            return (suffix, current);
        };
        match current.segments.last().map(String::as_str) {
            Some("Vec" | "VecDeque" | "HashSet" | "BTreeSet" | "SmallVec") => suffix.push_str("[]"),
            Some("HashMap" | "BTreeMap" | "IndexMap") => suffix.push_str(".*"),
            _ => {}
        }
        current = inner;
    }
}

/// Whether the walk should descend into a type or treat it as one key.
///
/// Three ways to stop. A type this scan never parsed is outside `crates/`.
/// A type without a derived `Deserialize` is not part of the document at
/// all, so its fields are runtime state rather than config keys, and a
/// hand-written `Deserialize` impl stops here too because its accepted shape
/// is not readable from the field list. An enum only presents a flat key
/// surface when serde tags it internally: externally and adjacently tagged
/// enums nest their payload under a variant name this walk does not model,
/// so descending would invent paths no operator can write.
///
/// Stopping checks the type as a single key, which is honest, rather than
/// describing its interior wrongly.
fn walkable_config_type(index: &RustTypeIndex, owner: &str) -> bool {
    if !index.fields.contains_key(owner) {
        return false;
    }
    if index
        .derived_traits
        .get(owner)
        .is_none_or(|traits| !traits.contains("Deserialize"))
    {
        return false;
    }
    if index
        .schema_fields
        .get(owner)
        .is_none_or(|fields| fields.is_empty())
    {
        return false;
    }
    !index.enum_variants.contains_key(owner) || index.enum_tags.contains_key(owner)
}

/// Derive every module-surface key the declared roots reach.
fn module_keys_for_roots(
    index: &RustTypeIndex,
    roots: &[ModuleConfigRoot],
) -> (
    BTreeSet<ConfigSchemaKey>,
    BTreeMap<String, &'static str>,
    Vec<RegistryError>,
) {
    let mut keys = BTreeSet::new();
    let mut enforced = BTreeSet::new();
    let mut report_only = BTreeMap::new();
    let mut errors = Vec::new();

    for root in roots {
        if !index.fields.contains_key(root.rust_type) {
            errors.push(RegistryError {
                subject: root.path.to_string(),
                message: format!(
                    "names module config root `{}`, which this scan cannot see. A config \
                     shape declared inside a function body is invisible to module indexing: \
                     give it module scope, or correct the type path",
                    root.rust_type
                ),
            });
            continue;
        }

        let mut produced = BTreeSet::new();
        collect_module_keys(
            index,
            root.rust_type,
            root.path,
            &mut Vec::new(),
            &mut produced,
        );
        if produced.is_empty() {
            errors.push(RegistryError {
                subject: root.path.to_string(),
                message: format!(
                    "names module config root `{}`, which produced no keys. A root that \
                     walks to nothing guards nothing",
                    root.rust_type
                ),
            });
        }

        // A path two roots both reach is enforced if either root enforces it.
        // Overlap is possible because module roots share the operator's YAML
        // path: `origins.*.action` is one path with a different shape per
        // action type.
        match root.enforcement {
            ModuleRootEnforcement::Enforced => {
                enforced.extend(produced.iter().map(|key| key.path.clone()));
            }
            ModuleRootEnforcement::ReportOnly(note) => {
                report_only.extend(produced.iter().map(|key| (key.path.clone(), note)));
            }
        }
        keys.extend(produced);
    }

    report_only.retain(|path, _| !enforced.contains(path));
    (keys, report_only, errors)
}

/// One place the config compiler turns an operator's `type:` string into a
/// module.
///
/// This is the authoritative list of what an operator can name, and it is a
/// `match` over string literals in one function, which makes it something a
/// scan can read.
#[derive(Debug, Clone, Copy)]
pub struct ModuleDispatch {
    /// Module kind as an operator says it: `action`, `auth`, `policy`,
    /// `transform`.
    pub kind: &'static str,
    /// Repo-relative source file holding the dispatch.
    pub source: &'static str,
    /// Function whose first string-literal `match` is the dispatch table.
    pub function: &'static str,
}

/// What the widened scan knows about one module's configuration surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleCoverageState {
    /// A declared [`ModuleConfigRoot`] walks this module's config type.
    Rooted,
    /// Not walked. The note says why and names the work that will change it.
    Deferred(&'static str),
}

/// One module name from a dispatch table, and its coverage classification.
#[derive(Debug, Clone, Copy)]
pub struct ModuleCoverage {
    /// Matches [`ModuleDispatch::kind`].
    pub kind: &'static str,
    /// The `type:` string an operator writes.
    pub name: &'static str,
    /// Whether the module's config surface is walked.
    pub state: ModuleCoverageState,
}

/// Require every dispatchable module to say whether its config is guarded.
///
/// This is the difference between a registry of roots and a registry that
/// cannot be silently outgrown. Adding a root for each module we happen to
/// remember leaves the next module unguarded until somebody notices; here a
/// module name that reaches the dispatch table without a [`ModuleCoverage`]
/// entry fails the build on the day it lands. Deferring is allowed and
/// costs one line plus a reason, which is the point: the decision is
/// recorded rather than skipped.
///
/// Checked in both directions, so a removed module cannot leave a stale
/// classification behind.
pub fn verify_module_dispatch_coverage(
    dispatches: &[ModuleDispatch],
    coverage: &[ModuleCoverage],
    sources: &[SourceFile],
) -> Vec<RegistryError> {
    let mut errors = Vec::new();
    let production_sources: Vec<&SourceFile> = sources
        .iter()
        .filter(|source| source_is_production(&source.path))
        .collect();

    // Both sides are keyed on `kind:name`, which is how an operator would
    // say it and how the errors below read.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for entry in coverage {
        let subject = format!("{}:{}", entry.kind, entry.name);
        if !declared.insert(subject.clone()) {
            errors.push(RegistryError {
                subject,
                message: "is classified twice in the module coverage registry".to_string(),
            });
        }
    }

    let mut dispatched: BTreeSet<String> = BTreeSet::new();
    for dispatch in dispatches {
        match dispatch_module_names(dispatch, &production_sources) {
            Ok(names) => dispatched.extend(
                names
                    .into_iter()
                    .map(|name| format!("{}:{name}", dispatch.kind)),
            ),
            Err(message) => errors.push(RegistryError {
                subject: format!("{}:{}", dispatch.kind, dispatch.function),
                message,
            }),
        }
    }

    for subject in dispatched.difference(&declared) {
        errors.push(RegistryError {
            subject: subject.clone(),
            message: "is dispatchable from config but is not classified in the module coverage \
                      registry. Give it a config root so the reader guard walks its keys, or \
                      defer it with a reason and a tracking issue"
                .to_string(),
        });
    }

    for subject in declared.difference(&dispatched) {
        errors.push(RegistryError {
            subject: subject.clone(),
            message: "is classified in the module coverage registry but no dispatch table \
                      accepts it. Remove the classification, or correct the name"
                .to_string(),
        });
    }

    errors
}

/// Read the `type:` strings one dispatch function accepts.
fn dispatch_module_names(
    dispatch: &ModuleDispatch,
    sources: &[&SourceFile],
) -> Result<BTreeSet<String>, String> {
    let source = sources
        .iter()
        .find(|source| {
            source
                .path
                .to_string_lossy()
                .replace('\\', "/")
                .ends_with(dispatch.source)
        })
        .ok_or_else(|| format!("dispatch source `{}` was not scanned", dispatch.source))?;
    let file = source.ast.as_ref().map_err(|error| {
        format!(
            "dispatch source `{}` did not parse: {error}",
            dispatch.source
        )
    })?;
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == dispatch.function => Some(function),
            _ => None,
        })
        .ok_or_else(|| {
            format!(
                "dispatch function `{}` no longer exists in `{}`. The module coverage check \
                 reads its match arms; point it at the function that dispatches now",
                dispatch.function, dispatch.source
            )
        })?;

    let mut visitor = DispatchArmVisitor { names: None };
    visitor.visit_item_fn(function);
    visitor.names.ok_or_else(|| {
        format!(
            "dispatch function `{}` has no match over string literals. The module coverage \
             check cannot read the accepted `type:` names from it. If the function now \
             delegates, point this entry at the one holding the match",
            dispatch.function
        )
    })
}

/// Collect the string-literal arms of the outermost `match` in a function.
///
/// The outermost one is the dispatch: `compile_auth` has an inner `match`
/// over the plugin-registry outcome, and taking the first hit rather than
/// the last keeps that from being mistaken for the table.
struct DispatchArmVisitor {
    names: Option<BTreeSet<String>>,
}

impl<'ast> Visit<'ast> for DispatchArmVisitor {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.names.is_some() {
            return;
        }
        let mut names = BTreeSet::new();
        for arm in &node.arms {
            collect_pattern_literals(&arm.pat, &mut names);
        }
        if names.is_empty() {
            // Some other match on the way to the dispatch. Keep descending.
            syn::visit::visit_expr_match(self, node);
            return;
        }
        self.names = Some(names);
    }
}

fn collect_pattern_literals(pattern: &syn::Pat, out: &mut BTreeSet<String>) {
    match pattern {
        syn::Pat::Lit(literal) => {
            if let syn::Lit::Str(value) = &literal.lit {
                out.insert(value.value());
            }
        }
        syn::Pat::Or(alternatives) => {
            for alternative in &alternatives.cases {
                collect_pattern_literals(alternative, out);
            }
        }
        syn::Pat::Paren(inner) => collect_pattern_literals(&inner.pat, out),
        syn::Pat::Reference(inner) => collect_pattern_literals(&inner.pat, out),
        _ => {}
    }
}

/// Verify that every schema key has either a production field read or a
/// reviewed override.
///
/// A stable override names an indirect consumer that source scanning cannot
/// see (for example, a serde discriminator or a flattened config handed to a
/// plugin). A `ConfigOnly` override names a deliberately inert key and owes
/// the operator a reason. Overrides are checked in both directions so a
/// removed or renamed schema path cannot leave stale policy behind.
pub fn verify_config_readers(
    keys: &[ConfigSchemaKey],
    overrides: &[ConfigKeyCapability],
    sources: &[SourceFile],
) -> Vec<RegistryError> {
    verify_config_readers_with_modules(keys, &[], overrides, sources).errors
}

/// Verify reader coverage across both key sources at once.
///
/// The generated schema describes everything `ConfigFile` types concretely.
/// `roots` describes the module and AI-gateway subtrees it types as
/// `serde_json::Value`, which is where the keys an operator can set and the
/// runtime ignores have historically hidden. Both sources produce the same
/// [`ConfigSchemaKey`] and are checked by one pass, so an override is proved
/// against the union: a `ConfigOnly` pin on a module key is subject to the
/// same stale-path check as every other entry.
///
/// This answers "is this key read?". It does not answer "does reading it do
/// anything". A function can read every field of a config struct into real
/// runtime state and still have no callers, which leaves the key inert with
/// a perfectly good read behind it. That shape needs a zero-caller pass over
/// the reachable call graph; `scripts/check-pub-item-ratchet.sh` does part of
/// it and skips trait-impl methods. The two checks are complementary and
/// neither subsumes the other. Do not try to make this one catch both.
pub fn verify_config_readers_with_modules(
    keys: &[ConfigSchemaKey],
    roots: &[ModuleConfigRoot],
    overrides: &[ConfigKeyCapability],
    sources: &[SourceFile],
) -> ConfigReaderReport {
    let mut errors = validate_config_keys(overrides);
    let mut reported = Vec::new();

    let production_sources: Vec<&SourceFile> = sources
        .iter()
        .filter(|source| source_is_production(&source.path))
        .collect();
    for source in &production_sources {
        if let Err(error) = &source.ast {
            errors.push(RegistryError {
                subject: source.path.display().to_string(),
                message: format!(
                    "could not parse production Rust source while proving config readers: {error}"
                ),
            });
        }
    }
    // Built once and shared: parsing the workspace is the dominant cost in
    // this guard, and the module walk and the reader check both need the
    // same index. Deriving the keys from it rather than from a second
    // schema generator is also what keeps the two halves consistent.
    let type_index = rust_type_index(&production_sources);
    let typed_reads = typed_field_reads(&production_sources, &type_index);

    let (module_keys, report_only, root_errors) = module_keys_for_roots(&type_index, roots);
    errors.extend(root_errors);

    let all_keys: Vec<ConfigSchemaKey> = keys
        .iter()
        .cloned()
        .chain(module_keys.iter().cloned())
        .collect();
    let declared: BTreeSet<&str> = all_keys.iter().map(|key| key.path.as_str()).collect();
    let override_index: BTreeMap<&str, &ConfigKeyCapability> =
        overrides.iter().map(|entry| (entry.path, entry)).collect();

    for entry in overrides {
        if !declared.contains(entry.path) {
            errors.push(RegistryError {
                subject: entry.path.to_string(),
                message: "has a config-reader override but is not present in the generated schema"
                    .to_string(),
            });
        }
        if entry.support == SupportLevel::ConfigOnly && entry.consumer.is_some() {
            errors.push(RegistryError {
                subject: entry.path.to_string(),
                message: "is config_only and must not name a live consumer".to_string(),
            });
        }
    }

    for key in &all_keys {
        if let Some(entry) = override_index.get(key.path.as_str()) {
            if entry.support == SupportLevel::Stable {
                if let Some(consumer) = entry.consumer {
                    if !production_consumer_exists(consumer, &production_sources) {
                        errors.push(RegistryError {
                            subject: key.path.clone(),
                            message: format!(
                                "names stable consumer `{consumer}`, but that symbol does not \
                                 exist in non-test production source"
                            ),
                        });
                    }
                }
            }
            continue;
        }
        if !has_unambiguous_field_read(key, &typed_reads, &type_index) {
            let message = format!(
                "is accepted by the configuration but has no unambiguous non-test Rust read of \
                 `{}::{}`. Wire the key, or add an exact reviewed override with production \
                 consumer evidence or a ConfigOnly reason",
                key.rust_owner.as_deref().unwrap_or("<unknown>"),
                key.rust_field,
            );
            match report_only.get(key.path.as_str()) {
                Some(note) => reported.push(RegistryError {
                    subject: key.path.clone(),
                    message: format!("{message}. Reported rather than fatal: {note}"),
                }),
                None => errors.push(RegistryError {
                    subject: key.path.clone(),
                    message,
                }),
            }
        }
    }

    ConfigReaderReport {
        errors,
        reported,
        module_keys: module_keys.into_iter().collect(),
    }
}

fn source_is_production(path: &std::path::Path) -> bool {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let Some(crates_at) = components
        .iter()
        .position(|component| *component == "crates")
    else {
        return false;
    };
    let within_crate = &components[crates_at.saturating_add(2)..];
    if matches!(
        within_crate.first().copied(),
        Some("tests" | "benches" | "examples")
    ) {
        return false;
    }
    !within_crate.contains(&"tests") && within_crate.last().copied() != Some("tests.rs")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleContext {
    crate_name: String,
    modules: Vec<String>,
}

impl ModuleContext {
    fn from_source_path(path: &std::path::Path) -> Option<Self> {
        let components: Vec<_> = path
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .collect();
        let crates_at = components
            .iter()
            .position(|component| *component == "crates")?;
        let crate_name = normalize_crate_name(components.get(crates_at + 1)?);
        let src_at = components[crates_at + 2..]
            .iter()
            .position(|component| *component == "src")?
            + crates_at
            + 2;
        let relative = &components[src_at + 1..];
        let (file, directories) = relative.split_last()?;
        let mut modules: Vec<String> = directories
            .iter()
            .map(|component| (*component).to_string())
            .collect();
        let stem = std::path::Path::new(file)
            .file_stem()
            .and_then(|stem| stem.to_str())?;
        if !matches!(stem, "lib" | "main" | "mod") {
            modules.push(stem.to_string());
        }
        Some(Self {
            crate_name,
            modules,
        })
    }

    fn child(&self, module: &syn::Ident) -> Self {
        let mut child = self.clone();
        child.modules.push(module.to_string());
        child
    }

    fn symbol(&self, name: &str) -> String {
        std::iter::once(self.crate_name.as_str())
            .chain(self.modules.iter().map(String::as_str))
            .chain(std::iter::once(name))
            .collect::<Vec<_>>()
            .join("::")
    }

    fn path(&self) -> String {
        std::iter::once(self.crate_name.as_str())
            .chain(self.modules.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("::")
    }
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn primitive_type_reference(reference: &TypeReference) -> Option<&str> {
    let [name] = reference.segments.as_slice() else {
        return None;
    };
    (!reference.leading_colon
        && matches!(
            name.as_str(),
            "()" | "bool"
                | "char"
                | "str"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "f32"
                | "f64"
        ))
    .then_some(name)
    .map(String::as_str)
}

fn resolved_type_identity(owner: String, arguments: &[String]) -> String {
    if arguments.is_empty() {
        owner
    } else {
        format!("{owner}<{}>", arguments.join(","))
    }
}

fn split_resolved_type_identity(identity: &str) -> Option<(&str, Vec<&str>)> {
    let Some(open) = identity.find('<') else {
        return Some((identity, Vec::new()));
    };
    if !identity.ends_with('>') {
        return None;
    }
    let mut arguments = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    for (offset, byte) in identity.as_bytes()[open + 1..identity.len() - 1]
        .iter()
        .enumerate()
    {
        match byte {
            b'<' => depth += 1,
            b'>' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                let end = open + 1 + offset;
                arguments.push(&identity[start..end]);
                start = end + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    arguments.push(&identity[start..identity.len() - 1]);
    Some((&identity[..open], arguments))
}

#[derive(Debug, Clone)]
struct TypeReference {
    segments: Vec<String>,
    generic_arguments: Vec<GenericArgumentReference>,
    has_unresolved_generic_arguments: bool,
    context: ModuleContext,
    leading_colon: bool,
}

#[derive(Debug, Clone)]
enum GenericArgumentReference {
    Type(TypeReference),
    Const(ConstArgumentReference),
}

#[derive(Debug, Clone)]
enum ConstArgumentReference {
    Literal(String),
    Path(Vec<String>),
}

#[derive(Debug, Clone)]
enum TypeAliasParameter {
    Type(String),
    Const(String),
}

#[derive(Debug, Clone)]
struct TypeAliasDefinition {
    parameters: Vec<TypeAliasParameter>,
    target: TypeReference,
}

#[derive(Debug, Clone)]
struct ValueTypeAliasParameter {
    name: String,
    default: Option<ValueTypeReference>,
}

#[derive(Debug, Clone)]
struct ValueTypeAliasDefinition {
    parameters: Vec<ValueTypeAliasParameter>,
    target: ValueTypeReference,
}

impl ValueTypeAliasDefinition {
    fn new(generics: &syn::Generics, target: ValueTypeReference, context: &ModuleContext) -> Self {
        Self {
            parameters: generics
                .params
                .iter()
                .filter_map(|parameter| match parameter {
                    syn::GenericParam::Type(parameter) => Some(ValueTypeAliasParameter {
                        name: parameter.ident.to_string(),
                        default: parameter
                            .default
                            .as_ref()
                            .and_then(|default| value_type_reference(default, context)),
                    }),
                    syn::GenericParam::Const(_) | syn::GenericParam::Lifetime(_) => None,
                })
                .collect(),
            target,
        }
    }
}

#[derive(Debug, Default)]
struct GenericOwnerBindings {
    type_arguments: BTreeMap<String, String>,
    const_arguments: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct GenericRequirements {
    trait_bounds: Vec<(String, TypeReference)>,
    has_unresolved_requirements: bool,
}

#[derive(Debug, Clone)]
enum ValueTypeReference {
    Nominal(TypeReference),
    Parameterized {
        wrapper: TypeReference,
        arguments: Vec<Option<ValueTypeReference>>,
    },
    Tuple(Vec<Option<ValueTypeReference>>),
}

#[derive(Debug, Clone)]
struct FunctionReturn {
    symbol: String,
    result: ValueTypeReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MethodReceiver {
    SharedOrValue,
    Mutable,
}

#[derive(Debug, Clone)]
struct MethodSignature {
    owner: TypeReference,
    type_parameters: BTreeSet<String>,
    const_parameters: BTreeSet<String>,
    requirements: GenericRequirements,
    receiver: MethodReceiver,
}

#[derive(Debug, Clone)]
struct TraitMethodSignature {
    receiver: MethodReceiver,
    has_default: bool,
}

#[derive(Debug, Clone)]
enum TraitImplementationOwner {
    Exact(TypeReference),
    Blanket {
        bounds: Vec<TypeReference>,
        has_unresolved_requirements: bool,
    },
}

#[derive(Debug, Clone)]
struct TraitImplementation {
    trait_reference: TypeReference,
    owner: TraitImplementationOwner,
    type_parameters: BTreeSet<String>,
    const_parameters: BTreeSet<String>,
    requirements: GenericRequirements,
    method_signatures: BTreeMap<String, Vec<MethodReceiver>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodReceiverResolution {
    Missing,
    SharedOrValue,
    Mutable,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraitImplementationApplicability {
    Rejected,
    ExternallyConstrained,
    Proven,
}

#[derive(Debug, Clone, Copy)]
enum SymbolKind {
    Type,
    Function,
}

#[derive(Default)]
struct SymbolResolution {
    symbols: BTreeSet<String>,
    tainted: bool,
}

impl SymbolResolution {
    fn found(symbol: String) -> Self {
        Self {
            symbols: BTreeSet::from([symbol]),
            tainted: false,
        }
    }

    fn tainted() -> Self {
        Self {
            symbols: BTreeSet::new(),
            tainted: true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.symbols.extend(other.symbols);
        self.tainted |= other.tainted;
    }

    fn exact(self) -> Option<String> {
        (!self.tainted && self.symbols.len() == 1)
            .then(|| self.symbols.into_iter().next())
            .flatten()
    }
}

#[derive(Default)]
struct NamespaceResolution {
    namespaces: BTreeSet<ModuleContext>,
    tainted: bool,
}

impl NamespaceResolution {
    fn known(namespace: ModuleContext) -> Self {
        Self {
            namespaces: BTreeSet::from([namespace]),
            tainted: false,
        }
    }

    fn tainted() -> Self {
        Self {
            namespaces: BTreeSet::new(),
            tainted: true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.namespaces.extend(other.namespaces);
        self.tainted |= other.tainted;
    }
}

#[derive(Default)]
struct RustTypeIndex {
    fields: BTreeMap<String, BTreeMap<String, Option<TypeReference>>>,
    /// Field types as declared, with their container wrappers intact.
    ///
    /// `fields` holds the *innermost* nominal type, which is what the
    /// reader check wants: a read of `targets` proves a read whether the
    /// field is a `Target` or a `Vec<Target>`. The module walk needs the
    /// opposite, because the container is exactly what decides the path
    /// an operator writes: a `Vec` adds `[]` and a map adds `.*`. Reading
    /// the peeled type for that purpose silently produced
    /// `targets.zone` for a list of targets.
    declared_fields: BTreeMap<String, BTreeMap<String, Option<TypeReference>>>,
    schema_fields: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    /// Rust field names carrying `#[serde(flatten)]`, by owning type.
    ///
    /// Only the module-surface walk needs this. A flattened field has no key
    /// of its own: its own fields are lifted into the parent object, so a
    /// walk that treated it like any other field would invent a path segment
    /// no operator can write.
    flattened_fields: BTreeMap<String, BTreeSet<String>>,
    type_components: BTreeMap<String, Vec<Option<TypeReference>>>,
    generic_type_parameters: BTreeMap<String, Vec<TypeAliasParameter>>,
    tuple_struct_fields: BTreeMap<String, Vec<Option<TypeReference>>>,
    enum_tuple_variant_fields: BTreeMap<(String, String), Vec<Option<TypeReference>>>,
    derived_traits: BTreeMap<String, BTreeSet<String>>,
    type_aliases: BTreeMap<String, Vec<TypeAliasDefinition>>,
    value_type_aliases: BTreeMap<String, Vec<ValueTypeAliasDefinition>>,
    types_by_name: BTreeMap<String, BTreeSet<String>>,
    symbol_bindings: BTreeMap<String, Vec<TypeReference>>,
    glob_imports: BTreeMap<ModuleContext, Vec<TypeReference>>,
    anonymous_imports: BTreeMap<ModuleContext, Vec<TypeReference>>,
    unexpanded_item_macro_namespaces: BTreeSet<ModuleContext>,
    known_crates: BTreeSet<String>,
    known_modules: BTreeSet<String>,
    enum_tags: BTreeMap<String, String>,
    enum_variants: BTreeMap<String, BTreeSet<String>>,
    function_returns: BTreeMap<String, Vec<FunctionReturn>>,
    method_signatures: BTreeMap<String, Vec<MethodSignature>>,
    trait_method_signatures: BTreeMap<String, BTreeMap<String, Vec<TraitMethodSignature>>>,
    trait_implementations: Vec<TraitImplementation>,
    trait_implementations_by_trait: BTreeMap<String, Vec<usize>>,
    trait_method_candidates: BTreeMap<String, BTreeSet<String>>,
}

impl RustTypeIndex {
    fn record_context(&mut self, context: &ModuleContext) {
        self.known_crates.insert(context.crate_name.clone());
        if !context.modules.is_empty() {
            self.known_modules.insert(context.path());
        }
    }

    fn record_type(&mut self, owner: &str, simple_name: &str) {
        self.fields.entry(owner.to_string()).or_default();
        self.schema_fields.entry(owner.to_string()).or_default();
        self.type_components.entry(owner.to_string()).or_default();
        self.types_by_name
            .entry(simple_name.to_string())
            .or_default()
            .insert(owner.to_string());
    }

    fn record_derived_traits(&mut self, owner: &str, attributes: &[syn::Attribute]) {
        for attribute in attributes
            .iter()
            .filter(|attribute| attribute.path().is_ident("derive"))
        {
            let Ok(paths) = attribute.parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            ) else {
                continue;
            };
            self.derived_traits
                .entry(owner.to_string())
                .or_default()
                .extend(paths.iter().filter_map(|path| {
                    path.segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                }));
        }
    }

    fn record_symbol_binding(&mut self, alias: String, target: TypeReference) {
        self.symbol_bindings.entry(alias).or_default().push(target);
    }

    fn record_type_alias(
        &mut self,
        alias: String,
        generics: &syn::Generics,
        target: TypeReference,
    ) {
        let parameters = generics
            .params
            .iter()
            .filter_map(|parameter| match parameter {
                syn::GenericParam::Type(parameter) => {
                    Some(TypeAliasParameter::Type(parameter.ident.to_string()))
                }
                syn::GenericParam::Const(parameter) => {
                    Some(TypeAliasParameter::Const(parameter.ident.to_string()))
                }
                syn::GenericParam::Lifetime(_) => None,
            })
            .collect();
        self.type_aliases
            .entry(alias)
            .or_default()
            .push(TypeAliasDefinition { parameters, target });
    }

    fn record_value_type_alias(
        &mut self,
        alias: String,
        generics: &syn::Generics,
        target: ValueTypeReference,
        context: &ModuleContext,
    ) {
        self.value_type_aliases
            .entry(alias)
            .or_default()
            .push(ValueTypeAliasDefinition::new(generics, target, context));
    }

    fn record_generic_type_parameters(&mut self, owner: &str, generics: &syn::Generics) {
        let parameters = generics
            .params
            .iter()
            .filter_map(|parameter| match parameter {
                syn::GenericParam::Type(parameter) => {
                    Some(TypeAliasParameter::Type(parameter.ident.to_string()))
                }
                syn::GenericParam::Const(parameter) => {
                    Some(TypeAliasParameter::Const(parameter.ident.to_string()))
                }
                syn::GenericParam::Lifetime(_) => None,
            })
            .collect();
        self.generic_type_parameters
            .insert(owner.to_string(), parameters);
    }

    fn tuple_field_references(
        fields: &syn::Fields,
        context: &ModuleContext,
    ) -> Option<Vec<Option<TypeReference>>> {
        let syn::Fields::Unnamed(fields) = fields else {
            return None;
        };
        Some(
            fields
                .unnamed
                .iter()
                .filter(|field| !attributes_exclude_production(&field.attrs))
                .map(|field| type_reference(&field.ty, context))
                .collect(),
        )
    }

    fn record_glob_import(&mut self, context: &ModuleContext, target: TypeReference) {
        self.glob_imports
            .entry(context.clone())
            .or_default()
            .push(target);
    }

    fn record_anonymous_import(&mut self, context: &ModuleContext, target: TypeReference) {
        self.anonymous_imports
            .entry(context.clone())
            .or_default()
            .push(target);
    }

    fn finalize_trait_method_candidates(&mut self) {
        for (trait_owner, methods) in &self.trait_method_signatures {
            for method in methods.keys() {
                self.trait_method_candidates
                    .entry(method.clone())
                    .or_default()
                    .insert(trait_owner.clone());
            }
        }
        let implementations: Vec<_> = self
            .trait_implementations
            .iter()
            .enumerate()
            .filter_map(|(index, implementation)| {
                self.resolve_type_reference(&implementation.trait_reference)
                    .map(|trait_owner| {
                        (
                            index,
                            trait_owner,
                            implementation
                                .method_signatures
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>(),
                        )
                    })
            })
            .collect();
        for (index, trait_owner, methods) in implementations {
            self.trait_implementations_by_trait
                .entry(trait_owner.clone())
                .or_default()
                .push(index);
            for method in methods {
                self.trait_method_candidates
                    .entry(method)
                    .or_default()
                    .insert(trait_owner.clone());
            }
        }
    }

    fn namespace_exists(&self, context: &ModuleContext) -> bool {
        if context.modules.is_empty() {
            self.known_crates.contains(&context.crate_name)
        } else {
            self.known_modules.contains(&context.path())
        }
    }

    fn record_fields(
        &mut self,
        owner: &str,
        fields: &syn::Fields,
        container_attributes: &[syn::Attribute],
        context: &ModuleContext,
    ) {
        for field in fields
            .iter()
            .filter(|field| !attributes_exclude_production(&field.attrs))
        {
            self.type_components
                .entry(owner.to_string())
                .or_default()
                .push(nominal_type_reference(&field.ty, context));
            if let Some(ident) = &field.ident {
                let field_name = ident.to_string().trim_start_matches("r#").to_string();
                if field_is_flattened(&field.attrs) {
                    self.flattened_fields
                        .entry(owner.to_string())
                        .or_default()
                        .insert(field_name.clone());
                }
                for serialized_name in
                    possible_schema_field_names(&field_name, &field.attrs, container_attributes)
                {
                    self.schema_fields
                        .entry(owner.to_string())
                        .or_default()
                        .entry(rust_field_name(&serialized_name))
                        .or_default()
                        .insert(field_name.clone());
                }
                self.declared_fields
                    .entry(owner.to_string())
                    .or_default()
                    .insert(
                        field_name.clone(),
                        nominal_type_reference(&field.ty, context),
                    );
                self.fields
                    .entry(owner.to_string())
                    .or_default()
                    .insert(field_name, type_reference(&field.ty, context));
            }
        }
    }

    fn record_enum(&mut self, owner: &str, item: &syn::ItemEnum, context: &ModuleContext) {
        self.record_type(owner, &item.ident.to_string());
        self.record_generic_type_parameters(owner, &item.generics);
        self.record_derived_traits(owner, &item.attrs);
        self.enum_variants.insert(
            owner.to_string(),
            item.variants
                .iter()
                .map(|variant| variant.ident.to_string())
                .collect(),
        );
        if let Some(tag) = serde_enum_tag(&item.attrs) {
            let tag = rust_field_name(&tag);
            self.enum_tags.insert(owner.to_string(), tag.clone());
            self.schema_fields
                .entry(owner.to_string())
                .or_default()
                .entry(tag.clone())
                .or_default()
                .insert(tag);
        }
        for variant in &item.variants {
            if attributes_exclude_production(&variant.attrs) {
                continue;
            }
            if let Some(fields) = Self::tuple_field_references(&variant.fields, context) {
                self.enum_tuple_variant_fields
                    .insert((owner.to_string(), variant.ident.to_string()), fields);
            }
            self.record_fields(owner, &variant.fields, &variant.attrs, context);
        }
    }

    fn field_type(&self, owner: &str, field: &str) -> Option<String> {
        self.fields
            .get(owner)
            .and_then(|fields| fields.get(field))
            .and_then(Option::as_ref)
            .and_then(|reference| self.resolve_exact_type_reference(reference))
    }

    fn rust_field_for_schema_field<'a>(
        &'a self,
        owner: &str,
        schema_field: &'a str,
    ) -> Option<&'a str> {
        let candidates = self.schema_fields.get(owner)?.get(schema_field)?;
        (candidates.len() == 1)
            .then(|| candidates.first().map(String::as_str))
            .flatten()
    }

    fn resolve_type_reference(&self, reference: &TypeReference) -> Option<String> {
        self.resolve_symbol_reference(SymbolKind::Type, reference, &mut BTreeSet::new())
            .exact()
    }

    fn resolve_exact_type_reference(&self, reference: &TypeReference) -> Option<String> {
        self.resolve_exact_type_reference_inner(reference, &mut BTreeSet::new())
    }

    fn resolve_exact_type_reference_inner(
        &self,
        reference: &TypeReference,
        resolving_aliases: &mut BTreeSet<String>,
    ) -> Option<String> {
        let aliases = self.type_alias_definitions_for_reference(reference, &mut BTreeSet::new());
        if !aliases.is_empty() {
            let [alias] = aliases.as_slice() else {
                return None;
            };
            let key = format!(
                "{}:{}",
                reference.context.path(),
                reference.segments.join("::")
            );
            if !resolving_aliases.insert(key.clone()) {
                return None;
            }
            let expanded = Self::instantiate_type_alias(alias, reference)?;
            let resolved = self.resolve_exact_type_reference_inner(&expanded, resolving_aliases);
            resolving_aliases.remove(&key);
            return resolved;
        }
        let owner = self
            .resolve_type_reference(reference)
            .or_else(|| primitive_type_reference(reference).map(str::to_string))?;
        if reference.has_unresolved_generic_arguments {
            return None;
        }
        let arguments: Option<Vec<_>> = reference
            .generic_arguments
            .iter()
            .map(|argument| match argument {
                GenericArgumentReference::Type(argument) => {
                    self.resolve_exact_type_reference_inner(argument, resolving_aliases)
                }
                GenericArgumentReference::Const(ConstArgumentReference::Literal(value)) => {
                    Some(format!("#{value}"))
                }
                GenericArgumentReference::Const(ConstArgumentReference::Path(_)) => None,
            })
            .collect();
        Some(resolved_type_identity(owner, &arguments?))
    }

    fn type_alias_definitions_for_reference(
        &self,
        reference: &TypeReference,
        resolving: &mut BTreeSet<String>,
    ) -> Vec<TypeAliasDefinition> {
        let Some(name) = reference.segments.last() else {
            return Vec::new();
        };
        if reference.segments.len() == 1 && !reference.leading_colon {
            return self.type_alias_definitions_in_namespace(&reference.context, name, resolving);
        }
        let namespace_reference = TypeReference {
            segments: reference.segments[..reference.segments.len() - 1].to_vec(),
            generic_arguments: Vec::new(),
            has_unresolved_generic_arguments: false,
            context: reference.context.clone(),
            leading_colon: reference.leading_colon,
        };
        let namespaces = self.resolve_namespace_reference(&namespace_reference, resolving);
        if namespaces.tainted {
            return Vec::new();
        }
        namespaces
            .namespaces
            .iter()
            .flat_map(|namespace| {
                self.type_alias_definitions_in_namespace(namespace, name, resolving)
            })
            .collect()
    }

    fn type_alias_definitions_in_namespace(
        &self,
        namespace: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> Vec<TypeAliasDefinition> {
        let key = format!("type-alias:{}::{name}", namespace.path());
        if !resolving.insert(key.clone()) {
            return Vec::new();
        }
        let exact = namespace.symbol(name);
        if let Some(aliases) = self.type_aliases.get(&exact) {
            resolving.remove(&key);
            return aliases.clone();
        }
        let mut aliases = Vec::new();
        if let Some(bindings) = self.symbol_bindings.get(&exact) {
            for binding in bindings {
                aliases.extend(self.type_alias_definitions_for_reference(binding, resolving));
            }
        }
        if let Some(globs) = self.glob_imports.get(namespace) {
            for glob in globs {
                let targets = self.resolve_namespace_reference(glob, resolving);
                if targets.tainted {
                    continue;
                }
                for target in targets.namespaces {
                    aliases
                        .extend(self.type_alias_definitions_in_namespace(&target, name, resolving));
                }
            }
        }
        resolving.remove(&key);
        aliases
    }

    fn value_type_alias_definitions_for_reference(
        &self,
        reference: &TypeReference,
        resolving: &mut BTreeSet<String>,
    ) -> Vec<ValueTypeAliasDefinition> {
        let Some(name) = reference.segments.last() else {
            return Vec::new();
        };
        if reference.segments.len() == 1 && !reference.leading_colon {
            return self.value_type_alias_definitions_in_namespace(
                &reference.context,
                name,
                resolving,
            );
        }
        let namespace_reference = TypeReference {
            segments: reference.segments[..reference.segments.len() - 1].to_vec(),
            generic_arguments: Vec::new(),
            has_unresolved_generic_arguments: false,
            context: reference.context.clone(),
            leading_colon: reference.leading_colon,
        };
        let namespaces = self.resolve_namespace_reference(&namespace_reference, resolving);
        if namespaces.tainted {
            return Vec::new();
        }
        namespaces
            .namespaces
            .iter()
            .flat_map(|namespace| {
                self.value_type_alias_definitions_in_namespace(namespace, name, resolving)
            })
            .collect()
    }

    fn value_type_alias_definitions_in_namespace(
        &self,
        namespace: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> Vec<ValueTypeAliasDefinition> {
        let key = format!("value-type-alias:{}::{name}", namespace.path());
        if !resolving.insert(key.clone()) {
            return Vec::new();
        }
        let exact = namespace.symbol(name);
        if let Some(aliases) = self.value_type_aliases.get(&exact) {
            resolving.remove(&key);
            return aliases.clone();
        }
        let mut aliases = Vec::new();
        if let Some(bindings) = self.symbol_bindings.get(&exact) {
            for binding in bindings {
                aliases.extend(self.value_type_alias_definitions_for_reference(binding, resolving));
            }
        }
        if let Some(globs) = self.glob_imports.get(namespace) {
            for glob in globs {
                let targets = self.resolve_namespace_reference(glob, resolving);
                if targets.tainted {
                    continue;
                }
                for target in targets.namespaces {
                    aliases.extend(
                        self.value_type_alias_definitions_in_namespace(&target, name, resolving),
                    );
                }
            }
        }
        resolving.remove(&key);
        aliases
    }

    fn instantiate_value_type_alias(
        alias: &ValueTypeAliasDefinition,
        arguments: &[Option<ValueTypeReference>],
    ) -> Option<ValueTypeReference> {
        if arguments.len() > alias.parameters.len() {
            return None;
        }
        let mut bindings = BTreeMap::new();
        for (index, parameter) in alias.parameters.iter().enumerate() {
            let argument = if let Some(argument) = arguments.get(index) {
                argument.as_ref()?.clone()
            } else {
                Self::substitute_value_type_reference(parameter.default.as_ref()?, &bindings)?
            };
            bindings.insert(parameter.name.clone(), argument);
        }
        Self::substitute_value_type_reference(&alias.target, &bindings)
    }

    fn substitute_value_type_reference(
        reference: &ValueTypeReference,
        bindings: &BTreeMap<String, ValueTypeReference>,
    ) -> Option<ValueTypeReference> {
        match reference {
            ValueTypeReference::Nominal(reference)
                if reference.segments.len() == 1
                    && reference.generic_arguments.is_empty()
                    && !reference.has_unresolved_generic_arguments
                    && !reference.leading_colon =>
            {
                Some(
                    bindings
                        .get(&reference.segments[0])
                        .cloned()
                        .unwrap_or_else(|| ValueTypeReference::Nominal(reference.clone())),
                )
            }
            ValueTypeReference::Nominal(reference) => {
                Some(ValueTypeReference::Nominal(reference.clone()))
            }
            ValueTypeReference::Parameterized { wrapper, arguments } => {
                Some(ValueTypeReference::Parameterized {
                    wrapper: wrapper.clone(),
                    arguments: arguments
                        .iter()
                        .map(|argument| {
                            argument.as_ref().and_then(|argument| {
                                Self::substitute_value_type_reference(argument, bindings)
                            })
                        })
                        .collect(),
                })
            }
            ValueTypeReference::Tuple(elements) => Some(ValueTypeReference::Tuple(
                elements
                    .iter()
                    .map(|element| {
                        element.as_ref().and_then(|element| {
                            Self::substitute_value_type_reference(element, bindings)
                        })
                    })
                    .collect(),
            )),
        }
    }

    fn value_type_alias_target(
        &self,
        reference: &TypeReference,
        arguments: &[Option<ValueTypeReference>],
    ) -> Option<ValueTypeReference> {
        let aliases =
            self.value_type_alias_definitions_for_reference(reference, &mut BTreeSet::new());
        let [alias] = aliases.as_slice() else {
            return None;
        };
        Self::instantiate_value_type_alias(alias, arguments)
    }

    fn transparent_wrapper_argument_index(
        &self,
        reference: &TypeReference,
        resolving: &mut BTreeSet<String>,
    ) -> Option<usize> {
        self.transparent_wrapper_argument_index_inner(reference, true, resolving)
    }

    fn transparent_wrapper_argument_index_inner(
        &self,
        reference: &TypeReference,
        allow_unqualified_fallback: bool,
        resolving: &mut BTreeSet<String>,
    ) -> Option<usize> {
        let key = format!(
            "transparent-wrapper:{}:{}:{}:{}",
            reference.context.path(),
            reference.leading_colon,
            allow_unqualified_fallback,
            reference.segments.join("::")
        );
        if !resolving.insert(key.clone()) {
            return None;
        }
        let result = (|| {
            let first = reference.segments.first()?;
            let name = reference.segments.last()?;

            if !reference.leading_colon && !matches!(first.as_str(), "crate" | "self" | "super") {
                let exact = reference.context.symbol(first);
                if let Some(bindings) = self.symbol_bindings.get(&exact) {
                    let indices: Vec<_> = bindings
                        .iter()
                        .map(|binding| {
                            let mut expanded = binding.clone();
                            expanded
                                .segments
                                .extend_from_slice(&reference.segments[1..]);
                            if !expanded.leading_colon && expanded.segments.first() == Some(first) {
                                expanded.leading_colon = true;
                            }
                            self.transparent_wrapper_argument_index_inner(
                                &expanded, true, resolving,
                            )
                        })
                        .collect();
                    let [Some(first), rest @ ..] = indices.as_slice() else {
                        return None;
                    };
                    return rest
                        .iter()
                        .all(|candidate| candidate == &Some(*first))
                        .then_some(*first);
                }
            }

            if reference.segments.len() > 1 {
                for split in (1..reference.segments.len()).rev() {
                    let namespace_reference = TypeReference {
                        segments: reference.segments[..split].to_vec(),
                        generic_arguments: Vec::new(),
                        has_unresolved_generic_arguments: false,
                        context: reference.context.clone(),
                        leading_colon: reference.leading_colon,
                    };
                    let namespaces = self
                        .resolve_namespace_reference(&namespace_reference, &mut BTreeSet::new());
                    if namespaces.tainted {
                        if !namespaces.namespaces.is_empty() {
                            return None;
                        }
                        continue;
                    }
                    let Some(namespace) = namespaces.namespaces.first() else {
                        continue;
                    };
                    if namespaces.namespaces.len() != 1 {
                        return None;
                    }
                    let nested = TypeReference {
                        segments: reference.segments[split..].to_vec(),
                        generic_arguments: reference.generic_arguments.clone(),
                        has_unresolved_generic_arguments: reference
                            .has_unresolved_generic_arguments,
                        context: namespace.clone(),
                        leading_colon: false,
                    };
                    return self
                        .transparent_wrapper_argument_index_inner(&nested, false, resolving);
                }

                let index = syntactic_transparent_wrapper_argument_index(reference, false)?;
                if !self.trusted_wrapper_root_is_unshadowed(reference, allow_unqualified_fallback) {
                    return None;
                }
                return Some(index);
            }

            let exact = reference.context.symbol(name);
            if self.value_type_aliases.contains_key(&exact) {
                return None;
            }

            let resolution =
                self.resolve_symbol_reference(SymbolKind::Type, reference, &mut BTreeSet::new());
            if !resolution.symbols.is_empty() {
                return None;
            }

            let mut glob_indices = Vec::new();
            if let Some(globs) = self.glob_imports.get(&reference.context) {
                for glob in globs {
                    let mut expanded = glob.clone();
                    expanded.segments.push(name.clone());
                    if let Some(index) =
                        self.transparent_wrapper_argument_index_inner(&expanded, false, resolving)
                    {
                        glob_indices.push(index);
                        continue;
                    }
                    let targets = self.resolve_namespace_reference(glob, &mut BTreeSet::new());
                    if targets.tainted || targets.namespaces.is_empty() {
                        return None;
                    }
                    let member = self.resolve_symbol_reference(
                        SymbolKind::Type,
                        &expanded,
                        &mut BTreeSet::new(),
                    );
                    if member.tainted || !member.symbols.is_empty() {
                        return None;
                    }
                }
            }
            if let [first, rest @ ..] = glob_indices.as_slice() {
                return rest
                    .iter()
                    .all(|candidate| candidate == first)
                    .then_some(*first);
            }

            if resolution.tainted
                || !allow_unqualified_fallback
                || self
                    .unexpanded_item_macro_namespaces
                    .contains(&reference.context)
            {
                return None;
            }
            syntactic_transparent_wrapper_argument_index(reference, true)
        })();
        resolving.remove(&key);
        result
    }

    fn trusted_wrapper_root_is_unshadowed(
        &self,
        reference: &TypeReference,
        consider_glob_imports: bool,
    ) -> bool {
        if reference.leading_colon {
            return true;
        }
        let Some(first) = reference.segments.first() else {
            return false;
        };
        if self
            .unexpanded_item_macro_namespaces
            .contains(&reference.context)
        {
            return false;
        }
        let exact = reference.context.symbol(first);
        if self
            .types_by_name
            .get(first)
            .is_some_and(|owners| owners.contains(&exact))
            || self.type_aliases.contains_key(&exact)
            || self.value_type_aliases.contains_key(&exact)
        {
            return false;
        }
        if !consider_glob_imports {
            return true;
        }
        let Some(globs) = self.glob_imports.get(&reference.context) else {
            return true;
        };
        for glob in globs {
            let targets = self.resolve_namespace_reference(glob, &mut BTreeSet::new());
            if targets.tainted || targets.namespaces.is_empty() {
                return false;
            }
            for namespace in targets.namespaces {
                let member = self.resolve_namespace_member(&namespace, first, &mut BTreeSet::new());
                if member.tainted || !member.namespaces.is_empty() {
                    return false;
                }
            }
        }
        true
    }

    fn instantiate_type_alias(
        alias: &TypeAliasDefinition,
        reference: &TypeReference,
    ) -> Option<TypeReference> {
        if reference.has_unresolved_generic_arguments
            || alias.parameters.len() != reference.generic_arguments.len()
        {
            return None;
        }
        let mut type_arguments = BTreeMap::new();
        let mut const_arguments = BTreeMap::new();
        for (parameter, argument) in alias.parameters.iter().zip(&reference.generic_arguments) {
            match (parameter, argument) {
                (TypeAliasParameter::Type(parameter), GenericArgumentReference::Type(argument)) => {
                    type_arguments.insert(parameter.clone(), argument.clone());
                }
                (
                    TypeAliasParameter::Const(parameter),
                    GenericArgumentReference::Const(argument),
                ) => {
                    const_arguments.insert(parameter.clone(), argument.clone());
                }
                (
                    TypeAliasParameter::Const(parameter),
                    GenericArgumentReference::Type(argument),
                ) if argument.segments.len() == 1
                    && argument.generic_arguments.is_empty()
                    && !argument.has_unresolved_generic_arguments
                    && !argument.leading_colon =>
                {
                    const_arguments.insert(
                        parameter.clone(),
                        ConstArgumentReference::Path(argument.segments.clone()),
                    );
                }
                _ => return None,
            }
        }
        Self::substitute_type_alias_target(&alias.target, &type_arguments, &const_arguments)
    }

    fn substitute_type_alias_target(
        reference: &TypeReference,
        type_arguments: &BTreeMap<String, TypeReference>,
        const_arguments: &BTreeMap<String, ConstArgumentReference>,
    ) -> Option<TypeReference> {
        if reference.segments.len() == 1
            && reference.generic_arguments.is_empty()
            && !reference.has_unresolved_generic_arguments
            && !reference.leading_colon
        {
            if let Some(argument) = type_arguments.get(&reference.segments[0]) {
                return Some(argument.clone());
            }
        }
        let mut substituted = reference.clone();
        substituted.generic_arguments = reference
            .generic_arguments
            .iter()
            .map(|argument| match argument {
                GenericArgumentReference::Type(argument)
                    if argument.segments.len() == 1
                        && argument.generic_arguments.is_empty()
                        && !argument.has_unresolved_generic_arguments
                        && !argument.leading_colon
                        && const_arguments.contains_key(&argument.segments[0]) =>
                {
                    Some(GenericArgumentReference::Const(
                        const_arguments.get(&argument.segments[0])?.clone(),
                    ))
                }
                GenericArgumentReference::Type(argument) => Some(GenericArgumentReference::Type(
                    Self::substitute_type_alias_target(argument, type_arguments, const_arguments)?,
                )),
                GenericArgumentReference::Const(ConstArgumentReference::Path(path))
                    if path.len() == 1 && const_arguments.contains_key(&path[0]) =>
                {
                    Some(GenericArgumentReference::Const(
                        const_arguments.get(&path[0])?.clone(),
                    ))
                }
                argument => Some(argument.clone()),
            })
            .collect::<Option<Vec<_>>>()?;
        Some(substituted)
    }

    fn direct_generic_parameter<'a>(
        reference: &'a TypeReference,
        parameters: &BTreeSet<String>,
    ) -> Option<&'a str> {
        let [name] = reference.segments.as_slice() else {
            return None;
        };
        (!reference.leading_colon
            && reference.generic_arguments.is_empty()
            && !reference.has_unresolved_generic_arguments
            && parameters.contains(name))
        .then_some(name.as_str())
    }

    fn bind_generic_argument(
        bindings: &mut BTreeMap<String, String>,
        parameter: &str,
        owner: &str,
    ) -> bool {
        if let Some(bound) = bindings.get(parameter) {
            return bound == owner;
        }
        bindings.insert(parameter.to_string(), owner.to_string());
        true
    }

    fn type_reference_owner_bindings(
        &self,
        reference: &TypeReference,
        type_parameters: &BTreeSet<String>,
        const_parameters: &BTreeSet<String>,
        owner: &str,
    ) -> Option<GenericOwnerBindings> {
        let mut bindings = GenericOwnerBindings::default();
        self.unify_type_reference_with_owner(
            reference,
            type_parameters,
            const_parameters,
            owner,
            &mut bindings,
        )
        .then_some(bindings)
    }

    fn unify_type_reference_with_owner(
        &self,
        reference: &TypeReference,
        type_parameters: &BTreeSet<String>,
        const_parameters: &BTreeSet<String>,
        owner: &str,
        bindings: &mut GenericOwnerBindings,
    ) -> bool {
        if let Some(parameter) = Self::direct_generic_parameter(reference, type_parameters) {
            if owner.starts_with('#') {
                return false;
            }
            return Self::bind_generic_argument(&mut bindings.type_arguments, parameter, owner);
        }
        let Some(pattern_owner) = self
            .resolve_type_reference(reference)
            .or_else(|| primitive_type_reference(reference).map(str::to_string))
        else {
            return false;
        };
        let Some((owner, owner_arguments)) = split_resolved_type_identity(owner) else {
            return false;
        };
        if pattern_owner != owner
            || reference.has_unresolved_generic_arguments
            || reference.generic_arguments.len() != owner_arguments.len()
        {
            return false;
        }
        reference
            .generic_arguments
            .iter()
            .zip(owner_arguments)
            .all(|(argument, owner)| match argument {
                GenericArgumentReference::Type(argument) => {
                    if let Some(parameter) =
                        Self::direct_generic_parameter(argument, const_parameters)
                    {
                        owner.starts_with('#')
                            && Self::bind_generic_argument(
                                &mut bindings.const_arguments,
                                parameter,
                                owner,
                            )
                    } else {
                        self.unify_type_reference_with_owner(
                            argument,
                            type_parameters,
                            const_parameters,
                            owner,
                            bindings,
                        )
                    }
                }
                GenericArgumentReference::Const(ConstArgumentReference::Literal(value)) => {
                    owner == format!("#{value}")
                }
                GenericArgumentReference::Const(ConstArgumentReference::Path(path)) => {
                    let [name] = path.as_slice() else {
                        return false;
                    };
                    const_parameters.contains(name)
                        && owner.starts_with('#')
                        && Self::bind_generic_argument(&mut bindings.const_arguments, name, owner)
                }
            })
    }

    fn generic_bindings_for_resolved_owner<'a>(
        &self,
        owner: &'a str,
    ) -> Option<(&'a str, GenericOwnerBindings)> {
        let (nominal_owner, owner_arguments) = split_resolved_type_identity(owner)?;
        let parameters = self.generic_type_parameters.get(nominal_owner)?;
        if parameters.len() != owner_arguments.len() {
            return None;
        }
        let mut bindings = GenericOwnerBindings::default();
        for (parameter, argument) in parameters.iter().zip(owner_arguments) {
            match parameter {
                TypeAliasParameter::Type(parameter) if !argument.starts_with('#') => {
                    bindings
                        .type_arguments
                        .insert(parameter.clone(), argument.to_string());
                }
                TypeAliasParameter::Const(parameter) if argument.starts_with('#') => {
                    bindings
                        .const_arguments
                        .insert(parameter.clone(), argument.to_string());
                }
                _ => return None,
            }
        }
        Some((nominal_owner, bindings))
    }

    fn resolve_type_reference_with_bindings(
        &self,
        reference: &TypeReference,
        bindings: &GenericOwnerBindings,
    ) -> Option<String> {
        if reference.segments.len() == 1
            && reference.generic_arguments.is_empty()
            && !reference.has_unresolved_generic_arguments
            && !reference.leading_colon
        {
            if let Some(owner) = bindings.type_arguments.get(&reference.segments[0]) {
                return Some(owner.clone());
            }
        }
        if reference.has_unresolved_generic_arguments {
            return None;
        }
        let owner = self
            .resolve_type_reference(reference)
            .or_else(|| primitive_type_reference(reference).map(str::to_string))?;
        let arguments: Option<Vec<_>> = reference
            .generic_arguments
            .iter()
            .map(|argument| match argument {
                GenericArgumentReference::Type(argument) => {
                    self.resolve_type_reference_with_bindings(argument, bindings)
                }
                GenericArgumentReference::Const(ConstArgumentReference::Literal(value)) => {
                    Some(format!("#{value}"))
                }
                GenericArgumentReference::Const(ConstArgumentReference::Path(path)) => {
                    let [parameter] = path.as_slice() else {
                        return None;
                    };
                    bindings.const_arguments.get(parameter).cloned()
                }
            })
            .collect();
        Some(resolved_type_identity(owner, &arguments?))
    }

    fn resolve_symbol_reference(
        &self,
        kind: SymbolKind,
        reference: &TypeReference,
        resolving: &mut BTreeSet<String>,
    ) -> SymbolResolution {
        let Some(name) = reference.segments.last() else {
            return SymbolResolution {
                tainted: true,
                ..SymbolResolution::default()
            };
        };
        if reference.segments.len() == 1 && !reference.leading_colon {
            return self.resolve_symbol_in_namespace(kind, &reference.context, name, resolving);
        }

        let namespace_reference = TypeReference {
            segments: reference.segments[..reference.segments.len() - 1].to_vec(),
            generic_arguments: Vec::new(),
            has_unresolved_generic_arguments: false,
            context: reference.context.clone(),
            leading_colon: reference.leading_colon,
        };
        let namespaces = self.resolve_namespace_reference(&namespace_reference, resolving);
        let mut result = SymbolResolution {
            tainted: namespaces.tainted,
            ..SymbolResolution::default()
        };
        for namespace in namespaces.namespaces {
            result.merge(self.resolve_symbol_in_namespace(kind, &namespace, name, resolving));
        }
        result
    }

    fn resolve_symbol_in_namespace(
        &self,
        kind: SymbolKind,
        namespace: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> SymbolResolution {
        let resolution_key = format!("{kind:?}:{}::{name}", namespace.path());
        if !resolving.insert(resolution_key.clone()) {
            return SymbolResolution::default();
        }

        let exact = namespace.symbol(name);
        let direct = match kind {
            SymbolKind::Type => self
                .types_by_name
                .get(name)
                .is_some_and(|candidates| candidates.contains(&exact)),
            SymbolKind::Function => self.function_returns.get(name).is_some_and(|candidates| {
                candidates.iter().any(|candidate| candidate.symbol == exact)
            }),
        };
        if direct {
            resolving.remove(&resolution_key);
            return SymbolResolution::found(exact);
        }

        if let Some(bindings) = self.symbol_bindings.get(&exact) {
            let mut result = SymbolResolution::default();
            let mut resolved_binding = false;
            for binding in bindings {
                if self.binding_targets_same_symbol(binding, namespace, name, resolving) {
                    continue;
                }
                resolved_binding = true;
                result.merge(self.resolve_symbol_reference(kind, binding, resolving));
            }
            if resolved_binding {
                resolving.remove(&resolution_key);
                return result;
            }
        }

        let mut result = SymbolResolution::default();
        if let Some(globs) = self.glob_imports.get(namespace) {
            for glob in globs {
                let targets = self.resolve_namespace_reference(glob, resolving);
                if targets.tainted || targets.namespaces.is_empty() {
                    result.tainted = true;
                }
                for target in targets.namespaces {
                    result.merge(self.resolve_symbol_in_namespace(kind, &target, name, resolving));
                }
            }
        }
        resolving.remove(&resolution_key);
        result
    }

    fn binding_targets_same_symbol(
        &self,
        binding: &TypeReference,
        namespace: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> bool {
        if binding.segments.len() < 2 || binding.segments.last().map(String::as_str) != Some(name) {
            return false;
        }
        let namespace_reference = TypeReference {
            segments: binding.segments[..binding.segments.len() - 1].to_vec(),
            generic_arguments: Vec::new(),
            has_unresolved_generic_arguments: false,
            context: binding.context.clone(),
            leading_colon: binding.leading_colon,
        };
        let target = self.resolve_namespace_reference(&namespace_reference, resolving);
        !target.tainted && target.namespaces.len() == 1 && target.namespaces.contains(namespace)
    }

    fn resolve_namespace_reference(
        &self,
        reference: &TypeReference,
        resolving: &mut BTreeSet<String>,
    ) -> NamespaceResolution {
        let Some(first) = reference.segments.first().map(String::as_str) else {
            return NamespaceResolution::tainted();
        };

        let (mut namespaces, consumed) = if reference.leading_colon {
            let crate_name = normalize_crate_name(first);
            if self.known_crates.contains(&crate_name) {
                (
                    NamespaceResolution::known(ModuleContext {
                        crate_name,
                        modules: Vec::new(),
                    }),
                    1,
                )
            } else {
                return NamespaceResolution::tainted();
            }
        } else {
            match first {
                "crate" => (
                    NamespaceResolution::known(ModuleContext {
                        crate_name: reference.context.crate_name.clone(),
                        modules: Vec::new(),
                    }),
                    1,
                ),
                "self" => (NamespaceResolution::known(reference.context.clone()), 1),
                "super" => {
                    let mut parent = reference.context.clone();
                    let mut consumed = 0;
                    while reference
                        .segments
                        .get(consumed)
                        .is_some_and(|segment| segment == "super")
                    {
                        if parent.modules.pop().is_none() {
                            return NamespaceResolution::tainted();
                        }
                        consumed += 1;
                    }
                    (NamespaceResolution::known(parent), consumed)
                }
                name => (
                    self.resolve_namespace_name_in_scope(&reference.context, name, resolving),
                    1,
                ),
            }
        };

        for segment in &reference.segments[consumed..] {
            let mut next = NamespaceResolution {
                tainted: namespaces.tainted,
                ..NamespaceResolution::default()
            };
            for namespace in namespaces.namespaces {
                next.merge(self.resolve_namespace_member(&namespace, segment, resolving));
            }
            namespaces = next;
        }
        namespaces
    }

    fn resolve_namespace_name_in_scope(
        &self,
        context: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> NamespaceResolution {
        let resolution_key = format!("scope-namespace:{}::{name}", context.path());
        if !resolving.insert(resolution_key.clone()) {
            return NamespaceResolution::default();
        }

        let binding_name = context.symbol(name);
        if let Some(bindings) = self.symbol_bindings.get(&binding_name) {
            let mut result = NamespaceResolution::default();
            for binding in bindings {
                result.merge(self.resolve_namespace_reference(binding, resolving));
            }
            resolving.remove(&resolution_key);
            return result;
        }

        let mut child = context.clone();
        child.modules.push(name.to_string());
        if self.namespace_exists(&child) {
            resolving.remove(&resolution_key);
            return NamespaceResolution::known(child);
        }

        let crate_name = normalize_crate_name(name);
        if self.known_crates.contains(&crate_name) {
            resolving.remove(&resolution_key);
            return NamespaceResolution::known(ModuleContext {
                crate_name,
                modules: Vec::new(),
            });
        }
        resolving.remove(&resolution_key);
        NamespaceResolution::tainted()
    }

    fn resolve_namespace_member(
        &self,
        context: &ModuleContext,
        name: &str,
        resolving: &mut BTreeSet<String>,
    ) -> NamespaceResolution {
        let resolution_key = format!("namespace:{}::{name}", context.path());
        if !resolving.insert(resolution_key.clone()) {
            return NamespaceResolution::default();
        }

        let binding_name = context.symbol(name);
        if let Some(bindings) = self.symbol_bindings.get(&binding_name) {
            let mut result = NamespaceResolution::default();
            for binding in bindings {
                result.merge(self.resolve_namespace_reference(binding, resolving));
            }
            resolving.remove(&resolution_key);
            return result;
        }

        let mut child = context.clone();
        child.modules.push(name.to_string());
        if self.namespace_exists(&child) {
            resolving.remove(&resolution_key);
            return NamespaceResolution::known(child);
        }

        let mut result = NamespaceResolution::default();
        if let Some(globs) = self.glob_imports.get(context) {
            for glob in globs {
                let targets = self.resolve_namespace_reference(glob, resolving);
                if targets.tainted || targets.namespaces.is_empty() {
                    result.tainted = true;
                }
                for target in targets.namespaces {
                    result.merge(self.resolve_namespace_member(&target, name, resolving));
                }
            }
        }
        resolving.remove(&resolution_key);
        result
    }

    fn schema_owner(&self, owner: &str) -> Option<String> {
        // A key produced by the module-surface walk names its owner exactly,
        // because that walk resolved the type as it descended instead of
        // reading a bare definition title out of a JSON Schema. Every key in
        // `fields` is fully qualified (`crate::module::Type`), so a bare
        // schema title can never land here and the JSON-Schema callers below
        // keep their existing name-based resolution.
        if self.fields.contains_key(owner) {
            return Some(owner.to_string());
        }
        let candidates = self.types_by_name.get(owner)?;
        if candidates.len() == 1 {
            return candidates.first().cloned();
        }
        let config_candidates: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                candidate.split("::").next().is_some_and(|crate_name| {
                    crate_name == "config"
                        || crate_name == "sbproxy_config"
                        || crate_name.ends_with("_config")
                })
            })
            .cloned()
            .collect();
        (config_candidates.len() == 1)
            .then(|| config_candidates.into_iter().next())
            .flatten()
    }

    fn record_function_return(&mut self, signature: &syn::Signature, context: &ModuleContext) {
        let syn::ReturnType::Type(_, ty) = &signature.output else {
            return;
        };
        let Some(result) = value_type_reference(ty, context) else {
            return;
        };
        let name = signature.ident.to_string();
        self.function_returns
            .entry(name.clone())
            .or_default()
            .push(FunctionReturn {
                symbol: context.symbol(&name),
                result,
            });
    }

    fn signature_receiver(signature: &syn::Signature) -> Option<MethodReceiver> {
        let Some(syn::FnArg::Receiver(receiver)) = signature.inputs.first() else {
            return None;
        };
        Some(
            if receiver.reference.is_some() && receiver.mutability.is_some()
                || receiver.colon_token.is_some() && type_is_mutable_reference(&receiver.ty)
            {
                MethodReceiver::Mutable
            } else {
                MethodReceiver::SharedOrValue
            },
        )
    }

    fn record_method_signature(
        &mut self,
        owner: &TypeReference,
        type_parameters: &BTreeSet<String>,
        const_parameters: &BTreeSet<String>,
        requirements: &GenericRequirements,
        signature: &syn::Signature,
    ) {
        let Some(receiver) = Self::signature_receiver(signature) else {
            return;
        };
        self.method_signatures
            .entry(signature.ident.to_string())
            .or_default()
            .push(MethodSignature {
                owner: owner.clone(),
                type_parameters: type_parameters.clone(),
                const_parameters: const_parameters.clone(),
                requirements: requirements.clone(),
                receiver,
            });
    }

    fn record_trait(&mut self, item: &syn::ItemTrait, context: &ModuleContext) {
        let name = item.ident.to_string();
        let owner = context.symbol(&name);
        self.record_type(&owner, &name);
        for trait_item in &item.items {
            let syn::TraitItem::Fn(method) = trait_item else {
                continue;
            };
            if attributes_exclude_production(&method.attrs) {
                continue;
            }
            let Some(receiver) = Self::signature_receiver(&method.sig) else {
                continue;
            };
            self.trait_method_signatures
                .entry(owner.clone())
                .or_default()
                .entry(method.sig.ident.to_string())
                .or_default()
                .push(TraitMethodSignature {
                    receiver,
                    has_default: method.default.is_some(),
                });
        }
    }

    fn collect_required_trait_bounds<'b>(
        bounds: impl IntoIterator<Item = &'b syn::TypeParamBound>,
        context: &ModuleContext,
        out: &mut Vec<TypeReference>,
        has_unresolved_requirements: &mut bool,
    ) {
        for bound in bounds {
            match bound {
                syn::TypeParamBound::Trait(bound)
                    if matches!(bound.modifier, syn::TraitBoundModifier::None) =>
                {
                    if let Some(reference) = path_reference(&bound.path, context) {
                        out.push(reference);
                    } else {
                        *has_unresolved_requirements = true;
                    }
                }
                syn::TypeParamBound::Trait(_) | syn::TypeParamBound::Lifetime(_) => {}
                _ => *has_unresolved_requirements = true,
            }
        }
    }

    fn blanket_trait_bounds(
        item: &syn::ItemImpl,
        parameter: &str,
        type_parameters: &BTreeSet<String>,
        context: &ModuleContext,
    ) -> (Vec<TypeReference>, bool) {
        let mut bounds = Vec::new();
        let mut has_unresolved_requirements = false;
        if let Some(parameter) = item.generics.params.iter().find_map(|candidate| {
            let syn::GenericParam::Type(candidate) = candidate else {
                return None;
            };
            (candidate.ident == parameter).then_some(candidate)
        }) {
            Self::collect_required_trait_bounds(
                &parameter.bounds,
                context,
                &mut bounds,
                &mut has_unresolved_requirements,
            );
        }
        if let Some(where_clause) = &item.generics.where_clause {
            for predicate in &where_clause.predicates {
                match predicate {
                    syn::WherePredicate::Type(predicate)
                        if direct_type_parameter_name(&predicate.bounded_ty, type_parameters)
                            .as_deref()
                            == Some(parameter) =>
                    {
                        Self::collect_required_trait_bounds(
                            &predicate.bounds,
                            context,
                            &mut bounds,
                            &mut has_unresolved_requirements,
                        );
                    }
                    syn::WherePredicate::Lifetime(_) => {}
                    _ => has_unresolved_requirements = true,
                }
            }
        }
        (bounds, has_unresolved_requirements)
    }

    fn generic_requirements(
        generics: &syn::Generics,
        type_parameters: &BTreeSet<String>,
        context: &ModuleContext,
    ) -> GenericRequirements {
        let mut requirements = GenericRequirements::default();
        for parameter in &generics.params {
            let syn::GenericParam::Type(parameter) = parameter else {
                continue;
            };
            let mut bounds = Vec::new();
            Self::collect_required_trait_bounds(
                &parameter.bounds,
                context,
                &mut bounds,
                &mut requirements.has_unresolved_requirements,
            );
            requirements.trait_bounds.extend(
                bounds
                    .into_iter()
                    .map(|bound| (parameter.ident.to_string(), bound)),
            );
        }
        if let Some(where_clause) = &generics.where_clause {
            for predicate in &where_clause.predicates {
                match predicate {
                    syn::WherePredicate::Type(predicate) => {
                        let Some(parameter) =
                            direct_type_parameter_name(&predicate.bounded_ty, type_parameters)
                        else {
                            requirements.has_unresolved_requirements = true;
                            continue;
                        };
                        let mut bounds = Vec::new();
                        Self::collect_required_trait_bounds(
                            &predicate.bounds,
                            context,
                            &mut bounds,
                            &mut requirements.has_unresolved_requirements,
                        );
                        requirements
                            .trait_bounds
                            .extend(bounds.into_iter().map(|bound| (parameter.clone(), bound)));
                    }
                    syn::WherePredicate::Lifetime(_) => {}
                    _ => requirements.has_unresolved_requirements = true,
                }
            }
        }
        requirements
    }

    fn record_trait_implementation(&mut self, item: &syn::ItemImpl, context: &ModuleContext) {
        let Some((negative, trait_path, _)) = &item.trait_ else {
            return;
        };
        if negative.is_some() {
            return;
        }
        let Some(trait_reference) = path_reference(trait_path, context) else {
            return;
        };
        let (type_parameters, const_parameters) = generic_parameter_names(&item.generics);
        let requirements = Self::generic_requirements(&item.generics, &type_parameters, context);
        let owner =
            if let Some(parameter) = direct_type_parameter_name(&item.self_ty, &type_parameters) {
                let (bounds, has_unresolved_requirements) =
                    Self::blanket_trait_bounds(item, &parameter, &type_parameters, context);
                TraitImplementationOwner::Blanket {
                    bounds,
                    has_unresolved_requirements,
                }
            } else {
                let Some(owner) = nominal_type_reference(&item.self_ty, context) else {
                    return;
                };
                TraitImplementationOwner::Exact(owner)
            };
        let mut method_signatures = BTreeMap::<String, Vec<MethodReceiver>>::new();
        for impl_item in &item.items {
            let syn::ImplItem::Fn(method) = impl_item else {
                continue;
            };
            if attributes_exclude_production(&method.attrs) {
                continue;
            }
            if let Some(receiver) = Self::signature_receiver(&method.sig) {
                method_signatures
                    .entry(method.sig.ident.to_string())
                    .or_default()
                    .push(receiver);
            }
        }
        self.trait_implementations.push(TraitImplementation {
            trait_reference,
            owner,
            type_parameters,
            const_parameters,
            requirements,
            method_signatures,
        });
    }

    fn receiver_resolution(receivers: &BTreeSet<MethodReceiver>) -> MethodReceiverResolution {
        match receivers.len() {
            0 => MethodReceiverResolution::Missing,
            1 if receivers.contains(&MethodReceiver::SharedOrValue) => {
                MethodReceiverResolution::SharedOrValue
            }
            1 => MethodReceiverResolution::Mutable,
            _ => MethodReceiverResolution::Ambiguous,
        }
    }

    fn generic_requirements_applicability(
        &self,
        requirements: &GenericRequirements,
        bindings: &GenericOwnerBindings,
        resolving: &mut BTreeSet<String>,
    ) -> TraitImplementationApplicability {
        if requirements.has_unresolved_requirements {
            return TraitImplementationApplicability::Rejected;
        }
        let mut applicability = TraitImplementationApplicability::Proven;
        for (parameter, bound) in &requirements.trait_bounds {
            let Some(owner) = bindings.type_arguments.get(parameter) else {
                return TraitImplementationApplicability::Rejected;
            };
            let bound_applicability = if let Some(bound) = self.resolve_type_reference(bound) {
                self.owner_implements_trait(owner, &bound, resolving)
            } else {
                self.external_trait_bound_applicability(owner, bound)
            };
            match bound_applicability {
                TraitImplementationApplicability::Rejected => {
                    return TraitImplementationApplicability::Rejected;
                }
                TraitImplementationApplicability::ExternallyConstrained => {
                    applicability = TraitImplementationApplicability::ExternallyConstrained;
                }
                TraitImplementationApplicability::Proven => {}
            }
        }
        applicability
    }

    fn trait_implementation_applies(
        &self,
        implementation: &TraitImplementation,
        owner: &str,
        resolving: &mut BTreeSet<String>,
    ) -> TraitImplementationApplicability {
        match &implementation.owner {
            TraitImplementationOwner::Blanket {
                bounds,
                has_unresolved_requirements,
            } => {
                if *has_unresolved_requirements {
                    return TraitImplementationApplicability::Rejected;
                }
                let mut applicability = TraitImplementationApplicability::Proven;
                for bound in bounds {
                    let bound_applicability =
                        if let Some(bound) = self.resolve_type_reference(bound) {
                            self.owner_implements_trait(owner, &bound, resolving)
                        } else {
                            self.external_trait_bound_applicability(owner, bound)
                        };
                    match bound_applicability {
                        TraitImplementationApplicability::Rejected => {
                            return TraitImplementationApplicability::Rejected;
                        }
                        TraitImplementationApplicability::ExternallyConstrained => {
                            applicability = TraitImplementationApplicability::ExternallyConstrained;
                        }
                        TraitImplementationApplicability::Proven => {}
                    }
                }
                applicability
            }
            TraitImplementationOwner::Exact(reference) => {
                let Some(bindings) = self.type_reference_owner_bindings(
                    reference,
                    &implementation.type_parameters,
                    &implementation.const_parameters,
                    owner,
                ) else {
                    return TraitImplementationApplicability::Rejected;
                };
                self.generic_requirements_applicability(
                    &implementation.requirements,
                    &bindings,
                    resolving,
                )
            }
        }
    }

    fn unresolved_trait_bound_is_external(&self, reference: &TypeReference) -> bool {
        let Some(first) = reference.segments.first().map(String::as_str) else {
            return false;
        };
        let Some(last) = reference.segments.last() else {
            return false;
        };
        !self.types_by_name.contains_key(last)
            && !matches!(first, "crate" | "self" | "super")
            && !self.known_crates.contains(&normalize_crate_name(first))
    }

    fn external_trait_bound_applicability(
        &self,
        owner: &str,
        reference: &TypeReference,
    ) -> TraitImplementationApplicability {
        if !self.unresolved_trait_bound_is_external(reference) {
            return TraitImplementationApplicability::Rejected;
        }
        let Some(bound) = reference.segments.last().map(String::as_str) else {
            return TraitImplementationApplicability::Rejected;
        };
        let explicit = self.explicit_external_trait_applicability(owner, bound);
        if explicit != TraitImplementationApplicability::Rejected {
            return explicit;
        }
        let Some((nominal_owner, _)) = split_resolved_type_identity(owner) else {
            return TraitImplementationApplicability::Rejected;
        };
        if self
            .derived_traits
            .get(nominal_owner)
            .is_some_and(|traits| traits.contains(bound))
        {
            return TraitImplementationApplicability::Proven;
        }
        if matches!(bound, "Send" | "Sync") {
            return self.structural_auto_trait_applicability(owner, bound, &mut BTreeSet::new());
        }
        TraitImplementationApplicability::ExternallyConstrained
    }

    fn explicit_external_trait_applicability(
        &self,
        owner: &str,
        bound: &str,
    ) -> TraitImplementationApplicability {
        let mut applicability = TraitImplementationApplicability::Rejected;
        for implementation in &self.trait_implementations {
            if implementation
                .trait_reference
                .segments
                .last()
                .map(String::as_str)
                != Some(bound)
                || !self.unresolved_trait_bound_is_external(&implementation.trait_reference)
            {
                continue;
            }
            let TraitImplementationOwner::Exact(reference) = &implementation.owner else {
                continue;
            };
            let Some(bindings) = self.type_reference_owner_bindings(
                reference,
                &implementation.type_parameters,
                &implementation.const_parameters,
                owner,
            ) else {
                continue;
            };
            match self.generic_requirements_applicability(
                &implementation.requirements,
                &bindings,
                &mut BTreeSet::new(),
            ) {
                TraitImplementationApplicability::Proven => {
                    return TraitImplementationApplicability::Proven;
                }
                TraitImplementationApplicability::ExternallyConstrained => {
                    applicability = TraitImplementationApplicability::ExternallyConstrained;
                }
                TraitImplementationApplicability::Rejected => {}
            }
        }
        applicability
    }

    fn structural_auto_trait_applicability(
        &self,
        owner: &str,
        auto_trait: &str,
        resolving: &mut BTreeSet<String>,
    ) -> TraitImplementationApplicability {
        let Some((nominal_owner, _)) = split_resolved_type_identity(owner) else {
            return TraitImplementationApplicability::Rejected;
        };
        let resolution_key = format!("{auto_trait}:{nominal_owner}");
        if !resolving.insert(resolution_key.clone()) {
            return TraitImplementationApplicability::ExternallyConstrained;
        }
        let applicability = self.type_components.get(nominal_owner).map_or(
            TraitImplementationApplicability::ExternallyConstrained,
            |components| {
                let mut applicability = TraitImplementationApplicability::Proven;
                for component in components {
                    let component_applicability = component.as_ref().map_or(
                        TraitImplementationApplicability::ExternallyConstrained,
                        |component| {
                            self.auto_trait_component_applicability(
                                component, auto_trait, resolving,
                            )
                        },
                    );
                    match component_applicability {
                        TraitImplementationApplicability::Rejected => {
                            return TraitImplementationApplicability::Rejected;
                        }
                        TraitImplementationApplicability::ExternallyConstrained => {
                            applicability = TraitImplementationApplicability::ExternallyConstrained;
                        }
                        TraitImplementationApplicability::Proven => {}
                    }
                }
                applicability
            },
        );
        resolving.remove(&resolution_key);
        applicability
    }

    fn auto_trait_component_applicability(
        &self,
        component: &TypeReference,
        auto_trait: &str,
        resolving: &mut BTreeSet<String>,
    ) -> TraitImplementationApplicability {
        if primitive_type_reference(component).is_some() {
            return TraitImplementationApplicability::Proven;
        }
        let component_name = component.segments.last().map(String::as_str);
        if component_name == Some("Rc") {
            return TraitImplementationApplicability::Rejected;
        }
        if component_name == Some("MutexGuard") {
            if auto_trait == "Send" {
                return TraitImplementationApplicability::Rejected;
            }
            if auto_trait == "Sync" {
                if component.has_unresolved_generic_arguments {
                    return TraitImplementationApplicability::ExternallyConstrained;
                }
                let mut applicability = TraitImplementationApplicability::Proven;
                for argument in &component.generic_arguments {
                    let GenericArgumentReference::Type(argument) = argument else {
                        continue;
                    };
                    match self.auto_trait_component_applicability(argument, auto_trait, resolving) {
                        TraitImplementationApplicability::Rejected => {
                            return TraitImplementationApplicability::Rejected;
                        }
                        TraitImplementationApplicability::ExternallyConstrained => {
                            applicability = TraitImplementationApplicability::ExternallyConstrained;
                        }
                        TraitImplementationApplicability::Proven => {}
                    }
                }
                return applicability;
            }
        }
        if let Some(owner) = self.resolve_exact_type_reference(component) {
            return self.structural_auto_trait_applicability(&owner, auto_trait, resolving);
        }
        TraitImplementationApplicability::ExternallyConstrained
    }

    fn owner_implements_trait(
        &self,
        owner: &str,
        trait_owner: &str,
        resolving: &mut BTreeSet<String>,
    ) -> TraitImplementationApplicability {
        let key = format!("{owner}:{trait_owner}");
        if !resolving.insert(key.clone()) {
            return TraitImplementationApplicability::Rejected;
        }
        let applicability = self.trait_implementations_by_trait.get(trait_owner).map_or(
            TraitImplementationApplicability::Rejected,
            |implementations| {
                let mut applicability = TraitImplementationApplicability::Rejected;
                for implementation in implementations {
                    match self.trait_implementation_applies(
                        &self.trait_implementations[*implementation],
                        owner,
                        resolving,
                    ) {
                        TraitImplementationApplicability::Proven => {
                            return TraitImplementationApplicability::Proven;
                        }
                        TraitImplementationApplicability::ExternallyConstrained => {
                            applicability = TraitImplementationApplicability::ExternallyConstrained;
                        }
                        TraitImplementationApplicability::Rejected => {}
                    }
                }
                applicability
            },
        );
        resolving.remove(&key);
        applicability
    }

    fn method_receiver(
        &self,
        owner: &str,
        method: &str,
        in_scope_traits: &BTreeSet<String>,
    ) -> MethodReceiverResolution {
        let mut receivers = BTreeSet::new();
        let mut externally_constrained_receivers = BTreeSet::new();
        if let Some(signatures) = self.method_signatures.get(method) {
            for signature in signatures {
                let Some(bindings) = self.type_reference_owner_bindings(
                    &signature.owner,
                    &signature.type_parameters,
                    &signature.const_parameters,
                    owner,
                ) else {
                    continue;
                };
                let target = match self.generic_requirements_applicability(
                    &signature.requirements,
                    &bindings,
                    &mut BTreeSet::new(),
                ) {
                    TraitImplementationApplicability::Rejected => continue,
                    TraitImplementationApplicability::ExternallyConstrained => {
                        &mut externally_constrained_receivers
                    }
                    TraitImplementationApplicability::Proven => &mut receivers,
                };
                target.insert(signature.receiver);
            }
        }
        let inherent = Self::receiver_resolution(&receivers);
        if inherent != MethodReceiverResolution::Missing {
            return inherent;
        }
        if in_scope_traits.is_empty() {
            return Self::receiver_resolution(&externally_constrained_receivers);
        }

        for trait_owner in in_scope_traits {
            let Some(implementations) = self.trait_implementations_by_trait.get(trait_owner) else {
                continue;
            };
            for implementation in implementations {
                let implementation = &self.trait_implementations[*implementation];
                let target = match self.trait_implementation_applies(
                    implementation,
                    owner,
                    &mut BTreeSet::new(),
                ) {
                    TraitImplementationApplicability::Rejected => continue,
                    TraitImplementationApplicability::ExternallyConstrained => {
                        &mut externally_constrained_receivers
                    }
                    TraitImplementationApplicability::Proven => &mut receivers,
                };
                if let Some(overrides) = implementation.method_signatures.get(method) {
                    target.extend(overrides);
                    continue;
                }
                let Some(signatures) = self
                    .trait_method_signatures
                    .get(trait_owner)
                    .and_then(|methods| methods.get(method))
                else {
                    continue;
                };
                target.extend(
                    signatures
                        .iter()
                        .filter(|signature| signature.has_default)
                        .map(|signature| signature.receiver),
                );
            }
        }
        let proven = Self::receiver_resolution(&receivers);
        if proven != MethodReceiverResolution::Missing {
            return proven;
        }
        Self::receiver_resolution(&externally_constrained_receivers)
    }
}

struct TypeIndexVisitor<'a> {
    index: &'a mut RustTypeIndex,
    context: ModuleContext,
}

impl<'ast> Visit<'ast> for TypeIndexVisitor<'_> {
    fn visit_block(&mut self, _node: &'ast syn::Block) {
        // Block-local imports are resolved by `FieldReadVisitor` with their
        // lexical scope; indexing them as module imports would leak aliases
        // into unrelated functions.
    }

    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !item_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        self.index.record_context(&self.context.child(&node.ident));
        let Some((_, items)) = &node.content else {
            return;
        };
        let saved_context = self.context.clone();
        self.context = self.context.child(&node.ident);
        for item in items {
            self.visit_item(item);
        }
        self.context = saved_context;
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.ident.is_none() && !attributes_exclude_production(&node.attrs) {
            self.index
                .unexpanded_item_macro_namespaces
                .insert(self.context.clone());
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let owner = self.context.symbol(&node.ident.to_string());
        self.index.record_type(&owner, &node.ident.to_string());
        self.index
            .record_generic_type_parameters(&owner, &node.generics);
        self.index.record_derived_traits(&owner, &node.attrs);
        if let Some(fields) = RustTypeIndex::tuple_field_references(&node.fields, &self.context) {
            self.index.tuple_struct_fields.insert(owner.clone(), fields);
        }
        self.index
            .record_fields(&owner, &node.fields, &node.attrs, &self.context);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let owner = self.context.symbol(&node.ident.to_string());
        self.index.record_enum(&owner, node, &self.context);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !attributes_exclude_production(&node.attrs) {
            self.index.record_function_return(&node.sig, &self.context);
        }
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if !attributes_exclude_production(&node.attrs) {
            self.index.record_trait(node, &self.context);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        if node.trait_.is_some() {
            self.index.record_trait_implementation(node, &self.context);
            return;
        }
        let Some(owner) = nominal_type_reference(&node.self_ty, &self.context) else {
            return;
        };
        let (type_parameters, const_parameters) = generic_parameter_names(&node.generics);
        let requirements =
            RustTypeIndex::generic_requirements(&node.generics, &type_parameters, &self.context);
        for item in &node.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if !attributes_exclude_production(&method.attrs) {
                self.index.record_method_signature(
                    &owner,
                    &type_parameters,
                    &const_parameters,
                    &requirements,
                    &method.sig,
                );
            }
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        let alias = self.context.symbol(&node.ident.to_string());
        if let Some(target) = value_type_reference(&node.ty, &self.context) {
            self.index.record_value_type_alias(
                alias.clone(),
                &node.generics,
                target,
                &self.context,
            );
        }
        if let Some(target) = type_reference(&node.ty, &self.context) {
            self.index
                .record_type_alias(alias.clone(), &node.generics, target.clone());
            self.index.record_symbol_binding(alias, target);
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut bindings = Vec::new();
        let mut globs = Vec::new();
        let mut anonymous = Vec::new();
        collect_use_bindings(
            &node.tree,
            &mut Vec::new(),
            &mut bindings,
            &mut globs,
            &mut anonymous,
        );
        for (alias, segments) in bindings {
            self.index.record_symbol_binding(
                self.context.symbol(&alias),
                TypeReference {
                    segments,
                    generic_arguments: Vec::new(),
                    has_unresolved_generic_arguments: false,
                    context: self.context.clone(),
                    leading_colon: node.leading_colon.is_some(),
                },
            );
        }
        for segments in globs {
            self.index.record_glob_import(
                &self.context,
                TypeReference {
                    segments,
                    generic_arguments: Vec::new(),
                    has_unresolved_generic_arguments: false,
                    context: self.context.clone(),
                    leading_colon: node.leading_colon.is_some(),
                },
            );
        }
        for segments in anonymous {
            self.index.record_anonymous_import(
                &self.context,
                TypeReference {
                    segments,
                    generic_arguments: Vec::new(),
                    has_unresolved_generic_arguments: false,
                    context: self.context.clone(),
                    leading_colon: node.leading_colon.is_some(),
                },
            );
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let alias = node
            .rename
            .as_ref()
            .map(|(_, alias)| alias.to_string())
            .unwrap_or_else(|| node.ident.to_string());
        let ident = node.ident.to_string();
        let (segments, leading_colon) = if ident == "self" {
            (vec!["crate".to_string()], false)
        } else {
            (vec![ident], true)
        };
        self.index.record_symbol_binding(
            self.context.symbol(&alias),
            TypeReference {
                segments,
                generic_arguments: Vec::new(),
                has_unresolved_generic_arguments: false,
                context: self.context.clone(),
                leading_colon,
            },
        );
    }
}

fn collect_use_bindings(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut Vec<(String, Vec<String>)>,
    globs: &mut Vec<Vec<String>>,
    anonymous: &mut Vec<Vec<String>>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_bindings(&path.tree, prefix, out, globs, anonymous);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let ident = name.ident.to_string();
            if ident == "self" {
                if let Some(alias) = prefix.last().cloned() {
                    out.push((alias, prefix.clone()));
                }
            } else {
                let mut target = prefix.clone();
                target.push(ident.clone());
                out.push((ident, target));
            }
        }
        syn::UseTree::Rename(rename) => {
            let alias = rename.rename.to_string();
            let mut target = prefix.clone();
            let ident = rename.ident.to_string();
            if ident != "self" {
                target.push(ident);
            }
            if alias == "_" {
                anonymous.push(target);
            } else {
                out.push((alias, target));
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_bindings(item, prefix, out, globs, anonymous);
            }
        }
        syn::UseTree::Glob(_) => globs.push(prefix.clone()),
    }
}

fn rust_type_index(sources: &[&SourceFile]) -> RustTypeIndex {
    let mut index = RustTypeIndex::default();
    for source in sources {
        let Some(context) = ModuleContext::from_source_path(&source.path) else {
            continue;
        };
        index.record_context(&context);
        if let Ok(file) = &source.ast {
            let mut visitor = TypeIndexVisitor {
                index: &mut index,
                context,
            };
            visitor.visit_file(file);
        }
    }
    index.finalize_trait_method_candidates();
    index
}

fn serde_enum_tag(attributes: &[syn::Attribute]) -> Option<String> {
    let mut tag = None;
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
    {
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                tag = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.input.peek(syn::Token![=]) {
                let _ = meta.value()?.parse::<syn::Expr>()?;
            }
            Ok(())
        });
    }
    tag
}

/// Whether a struct field is lifted into its parent object by serde.
///
/// Written the same way as [`serde_enum_tag`], and with the same known
/// limitation: an attribute shaped `rename(serialize = "a")` makes
/// `parse_nested_meta` give up part-way, so anything after it in the same
/// attribute is not seen. Config types do not mix that form with `flatten`
/// today, and being wrong here costs a spurious path segment rather than a
/// missed read.
fn field_is_flattened(attributes: &[syn::Attribute]) -> bool {
    let mut flattened = false;
    for attribute in attributes.iter().filter(|attribute| {
        attribute.path().is_ident("serde") || attribute.path().is_ident("schemars")
    }) {
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("flatten") {
                flattened = true;
            } else if meta.input.peek(syn::Token![=]) {
                let _ = meta.value()?.parse::<syn::Expr>()?;
            }
            Ok(())
        });
    }
    flattened
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RenameRule {
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl RenameRule {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "lowercase" => Some(Self::Lower),
            "UPPERCASE" => Some(Self::Upper),
            "PascalCase" => Some(Self::Pascal),
            "camelCase" => Some(Self::Camel),
            "snake_case" => Some(Self::Snake),
            "SCREAMING_SNAKE_CASE" => Some(Self::ScreamingSnake),
            "kebab-case" => Some(Self::Kebab),
            "SCREAMING-KEBAB-CASE" => Some(Self::ScreamingKebab),
            _ => None,
        }
    }

    fn apply_to_field(self, field: &str) -> String {
        match self {
            Self::Lower | Self::Snake => field.to_string(),
            Self::Upper => field.to_ascii_uppercase(),
            Self::Pascal => pascal_case_field(field),
            Self::Camel => {
                let mut pascal = pascal_case_field(field);
                if let Some(first) = pascal.get_mut(0..1) {
                    first.make_ascii_lowercase();
                }
                pascal
            }
            Self::ScreamingSnake => field.to_ascii_uppercase(),
            Self::Kebab => field.replace('_', "-"),
            Self::ScreamingKebab => field.to_ascii_uppercase().replace('_', "-"),
        }
    }
}

fn pascal_case_field(field: &str) -> String {
    let mut output = String::with_capacity(field.len());
    let mut capitalize = true;
    for character in field.chars() {
        if character == '_' {
            capitalize = true;
        } else if capitalize {
            output.extend(character.to_uppercase());
            capitalize = false;
        } else {
            output.push(character);
        }
    }
    output
}

fn meta_items(list: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    list.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .ok()
        .map(|items| items.into_iter().collect())
}

fn meta_string_value(meta: &syn::Meta) -> Option<String> {
    let syn::Meta::NameValue(name_value) = meta else {
        return None;
    };
    let syn::Expr::Lit(expression) = &name_value.value else {
        return None;
    };
    let syn::Lit::Str(value) = &expression.lit else {
        return None;
    };
    Some(value.value())
}

fn attribute_string_setting(meta: &syn::Meta, setting: &str) -> Option<String> {
    let syn::Meta::List(list) = meta else {
        return None;
    };
    for item in meta_items(list)? {
        if !item.path().is_ident(setting) {
            continue;
        }
        if let Some(value) = meta_string_value(&item) {
            return Some(value);
        }
        let syn::Meta::List(directions) = item else {
            continue;
        };
        for direction in meta_items(&directions)? {
            if direction.path().is_ident("deserialize") {
                return meta_string_value(&direction);
            }
        }
    }
    None
}

fn apply_attribute_setting(
    states: &BTreeSet<Option<String>>,
    meta: &syn::Meta,
    attribute_name: &str,
    setting: &str,
) -> BTreeSet<Option<String>> {
    if meta.path().is_ident(attribute_name) {
        let Some(value) = attribute_string_setting(meta, setting) else {
            return states.clone();
        };
        return BTreeSet::from([Some(value)]);
    }

    let syn::Meta::List(list) = meta else {
        return states.clone();
    };
    if !list.path.is_ident("cfg_attr") {
        return states.clone();
    }
    let Some(items) = meta_items(list) else {
        return states.clone();
    };
    let Some((condition, nested_attributes)) = items.split_first() else {
        return states.clone();
    };
    let (can_be_true, can_be_false) = production_cfg_condition_possibility(condition);
    let mut possibilities = BTreeSet::new();
    if can_be_false {
        possibilities.extend(states.iter().cloned());
    }
    if can_be_true {
        let mut applied = states.clone();
        for nested in nested_attributes {
            applied = apply_attribute_setting(&applied, nested, attribute_name, setting);
        }
        possibilities.extend(applied);
    }
    if possibilities.is_empty() {
        states.clone()
    } else {
        possibilities
    }
}

fn possible_attribute_settings(
    attributes: &[syn::Attribute],
    attribute_name: &str,
    setting: &str,
) -> BTreeSet<Option<String>> {
    attributes
        .iter()
        .fold(BTreeSet::from([None]), |states, attribute| {
            apply_attribute_setting(&states, &attribute.meta, attribute_name, setting)
        })
}

fn possible_schema_attribute_settings(
    attributes: &[syn::Attribute],
    setting: &str,
) -> BTreeSet<Option<String>> {
    let schemars = possible_attribute_settings(attributes, "schemars", setting);
    let serde = possible_attribute_settings(attributes, "serde", setting);
    let mut settings = BTreeSet::new();
    for schema_setting in &schemars {
        for serde_setting in &serde {
            settings.insert(schema_setting.as_ref().or(serde_setting.as_ref()).cloned());
        }
    }
    settings
}

fn possible_schema_field_names(
    field: &str,
    field_attributes: &[syn::Attribute],
    container_attributes: &[syn::Attribute],
) -> BTreeSet<String> {
    let explicit_names = possible_schema_attribute_settings(field_attributes, "rename");
    let rename_rules = possible_schema_attribute_settings(container_attributes, "rename_all");
    let mut names = BTreeSet::new();
    for explicit_name in explicit_names {
        if let Some(explicit_name) = explicit_name {
            names.insert(explicit_name);
            continue;
        }
        for rule in &rename_rules {
            let name = rule
                .as_deref()
                .and_then(RenameRule::parse)
                .map_or_else(|| field.to_string(), |rule| rule.apply_to_field(field));
            names.insert(name);
        }
    }
    names
}

fn type_reference(ty: &syn::Type, context: &ModuleContext) -> Option<TypeReference> {
    let path = innermost_type_path(ty)?;
    path_reference(path, context)
}

fn parameterized_type_arguments(ty: &syn::Type) -> Option<(&syn::Path, Vec<&syn::Type>)> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segment = path.path.segments.last()?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let generic_types: Vec<_> = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect();
    (!generic_types.is_empty()).then_some((&path.path, generic_types))
}

fn value_type_reference(ty: &syn::Type, context: &ModuleContext) -> Option<ValueTypeReference> {
    match ty {
        syn::Type::Array(array) => value_type_reference(&array.elem, context),
        syn::Type::Group(group) => value_type_reference(&group.elem, context),
        syn::Type::Paren(paren) => value_type_reference(&paren.elem, context),
        syn::Type::Ptr(pointer) => value_type_reference(&pointer.elem, context),
        syn::Type::Reference(reference) => value_type_reference(&reference.elem, context),
        syn::Type::Slice(slice) => value_type_reference(&slice.elem, context),
        syn::Type::Tuple(tuple) => Some(ValueTypeReference::Tuple(
            tuple
                .elems
                .iter()
                .map(|element| value_type_reference(element, context))
                .collect(),
        )),
        syn::Type::Path(_) => {
            if let Some((wrapper, arguments)) = parameterized_type_arguments(ty) {
                if let Some(wrapper) = path_reference(wrapper, context) {
                    return Some(ValueTypeReference::Parameterized {
                        wrapper,
                        arguments: arguments
                            .into_iter()
                            .map(|argument| value_type_reference(argument, context))
                            .collect(),
                    });
                }
            }
            type_reference(ty, context).map(ValueTypeReference::Nominal)
        }
        _ => type_reference(ty, context).map(ValueTypeReference::Nominal),
    }
}

fn syntactic_transparent_wrapper_argument_index(
    reference: &TypeReference,
    allow_unqualified: bool,
) -> Option<usize> {
    let path = reference.segments.join("::");
    let name = reference.segments.last()?.as_str();
    if allow_unqualified && reference.segments.len() == 1 && !reference.leading_colon {
        return match name {
            "HashMap" | "BTreeMap" | "IndexMap" => Some(1),
            "Result" | "Option" | "Vec" | "VecDeque" | "Box" | "Arc" | "Rc" | "Cow"
            | "SmallVec" | "HashSet" | "BTreeSet" | "Guard" | "MappedGuard" | "MutexGuard"
            | "RwLockReadGuard" | "RwLockWriteGuard" => Some(0),
            _ => None,
        };
    }
    match name {
        "Result" => matches!(
            path.as_str(),
            "std::result::Result" | "core::result::Result" | "anyhow::Result"
        )
        .then_some(0),
        "Option" => matches!(
            path.as_str(),
            "std::option::Option" | "core::option::Option"
        )
        .then_some(0),
        "Vec" => matches!(path.as_str(), "std::vec::Vec" | "alloc::vec::Vec").then_some(0),
        "VecDeque" => matches!(
            path.as_str(),
            "std::collections::VecDeque" | "alloc::collections::VecDeque"
        )
        .then_some(0),
        "Box" => matches!(path.as_str(), "std::boxed::Box" | "alloc::boxed::Box").then_some(0),
        "Arc" => matches!(path.as_str(), "std::sync::Arc" | "alloc::sync::Arc").then_some(0),
        "Rc" => matches!(path.as_str(), "std::rc::Rc" | "alloc::rc::Rc").then_some(0),
        "Cow" => matches!(path.as_str(), "std::borrow::Cow" | "alloc::borrow::Cow").then_some(0),
        "HashMap" => matches!(
            path.as_str(),
            "std::collections::HashMap" | "hashbrown::HashMap"
        )
        .then_some(1),
        "BTreeMap" => matches!(
            path.as_str(),
            "std::collections::BTreeMap" | "alloc::collections::BTreeMap"
        )
        .then_some(1),
        "IndexMap" => (path == "indexmap::IndexMap").then_some(1),
        "SmallVec" => (path == "smallvec::SmallVec").then_some(0),
        "HashSet" => matches!(
            path.as_str(),
            "std::collections::HashSet" | "hashbrown::HashSet"
        )
        .then_some(0),
        "BTreeSet" => matches!(
            path.as_str(),
            "std::collections::BTreeSet" | "alloc::collections::BTreeSet"
        )
        .then_some(0),
        "Guard" => (path == "arc_swap::Guard").then_some(0),
        "MappedGuard" => matches!(
            path.as_str(),
            "parking_lot::MappedMutexGuard" | "parking_lot::MappedRwLockReadGuard"
        )
        .then_some(0),
        "MutexGuard" => matches!(
            path.as_str(),
            "std::sync::MutexGuard" | "tokio::sync::MutexGuard" | "parking_lot::MutexGuard"
        )
        .then_some(0),
        "RwLockReadGuard" => matches!(
            path.as_str(),
            "std::sync::RwLockReadGuard"
                | "tokio::sync::RwLockReadGuard"
                | "parking_lot::RwLockReadGuard"
        )
        .then_some(0),
        "RwLockWriteGuard" => matches!(
            path.as_str(),
            "std::sync::RwLockWriteGuard"
                | "tokio::sync::RwLockWriteGuard"
                | "parking_lot::RwLockWriteGuard"
        )
        .then_some(0),
        _ => None,
    }
}

fn nominal_type_reference(ty: &syn::Type, context: &ModuleContext) -> Option<TypeReference> {
    match ty {
        syn::Type::Group(group) => nominal_type_reference(&group.elem, context),
        syn::Type::Paren(paren) => nominal_type_reference(&paren.elem, context),
        syn::Type::Reference(reference) => nominal_type_reference(&reference.elem, context),
        syn::Type::Path(path) if path.qself.is_none() => path_reference(&path.path, context),
        syn::Type::Tuple(tuple) if tuple.elems.is_empty() => Some(TypeReference {
            segments: vec!["()".to_string()],
            generic_arguments: Vec::new(),
            has_unresolved_generic_arguments: false,
            context: context.clone(),
            leading_colon: false,
        }),
        _ => None,
    }
}

fn generic_parameter_names(generics: &syn::Generics) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut type_parameters = BTreeSet::new();
    let mut const_parameters = BTreeSet::new();
    for parameter in &generics.params {
        match parameter {
            syn::GenericParam::Type(parameter) => {
                type_parameters.insert(parameter.ident.to_string());
            }
            syn::GenericParam::Const(parameter) => {
                const_parameters.insert(parameter.ident.to_string());
            }
            syn::GenericParam::Lifetime(_) => {}
        }
    }
    (type_parameters, const_parameters)
}

fn direct_type_parameter_name(ty: &syn::Type, parameters: &BTreeSet<String>) -> Option<String> {
    match ty {
        syn::Type::Group(group) => direct_type_parameter_name(&group.elem, parameters),
        syn::Type::Paren(paren) => direct_type_parameter_name(&paren.elem, parameters),
        syn::Type::Path(path)
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1 =>
        {
            let segment = &path.path.segments[0];
            let name = segment.ident.to_string();
            (matches!(segment.arguments, syn::PathArguments::None) && parameters.contains(&name))
                .then_some(name)
        }
        _ => None,
    }
}

fn const_argument_reference(expression: &syn::Expr) -> Option<ConstArgumentReference> {
    match expression {
        syn::Expr::Group(group) => const_argument_reference(&group.expr),
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Bool(value) => Some(ConstArgumentReference::Literal(value.value.to_string())),
            syn::Lit::Byte(value) => {
                Some(ConstArgumentReference::Literal(value.value().to_string()))
            }
            syn::Lit::Char(value) => Some(ConstArgumentReference::Literal(
                value.value().escape_default().to_string(),
            )),
            syn::Lit::Int(value) => Some(ConstArgumentReference::Literal(
                value.base10_digits().to_string(),
            )),
            _ => None,
        },
        syn::Expr::Paren(paren) => const_argument_reference(&paren.expr),
        syn::Expr::Path(path) if path.qself.is_none() => Some(ConstArgumentReference::Path(
            path.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
        )),
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Neg(_)) => {
            let ConstArgumentReference::Literal(value) = const_argument_reference(&unary.expr)?
            else {
                return None;
            };
            Some(ConstArgumentReference::Literal(format!("-{value}")))
        }
        _ => None,
    }
}

fn path_reference(path: &syn::Path, context: &ModuleContext) -> Option<TypeReference> {
    let segment = path.segments.last()?;
    let mut generic_arguments = Vec::new();
    let mut has_unresolved_generic_arguments = false;
    match &segment.arguments {
        syn::PathArguments::None => {}
        syn::PathArguments::AngleBracketed(arguments) => {
            for argument in &arguments.args {
                match argument {
                    syn::GenericArgument::Type(ty) => {
                        if let Some(reference) = nominal_type_reference(ty, context) {
                            generic_arguments.push(GenericArgumentReference::Type(reference));
                        } else {
                            has_unresolved_generic_arguments = true;
                        }
                    }
                    syn::GenericArgument::Const(expression) => {
                        if let Some(reference) = const_argument_reference(expression) {
                            generic_arguments.push(GenericArgumentReference::Const(reference));
                        } else {
                            has_unresolved_generic_arguments = true;
                        }
                    }
                    syn::GenericArgument::Lifetime(_) => {}
                    _ => has_unresolved_generic_arguments = true,
                }
            }
        }
        syn::PathArguments::Parenthesized(_) => has_unresolved_generic_arguments = true,
    }
    Some(TypeReference {
        segments: path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
        generic_arguments,
        has_unresolved_generic_arguments,
        context: context.clone(),
        leading_colon: path.leading_colon.is_some(),
    })
}

fn innermost_type_path(ty: &syn::Type) -> Option<&syn::Path> {
    match ty {
        syn::Type::Array(array) => innermost_type_path(&array.elem),
        syn::Type::Group(group) => innermost_type_path(&group.elem),
        syn::Type::Paren(paren) => innermost_type_path(&paren.elem),
        syn::Type::Ptr(pointer) => innermost_type_path(&pointer.elem),
        syn::Type::Reference(reference) => innermost_type_path(&reference.elem),
        syn::Type::Slice(slice) => innermost_type_path(&slice.elem),
        syn::Type::Path(path) => {
            let segment = path.path.segments.last()?;
            let generic_types: Vec<&syn::Type> = match &segment.arguments {
                syn::PathArguments::AngleBracketed(arguments) => arguments
                    .args
                    .iter()
                    .filter_map(|argument| match argument {
                        syn::GenericArgument::Type(ty) => Some(ty),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let wrapper = segment.ident.to_string();
            let inner = match wrapper.as_str() {
                "HashMap" | "BTreeMap" | "IndexMap" => generic_types.get(1).copied(),
                "Result" => generic_types.first().copied(),
                "Option" | "Vec" | "VecDeque" | "Box" | "Arc" | "Rc" | "Cow" | "SmallVec"
                | "HashSet" | "BTreeSet" | "Guard" | "MappedGuard" | "MutexGuard"
                | "RwLockReadGuard" | "RwLockWriteGuard" => generic_types.first().copied(),
                _ => None,
            };
            inner.and_then(innermost_type_path).or(Some(&path.path))
        }
        _ => None,
    }
}

fn type_is_mutable_reference(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Group(group) => type_is_mutable_reference(&group.elem),
        syn::Type::Paren(paren) => type_is_mutable_reference(&paren.elem),
        syn::Type::Reference(reference) => reference.mutability.is_some(),
        _ => false,
    }
}

#[derive(Clone, PartialEq, Eq)]
enum InferredValueKind {
    Nominal(String),
    Tuple(Vec<Option<InferredValue>>),
}

#[derive(Clone, PartialEq, Eq)]
struct InferredValue {
    kind: InferredValueKind,
    mutable_place: bool,
}

impl InferredValue {
    fn nominal(owner: String, mutable_place: bool) -> Self {
        Self {
            kind: InferredValueKind::Nominal(owner),
            mutable_place,
        }
    }

    fn tuple(elements: Vec<Option<Self>>) -> Self {
        Self {
            kind: InferredValueKind::Tuple(elements),
            mutable_place: false,
        }
    }

    fn owner(&self) -> Option<&str> {
        match &self.kind {
            InferredValueKind::Nominal(owner) => Some(owner),
            InferredValueKind::Tuple(_) => None,
        }
    }

    fn tuple_elements(&self) -> Option<&[Option<Self>]> {
        match &self.kind {
            InferredValueKind::Nominal(_) => None,
            InferredValueKind::Tuple(elements) => Some(elements),
        }
    }

    fn with_enclosing_mutability(&self, mutable_place: bool) -> Self {
        let mut value = self.clone();
        value.mutable_place |= mutable_place;
        value
    }

    fn fill_missing(primary: Option<Self>, fallback: Option<Self>) -> Option<Self> {
        match (primary, fallback) {
            (None, fallback) => fallback,
            (primary, None) => primary,
            (Some(mut primary), Some(fallback)) => {
                if let (
                    InferredValueKind::Tuple(primary_elements),
                    InferredValueKind::Tuple(fallback_elements),
                ) = (&mut primary.kind, fallback.kind)
                {
                    if primary_elements.len() == fallback_elements.len() {
                        for (primary, fallback) in
                            primary_elements.iter_mut().zip(fallback_elements)
                        {
                            *primary = Self::fill_missing(primary.take(), fallback);
                        }
                    }
                }
                Some(primary)
            }
        }
    }
}

#[derive(Clone, Default)]
struct LocalSymbolScope {
    bindings: BTreeMap<String, Vec<LocalSymbolBinding>>,
    glob_imports: Vec<TypeReference>,
    anonymous_imports: Vec<TypeReference>,
    traits_by_method: BTreeMap<String, BTreeSet<String>>,
    type_declarations: BTreeSet<String>,
    function_declarations: BTreeSet<String>,
    function_returns: BTreeMap<String, Vec<ValueTypeReference>>,
    value_type_aliases: BTreeMap<String, Vec<ValueTypeAliasDefinition>>,
    namespace_declarations: BTreeSet<String>,
    has_unexpanded_item_macro: bool,
}

#[derive(Clone)]
struct LocalSymbolBinding {
    target: TypeReference,
    // An import whose target starts with its own alias resolves that prefix
    // outside the binding it is introducing. A type alias remains recursive.
    is_import: bool,
}

impl LocalSymbolScope {
    fn declares(&self, kind: SymbolKind, name: &str) -> bool {
        match kind {
            SymbolKind::Type => self.type_declarations.contains(name),
            SymbolKind::Function => self.function_declarations.contains(name),
        }
    }
}

struct FieldReadVisitor<'a> {
    types: &'a RustTypeIndex,
    reads: BTreeSet<(String, String)>,
    environment: BTreeMap<String, InferredValue>,
    local_scopes: Vec<LocalSymbolScope>,
    in_function: bool,
    impl_owner: Option<String>,
    context: ModuleContext,
}

impl<'a> FieldReadVisitor<'a> {
    fn new(types: &'a RustTypeIndex, context: ModuleContext) -> Self {
        Self {
            types,
            reads: BTreeSet::new(),
            environment: BTreeMap::new(),
            local_scopes: Vec::new(),
            in_function: false,
            impl_owner: None,
            context,
        }
    }

    fn resolve_type_scoped(&self, ty: &syn::Type) -> Option<String> {
        let reference = type_reference(ty, &self.context)?;
        self.resolve_exact_type_scoped_with_limit(&reference, self.local_scopes.len())
    }

    fn resolve_path_scoped(&self, path: &syn::Path) -> Option<String> {
        let reference = path_reference(path, &self.context)?;
        self.resolve_symbol_scoped(SymbolKind::Type, &reference)
    }

    fn resolve_symbol_scoped(&self, kind: SymbolKind, reference: &TypeReference) -> Option<String> {
        self.resolve_symbol_scoped_with_limit(
            kind,
            reference,
            self.local_scopes.len(),
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
        )
        .exact()
    }

    fn resolve_exact_type_scoped_with_limit(
        &self,
        reference: &TypeReference,
        scope_limit: usize,
    ) -> Option<String> {
        let owner = self
            .resolve_symbol_scoped_with_limit(
                SymbolKind::Type,
                reference,
                scope_limit,
                &mut BTreeSet::new(),
                &mut BTreeSet::new(),
            )
            .exact()
            .or_else(|| primitive_type_reference(reference).map(str::to_string))?;
        if reference.has_unresolved_generic_arguments {
            return None;
        }
        let arguments: Option<Vec<_>> = reference
            .generic_arguments
            .iter()
            .map(|argument| match argument {
                GenericArgumentReference::Type(argument) => {
                    self.resolve_exact_type_scoped_with_limit(argument, scope_limit)
                }
                GenericArgumentReference::Const(ConstArgumentReference::Literal(value)) => {
                    Some(format!("#{value}"))
                }
                GenericArgumentReference::Const(ConstArgumentReference::Path(_)) => None,
            })
            .collect();
        Some(resolved_type_identity(owner, &arguments?))
    }

    fn resolve_symbol_scoped_with_limit(
        &self,
        kind: SymbolKind,
        reference: &TypeReference,
        // Binding targets see their defining scope and its ancestors, never
        // a shadow introduced by a block nested inside the use site.
        scope_limit: usize,
        resolving_symbols: &mut BTreeSet<String>,
        resolving_bindings: &mut BTreeSet<String>,
    ) -> SymbolResolution {
        let resolution_key = format!(
            "{kind:?}:{scope_limit}:{}:{}:{}",
            reference.context.path(),
            reference.leading_colon,
            reference.segments.join("::"),
        );
        if !resolving_bindings.insert(resolution_key.clone()) {
            return SymbolResolution::tainted();
        }

        let result = (|| {
            if !reference.leading_colon {
                let Some(first) = reference.segments.first() else {
                    return SymbolResolution::tainted();
                };
                for scope_index in (0..scope_limit).rev() {
                    let scope = &self.local_scopes[scope_index];
                    if scope.declares(kind, first)
                        || (reference.segments.len() > 1
                            && scope.namespace_declarations.contains(first))
                    {
                        return SymbolResolution::tainted();
                    }

                    if let Some(bindings) = scope.bindings.get(first) {
                        let mut result = SymbolResolution::default();
                        for binding in bindings {
                            let mut expanded = binding.target.clone();
                            expanded
                                .segments
                                .extend_from_slice(&reference.segments[1..]);
                            let target_scope_limit = if binding.is_import
                                && !expanded.leading_colon
                                && expanded.segments.first() == Some(first)
                            {
                                scope_index
                            } else {
                                scope_index + 1
                            };
                            result.merge(self.resolve_symbol_scoped_with_limit(
                                kind,
                                &expanded,
                                target_scope_limit,
                                resolving_symbols,
                                resolving_bindings,
                            ));
                        }
                        return result;
                    }

                    if reference.segments.len() == 1 && !scope.glob_imports.is_empty() {
                        let mut result = SymbolResolution::default();
                        for glob in &scope.glob_imports {
                            let mut expanded = glob.clone();
                            expanded.segments.push(first.clone());
                            result.merge(self.resolve_symbol_scoped_with_limit(
                                kind,
                                &expanded,
                                scope_index + 1,
                                resolving_symbols,
                                resolving_bindings,
                            ));
                        }
                        if result.tainted || !result.symbols.is_empty() {
                            return result;
                        }
                    }
                }
            }

            self.types
                .resolve_symbol_reference(kind, reference, resolving_symbols)
        })();
        resolving_bindings.remove(&resolution_key);
        result
    }

    fn traits_in_scope_for_method(&mut self, method: &str) -> BTreeSet<String> {
        if let Some(traits) = self
            .local_scopes
            .last()
            .and_then(|scope| scope.traits_by_method.get(method))
        {
            return traits.clone();
        }
        let Some(candidate_traits) = self.types.trait_method_candidates.get(method) else {
            return BTreeSet::new();
        };

        let mut names = BTreeSet::new();
        for trait_owner in candidate_traits {
            if let Some(name) = trait_owner.rsplit("::").next() {
                names.insert(name.to_string());
            }
        }
        for scope in &self.local_scopes {
            names.extend(scope.bindings.keys().cloned());
        }
        let module_prefix = format!("{}::", self.context.path());
        for symbol in self
            .types
            .symbol_bindings
            .range(module_prefix.clone()..)
            .map(|(symbol, _)| symbol)
        {
            let Some(name) = symbol.strip_prefix(&module_prefix) else {
                break;
            };
            if !name.contains("::") {
                names.insert(name.to_string());
            }
        }

        let mut traits = BTreeSet::new();
        for name in names {
            let reference = TypeReference {
                segments: vec![name],
                generic_arguments: Vec::new(),
                has_unresolved_generic_arguments: false,
                context: self.context.clone(),
                leading_colon: false,
            };
            if let Some(symbol) = self.resolve_symbol_scoped(SymbolKind::Type, &reference) {
                if candidate_traits.contains(&symbol) {
                    traits.insert(symbol);
                }
            }
        }
        if let Some(imports) = self.types.anonymous_imports.get(&self.context) {
            for import in imports {
                if let Some(symbol) = self
                    .types
                    .resolve_symbol_reference(SymbolKind::Type, import, &mut BTreeSet::new())
                    .exact()
                {
                    if candidate_traits.contains(&symbol) {
                        traits.insert(symbol);
                    }
                }
            }
        }
        for (scope_index, scope) in self.local_scopes.iter().enumerate() {
            for import in &scope.anonymous_imports {
                if let Some(symbol) = self
                    .resolve_symbol_scoped_with_limit(
                        SymbolKind::Type,
                        import,
                        scope_index + 1,
                        &mut BTreeSet::new(),
                        &mut BTreeSet::new(),
                    )
                    .exact()
                {
                    if candidate_traits.contains(&symbol) {
                        traits.insert(symbol);
                    }
                }
            }
        }
        if let Some(scope) = self.local_scopes.last_mut() {
            scope
                .traits_by_method
                .insert(method.to_string(), traits.clone());
        }
        traits
    }

    fn value_type_alias_target_scoped(
        &self,
        reference: &TypeReference,
        arguments: &[Option<ValueTypeReference>],
        scope_limit: usize,
        resolving: &mut BTreeSet<String>,
    ) -> Option<(ValueTypeReference, usize)> {
        if !reference.leading_colon {
            let first = reference.segments.first()?;
            for scope_index in (0..scope_limit).rev() {
                let scope = &self.local_scopes[scope_index];
                if reference.segments.len() == 1 {
                    if let Some(aliases) = scope.value_type_aliases.get(first) {
                        let [alias] = aliases.as_slice() else {
                            return None;
                        };
                        return Some((
                            RustTypeIndex::instantiate_value_type_alias(alias, arguments)?,
                            scope_index + 1,
                        ));
                    }
                }
                if scope.type_declarations.contains(first)
                    || (reference.segments.len() > 1
                        && scope.namespace_declarations.contains(first))
                {
                    return None;
                }
                if let Some(bindings) = scope.bindings.get(first) {
                    let [binding] = bindings.as_slice() else {
                        return None;
                    };
                    let mut expanded = binding.target.clone();
                    expanded
                        .segments
                        .extend_from_slice(&reference.segments[1..]);
                    let target_scope_limit = if binding.is_import
                        && !expanded.leading_colon
                        && expanded.segments.first() == Some(first)
                    {
                        scope_index
                    } else {
                        scope_index + 1
                    };
                    let key = format!(
                        "scoped-value-alias:{target_scope_limit}:{}",
                        expanded.segments.join("::")
                    );
                    if !resolving.insert(key.clone()) {
                        return None;
                    }
                    let target = self.value_type_alias_target_scoped(
                        &expanded,
                        arguments,
                        target_scope_limit,
                        resolving,
                    );
                    resolving.remove(&key);
                    return target;
                }
                if !scope.glob_imports.is_empty() {
                    return None;
                }
            }
        }
        self.types
            .value_type_alias_target(reference, arguments)
            .map(|target| (target, scope_limit))
    }

    fn transparent_wrapper_argument_index_scoped(
        &self,
        reference: &TypeReference,
        scope_limit: usize,
        resolving: &mut BTreeSet<String>,
    ) -> Option<(usize, usize)> {
        if !reference.leading_colon {
            let first = reference.segments.first()?;
            for scope_index in (0..scope_limit).rev() {
                let scope = &self.local_scopes[scope_index];
                if reference.segments.len() == 1 && scope.value_type_aliases.contains_key(first) {
                    return None;
                }
                if scope.type_declarations.contains(first)
                    || (reference.segments.len() > 1
                        && scope.namespace_declarations.contains(first))
                {
                    return None;
                }
                if let Some(bindings) = scope.bindings.get(first) {
                    let [binding] = bindings.as_slice() else {
                        return None;
                    };
                    let mut expanded = binding.target.clone();
                    expanded
                        .segments
                        .extend_from_slice(&reference.segments[1..]);
                    let target_scope_limit = if binding.is_import
                        && !expanded.leading_colon
                        && expanded.segments.first() == Some(first)
                    {
                        scope_index
                    } else {
                        scope_index + 1
                    };
                    let key = format!(
                        "scoped-transparent-wrapper:{target_scope_limit}:{}",
                        expanded.segments.join("::")
                    );
                    if !resolving.insert(key.clone()) {
                        return None;
                    }
                    let index = self.transparent_wrapper_argument_index_scoped(
                        &expanded,
                        target_scope_limit,
                        resolving,
                    );
                    resolving.remove(&key);
                    return index.map(|(index, _)| (index, scope_limit));
                }
                if scope.has_unexpanded_item_macro {
                    return None;
                }
                if !scope.glob_imports.is_empty() {
                    if reference.segments.len() != 1 {
                        return None;
                    }
                    let indices: Vec<_> = scope
                        .glob_imports
                        .iter()
                        .map(|glob| {
                            let mut expanded = glob.clone();
                            expanded.segments.push(first.clone());
                            self.transparent_wrapper_argument_index_scoped(
                                &expanded,
                                scope_index,
                                resolving,
                            )
                        })
                        .collect();
                    let [Some(first), rest @ ..] = indices.as_slice() else {
                        return None;
                    };
                    return rest
                        .iter()
                        .all(|candidate| candidate == &Some(*first))
                        .then_some((first.0, scope_index));
                }
            }
        }
        self.types
            .transparent_wrapper_argument_index(reference, &mut BTreeSet::new())
            .map(|index| (index, scope_limit))
    }

    fn resolve_value_type_scoped_with_limit(
        &self,
        reference: &ValueTypeReference,
        scope_limit: usize,
    ) -> Option<InferredValue> {
        self.resolve_value_type_scoped_inner(reference, scope_limit, &mut BTreeSet::new())
    }

    fn resolve_value_type_scoped_inner(
        &self,
        reference: &ValueTypeReference,
        scope_limit: usize,
        resolving_aliases: &mut BTreeSet<String>,
    ) -> Option<InferredValue> {
        match reference {
            ValueTypeReference::Nominal(reference) => {
                if let Some((target, target_scope_limit)) = self.value_type_alias_target_scoped(
                    reference,
                    &[],
                    scope_limit,
                    &mut BTreeSet::new(),
                ) {
                    let key = format!(
                        "scoped-value-alias:{scope_limit}:{}:{}",
                        reference.context.path(),
                        reference.segments.join("::")
                    );
                    if !resolving_aliases.insert(key.clone()) {
                        return None;
                    }
                    let result = self.resolve_value_type_scoped_inner(
                        &target,
                        target_scope_limit,
                        resolving_aliases,
                    );
                    resolving_aliases.remove(&key);
                    return result;
                }
                self.resolve_exact_type_scoped_with_limit(reference, scope_limit)
                    .map(|owner| InferredValue::nominal(owner, false))
            }
            ValueTypeReference::Parameterized { wrapper, arguments } => {
                if let Some((target, target_scope_limit)) = self.value_type_alias_target_scoped(
                    wrapper,
                    arguments,
                    scope_limit,
                    &mut BTreeSet::new(),
                ) {
                    let key = format!(
                        "scoped-value-alias:{scope_limit}:{}:{}",
                        wrapper.context.path(),
                        wrapper.segments.join("::")
                    );
                    if !resolving_aliases.insert(key.clone()) {
                        return None;
                    }
                    let result = self.resolve_value_type_scoped_inner(
                        &target,
                        target_scope_limit,
                        resolving_aliases,
                    );
                    resolving_aliases.remove(&key);
                    return result;
                }
                if let Some((index, argument_scope_limit)) = self
                    .transparent_wrapper_argument_index_scoped(
                        wrapper,
                        scope_limit,
                        &mut BTreeSet::new(),
                    )
                {
                    let argument = arguments.get(index)?.as_ref()?;
                    let primary = self.resolve_value_type_scoped_inner(
                        argument,
                        scope_limit,
                        resolving_aliases,
                    );
                    if argument_scope_limit == scope_limit {
                        return primary;
                    }
                    let fallback = self.resolve_value_type_scoped_inner(
                        argument,
                        argument_scope_limit,
                        resolving_aliases,
                    );
                    return InferredValue::fill_missing(primary, fallback);
                }
                self.resolve_exact_type_scoped_with_limit(wrapper, scope_limit)
                    .map(|owner| InferredValue::nominal(owner, false))
            }
            ValueTypeReference::Tuple(elements) => Some(InferredValue::tuple(
                elements
                    .iter()
                    .map(|element| {
                        element.as_ref().and_then(|element| {
                            self.resolve_value_type_scoped_inner(
                                element,
                                scope_limit,
                                resolving_aliases,
                            )
                        })
                    })
                    .collect(),
            )),
        }
    }

    fn resolve_value_type(&self, reference: &ValueTypeReference) -> Option<InferredValue> {
        self.resolve_value_type_inner(reference, &mut BTreeSet::new())
    }

    fn resolve_value_type_inner(
        &self,
        reference: &ValueTypeReference,
        resolving_aliases: &mut BTreeSet<String>,
    ) -> Option<InferredValue> {
        match reference {
            ValueTypeReference::Nominal(reference) => {
                if let Some(target) = self.types.value_type_alias_target(reference, &[]) {
                    let key = format!(
                        "value-alias:{}:{}",
                        reference.context.path(),
                        reference.segments.join("::")
                    );
                    if !resolving_aliases.insert(key.clone()) {
                        return None;
                    }
                    let result = self.resolve_value_type_inner(&target, resolving_aliases);
                    resolving_aliases.remove(&key);
                    return result;
                }
                self.types
                    .resolve_exact_type_reference(reference)
                    .map(|owner| InferredValue::nominal(owner, false))
            }
            ValueTypeReference::Parameterized { wrapper, arguments } => {
                if let Some(target) = self.types.value_type_alias_target(wrapper, arguments) {
                    let key = format!(
                        "value-alias:{}:{}",
                        wrapper.context.path(),
                        wrapper.segments.join("::")
                    );
                    if !resolving_aliases.insert(key.clone()) {
                        return None;
                    }
                    let result = self.resolve_value_type_inner(&target, resolving_aliases);
                    resolving_aliases.remove(&key);
                    return result;
                }
                if let Some(index) = self
                    .types
                    .transparent_wrapper_argument_index(wrapper, &mut BTreeSet::new())
                {
                    return arguments.get(index)?.as_ref().and_then(|argument| {
                        self.resolve_value_type_inner(argument, resolving_aliases)
                    });
                }
                self.types
                    .resolve_exact_type_reference(wrapper)
                    .map(|owner| InferredValue::nominal(owner, false))
            }
            ValueTypeReference::Tuple(elements) => Some(InferredValue::tuple(
                elements
                    .iter()
                    .map(|element| {
                        element.as_ref().and_then(|element| {
                            self.resolve_value_type_inner(element, resolving_aliases)
                        })
                    })
                    .collect(),
            )),
        }
    }

    fn function_return_scoped(&self, path: &syn::Path) -> Option<InferredValue> {
        let reference = path_reference(path, &self.context)?;
        if !reference.leading_colon && reference.segments.len() == 1 {
            let name = reference.segments.first()?;
            for scope_index in (0..self.local_scopes.len()).rev() {
                let scope = &self.local_scopes[scope_index];
                if !scope.function_declarations.contains(name) {
                    continue;
                }
                let returns = scope.function_returns.get(name)?;
                if returns.len() != 1 {
                    return None;
                }
                return self.resolve_value_type_scoped_with_limit(&returns[0], scope_index + 1);
            }
        }
        let symbol = self.resolve_symbol_scoped(SymbolKind::Function, &reference)?;
        let name = symbol.rsplit("::").next()?;
        let result = &self
            .types
            .function_returns
            .get(name)?
            .iter()
            .find(|candidate| candidate.symbol == symbol)?
            .result;
        self.resolve_value_type(result)
    }

    fn block_symbol_scope(&self, block: &syn::Block) -> LocalSymbolScope {
        let mut scope = LocalSymbolScope::default();
        for statement in &block.stmts {
            if let syn::Stmt::Macro(statement_macro) = statement {
                if !attributes_exclude_production(&statement_macro.attrs) {
                    scope.has_unexpanded_item_macro = true;
                }
                continue;
            }
            let syn::Stmt::Item(item) = statement else {
                continue;
            };
            if item_attributes(item).is_some_and(attributes_exclude_production) {
                continue;
            }
            match item {
                syn::Item::Use(item_use) => {
                    let mut bindings = Vec::new();
                    let mut globs = Vec::new();
                    let mut anonymous = Vec::new();
                    collect_use_bindings(
                        &item_use.tree,
                        &mut Vec::new(),
                        &mut bindings,
                        &mut globs,
                        &mut anonymous,
                    );
                    for (alias, segments) in bindings {
                        scope
                            .bindings
                            .entry(alias)
                            .or_default()
                            .push(LocalSymbolBinding {
                                target: TypeReference {
                                    segments,
                                    generic_arguments: Vec::new(),
                                    has_unresolved_generic_arguments: false,
                                    context: self.context.clone(),
                                    leading_colon: item_use.leading_colon.is_some(),
                                },
                                is_import: true,
                            });
                    }
                    for segments in globs {
                        scope.glob_imports.push(TypeReference {
                            segments,
                            generic_arguments: Vec::new(),
                            has_unresolved_generic_arguments: false,
                            context: self.context.clone(),
                            leading_colon: item_use.leading_colon.is_some(),
                        });
                    }
                    for segments in anonymous {
                        scope.anonymous_imports.push(TypeReference {
                            segments,
                            generic_arguments: Vec::new(),
                            has_unresolved_generic_arguments: false,
                            context: self.context.clone(),
                            leading_colon: item_use.leading_colon.is_some(),
                        });
                    }
                }
                syn::Item::Type(item_type) => {
                    let name = item_type.ident.to_string();
                    if let Some(target) = value_type_reference(&item_type.ty, &self.context) {
                        scope
                            .value_type_aliases
                            .entry(name.clone())
                            .or_default()
                            .push(ValueTypeAliasDefinition::new(
                                &item_type.generics,
                                target,
                                &self.context,
                            ));
                    }
                    if let Some(target) = type_reference(&item_type.ty, &self.context) {
                        scope
                            .bindings
                            .entry(name)
                            .or_default()
                            .push(LocalSymbolBinding {
                                target,
                                is_import: false,
                            });
                    } else {
                        scope.type_declarations.insert(name);
                    }
                }
                syn::Item::ExternCrate(item_extern) => {
                    let alias = item_extern
                        .rename
                        .as_ref()
                        .map(|(_, alias)| alias.to_string())
                        .unwrap_or_else(|| item_extern.ident.to_string());
                    let ident = item_extern.ident.to_string();
                    let (segments, leading_colon) = if ident == "self" {
                        (vec!["crate".to_string()], false)
                    } else {
                        (vec![ident], true)
                    };
                    scope
                        .bindings
                        .entry(alias)
                        .or_default()
                        .push(LocalSymbolBinding {
                            target: TypeReference {
                                segments,
                                generic_arguments: Vec::new(),
                                has_unresolved_generic_arguments: false,
                                context: self.context.clone(),
                                leading_colon,
                            },
                            is_import: true,
                        });
                }
                syn::Item::Struct(item_struct) => {
                    scope
                        .type_declarations
                        .insert(item_struct.ident.to_string());
                }
                syn::Item::Enum(item_enum) => {
                    scope.type_declarations.insert(item_enum.ident.to_string());
                }
                syn::Item::Union(item_union) => {
                    scope.type_declarations.insert(item_union.ident.to_string());
                }
                syn::Item::Trait(item_trait) => {
                    scope.type_declarations.insert(item_trait.ident.to_string());
                }
                syn::Item::TraitAlias(item_alias) => {
                    scope.type_declarations.insert(item_alias.ident.to_string());
                }
                syn::Item::Mod(item_mod) => {
                    let name = item_mod.ident.to_string();
                    scope.type_declarations.insert(name.clone());
                    scope.namespace_declarations.insert(name);
                }
                syn::Item::Fn(item_fn) => {
                    let name = item_fn.sig.ident.to_string();
                    scope.function_declarations.insert(name.clone());
                    if let syn::ReturnType::Type(_, ty) = &item_fn.sig.output {
                        if let Some(result) = value_type_reference(ty, &self.context) {
                            scope.function_returns.entry(name).or_default().push(result);
                        }
                    }
                }
                syn::Item::Macro(item_macro) if item_macro.ident.is_none() => {
                    scope.has_unexpanded_item_macro = true;
                }
                _ => {}
            }
        }
        scope
    }

    fn visit_function(
        &mut self,
        inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
        block: &syn::Block,
    ) {
        let saved_environment = std::mem::take(&mut self.environment);
        let saved_in_function = self.in_function;
        let saved_local_scopes =
            (!saved_in_function).then(|| std::mem::take(&mut self.local_scopes));
        self.in_function = true;
        for input in inputs {
            match input {
                syn::FnArg::Receiver(receiver) => {
                    if let Some(owner) = &self.impl_owner {
                        self.environment.insert(
                            "self".to_string(),
                            InferredValue::nominal(
                                owner.to_string(),
                                receiver.mutability.is_some(),
                            ),
                        );
                    }
                }
                syn::FnArg::Typed(typed) => {
                    let value = self.resolve_type_scoped(&typed.ty).map(|owner| {
                        InferredValue::nominal(owner, type_is_mutable_reference(&typed.ty))
                    });
                    self.bind_pattern(&typed.pat, value.as_ref());
                }
            }
        }
        self.visit_block(block);
        self.environment = saved_environment;
        if let Some(saved_local_scopes) = saved_local_scopes {
            self.local_scopes = saved_local_scopes;
        }
        self.in_function = saved_in_function;
    }

    fn bind_inferred_sequence<'b>(
        &mut self,
        patterns: impl IntoIterator<Item = &'b syn::Pat>,
        values: &[Option<InferredValue>],
        mutable_place: bool,
    ) -> bool {
        let patterns: Vec<_> = patterns.into_iter().collect();
        let rest_positions: Vec<_> = patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| Self::pattern_is_rest(pattern).then_some(index))
            .collect();
        if rest_positions.is_empty() {
            if patterns.len() != values.len() {
                return false;
            }
            for (pattern, value) in patterns.into_iter().zip(values) {
                let value = value
                    .as_ref()
                    .map(|value| value.with_enclosing_mutability(mutable_place));
                self.bind_pattern(pattern, value.as_ref());
            }
            return true;
        }
        if rest_positions.len() != 1 || values.len() + 1 < patterns.len() {
            return false;
        }

        let rest_index = rest_positions[0];
        for (pattern, value) in patterns[..rest_index].iter().zip(&values[..rest_index]) {
            let value = value
                .as_ref()
                .map(|value| value.with_enclosing_mutability(mutable_place));
            self.bind_pattern(pattern, value.as_ref());
        }
        let suffix_len = patterns.len() - rest_index - 1;
        for (pattern, value) in patterns[rest_index + 1..]
            .iter()
            .zip(&values[values.len() - suffix_len..])
        {
            let value = value
                .as_ref()
                .map(|value| value.with_enclosing_mutability(mutable_place));
            self.bind_pattern(pattern, value.as_ref());
        }
        true
    }

    fn tuple_pattern_field_values(
        &self,
        path: &syn::Path,
        value: &InferredValue,
    ) -> Option<Vec<Option<InferredValue>>> {
        let value_owner = value.owner()?;
        let (nominal_owner, bindings) = self
            .types
            .generic_bindings_for_resolved_owner(value_owner)?;

        let fields = if self.resolve_path_scoped(path).as_deref() == Some(nominal_owner) {
            self.types.tuple_struct_fields.get(nominal_owner)?
        } else {
            let mut reference = path_reference(path, &self.context)?;
            let variant = reference.segments.pop()?;
            let pattern_owner = self.resolve_symbol_scoped(SymbolKind::Type, &reference)?;
            if pattern_owner != nominal_owner {
                return None;
            }
            self.types
                .enum_tuple_variant_fields
                .get(&(pattern_owner, variant))?
        };

        Some(
            fields
                .iter()
                .map(|reference| {
                    reference
                        .as_ref()
                        .and_then(|reference| {
                            self.types
                                .resolve_type_reference_with_bindings(reference, &bindings)
                        })
                        .map(|owner| InferredValue::nominal(owner, value.mutable_place))
                })
                .collect(),
        )
    }

    fn bind_pattern(&mut self, pattern: &syn::Pat, value: Option<&InferredValue>) {
        match pattern {
            syn::Pat::Ident(ident) => {
                self.bind_identifier(ident, value);
                if let Some((_, subpattern)) = &ident.subpat {
                    self.bind_pattern(subpattern, value);
                }
            }
            syn::Pat::Or(alternatives) => {
                for alternative in &alternatives.cases {
                    self.bind_pattern(alternative, value);
                }
            }
            syn::Pat::Reference(reference) => {
                let referenced = value.cloned().map(|mut value| {
                    value.mutable_place |= reference.mutability.is_some();
                    value
                });
                self.bind_pattern(&reference.pat, referenced.as_ref());
            }
            syn::Pat::Type(typed) => {
                let explicit = self.resolve_type_scoped(&typed.ty).map(|owner| {
                    InferredValue::nominal(
                        owner,
                        type_is_mutable_reference(&typed.ty)
                            || value.is_some_and(|value| value.mutable_place),
                    )
                });
                self.bind_pattern(&typed.pat, explicit.as_ref().or(value));
            }
            syn::Pat::Tuple(tuple) => {
                if let Some(value) = value {
                    if let Some(elements) = value.tuple_elements() {
                        if self.bind_inferred_sequence(
                            tuple.elems.iter(),
                            elements,
                            value.mutable_place,
                        ) {
                            return;
                        }
                    }
                }
                for element in &tuple.elems {
                    self.bind_pattern(element, value);
                }
            }
            syn::Pat::Slice(slice) => {
                for element in &slice.elems {
                    self.bind_pattern(element, value);
                }
            }
            syn::Pat::TupleStruct(tuple) => {
                self.record_tagged_enum_match(&tuple.path);
                if let Some(value) = value {
                    if let Some(fields) = self.tuple_pattern_field_values(&tuple.path, value) {
                        if self.bind_inferred_sequence(
                            tuple.elems.iter(),
                            &fields,
                            value.mutable_place,
                        ) {
                            return;
                        }
                    }
                }
                for element in &tuple.elems {
                    self.bind_pattern(element, value);
                }
            }
            syn::Pat::Struct(record) => {
                self.record_tagged_enum_match(&record.path);
                let pattern_owner = self
                    .resolve_path_scoped(&record.path)
                    .or_else(|| value.and_then(InferredValue::owner).map(str::to_string));
                if let Some(pattern_owner) = pattern_owner {
                    for field in &record.fields {
                        if attributes_exclude_production(&field.attrs)
                            || matches!(field.pat.as_ref(), syn::Pat::Wild(_))
                        {
                            continue;
                        }
                        if let Some(member) = Self::named_member(&field.member) {
                            if !value.is_some_and(|value| value.mutable_place) {
                                self.reads.insert((pattern_owner.clone(), member.clone()));
                            }
                            let target =
                                self.types.field_type(&pattern_owner, &member).map(|owner| {
                                    InferredValue::nominal(
                                        owner,
                                        value.is_some_and(|value| value.mutable_place),
                                    )
                                });
                            self.bind_pattern(&field.pat, target.as_ref());
                        }
                    }
                }
            }
            syn::Pat::Path(path) => self.record_tagged_enum_match(&path.path),
            _ => {}
        }
    }

    fn bind_identifier(&mut self, ident: &syn::PatIdent, value: Option<&InferredValue>) {
        let name = ident.ident.to_string();
        if let Some(value) = value {
            self.environment.insert(name, value.clone());
        } else {
            self.environment.remove(&name);
        }
    }

    fn pattern_is_rest(pattern: &syn::Pat) -> bool {
        match pattern {
            syn::Pat::Ident(ident) => ident
                .subpat
                .as_ref()
                .is_some_and(|(_, pattern)| Self::pattern_is_rest(pattern)),
            syn::Pat::Paren(paren) => Self::pattern_is_rest(&paren.pat),
            syn::Pat::Reference(reference) => Self::pattern_is_rest(&reference.pat),
            syn::Pat::Rest(_) => true,
            syn::Pat::Type(typed) => Self::pattern_is_rest(&typed.pat),
            _ => false,
        }
    }

    fn pattern_has_initializer_structure(pattern: &syn::Pat) -> bool {
        match pattern {
            syn::Pat::Ident(ident) => ident
                .subpat
                .as_ref()
                .is_some_and(|(_, pattern)| Self::pattern_has_initializer_structure(pattern)),
            syn::Pat::Paren(paren) => Self::pattern_has_initializer_structure(&paren.pat),
            syn::Pat::Reference(reference) => {
                Self::pattern_has_initializer_structure(&reference.pat)
            }
            syn::Pat::Or(alternatives) => alternatives
                .cases
                .iter()
                .any(Self::pattern_has_initializer_structure),
            syn::Pat::Slice(_)
            | syn::Pat::Struct(_)
            | syn::Pat::Tuple(_)
            | syn::Pat::TupleStruct(_) => true,
            syn::Pat::Type(typed) => Self::pattern_has_initializer_structure(&typed.pat),
            _ => false,
        }
    }

    fn pattern_observes_scrutinee(pattern: &syn::Pat) -> bool {
        match pattern {
            syn::Pat::Ident(_) => true,
            syn::Pat::Or(alternatives) => alternatives
                .cases
                .iter()
                .any(Self::pattern_observes_scrutinee),
            syn::Pat::Paren(paren) => Self::pattern_observes_scrutinee(&paren.pat),
            syn::Pat::Reference(reference) => Self::pattern_observes_scrutinee(&reference.pat),
            syn::Pat::Rest(_) | syn::Pat::Wild(_) => false,
            syn::Pat::Type(typed) => Self::pattern_observes_scrutinee(&typed.pat),
            _ => true,
        }
    }

    fn record_tagged_enum_match(&mut self, path: &syn::Path) {
        let Some(mut reference) = path_reference(path, &self.context) else {
            return;
        };
        let Some(variant) = reference.segments.pop() else {
            return;
        };
        let Some(owner) = self.resolve_symbol_scoped(SymbolKind::Type, &reference) else {
            return;
        };
        if !self
            .types
            .enum_variants
            .get(&owner)
            .is_some_and(|variants| variants.contains(&variant))
        {
            return;
        }
        if let Some(tag) = self.types.enum_tags.get(&owner) {
            self.reads.insert((owner, tag.clone()));
        }
    }

    fn named_member(member: &syn::Member) -> Option<String> {
        match member {
            syn::Member::Named(ident) => {
                Some(ident.to_string().trim_start_matches("r#").to_string())
            }
            syn::Member::Unnamed(_) => None,
        }
    }

    fn members_match(left: &syn::Member, right: &syn::Member) -> bool {
        match (left, right) {
            (syn::Member::Named(left), syn::Member::Named(right)) => left == right,
            (syn::Member::Unnamed(left), syn::Member::Unnamed(right)) => left.index == right.index,
            _ => false,
        }
    }

    fn record_paths_match(&self, left: &syn::Path, right: &syn::Path) -> bool {
        if let (Some(left), Some(right)) = (
            self.resolve_path_scoped(left),
            self.resolve_path_scoped(right),
        ) {
            return left == right;
        }
        left.leading_colon.is_some() == right.leading_colon.is_some()
            && left.segments.len() == right.segments.len()
            && left
                .segments
                .iter()
                .zip(&right.segments)
                .all(|(left, right)| left.ident == right.ident)
    }

    fn visit_patterned_sequence(
        &mut self,
        patterns: &[&syn::Pat],
        expressions: &[&syn::Expr],
    ) -> bool {
        let rest_positions: Vec<_> = patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| Self::pattern_is_rest(pattern).then_some(index))
            .collect();

        if rest_positions.is_empty() {
            if patterns.len() != expressions.len() {
                return false;
            }
            for (pattern, expression) in patterns.iter().zip(expressions) {
                if !self.visit_patterned_initializer(pattern, expression) {
                    self.visit_expr(expression);
                }
            }
            return true;
        }
        if rest_positions.len() != 1 || expressions.len() + 1 < patterns.len() {
            return false;
        }

        let rest_index = rest_positions[0];
        for (pattern, expression) in patterns[..rest_index]
            .iter()
            .zip(&expressions[..rest_index])
        {
            if !self.visit_patterned_initializer(pattern, expression) {
                self.visit_expr(expression);
            }
        }

        let suffix_len = patterns.len() - rest_index - 1;
        for expression in &expressions[rest_index..expressions.len() - suffix_len] {
            if matches!(patterns[rest_index], syn::Pat::Rest(_)) {
                self.visit_discarded_expr(expression);
            } else if !self.visit_patterned_initializer(patterns[rest_index], expression) {
                self.visit_expr(expression);
            }
        }
        for (pattern, expression) in patterns[rest_index + 1..]
            .iter()
            .zip(&expressions[expressions.len() - suffix_len..])
        {
            if !self.visit_patterned_initializer(pattern, expression) {
                self.visit_expr(expression);
            }
        }
        true
    }

    fn visit_repeated_patterned_sequence(
        &mut self,
        patterns: &[&syn::Pat],
        expression: &syn::Expr,
    ) -> bool {
        let rest_positions: Vec<_> = patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| Self::pattern_is_rest(pattern).then_some(index))
            .collect();
        if rest_positions.len() > 1 {
            return false;
        }
        for pattern in patterns {
            if matches!(pattern, syn::Pat::Rest(_)) {
                self.visit_discarded_expr(expression);
                continue;
            }
            if !self.visit_patterned_initializer(pattern, expression) {
                self.visit_expr(expression);
            }
        }
        true
    }

    fn constructor_path(expression: &syn::Expr) -> Option<&syn::Path> {
        match expression {
            syn::Expr::Group(group) => Self::constructor_path(&group.expr),
            syn::Expr::Paren(paren) => Self::constructor_path(&paren.expr),
            syn::Expr::Path(path) => Some(&path.path),
            _ => None,
        }
    }

    fn visit_patterned_record(
        &mut self,
        pattern: &syn::PatStruct,
        expression: &syn::ExprStruct,
    ) -> bool {
        if !self.record_paths_match(&pattern.path, &expression.path) {
            return false;
        }
        let pattern_fields: Vec<_> = pattern
            .fields
            .iter()
            .filter(|field| !attributes_exclude_production(&field.attrs))
            .collect();
        let expression_fields: Vec<_> = expression
            .fields
            .iter()
            .filter(|field| !attributes_exclude_production(&field.attrs))
            .collect();
        let mut matched = BTreeSet::new();

        for pattern_field in pattern_fields {
            let Some((index, expression_field)) = expression_fields
                .iter()
                .enumerate()
                .find(|(_, field)| Self::members_match(&pattern_field.member, &field.member))
            else {
                return false;
            };
            if !matched.insert(index) {
                return false;
            }
            if !self.visit_patterned_initializer(&pattern_field.pat, &expression_field.expr) {
                self.visit_expr(&expression_field.expr);
            }
        }

        if pattern.rest.is_none() && matched.len() != expression_fields.len() {
            return false;
        }
        for (index, field) in expression_fields.iter().enumerate() {
            if !matched.contains(&index) {
                self.visit_discarded_expr(&field.expr);
            }
        }
        if let Some(rest) = &expression.rest {
            if pattern.rest.is_none() {
                return false;
            }
            self.visit_discarded_expr(rest);
        }
        true
    }

    fn bind_patterned_sequence(
        &mut self,
        patterns: &[&syn::Pat],
        expressions: &[&syn::Expr],
    ) -> bool {
        let rest_positions: Vec<_> = patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| Self::pattern_is_rest(pattern).then_some(index))
            .collect();
        if rest_positions.is_empty() {
            if patterns.len() != expressions.len() {
                return false;
            }
            for (pattern, expression) in patterns.iter().zip(expressions) {
                self.bind_patterned_initializer(pattern, expression);
            }
            return true;
        }
        if rest_positions.len() != 1 || expressions.len() + 1 < patterns.len() {
            return false;
        }

        let rest_index = rest_positions[0];
        for (pattern, expression) in patterns[..rest_index]
            .iter()
            .zip(&expressions[..rest_index])
        {
            self.bind_patterned_initializer(pattern, expression);
        }
        let suffix_len = patterns.len() - rest_index - 1;
        if let Some(expression) = expressions
            .get(rest_index..expressions.len() - suffix_len)
            .and_then(|expressions| expressions.first())
        {
            self.bind_patterned_initializer(patterns[rest_index], expression);
        } else {
            self.bind_pattern(patterns[rest_index], None);
        }
        for (pattern, expression) in patterns[rest_index + 1..]
            .iter()
            .zip(&expressions[expressions.len() - suffix_len..])
        {
            self.bind_patterned_initializer(pattern, expression);
        }
        true
    }

    fn bind_repeated_patterned_sequence(
        &mut self,
        patterns: &[&syn::Pat],
        expression: &syn::Expr,
    ) -> bool {
        if patterns
            .iter()
            .filter(|pattern| Self::pattern_is_rest(pattern))
            .count()
            > 1
        {
            return false;
        }
        for pattern in patterns {
            if !matches!(pattern, syn::Pat::Rest(_)) {
                self.bind_patterned_initializer(pattern, expression);
            }
        }
        true
    }

    fn bind_patterned_record(
        &mut self,
        pattern: &syn::PatStruct,
        expression: &syn::ExprStruct,
    ) -> bool {
        if !self.record_paths_match(&pattern.path, &expression.path) {
            return false;
        }
        let expression_fields: Vec<_> = expression
            .fields
            .iter()
            .filter(|field| !attributes_exclude_production(&field.attrs))
            .collect();
        for pattern_field in pattern
            .fields
            .iter()
            .filter(|field| !attributes_exclude_production(&field.attrs))
        {
            let Some(expression_field) = expression_fields
                .iter()
                .find(|field| Self::members_match(&pattern_field.member, &field.member))
            else {
                return false;
            };
            self.bind_patterned_initializer(&pattern_field.pat, &expression_field.expr);
        }
        true
    }

    fn bind_patterned_initializer(&mut self, pattern: &syn::Pat, expression: &syn::Expr) {
        let saved_environment = self.environment.clone();
        if !self.try_bind_patterned_initializer(pattern, expression) {
            self.environment = saved_environment;
            self.bind_inferred_pattern(pattern, expression);
        }
    }

    fn try_bind_patterned_initializer(
        &mut self,
        pattern: &syn::Pat,
        expression: &syn::Expr,
    ) -> bool {
        match (pattern, expression) {
            (syn::Pat::Ident(ident), _) if ident.subpat.is_some() => {
                let inferred = self.infer_expr(expression);
                self.bind_identifier(ident, inferred.as_ref());
                if let Some((_, subpattern)) = &ident.subpat {
                    return self.try_bind_patterned_initializer(subpattern, expression);
                }
                true
            }
            (syn::Pat::Paren(pattern), _) => {
                self.try_bind_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Reference(pattern), _) => {
                self.try_bind_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Type(pattern), _) => {
                self.try_bind_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Or(alternatives), _) => {
                let saved_environment = self.environment.clone();
                for alternative in &alternatives.cases {
                    self.environment = saved_environment.clone();
                    if self.try_bind_patterned_initializer(alternative, expression) {
                        return true;
                    }
                }
                self.environment = saved_environment;
                false
            }
            (_, syn::Expr::Group(expression)) => {
                self.try_bind_patterned_initializer(pattern, &expression.expr)
            }
            (_, syn::Expr::Paren(expression)) => {
                self.try_bind_patterned_initializer(pattern, &expression.expr)
            }
            (syn::Pat::Wild(_) | syn::Pat::Rest(_), _) => true,
            (syn::Pat::Tuple(pattern), syn::Expr::Tuple(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.elems.iter().collect();
                self.bind_patterned_sequence(&patterns, &expressions)
            }
            (syn::Pat::TupleStruct(pattern), syn::Expr::Call(expression)) => {
                match Self::constructor_path(&expression.func) {
                    Some(path) if self.record_paths_match(&pattern.path, path) => {
                        let patterns: Vec<_> = pattern.elems.iter().collect();
                        let expressions: Vec<_> = expression.args.iter().collect();
                        self.bind_patterned_sequence(&patterns, &expressions)
                    }
                    _ => false,
                }
            }
            (syn::Pat::Slice(pattern), syn::Expr::Array(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.elems.iter().collect();
                self.bind_patterned_sequence(&patterns, &expressions)
            }
            (syn::Pat::Slice(pattern), syn::Expr::Repeat(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                self.bind_repeated_patterned_sequence(&patterns, &expression.expr)
            }
            (syn::Pat::Struct(pattern), syn::Expr::Struct(expression)) => {
                self.bind_patterned_record(pattern, expression)
            }
            _ => false,
        }
    }

    fn bind_inferred_pattern(&mut self, pattern: &syn::Pat, expression: &syn::Expr) {
        let inferred = self.infer_expr(expression);
        self.bind_pattern(pattern, inferred.as_ref());
    }

    fn visit_patterned_initializer(&mut self, pattern: &syn::Pat, expression: &syn::Expr) -> bool {
        match (pattern, expression) {
            (syn::Pat::Ident(ident), _) if ident.subpat.is_some() => {
                self.visit_expr(expression);
                if let Some((_, subpattern)) = &ident.subpat {
                    let _ = self.visit_patterned_initializer(subpattern, expression);
                }
                true
            }
            (syn::Pat::Paren(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Reference(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Type(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Or(alternatives), _) => {
                let saved_environment = self.environment.clone();
                let mut paired = false;
                for alternative in &alternatives.cases {
                    self.environment = saved_environment.clone();
                    paired |= self.visit_patterned_initializer(alternative, expression);
                }
                self.environment = saved_environment;
                paired
            }
            (_, syn::Expr::Group(expression)) => {
                self.visit_patterned_initializer(pattern, &expression.expr)
            }
            (_, syn::Expr::Paren(expression)) => {
                self.visit_patterned_initializer(pattern, &expression.expr)
            }
            (syn::Pat::Wild(_), _) => {
                self.visit_discarded_expr(expression);
                true
            }
            (syn::Pat::Rest(_), _) => {
                self.visit_discarded_expr(expression);
                true
            }
            (syn::Pat::Tuple(pattern), syn::Expr::Tuple(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.elems.iter().collect();
                self.visit_patterned_sequence(&patterns, &expressions)
            }
            (syn::Pat::TupleStruct(pattern), syn::Expr::Call(expression)) => {
                let Some(path) = Self::constructor_path(&expression.func) else {
                    return false;
                };
                if !self.record_paths_match(&pattern.path, path) {
                    return false;
                }
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.args.iter().collect();
                self.visit_patterned_sequence(&patterns, &expressions)
            }
            (syn::Pat::Slice(pattern), syn::Expr::Array(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.elems.iter().collect();
                self.visit_patterned_sequence(&patterns, &expressions)
            }
            (syn::Pat::Slice(pattern), syn::Expr::Repeat(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let paired = self.visit_repeated_patterned_sequence(&patterns, &expression.expr);
                if paired {
                    self.visit_expr(&expression.len);
                }
                paired
            }
            (syn::Pat::Struct(pattern), syn::Expr::Struct(expression)) => {
                self.visit_patterned_record(pattern, expression)
            }
            _ => false,
        }
    }

    fn infer_item_closure(
        &mut self,
        closure: &syn::ExprClosure,
        item_owner: Option<&InferredValue>,
    ) -> Option<InferredValue> {
        let saved_environment = self.environment.clone();
        for (index, input) in closure.inputs.iter().enumerate() {
            self.bind_pattern(input, (index == 0).then_some(item_owner).flatten());
        }
        let result = self.infer_expr(&closure.body);
        self.environment = saved_environment;
        result
    }

    fn method_passes_item_to_closure(method: &str) -> bool {
        matches!(
            method,
            "all"
                | "and_then"
                | "any"
                | "filter"
                | "filter_map"
                | "find"
                | "find_map"
                | "for_each"
                | "inspect"
                | "is_some_and"
                | "map"
                | "map_or"
                | "map_or_else"
                | "max_by_key"
                | "min_by_key"
                | "partition"
                | "position"
                | "retain"
                | "rposition"
                | "skip_while"
                | "sort_by_key"
                | "take_while"
        )
    }

    fn method_preserves_owner(method: &str) -> bool {
        matches!(
            method,
            "as_ref"
                | "as_mut"
                | "as_deref"
                | "as_slice"
                | "as_str"
                | "borrow"
                | "borrow_mut"
                | "chain"
                | "clone"
                | "cloned"
                | "copied"
                | "enumerate"
                | "expect"
                | "filter"
                | "first"
                | "first_mut"
                | "flatten"
                | "fuse"
                | "get"
                | "get_mut"
                | "inspect"
                | "into_iter"
                | "iter"
                | "iter_mut"
                | "last"
                | "last_mut"
                | "next"
                | "peekable"
                | "rev"
                | "skip"
                | "skip_while"
                | "take"
                | "take_while"
                | "unwrap"
                | "unwrap_or"
                | "unwrap_or_default"
                | "values"
                | "values_mut"
        )
    }

    fn method_reads_receiver(method: &str) -> bool {
        Self::method_passes_item_to_closure(method)
            || Self::method_preserves_owner(method)
            || matches!(
                method,
                "abs"
                    | "abs_diff"
                    | "as_bytes"
                    | "as_micros"
                    | "as_millis"
                    | "as_nanos"
                    | "as_os_str"
                    | "as_path"
                    | "as_secs"
                    | "as_secs_f64"
                    | "binary_search"
                    | "binary_search_by"
                    | "binary_search_by_key"
                    | "bytes"
                    | "capacity"
                    | "chars"
                    | "checked_add"
                    | "checked_div"
                    | "checked_mul"
                    | "checked_sub"
                    | "clamp"
                    | "cmp"
                    | "collect"
                    | "contains"
                    | "contains_key"
                    | "count"
                    | "display"
                    | "duration_since"
                    | "elapsed"
                    | "ends_with"
                    | "eq"
                    | "eq_ignore_ascii_case"
                    | "floor"
                    | "ge"
                    | "gt"
                    | "has_root"
                    | "is_absolute"
                    | "is_ascii"
                    | "is_empty"
                    | "is_err"
                    | "is_finite"
                    | "is_infinite"
                    | "is_nan"
                    | "is_none"
                    | "is_ok"
                    | "is_relative"
                    | "is_some"
                    | "is_pinned"
                    | "is_zero"
                    | "join"
                    | "le"
                    | "len"
                    | "lines"
                    | "lt"
                    | "matches_wire"
                    | "max"
                    | "min"
                    | "ne"
                    | "parse"
                    | "rsplit"
                    | "rsplit_once"
                    | "saturating_add"
                    | "saturating_mul"
                    | "saturating_sub"
                    | "split"
                    | "split_once"
                    | "starts_with"
                    | "strip_prefix"
                    | "strip_suffix"
                    | "then"
                    | "then_some"
                    | "to_owned"
                    | "to_ascii_lowercase"
                    | "to_ascii_uppercase"
                    | "to_be_bytes"
                    | "to_le_bytes"
                    | "to_path_buf"
                    | "to_str"
                    | "to_string"
                    | "to_string_lossy"
                    | "to_vec"
                    | "trim"
                    | "trim_end"
                    | "trim_end_matches"
                    | "trim_matches"
                    | "trim_start"
                    | "trim_start_matches"
                    | "wrapping_add"
                    | "wrapping_mul"
                    | "wrapping_sub"
            )
    }

    fn method_uses_mutable_receiver(method: &str) -> bool {
        matches!(
            method,
            "as_mut"
                | "borrow_mut"
                | "clone_from"
                | "clone_from_slice"
                | "copy_from_slice"
                | "first_mut"
                | "get_mut"
                | "iter_mut"
                | "last_mut"
                | "retain"
                | "sort_by_key"
                | "values_mut"
        )
    }

    fn infer_homogeneous_elements<'b>(
        &mut self,
        elements: impl IntoIterator<Item = &'b syn::Expr>,
    ) -> Option<InferredValue> {
        let inferred: Vec<_> = elements
            .into_iter()
            .map(|element| self.infer_expr(element))
            .collect();
        let first = inferred.first()?.as_ref()?.clone();
        inferred
            .iter()
            .all(|candidate| {
                candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.kind == first.kind)
            })
            .then_some(first)
    }

    fn infer_expr(&mut self, expression: &syn::Expr) -> Option<InferredValue> {
        if expr_attributes(expression).is_some_and(attributes_exclude_production) {
            return None;
        }
        match expression {
            syn::Expr::Array(array) => self.infer_homogeneous_elements(&array.elems),
            syn::Expr::Await(awaited) => self.infer_expr(&awaited.base),
            syn::Expr::Call(call) => {
                self.visit_expr(&call.func);
                for argument in &call.args {
                    self.visit_expr(argument);
                }
                let syn::Expr::Path(path) = call.func.as_ref() else {
                    return None;
                };
                self.function_return_scoped(&path.path)
            }
            syn::Expr::Field(field) => {
                let member = Self::named_member(&field.member)?;
                let owner = self.infer_expr(&field.base)?;
                let owner = owner.owner()?.to_string();
                let target = self.types.field_type(&owner, &member);
                if self.types.fields.contains_key(&owner) {
                    self.reads.insert((owner, member));
                }
                target.map(|owner| InferredValue::nominal(owner, false))
            }
            syn::Expr::Group(group) => self.infer_expr(&group.expr),
            syn::Expr::Index(index) => {
                let owner = self.infer_expr(&index.expr);
                self.visit_expr(&index.index);
                owner
            }
            syn::Expr::MethodCall(call) => {
                let method = call.method.to_string();
                let passes_item_to_closure = Self::method_passes_item_to_closure(method.as_str());
                // First resolve the receiver as a place, which gives local
                // method signatures an owner without treating the destination
                // itself as a read.
                let place_owner = self.infer_place_expr(&call.receiver);
                let receiver = place_owner
                    .as_ref()
                    .and_then(|owner| {
                        let owner = owner.owner()?;
                        let in_scope_traits = self.traits_in_scope_for_method(&method);
                        Some(self.types.method_receiver(owner, &method, &in_scope_traits))
                    })
                    .unwrap_or(MethodReceiverResolution::Missing);
                let (reads_receiver, uses_mutable_receiver) = match receiver {
                    MethodReceiverResolution::SharedOrValue => (true, false),
                    MethodReceiverResolution::Mutable | MethodReceiverResolution::Ambiguous => {
                        (false, true)
                    }
                    MethodReceiverResolution::Missing => (
                        Self::method_reads_receiver(method.as_str()),
                        Self::method_uses_mutable_receiver(method.as_str()),
                    ),
                };
                // Unknown methods fail closed as potential mutations. Known
                // standard mutable readers still evaluate their receiver as a
                // value; mutable access only affects downstream provenance.
                let mut owner = if reads_receiver {
                    self.infer_expr(&call.receiver)
                } else {
                    place_owner
                };
                if uses_mutable_receiver {
                    if let Some(owner) = owner.as_mut() {
                        owner.mutable_place = true;
                    }
                }
                let mut closure_result = None;
                for argument in &call.args {
                    if passes_item_to_closure {
                        if let syn::Expr::Closure(closure) = argument {
                            closure_result = self.infer_item_closure(closure, owner.as_ref());
                            continue;
                        }
                    }
                    self.visit_expr(argument);
                }
                if !reads_receiver {
                    return None;
                }
                if matches!(method.as_str(), "and_then" | "filter_map" | "map") {
                    return closure_result;
                }
                Self::method_preserves_owner(method.as_str())
                    .then_some(owner)
                    .flatten()
            }
            syn::Expr::Paren(paren) => self.infer_expr(&paren.expr),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.environment.get(&ident.to_string()).cloned()),
            syn::Expr::Reference(reference) => {
                if reference.mutability.is_some() {
                    self.infer_place_expr(&reference.expr)
                } else {
                    self.infer_expr(&reference.expr)
                }
            }
            syn::Expr::Repeat(repeat) => {
                let owner = self.infer_expr(&repeat.expr);
                self.visit_expr(&repeat.len);
                owner
            }
            syn::Expr::Struct(record) => {
                for field in &record.fields {
                    self.visit_field_value(field);
                }
                if let Some(rest) = &record.rest {
                    self.visit_expr(rest);
                }
                self.resolve_path_scoped(&record.path)
                    .map(|owner| InferredValue::nominal(owner, false))
            }
            syn::Expr::Try(tried) => self.infer_expr(&tried.expr),
            syn::Expr::Tuple(tuple) => Some(InferredValue::tuple(
                tuple
                    .elems
                    .iter()
                    .map(|element| self.infer_expr(element))
                    .collect(),
            )),
            syn::Expr::Unary(unary) => self.infer_expr(&unary.expr),
            _ => {
                syn::visit::visit_expr(self, expression);
                None
            }
        }
    }

    fn infer_place_expr(&mut self, expression: &syn::Expr) -> Option<InferredValue> {
        if expr_attributes(expression).is_some_and(attributes_exclude_production) {
            return None;
        }
        match expression {
            syn::Expr::Array(array) => {
                for element in &array.elems {
                    let _ = self.infer_place_expr(element);
                }
                None
            }
            syn::Expr::Field(field) => {
                let owner = self.infer_place_expr(&field.base)?;
                let owner = owner.owner()?;
                let member = Self::named_member(&field.member)?;
                self.types
                    .field_type(owner, &member)
                    .map(|target| InferredValue::nominal(target, true))
            }
            syn::Expr::Group(group) => self.infer_place_expr(&group.expr),
            syn::Expr::Index(index) => {
                let owner = self.infer_place_expr(&index.expr);
                self.visit_expr(&index.index);
                owner
            }
            syn::Expr::Paren(paren) => self.infer_place_expr(&paren.expr),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.environment.get(&ident.to_string()).cloned()),
            syn::Expr::Reference(reference) => self.infer_place_expr(&reference.expr),
            syn::Expr::Struct(record) => {
                for field in &record.fields {
                    if !attributes_exclude_production(&field.attrs) {
                        let _ = self.infer_place_expr(&field.expr);
                    }
                }
                if let Some(rest) = &record.rest {
                    let _ = self.infer_place_expr(rest);
                }
                None
            }
            syn::Expr::Try(tried) => self.infer_place_expr(&tried.expr),
            syn::Expr::Tuple(tuple) => {
                for element in &tuple.elems {
                    let _ = self.infer_place_expr(element);
                }
                None
            }
            syn::Expr::Unary(unary) => {
                if matches!(&unary.op, syn::UnOp::Deref(_)) {
                    self.infer_expr(&unary.expr)
                } else {
                    self.visit_expr(&unary.expr);
                    None
                }
            }
            _ => {
                self.visit_expr(expression);
                None
            }
        }
    }

    fn visit_discarded_expr(&mut self, expression: &syn::Expr) {
        match expression {
            syn::Expr::Field(_)
            | syn::Expr::Path(_)
            | syn::Expr::Reference(_)
            | syn::Expr::Unary(_) => {
                let _ = self.infer_place_expr(expression);
            }
            syn::Expr::Group(group) => self.visit_discarded_expr(&group.expr),
            syn::Expr::Paren(paren) => self.visit_discarded_expr(&paren.expr),
            syn::Expr::Try(tried) => self.visit_discarded_expr(&tried.expr),
            _ => self.visit_expr(expression),
        }
    }
}

impl<'ast> Visit<'ast> for FieldReadVisitor<'_> {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        let test_only = match node {
            syn::Stmt::Local(local) => attributes_exclude_production(&local.attrs),
            syn::Stmt::Item(item) => {
                item_attributes(item).is_some_and(attributes_exclude_production)
            }
            syn::Stmt::Expr(expression, _) => {
                expr_attributes(expression).is_some_and(attributes_exclude_production)
            }
            syn::Stmt::Macro(statement) => attributes_exclude_production(&statement.attrs),
        };
        if !test_only {
            syn::visit::visit_stmt(self, node);
        }
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if !expr_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_expr(self, node);
        }
    }

    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        if !attributes_exclude_production(&node.attrs) {
            syn::visit::visit_field_value(self, node);
        }
    }

    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !item_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        if !impl_item_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_impl_item(self, node);
        }
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        if !trait_item_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_trait_item(self, node);
        }
    }

    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        if !foreign_item_attributes(node).is_some_and(attributes_exclude_production) {
            syn::visit::visit_foreign_item(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let Some((_, items)) = &node.content else {
            return;
        };
        let saved_context = self.context.clone();
        self.context = self.context.child(&node.ident);
        for item in items {
            self.visit_item(item);
        }
        self.context = saved_context;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let saved_owner = self.impl_owner.clone();
        self.impl_owner = self.resolve_type_scoped(&node.self_ty);
        syn::visit::visit_item_impl(self, node);
        self.impl_owner = saved_owner;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !attributes_exclude_production(&node.attrs) {
            self.visit_function(&node.sig.inputs, &node.block);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !attributes_exclude_production(&node.attrs) {
            self.visit_function(&node.sig.inputs, &node.block);
        }
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        let _ = self.infer_expr(&syn::Expr::Field(node.clone()));
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        // The destination is a place, not a value read. The right-hand side
        // can still contain genuine config reads. Computing a nested place
        // (for example, an index expression) can contain reads of its own.
        let _ = self.infer_place_expr(&node.left);
        self.visit_expr(&node.right);
    }

    fn visit_expr_reference(&mut self, node: &'ast syn::ExprReference) {
        if node.mutability.is_some() {
            let _ = self.infer_place_expr(&node.expr);
        } else {
            self.visit_expr(&node.expr);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let _ = self.infer_expr(&syn::Expr::MethodCall(node.clone()));
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if attributes_exclude_production(&node.attrs) {
            return;
        }
        let saved_environment = self.environment.clone();
        let (inferred, patterned_initializer) = node.init.as_ref().map_or((None, false), |init| {
            if self.visit_patterned_initializer(&node.pat, &init.expr) {
                (None, true)
            } else {
                (self.infer_expr(&init.expr), false)
            }
        });
        self.environment = saved_environment.clone();
        if let Some(init) = &node.init {
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
                self.environment = saved_environment.clone();
            }
        }
        if patterned_initializer {
            if let Some(init) = &node.init {
                self.bind_patterned_initializer(&node.pat, &init.expr);
            }
        } else {
            self.bind_pattern(&node.pat, inferred.as_ref());
        }
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        let saved_environment = self.environment.clone();
        if self.in_function {
            self.local_scopes.push(self.block_symbol_scope(node));
        }
        syn::visit::visit_block(self, node);
        self.environment = saved_environment;
        if self.in_function {
            self.local_scopes.pop();
        }
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let owner = self.infer_expr(&node.expr);
        let saved_environment = self.environment.clone();
        self.bind_pattern(&node.pat, owner.as_ref());
        self.visit_block(&node.body);
        self.environment = saved_environment;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let saved_environment = self.environment.clone();
        self.visit_expr(&node.cond);
        self.visit_block(&node.then_branch);
        self.environment = saved_environment.clone();
        if let Some((_, otherwise)) = &node.else_branch {
            self.visit_expr(otherwise);
        }
        self.environment = saved_environment;
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        let saved_environment = self.environment.clone();
        let patterned_initializer = self.visit_patterned_initializer(&node.pat, &node.expr);
        let inferred = (!patterned_initializer)
            .then(|| self.infer_expr(&node.expr))
            .flatten();
        self.environment = saved_environment;
        if patterned_initializer {
            self.bind_patterned_initializer(&node.pat, &node.expr);
        } else {
            self.bind_pattern(&node.pat, inferred.as_ref());
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let saved_environment = self.environment.clone();
        let patterned_arms: Vec<_> = node
            .arms
            .iter()
            .map(|arm| {
                if attributes_exclude_production(&arm.attrs) {
                    return false;
                }
                self.environment = saved_environment.clone();
                self.visit_patterned_initializer(&arm.pat, &node.expr)
            })
            .collect();
        self.environment = saved_environment.clone();
        let has_patterned_arm = node
            .arms
            .iter()
            .zip(&patterned_arms)
            .any(|(arm, paired)| *paired && Self::pattern_has_initializer_structure(&arm.pat));
        let observes_scrutinee = node.arms.iter().any(|arm| {
            !attributes_exclude_production(&arm.attrs) && Self::pattern_observes_scrutinee(&arm.pat)
        });
        let inferred = (!has_patterned_arm)
            .then(|| {
                if observes_scrutinee {
                    self.infer_expr(&node.expr)
                } else {
                    self.infer_place_expr(&node.expr)
                        .or_else(|| self.infer_expr(&node.expr))
                }
            })
            .flatten();
        self.environment = saved_environment.clone();
        for (arm, patterned_initializer) in node.arms.iter().zip(patterned_arms) {
            if attributes_exclude_production(&arm.attrs) {
                continue;
            }
            let saved_environment = self.environment.clone();
            if patterned_initializer {
                self.bind_patterned_initializer(&arm.pat, &node.expr);
            } else if !has_patterned_arm {
                self.bind_pattern(&arm.pat, inferred.as_ref());
            }
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.environment = saved_environment;
        }
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let saved_environment = self.environment.clone();
        self.visit_expr(&node.cond);
        self.visit_block(&node.body);
        self.environment = saved_environment;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let saved_environment = self.environment.clone();
        for input in &node.inputs {
            self.bind_pattern(input, None);
        }
        self.visit_expr(&node.body);
        self.environment = saved_environment;
    }
}

fn typed_field_reads(sources: &[&SourceFile], types: &RustTypeIndex) -> BTreeSet<(String, String)> {
    let mut reads = BTreeSet::new();
    for source in sources {
        let Some(context) = ModuleContext::from_source_path(&source.path) else {
            continue;
        };
        if let Ok(file) = &source.ast {
            let mut visitor = FieldReadVisitor::new(types, context);
            visitor.visit_file(file);
            reads.extend(visitor.reads);
        }
    }
    reads
}

fn has_unambiguous_field_read(
    key: &ConfigSchemaKey,
    typed_reads: &BTreeSet<(String, String)>,
    types: &RustTypeIndex,
) -> bool {
    let Some(owner) = key.rust_owner.as_deref() else {
        return false;
    };
    let Some(owner) = types.schema_owner(owner) else {
        return false;
    };
    let Some(rust_field) = types.rust_field_for_schema_field(&owner, &key.rust_field) else {
        return false;
    };
    typed_reads.contains(&(owner, rust_field.to_string()))
}

/// Whether a named consumer resolves to a real production symbol.
///
/// Two shapes resolve, because real readers come in both. A free
/// function is `crate::module::function`. A method is
/// `crate::module::Type::method`, and the last-but-one segment is then a
/// type rather than another module. The free-function reading is tried
/// first and the method reading only if the module file it implies does
/// not exist, so a module and a type sharing a name cannot make one
/// shape silently satisfy the other.
///
/// Rejecting methods outright is what this used to do, and it left no
/// way to name a reader like `AiHandlerConfig::router`: the only
/// options were to invent a free function that existed to be cited, or
/// to misclassify a wired key as `config_only`. Both are worse than
/// teaching the guard the second shape.
fn production_consumer_exists(consumer: &str, sources: &[&SourceFile]) -> bool {
    let segments: Vec<&str> = consumer.split("::").collect();
    let [crate_name, modules @ .., symbol] = segments.as_slice() else {
        return false;
    };
    if consumer_symbol_exists(crate_name, modules, symbol, None, sources) {
        return true;
    }
    // `modules` ends with a type name for the method shape, so the file
    // is one segment shorter than the free-function reading assumed.
    let [outer @ .., type_name] = modules else {
        return false;
    };
    consumer_symbol_exists(crate_name, outer, symbol, Some(type_name), sources)
}

/// Resolve one reading of a consumer path against the scanned sources.
///
/// `impl_type` selects the shape: `None` looks for a free function in
/// the module file, `Some(type)` for a method in an `impl type` block
/// inside it.
fn consumer_symbol_exists(
    crate_name: &str,
    modules: &[&str],
    symbol: &str,
    impl_type: Option<&str>,
    sources: &[&SourceFile],
) -> bool {
    let crate_dir = crate_name.replace('_', "-");
    let module_path = modules.join("/");
    let expected_files: Vec<String> = if module_path.is_empty() {
        vec![
            format!("crates/{crate_dir}/src/lib.rs"),
            format!("crates/{crate_dir}/src/main.rs"),
        ]
    } else {
        vec![
            format!("crates/{crate_dir}/src/{module_path}.rs"),
            format!("crates/{crate_dir}/src/{module_path}/mod.rs"),
        ]
    };

    sources.iter().any(|source| {
        let normalized = source.path.to_string_lossy().replace('\\', "/");
        expected_files
            .iter()
            .any(|expected| normalized.ends_with(expected))
            && match impl_type {
                None => source_declares_function(source, symbol),
                Some(type_name) => source_declares_method(source, type_name, symbol),
            }
    })
}

fn source_declares_function(source: &SourceFile, symbol: &str) -> bool {
    let Ok(file) = &source.ast else {
        return false;
    };
    file.items.iter().any(|item| {
        matches!(
            item,
            syn::Item::Fn(function)
                if function.sig.ident == symbol
                    && !attributes_exclude_production(&function.attrs)
        )
    })
}

/// Whether `impl type_name` in this file declares `symbol` as a method.
///
/// Trait impls are skipped. A trait method's name is the trait's rather
/// than this type's, so accepting them would let a path like
/// `Type::fmt` stand as evidence that a config key is read.
fn source_declares_method(source: &SourceFile, type_name: &str, symbol: &str) -> bool {
    let Ok(file) = &source.ast else {
        return false;
    };
    file.items.iter().any(|item| {
        let syn::Item::Impl(block) = item else {
            return false;
        };
        if block.trait_.is_some() || attributes_exclude_production(&block.attrs) {
            return false;
        }
        let syn::Type::Path(path) = block.self_ty.as_ref() else {
            return false;
        };
        if path
            .path
            .segments
            .last()
            .is_none_or(|last| last.ident != type_name)
        {
            return false;
        }
        block.items.iter().any(|item| {
            matches!(
                item,
                syn::ImplItem::Fn(method)
                    if method.sig.ident == symbol
                        && !attributes_exclude_production(&method.attrs)
            )
        })
    })
}

fn item_attributes(item: &syn::Item) -> Option<&[syn::Attribute]> {
    match item {
        syn::Item::Const(item) => Some(&item.attrs),
        syn::Item::Enum(item) => Some(&item.attrs),
        syn::Item::ExternCrate(item) => Some(&item.attrs),
        syn::Item::Fn(item) => Some(&item.attrs),
        syn::Item::ForeignMod(item) => Some(&item.attrs),
        syn::Item::Impl(item) => Some(&item.attrs),
        syn::Item::Macro(item) => Some(&item.attrs),
        syn::Item::Mod(item) => Some(&item.attrs),
        syn::Item::Static(item) => Some(&item.attrs),
        syn::Item::Struct(item) => Some(&item.attrs),
        syn::Item::Trait(item) => Some(&item.attrs),
        syn::Item::TraitAlias(item) => Some(&item.attrs),
        syn::Item::Type(item) => Some(&item.attrs),
        syn::Item::Union(item) => Some(&item.attrs),
        syn::Item::Use(item) => Some(&item.attrs),
        syn::Item::Verbatim(_) | _ => None,
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::ImplItem::Const(item) => Some(&item.attrs),
        syn::ImplItem::Fn(item) => Some(&item.attrs),
        syn::ImplItem::Type(item) => Some(&item.attrs),
        syn::ImplItem::Macro(item) => Some(&item.attrs),
        syn::ImplItem::Verbatim(_) | _ => None,
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::TraitItem::Const(item) => Some(&item.attrs),
        syn::TraitItem::Fn(item) => Some(&item.attrs),
        syn::TraitItem::Type(item) => Some(&item.attrs),
        syn::TraitItem::Macro(item) => Some(&item.attrs),
        syn::TraitItem::Verbatim(_) | _ => None,
    }
}

fn foreign_item_attributes(item: &syn::ForeignItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::ForeignItem::Fn(item) => Some(&item.attrs),
        syn::ForeignItem::Static(item) => Some(&item.attrs),
        syn::ForeignItem::Type(item) => Some(&item.attrs),
        syn::ForeignItem::Macro(item) => Some(&item.attrs),
        syn::ForeignItem::Verbatim(_) | _ => None,
    }
}

fn expr_attributes(expression: &syn::Expr) -> Option<&[syn::Attribute]> {
    macro_rules! attributes {
        ($($variant:ident),+ $(,)?) => {
            match expression {
                $(syn::Expr::$variant(expression) => Some(&expression.attrs),)+
                syn::Expr::Verbatim(_) => None,
                _ => None,
            }
        };
    }

    attributes!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary,
        Unsafe, While, Yield,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn source(text: &str) -> SourceFile {
        source_at("crates/example/src/lib.rs", text)
    }

    fn source_at(path: &str, text: &str) -> SourceFile {
        source_with_views(path, text, &crate::scan::strip_test_regions(text))
    }

    fn source_with_views(path: &str, raw_text: &str, text: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from(path),
            raw_text: raw_text.to_string(),
            text: text.to_string(),
            // Parsed here so fixtures carry the same invariant the collector
            // guarantees: `ast` is always `raw_text` parsed. Fixtures that are
            // deliberately unparseable land in `Err`, which is what the
            // parse-error path expects to see.
            ast: syn::parse_file(raw_text).map_err(|error| error.to_string()),
        }
    }

    fn key(path: &str, field: &str) -> ConfigSchemaKey {
        ConfigSchemaKey {
            path: path.to_string(),
            rust_field: field.to_string(),
            rust_owner: Some("Config".to_string()),
        }
    }

    fn guard_key() -> ConfigSchemaKey {
        ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }
    }

    fn guard_errors(sources: &[SourceFile]) -> Vec<RegistryError> {
        verify_config_readers(&[guard_key()], &[], sources)
    }

    #[test]
    fn schema_walk_follows_refs_arrays_maps_and_nested_objects() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "proxy": {"$ref": "#/definitions/Proxy"},
                "origins": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/definitions/Origin"}
                }
            },
            "definitions": {
                "Proxy": {
                    "type": "object",
                    "properties": {
                        "live-key": {"type": "boolean"},
                        "nested": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}}
                        },
                        "routes": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/Route"}
                        }
                    }
                },
                "Origin": {
                    "allOf": [{
                        "type": "object",
                        "properties": {"enabled": {"type": "boolean"}}
                    }]
                },
                "Route": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}}
                }
            }
        });

        let paths: BTreeMap<String, String> = schema_key_paths(&schema)
            .into_iter()
            .map(|key| (key.path, key.rust_field))
            .collect();

        assert_eq!(paths.get("proxy.live-key"), Some(&"live_key".to_string()));
        assert!(paths.contains_key("proxy.nested.value"));
        assert!(paths.contains_key("proxy.routes[].path"));
        assert!(paths.contains_key("origins.*.enabled"));
        assert!(
            !paths.contains_key("proxy"),
            "object containers are not configuration leaves"
        );
        assert!(
            !paths.contains_key("proxy.nested"),
            "only leaf keys need reader evidence"
        );
    }

    #[test]
    fn scalar_collections_emit_element_leaves_with_the_container_field_owner() {
        let schema = serde_json::json!({
            "title": "Config",
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "labels": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }
            }
        });

        let keys: BTreeMap<_, _> = schema_key_paths(&schema)
            .into_iter()
            .map(|key| (key.path, (key.rust_owner, key.rust_field)))
            .collect();

        assert_eq!(
            keys,
            BTreeMap::from([
                (
                    "labels.*".to_string(),
                    (Some("Config".to_string()), "labels".to_string()),
                ),
                (
                    "tags[]".to_string(),
                    (Some("Config".to_string()), "tags".to_string()),
                ),
            ])
        );
    }

    #[test]
    fn unread_schema_key_fails_and_names_the_key() {
        let keys = [key("proxy.live", "live"), key("proxy.unread", "unread")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
    unread: bool,
}

pub fn production(config: &Config) {
    consume(config.live);
}

#[cfg(test)]
mod tests {
    fn only_test_reads(config: &Config) { consume(config.unread); }
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].subject, "proxy.unread");
        assert!(errors[0]
            .message
            .contains("no unambiguous non-test Rust read"));
    }

    #[test]
    fn config_only_override_with_reason_allows_an_unread_key() {
        let keys = [key("proxy.unread", "unread")];
        let override_entry = ConfigKeyCapability {
            path: "proxy.unread",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("reserved and rejected until WOR-9999"),
        };

        assert_eq!(verify_config_readers(&keys, &[override_entry], &[]), vec![]);
    }

    #[test]
    fn parent_override_does_not_exempt_a_new_unread_child() {
        let keys = [
            key("proxy.reserved", "reserved"),
            key("proxy.reserved.enabled", "enabled"),
        ];
        let override_entry = ConfigKeyCapability {
            path: "proxy.reserved",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("reserved until WOR-9999"),
        };

        let errors = verify_config_readers(&keys, &[override_entry], &[]);

        assert!(
            errors
                .iter()
                .any(|error| error.subject == "proxy.reserved.enabled"),
            "a parent classification must not silently classify future leaves: {errors:?}"
        );
    }

    #[test]
    fn unrelated_same_named_field_read_does_not_cover_a_schema_leaf() {
        let schema = serde_json::json!({
            "title": "ConfigFile",
            "type": "object",
            "properties": {
                "proxy": {"$ref": "#/definitions/ProxyConfig"}
            },
            "definitions": {
                "ProxyConfig": {
                    "type": "object",
                    "properties": {
                        "new_guard": {"$ref": "#/definitions/NewGuardConfig"}
                    }
                },
                "NewGuardConfig": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"}
                    }
                }
            }
        });
        let keys = schema_key_paths(&schema);
        let sources = [source(
            r#"
struct ExistingFeature {
    enabled: bool,
}

struct NewGuardConfig {
    enabled: bool,
}

fn production(existing: &ExistingFeature) {
    consume(existing.enabled);
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors
                .iter()
                .any(|error| error.subject == "proxy.new_guard.enabled"),
            "a read of ExistingFeature::enabled must not prove NewGuardConfig::enabled: {errors:?}"
        );
    }

    #[test]
    fn same_named_type_in_another_crate_cannot_prove_the_schema_owner() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors
                .iter()
                .any(|error| error.subject == "proxy.guard.enabled"),
            "a runtime-local namesake must not prove the config type: {errors:?}"
        );
    }

    #[test]
    fn unresolved_explicit_external_type_cannot_collapse_to_a_local_namesake() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime(v: external_crate::GuardConfig) { consume(v.enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "an unresolved qualified type must fail closed: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn external_imports_and_type_aliases_cannot_shadow_the_config_owner() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for runtime in [
            "use external_crate::GuardConfig;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "use external_crate::Something as GuardConfig;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "type GuardConfig = external_crate::Something;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        ] {
            let sources = [
                source_at(
                    "crates/config/src/types.rs",
                    "struct GuardConfig { enabled: bool }",
                ),
                source_at("crates/runtime/src/lib.rs", runtime),
            ];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert_eq!(
                errors.len(),
                1,
                "an external import or alias must fail closed: {errors:?}"
            );
            assert_eq!(errors[0].subject, "proxy.guard.enabled");
        }
    }

    #[test]
    fn unresolved_qualified_external_function_cannot_collapse_to_a_local_namesake() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn make_guard() -> GuardConfig { todo!() }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime() { consume(external_crate::make_guard().enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "an unresolved qualified function must fail closed: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn imported_external_function_cannot_collapse_to_a_unique_local_namesake() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for runtime in [
            "use external_crate::make_guard;\n\
             fn runtime() { consume(make_guard().enabled); }",
            "use external_crate::something as make_guard;\n\
             fn runtime() { consume(make_guard().enabled); }",
        ] {
            let sources = [
                source_at(
                    "crates/config/src/lib.rs",
                    "struct GuardConfig { enabled: bool }\n\
                     fn make_guard() -> GuardConfig { todo!() }",
                ),
                source_at("crates/runtime/src/lib.rs", runtime),
            ];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert_eq!(
                errors.len(),
                1,
                "an unresolved imported function must fail closed: {errors:?}"
            );
            assert_eq!(errors[0].subject, "proxy.guard.enabled");
        }
    }

    #[test]
    fn external_glob_import_cannot_collapse_to_a_unique_local_type_namesake() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use external_crate::*;\n\
                 fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "an unresolved external glob must make type provenance fail closed: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn external_glob_import_cannot_collapse_to_a_unique_local_function_namesake() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn make_guard() -> GuardConfig { todo!() }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use external_crate::*;\n\
                 fn runtime() { consume(make_guard().enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "an unresolved external glob must make function provenance fail closed: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn external_glob_reexported_by_local_facade_taints_type_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "mod facade { pub use external_crate::*; }\n\
                 use facade::*;\n\
                 fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "a local facade must propagate unresolved external glob taint: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn external_glob_reexported_by_local_facade_taints_function_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn make_guard() -> GuardConfig { todo!() }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "mod facade { pub use external_crate::*; }\n\
                 use facade::*;\n\
                 fn runtime() { consume(make_guard().enabled); }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "a local facade must taint an unresolved external function glob: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn parent_external_glob_inherited_with_super_taints_type_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use external_crate::*;\n\
                 mod child {\n\
                     use super::*;\n\
                     fn runtime(v: &GuardConfig) { consume(v.enabled); }\n\
                 }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "a child `use super::*` must inherit unresolved glob taint: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn parent_external_glob_inherited_with_super_taints_function_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn make_guard() -> GuardConfig { todo!() }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use external_crate::*;\n\
                 mod child {\n\
                     use super::*;\n\
                     fn runtime() { consume(make_guard().enabled); }\n\
                 }",
            ),
        ];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors.len(),
            1,
            "a child `use super::*` must inherit unresolved function glob taint: {errors:?}"
        );
        assert_eq!(errors[0].subject, "proxy.guard.enabled");
    }

    #[test]
    fn qualified_external_aliases_cannot_impersonate_the_config_type_prefix() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for runtime in [
            "use external_crate as sbproxy_config;\n\
             fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }",
            "use external_crate::types as sbproxy_config;\n\
             fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }",
            "extern crate external_crate as sbproxy_config;\n\
             fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }",
            "mod sbproxy_config {\n\
                 pub use external_crate::GuardConfig;\n\
             }\n\
             fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }",
        ] {
            let sources = [
                source_at(
                    "crates/sbproxy-config/src/lib.rs",
                    "struct GuardConfig { enabled: bool }",
                ),
                source_at("crates/runtime/src/lib.rs", runtime),
            ];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert_eq!(
                errors.len(),
                1,
                "a lexical external alias must override crate-name spelling: {runtime}\n{errors:?}"
            );
            assert_eq!(errors[0].subject, "proxy.guard.enabled");
        }
    }

    #[test]
    fn qualified_external_aliases_cannot_impersonate_the_config_function_prefix() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for runtime in [
            "use external_crate as sbproxy_config;\n\
             fn runtime() { consume(sbproxy_config::make_guard().enabled); }",
            "use external_crate::factory as sbproxy_config;\n\
             fn runtime() { consume(sbproxy_config::make_guard().enabled); }",
            "extern crate external_crate as sbproxy_config;\n\
             fn runtime() { consume(sbproxy_config::make_guard().enabled); }",
            "mod sbproxy_config {\n\
                 pub use external_crate::make_guard;\n\
             }\n\
             fn runtime() { consume(sbproxy_config::make_guard().enabled); }",
        ] {
            let sources = [
                source_at(
                    "crates/sbproxy-config/src/lib.rs",
                    "struct GuardConfig { enabled: bool }\n\
                     fn make_guard() -> GuardConfig { todo!() }",
                ),
                source_at("crates/runtime/src/lib.rs", runtime),
            ];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert_eq!(
                errors.len(),
                1,
                "a lexical external alias must override function crate spelling: \
                 {runtime}\n{errors:?}"
            );
            assert_eq!(errors[0].subject, "proxy.guard.enabled");
        }
    }

    #[test]
    fn legitimate_local_qualified_aliases_preserve_type_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for source_text in [
            "struct GuardConfig { enabled: bool }\n\
             use crate as config_alias;\n\
             fn runtime(v: &config_alias::GuardConfig) { consume(v.enabled); }",
            "mod types { struct GuardConfig { enabled: bool } }\n\
             use crate::types as config_alias;\n\
             fn runtime(v: &config_alias::GuardConfig) { consume(v.enabled); }",
        ] {
            let sources = [source_at("crates/config/src/lib.rs", source_text)];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert!(
                errors.is_empty(),
                "a local crate or module alias must retain type provenance: {errors:?}"
            );
        }
    }

    #[test]
    fn legitimate_local_qualified_aliases_preserve_function_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for source_text in [
            "struct GuardConfig { enabled: bool }\n\
             fn make_guard() -> GuardConfig { todo!() }\n\
             use crate as config_alias;\n\
             fn runtime() { consume(config_alias::make_guard().enabled); }",
            "struct GuardConfig { enabled: bool }\n\
             mod factory {\n\
                 fn make_guard() -> crate::GuardConfig { todo!() }\n\
             }\n\
             use crate::factory as config_alias;\n\
             fn runtime() { consume(config_alias::make_guard().enabled); }",
        ] {
            let sources = [source_at("crates/config/src/lib.rs", source_text)];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert!(
                errors.is_empty(),
                "a local crate or module alias must retain function provenance: {errors:?}"
            );
        }
    }

    #[test]
    fn legitimate_local_glob_facade_preserves_type_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [source_at(
            "crates/config/src/lib.rs",
            "mod types { struct GuardConfig { enabled: bool } }\n\
             mod facade { pub use crate::types::*; }\n\
             use facade::*;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors.is_empty(),
            "a local glob facade must retain type provenance: {errors:?}"
        );
    }

    #[test]
    fn legitimate_local_glob_facade_preserves_function_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [source_at(
            "crates/config/src/lib.rs",
            "struct GuardConfig { enabled: bool }\n\
             mod factory {\n\
                 fn make_guard() -> crate::GuardConfig { todo!() }\n\
             }\n\
             mod facade { pub use crate::factory::*; }\n\
             use facade::*;\n\
             fn runtime() { consume(make_guard().enabled); }",
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors.is_empty(),
            "a local glob facade must retain function provenance: {errors:?}"
        );
    }

    #[test]
    fn transitive_named_and_two_hop_external_reexports_fail_closed() {
        let config = || {
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
             fn make_guard() -> GuardConfig { todo!() }",
            )
        };
        for runtime in [
            "mod facade { pub use external_crate::GuardConfig; }\n\
             use facade::*;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "mod facade { pub use external_crate::make_guard; }\n\
             use facade::*;\n\
             fn runtime() { consume(make_guard().enabled); }",
            "use external_crate::GuardConfig;\n\
             mod child {\n\
                 use super::*;\n\
                 fn runtime(v: &GuardConfig) { consume(v.enabled); }\n\
             }",
            "use external_crate::make_guard;\n\
             mod child {\n\
                 use super::*;\n\
                 fn runtime() { consume(make_guard().enabled); }\n\
             }",
            "mod first { pub use external_crate::*; }\n\
             mod second { pub use crate::first::*; }\n\
             use second::*;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "mod first { pub use external_crate::*; }\n\
             mod second { pub use crate::first::*; }\n\
             use second::*;\n\
             fn runtime() { consume(make_guard().enabled); }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert_eq!(
                errors.len(),
                1,
                "transitive external provenance must fail closed: {runtime}\n{errors:?}"
            );
        }
    }

    #[test]
    fn lexical_module_collisions_override_extern_crate_spelling() {
        let config = || {
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
             fn make_guard() -> GuardConfig { todo!() }",
            )
        };
        for runtime in [
            "mod sbproxy_config { pub struct GuardConfig { pub enabled: bool } }\n\
             fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }",
            "mod outer {\n\
                 mod sbproxy_config { pub struct GuardConfig { pub enabled: bool } }\n\
                 fn runtime(v: &sbproxy_config::GuardConfig) { consume(v.enabled); }\n\
             }",
            "mod sbproxy_config {\n\
                 pub struct GuardConfig { pub enabled: bool }\n\
                 pub fn make_guard() -> GuardConfig { todo!() }\n\
             }\n\
             fn runtime() { consume(sbproxy_config::make_guard().enabled); }",
            "mod outer {\n\
                 mod sbproxy_config {\n\
                     pub struct GuardConfig { pub enabled: bool }\n\
                     pub fn make_guard() -> GuardConfig { todo!() }\n\
                 }\n\
                 fn runtime() { consume(sbproxy_config::make_guard().enabled); }\n\
             }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert_eq!(
                errors.len(),
                1,
                "a lexical module must shadow extern-prelude spelling: {runtime}\n{errors:?}"
            );
        }
    }

    #[test]
    fn local_module_paths_and_exact_globs_preserve_provenance() {
        for sources in [
            vec![source_at(
                "crates/config/src/lib.rs",
                "mod types { pub struct GuardConfig { pub enabled: bool } }\n\
                 fn runtime(v: &types::GuardConfig) { consume(v.enabled); }",
            )],
            vec![
                source_at(
                    "crates/sbproxy-config/src/types.rs",
                    "pub struct GuardConfig { pub enabled: bool }",
                ),
                source_at(
                    "crates/runtime/src/lib.rs",
                    "mod unrelated { struct GuardConfig { enabled: bool } }\n\
                     use sbproxy_config::types::*;\n\
                     fn runtime(v: &GuardConfig) { consume(v.enabled); }",
                ),
            ],
            vec![
                source_at(
                    "crates/sbproxy-config/src/lib.rs",
                    "struct GuardConfig { enabled: bool }\n\
                     fn make_guard() -> GuardConfig { todo!() }",
                ),
                source_at(
                    "crates/runtime/src/lib.rs",
                    "use sbproxy_config::*;\n\
                     fn runtime(v: &GuardConfig) { consume(v.enabled); }\n\
                     fn runtime_fn() { consume(make_guard().enabled); }",
                ),
            ],
            vec![source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
                 fn make_guard() -> GuardConfig { todo!() }\n\
                 mod child {\n\
                     use super::*;\n\
                     fn runtime(v: &GuardConfig) { consume(v.enabled); }\n\
                     fn runtime_fn() { consume(make_guard().enabled); }\n\
                 }",
            )],
        ] {
            let errors = guard_errors(&sources);
            assert!(
                errors.is_empty(),
                "exact local/glob provenance must remain usable: {errors:?}"
            );
        }
    }

    #[test]
    fn macro_generated_names_do_not_use_global_unique_fallbacks() {
        let config = || {
            source_at(
                "crates/config/src/lib.rs",
                "struct GuardConfig { enabled: bool }\n\
             fn make_guard() -> GuardConfig { todo!() }",
            )
        };
        for runtime in [
            "macro_rules! define_guard {\n\
                 () => { struct GuardConfig { enabled: bool } };\n\
             }\n\
             define_guard!();\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "macro_rules! define_guard {\n\
                 () => {\n\
                     struct GuardConfig { enabled: bool }\n\
                     fn make_guard() -> GuardConfig { todo!() }\n\
                 };\n\
             }\n\
             define_guard!();\n\
             fn runtime() { consume(make_guard().enabled); }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert_eq!(
                errors.len(),
                1,
                "unexpanded macro names must not fall back globally: {runtime}\n{errors:?}"
            );
        }
    }

    #[test]
    fn module_aliases_resolve_their_exact_lexical_targets() {
        let config = || {
            source_at(
                "crates/sbproxy-config/src/types.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            )
        };
        for runtime in [
            "use sbproxy_config::types;\n\
             fn runtime(v: &types::GuardConfig) { consume(v.enabled); }",
            "use sbproxy_config::types as cfg;\n\
             fn runtime(v: &cfg::GuardConfig) { consume(v.enabled); }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert!(
                errors.is_empty(),
                "a config module alias must preserve provenance: {runtime}\n{errors:?}"
            );
        }

        for runtime in [
            "use external_crate::types;\n\
             fn runtime(v: &types::GuardConfig) { consume(v.enabled); }",
            "use external_crate::types as cfg;\n\
             fn runtime(v: &cfg::GuardConfig) { consume(v.enabled); }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert_eq!(
                errors.len(),
                1,
                "an external module alias must fail closed: {runtime}\n{errors:?}"
            );
        }
    }

    #[test]
    fn leading_colon_selects_the_extern_root_before_lexical_modules() {
        let config = || {
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            )
        };
        let local_module = "mod sbproxy_config { pub struct GuardConfig { pub enabled: bool } }\n";

        let bare = guard_errors(&[
            config(),
            source_at(
                "crates/runtime/src/lib.rs",
                &format!(
                    "{local_module}\
                     fn runtime(v: &sbproxy_config::GuardConfig) {{ consume(v.enabled); }}"
                ),
            ),
        ]);
        assert_eq!(
            bare.len(),
            1,
            "a bare prefix must select the lexical module: {bare:?}"
        );

        let absolute = guard_errors(&[
            config(),
            source_at(
                "crates/runtime/src/lib.rs",
                &format!(
                    "{local_module}\
                     fn runtime(v: &::sbproxy_config::GuardConfig) {{ consume(v.enabled); }}"
                ),
            ),
        ]);
        assert!(
            absolute.is_empty(),
            "a leading colon must select the extern root: {absolute:?}"
        );
    }

    #[test]
    fn exact_external_root_binding_wins_over_local_namesake() {
        let errors = guard_errors(&[source_at(
            "crates/config/src/lib.rs",
            "mod types { pub struct GuardConfig { pub enabled: bool } }\n\
             pub use external_crate::GuardConfig;\n\
             fn runtime(v: &crate::GuardConfig) { consume(v.enabled); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an exact external root re-export must fail closed: {errors:?}"
        );
    }

    #[test]
    fn block_local_imports_are_resolved_without_leaking_between_functions() {
        let config = || {
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub mod types { pub struct GuardConfig { pub enabled: bool } }\n\
                 pub fn make_guard() -> types::GuardConfig { todo!() }",
            )
        };
        for runtime in [
            "fn runtime() {\n\
                 use sbproxy_config::types::GuardConfig;\n\
                 let value: &GuardConfig = todo!();\n\
                 consume(value.enabled);\n\
             }",
            "fn runtime() {\n\
                 use sbproxy_config::types::*;\n\
                 let value: &GuardConfig = todo!();\n\
                 consume(value.enabled);\n\
             }",
            "fn runtime() {\n\
                 use sbproxy_config::make_guard;\n\
                 consume(make_guard().enabled);\n\
             }",
        ] {
            let errors = guard_errors(&[config(), source_at("crates/runtime/src/lib.rs", runtime)]);
            assert!(
                errors.is_empty(),
                "a block-local config import must retain provenance: {runtime}\n{errors:?}"
            );
        }

        let errors = guard_errors(&[
            config(),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn unrelated() { use sbproxy_config::types::GuardConfig; }\n\
                 macro_rules! define_guard {\n\
                     () => { struct GuardConfig { enabled: bool } };\n\
                 }\n\
                 define_guard!();\n\
                 fn runtime(value: &GuardConfig) { consume(value.enabled); }",
            ),
        ]);
        assert_eq!(
            errors.len(),
            1,
            "an import in another function must not tag a macro-generated namesake: {errors:?}"
        );
    }

    #[test]
    fn same_block_alias_chains_preserve_config_provenance() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime() {\n\
                     use sbproxy_config as cfg;\n\
                     use cfg::GuardConfig;\n\
                     let value: &GuardConfig = todo!();\n\
                     consume(value.enabled);\n\
                 }",
            ),
        ]);

        assert!(
            errors.is_empty(),
            "a block import target may resolve through a same-block alias: {errors:?}"
        );
    }

    #[test]
    fn nested_block_alias_chains_preserve_config_provenance() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime() {\n\
                     use sbproxy_config as cfg;\n\
                     {\n\
                         use cfg::GuardConfig;\n\
                         let value: &GuardConfig = todo!();\n\
                         consume(value.enabled);\n\
                     }\n\
                 }",
            ),
        ]);

        assert!(
            errors.is_empty(),
            "an inner import target may resolve through an enclosing alias: {errors:?}"
        );
    }

    #[test]
    fn nested_functions_inherit_enclosing_block_imports() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn outer() {\n\
                     use sbproxy_config::GuardConfig;\n\
                     fn nested(value: &GuardConfig) {\n\
                         consume(value.enabled);\n\
                     }\n\
                 }",
            ),
        ]);

        assert!(
            errors.is_empty(),
            "a nested function item sees imports from its enclosing block: {errors:?}"
        );
    }

    #[test]
    fn block_alias_targets_respect_hoisted_local_declarations() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use sbproxy_config::GuardConfig as Alias;\n\
                 fn runtime() {\n\
                     type GuardConfig = Alias;\n\
                     struct Alias { enabled: bool }\n\
                     let value: &GuardConfig = todo!();\n\
                     consume(value.enabled);\n\
                 }",
            ),
        ]);

        assert_eq!(
            errors.len(),
            1,
            "a hoisted local declaration shadows a module alias used by a local type: {errors:?}"
        );
    }

    #[test]
    fn inner_named_import_shadows_outer_external_binding_for_the_whole_block() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/types.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime() {\n\
                     use external_crate::GuardConfig;\n\
                     {\n\
                         let value: &GuardConfig = todo!();\n\
                         consume(value.enabled);\n\
                         use sbproxy_config::types::GuardConfig;\n\
                     }\n\
                 }",
            ),
        ]);

        assert!(
            errors.is_empty(),
            "the inner named import is hoisted and shadows the outer binding: {errors:?}"
        );
    }

    #[test]
    fn inner_external_glob_shadows_an_outer_config_binding() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/types.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn runtime() {\n\
                     use sbproxy_config::types::GuardConfig;\n\
                     {\n\
                         use external_crate::*;\n\
                         let value: &GuardConfig = todo!();\n\
                         consume(value.enabled);\n\
                     }\n\
                 }",
            ),
        ]);

        assert_eq!(
            errors.len(),
            1,
            "an inner unresolved glob must shadow outer provenance: {errors:?}"
        );
    }

    #[test]
    fn later_block_items_shadow_outer_config_bindings_for_the_whole_block() {
        for shadow in [
            "use external_crate::GuardConfig;",
            "type GuardConfig = external_crate::GuardConfig;",
            "struct GuardConfig { enabled: bool }",
        ] {
            let errors = guard_errors(&[
                source_at(
                    "crates/sbproxy-config/src/types.rs",
                    "pub struct GuardConfig { pub enabled: bool }",
                ),
                source_at(
                    "crates/runtime/src/lib.rs",
                    &format!(
                        "use sbproxy_config::types::GuardConfig;\n\
                         fn runtime() {{\n\
                             let value: &GuardConfig = todo!();\n\
                             consume(value.enabled);\n\
                             {shadow}\n\
                         }}"
                    ),
                ),
            ]);

            assert_eq!(
                errors.len(),
                1,
                "a hoisted block item must shadow the outer binding: {shadow}\n{errors:?}"
            );
        }
    }

    #[test]
    fn recursive_local_glob_cycles_preserve_exact_results_and_external_taint() {
        let local = guard_errors(&[source_at(
            "crates/config/src/lib.rs",
            "mod types { pub struct GuardConfig { pub enabled: bool } }\n\
             mod first { pub use crate::second::*; }\n\
             mod second {\n\
                 pub use crate::first::*;\n\
                 pub use crate::types::*;\n\
             }\n\
             use first::*;\n\
             fn runtime(value: &GuardConfig) { consume(value.enabled); }",
        )]);
        assert!(
            local.is_empty(),
            "a cyclic local facade may still export one exact owner: {local:?}"
        );

        let external = guard_errors(&[
            source_at(
                "crates/config/src/types.rs",
                "struct GuardConfig { enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "mod first { pub use crate::second::*; }\n\
                 mod second {\n\
                     pub use crate::first::*;\n\
                     pub use external_crate::*;\n\
                 }\n\
                 use first::*;\n\
                 fn runtime(value: &GuardConfig) { consume(value.enabled); }",
            ),
        ]);
        assert_eq!(
            external.len(),
            1,
            "a cyclic facade must retain unresolved external taint: {external:?}"
        );
    }

    #[test]
    fn sibling_root_reimports_do_not_taint_an_exact_local_reexport() {
        let errors = guard_errors(&[source_at(
            "crates/config/src/lib.rs",
            "mod types { pub struct GuardConfig { pub enabled: bool } }\n\
             pub use types::*;\n\
             mod sibling {\n\
                 use crate::GuardConfig;\n\
                 pub fn inspect(value: &GuardConfig) { consume(value.enabled); }\n\
             }\n\
             pub use sibling::*;",
        )]);

        assert!(
            errors.is_empty(),
            "a sibling's import of a root re-export is a cycle, not external taint: {errors:?}"
        );
    }

    #[test]
    fn same_crate_root_reexport_preserves_type_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        let sources = [source_at(
            "crates/config/src/lib.rs",
            "mod types { struct GuardConfig { enabled: bool } }\n\
             pub use types::*;\n\
             use crate::GuardConfig;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors.is_empty(),
            "a same-crate root re-export must retain exact provenance: {errors:?}"
        );
    }

    #[test]
    fn legitimate_local_imports_and_aliases_preserve_provenance() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for reader in [
            "use crate::types::GuardConfig;\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
            "type LocalGuard = crate::types::GuardConfig;\n\
             fn runtime(v: &LocalGuard) { consume(v.enabled); }",
            "use crate::factory::make_guard;\n\
             fn runtime() { consume(make_guard().enabled); }",
        ] {
            let sources = [source_at(
                "crates/config/src/lib.rs",
                &format!(
                    "mod types {{ struct GuardConfig {{ enabled: bool }} }}\n\
                     mod factory {{\n\
                         fn make_guard() -> crate::types::GuardConfig {{ todo!() }}\n\
                     }}\n\
                     {reader}"
                ),
            )];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert!(
                errors.is_empty(),
                "a local import or alias must retain exact provenance: {errors:?}"
            );
        }
    }

    #[test]
    fn undeclared_external_receiver_cannot_cover_a_schema_leaf_by_last_token() {
        let schema = serde_json::json!({
            "title": "ConfigFile",
            "type": "object",
            "properties": {
                "proxy": {"$ref": "#/definitions/ProxyConfig"}
            },
            "definitions": {
                "ProxyConfig": {
                    "type": "object",
                    "properties": {
                        "new_guard": {"$ref": "#/definitions/NewGuardConfig"}
                    }
                },
                "NewGuardConfig": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"}
                    }
                }
            }
        });
        let keys = schema_key_paths(&schema);
        let sources = [source(
            r#"
struct NewGuardConfig {
    enabled: bool,
}

fn production(external: &ExternalFeature) {
    consume(external.enabled);
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors
                .iter()
                .any(|error| error.subject == "proxy.new_guard.enabled"),
            "a global `.enabled` token must not prove NewGuardConfig::enabled: {errors:?}"
        );
    }

    #[test]
    fn typed_owner_read_covers_the_matching_ambiguous_field() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn production(config: &Config) {
    consume(config.live);
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(
            errors,
            vec![],
            "an explicitly typed Config::live read is exact evidence"
        );
    }

    #[test]
    fn typed_nested_field_chain_covers_each_exact_owner() {
        let schema = serde_json::json!({
            "title": "Config",
            "type": "object",
            "properties": {
                "nested": {"$ref": "#/definitions/Nested"}
            },
            "definitions": {
                "Nested": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "boolean"}
                    }
                }
            }
        });
        let keys = schema_key_paths(&schema);
        let sources = [source(
            r#"
struct Config {
    nested: Nested,
}

struct Nested {
    value: bool,
}

struct Unrelated {
    value: bool,
}

fn production(config: &Config) {
    consume(config.nested.value);
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn typed_match_binding_covers_the_matched_owner() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn production(config: Option<&Config>) {
    match config {
        Some(config) => consume(config.live),
        None => {}
    }
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn if_let_structural_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 if let Some(cfg) = Some(v) {\n\
                     consume(cfg.enabled);\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an if-let binding must retain structural initializer provenance: {errors:?}"
        );
    }

    #[test]
    fn if_let_discarded_fields_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 if let Some(_) = Some(v.enabled) {}\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an if-let wildcard must discard its paired field expression: {errors:?}"
        );
    }

    #[test]
    fn match_structural_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 match Some(v) {\n\
                     Some(cfg) => consume(cfg.enabled),\n\
                     None => {}\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a match binding must retain structural scrutinee provenance: {errors:?}"
        );
    }

    #[test]
    fn match_fallback_bindings_ignore_catch_all_arm_pairing() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: Option<&GuardConfig>) {\n\
                 match v {\n\
                     Some(cfg) if cfg.enabled => {},\n\
                     _ => {}\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a catch-all arm cannot suppress whole-scrutinee type inference: {errors:?}"
        );
    }

    #[test]
    fn match_discarded_fields_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 match Some(v.enabled) {\n\
                     Some(_) => {},\n\
                     None => {}\n\
                 }\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a match wildcard must discard its paired field expression: {errors:?}"
        );
    }

    #[test]
    fn match_catch_all_does_not_read_a_field_scrutinee() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 match v.enabled { _ => {} }\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a catch-all pattern must not turn its field scrutinee into reader evidence: \
             {errors:?}"
        );
    }

    #[test]
    fn match_value_patterns_read_a_field_scrutinee() {
        let errors = guard_errors(&[source(
            "enum Decision { Enabled, Disabled }\n\
             struct GuardConfig { enabled: Decision }\n\
             fn inspect(v: &GuardConfig) {\n\
                 match v.enabled {\n\
                     Decision::Enabled => {},\n\
                     Decision::Disabled => {},\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "value-discriminating patterns must read their field scrutinee: {errors:?}"
        );
    }

    #[test]
    fn match_named_bindings_read_a_field_scrutinee() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 match v.enabled { observed => consume(observed) }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a named binding must read its field scrutinee: {errors:?}"
        );
    }

    #[test]
    fn match_unused_named_bindings_still_read_a_field_scrutinee() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) {\n\
                 match v.enabled { _observed => {} }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an underscore-prefixed name remains a binding that moves its field scrutinee: \
             {errors:?}"
        );
    }

    #[test]
    fn or_pattern_discards_each_structurally_matched_field() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 match Some(v.enabled) {\n\
                     Some(_) | None => {}\n\
                 }\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an or-pattern must preserve the discard semantics of its matching alternative: \
             {errors:?}"
        );
    }

    #[test]
    fn or_pattern_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "enum Either<T> { A(T), B(T) }\n\
             struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 match Either::A(v) {\n\
                     Either::A(cfg) | Either::B(cfg) => consume(cfg.enabled),\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a binding shared by or-pattern alternatives must retain config provenance: \
            {errors:?}"
        );
    }

    #[test]
    fn generic_enum_variable_patterns_preserve_payload_provenance() {
        let errors = guard_errors(&[source(
            "enum Either<T> { A(T), B(T) }\n\
             struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(value: Either<&GuardConfig>) {\n\
                 match value {\n\
                     Either::A(cfg) | Either::B(cfg) => consume(cfg.enabled),\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a generic enum variable must project its payload owner into variant bindings: \
             {errors:?}"
        );
    }

    #[test]
    fn generic_tuple_struct_variable_patterns_preserve_payload_provenance() {
        let errors = guard_errors(&[source(
            "struct Wrap<T>(T);\n\
             struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(value: Wrap<&GuardConfig>) {\n\
                 let Wrap(cfg) = value;\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a generic tuple-struct variable must project its field owner into bindings: \
             {errors:?}"
        );
    }

    #[test]
    fn separate_structural_match_arms_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "enum Either<T> { A(T), B(T) }\n\
             struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 match Either::A(v) {\n\
                     Either::A(cfg) => consume(cfg.enabled),\n\
                     Either::B(_) => {}\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "separate structural arms remain a control for or-pattern traversal: {errors:?}"
        );
    }

    #[test]
    fn test_attributed_match_arms_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(value: &GuardConfig, selected: bool) {\n\
                 match selected {\n\
                     #[cfg(test)]\n\
                     true => consume(value.enabled),\n\
                     false => {}\n\
                 }\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a test-only match arm must not prove a production reader: {errors:?}"
        );
    }

    #[test]
    fn conditionally_production_match_arms_remain_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(value: &GuardConfig, selected: bool) {\n\
                 match selected {\n\
                     #[cfg(any(test, feature = \"fixtures\"))]\n\
                     true => consume(value.enabled),\n\
                     false => {}\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an arm reachable in a production feature remains evidence: {errors:?}"
        );
    }

    #[test]
    fn matched_serde_enum_variant_covers_its_exact_tag_leaf() {
        let keys = [ConfigSchemaKey {
            path: "proxy.backend.type".to_string(),
            rust_field: "type".to_string(),
            rust_owner: Some("BackendConfig".to_string()),
        }];
        let sources = [source(
            r#"
#[serde(tag = "type", rename_all = "snake_case")]
enum BackendConfig {
    Memory,
    File { path: String },
}

fn build(config: &BackendConfig) {
    match config {
        BackendConfig::Memory => {}
        BackendConfig::File { path } => consume(path),
    }
}
"#,
        )];

        assert_eq!(
            verify_config_readers(&keys, &[], &sources),
            vec![],
            "matching a tagged enum proves the exact serde discriminator is consumed"
        );
    }

    #[test]
    fn unrelated_tagged_enum_match_does_not_cover_the_same_tag_name() {
        let keys = [ConfigSchemaKey {
            path: "proxy.backend.type".to_string(),
            rust_field: "type".to_string(),
            rust_owner: Some("BackendConfig".to_string()),
        }];
        let sources = [source(
            r#"
#[serde(tag = "type")]
enum BackendConfig {
    Memory,
}

#[serde(tag = "type")]
enum UnrelatedBackend {
    Memory,
}

fn build(config: &UnrelatedBackend) {
    match config {
        UnrelatedBackend::Memory => {}
    }
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert!(
            errors
                .iter()
                .any(|error| error.subject == "proxy.backend.type"),
            "a match on another enum's `type` tag is not reader evidence: {errors:?}"
        );
    }

    #[test]
    fn typed_struct_pattern_is_reader_evidence() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn production(config: &Config) {
    let Config { live } = config;
    consume(live);
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn typed_iterator_closure_covers_the_item_owner() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn production(configs: &[Config]) {
    configs
        .iter()
        .for_each(|config| consume(config.live));
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn array_literal_iteration_preserves_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 for cfg in [v] {\n\
                     consume(cfg.enabled);\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an array literal's item owner must reach its for-loop binding: {errors:?}"
        );
    }

    #[test]
    fn array_literal_into_iter_closure_preserves_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 [v].into_iter().for_each(|cfg| consume(cfg.enabled));\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an array literal's item owner must reach an iterator closure: {errors:?}"
        );
    }

    #[test]
    fn tuple_wrapped_array_iteration_preserves_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 for (cfg,) in [(v,)] {\n\
                     consume(cfg.enabled);\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "tuple structure inside an array must reach its for-loop pattern: {errors:?}"
        );
    }

    #[test]
    fn tuple_wrapped_repeat_iteration_preserves_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 for (cfg,) in [(v,); 2] {\n\
                     consume(cfg.enabled);\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "tuple structure inside a repeated array must reach its for-loop pattern: \
             {errors:?}"
        );
    }

    #[test]
    fn tuple_wrapped_array_closures_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 [(v,)].into_iter().for_each(|(cfg,)| consume(cfg.enabled));\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "tuple structure inside an array must reach iterator closure patterns: {errors:?}"
        );
    }

    #[test]
    fn vec_iteration_continues_to_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(values: Vec<&GuardConfig>) {\n\
                 for cfg in values {\n\
                     consume(cfg.enabled);\n\
                 }\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a typed Vec remains the collection-provenance control: {errors:?}"
        );
    }

    #[test]
    fn typed_chained_iterator_covers_the_item_owner() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn production(left: &[Config], right: &[Config]) {
    for config in left.iter().chain(right.iter()) {
        consume(config.live);
    }
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn typed_free_function_return_covers_the_returned_owner() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn current_config() -> Config {
    todo!()
}

fn production() {
    consume(current_config().live);
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn tuple_function_return_destructuring_preserves_the_selected_owner() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

fn fold(config: Config) -> Result<(String, Config, bool), ()> {
    Ok((String::new(), config, false))
}

fn production(config: Config) -> Result<(), ()> {
    let (_, config, _) = fold(config)?;
    consume(config.live);
    Ok(())
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn tuple_function_return_destructuring_does_not_cross_contaminate_slots() {
        let keys = [key("proxy.live", "live")];
        let sources = [source(
            r#"
struct Config {
    live: bool,
}

struct Unrelated {
    live: bool,
}

fn fold(config: Config) -> (Config, Unrelated) {
    todo!()
}

fn production(config: Config) {
    let (_, unrelated) = fold(config);
    consume(unrelated.live);
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources).len(), 1);
    }

    #[test]
    fn custom_result_types_do_not_inherit_standard_result_provenance() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }\n\
                 pub struct Other { pub enabled: bool }\n\
                 pub struct Result<A, B>(pub A, pub B);\n\
                 pub fn fold(c: GuardConfig, o: Other) -> Result<GuardConfig, Other> {\n\
                     Result(c, o)\n\
                 }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn consume<T>(_: T) {}\n\
                 fn run(c: sbproxy_config::GuardConfig, o: sbproxy_config::Other) {\n\
                     let sbproxy_config::Result(_, other) = sbproxy_config::fold(c, o);\n\
                     consume(other.enabled);\n\
                 }",
            ),
        ]);

        assert_eq!(
            errors.len(),
            1,
            "a custom type named Result must retain its own tuple slots: {errors:?}"
        );
    }

    #[test]
    fn imported_external_custom_result_is_not_a_transparent_wrapper() {
        let errors = verify_config_readers(
            &[key("proxy.live", "live")],
            &[],
            &[source(
                "use opaque::Result;\n\
                 struct Config { live: bool }\n\
                 struct Other { live: bool }\n\
                 fn fold(c: Config, o: Other) -> Result<Config, Other> { todo!() }\n\
                 fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            )],
        );

        assert_eq!(
            errors.len(),
            1,
            "an imported external custom Result must not expose its first generic owner: \
            {errors:?}"
        );
    }

    #[test]
    fn qualified_wrapper_names_cannot_be_spoofed_by_lexical_modules_or_aliases() {
        for text in [
            "mod anyhow {\n\
                 pub struct Result<T, E> { pub first: T, pub second: E, pub live: bool }\n\
             }\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config, o: Other) -> anyhow::Result<Config, Other> {\n\
                 anyhow::Result { first: c, second: o, live: false }\n\
             }\n\
             fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            "use opaque as anyhow;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config, o: Other) -> anyhow::Result<Config, Other> { todo!() }\n\
             fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            "mod hashbrown {\n\
                 pub struct HashMap<K, V> { pub key: K, pub value: V, pub live: bool }\n\
             }\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config, o: Other) -> hashbrown::HashMap<Other, Config> {\n\
                 hashbrown::HashMap { key: o, value: c, live: false }\n\
             }\n\
             fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            "mod std {\n\
                 pub mod result {\n\
                     pub struct Result<T, E> { pub first: T, pub second: E, pub live: bool }\n\
                 }\n\
             }\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config, o: Other) -> std::result::Result<Config, Other> {\n\
                 std::result::Result { first: c, second: o, live: false }\n\
             }\n\
             fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            "mod std {\n\
                 pub mod boxed {\n\
                     pub struct Box<T> { pub inner: T, pub live: bool }\n\
                 }\n\
             }\n\
             struct Config { live: bool }\n\
             fn fold(c: Config) -> std::boxed::Box<Config> {\n\
                 std::boxed::Box { inner: c, live: false }\n\
             }\n\
             fn run(c: Config) { consume(fold(c).live); }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert_eq!(
                errors.len(),
                1,
                "a lexical module or alias must override a trusted wrapper spelling: \
                 {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn macro_generated_bare_wrapper_names_fail_closed() {
        for text in [
            "macro_rules! define_result {\n\
                 () => {\n\
                     struct Result<T, E> { first: T, second: E, live: bool }\n\
                 }\n\
             }\n\
             define_result!();\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config, o: Other) -> Result<Config, Other> {\n\
                 Result { first: c, second: o, live: false }\n\
             }\n\
             fn run(c: Config, o: Other) { consume(fold(c, o).live); }",
            "struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn run(c: Config, o: Other) {\n\
                 macro_rules! define_result {\n\
                     () => {\n\
                         struct Result<T, E> { first: T, second: E, live: bool }\n\
                     }\n\
                 }\n\
                 define_result!();\n\
                 fn fold(c: Config, o: Other) -> Result<Config, Other> {\n\
                     Result { first: c, second: o, live: false }\n\
                 }\n\
                 consume(fold(c, o).live);\n\
             }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert_eq!(
                errors.len(),
                1,
                "an unexpanded macro may define a custom bare wrapper and must fail closed: \
                 {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn renamed_and_aliased_standard_results_preserve_tuple_provenance() {
        for text in [
            "use std::result::Result as StdResult;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> StdResult<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> StdResult<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "type AppResult<T> = std::result::Result<T, ()>;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> AppResult<(Other, Config, bool)> { todo!() }\n\
             fn run(c: Config) -> AppResult<()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "use anyhow::Result as AnyResult;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> AnyResult<(Other, Config, bool)> { todo!() }\n\
             fn run(c: Config) -> AnyResult<()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert!(
                errors.is_empty(),
                "a renamed or aliased standard Result remains transparent: {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn module_scope_prelude_wrapper_aliases_preserve_provenance() {
        for text in [
            "use Result as Wrapped;\n\
             struct Config { live: bool }\n\
             fn fold(c: Config) -> Wrapped<Config, ()> { todo!() }\n\
             fn run(c: Config) -> Wrapped<(), ()> {\n\
                 consume(fold(c)?.live);\n\
                 Ok(())\n\
             }",
            "use Option as Wrapped;\n\
             struct Config { live: bool }\n\
             fn fold(c: Config) -> Wrapped<Config> { todo!() }\n\
             fn run(c: Config) { consume(fold(c).unwrap().live); }",
            "use Box as Wrapped;\n\
             struct Config { live: bool }\n\
             fn fold(c: Config) -> Wrapped<Config> { todo!() }\n\
             fn run(c: Config) { consume(fold(c).live); }",
            "use Vec as Wrapped;\n\
             struct Config { live: bool }\n\
             fn fold(c: Config) -> Wrapped<Config> { todo!() }\n\
             fn run(c: Config) { consume(fold(c).first().unwrap().live); }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert!(
                errors.is_empty(),
                "a module-scope alias of a prelude wrapper remains transparent: {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn wrapper_module_aliases_and_glob_reexports_preserve_provenance() {
        for text in [
            "use std::result::*;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> Result<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "mod facade { pub use std::result::Result; }\n\
             use facade::*;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> Result<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "use std::result as r;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> r::Result<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> r::Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "use std as s;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> s::result::Result<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> s::result::Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "mod facade { pub use std::result as r; }\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> facade::r::Result<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> facade::r::Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn run(c: Config) -> std::result::Result<(), ()> {\n\
                 use std::result::*;\n\
                 fn fold(c: Config) -> Result<(Other, Config, bool), ()> { todo!() }\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn run(c: Config) -> std::result::Result<(), ()> {\n\
                 use std as s;\n\
                 fn fold(c: Config) -> s::result::Result<(Other, Config, bool), ()> { todo!() }\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert!(
                errors.is_empty(),
                "wrapper module aliases and glob reexports remain transparent: {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn zero_generic_and_defaulted_result_aliases_preserve_tuple_provenance() {
        for text in [
            "type FoldResult = Result<(Other, Config, bool), ()>;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> FoldResult { todo!() }\n\
             fn run(c: Config) -> Result<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "type AppResult<T, E = ()> = Result<T, E>;\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> AppResult<(Other, Config, bool)> { todo!() }\n\
             fn run(c: Config) -> AppResult<()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert!(
                errors.is_empty(),
                "zero-generic and defaulted aliases remain transparent: {errors:?}\n{text}"
            );
        }
    }

    #[test]
    fn block_local_and_reexported_standard_result_aliases_preserve_provenance() {
        for text in [
            "struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn run(c: Config) -> std::result::Result<(), ()> {\n\
                 use std::result::Result as StdResult;\n\
                 fn fold(c: Config) -> StdResult<(Other, Config, bool), ()> { todo!() }\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn run(c: Config) -> std::result::Result<(), ()> {\n\
                 type AppResult<T> = std::result::Result<T, ()>;\n\
                 fn fold(c: Config) -> AppResult<(Other, Config, bool)> { todo!() }\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
            "mod facade { pub use std::result::Result as AppResult; }\n\
             struct Config { live: bool }\n\
             struct Other { live: bool }\n\
             fn fold(c: Config) -> facade::AppResult<(Other, Config, bool), ()> { todo!() }\n\
             fn run(c: Config) -> facade::AppResult<(), ()> {\n\
                 let (_, selected, ..) = fold(c)?;\n\
                 consume(selected.live);\n\
                 Ok(())\n\
             }",
        ] {
            let errors = verify_config_readers(&[key("proxy.live", "live")], &[], &[source(text)]);

            assert!(
                errors.is_empty(),
                "lexically resolved standard Result aliases remain transparent: {errors:?}\n\
                 {text}"
            );
        }
    }

    #[test]
    fn block_local_external_custom_result_import_fails_closed() {
        let errors = verify_config_readers(
            &[key("proxy.live", "live")],
            &[],
            &[source(
                "struct Config { live: bool }\n\
                 struct Other { live: bool }\n\
                 fn run(c: Config, o: Other) {\n\
                     use opaque::Result;\n\
                     fn fold(c: Config, o: Other) -> Result<Config, Other> { todo!() }\n\
                     consume(fold(c, o).live);\n\
                 }",
            )],
        );

        assert_eq!(
            errors.len(),
            1,
            "a block-local unresolved custom wrapper import must fail closed: {errors:?}"
        );
    }

    #[test]
    fn tuple_function_return_rest_patterns_preserve_aligned_slots() {
        for body in [
            "let (_, selected, ..) = fold(c);",
            "let (.., selected) = fold(c);",
            "let (_, .., selected) = fold(c);",
        ] {
            let signature = if body.starts_with("let (..") {
                "(bool, Other, Config)"
            } else if body.contains(".., selected") {
                "(Other, bool, Config)"
            } else {
                "(Other, Config, bool)"
            };
            let errors = verify_config_readers(
                &[key("proxy.live", "live")],
                &[],
                &[source(&format!(
                    "struct Config {{ live: bool }}\n\
                     struct Other {{ live: bool }}\n\
                     fn consume<T>(_: T) {{}}\n\
                     fn fold(c: Config) -> {signature} {{ todo!() }}\n\
                     fn run(c: Config) {{\n\
                         {body}\n\
                         consume(selected.live);\n\
                     }}"
                ))],
            );

            assert!(
                errors.is_empty(),
                "a tuple rest must preserve the selected slot for `{body}`: {errors:?}"
            );
        }
    }

    #[test]
    fn tuple_function_return_rest_patterns_do_not_cross_contaminate_slots() {
        let errors = verify_config_readers(
            &[key("proxy.live", "live")],
            &[],
            &[source(
                "struct Config { live: bool }\n\
                 struct Other { live: bool }\n\
                 fn consume<T>(_: T) {}\n\
                 fn fold(c: Config) -> (Config, bool, Other) { todo!() }\n\
                 fn run(c: Config) {\n\
                     let (.., selected) = fold(c);\n\
                     consume(selected.live);\n\
                 }",
            )],
        );

        assert_eq!(
            errors.len(),
            1,
            "a tuple rest must not assign a config owner to the wrong suffix slot: {errors:?}"
        );
    }

    #[test]
    fn serde_renamed_schema_field_maps_back_to_the_rust_field() {
        let keys = [key("proxy.poll_interval", "poll_interval")];
        let sources = [source(
            r#"
struct Config {
    #[serde(rename = "poll_interval")]
    poll_interval_secs: u64,
}

fn production(config: &Config) {
    consume(config.poll_interval_secs);
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn serde_renamed_schema_field_still_requires_a_value_read() {
        let keys = [key("proxy.poll_interval", "poll_interval")];
        let sources = [source(
            r#"
struct Config {
    #[serde(rename = "poll_interval")]
    poll_interval_secs: u64,
}

fn production(config: &mut Config) {
    config.poll_interval_secs = 30;
}
"#,
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources).len(), 1);
    }

    #[test]
    fn serde_rename_all_does_not_let_a_decoy_rust_field_cover_the_schema_field() {
        let errors = verify_config_readers(
            &[key("proxy.pollInterval", "pollInterval")],
            &[],
            &[source(
                "#[allow(non_snake_case)]\n\
                 #[serde(rename_all = \"camelCase\")]\n\
                 struct Config {\n\
                     poll_interval: bool,\n\
                     #[serde(rename = \"other\")]\n\
                     pollInterval: bool,\n\
                 }\n\
                 fn consume<T>(_: T) {}\n\
                 fn run(c: &Config) { consume(c.pollInterval); }",
            )],
        );

        assert_eq!(
            errors.len(),
            1,
            "rename_all must map the schema property to poll_interval, not its decoy: {errors:?}"
        );
    }

    #[test]
    fn production_cfg_attr_rename_does_not_let_a_decoy_cover_the_schema_field() {
        let errors = verify_config_readers(
            &[key("proxy.productionName", "productionName")],
            &[],
            &[source(
                "#[allow(non_snake_case)]\n\
                 struct Config {\n\
                     #[cfg_attr(not(test), serde(rename = \"productionName\"))]\n\
                     actual: bool,\n\
                     #[serde(rename = \"other\")]\n\
                     productionName: bool,\n\
                 }\n\
                 fn consume<T>(_: T) {}\n\
                 fn run(c: &Config) { consume(c.productionName); }",
            )],
        );

        assert_eq!(
            errors.len(),
            1,
            "a production cfg_attr rename must map to the actual Rust field: {errors:?}"
        );
    }

    #[test]
    fn production_serde_and_schemars_cfg_attr_renames_map_to_rust_fields() {
        let keys = [
            key("proxy.serde_name", "serde_name"),
            key("proxy.schema_name", "schema_name"),
        ];
        let errors = verify_config_readers(
            &keys,
            &[],
            &[source(
                "struct Config {\n\
                     #[cfg_attr(not(test), serde(rename = \"serde_name\"))]\n\
                     serde_field: bool,\n\
                     #[cfg_attr(not(test), schemars(rename = \"schema_name\"))]\n\
                     schema_field: bool,\n\
                 }\n\
                 fn consume<T>(_: T) {}\n\
                 fn run(c: &Config) {\n\
                     consume(c.serde_field);\n\
                     consume(c.schema_field);\n\
                 }",
            )],
        );

        assert!(
            errors.is_empty(),
            "production cfg_attr renames must map back to their Rust fields: {errors:?}"
        );
    }

    #[test]
    fn asymmetric_serde_rename_uses_the_deserialize_name() {
        let errors = verify_config_readers(
            &[key("proxy.wire_in", "wire_in")],
            &[],
            &[source(
                "struct Config {\n\
                     #[serde(rename(serialize = \"wire_out\", deserialize = \"wire_in\"))]\n\
                     rust_name: bool,\n\
                 }\n\
                 fn consume<T>(_: T) {}\n\
                 fn run(c: &Config) { consume(c.rust_name); }",
            )],
        );

        assert!(
            errors.is_empty(),
            "the input schema uses the deserialize-side name: {errors:?}"
        );
    }

    #[test]
    fn cfg_test_fields_are_not_schema_field_candidates() {
        let errors = verify_config_readers(
            &[key("proxy.live", "live")],
            &[],
            &[source(
                "struct Config {\n\
                     live: bool,\n\
                     #[cfg(test)]\n\
                     #[serde(rename = \"live\")]\n\
                     decoy: bool,\n\
                 }\n\
                 fn consume<T>(_: T) {}\n\
                 fn run(c: &Config) { consume(c.live); }",
            )],
        );

        assert!(
            errors.is_empty(),
            "test-only fields must not make a production schema mapping ambiguous: {errors:?}"
        );
    }

    #[test]
    fn block_local_factory_returns_preserve_config_provenance() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "fn outer() {\n\
                     fn make() -> sbproxy_config::GuardConfig { todo!() }\n\
                     consume(make().enabled);\n\
                 }",
            ),
        ]);

        assert!(
            errors.is_empty(),
            "a block-local factory return type must retain provenance: {errors:?}"
        );
    }

    #[test]
    fn block_local_factories_shadow_imported_config_factories() {
        let errors = guard_errors(&[
            source_at(
                "crates/sbproxy-config/src/lib.rs",
                "pub struct GuardConfig { pub enabled: bool }\n\
                 pub fn make() -> GuardConfig { todo!() }",
            ),
            source_at(
                "crates/runtime/src/lib.rs",
                "use sbproxy_config::make;\n\
                 fn outer() {\n\
                     fn make() -> external_crate::GuardConfig { todo!() }\n\
                     consume(make().enabled);\n\
                 }",
            ),
        ]);

        assert_eq!(
            errors.len(),
            1,
            "a local factory must shadow an imported config factory: {errors:?}"
        );
    }

    #[test]
    fn unparseable_production_source_cannot_be_silently_skipped() {
        let keys = [key("proxy.indirect", "indirect")];
        let override_entry = ConfigKeyCapability {
            path: "proxy.indirect",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("reserved under WOR-9999"),
        };
        let sources = [source("fn malformed( {")];

        let errors = verify_config_readers(&keys, &[override_entry], &sources);

        assert!(
            errors.iter().any(|error| {
                error.subject.contains("crates/example/src/lib.rs")
                    && error.message.contains("could not parse")
            }),
            "source parsing failures must make the guard fail: {errors:?}"
        );
    }

    #[test]
    fn syntax_analysis_uses_the_unmodified_source_view() {
        let keys = [key("proxy.live", "live")];
        let sources = [source_with_views(
            "crates/example/src/lib.rs",
            r#"
struct Config {
    live: bool,
}

fn production(config: &Config) {
    consume(config.live);
}
"#,
            "fn broken_by_textual_stripping( {",
        )];

        assert_eq!(verify_config_readers(&keys, &[], &sources), vec![]);
    }

    #[test]
    fn syntax_analysis_does_not_count_test_attributed_items() {
        let keys = [key("proxy.unread", "unread")];
        let raw_text = r#"
struct Config {
    unread: bool,
}

#[test]
fn unit_test(config: &Config) {
    consume(config.unread);
}

#[tokio::test(flavor = "current_thread")]
async fn async_test(config: &Config) {
    consume(config.unread);
}

#[cfg(test)]
fn cfg_test(config: &Config) {
    consume(config.unread);
}
"#;
        let sources = [source_with_views(
            "crates/example/src/lib.rs",
            raw_text,
            &crate::scan::strip_test_regions(raw_text),
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].subject, "proxy.unread");
    }

    #[test]
    fn test_attributed_statements_and_locals_are_not_reader_evidence() {
        for statement in [
            "#[cfg(test)] consume(v.enabled);",
            "#[cfg(all(test, unix))] let observed = v.enabled;",
        ] {
            let errors = guard_errors(&[source(&format!(
                "struct GuardConfig {{ enabled: bool }}\n\
                 fn runtime(v: &GuardConfig) {{ {statement} }}"
            ))]);

            assert_eq!(
                errors.len(),
                1,
                "a test-only statement must not prove a reader: {statement}\n{errors:?}"
            );
        }
    }

    #[test]
    fn conditionally_production_statement_remains_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 #[cfg(any(test, feature = \"fixtures\"))]\n\
                 consume(v.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a statement reachable in a production feature remains evidence: {errors:?}"
        );
    }

    #[test]
    fn mutually_exclusive_target_cfg_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 #[cfg(all(unix, windows))]\n\
                 consume(v.enabled);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a statement impossible on every Rust target must be excluded: {errors:?}"
        );
    }

    #[test]
    fn contradictory_feature_cfg_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 #[cfg(all(feature = \"x\", not(feature = \"x\")))]\n\
                 consume(v.enabled);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a contradictory feature predicate must be excluded from production: {errors:?}"
        );
    }

    #[test]
    fn cfg_attr_that_adds_cfg_test_in_production_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             #[cfg_attr(not(test), cfg(test))]\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "cfg_attr applies cfg(test) precisely in production and must exclude the item: \
             {errors:?}"
        );
    }

    #[test]
    fn cfg_attr_that_adds_an_impossible_cfg_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             #[cfg_attr(not(test), cfg(all(unix, windows)))]\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "cfg_attr adds an impossible production predicate and must exclude the item: \
             {errors:?}"
        );
    }

    #[test]
    fn competing_target_abi_values_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             #[cfg(all(target_abi = \"eabi\", target_abi = \"eabihf\"))]\n\
             fn runtime(v: &GuardConfig) { consume(v.enabled); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "target_abi is single-valued and cannot satisfy competing values: {errors:?}"
        );
    }

    #[test]
    fn possible_cfg_attr_and_target_abi_predicates_remain_reader_evidence() {
        for attribute in [
            "#[cfg_attr(test, cfg(test))]",
            "#[cfg(any(target_abi = \"eabi\", target_abi = \"eabihf\"))]",
        ] {
            let errors = guard_errors(&[source(&format!(
                "struct GuardConfig {{ enabled: bool }}\n\
                 fn consume<T>(_: T) {{}}\n\
                 {attribute}\n\
                 fn runtime(v: &GuardConfig) {{ consume(v.enabled); }}"
            ))]);

            assert!(
                errors.is_empty(),
                "a production-reachable attribute remains reader evidence: {attribute}\n\
                 {errors:?}"
            );
        }
    }

    #[test]
    fn target_disjunction_remains_possible_production_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 #[cfg(any(unix, windows))]\n\
                 consume(v.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a target disjunction reachable in production remains evidence: {errors:?}"
        );
    }

    #[test]
    fn test_attributed_struct_fields_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Carrier { observed: bool, kept: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 consume(Carrier {\n\
                     #[cfg(test)]\n\
                     observed: v.enabled,\n\
                     kept: true,\n\
                 });\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a test-only struct field must not prove a production reader: {errors:?}"
        );
    }

    #[test]
    fn conditionally_production_struct_fields_remain_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Carrier { observed: bool, kept: bool }\n\
             fn runtime(v: &GuardConfig) {\n\
                 consume(Carrier {\n\
                     #[cfg(any(test, feature = \"fixtures\"))]\n\
                     observed: v.enabled,\n\
                     kept: true,\n\
                 });\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a struct field reachable in production remains evidence: {errors:?}"
        );
    }

    #[test]
    fn struct_update_rest_expressions_remain_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Carrier { observed: bool }\n\
             fn make(observed: bool) -> Carrier { Carrier { observed } }\n\
             fn runtime(v: &GuardConfig) {\n\
                 let x = Carrier { ..make(v.enabled) };\n\
                 consume(x);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a struct update base expression must be traversed: {errors:?}"
        );
    }

    #[test]
    fn struct_update_rest_preserves_test_only_field_filtering() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Carrier { observed: bool, kept: bool }\n\
             fn make() -> Carrier { todo!() }\n\
             fn runtime(v: &GuardConfig) {\n\
                 let x = Carrier {\n\
                     #[cfg(test)]\n\
                     observed: v.enabled,\n\
                     ..make()\n\
                 };\n\
                 consume(x);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "traversing a struct update base must not revive test-only fields: {errors:?}"
        );
    }

    #[test]
    fn composite_cfg_and_non_function_test_items_are_not_reader_evidence() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for text in [
            "struct GuardConfig { enabled: bool }\n\
             #[cfg(all(test, unix))]\n\
             fn only_test(v: &GuardConfig) { consume(v.enabled); }",
            "struct GuardConfig { enabled: bool }\n\
             #[cfg(test)]\n\
             const ONLY_TEST: bool = {\n\
                 let v: GuardConfig = todo!();\n\
                 v.enabled\n\
             };",
        ] {
            let errors = verify_config_readers(&keys, &[], &[source(text)]);
            assert_eq!(
                errors.len(),
                1,
                "test-only item must not prove a reader: {errors:?}"
            );
        }
    }

    #[test]
    fn externally_defined_test_module_is_not_production_evidence() {
        for cfg in ["test", "all(test, unix)"] {
            let temp = tempfile::tempdir().expect("temp repo");
            let src = temp.path().join("crates/example/src");
            std::fs::create_dir_all(&src).expect("crate source directory");
            std::fs::write(
                src.join("lib.rs"),
                format!(
                    "struct GuardConfig {{ enabled: bool }}\n\
                     #[cfg({cfg})]\n\
                     mod fixture;\n"
                ),
            )
            .expect("crate root");
            std::fs::write(
                src.join("fixture.rs"),
                "fn only_test(v: &GuardConfig) { consume(v.enabled); }\n",
            )
            .expect("test-only module");

            let keys = [ConfigSchemaKey {
                path: "proxy.guard.enabled".to_string(),
                rust_field: "enabled".to_string(),
                rust_owner: Some("GuardConfig".to_string()),
            }];
            let sources = crate::scan::rust_sources(temp.path());
            let errors = verify_config_readers(&keys, &[], sources);

            assert_eq!(
                errors.len(),
                1,
                "externally defined #[cfg({cfg})] module must be excluded: {errors:?}"
            );
        }
    }

    #[test]
    fn integration_test_bench_and_example_reads_are_not_production_evidence() {
        for path in [
            "crates/example/tests/reader.rs",
            "crates/example/benches/reader.rs",
            "crates/example/examples/reader.rs",
        ] {
            let keys = [key("proxy.unread", "unread")];
            let sources = [source_at(
                path,
                "fn fixture(config: &Config) { consume(config.unread); }",
            )];

            let errors = verify_config_readers(&keys, &[], &sources);

            assert_eq!(
                errors.len(),
                1,
                "{path} must not make a configuration key live: {errors:?}"
            );
            assert_eq!(errors[0].subject, "proxy.unread");
        }
    }

    #[test]
    fn stable_override_must_name_an_existing_production_consumer() {
        let keys = [key("proxy.indirect", "indirect")];
        let override_entry = ConfigKeyCapability {
            path: "proxy.indirect",
            support: SupportLevel::Stable,
            consumer: Some("example::compiler::missing_consumer"),
            note: None,
        };
        let sources = [source_at(
            "crates/example/src/compiler.rs",
            "pub fn actual_consumer() {}",
        )];

        let errors = verify_config_readers(&keys, &[override_entry], &sources);

        assert!(
            errors.iter().any(|error| {
                error.subject == "proxy.indirect"
                    && error.message.contains("missing_consumer")
                    && error.message.contains("production")
            }),
            "stable evidence must resolve to production source: {errors:?}"
        );
    }

    #[test]
    fn stable_consumer_must_be_an_exact_top_level_production_symbol() {
        let keys = [key("proxy.guard.enabled", "enabled")];
        let override_entry = ConfigKeyCapability {
            path: "proxy.guard.enabled",
            support: SupportLevel::Stable,
            consumer: Some("example::compiler::consume_guard"),
            note: None,
        };
        for text in [
            "mod hidden { pub fn consume_guard() {} }",
            "#[cfg(all(test, unix))] pub fn consume_guard() {}",
        ] {
            let sources = [source_at("crates/example/src/compiler.rs", text)];
            let errors = verify_config_readers(&keys, &[override_entry], &sources);
            assert!(
                errors
                    .iter()
                    .any(|error| error.subject == "proxy.guard.enabled"),
                "nested or test-only namesake must not prove an exact consumer: {errors:?}"
            );
        }
    }

    #[test]
    fn stable_consumer_resolves_an_inherent_method_but_not_a_trait_method() {
        let keys = [key("proxy.router.mode", "mode")];
        let stable_entry = |consumer| ConfigKeyCapability {
            path: "proxy.router.mode",
            support: SupportLevel::Stable,
            consumer: Some(consumer),
            note: None,
        };
        let sources = [source_at(
            "crates/example/src/handler.rs",
            "pub struct HandlerConfig;\n\
             impl HandlerConfig { pub fn router(&self) {} }\n\
             impl std::fmt::Debug for HandlerConfig {\n\
                 fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) }\n\
             }",
        )];

        assert_eq!(
            verify_config_readers(
                &keys,
                &[stable_entry("example::handler::HandlerConfig::router")],
                &sources
            ),
            vec![],
            "an inherent method is a real reader and must satisfy stable evidence"
        );

        // A trait method's name belongs to the trait, so citing one would let
        // any type with a `Debug` impl stand as evidence for any key.
        assert!(
            verify_config_readers(
                &keys,
                &[stable_entry("example::handler::HandlerConfig::fmt")],
                &sources
            )
            .iter()
            .any(|error| error.subject == "proxy.router.mode"),
            "a trait method must not prove a config key is read"
        );
    }

    #[test]
    fn writes_ignored_patterns_and_inner_shadowing_are_not_reads() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for text in [
            "struct GuardConfig { enabled: bool }\n\
             fn normalize(v: &mut GuardConfig) { v.enabled = false; }",
            "struct GuardConfig { enabled: bool }\n\
             fn normalize(v: &mut GuardConfig) { overwrite(&mut v.enabled); }",
            "struct GuardConfig { enabled: bool }\n\
             fn normalize(v: &mut GuardConfig) { v.enabled.clone_from(&false); }",
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) { let _ = v.enabled; }",
            "struct GuardConfig { enabled: bool }\n\
             fn normalize(v: &mut GuardConfig) {\n\
                 let GuardConfig { enabled, .. } = v;\n\
                 *enabled = false;\n\
             }",
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let GuardConfig { enabled: _, .. } = v;\n\
             }",
            "struct GuardConfig { enabled: bool }\n\
             struct Existing { enabled: bool }\n\
             fn f(existing: &Existing, guard: &GuardConfig) {\n\
                 let value = existing;\n\
                 { let value = guard; consume(value); }\n\
                 consume(value.enabled);\n\
             }",
        ] {
            let errors = verify_config_readers(&keys, &[], &[source(text)]);
            assert_eq!(
                errors.len(),
                1,
                "non-read syntax must not prove a reader: {errors:?}"
            );
        }
    }

    #[test]
    fn assignment_places_preserve_nested_index_reads() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn route(v: &GuardConfig, out: &mut [bool]) {\n\
                 out[v.enabled as usize] = true;\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "the index used to select an assignment place is a value read: {errors:?}"
        );
    }

    #[test]
    fn ignored_tuple_initializer_elements_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let (_, kept) = (v.enabled, 1);\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an initializer paired with `_` is discarded, not consumed: {errors:?}"
        );
    }

    #[test]
    fn ignored_tuple_rest_initializer_elements_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let (_, .., kept) = (v.enabled, 0, 1, 2);\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "tuple rest must preserve positional discard mapping: {errors:?}"
        );
    }

    #[test]
    fn parenthesized_tuple_initializers_preserve_ignored_elements() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let (_, kept) = ((v.enabled, 1));\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "parentheses around a tuple must not erase ignored positions: {errors:?}"
        );
    }

    #[test]
    fn ignored_array_initializer_elements_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let [_, kept] = [v.enabled, true];\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an array initializer paired with `_` is discarded: {errors:?}"
        );
    }

    #[test]
    fn ignored_record_initializer_fields_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Pair { ignored: bool, kept: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let Pair { ignored: _, kept } = Pair {\n\
                     ignored: v.enabled,\n\
                     kept: true,\n\
                 };\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a record initializer field paired with `_` is discarded: {errors:?}"
        );
    }

    #[test]
    fn array_rest_and_nested_patterns_preserve_live_elements() {
        for statement in [
            "let [kept, ..] = [v.enabled, true]; consume(kept);",
            "let [[kept, _], ..] = [[v.enabled, true], [false, false]]; consume(kept);",
        ] {
            let errors = guard_errors(&[source(&format!(
                "struct GuardConfig {{ enabled: bool }}\n\
                 fn inspect(v: &GuardConfig) {{ {statement} }}"
            ))]);

            assert!(
                errors.is_empty(),
                "a live array element remains reader evidence: {statement}\n{errors:?}"
            );
        }
    }

    #[test]
    fn record_rest_and_nested_patterns_preserve_live_fields() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Pair { ignored: bool, kept: (bool, bool), spare: bool }\n\
             fn inspect(v: &GuardConfig) {\n\
                 let Pair { kept: (kept, _), .. } = Pair {\n\
                     ignored: false,\n\
                     kept: (v.enabled, true),\n\
                     spare: false,\n\
                 };\n\
                 consume(kept);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a live nested record field remains reader evidence: {errors:?}"
        );
    }

    #[test]
    fn ignored_tuple_struct_initializer_elements_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Pair(bool, bool);\n\
             fn ignore(v: &GuardConfig) {\n\
                 let Pair(_, kept) = Pair(v.enabled, true);\n\
                 consume(kept);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a tuple-struct constructor argument paired with `_` is discarded: {errors:?}"
        );
    }

    #[test]
    fn live_tuple_struct_initializer_elements_remain_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Pair(bool, bool);\n\
             fn inspect(v: &GuardConfig) {\n\
                 let Pair(kept, _) = Pair(v.enabled, true);\n\
                 consume(kept);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a live tuple-struct constructor argument remains evidence: {errors:?}"
        );
    }

    #[test]
    fn tuple_initializer_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) {\n\
                 let (cfg,) = (v,);\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a tuple-bound local must retain the initializer provenance: {errors:?}"
        );
    }

    #[test]
    fn array_initializer_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) {\n\
                 let [cfg] = [v];\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an array-bound local must retain the initializer provenance: {errors:?}"
        );
    }

    #[test]
    fn tuple_struct_initializer_bindings_preserve_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             struct Wrap<T>(T);\n\
             fn inspect(v: &GuardConfig) {\n\
                 let Wrap(cfg) = Wrap(v);\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a tuple-struct-bound local must retain initializer provenance: {errors:?}"
        );
    }

    #[test]
    fn at_subpatterns_preserve_nested_config_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) {\n\
                 let _outer @ Some(cfg) = Some(v) else { return; };\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "an identifier binding must not hide its nested @ subpattern: {errors:?}"
        );
    }

    #[test]
    fn named_rest_keeps_discarded_prefix_fields_unread() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn ignore(v: &GuardConfig) {\n\
                 let [_, tail @ ..] = [v.enabled, true, false];\n\
                 consume(tail[0]);\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a named rest must not revive a field paired with a prefix wildcard: {errors:?}"
        );
    }

    #[test]
    fn named_rest_bindings_preserve_element_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig, other: &GuardConfig) {\n\
                 let [_, tail @ ..] = [other, v, other];\n\
                 consume(tail[0].enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a named rest binding must retain its element owner: {errors:?}"
        );
    }

    #[test]
    fn ignored_repeat_initializer_elements_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn ignore(v: &GuardConfig) {\n\
                 let [_, _] = [v.enabled; 2];\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a repeated initializer discarded by every element is not evidence: {errors:?}"
        );
    }

    #[test]
    fn named_repeat_counts_do_not_revive_fully_discarded_reads() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             const N: usize = 2;\n\
             fn ignore(v: &GuardConfig) {\n\
                 let [_, _] = [v.enabled; N];\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a named repeat count must retain element-wise discard mapping: {errors:?}"
        );
    }

    #[test]
    fn named_repeat_counts_preserve_live_binding_provenance() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             const N: usize = 1;\n\
             fn inspect(v: &GuardConfig) {\n\
                 let [cfg] = [v; N];\n\
                 consume(cfg.enabled);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "a live binding remains traceable through a named repeat count: {errors:?}"
        );
    }

    #[test]
    fn live_repeat_initializer_elements_remain_reader_evidence() {
        for statement in [
            "let [kept, _] = [v.enabled; 2]; consume(kept);",
            "let [kept, ..] = [v.enabled; 2]; consume(kept);",
        ] {
            let errors = guard_errors(&[source(&format!(
                "struct GuardConfig {{ enabled: bool }}\n\
                 fn inspect(v: &GuardConfig) {{ {statement} }}"
            ))]);

            assert!(
                errors.is_empty(),
                "a live repeated initializer element remains evidence: {statement}\n{errors:?}"
            );
        }
    }

    #[test]
    fn dereferenced_assignment_places_preserve_call_argument_reads() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn route(v: &GuardConfig) {\n\
                 *pick(v.enabled) = true;\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "computing a dereferenced destination still reads call arguments: {errors:?}"
        );
    }

    #[test]
    fn destructuring_assignment_places_preserve_nested_index_reads() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn route(v: &GuardConfig, out: &mut [bool], other: &mut bool) {\n\
                 (out[v.enabled as usize], *other) = (true, false);\n\
             }",
        )]);

        assert!(
            errors.is_empty(),
            "every destination in a destructuring assignment must be traversed: {errors:?}"
        );
    }

    #[test]
    fn unknown_mutating_methods_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: bool }\n\
             fn normalize(v: &mut GuardConfig) {\n\
                 v.enabled.set_false();\n\
             }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "an unknown method may mutate its receiver and must fail closed: {errors:?}"
        );
    }

    #[test]
    fn known_reader_methods_remain_reader_evidence() {
        for method in ["clone()", "to_string()"] {
            let errors = guard_errors(&[source(&format!(
                "struct GuardConfig {{ enabled: bool }}\n\
                 fn inspect(v: &GuardConfig) {{ consume(v.enabled.{method}); }}"
            ))]);

            assert!(
                errors.is_empty(),
                "a known reader method must still consume its receiver: {method}\n{errors:?}"
            );
        }
    }

    #[test]
    fn resolved_shared_receiver_methods_are_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             impl Flag { fn is_set(&self) -> bool { true } }\n\
             struct GuardConfig { enabled: Flag }\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a resolved `&self` method consumes its receiver: {errors:?}"
        );
    }

    #[test]
    fn resolved_mutable_len_method_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             impl Flag { fn len(&mut self) -> usize { 0 } }\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.len()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a resolved custom `len(&mut self)` may only mutate: {errors:?}"
        );
    }

    #[test]
    fn resolved_mutable_clone_method_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             impl Flag { fn clone(&mut self) -> bool { true } }\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.clone()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a resolved custom `clone(&mut self)` may only mutate: {errors:?}"
        );
    }

    #[test]
    fn resolved_mutable_to_string_method_is_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             impl Flag { fn to_string(&mut self) -> String { String::new() } }\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.to_string()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a resolved custom `to_string(&mut self)` may only mutate: {errors:?}"
        );
    }

    #[test]
    fn trait_default_shared_receiver_methods_are_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             impl State for Flag {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a trait default `&self` method consumes its receiver: {errors:?}"
        );
    }

    #[test]
    fn trait_default_mutable_receiver_methods_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait Normalize { fn len(&mut self) -> usize { 0 } }\n\
             impl Normalize for Flag {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.len()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a trait default `&mut self` method may only mutate: {errors:?}"
        );
    }

    #[test]
    fn blanket_trait_default_shared_receiver_methods_are_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             impl<T> State for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a blanket-provided `&self` default consumes its receiver: {errors:?}"
        );
    }

    #[test]
    fn blanket_trait_default_mutable_receiver_methods_are_not_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait Normalize { fn len(&mut self) -> usize { 0 } }\n\
             impl<T> Normalize for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.len()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a blanket-provided `&mut self` default may only mutate: {errors:?}"
        );
    }

    #[test]
    fn explicit_trait_impl_receiver_methods_remain_resolved() {
        for (receiver, expected_errors) in [("&self", 0), ("&mut self", 1)] {
            let errors = guard_errors(&[source(&format!(
                "struct Flag;\n\
                 trait Inspect {{ fn len({receiver}) -> usize {{ 0 }} }}\n\
                 impl Inspect for Flag {{ fn len({receiver}) -> usize {{ 0 }} }}\n\
                 struct GuardConfig {{ enabled: Flag }}\n\
                 fn inspect(v: &mut GuardConfig) {{ consume(v.enabled.len()); }}"
            ))]);

            assert_eq!(
                errors.len(),
                expected_errors,
                "an explicit trait override keeps its receiver semantics: {receiver}\n{errors:?}"
            );
        }
    }

    #[test]
    fn unsatisfied_blanket_trait_bounds_do_not_poison_shared_methods() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait Marker {}\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl State for Flag {}\n\
             impl<T: Marker> Mutate for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an unsatisfied blanket bound cannot conflict with a shared method: {errors:?}"
        );
    }

    #[test]
    fn external_blanket_bounds_use_compiled_method_applicability() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             impl<T: Send> State for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an unresolved standard-library bound must not hide a compiled method call: {errors:?}"
        );
    }

    #[test]
    fn inapplicable_external_bounds_do_not_poison_proven_shared_methods() {
        let errors = guard_errors(&[source(
            "struct Flag(std::rc::Rc<()>);\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl State for Flag {}\n\
             impl<T: Send> Mutate for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an external bound cannot conflict with a receiver already proven applicable: \
             {errors:?}"
        );
    }

    #[test]
    fn competing_external_bounds_use_derived_and_structural_applicability() {
        let errors = guard_errors(&[source(
            "#[derive(Clone)]\n\
             struct Flag(std::rc::Rc<()>);\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl<T: Clone> Observe for T {}\n\
             impl<T: Send> Mutate for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "derived Clone applies while an Rc-backed Flag is structurally non-Send: {errors:?}"
        );
    }

    #[test]
    fn sync_but_not_send_components_select_the_shared_blanket_method() {
        let errors = guard_errors(&[source(
            "struct Flag(std::sync::MutexGuard<'static, ()>);\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl<T: Sync> Observe for T {}\n\
             impl<T: Send> Mutate for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "MutexGuard makes Flag Sync but not Send, so only the shared method applies: \
             {errors:?}"
        );
    }

    #[test]
    fn manual_clone_impls_select_the_clone_bounded_shared_method() {
        let errors = guard_errors(&[source(
            "struct Flag(std::sync::MutexGuard<'static, ()>);\n\
             impl Clone for Flag { fn clone(&self) -> Self { todo!() } }\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl<T: Clone> Observe for T {}\n\
             impl<T: Send> Mutate for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a manual Clone impl applies while MutexGuard keeps Flag non-Send: {errors:?}"
        );
    }

    #[test]
    fn structurally_non_send_bound_cannot_override_a_mutable_receiver() {
        let errors = guard_errors(&[source(
            "struct Flag(std::rc::Rc<()>);\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             impl Mutate for Flag {}\n\
             impl<T: Send> Observe for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a shared method behind an impossible Send bound must not create reader evidence: \
             {errors:?}"
        );
    }

    #[test]
    fn out_of_scope_blanket_traits_do_not_poison_shared_methods() {
        let errors = guard_errors(&[source(
            "mod hidden {\n\
                 pub trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
                 impl<T> Mutate for T {}\n\
             }\n\
             struct Flag;\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             impl State for Flag {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "only traits in lexical scope participate in method lookup: {errors:?}"
        );
    }

    #[test]
    fn satisfied_blanket_bounds_preserve_mutable_receiver_semantics() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             trait Marker {}\n\
             impl Marker for Flag {}\n\
             trait Normalize { fn len(&mut self) -> usize { 0 } }\n\
             impl<T: Marker> Normalize for T {}\n\
             struct GuardConfig { enabled: Flag }\n\
             fn normalize(v: &mut GuardConfig) { consume(v.enabled.len()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "a satisfied blanket bound retains its mutable semantics: {errors:?}"
        );
    }

    #[test]
    fn imported_blanket_traits_remain_method_candidates() {
        for import in [
            "use extension::Normalize;",
            "use extension::Normalize as _;",
        ] {
            let errors = guard_errors(&[source(&format!(
                "mod extension {{\n\
                     pub trait Normalize {{ fn len(&mut self) -> usize {{ 0 }} }}\n\
                     impl<T> Normalize for T {{}}\n\
                 }}\n\
                 {import}\n\
                 struct Flag;\n\
                 struct GuardConfig {{ enabled: Flag }}\n\
                 fn normalize(v: &mut GuardConfig) {{ consume(v.enabled.len()); }}"
            ))]);

            assert_eq!(
                errors.len(),
                1,
                "an imported mutable extension trait remains visible: {import}\n{errors:?}"
            );
        }
    }

    #[test]
    fn generic_inherent_impl_owner_unifies_with_a_concrete_receiver() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T>(T);\n\
             impl<T> Wrap<T> { fn is_set(&self) -> bool { true } }\n\
             struct GuardConfig { enabled: Wrap<Flag> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an inherent impl<T> owner must unify with Wrap<Flag>: {errors:?}"
        );
    }

    #[test]
    fn generic_trait_impl_owner_unifies_with_a_concrete_receiver() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T>(T);\n\
             trait State { fn is_set(&self) -> bool { true } }\n\
             impl<T> State for Wrap<T> {}\n\
             struct GuardConfig { enabled: Wrap<Flag> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a trait impl<T> owner must unify with Wrap<Flag>: {errors:?}"
        );
    }

    #[test]
    fn const_generic_impl_owner_unifies_with_a_concrete_receiver() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T, const N: usize>([T; N]);\n\
             impl<T, const N: usize> Wrap<T, N> {\n\
                 fn is_set(&self) -> bool { true }\n\
             }\n\
             struct GuardConfig { enabled: Wrap<Flag, 1> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an impl<T, const N> owner must unify with Wrap<Flag, 1>: {errors:?}"
        );
    }

    #[test]
    fn repeated_impl_type_parameters_require_equal_receiver_arguments() {
        let errors = guard_errors(&[source(
            "struct A;\n\
             struct B;\n\
             struct Pair<X, Y>(X, Y);\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Pair<A, B> {}\n\
             impl<T> Mutate for Pair<T, T> {}\n\
             struct GuardConfig { enabled: Pair<A, B> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "Pair<T, T> cannot match Pair<A, B> and hide its shared receiver: {errors:?}"
        );
    }

    #[test]
    fn structured_impl_bounds_must_apply_to_the_concrete_argument() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T>(T);\n\
             trait Marker {}\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Wrap<Flag> {}\n\
             impl<T: Marker> Mutate for Wrap<T> {}\n\
             struct GuardConfig { enabled: Wrap<Flag> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an unsatisfied bound on impl<T: Marker> Wrap<T> cannot hide a shared receiver: \
             {errors:?}"
        );
    }

    #[test]
    fn repeated_impl_const_parameters_require_equal_receiver_arguments() {
        let errors = guard_errors(&[source(
            "struct Pair<const A: usize, const B: usize>;\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Pair<1, 2> {}\n\
             impl<const N: usize> Mutate for Pair<N, N> {}\n\
             struct GuardConfig { enabled: Pair<1, 2> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "Pair<N, N> cannot match Pair<1, 2> and hide its shared receiver: {errors:?}"
        );
    }

    #[test]
    fn swapped_alias_arguments_resolve_to_the_underlying_owner_order() {
        let errors = guard_errors(&[source(
            "struct A;\n\
             struct B;\n\
             struct Pair<X, Y>(X, Y);\n\
             type Swap<X, Y> = Pair<Y, X>;\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Pair<B, A> {}\n\
             impl Mutate for Pair<A, B> {}\n\
             struct GuardConfig { enabled: Swap<A, B> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "Swap<A, B> must resolve as Pair<B, A> before method lookup: {errors:?}"
        );
    }

    #[test]
    fn swapped_alias_arguments_do_not_preserve_the_alias_order() {
        let errors = guard_errors(&[source(
            "struct A;\n\
             struct B;\n\
             struct Pair<X, Y>(X, Y);\n\
             type Swap<X, Y> = Pair<Y, X>;\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Pair<A, B> {}\n\
             impl Mutate for Pair<B, A> {}\n\
             struct GuardConfig { enabled: Swap<A, B> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "Swap<A, B> must not be mistaken for Pair<A, B>: {errors:?}"
        );
    }

    #[test]
    fn simple_generic_aliases_preserve_argument_provenance() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T>(T);\n\
             type Alias<T> = Wrap<T>;\n\
             impl<T> Wrap<T> { fn is_set(&self) -> bool { true } }\n\
             struct GuardConfig { enabled: Alias<Flag> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "a non-reordering generic alias remains a live-reader control: {errors:?}"
        );
    }

    #[test]
    fn generic_inherent_mutable_receiver_remains_unread() {
        let errors = guard_errors(&[source(
            "struct Flag;\n\
             struct Wrap<T>(T);\n\
             impl<T> Wrap<T> { fn is_set(&mut self) -> bool { true } }\n\
             struct GuardConfig { enabled: Wrap<Flag> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "generic owner unification must retain mutable receiver semantics: {errors:?}"
        );
    }

    #[test]
    fn generic_exact_impl_owners_keep_receiver_semantics_distinct() {
        let errors = guard_errors(&[source(
            "struct A;\n\
             struct B;\n\
             struct Wrap<T>(T);\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Wrap<A> {}\n\
             impl Mutate for Wrap<B> {}\n\
             struct GuardConfig { enabled: Wrap<A> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert!(
            errors.is_empty(),
            "an impl for Wrap<B> cannot conflict with the Wrap<A> receiver: {errors:?}"
        );
    }

    #[test]
    fn generic_exact_impl_owners_preserve_matching_mutable_receivers() {
        let errors = guard_errors(&[source(
            "struct A;\n\
             struct B;\n\
             struct Wrap<T>(T);\n\
             trait Observe { fn is_set(&self) -> bool { true } }\n\
             trait Mutate { fn is_set(&mut self) -> bool { false } }\n\
             impl Observe for Wrap<A> {}\n\
             impl Mutate for Wrap<B> {}\n\
             struct GuardConfig { enabled: Wrap<B> }\n\
             fn consume<T>(_: T) {}\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.is_set()); }",
        )]);

        assert_eq!(
            errors.len(),
            1,
            "the matching Wrap<B> impl must retain its mutable receiver: {errors:?}"
        );
    }

    #[test]
    fn option_as_mut_remains_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: Option<bool> }\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.as_mut()); }",
        )]);

        assert!(
            errors.is_empty(),
            "Option::as_mut observes whether the configured value exists: {errors:?}"
        );
    }

    #[test]
    fn vec_iter_mut_remains_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: Vec<bool> }\n\
             fn inspect(v: &mut GuardConfig) { consume(v.enabled.iter_mut()); }",
        )]);

        assert!(
            errors.is_empty(),
            "Vec::iter_mut traverses the configured values: {errors:?}"
        );
    }

    #[test]
    fn vec_retain_remains_reader_evidence() {
        let errors = guard_errors(&[source(
            "struct GuardConfig { enabled: Vec<bool> }\n\
             fn inspect(v: &mut GuardConfig) { v.enabled.retain(|item| *item); }",
        )]);

        assert!(
            errors.is_empty(),
            "Vec::retain reads configured values through its predicate: {errors:?}"
        );
    }

    #[test]
    fn immutable_borrows_and_destructuring_remain_reader_evidence() {
        for text in [
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) { consume(&v.enabled); }",
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) { let _ = consume(v.enabled); }",
            "struct GuardConfig { enabled: bool }\n\
             fn inspect(v: &GuardConfig) {\n\
                 let GuardConfig { enabled, .. } = v;\n\
                 consume(enabled);\n\
             }",
        ] {
            let errors = guard_errors(&[source(text)]);
            assert!(
                errors.is_empty(),
                "an immutable value use remains reader evidence: {errors:?}"
            );
        }
    }

    #[test]
    fn conditional_pattern_bindings_do_not_escape_their_rust_scopes() {
        let keys = [ConfigSchemaKey {
            path: "proxy.guard.enabled".to_string(),
            rust_field: "enabled".to_string(),
            rust_owner: Some("GuardConfig".to_string()),
        }];
        for text in [
            "struct GuardConfig { enabled: bool }\n\
             struct Existing { enabled: bool }\n\
             fn f(value: &Existing, maybe: Option<&GuardConfig>) {\n\
                 if let Some(value) = maybe { consume(value); }\n\
                 consume(value.enabled);\n\
             }",
            "struct GuardConfig { enabled: bool }\n\
             struct Existing { enabled: bool }\n\
             fn f(value: &Existing, maybe: Option<&GuardConfig>) {\n\
                 while let Some(value) = maybe { consume(value); break; }\n\
                 consume(value.enabled);\n\
             }",
            "struct GuardConfig { enabled: bool }\n\
             struct Existing { enabled: bool }\n\
             fn f(value: &Existing, maybe: Option<&GuardConfig>) {\n\
                 let Some(value) = maybe else {\n\
                     consume(value.enabled);\n\
                     return;\n\
                 };\n\
                 consume(value);\n\
             }",
        ] {
            let errors = verify_config_readers(&keys, &[], &[source(text)]);
            assert_eq!(
                errors.len(),
                1,
                "a conditional binding must not retag an outer value: {errors:?}"
            );
        }
    }

    #[test]
    fn stale_override_fails_after_a_schema_key_is_removed() {
        let override_entry = ConfigKeyCapability {
            path: "proxy.removed",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("removed after WOR-9999"),
        };

        let errors = verify_config_readers(&[], &[override_entry], &[]);

        assert!(errors
            .iter()
            .any(|error| error.message.contains("not present")));
    }

    #[test]
    fn comments_and_strings_do_not_fake_a_reader() {
        let keys = [key("proxy.unread", "unread")];
        let sources = [source(
            r#"
struct Config {
    unread: bool,
}

// config.unread is intentionally absent.
const DOC: &str = "config.unread";
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    // --- Module surface ---

    fn module_index(sources: &[SourceFile]) -> RustTypeIndex {
        let production: Vec<&SourceFile> = sources.iter().collect();
        rust_type_index(&production)
    }

    fn module_paths(sources: &[SourceFile], rust_type: &'static str) -> BTreeSet<String> {
        let index = module_index(sources);
        let (keys, _, errors) = module_keys_for_roots(
            &index,
            &[ModuleConfigRoot {
                path: "origins.*.action",
                rust_type,
                enforcement: ModuleRootEnforcement::Enforced,
            }],
        );
        assert_eq!(errors, vec![], "the fixture root must resolve");
        keys.into_iter().map(|key| key.path).collect()
    }

    #[test]
    fn module_walk_reaches_keys_the_generated_schema_cannot_describe() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    targets: Vec<Target>,
    sticky: Option<Sticky>,
    labels: std::collections::HashMap<String, String>,
    opaque: serde_json::Value,
}

#[derive(Deserialize)]
struct Target {
    url: String,
    zone: Option<String>,
}

#[derive(Deserialize)]
struct Sticky {
    #[serde(rename = "cookie")]
    cookie_name: String,
}
"#,
        )];

        assert_eq!(
            module_paths(&sources, "example::ActionConfig"),
            BTreeSet::from([
                "origins.*.action.labels.*".to_string(),
                "origins.*.action.opaque".to_string(),
                "origins.*.action.sticky.cookie".to_string(),
                "origins.*.action.targets[].url".to_string(),
                "origins.*.action.targets[].zone".to_string(),
            ]),
            "a sequence adds `[]`, a map adds `.*`, and Option adds no level"
        );
    }

    #[test]
    fn module_walk_lifts_a_flattened_block_into_its_parent_path() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    url: String,
    #[serde(flatten, default)]
    forwarding: Forwarding,
}

#[derive(Deserialize)]
struct Forwarding {
    forwarded_for: bool,
}
"#,
        )];

        assert_eq!(
            module_paths(&sources, "example::ActionConfig"),
            BTreeSet::from([
                "origins.*.action.forwarded_for".to_string(),
                "origins.*.action.url".to_string(),
            ]),
            "serde lifts a flattened block, so it owns no path segment"
        );
    }

    #[test]
    fn module_walk_stops_at_an_enum_serde_does_not_tag_internally() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    algorithm: Algorithm,
    backend: Backend,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Algorithm {
    RoundRobin,
    HeaderHash { header: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Backend {
    Redis { url: String },
}
"#,
        )];

        assert_eq!(
            module_paths(&sources, "example::ActionConfig"),
            BTreeSet::from([
                "origins.*.action.algorithm".to_string(),
                "origins.*.action.backend.kind".to_string(),
                "origins.*.action.backend.url".to_string(),
            ]),
            "an externally tagged variant nests under a name this walk does not \
             model, so the enum is checked as one key instead of described wrongly"
        );
    }

    #[test]
    fn a_report_only_root_reports_findings_without_failing_the_build() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    zone: Option<String>,
}
"#,
        )];

        let report = verify_config_readers_with_modules(
            &[],
            &[ModuleConfigRoot {
                path: "origins.*.action",
                rust_type: "example::ActionConfig",
                enforcement: ModuleRootEnforcement::ReportOnly("triaged under WOR-2246"),
            }],
            &[],
            &sources,
        );

        assert_eq!(
            report.errors,
            vec![],
            "pre-existing debt is not a build break"
        );
        assert_eq!(
            report
                .reported
                .iter()
                .map(|error| error.subject.clone())
                .collect::<Vec<_>>(),
            vec!["origins.*.action.zone".to_string()]
        );
    }

    #[test]
    fn an_enforced_root_fails_on_a_key_nothing_reads() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    zone: Option<String>,
}
"#,
        )];

        let report = verify_config_readers_with_modules(
            &[],
            &[ModuleConfigRoot {
                path: "origins.*.action",
                rust_type: "example::ActionConfig",
                enforcement: ModuleRootEnforcement::Enforced,
            }],
            &[],
            &sources,
        );

        assert_eq!(report.reported, vec![]);
        assert_eq!(
            report
                .errors
                .iter()
                .map(|error| error.subject.clone())
                .collect::<Vec<_>>(),
            vec!["origins.*.action.zone".to_string()]
        );
    }

    #[test]
    fn a_module_override_is_held_to_the_same_stale_path_check() {
        let sources = [source(
            r#"
#[derive(Deserialize)]
struct ActionConfig {
    zone: Option<String>,
}
"#,
        )];
        let overrides = [ConfigKeyCapability {
            path: "origins.*.action.renamed_away",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("WOR-0000"),
        }];

        let report = verify_config_readers_with_modules(
            &[],
            &[ModuleConfigRoot {
                path: "origins.*.action",
                rust_type: "example::ActionConfig",
                enforcement: ModuleRootEnforcement::ReportOnly("triaged under WOR-2246"),
            }],
            &overrides,
            &sources,
        );

        assert!(
            report.errors.iter().any(|error| {
                error.subject == "origins.*.action.renamed_away"
                    && error
                        .message
                        .contains("not present in the generated schema")
            }),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn a_root_naming_a_shape_this_scan_cannot_see_says_so() {
        let sources = [source(
            r#"
fn build() {
    #[derive(Deserialize)]
    struct Config {
        zone: Option<String>,
    }
}
"#,
        )];

        let report = verify_config_readers_with_modules(
            &[],
            &[ModuleConfigRoot {
                path: "origins.*.action",
                rust_type: "example::Config",
                enforcement: ModuleRootEnforcement::Enforced,
            }],
            &[],
            &sources,
        );

        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(
            report.errors[0].message.contains("inside a function body"),
            "{:?}",
            report.errors[0]
        );
    }

    fn dispatch_fixture() -> [SourceFile; 1] {
        [source_at(
            "crates/sbproxy-modules/src/compile.rs",
            r#"
pub fn compile_action(config: &serde_json::Value) -> Result<Action> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "proxy" => Ok(Action::Proxy),
        "load_balancer" | "lb" => Ok(Action::LoadBalancer),
        _ => anyhow::bail!("unknown action type"),
    }
}
"#,
        )]
    }

    fn action_dispatch() -> [ModuleDispatch; 1] {
        [ModuleDispatch {
            kind: "action",
            source: "crates/sbproxy-modules/src/compile.rs",
            function: "compile_action",
        }]
    }

    #[test]
    fn a_dispatchable_module_must_be_classified() {
        let errors = verify_module_dispatch_coverage(
            &action_dispatch(),
            &[ModuleCoverage {
                kind: "action",
                name: "proxy",
                state: ModuleCoverageState::Rooted,
            }],
            &dispatch_fixture(),
        );

        assert_eq!(
            errors
                .iter()
                .map(|error| error.subject.clone())
                .collect::<Vec<_>>(),
            vec!["action:lb".to_string(), "action:load_balancer".to_string()],
            "every arm of the dispatch table needs a classification, aliases included"
        );
    }

    #[test]
    fn a_classification_no_dispatch_table_accepts_is_stale() {
        let coverage = [
            ModuleCoverage {
                kind: "action",
                name: "proxy",
                state: ModuleCoverageState::Rooted,
            },
            ModuleCoverage {
                kind: "action",
                name: "lb",
                state: ModuleCoverageState::Deferred("WOR-2246"),
            },
            ModuleCoverage {
                kind: "action",
                name: "load_balancer",
                state: ModuleCoverageState::Deferred("WOR-2246"),
            },
            ModuleCoverage {
                kind: "action",
                name: "removed_last_release",
                state: ModuleCoverageState::Deferred("WOR-2246"),
            },
        ];

        let errors =
            verify_module_dispatch_coverage(&action_dispatch(), &coverage, &dispatch_fixture());

        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].subject, "action:removed_last_release");
        assert!(
            errors[0].message.contains("no dispatch table accepts it"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn a_dispatch_function_that_moved_is_loud_rather_than_silent() {
        let errors = verify_module_dispatch_coverage(
            &[ModuleDispatch {
                kind: "action",
                source: "crates/sbproxy-modules/src/compile.rs",
                function: "compile_action_renamed",
            }],
            &[],
            &dispatch_fixture(),
        );

        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("no longer exists"),
            "{:?}",
            errors[0]
        );
    }
}
