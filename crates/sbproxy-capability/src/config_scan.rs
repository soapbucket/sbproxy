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

use crate::scan::{attributes_are_test_only, SourceFile};
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
    let mut errors = validate_config_keys(overrides);
    let declared: BTreeSet<&str> = keys.iter().map(|key| key.path.as_str()).collect();
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

    let production_sources: Vec<&SourceFile> = sources
        .iter()
        .filter(|source| source_is_production(&source.path))
        .collect();
    for source in &production_sources {
        if let Err(error) = syn::parse_file(&source.raw_text) {
            errors.push(RegistryError {
                subject: source.path.display().to_string(),
                message: format!(
                    "could not parse production Rust source while proving config readers: {error}"
                ),
            });
        }
    }
    let type_index = rust_type_index(&production_sources);
    let typed_reads = typed_field_reads(&production_sources, &type_index);

    for key in keys {
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
            errors.push(RegistryError {
                subject: key.path.clone(),
                message: format!(
                    "is accepted by the generated schema but has no unambiguous non-test Rust \
                     read of `{}::{}`. Wire the key, or add an exact reviewed override with \
                     production consumer evidence or a ConfigOnly reason",
                    key.rust_owner.as_deref().unwrap_or("<unknown>"),
                    key.rust_field,
                ),
            });
        }
    }

    errors
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

#[derive(Debug, Clone)]
struct TypeReference {
    segments: Vec<String>,
    context: ModuleContext,
    leading_colon: bool,
}

#[derive(Debug, Clone)]
struct FunctionReturn {
    symbol: String,
    result: TypeReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodReceiver {
    SharedOrValue,
    Mutable,
}

#[derive(Debug, Clone)]
struct MethodSignature {
    owner: TypeReference,
    receiver: MethodReceiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodReceiverResolution {
    Missing,
    SharedOrValue,
    Mutable,
    Ambiguous,
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
    types_by_name: BTreeMap<String, BTreeSet<String>>,
    symbol_bindings: BTreeMap<String, Vec<TypeReference>>,
    glob_imports: BTreeMap<ModuleContext, Vec<TypeReference>>,
    known_crates: BTreeSet<String>,
    known_modules: BTreeSet<String>,
    enum_tags: BTreeMap<String, String>,
    enum_variants: BTreeMap<String, BTreeSet<String>>,
    function_returns: BTreeMap<String, Vec<FunctionReturn>>,
    method_signatures: BTreeMap<String, Vec<MethodSignature>>,
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
        self.types_by_name
            .entry(simple_name.to_string())
            .or_default()
            .insert(owner.to_string());
    }

    fn record_symbol_binding(&mut self, alias: String, target: TypeReference) {
        self.symbol_bindings.entry(alias).or_default().push(target);
    }

    fn record_glob_import(&mut self, context: &ModuleContext, target: TypeReference) {
        self.glob_imports
            .entry(context.clone())
            .or_default()
            .push(target);
    }

    fn namespace_exists(&self, context: &ModuleContext) -> bool {
        if context.modules.is_empty() {
            self.known_crates.contains(&context.crate_name)
        } else {
            self.known_modules.contains(&context.path())
        }
    }

    fn record_fields(&mut self, owner: &str, fields: &syn::Fields, context: &ModuleContext) {
        for field in fields {
            if let Some(ident) = &field.ident {
                let field_name = ident.to_string().trim_start_matches("r#").to_string();
                self.fields
                    .entry(owner.to_string())
                    .or_default()
                    .insert(field_name, type_reference(&field.ty, context));
            }
        }
    }

    fn record_enum(&mut self, owner: &str, item: &syn::ItemEnum, context: &ModuleContext) {
        self.record_type(owner, &item.ident.to_string());
        self.enum_variants.insert(
            owner.to_string(),
            item.variants
                .iter()
                .map(|variant| variant.ident.to_string())
                .collect(),
        );
        if let Some(tag) = serde_enum_tag(&item.attrs) {
            self.enum_tags
                .insert(owner.to_string(), rust_field_name(&tag));
        }
        for variant in &item.variants {
            self.record_fields(owner, &variant.fields, context);
        }
    }

    fn field_type(&self, owner: &str, field: &str) -> Option<String> {
        self.fields
            .get(owner)
            .and_then(|fields| fields.get(field))
            .and_then(Option::as_ref)
            .and_then(|reference| self.resolve_type_reference(reference))
    }

    fn resolve_type_reference(&self, reference: &TypeReference) -> Option<String> {
        self.resolve_symbol_reference(SymbolKind::Type, reference, &mut BTreeSet::new())
            .exact()
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
        let Some(result) = type_reference(ty, context) else {
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

    fn record_method_signature(&mut self, owner: &TypeReference, signature: &syn::Signature) {
        let Some(syn::FnArg::Receiver(receiver)) = signature.inputs.first() else {
            return;
        };
        let receiver = if receiver.reference.is_some() && receiver.mutability.is_some()
            || receiver.colon_token.is_some() && type_is_mutable_reference(&receiver.ty)
        {
            MethodReceiver::Mutable
        } else {
            MethodReceiver::SharedOrValue
        };
        self.method_signatures
            .entry(signature.ident.to_string())
            .or_default()
            .push(MethodSignature {
                owner: owner.clone(),
                receiver,
            });
    }

    fn method_receiver(&self, owner: &str, method: &str) -> MethodReceiverResolution {
        let Some(signatures) = self.method_signatures.get(method) else {
            return MethodReceiverResolution::Missing;
        };
        let mut resolved = None;
        for signature in signatures {
            if self.resolve_type_reference(&signature.owner).as_deref() != Some(owner) {
                continue;
            }
            match resolved {
                None => resolved = Some(signature.receiver),
                Some(receiver) if receiver == signature.receiver => {}
                Some(_) => return MethodReceiverResolution::Ambiguous,
            }
        }
        match resolved {
            Some(MethodReceiver::SharedOrValue) => MethodReceiverResolution::SharedOrValue,
            Some(MethodReceiver::Mutable) => MethodReceiverResolution::Mutable,
            None => MethodReceiverResolution::Missing,
        }
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
        if !item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attributes_are_test_only(&node.attrs) {
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

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let owner = self.context.symbol(&node.ident.to_string());
        self.index.record_type(&owner, &node.ident.to_string());
        self.index
            .record_fields(&owner, &node.fields, &self.context);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let owner = self.context.symbol(&node.ident.to_string());
        self.index.record_enum(&owner, node, &self.context);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !attributes_are_test_only(&node.attrs) {
            self.index.record_function_return(&node.sig, &self.context);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let Some(owner) = type_reference(&node.self_ty, &self.context) else {
            return;
        };
        for item in &node.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if !attributes_are_test_only(&method.attrs) {
                self.index.record_method_signature(&owner, &method.sig);
            }
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if let Some(target) = type_reference(&node.ty, &self.context) {
            self.index
                .record_symbol_binding(self.context.symbol(&node.ident.to_string()), target);
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut bindings = Vec::new();
        let mut globs = Vec::new();
        collect_use_bindings(&node.tree, &mut Vec::new(), &mut bindings, &mut globs);
        for (alias, segments) in bindings {
            self.index.record_symbol_binding(
                self.context.symbol(&alias),
                TypeReference {
                    segments,
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
                    context: self.context.clone(),
                    leading_colon: node.leading_colon.is_some(),
                },
            );
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        if attributes_are_test_only(&node.attrs) {
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
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_bindings(&path.tree, prefix, out, globs);
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
            if alias != "_" {
                let mut target = prefix.clone();
                let ident = rename.ident.to_string();
                if ident != "self" {
                    target.push(ident);
                }
                out.push((alias, target));
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_bindings(item, prefix, out, globs);
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
        if let Ok(file) = syn::parse_file(&source.raw_text) {
            let mut visitor = TypeIndexVisitor {
                index: &mut index,
                context,
            };
            visitor.visit_file(&file);
        }
    }
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

fn type_reference(ty: &syn::Type, context: &ModuleContext) -> Option<TypeReference> {
    let path = innermost_type_path(ty)?;
    path_reference(path, context)
}

fn path_reference(path: &syn::Path, context: &ModuleContext) -> Option<TypeReference> {
    (!path.segments.is_empty()).then(|| TypeReference {
        segments: path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
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

#[derive(Clone)]
struct InferredValue {
    owner: String,
    mutable_place: bool,
}

#[derive(Clone, Default)]
struct LocalSymbolScope {
    bindings: BTreeMap<String, Vec<LocalSymbolBinding>>,
    glob_imports: Vec<TypeReference>,
    type_declarations: BTreeSet<String>,
    function_declarations: BTreeSet<String>,
    function_returns: BTreeMap<String, Vec<TypeReference>>,
    namespace_declarations: BTreeSet<String>,
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
        self.resolve_symbol_scoped(SymbolKind::Type, &reference)
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

    fn function_return_scoped(&self, path: &syn::Path) -> Option<String> {
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
                return self
                    .resolve_symbol_scoped_with_limit(
                        SymbolKind::Type,
                        &returns[0],
                        scope_index + 1,
                        &mut BTreeSet::new(),
                        &mut BTreeSet::new(),
                    )
                    .exact();
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
        self.types.resolve_type_reference(result)
    }

    fn block_symbol_scope(&self, block: &syn::Block) -> LocalSymbolScope {
        let mut scope = LocalSymbolScope::default();
        for statement in &block.stmts {
            let syn::Stmt::Item(item) = statement else {
                continue;
            };
            if item_attributes(item).is_some_and(attributes_are_test_only) {
                continue;
            }
            match item {
                syn::Item::Use(item_use) => {
                    let mut bindings = Vec::new();
                    let mut globs = Vec::new();
                    collect_use_bindings(
                        &item_use.tree,
                        &mut Vec::new(),
                        &mut bindings,
                        &mut globs,
                    );
                    for (alias, segments) in bindings {
                        scope
                            .bindings
                            .entry(alias)
                            .or_default()
                            .push(LocalSymbolBinding {
                                target: TypeReference {
                                    segments,
                                    context: self.context.clone(),
                                    leading_colon: item_use.leading_colon.is_some(),
                                },
                                is_import: true,
                            });
                    }
                    for segments in globs {
                        scope.glob_imports.push(TypeReference {
                            segments,
                            context: self.context.clone(),
                            leading_colon: item_use.leading_colon.is_some(),
                        });
                    }
                }
                syn::Item::Type(item_type) => {
                    let name = item_type.ident.to_string();
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
                        if let Some(result) = type_reference(ty, &self.context) {
                            scope.function_returns.entry(name).or_default().push(result);
                        }
                    }
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
                            InferredValue {
                                owner: owner.to_string(),
                                mutable_place: receiver.mutability.is_some(),
                            },
                        );
                    }
                }
                syn::FnArg::Typed(typed) => {
                    let value = self
                        .resolve_type_scoped(&typed.ty)
                        .map(|owner| InferredValue {
                            owner,
                            mutable_place: type_is_mutable_reference(&typed.ty),
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

    fn bind_pattern(&mut self, pattern: &syn::Pat, value: Option<&InferredValue>) {
        match pattern {
            syn::Pat::Ident(ident) => {
                let name = ident.ident.to_string();
                if let Some(value) = value {
                    self.environment.insert(name, value.clone());
                } else {
                    self.environment.remove(&name);
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
                let explicit = self
                    .resolve_type_scoped(&typed.ty)
                    .map(|owner| InferredValue {
                        owner,
                        mutable_place: type_is_mutable_reference(&typed.ty)
                            || value.is_some_and(|value| value.mutable_place),
                    });
                self.bind_pattern(&typed.pat, explicit.as_ref().or(value));
            }
            syn::Pat::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.bind_pattern(element, value);
                }
            }
            syn::Pat::TupleStruct(tuple) => {
                self.record_tagged_enum_match(&tuple.path);
                for element in &tuple.elems {
                    self.bind_pattern(element, value);
                }
            }
            syn::Pat::Struct(record) => {
                self.record_tagged_enum_match(&record.path);
                let pattern_owner = self
                    .resolve_path_scoped(&record.path)
                    .or_else(|| value.map(|value| value.owner.clone()));
                if let Some(pattern_owner) = pattern_owner {
                    for field in &record.fields {
                        if attributes_are_test_only(&field.attrs)
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
                                    InferredValue {
                                        owner,
                                        mutable_place: value
                                            .is_some_and(|value| value.mutable_place),
                                    }
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
            .filter_map(|(index, pattern)| matches!(pattern, syn::Pat::Rest(_)).then_some(index))
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
            self.visit_discarded_expr(expression);
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
            .filter(|field| !attributes_are_test_only(&field.attrs))
            .collect();
        let expression_fields: Vec<_> = expression
            .fields
            .iter()
            .filter(|field| !attributes_are_test_only(&field.attrs))
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

    fn visit_patterned_initializer(&mut self, pattern: &syn::Pat, expression: &syn::Expr) -> bool {
        match (pattern, expression) {
            (syn::Pat::Paren(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Reference(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
            }
            (syn::Pat::Type(pattern), _) => {
                self.visit_patterned_initializer(&pattern.pat, expression)
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
            (syn::Pat::Slice(pattern), syn::Expr::Array(expression)) => {
                let patterns: Vec<_> = pattern.elems.iter().collect();
                let expressions: Vec<_> = expression.elems.iter().collect();
                self.visit_patterned_sequence(&patterns, &expressions)
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

    fn infer_expr(&mut self, expression: &syn::Expr) -> Option<InferredValue> {
        if expr_attributes(expression).is_some_and(attributes_are_test_only) {
            return None;
        }
        match expression {
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
                    .map(|owner| InferredValue {
                        owner,
                        mutable_place: false,
                    })
            }
            syn::Expr::Field(field) => {
                let member = Self::named_member(&field.member)?;
                let owner = self.infer_expr(&field.base)?;
                let target = self.types.field_type(&owner.owner, &member);
                if self.types.fields.contains_key(&owner.owner) {
                    self.reads.insert((owner.owner, member));
                }
                target.map(|owner| InferredValue {
                    owner,
                    mutable_place: false,
                })
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
                    .map(|owner| self.types.method_receiver(&owner.owner, &method))
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
            syn::Expr::Struct(record) => {
                for field in &record.fields {
                    self.visit_field_value(field);
                }
                self.resolve_path_scoped(&record.path)
                    .map(|owner| InferredValue {
                        owner,
                        mutable_place: false,
                    })
            }
            syn::Expr::Try(tried) => self.infer_expr(&tried.expr),
            syn::Expr::Unary(unary) => self.infer_expr(&unary.expr),
            _ => {
                syn::visit::visit_expr(self, expression);
                None
            }
        }
    }

    fn infer_place_expr(&mut self, expression: &syn::Expr) -> Option<InferredValue> {
        if expr_attributes(expression).is_some_and(attributes_are_test_only) {
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
                let member = Self::named_member(&field.member)?;
                self.types
                    .field_type(&owner.owner, &member)
                    .map(|target| InferredValue {
                        owner: target,
                        mutable_place: true,
                    })
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
                    if !attributes_are_test_only(&field.attrs) {
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
            syn::Stmt::Local(local) => attributes_are_test_only(&local.attrs),
            syn::Stmt::Item(item) => item_attributes(item).is_some_and(attributes_are_test_only),
            syn::Stmt::Expr(expression, _) => {
                expr_attributes(expression).is_some_and(attributes_are_test_only)
            }
            syn::Stmt::Macro(statement) => attributes_are_test_only(&statement.attrs),
        };
        if !test_only {
            syn::visit::visit_stmt(self, node);
        }
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if !expr_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_expr(self, node);
        }
    }

    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        if !attributes_are_test_only(&node.attrs) {
            syn::visit::visit_field_value(self, node);
        }
    }

    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        if !impl_item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_impl_item(self, node);
        }
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        if !trait_item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_trait_item(self, node);
        }
    }

    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        if !foreign_item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_foreign_item(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attributes_are_test_only(&node.attrs) {
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
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let saved_owner = self.impl_owner.clone();
        self.impl_owner = self.resolve_type_scoped(&node.self_ty);
        syn::visit::visit_item_impl(self, node);
        self.impl_owner = saved_owner;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !attributes_are_test_only(&node.attrs) {
            self.visit_function(&node.sig.inputs, &node.block);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !attributes_are_test_only(&node.attrs) {
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
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let saved_environment = self.environment.clone();
        let inferred = node.init.as_ref().and_then(|init| {
            if self.visit_patterned_initializer(&node.pat, &init.expr) {
                None
            } else {
                self.infer_expr(&init.expr)
            }
        });
        self.environment = saved_environment.clone();
        if let Some(init) = &node.init {
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
                self.environment = saved_environment;
            }
        }
        self.bind_pattern(&node.pat, inferred.as_ref());
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
        let owner = self.infer_expr(&node.expr);
        self.bind_pattern(&node.pat, owner.as_ref());
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let owner = self.infer_expr(&node.expr);
        for arm in &node.arms {
            if attributes_are_test_only(&arm.attrs) {
                continue;
            }
            let saved_environment = self.environment.clone();
            self.bind_pattern(&arm.pat, owner.as_ref());
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
        if let Ok(file) = syn::parse_file(&source.raw_text) {
            let mut visitor = FieldReadVisitor::new(types, context);
            visitor.visit_file(&file);
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
    typed_reads.contains(&(owner, key.rust_field.clone()))
}

fn production_consumer_exists(consumer: &str, sources: &[&SourceFile]) -> bool {
    let segments: Vec<&str> = consumer.split("::").collect();
    let [crate_name, modules @ .., symbol] = segments.as_slice() else {
        return false;
    };
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
            && source_declares_function(&source.raw_text, symbol)
    })
}

fn source_declares_function(source: &str, symbol: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    file.items.iter().any(|item| {
        matches!(
            item,
            syn::Item::Fn(function)
                if function.sig.ident == symbol
                    && !attributes_are_test_only(&function.attrs)
        )
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
        SourceFile {
            path: PathBuf::from(path),
            raw_text: text.to_string(),
            text: crate::scan::strip_test_regions(text),
        }
    }

    fn source_with_views(path: &str, raw_text: &str, text: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from(path),
            raw_text: raw_text.to_string(),
            text: text.to_string(),
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
            let errors = verify_config_readers(&keys, &[], &sources);

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
}
