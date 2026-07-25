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
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

#[derive(Debug, Clone)]
struct TypeReference {
    segments: Vec<String>,
    context: ModuleContext,
}

#[derive(Debug, Clone)]
struct FunctionReturn {
    symbol: String,
    result: TypeReference,
}

#[derive(Default)]
struct RustTypeIndex {
    fields: BTreeMap<String, BTreeMap<String, Option<TypeReference>>>,
    types_by_name: BTreeMap<String, BTreeSet<String>>,
    enum_tags: BTreeMap<String, String>,
    enum_variants: BTreeMap<String, BTreeSet<String>>,
    function_returns: BTreeMap<String, Vec<FunctionReturn>>,
}

impl RustTypeIndex {
    fn record_type(&mut self, owner: &str, simple_name: &str) {
        self.fields.entry(owner.to_string()).or_default();
        self.types_by_name
            .entry(simple_name.to_string())
            .or_default()
            .insert(owner.to_string());
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

    fn enum_tag_for_variant_path(
        &self,
        path: &syn::Path,
        context: &ModuleContext,
    ) -> Option<(&str, &str)> {
        let mut segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let variant = segments.pop()?;
        let owner = self.resolve_path_segments(&segments, context)?;
        self.enum_variants
            .get(&owner)?
            .contains(&variant)
            .then_some(())?;
        let (owner, tag) = self.enum_tags.get_key_value(&owner)?;
        Some((owner.as_str(), tag.as_str()))
    }

    fn field_type(&self, owner: &str, field: &str) -> Option<String> {
        self.fields
            .get(owner)
            .and_then(|fields| fields.get(field))
            .and_then(Option::as_ref)
            .and_then(|reference| {
                self.resolve_path_segments(&reference.segments, &reference.context)
            })
    }

    fn resolve_type(&self, ty: &syn::Type, context: &ModuleContext) -> Option<String> {
        let reference = type_reference(ty, context)?;
        self.resolve_path_segments(&reference.segments, &reference.context)
    }

    fn resolve_path(&self, path: &syn::Path, context: &ModuleContext) -> Option<String> {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.resolve_path_segments(&segments, context)
    }

    fn resolve_path_segments(
        &self,
        segments: &[String],
        context: &ModuleContext,
    ) -> Option<String> {
        let simple_name = segments.last()?;
        let candidates = self.types_by_name.get(simple_name)?;

        if segments.len() == 1 {
            let local = context.symbol(simple_name);
            if candidates.contains(&local) {
                return Some(local);
            }
        } else {
            let first = segments.first()?.as_str();
            let mut prefixes = Vec::new();
            match first {
                "crate" => {
                    prefixes.push(
                        std::iter::once(context.crate_name.as_str())
                            .chain(segments[1..segments.len() - 1].iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("::"),
                    );
                }
                "self" => {
                    prefixes.push(
                        std::iter::once(context.crate_name.as_str())
                            .chain(context.modules.iter().map(String::as_str))
                            .chain(segments[1..segments.len() - 1].iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("::"),
                    );
                }
                "super" => {
                    let mut modules = context.modules.clone();
                    let mut skip = 0usize;
                    while segments.get(skip).is_some_and(|segment| segment == "super") {
                        modules.pop();
                        skip += 1;
                    }
                    prefixes.push(
                        std::iter::once(context.crate_name.as_str())
                            .chain(modules.iter().map(String::as_str))
                            .chain(
                                segments[skip..segments.len() - 1]
                                    .iter()
                                    .map(String::as_str),
                            )
                            .collect::<Vec<_>>()
                            .join("::"),
                    );
                }
                external => prefixes.push(
                    std::iter::once(normalize_crate_name(external))
                        .chain(segments[1..segments.len() - 1].iter().cloned())
                        .collect::<Vec<_>>()
                        .join("::"),
                ),
            }

            let exact = prefixes
                .iter()
                .map(|prefix| {
                    if prefix.is_empty() {
                        simple_name.clone()
                    } else {
                        format!("{prefix}::{simple_name}")
                    }
                })
                .filter(|candidate| candidates.contains(candidate))
                .collect::<Vec<_>>();
            if exact.len() == 1 {
                return exact.into_iter().next();
            }

            // Public re-exports often omit the defining module
            // (`sbproxy_config::Foo` vs `sbproxy_config::types::Foo`).
            // An explicit crate path still resolves safely when that crate
            // owns exactly one type with the requested simple name.
            if !matches!(first, "crate" | "self" | "super") {
                let crate_name = normalize_crate_name(first);
                let in_crate: Vec<_> = candidates
                    .iter()
                    .filter(|candidate| {
                        candidate
                            .split("::")
                            .next()
                            .is_some_and(|owner| owner == crate_name)
                    })
                    .cloned()
                    .collect();
                if in_crate.len() == 1 {
                    return in_crate.into_iter().next();
                }
            }
        }

        (candidates.len() == 1)
            .then(|| candidates.first().cloned())
            .flatten()
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

    fn function_return(&self, path: &syn::Path, context: &ModuleContext) -> Option<String> {
        let name = path.segments.last()?.ident.to_string();
        let candidates = self.function_returns.get(&name)?;
        let symbol = if path.segments.len() == 1 {
            let local = context.symbol(&name);
            candidates
                .iter()
                .find(|candidate| candidate.symbol == local)
                .map(|candidate| candidate.symbol.clone())
                .or_else(|| (candidates.len() == 1).then(|| candidates[0].symbol.clone()))?
        } else {
            let path_segments: Vec<String> = path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let first = path_segments.first()?.as_str();
            let crate_name = if first == "crate" {
                context.crate_name.clone()
            } else {
                normalize_crate_name(first)
            };
            let in_crate: Vec<_> = candidates
                .iter()
                .filter(|candidate| candidate.symbol.starts_with(&format!("{crate_name}::")))
                .collect();
            (in_crate.len() == 1).then(|| in_crate[0].symbol.clone())?
        };
        let result = &candidates
            .iter()
            .find(|candidate| candidate.symbol == symbol)?
            .result;
        self.resolve_path_segments(&result.segments, &result.context)
    }
}

struct TypeIndexVisitor<'a> {
    index: &'a mut RustTypeIndex,
    context: ModuleContext,
}

impl<'ast> Visit<'ast> for TypeIndexVisitor<'_> {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !item_attributes(node).is_some_and(attributes_are_test_only) {
            syn::visit::visit_item(self, node);
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
}

fn rust_type_index(sources: &[&SourceFile]) -> RustTypeIndex {
    let mut index = RustTypeIndex::default();
    for source in sources {
        let Some(context) = ModuleContext::from_source_path(&source.path) else {
            continue;
        };
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
    Some(TypeReference {
        segments: path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
        context: context.clone(),
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

struct FieldReadVisitor<'a> {
    types: &'a RustTypeIndex,
    reads: BTreeSet<(String, String)>,
    environment: BTreeMap<String, String>,
    impl_owner: Option<String>,
    context: ModuleContext,
}

impl<'a> FieldReadVisitor<'a> {
    fn new(types: &'a RustTypeIndex, context: ModuleContext) -> Self {
        Self {
            types,
            reads: BTreeSet::new(),
            environment: BTreeMap::new(),
            impl_owner: None,
            context,
        }
    }

    fn visit_function(
        &mut self,
        inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
        block: &syn::Block,
    ) {
        let saved_environment = std::mem::take(&mut self.environment);
        for input in inputs {
            match input {
                syn::FnArg::Receiver(_) => {
                    if let Some(owner) = &self.impl_owner {
                        self.environment
                            .insert("self".to_string(), owner.to_string());
                    }
                }
                syn::FnArg::Typed(typed) => {
                    let owner = self.types.resolve_type(&typed.ty, &self.context);
                    self.bind_pattern(&typed.pat, owner.as_deref());
                }
            }
        }
        self.visit_block(block);
        self.environment = saved_environment;
    }

    fn bind_pattern(&mut self, pattern: &syn::Pat, owner: Option<&str>) {
        match pattern {
            syn::Pat::Ident(ident) => {
                let name = ident.ident.to_string();
                if let Some(owner) = owner {
                    self.environment.insert(name, owner.to_string());
                } else {
                    self.environment.remove(&name);
                }
            }
            syn::Pat::Reference(reference) => self.bind_pattern(&reference.pat, owner),
            syn::Pat::Type(typed) => {
                let explicit = self.types.resolve_type(&typed.ty, &self.context);
                self.bind_pattern(&typed.pat, explicit.as_deref().or(owner));
            }
            syn::Pat::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.bind_pattern(element, owner);
                }
            }
            syn::Pat::TupleStruct(tuple) => {
                self.record_tagged_enum_match(&tuple.path);
                for element in &tuple.elems {
                    self.bind_pattern(element, owner);
                }
            }
            syn::Pat::Struct(record) => {
                self.record_tagged_enum_match(&record.path);
                let pattern_owner = self
                    .types
                    .resolve_path(&record.path, &self.context)
                    .or_else(|| owner.map(str::to_string));
                if let Some(pattern_owner) = pattern_owner {
                    for field in &record.fields {
                        if matches!(field.pat.as_ref(), syn::Pat::Wild(_)) {
                            continue;
                        }
                        if let Some(member) = Self::named_member(&field.member) {
                            self.reads.insert((pattern_owner.clone(), member.clone()));
                            let target = self
                                .types
                                .field_type(&pattern_owner, &member)
                                .map(|target| target.to_string());
                            self.bind_pattern(&field.pat, target.as_deref());
                        }
                    }
                }
            }
            syn::Pat::Path(path) => self.record_tagged_enum_match(&path.path),
            _ => {}
        }
    }

    fn record_tagged_enum_match(&mut self, path: &syn::Path) {
        if let Some((owner, tag)) = self.types.enum_tag_for_variant_path(path, &self.context) {
            self.reads.insert((owner.to_string(), tag.to_string()));
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

    fn infer_item_closure(
        &mut self,
        closure: &syn::ExprClosure,
        item_owner: Option<&str>,
    ) -> Option<String> {
        let saved_environment = self.environment.clone();
        for (index, input) in closure.inputs.iter().enumerate() {
            self.bind_pattern(input, (index == 0).then_some(item_owner).flatten());
        }
        let result = self.infer_expr(&closure.body);
        self.environment = saved_environment;
        result
    }

    fn infer_expr(&mut self, expression: &syn::Expr) -> Option<String> {
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
                self.types.function_return(&path.path, &self.context)
            }
            syn::Expr::Field(field) => {
                let owner = self.infer_expr(&field.base)?;
                let member = Self::named_member(&field.member)?;
                let target = self.types.field_type(&owner, &member);
                if self.types.fields.contains_key(&owner) {
                    self.reads.insert((owner, member));
                }
                target
            }
            syn::Expr::Group(group) => self.infer_expr(&group.expr),
            syn::Expr::Index(index) => {
                let owner = self.infer_expr(&index.expr);
                self.visit_expr(&index.index);
                owner
            }
            syn::Expr::MethodCall(call) => {
                let owner = self.infer_expr(&call.receiver);
                let method = call.method.to_string();
                let passes_item_to_closure = matches!(
                    method.as_str(),
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
                );
                let mut closure_result = None;
                for argument in &call.args {
                    if passes_item_to_closure {
                        if let syn::Expr::Closure(closure) = argument {
                            closure_result = self.infer_item_closure(closure, owner.as_deref());
                            continue;
                        }
                    }
                    self.visit_expr(argument);
                }
                if matches!(method.as_str(), "and_then" | "filter_map" | "map") {
                    return closure_result;
                }
                matches!(
                    method.as_str(),
                    "as_ref"
                        | "as_mut"
                        | "borrow"
                        | "borrow_mut"
                        | "chain"
                        | "clone"
                        | "copied"
                        | "enumerate"
                        | "expect"
                        | "first"
                        | "first_mut"
                        | "flatten"
                        | "fuse"
                        | "get"
                        | "get_mut"
                        | "into_iter"
                        | "iter"
                        | "iter_mut"
                        | "last"
                        | "last_mut"
                        | "next"
                        | "peekable"
                        | "rev"
                        | "skip"
                        | "filter"
                        | "inspect"
                        | "skip_while"
                        | "take"
                        | "take_while"
                        | "unwrap"
                        | "unwrap_or"
                        | "unwrap_or_default"
                        | "values"
                        | "values_mut"
                )
                .then_some(owner)
                .flatten()
            }
            syn::Expr::Paren(paren) => self.infer_expr(&paren.expr),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.environment.get(&ident.to_string()).cloned()),
            syn::Expr::Reference(reference) => self.infer_expr(&reference.expr),
            syn::Expr::Struct(record) => {
                for field in &record.fields {
                    self.visit_expr(&field.expr);
                }
                self.types.resolve_path(&record.path, &self.context)
            }
            syn::Expr::Try(tried) => self.infer_expr(&tried.expr),
            syn::Expr::Unary(unary) => self.infer_expr(&unary.expr),
            _ => {
                syn::visit::visit_expr(self, expression);
                None
            }
        }
    }
}

impl<'ast> Visit<'ast> for FieldReadVisitor<'_> {
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
        self.impl_owner = self.types.resolve_type(&node.self_ty, &self.context);
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
        // can still contain genuine config reads.
        self.visit_expr(&node.right);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let _ = self.infer_expr(&syn::Expr::MethodCall(node.clone()));
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        let inferred = node
            .init
            .as_ref()
            .and_then(|init| self.infer_expr(&init.expr));
        self.bind_pattern(&node.pat, inferred.as_deref());
        if let Some(init) = &node.init {
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        let saved_environment = self.environment.clone();
        syn::visit::visit_block(self, node);
        self.environment = saved_environment;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let owner = self.infer_expr(&node.expr);
        let saved_environment = self.environment.clone();
        self.bind_pattern(&node.pat, owner.as_deref());
        self.visit_block(&node.body);
        self.environment = saved_environment;
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        let owner = self.infer_expr(&node.expr);
        self.bind_pattern(&node.pat, owner.as_deref());
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let owner = self.infer_expr(&node.expr);
        for arm in &node.arms {
            let saved_environment = self.environment.clone();
            self.bind_pattern(&arm.pat, owner.as_deref());
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.environment = saved_environment;
        }
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
