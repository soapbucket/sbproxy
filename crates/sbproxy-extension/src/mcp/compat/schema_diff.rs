//! A focused JSON-Schema diff over a tool's `inputSchema` or `outputSchema`.
//!
//! Self-contained (no dependency on the drift engines elsewhere) and narrow: it
//! compares the property set, the required set, property types, and enum sets.
//! The variance grading in [`super::structural`] turns these changes into a
//! semver grade, applying the opposite variance to inputs and outputs.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// One property-level change inside a JSON Schema.
#[derive(Debug, Clone, PartialEq)]
pub enum SchemaChange {
    /// A property was added.
    PropertyAdded(String),
    /// A property was removed.
    PropertyRemoved(String),
    /// A property became required.
    RequiredAdded(String),
    /// A property stopped being required.
    RequiredRemoved(String),
    /// A property's declared type changed.
    TypeChanged {
        /// Property name.
        path: String,
        /// Previous type token.
        old: String,
        /// New type token.
        new: String,
    },
    /// A property's enum gained values (accepts more).
    EnumWidened(String),
    /// A property's enum lost values (accepts fewer).
    EnumNarrowed(String),
}

/// Diff two JSON Schemas, returning the property-level changes. An absent or
/// non-object schema is treated as empty.
pub fn diff_schema(old: &Value, new: &Value) -> Vec<SchemaChange> {
    let old_props = properties(old);
    let new_props = properties(new);
    let mut out = Vec::new();

    for name in new_props.keys() {
        if !old_props.contains_key(name) {
            out.push(SchemaChange::PropertyAdded(name.clone()));
        }
    }
    for (name, old_schema) in &old_props {
        let Some(new_schema) = new_props.get(name) else {
            out.push(SchemaChange::PropertyRemoved(name.clone()));
            continue;
        };
        if let (Some(old_ty), Some(new_ty)) = (type_of(old_schema), type_of(new_schema)) {
            if old_ty != new_ty {
                out.push(SchemaChange::TypeChanged {
                    path: name.clone(),
                    old: old_ty,
                    new: new_ty,
                });
            }
        }
        match enum_delta(old_schema, new_schema) {
            EnumDelta::Widened => out.push(SchemaChange::EnumWidened(name.clone())),
            EnumDelta::Narrowed => out.push(SchemaChange::EnumNarrowed(name.clone())),
            EnumDelta::Same => {}
        }
    }

    let old_req = required(old);
    let new_req = required(new);
    for name in new_req.difference(&old_req) {
        out.push(SchemaChange::RequiredAdded(name.clone()));
    }
    for name in old_req.difference(&new_req) {
        out.push(SchemaChange::RequiredRemoved(name.clone()));
    }
    out
}

fn properties(schema: &Value) -> BTreeMap<String, Value> {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn required(schema: &Value) -> BTreeSet<String> {
    schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn type_of(schema: &Value) -> Option<String> {
    schema
        .get("type")
        .and_then(|t| t.as_str())
        .map(String::from)
}

enum EnumDelta {
    Same,
    Widened,
    Narrowed,
}

fn enum_delta(old: &Value, new: &Value) -> EnumDelta {
    let old_enum = old.get("enum");
    let new_enum = new.get("enum");
    match (old_enum, new_enum) {
        (None, None) => EnumDelta::Same,
        // Dropping the enum constraint accepts more; adding one accepts fewer.
        (Some(_), None) => EnumDelta::Widened,
        (None, Some(_)) => EnumDelta::Narrowed,
        (Some(_), Some(_)) => {
            let o = enum_set(old);
            let n = enum_set(new);
            if o == n {
                EnumDelta::Same
            } else if o.is_subset(&n) {
                EnumDelta::Widened
            } else {
                EnumDelta::Narrowed
            }
        }
    }
}

fn enum_set(schema: &Value) -> BTreeSet<String> {
    schema
        .get("enum")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().map(|v| v.to_string()).collect())
        .unwrap_or_default()
}
