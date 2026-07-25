//! Pure config merge engine for the config authority.
//!
//! [`merge_config`] folds a remote, authority-supplied YAML document into
//! a locally owned base YAML document and reports where every leaf in the
//! result came from. It is deliberately a pure function: no filesystem, no
//! network, no globals, no dependency on a compiled config, and no
//! knowledge of how either document was obtained. Git resolution happens
//! elsewhere and produces the base document; the caller passes the
//! resulting [`BaseOrigin`] tag in and this function only propagates it.
//!
//! # What the caller gets
//!
//! A [`MergeOutcome`] with the merged YAML text and a [`ProvenanceMap`]
//! from dotted leaf path (`origins.api.timeout`) to the [`Provenance`] of
//! that leaf. Provenance is what lets an operator answer "who set this?"
//! without re-running the merge.
//!
//! # Merge semantics
//!
//! Committed to here, and each one covered by a test in this module:
//!
//! - Nested maps merge recursively. A key that holds a map in both
//!   documents descends; it is not replaced wholesale.
//! - Sequences replace wholesale. They are never element-merged and never
//!   concatenated, because element identity in a YAML list is not
//!   knowable to a generic merge and guessing at it produces silent
//!   duplicates.
//! - An explicit `null` in the remote document sets the key to null. It
//!   does not delete the key and does not mean "absent". There is no
//!   delete verb in this merge.
//! - A key present in the base and absent from the remote keeps the base
//!   value under [`MergeMode::Overlay`], and is discarded under
//!   [`MergeMode::Replace`] unless it sits at or under a deny-listed
//!   path.
//! - Non-map YAML at the document root of either input is a
//!   [`MergeError`], never a panic. A blank document (empty, whitespace,
//!   comments, or a bare `---`) counts as an empty mapping, since there
//!   is nothing in it to conflict with. An explicit `null` document root
//!   is an error: that is a malformed document rather than an empty one.
//!
//! # The deny list
//!
//! [`AUTHORITY_DENIED_PATHS`] names the config paths the subscriber owns
//! outright. Presence of one of them anywhere in the remote document
//! rejects the whole merge. Two rules make that hold:
//!
//! 1. Detection walks the remote document looking for the presence of a
//!    denied path. It does not diff the merge result. A remote value that
//!    happens to equal the base value is still a rejection, because it is
//!    the authority's claim on the key that is denied, not a change to
//!    the key's value.
//! 2. After merging, every denied path is restored unconditionally from
//!    the base document: present in the base means present with the base
//!    value, absent from the base means absent. Rule 1 already rejects a
//!    remote that names a denied path, so this only bites when a remote
//!    wipes an *ancestor* of one, for example `proxy: null` or, in
//!    replace mode, a `proxy` block that simply omits `proxy.tls`. The
//!    denied subtree comes back and its ancestor is re-materialized as a
//!    mapping.
//!
//! Rejection is total. A denied path is never silently dropped and never
//! partially applied, and the error names every offending path rather
//! than the first one. Silent-drop behavior in config import is a bug
//! this repo has already paid for once in the LiteLLM importer, which
//! carries a gate for exactly this reason.
//!
//! # Round-trip caveat
//!
//! The merge parses both documents into `serde_yaml::Value`, merges the
//! trees, and re-serializes. Comments and original key ordering are lost.
//! That is expected rather than a regression: the `compile_config` path
//! already does the same round-trip on every boot in its
//! `migrate_features_to_extensions` step. Ordering in the output is still
//! deterministic. Base keys keep their relative order and remote-only
//! keys follow in remote order.
//!
//! Dotted provenance paths are for display and audit. A YAML key that
//! itself contains a dot (an origin hostname, say) produces an ambiguous
//! dotted string. Deny-list matching never uses those strings; it walks
//! the tree structurally, key by key, so the ambiguity cannot widen or
//! narrow what is denied.
//!
//! Recursion here is bounded by the YAML parser, which refuses documents
//! nested deeper than 128 levels, so neither the merge walk nor the
//! provenance walk can be driven into a stack overflow by a hostile
//! bundle.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

/// Config paths the subscriber owns outright. A remote document that
/// names any of these is rejected in full.
///
/// Declared once, here, so no downstream consumer can drift from it.
/// Everything on the list describes the box rather than the fleet, so an
/// authority pushing one machine's answer to every subscriber is always
/// wrong:
///
/// - `proxy.cluster`: node identity, gossip seeds, and advertise
///   addresses are per-node facts. One fleet-wide value would hand every
///   member the same identity.
/// - `proxy.admin`: the admin listener, its credentials, and its IP
///   allowlist are how an operator reaches the box when the fleet is
///   misbehaving. That path must not itself be reachable from the fleet.
/// - `proxy.listeners`: which ports this machine binds is a property of
///   the machine and its network, not of the config being distributed.
/// - `proxy.tls`: certificate and key material lives on the box. A
///   remote document has no business naming local key paths.
/// - `proxy.secrets`: secret backends and their addressing are local
///   trust configuration. Repointing them remotely repoints every
///   credential the proxy resolves.
/// - `proxy.config_authority`: a bundle that could repoint the
///   subscriber at a different authority, or disable signature
///   verification, defeats the entire design. The subscriber decides who
///   it listens to.
/// - `proxy.model_host`: signed deployment bundles already own that
///   state through their own channel. Two signed writers on one piece of
///   state is a correctness hazard, so this channel declines it.
/// - `source`: the authority overlays the base document. It does not get
///   to choose which repository the base document comes from, which
///   would let it swap out its own input.
pub const AUTHORITY_DENIED_PATHS: &[&str] = &[
    "proxy.cluster",
    "proxy.admin",
    "proxy.listeners",
    "proxy.tls",
    "proxy.secrets",
    "proxy.config_authority",
    "proxy.model_host",
    "source",
];

/// Where the base document came from, as determined by the caller.
///
/// The merge engine never resolves git itself. Whatever produced the base
/// document tags it here, and the tag is copied onto every leaf the
/// merged document takes from the base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseOrigin {
    /// The base document came from a local file on this machine.
    Local,
    /// The base document came from a git repository, already resolved.
    Git {
        /// Repository the base document was read from.
        repo: String,
        /// Branch, tag, or other reference that was requested.
        reference: String,
        /// Commit the reference resolved to when the document was read.
        commit: String,
    },
}

impl BaseOrigin {
    /// The [`Provenance`] recorded for leaves that came from this base.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        match self {
            Self::Local => Provenance::Local,
            Self::Git {
                repo,
                reference,
                commit,
            } => Provenance::Git {
                repo: repo.clone(),
                reference: reference.clone(),
                commit: commit.clone(),
            },
        }
    }
}

/// Where a single leaf in the merged document came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// The leaf came from a base document read from a local file.
    Local,
    /// The leaf came from a base document read from a git repository.
    Git {
        /// Repository the base document was read from.
        repo: String,
        /// Branch, tag, or other reference that was requested.
        reference: String,
        /// Commit the reference resolved to when the document was read.
        commit: String,
    },
    /// The leaf came from the remote document supplied by the authority.
    Authority,
}

/// Dotted leaf path to [`Provenance`] for every leaf in a merged
/// document.
///
/// A leaf is any value that is not a non-empty mapping: scalars, nulls,
/// sequences (which merge wholesale, so their elements are not walked),
/// and empty mappings. An empty mapping counts as a leaf because it
/// carries a value even though it has no children, and skipping it would
/// make the key invisible in an audit.
///
/// Paths are joined with `.`. See the module documentation for the
/// ambiguity a key containing a dot introduces, and for why it cannot
/// affect deny-list enforcement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMap(BTreeMap<String, Provenance>);

impl ProvenanceMap {
    /// Provenance recorded for `path`, or `None` when the merged
    /// document has no leaf there.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Provenance> {
        self.0.get(path)
    }

    /// Number of leaves recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no leaves were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every recorded `(path, provenance)` pair, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Provenance)> {
        self.0.iter()
    }

    /// Every recorded path, in path order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Consume the map and return the underlying path-to-provenance
    /// mapping.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<String, Provenance> {
        self.0
    }
}

/// How the remote document combines with the base document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMode {
    /// The base document is the base and the remote document merges on
    /// top of it, remote winning key by key. Base keys the remote does
    /// not mention survive. The default, and the conservative choice.
    #[default]
    Overlay,
    /// The remote document is the base. Deny-listed paths are grafted in
    /// from the base document and every other base key is discarded.
    Replace,
}

/// A completed merge.
#[derive(Debug, Clone)]
pub struct MergeOutcome {
    /// The merged document, re-serialized as YAML. Comments and original
    /// key order from the inputs are not preserved.
    pub merged_yaml: String,
    /// Where each leaf in `merged_yaml` came from.
    pub provenance: ProvenanceMap,
}

/// Why a merge could not be performed.
#[derive(Debug, thiserror::Error)]
pub enum MergeError {
    /// The remote document names one or more paths the subscriber owns.
    /// Every offending path is listed, and the merge is rejected in full
    /// rather than applied with the denied keys stripped out.
    #[error("config authority merge rejected: remote sets denied path(s): {}", .0.join(", "))]
    DeniedPaths(Vec<String>),
    /// The base document's root was not a YAML mapping.
    #[error("config authority merge rejected: the base document root must be a YAML mapping")]
    BaseNotMapping,
    /// The remote document's root was not a YAML mapping.
    #[error("config authority merge rejected: the remote document root must be a YAML mapping")]
    RemoteNotMapping,
    /// One of the documents, or the merged result, was not valid YAML.
    #[error("config authority merge failed on YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Merge an authority-supplied `remote_yaml` document into a locally
/// owned `base_yaml` document.
///
/// `base_origin` tags where the base document came from and is copied
/// onto every leaf the result takes from the base. `mode` selects overlay
/// or replace semantics. See the module documentation for the full merge
/// semantics and for what the deny list protects.
///
/// # Errors
///
/// Returns [`MergeError::DeniedPaths`] when the remote document names any
/// of [`AUTHORITY_DENIED_PATHS`], listing all of them.
/// [`MergeError::BaseNotMapping`] or [`MergeError::RemoteNotMapping`]
/// when the corresponding document's root is not a mapping. And
/// [`MergeError::Yaml`] when a document does not parse or the result does
/// not serialize.
pub fn merge_config(
    base_yaml: &str,
    base_origin: BaseOrigin,
    remote_yaml: &str,
    mode: MergeMode,
) -> Result<MergeOutcome, MergeError> {
    let base = parse_root(base_yaml)?.ok_or(MergeError::BaseNotMapping)?;
    let remote = parse_root(remote_yaml)?.ok_or(MergeError::RemoteNotMapping)?;

    // Walk the REMOTE document for the presence of denied paths. This is
    // deliberately not a diff of the merge result: a remote value equal
    // to the base value is still a claim on a key the subscriber owns.
    let denied = scan_denied(&remote);
    if !denied.is_empty() {
        return Err(MergeError::DeniedPaths(denied));
    }

    let mut merged = match mode {
        MergeMode::Overlay => deep_merge(&base, &remote),
        MergeMode::Replace => remote.clone(),
    };
    // Belt and suspenders over the scan above. The scan rejects a remote
    // that names a denied path; this pass also undoes a remote that wiped
    // an ancestor of one.
    restore_denied(&mut merged, &base);

    let context = ProvenanceContext {
        remote: &remote,
        base: base_origin.provenance(),
    };
    let mut provenance = BTreeMap::new();
    let mut trail = Vec::new();
    record_provenance(&context, &merged, &mut trail, &mut provenance);

    let merged_yaml = serde_yaml::to_string(&Value::Mapping(merged))?;
    Ok(MergeOutcome {
        merged_yaml,
        provenance: ProvenanceMap(provenance),
    })
}

/// Parse a document root. `Ok(None)` means the document parsed but its
/// root was not a mapping, which the caller turns into the error variant
/// naming the offending document.
fn parse_root(yaml: &str) -> Result<Option<Mapping>, serde_yaml::Error> {
    if is_blank_document(yaml) {
        return Ok(Some(Mapping::new()));
    }
    let root: Value = serde_yaml::from_str(yaml)?;
    match root {
        Value::Mapping(map) => Ok(Some(map)),
        _ => Ok(None),
    }
}

/// Whether a document carries no content at all. Checked textually so the
/// answer does not depend on how the parser represents an empty stream.
fn is_blank_document(yaml: &str) -> bool {
    yaml.lines().all(|line| {
        let trimmed = line.trim();
        trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" || trimmed == "..."
    })
}

/// Every deny-listed path present in `remote`, in deny-list order.
fn scan_denied(remote: &Mapping) -> Vec<String> {
    AUTHORITY_DENIED_PATHS
        .iter()
        .filter(|path| lookup_path(remote, &split_path(path)).is_some())
        .map(|path| (*path).to_string())
        .collect()
}

/// Recursively merge `remote` on top of `base`. Base keys keep their
/// relative order and remote-only keys follow, so the output is stable.
fn deep_merge(base: &Mapping, remote: &Mapping) -> Mapping {
    let mut out = Mapping::with_capacity(base.len() + remote.len());
    for (key, base_value) in base {
        let Some(remote_value) = remote.get(key) else {
            out.insert(key.clone(), base_value.clone());
            continue;
        };
        // Two mappings descend. Anything else, including a sequence and
        // an explicit null, is taken from the remote wholesale.
        match (base_value.as_mapping(), remote_value.as_mapping()) {
            (Some(base_map), Some(remote_map)) => {
                let merged = deep_merge(base_map, remote_map);
                out.insert(key.clone(), Value::Mapping(merged));
            }
            _ => {
                out.insert(key.clone(), remote_value.clone());
            }
        }
    }
    for (key, remote_value) in remote {
        if !base.contains_key(key) {
            out.insert(key.clone(), remote_value.clone());
        }
    }
    out
}

/// Force every deny-listed path in `merged` back to whatever the base
/// document says, including forcing it absent when the base has no value
/// there.
fn restore_denied(merged: &mut Mapping, base: &Mapping) {
    for path in AUTHORITY_DENIED_PATHS {
        let segments = split_path(path);
        match lookup_path(base, &segments) {
            Some(value) => set_path(merged, &segments, value.clone()),
            None => remove_path(merged, &segments),
        }
    }
}

fn split_path(path: &str) -> Vec<&str> {
    path.split('.').collect()
}

/// Look a dotted path up by string segments.
fn lookup_path<'a>(root: &'a Mapping, segments: &[&str]) -> Option<&'a Value> {
    let (last, parents) = segments.split_last()?;
    let mut map = root;
    for segment in parents {
        map = map.get(*segment)?.as_mapping()?;
    }
    map.get(*last)
}

/// Look a path up by its actual key values, so a key containing a dot
/// cannot be confused with a nesting level.
fn lookup_keys<'a>(root: &'a Mapping, trail: &[Value]) -> Option<&'a Value> {
    let (last, parents) = trail.split_last()?;
    let mut map = root;
    for key in parents {
        map = map.get(key)?.as_mapping()?;
    }
    map.get(last)
}

/// Write `value` at `segments`, creating intermediate mappings and
/// overwriting any non-mapping ancestor found on the way down. A denied
/// path is not negotiable, so an ancestor the remote nulled out is
/// re-materialized rather than honored.
fn set_path(root: &mut Mapping, segments: &[&str], value: Value) {
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut map = root;
    for segment in parents {
        let key = Value::String((*segment).to_string());
        let slot = map
            .entry(key)
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if !slot.is_mapping() {
            *slot = Value::Mapping(Mapping::new());
        }
        let Value::Mapping(inner) = slot else {
            unreachable!("the slot was just normalized to a mapping")
        };
        map = inner;
    }
    map.insert(Value::String((*last).to_string()), value);
}

/// Remove whatever sits at `segments`. A missing or non-mapping ancestor
/// means there is nothing there, so this is a no-op rather than an error.
/// Ancestors that end up empty are left in place: the merge neither
/// invents structure nor prunes it.
fn remove_path(root: &mut Mapping, segments: &[&str]) {
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut map = root;
    for segment in parents {
        let Some(inner) = map.get_mut(*segment).and_then(Value::as_mapping_mut) else {
            return;
        };
        map = inner;
    }
    map.shift_remove(*last);
}

/// Inputs the provenance walk needs at every leaf.
struct ProvenanceContext<'a> {
    /// The parsed remote document, used to answer "did the authority set
    /// a value at this exact path?".
    remote: &'a Mapping,
    /// Provenance recorded for leaves that did not come from the remote.
    base: Provenance,
}

/// Walk the merged document and record one entry per leaf.
fn record_provenance(
    context: &ProvenanceContext<'_>,
    merged: &Mapping,
    trail: &mut Vec<Value>,
    out: &mut BTreeMap<String, Provenance>,
) {
    for (key, value) in merged {
        trail.push(key.clone());
        match value.as_mapping() {
            Some(inner) if !inner.is_empty() => record_provenance(context, inner, trail, out),
            _ => {
                out.insert(dotted_path(trail), leaf_provenance(context, trail));
            }
        }
        trail.pop();
    }
}

/// Decide where a single leaf came from.
///
/// Deny-listed paths were restored from the base, so they are base by
/// construction. Everywhere else the merged value is the remote's when
/// the remote has a value at that exact path and the base's otherwise,
/// which is what both merge modes produce.
fn leaf_provenance(context: &ProvenanceContext<'_>, trail: &[Value]) -> Provenance {
    if is_denied_trail(trail) {
        return context.base.clone();
    }
    if lookup_keys(context.remote, trail).is_some() {
        Provenance::Authority
    } else {
        context.base.clone()
    }
}

/// Whether `trail` sits at, or anywhere under, a deny-listed path.
/// Compared segment by segment against the real key values rather than
/// against a joined string.
fn is_denied_trail(trail: &[Value]) -> bool {
    AUTHORITY_DENIED_PATHS.iter().any(|path| {
        let segments = split_path(path);
        trail.len() >= segments.len()
            && segments
                .iter()
                .zip(trail.iter())
                .all(|(segment, key)| key.as_str() == Some(*segment))
    })
}

fn dotted_path(trail: &[Value]) -> String {
    trail.iter().map(path_segment).collect::<Vec<_>>().join(".")
}

/// Render one key as a path segment. Non-scalar keys are legal YAML but
/// have no sensible dotted form, so they get a placeholder rather than a
/// misleading rendering.
fn path_segment(key: &Value) -> String {
    match key {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Null => "null".to_string(),
        Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => "<non-scalar key>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [MergeMode; 2] = [MergeMode::Overlay, MergeMode::Replace];

    const SIMPLE_BASE: &str = "proxy:\n  http_bind_port: 8080\n";
    const ONE_ORIGIN: &str = "origins:\n  api:\n    url: https://one.example.com\n";
    const TWO_ORIGIN: &str = "origins:\n  api:\n    url: https://two.example.com\n";

    fn local() -> BaseOrigin {
        BaseOrigin::Local
    }

    fn git() -> BaseOrigin {
        BaseOrigin::Git {
            repo: "git@github.com:soapbucket/fleet-config.git".to_string(),
            reference: "main".to_string(),
            commit: "9f1c0de5c4a24b6f8d3e7a10b5c9d2f4e6a8b0c1".to_string(),
        }
    }

    fn merge(base: &str, remote: &str, mode: MergeMode) -> MergeOutcome {
        merge_config(base, local(), remote, mode).expect("merge should succeed")
    }

    /// Reparse a merge result so assertions run against the YAML that was
    /// actually emitted, not against an in-memory tree.
    fn merged_tree(outcome: &MergeOutcome) -> Value {
        serde_yaml::from_str(&outcome.merged_yaml).expect("merged output must be valid YAML")
    }

    fn at<'a>(tree: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = tree;
        for segment in path.split('.') {
            current = current.as_mapping()?.get(segment)?;
        }
        Some(current)
    }

    /// Build a document that sets `path` to `true`, nesting one mapping
    /// per dotted segment.
    fn nested_yaml(path: &str) -> String {
        let segments = split_path(path);
        let mut out = String::new();
        for (depth, segment) in segments.iter().enumerate() {
            out.push_str(&"  ".repeat(depth));
            out.push_str(segment);
            if depth + 1 == segments.len() {
                out.push_str(": true\n");
            } else {
                out.push_str(":\n");
            }
        }
        out
    }

    fn denied_paths(error: MergeError) -> Vec<String> {
        match error {
            MergeError::DeniedPaths(paths) => paths,
            other => panic!("expected a denied-path rejection, got {other}"),
        }
    }

    // --- deny list ----------------------------------------------------

    #[test]
    fn every_denied_path_is_rejected_at_its_own_level_in_both_modes() {
        for path in AUTHORITY_DENIED_PATHS {
            for mode in MODES {
                let remote = nested_yaml(path);
                let error = merge_config(SIMPLE_BASE, local(), &remote, mode)
                    .expect_err("a denied path must be rejected");
                assert_eq!(
                    denied_paths(error),
                    vec![(*path).to_string()],
                    "{path} in {mode:?}"
                );
            }
        }
    }

    #[test]
    fn every_denied_path_is_rejected_one_level_deeper_in_both_modes() {
        for path in AUTHORITY_DENIED_PATHS {
            let deeper = format!("{path}.password");
            for mode in MODES {
                let remote = nested_yaml(&deeper);
                let error = merge_config(SIMPLE_BASE, local(), &remote, mode)
                    .expect_err("a nested denied path must be rejected");
                assert_eq!(
                    denied_paths(error),
                    vec![(*path).to_string()],
                    "presence of the parent is what is denied: {deeper} in {mode:?}"
                );
            }
        }
    }

    #[test]
    fn a_denied_path_set_to_an_empty_mapping_is_still_rejected() {
        for mode in MODES {
            let error = merge_config("proxy: {}\n", local(), "proxy:\n  admin: {}\n", mode)
                .expect_err("an empty denied block is still a claim on the key");
            assert_eq!(
                denied_paths(error),
                vec!["proxy.admin".to_string()],
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_denied_path_set_to_null_is_still_rejected() {
        for mode in MODES {
            let error = merge_config("proxy: {}\n", local(), "proxy:\n  tls: null\n", mode)
                .expect_err("nulling a denied key is still naming it");
            assert_eq!(
                denied_paths(error),
                vec!["proxy.tls".to_string()],
                "{mode:?}"
            );
        }
    }

    #[test]
    fn every_offending_path_is_named_not_just_the_first() {
        let remote = "\
source:
  repo: git@example.com:evil/config.git
proxy:
  admin:
    password: hunter2
  cluster:
    cluster_id: elsewhere
  model_host:
    authority: admin_managed
";
        for mode in MODES {
            let error = merge_config("proxy: {}\n", local(), remote, mode)
                .expect_err("four denied paths must be rejected");
            assert_eq!(
                denied_paths(error),
                vec![
                    "proxy.cluster".to_string(),
                    "proxy.admin".to_string(),
                    "proxy.model_host".to_string(),
                    "source".to_string(),
                ],
                "all offending paths, in deny-list order, in {mode:?}"
            );
        }
    }

    #[test]
    fn the_error_message_names_every_offending_path() {
        let remote = "source: local\nproxy:\n  admin:\n    enabled: true\n";
        let error = merge_config("proxy: {}\n", local(), remote, MergeMode::Overlay)
            .expect_err("two denied paths");
        let rendered = error.to_string();
        assert!(rendered.contains("proxy.admin"), "{rendered}");
        assert!(rendered.contains("source"), "{rendered}");
    }

    #[test]
    fn a_denied_value_identical_to_the_base_is_still_rejected() {
        // Detection walks the remote for presence, so a no-op value is
        // still a rejection. Diffing the merge result would let this
        // through, which is the bug this test pins.
        let document = "proxy:\n  admin:\n    enabled: true\n    port: 9090\n";
        for mode in MODES {
            let error = merge_config(document, local(), document, mode)
                .expect_err("presence is denied, not change");
            assert_eq!(
                denied_paths(error),
                vec!["proxy.admin".to_string()],
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_non_denied_sibling_of_a_denied_path_is_allowed() {
        let base = "proxy:\n  admin:\n    port: 9090\n  http_bind_port: 8080\n";
        let outcome = merge(base, "proxy:\n  http_bind_port: 9999\n", MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "proxy.http_bind_port"), Some(&Value::from(9999)));
        assert_eq!(at(&tree, "proxy.admin.port"), Some(&Value::from(9090)));
    }

    #[test]
    fn replace_mode_grafts_denied_paths_back_in_from_the_base() {
        let base = "\
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
origins:
  api:
    url: https://one.example.com
";
        let outcome = merge(base, TWO_ORIGIN, MergeMode::Replace);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "proxy.admin.port"), Some(&Value::from(9090)));
        assert_eq!(
            at(&tree, "proxy.http_bind_port"),
            None,
            "replace discards non-denied base keys"
        );
        assert_eq!(
            at(&tree, "origins.api.url"),
            Some(&Value::from("https://two.example.com"))
        );
    }

    #[test]
    fn a_denied_path_absent_from_the_base_stays_absent() {
        for mode in MODES {
            let outcome = merge(ONE_ORIGIN, TWO_ORIGIN, mode);
            let tree = merged_tree(&outcome);
            assert_eq!(at(&tree, "proxy.admin"), None, "{mode:?}");
            assert_eq!(at(&tree, "proxy"), None, "{mode:?}");
        }
    }

    #[test]
    fn wiping_an_ancestor_does_not_wipe_the_denied_subtree() {
        // `proxy` itself is not deny-listed, so a remote may set it. The
        // restore pass has to put the denied children back regardless.
        let base = "proxy:\n  admin:\n    port: 9090\n  http_bind_port: 8080\n";
        let cases = [
            (MergeMode::Overlay, "proxy: null\n"),
            (MergeMode::Replace, "proxy: null\n"),
            (MergeMode::Replace, "proxy:\n  http_bind_port: 9999\n"),
        ];
        for (mode, remote) in cases {
            let outcome = merge(base, remote, mode);
            let tree = merged_tree(&outcome);
            assert_eq!(
                at(&tree, "proxy.admin.port"),
                Some(&Value::from(9090)),
                "{mode:?} with remote {remote:?}"
            );
        }
    }

    #[test]
    fn a_denied_path_hidden_behind_a_yaml_merge_key_cannot_take_effect() {
        // The parser expands aliases but does not resolve the `<<` merge
        // key, so `proxy.admin` is not literally present and the scan
        // does not fire. This is exactly the case the restore pass
        // exists for: the base value wins anyway.
        let base = "proxy:\n  admin:\n    password: local-only\n";
        let remote = "\
defaults: &defaults
  admin:
    password: fleet-wide
proxy:
  <<: *defaults
";
        for mode in MODES {
            let outcome = merge(base, remote, mode);
            let tree = merged_tree(&outcome);
            assert_eq!(
                at(&tree, "proxy.admin.password"),
                Some(&Value::from("local-only")),
                "{mode:?}: the local credential must survive"
            );
        }
    }

    // --- deep-merge semantics -----------------------------------------

    #[test]
    fn nested_maps_merge_recursively() {
        let base = "\
origins:
  api:
    url: https://one.example.com
    timeout: 30
  web:
    url: https://web.example.com
";
        let remote = "origins:\n  api:\n    timeout: 5\n";
        let outcome = merge(base, remote, MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "origins.api.timeout"), Some(&Value::from(5)));
        assert_eq!(
            at(&tree, "origins.api.url"),
            Some(&Value::from("https://one.example.com")),
            "a sibling the remote did not mention survives"
        );
        assert_eq!(
            at(&tree, "origins.web.url"),
            Some(&Value::from("https://web.example.com")),
            "an untouched branch survives"
        );
    }

    #[test]
    fn sequences_replace_wholesale_and_are_never_concatenated() {
        let base = "origins:\n  api:\n    allowed_methods: [GET, POST, DELETE]\n";
        let remote = "origins:\n  api:\n    allowed_methods: [PUT]\n";
        for mode in MODES {
            let outcome = merge(base, remote, mode);
            let tree = merged_tree(&outcome);
            let methods = at(&tree, "origins.api.allowed_methods")
                .and_then(Value::as_sequence)
                .expect("sequence present");
            assert_eq!(
                methods,
                &vec![Value::from("PUT")],
                "{mode:?}: the remote list replaces the base list outright"
            );
        }
    }

    #[test]
    fn an_empty_remote_sequence_replaces_a_populated_base_sequence() {
        let base = "origins:\n  api:\n    allowed_methods: [GET]\n";
        let remote = "origins:\n  api:\n    allowed_methods: []\n";
        let outcome = merge(base, remote, MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        let methods = at(&tree, "origins.api.allowed_methods")
            .and_then(Value::as_sequence)
            .expect("sequence present");
        assert!(
            methods.is_empty(),
            "an empty list is a value, not an absence"
        );
    }

    #[test]
    fn a_sequence_replaces_a_mapping_and_a_mapping_replaces_a_sequence() {
        let outcome = merge("a:\n  b: 1\n", "a:\n  - one\n", MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        assert!(matches!(at(&tree, "a"), Some(Value::Sequence(_))));

        let outcome = merge("a:\n  - one\n", "a:\n  b: 1\n", MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "a.b"), Some(&Value::from(1)));
    }

    #[test]
    fn an_explicit_null_sets_the_key_to_null_rather_than_removing_it() {
        let base = "origins:\n  api:\n    url: https://one.example.com\n    timeout: 30\n";
        let remote = "origins:\n  api:\n    timeout: null\n";
        let outcome = merge(base, remote, MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        let api = at(&tree, "origins.api")
            .and_then(Value::as_mapping)
            .expect("api block");
        assert!(
            api.contains_key("timeout"),
            "the key stays present; there is no delete verb"
        );
        assert_eq!(api.get("timeout"), Some(&Value::Null));
        assert_eq!(
            api.get("url"),
            Some(&Value::from("https://one.example.com")),
            "nulling one key does not touch its siblings"
        );
    }

    #[test]
    fn a_null_in_the_base_is_overwritten_by_a_remote_value() {
        let outcome = merge("a:\n  b: null\n", "a:\n  b: 7\n", MergeMode::Overlay);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "a.b"), Some(&Value::from(7)));
    }

    #[test]
    fn a_base_key_absent_from_the_remote_is_kept_by_overlay_and_dropped_by_replace() {
        let base = "origins:\n  api:\n    url: https://one.example.com\nkept: 1\n";

        let overlay = merged_tree(&merge(base, TWO_ORIGIN, MergeMode::Overlay));
        assert_eq!(at(&overlay, "kept"), Some(&Value::from(1)));

        let replace = merged_tree(&merge(base, TWO_ORIGIN, MergeMode::Replace));
        assert_eq!(at(&replace, "kept"), None);
        assert_eq!(
            at(&replace, "origins.api.url"),
            Some(&Value::from("https://two.example.com"))
        );
    }

    #[test]
    fn a_remote_only_key_is_added_in_both_modes() {
        for mode in MODES {
            let outcome = merge("a: 1\n", "b: 2\n", mode);
            let tree = merged_tree(&outcome);
            assert_eq!(at(&tree, "b"), Some(&Value::from(2)), "{mode:?}");
        }
    }

    // --- empty and malformed documents ---------------------------------

    #[test]
    fn an_empty_remote_document_leaves_the_base_alone_under_overlay() {
        let base = "proxy:\n  http_bind_port: 8080\norigins:\n  api:\n    url: https://x.test\n";
        for remote in ["", "   \n", "# just a comment\n", "---\n"] {
            let outcome = merge(base, remote, MergeMode::Overlay);
            let tree = merged_tree(&outcome);
            assert_eq!(
                at(&tree, "origins.api.url"),
                Some(&Value::from("https://x.test")),
                "empty remote {remote:?}"
            );
            assert_eq!(at(&tree, "proxy.http_bind_port"), Some(&Value::from(8080)));
        }
    }

    #[test]
    fn an_empty_remote_document_under_replace_keeps_only_denied_paths() {
        let base = "proxy:\n  http_bind_port: 8080\n  admin:\n    port: 9090\n";
        let outcome = merge(base, "", MergeMode::Replace);
        let tree = merged_tree(&outcome);
        assert_eq!(at(&tree, "proxy.admin.port"), Some(&Value::from(9090)));
        assert_eq!(at(&tree, "proxy.http_bind_port"), None);
    }

    #[test]
    fn an_empty_base_document_is_accepted() {
        for mode in MODES {
            let outcome = merge("", TWO_ORIGIN, mode);
            let tree = merged_tree(&outcome);
            assert_eq!(
                at(&tree, "origins.api.url"),
                Some(&Value::from("https://two.example.com")),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn two_empty_documents_produce_an_empty_mapping() {
        for mode in MODES {
            let outcome = merge("", "", mode);
            let tree = merged_tree(&outcome);
            assert_eq!(tree, Value::Mapping(Mapping::new()), "{mode:?}");
            assert!(outcome.provenance.is_empty(), "{mode:?}");
        }
    }

    #[test]
    fn a_non_mapping_root_errors_rather_than_panicking() {
        let cases = [
            "42\n",
            "just a string\n",
            "- one\n- two\n",
            "true\n",
            "null\n",
        ];
        for case in cases {
            for mode in MODES {
                let error = merge_config(case, local(), "a: 1\n", mode)
                    .expect_err("non-mapping base must error");
                assert!(
                    matches!(error, MergeError::BaseNotMapping),
                    "base {case:?} in {mode:?} gave {error}"
                );

                let error = merge_config("a: 1\n", local(), case, mode)
                    .expect_err("non-mapping remote must error");
                assert!(
                    matches!(error, MergeError::RemoteNotMapping),
                    "remote {case:?} in {mode:?} gave {error}"
                );
            }
        }
    }

    #[test]
    fn invalid_yaml_errors_rather_than_panicking() {
        let error = merge_config("a: [1, 2\n", local(), "b: 1\n", MergeMode::Overlay)
            .expect_err("an unterminated flow sequence must error");
        assert!(matches!(error, MergeError::Yaml(_)), "got {error}");
    }

    // --- provenance -----------------------------------------------------

    #[test]
    fn provenance_tags_base_leaves_local_and_remote_leaves_authority() {
        let base = "origins:\n  api:\n    url: https://one.example.com\n    timeout: 30\n";
        let remote = "origins:\n  api:\n    timeout: 5\n  web:\n    url: https://web.test\n";

        let outcome = merge_config(base, local(), remote, MergeMode::Overlay).expect("merge");
        assert_eq!(
            outcome.provenance.get("origins.api.url"),
            Some(&Provenance::Local),
            "kept from the base"
        );
        assert_eq!(
            outcome.provenance.get("origins.api.timeout"),
            Some(&Provenance::Authority),
            "overwritten by the remote"
        );
        assert_eq!(
            outcome.provenance.get("origins.web.url"),
            Some(&Provenance::Authority),
            "introduced by the remote"
        );
    }

    #[test]
    fn provenance_carries_the_supplied_git_tag_on_base_leaves() {
        let base = "origins:\n  api:\n    url: https://one.example.com\n    timeout: 30\n";
        let remote = "origins:\n  api:\n    timeout: 5\n";
        let outcome = merge_config(base, git(), remote, MergeMode::Overlay).expect("merge");

        assert_eq!(
            outcome.provenance.get("origins.api.url"),
            Some(&git().provenance())
        );
        assert_eq!(
            outcome.provenance.get("origins.api.timeout"),
            Some(&Provenance::Authority)
        );
        match outcome.provenance.get("origins.api.url") {
            Some(Provenance::Git {
                repo,
                reference,
                commit,
            }) => {
                assert_eq!(reference, "main");
                assert_eq!(commit, "9f1c0de5c4a24b6f8d3e7a10b5c9d2f4e6a8b0c1");
                assert!(repo.contains("fleet-config"), "{repo}");
            }
            other => panic!("expected a git tag, got {other:?}"),
        }
    }

    #[test]
    fn restored_denied_paths_carry_the_base_tag_in_both_modes() {
        let base = "\
proxy:
  admin:
    port: 9090
    enabled: true
origins:
  api:
    url: https://one.example.com
";
        for origin in [local(), git()] {
            for mode in MODES {
                let outcome = merge_config(base, origin.clone(), TWO_ORIGIN, mode)
                    .expect("merge should succeed");
                assert_eq!(
                    outcome.provenance.get("proxy.admin.port"),
                    Some(&origin.provenance()),
                    "{mode:?} with {origin:?}"
                );
                assert_eq!(
                    outcome.provenance.get("origins.api.url"),
                    Some(&Provenance::Authority),
                    "{mode:?} with {origin:?}"
                );
            }
        }
    }

    #[test]
    fn provenance_covers_every_leaf_in_the_merged_document() {
        let base = "a: 1\nb:\n  c: 2\n  d: [1, 2]\n";
        let remote = "b:\n  c: 3\ne: {}\n";
        let outcome = merge_config(base, local(), remote, MergeMode::Overlay).expect("merge");
        let paths: Vec<&str> = outcome.provenance.paths().collect();
        assert_eq!(
            paths,
            vec!["a", "b.c", "b.d", "e"],
            "sequences and empty mappings are leaves; non-empty mappings are not"
        );
        assert_eq!(outcome.provenance.len(), 4);
        assert_eq!(outcome.provenance.get("b.d"), Some(&Provenance::Local));
        assert_eq!(outcome.provenance.get("e"), Some(&Provenance::Authority));
    }

    #[test]
    fn an_explicit_null_from_the_remote_is_attributed_to_the_authority() {
        let outcome =
            merge_config("a: 1\n", local(), "a: null\n", MergeMode::Overlay).expect("merge");
        assert_eq!(outcome.provenance.get("a"), Some(&Provenance::Authority));
    }

    // --- output shape ---------------------------------------------------

    #[test]
    fn the_merged_output_parses_back_as_valid_yaml_in_both_modes() {
        let base = "\
proxy:
  http_bind_port: 8080
  admin:
    port: 9090
origins:
  api.example.com:
    url: https://one.example.com
    allowed_methods: [GET, POST]
    nested:
      deep:
        value: 1
";
        let remote = "\
origins:
  api.example.com:
    allowed_methods: [PUT]
    nested:
      deep:
        value: 2
        added: true
";
        for mode in MODES {
            let outcome = merge(base, remote, mode);
            let tree: Value =
                serde_yaml::from_str(&outcome.merged_yaml).expect("output must reparse");
            assert!(tree.is_mapping(), "{mode:?}");
            // A key containing a dot still round-trips structurally, even
            // though its dotted provenance path is ambiguous.
            let origins = at(&tree, "origins")
                .and_then(Value::as_mapping)
                .expect("origins block");
            assert!(origins.contains_key("api.example.com"), "{mode:?}");
        }
    }

    #[test]
    fn merging_is_deterministic_for_the_same_inputs() {
        let base = "b: 1\na: 2\nc:\n  z: 1\n  y: 2\n";
        let remote = "c:\n  y: 3\n  x: 4\nd: 5\n";
        let first = merge(base, remote, MergeMode::Overlay);
        let second = merge(base, remote, MergeMode::Overlay);
        assert_eq!(first.merged_yaml, second.merged_yaml);
        assert_eq!(first.provenance, second.provenance);
    }

    // --- property-style sweep ---------------------------------------------

    /// Small deterministic generator. A real property-testing crate would
    /// mean a new dependency; this covers the same ground with a fixed
    /// seed, so a failure reproduces exactly.
    struct Rng(u64);

    impl Rng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: u32) -> u32 {
            self.next_u32() % n
        }
    }

    /// Deliberately loaded with deny-listed names so the sweep exercises
    /// both the rejection path and the merge path.
    const VOCABULARY: &[&str] = &[
        "proxy",
        "origins",
        "source",
        "cluster",
        "admin",
        "tls",
        "listeners",
        "secrets",
        "config_authority",
        "model_host",
        "api",
        "timeout",
        "url",
        "enabled",
        "port",
    ];

    const PROPERTY_BASE: &str = "\
proxy:
  http_bind_port: 8080
  admin:
    port: 9090
    password: local-only
  tls:
    cert: /etc/sbproxy/tls.pem
  cluster:
    cluster_id: local
source:
  repo: git@example.com:fleet/base.git
origins:
  api:
    url: https://one.example.com
";

    fn random_document(rng: &mut Rng, depth: u32) -> Mapping {
        let mut map = Mapping::new();
        let entries = rng.below(4) + 1;
        for _ in 0..entries {
            let index = rng.below(VOCABULARY.len() as u32) as usize;
            let value = if depth > 0 && rng.below(2) == 0 {
                Value::Mapping(random_document(rng, depth - 1))
            } else {
                match rng.below(4) {
                    0 => Value::Null,
                    1 => Value::from(i64::from(rng.below(1000))),
                    2 => Value::Sequence(vec![Value::from("a"), Value::from("b")]),
                    _ => Value::from("value"),
                }
            };
            map.insert(Value::String(VOCABULARY[index].to_string()), value);
        }
        map
    }

    fn assert_denied_paths_match_base(merged: &Mapping, base: &Mapping, context: &str) {
        for path in AUTHORITY_DENIED_PATHS {
            let segments = split_path(path);
            assert_eq!(
                lookup_path(merged, &segments),
                lookup_path(base, &segments),
                "{path} drifted from the base: {context}"
            );
        }
    }

    fn assert_no_authority_claim_on_denied_leaves(provenance: &ProvenanceMap) {
        for (recorded, tag) in provenance.iter() {
            let denied = AUTHORITY_DENIED_PATHS.iter().any(|path| {
                recorded.as_str() == *path || recorded.starts_with(&format!("{path}."))
            });
            if denied {
                assert_eq!(
                    tag,
                    &Provenance::Local,
                    "{recorded} credited to the authority"
                );
            }
        }
    }

    #[test]
    fn no_denied_path_in_any_output_ever_differs_from_the_base() {
        let base_map = parse_root(PROPERTY_BASE)
            .expect("base parses")
            .expect("base is a mapping");

        let mut rng = Rng(0x5b09_ab1e);
        let mut rejected = 0_u32;
        let mut accepted = 0_u32;
        for _ in 0..600 {
            let generated = Value::Mapping(random_document(&mut rng, 3));
            let remote = serde_yaml::to_string(&generated).expect("generated doc serializes");
            for mode in MODES {
                match merge_config(PROPERTY_BASE, local(), &remote, mode) {
                    Err(MergeError::DeniedPaths(paths)) => {
                        rejected += 1;
                        assert!(!paths.is_empty());
                        for path in &paths {
                            assert!(
                                AUTHORITY_DENIED_PATHS.contains(&path.as_str()),
                                "reported {path}, which is not on the deny list"
                            );
                        }
                    }
                    Err(other) => panic!("unexpected error for {remote:?}: {other}"),
                    Ok(outcome) => {
                        accepted += 1;
                        let merged = parse_root(&outcome.merged_yaml)
                            .expect("output parses")
                            .expect("output is a mapping");
                        let context = format!("{mode:?} for remote {remote:?}");
                        assert_denied_paths_match_base(&merged, &base_map, &context);
                        assert_no_authority_claim_on_denied_leaves(&outcome.provenance);
                    }
                }
            }
        }
        assert!(rejected > 0, "the sweep must exercise the rejection path");
        assert!(accepted > 0, "the sweep must exercise the merge path");
    }

    #[test]
    fn the_deny_list_has_no_duplicates_and_no_empty_segments() {
        let mut seen = std::collections::BTreeSet::new();
        for path in AUTHORITY_DENIED_PATHS {
            assert!(seen.insert(*path), "{path} is listed twice");
            assert!(!path.is_empty());
            assert!(
                path.split('.').all(|segment| !segment.is_empty()),
                "{path} has an empty segment"
            );
        }
    }
}
