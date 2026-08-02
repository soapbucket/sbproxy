// SPDX-License-Identifier: Apache-2.0
//! What configuration is actually running on this node, and which parts of
//! it the node still owns.
//!
//! A node's configuration can arrive from three places. Its own file. A
//! git repository named by a `source:` block. An authority that publishes
//! signed bundles. Any two of those can be in play at once, and the
//! interesting question is not "where did the config come from" but "if I
//! edit this file, will my edit survive the next poll".
//!
//! This module answers both, from one merge, so the answer the admin API
//! reports and the answer its write guard enforces cannot disagree.
//!
//! # The write guard, stated precisely
//!
//! The naive guard compares an edit against a list of paths the authority
//! owns. That list is not a thing that exists: ownership depends on merge
//! mode, on the deny list, on whether the base came from git, and on the
//! shape of the two documents at that exact path. Every attempt to
//! enumerate it is a second implementation of the merge, and a second
//! implementation of the merge is a source of drift.
//!
//! So the guard does not enumerate. It runs the real merge twice, once
//! with the file on disk as the base and once with the file the operator
//! proposed, and compares the two results. An edit that changes the merged
//! document will take effect. An edit that does not is one the remote
//! layer swallows, and it is reported as a conflict rather than written to
//! a file where it would look applied and do nothing.
//!
//! Every shape falls out of that single comparison:
//!
//! - **Local file only.** Nothing to merge, every edit takes effect. This
//!   is the historical behaviour and it is short-circuited before any
//!   merge runs.
//! - **Authority, overlay mode.** Edits to paths the authority does not
//!   set survive; edits to paths it does set are swallowed. Adding a
//!   brand-new key survives, which is why the guard cannot be a lookup
//!   against the current provenance map: a key that does not exist yet
//!   has no provenance and is not therefore forbidden.
//! - **Authority, replace mode.** The authority document is the config, so
//!   almost everything is swallowed. The exception is the deny list, which
//!   is grafted back from the local file on every merge. Those paths, the
//!   admin listener and the TLS material among them, remain editable
//!   because the authority provably cannot take them. A guard that
//!   rejected every write under replace mode would lock an operator out of
//!   changing their own admin password on the grounds that a remote
//!   authority might object, which it cannot.
//! - **Git source.** The local file is a pointer; the merge never reads
//!   its content. Both runs produce the same document and every edit is
//!   reported, pointing the operator at the repository.
//! - **Git base with an authority overlay.** The same, for both reasons at
//!   once.

use sbproxy_config::config_merge::{
    changed_leaf_paths, merge_config, BaseOrigin, MergeError, MergeMode, Provenance, ProvenanceMap,
};

use crate::config_subscriber::AppliedAuthority;

/// The documents that combine into the configuration this node runs.
///
/// Read from process state by [`current_layers`] and passed explicitly
/// from there on, so everything below is a pure function of its inputs and
/// can be tested without a running server.
#[derive(Debug, Clone)]
pub struct ConfigLayers {
    /// The base document: the resolved git document on a node with a
    /// `source:` block, otherwise the node's own file.
    pub base_yaml: String,
    /// Where the base document came from.
    pub base_origin: BaseOrigin,
    /// The authority payload layered on top, if this node has one applied.
    pub authority: Option<AppliedAuthority>,
}

impl ConfigLayers {
    /// Whether this node's own file is the whole configuration.
    ///
    /// True only with a local base and no applied authority. A node with an
    /// authority configured but not yet reached is not local: the next poll
    /// can take ownership of any path, and reporting the file as
    /// authoritative in that window would be a promise the node cannot
    /// keep.
    #[must_use]
    pub fn is_local_only(&self) -> bool {
        matches!(self.base_origin, BaseOrigin::Local) && self.authority.is_none()
    }

    /// The same layers with `local_yaml` substituted for the node's own
    /// file.
    ///
    /// On a git-sourced node this returns the layers unchanged, because the
    /// local file contributes nothing but the `source:` pointer that
    /// selected the repository. That is not a special case bolted on; it is
    /// the reason a git-sourced node rejects every write.
    #[must_use]
    pub fn with_local_file(&self, local_yaml: &str) -> Self {
        match self.base_origin {
            BaseOrigin::Local => Self {
                base_yaml: local_yaml.to_string(),
                ..self.clone()
            },
            BaseOrigin::Git { .. } => self.clone(),
        }
    }
}

/// The configuration this node is running, and where each leaf came from.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    /// The merged document. Re-serialized, so comments and the original
    /// key order are gone even when the merge changed nothing.
    pub yaml: String,
    /// Where every leaf in `yaml` came from.
    pub provenance: ProvenanceMap,
    /// Where the base document came from.
    pub base_origin: BaseOrigin,
    /// The authority payload merged on top, if any.
    pub authority: Option<AppliedAuthority>,
}

/// One edit a write would make that the node's remote layers would
/// swallow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteConflict {
    /// Dotted leaf path the write changes.
    pub path: String,
    /// Which layer owns that path in the running configuration, or `None`
    /// when no layer sets it. `None` means the remote layer suppresses the
    /// path entirely: a replace-mode authority discards it, or a git base
    /// never had it.
    pub owner: Option<Provenance>,
}

/// The layers currently in play on this process, with `local_yaml` as the
/// node's own file.
///
/// The only function here that reads global state. A node that resolved a
/// `source:` block has published the resolved document, and a node that
/// applied an authority bundle has recorded the payload; both are read
/// here and nowhere else.
#[must_use]
pub fn current_layers(local_yaml: &str) -> ConfigLayers {
    match crate::config_source::current_resolved_base() {
        Some(base) => ConfigLayers {
            base_yaml: base.yaml.clone(),
            base_origin: base.origin.clone(),
            authority: crate::config_subscriber::applied_authority(),
        },
        None => ConfigLayers {
            base_yaml: local_yaml.to_string(),
            base_origin: BaseOrigin::Local,
            authority: crate::config_subscriber::applied_authority(),
        },
    }
}

/// Merge the layers into the document the node runs, with provenance.
///
/// # Errors
///
/// Returns the underlying [`MergeError`] when a document's root is not a
/// mapping, when it does not parse, or when the recorded authority payload
/// names a path the subscriber owns. The last cannot happen on a node that
/// applied the payload through the normal path, since the same check
/// refused it then, but it is reported rather than assumed away.
pub fn effective_config(layers: &ConfigLayers) -> Result<EffectiveConfig, MergeError> {
    // With no authority, merge against an empty document rather than
    // skipping the merge. It produces the same text and it produces a
    // provenance map, which the caller needs either way, and it keeps one
    // code path instead of two that have to agree.
    let (remote_yaml, mode) = match &layers.authority {
        Some(applied) => (applied.config_yaml.as_str(), applied.merge_mode),
        None => ("", MergeMode::Overlay),
    };
    let outcome = merge_config(
        &layers.base_yaml,
        layers.base_origin.clone(),
        remote_yaml,
        mode,
    )?;
    Ok(EffectiveConfig {
        yaml: outcome.merged_yaml,
        provenance: outcome.provenance,
        base_origin: layers.base_origin.clone(),
        authority: layers.authority.clone(),
    })
}

/// Which edits in `proposed`, relative to `on_disk`, would not reach the
/// running configuration.
///
/// An empty result means every edit takes effect and the write is safe to
/// persist. See the module documentation for why this is computed by
/// running the merge twice rather than by testing paths against a list.
///
/// # Errors
///
/// Returns the underlying [`MergeError`] when any document involved does
/// not parse or is not a mapping at its root.
pub fn write_conflicts(
    layers: &ConfigLayers,
    on_disk: &str,
    proposed: &str,
) -> Result<Vec<WriteConflict>, MergeError> {
    // A node whose file is the whole configuration has nothing that could
    // swallow an edit. Short-circuiting keeps the historical write path
    // free of two merges it would learn nothing from.
    if layers.is_local_only() {
        return Ok(Vec::new());
    }

    let intended = changed_leaf_paths(on_disk, proposed)?;
    if intended.is_empty() {
        return Ok(Vec::new());
    }

    let before = effective_config(&layers.with_local_file(on_disk))?;
    let after = effective_config(&layers.with_local_file(proposed))?;
    let effective: std::collections::BTreeSet<String> =
        changed_leaf_paths(&before.yaml, &after.yaml)?
            .into_iter()
            .collect();

    Ok(intended
        .into_iter()
        .filter(|path| !effective.contains(path))
        .map(|path| WriteConflict {
            owner: before.provenance.get(&path).cloned(),
            path,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "proxy:\n  http_bind_port: 8080\n  admin:\n    bind_port: 9090\norigins:\n  api:\n    url: https://api.test\n    timeout: 5s\n";

    fn authority(config_yaml: &str, merge_mode: MergeMode) -> AppliedAuthority {
        AppliedAuthority {
            config_yaml: config_yaml.to_string(),
            merge_mode,
            revision: 7,
            authority_id: "control-plane".to_string(),
        }
    }

    fn local_layers() -> ConfigLayers {
        ConfigLayers {
            base_yaml: LOCAL.to_string(),
            base_origin: BaseOrigin::Local,
            authority: None,
        }
    }

    fn git_origin() -> BaseOrigin {
        BaseOrigin::Git {
            repo: "https://git.test/fleet.git".to_string(),
            reference: "main".to_string(),
            commit: "a".repeat(40),
        }
    }

    fn edit(yaml: &str, from: &str, to: &str) -> String {
        assert!(yaml.contains(from), "fixture does not contain {from}");
        yaml.replace(from, to)
    }

    fn paths(conflicts: &[WriteConflict]) -> Vec<&str> {
        conflicts.iter().map(|c| c.path.as_str()).collect()
    }

    #[test]
    fn a_local_only_node_has_no_conflicts_at_all() {
        let layers = local_layers();
        assert!(layers.is_local_only());
        let proposed = edit(LOCAL, "timeout: 5s", "timeout: 30s");
        assert!(write_conflicts(&layers, LOCAL, &proposed)
            .expect("guard")
            .is_empty());
    }

    #[test]
    fn overlay_allows_an_edit_the_authority_does_not_claim() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let proposed = edit(LOCAL, "url: https://api.test", "url: https://api2.test");
        assert!(
            write_conflicts(&layers, LOCAL, &proposed)
                .expect("guard")
                .is_empty(),
            "the authority sets timeout, not url"
        );
    }

    #[test]
    fn overlay_rejects_an_edit_to_a_path_the_authority_claims() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let proposed = edit(LOCAL, "timeout: 5s", "timeout: 30s");
        let conflicts = write_conflicts(&layers, LOCAL, &proposed).expect("guard");
        assert_eq!(paths(&conflicts), vec!["origins.api.timeout"]);
        assert_eq!(conflicts[0].owner, Some(Provenance::Authority));
    }

    /// A key that does not exist yet has no provenance, so a guard built on
    /// a provenance lookup would have to decide what "no entry" means and
    /// would get this wrong in one direction or the other. Running the
    /// merge answers it without deciding.
    #[test]
    fn overlay_allows_adding_a_key_the_authority_has_never_mentioned() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let proposed = format!("{LOCAL}  second:\n    url: https://other.test\n");
        assert!(write_conflicts(&layers, LOCAL, &proposed)
            .expect("guard")
            .is_empty());
    }

    #[test]
    fn overlay_reports_every_conflicting_path_in_a_multi_edit_write() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n    url: https://central.test\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let proposed = edit(
            &edit(LOCAL, "timeout: 5s", "timeout: 30s"),
            "url: https://api.test",
            "url: https://mine.test",
        );
        assert_eq!(
            paths(&write_conflicts(&layers, LOCAL, &proposed).expect("guard")),
            vec!["origins.api.timeout", "origins.api.url"]
        );
    }

    /// A write that mixes an allowed edit with a forbidden one still
    /// reports the forbidden one. The caller rejects the whole request on a
    /// non-empty result, so a partial apply is not representable.
    #[test]
    fn overlay_reports_the_forbidden_half_of_a_mixed_write() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let proposed = edit(
            &edit(LOCAL, "timeout: 5s", "timeout: 30s"),
            "url: https://api.test",
            "url: https://mine.test",
        );
        assert_eq!(
            paths(&write_conflicts(&layers, LOCAL, &proposed).expect("guard")),
            vec!["origins.api.timeout"]
        );
    }

    #[test]
    fn replace_rejects_an_edit_to_a_path_the_authority_document_supplies() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "proxy:\n  http_bind_port: 8080\norigins:\n  api:\n    url: https://central.test\n    timeout: 60s\n",
                MergeMode::Replace,
            )),
            ..local_layers()
        };
        let proposed = edit(LOCAL, "timeout: 5s", "timeout: 30s");
        let conflicts = write_conflicts(&layers, LOCAL, &proposed).expect("guard");
        assert_eq!(paths(&conflicts), vec!["origins.api.timeout"]);
    }

    /// The deny list is grafted from the local file on every merge, so
    /// those paths stay editable under replace mode. An operator locked out
    /// of their own admin listener by a remote authority that cannot touch
    /// it would be a guard protecting nothing at the cost of the one
    /// setting they most need.
    #[test]
    fn replace_still_allows_editing_the_paths_the_authority_cannot_take() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "proxy:\n  http_bind_port: 8080\norigins:\n  api:\n    url: https://central.test\n",
                MergeMode::Replace,
            )),
            ..local_layers()
        };
        let proposed = edit(LOCAL, "bind_port: 9090", "bind_port: 9099");
        assert!(
            write_conflicts(&layers, LOCAL, &proposed)
                .expect("guard")
                .is_empty(),
            "proxy.admin is on the deny list and is restored from the local file"
        );
    }

    /// Under replace mode a local-only key is discarded rather than
    /// overwritten, so it has no provenance entry. The conflict is still
    /// reported, with no owner, because "discarded" and "overwritten" are
    /// the same outcome for the operator.
    #[test]
    fn replace_reports_a_discarded_local_key_with_no_owner() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "proxy:\n  http_bind_port: 8080\n",
                MergeMode::Replace,
            )),
            ..local_layers()
        };
        let proposed = edit(LOCAL, "url: https://api.test", "url: https://mine.test");
        let conflicts = write_conflicts(&layers, LOCAL, &proposed).expect("guard");
        assert_eq!(paths(&conflicts), vec!["origins.api.url"]);
        assert_eq!(conflicts[0].owner, None);
    }

    #[test]
    fn a_git_sourced_node_rejects_every_edit_and_names_the_repository() {
        let layers = ConfigLayers {
            base_yaml: LOCAL.to_string(),
            base_origin: git_origin(),
            authority: None,
        };
        assert!(!layers.is_local_only());
        let pointer = "source:\n  git:\n    repo: https://git.test/fleet.git\n";
        let proposed = format!("{pointer}proxy:\n  workers: 4\n");
        let conflicts = write_conflicts(&layers, pointer, &proposed).expect("guard");
        assert_eq!(paths(&conflicts), vec!["proxy.workers"]);
        assert_eq!(conflicts[0].owner, None);
    }

    #[test]
    fn a_git_base_with_an_authority_overlay_rejects_every_edit() {
        let layers = ConfigLayers {
            base_yaml: LOCAL.to_string(),
            base_origin: git_origin(),
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
        };
        let pointer = "source:\n  git:\n    repo: https://git.test/fleet.git\n";
        let proposed = format!("{pointer}origins:\n  api:\n    timeout: 30s\n");
        assert_eq!(
            paths(&write_conflicts(&layers, pointer, &proposed).expect("guard")),
            vec!["origins.api.timeout"]
        );
    }

    #[test]
    fn a_write_that_changes_nothing_conflicts_with_nothing() {
        let layers = ConfigLayers {
            base_yaml: LOCAL.to_string(),
            base_origin: git_origin(),
            authority: None,
        };
        assert!(write_conflicts(&layers, LOCAL, LOCAL)
            .expect("guard")
            .is_empty());
    }

    /// Reserializing the same document is not an edit. Without this a
    /// client that read the config, parsed it, and wrote it back would be
    /// told it had a conflict it did not have.
    #[test]
    fn reformatting_without_changing_a_value_conflicts_with_nothing() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let reserialized = serde_yaml::to_string(
            &serde_yaml::from_str::<serde_yaml::Value>(LOCAL).expect("parse"),
        )
        .expect("serialize");
        assert!(write_conflicts(&layers, LOCAL, &reserialized)
            .expect("guard")
            .is_empty());
    }

    #[test]
    fn effective_config_tags_every_leaf_local_on_a_local_node() {
        let effective = effective_config(&local_layers()).expect("merge");
        assert!(!effective.provenance.is_empty());
        for (path, provenance) in effective.provenance.iter() {
            assert_eq!(provenance, &Provenance::Local, "{path}");
        }
        assert!(effective.authority.is_none());
    }

    #[test]
    fn effective_config_tags_leaves_by_the_layer_that_set_them() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "origins:\n  api:\n    timeout: 60s\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        let effective = effective_config(&layers).expect("merge");
        assert_eq!(
            effective.provenance.get("origins.api.timeout"),
            Some(&Provenance::Authority)
        );
        assert_eq!(
            effective.provenance.get("origins.api.url"),
            Some(&Provenance::Local)
        );
        assert!(effective.yaml.contains("60s"), "the authority value wins");
    }

    #[test]
    fn effective_config_carries_the_git_origin_onto_every_base_leaf() {
        let layers = ConfigLayers {
            base_yaml: LOCAL.to_string(),
            base_origin: git_origin(),
            authority: None,
        };
        let effective = effective_config(&layers).expect("merge");
        for (path, provenance) in effective.provenance.iter() {
            assert!(
                matches!(provenance, Provenance::Git { commit, .. } if commit.len() == 40),
                "{path} should carry the resolved commit"
            );
        }
    }

    #[test]
    fn an_authority_configured_but_never_reached_is_not_local_only() {
        let layers = ConfigLayers {
            authority: Some(authority("proxy: {}\n", MergeMode::Overlay)),
            ..local_layers()
        };
        assert!(!layers.is_local_only());
    }

    #[test]
    fn a_denied_authority_payload_is_reported_rather_than_merged() {
        let layers = ConfigLayers {
            authority: Some(authority(
                "proxy:\n  admin:\n    bind_port: 1\n",
                MergeMode::Overlay,
            )),
            ..local_layers()
        };
        assert!(matches!(
            effective_config(&layers),
            Err(MergeError::DeniedPaths(paths)) if paths == vec!["proxy.admin".to_string()]
        ));
    }
}
