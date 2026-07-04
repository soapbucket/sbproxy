// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Weight-cache warm plan (WOR-1682 core).
//!
//! `sbproxy models pull` warms the weight cache without starting the
//! server (for an air-gapped build or a container image). This is the
//! pure selection: given a manifest and a mode, which entries to fetch,
//! with the source, revision, and digests each needs. The command
//! itself (driving the download over `weights`, printing progress) is
//! the binary-side wiring; this decides *what* to pull so it is
//! testable with no network.

use crate::catalog::{Catalog, PullPolicy};
use crate::manifest::SourceScheme;

/// Which entries `sbproxy models pull` warms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullMode {
    /// Only entries marked `pull: on_boot` (the default warm set).
    Boot,
    /// Every entry in the manifest.
    All,
    /// Only these named entries (errors if a name is missing).
    Only(Vec<String>),
}

/// One model to warm: everything the downloader needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullItem {
    /// Manifest id / model name.
    pub name: String,
    /// The `source:` string (derived `hf:{hf_repo}` when unset).
    pub source: String,
    /// Revision to pin (`main` when unset).
    pub revision: String,
    /// Per-file sha256 digests to verify after fetch.
    pub sha256: std::collections::BTreeMap<String, String>,
    /// True when the source is already local (`file:`), so the
    /// downloader skips it (nothing to fetch).
    pub local: bool,
}

/// Build the ordered pull plan for a manifest and mode. Order follows
/// the manifest's (sorted) id order for determinism. `Only` errors on
/// the first name not in the manifest.
pub fn pull_plan(catalog: &Catalog, mode: &PullMode) -> Result<Vec<PullItem>, String> {
    let mut items = Vec::new();
    match mode {
        PullMode::Only(names) => {
            for name in names {
                let entry = catalog
                    .get(name)
                    .ok_or_else(|| format!("model '{name}' is not in the manifest"))?;
                items.push(to_item(name, entry)?);
            }
        }
        PullMode::Boot | PullMode::All => {
            for (name, entry) in &catalog.models {
                let want = matches!(mode, PullMode::All) || entry.pull == PullPolicy::OnBoot;
                if want {
                    items.push(to_item(name, entry)?);
                }
            }
        }
    }
    Ok(items)
}

/// Turn a catalog entry into a pull item, deriving the source and
/// validating its scheme.
fn to_item(name: &str, entry: &crate::catalog::CatalogEntry) -> Result<PullItem, String> {
    let source = entry
        .source
        .clone()
        .unwrap_or_else(|| format!("hf:{}", entry.hf_repo));
    let scheme = SourceScheme::parse(&source).map_err(|e| e.to_string())?;
    scheme.require_supported().map_err(|e| e.to_string())?;
    Ok(PullItem {
        name: name.to_string(),
        source,
        revision: entry.revision.clone().unwrap_or_else(|| "main".to_string()),
        sha256: entry.sha256.clone(),
        local: scheme.is_local(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::from_yaml(
            "\
models:
  boot-model:
    hf_repo: Org/Boot
    quants: [Q4_K_M]
    params: 8B
    license: apache-2.0
    family: t
    min_vram_hint_gib: 6.0
    pull: on_boot
    revision: v1.0
  demand-model:
    hf_repo: Org/Demand
    quants: [Q4_K_M]
    params: 8B
    license: apache-2.0
    family: t
    min_vram_hint_gib: 6.0
    pull: on_demand
  offline-model:
    hf_repo: local/off
    source: file:/weights/off
    quants: [Q4_K_M]
    params: 8B
    license: apache-2.0
    family: t
    min_vram_hint_gib: 6.0
    pull: manual
",
        )
        .expect("parse")
    }

    #[test]
    fn boot_mode_selects_only_on_boot() {
        let plan = pull_plan(&catalog(), &PullMode::Boot).unwrap();
        let names: Vec<_> = plan.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["boot-model"]);
        // Source derived from hf_repo; revision pinned from the entry.
        assert_eq!(plan[0].source, "hf:Org/Boot");
        assert_eq!(plan[0].revision, "v1.0");
        assert!(!plan[0].local);
    }

    #[test]
    fn all_mode_selects_everything_and_marks_local() {
        let plan = pull_plan(&catalog(), &PullMode::All).unwrap();
        assert_eq!(plan.len(), 3);
        let offline = plan.iter().find(|i| i.name == "offline-model").unwrap();
        assert!(offline.local, "file: source is local, downloader skips it");
        assert_eq!(offline.source, "file:/weights/off");
        // A demand model with no explicit revision defaults to main.
        let demand = plan.iter().find(|i| i.name == "demand-model").unwrap();
        assert_eq!(demand.revision, "main");
    }

    #[test]
    fn only_mode_selects_named_and_errors_on_missing() {
        let plan = pull_plan(&catalog(), &PullMode::Only(vec!["demand-model".into()])).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].name, "demand-model");
        let err = pull_plan(&catalog(), &PullMode::Only(vec!["ghost".into()])).unwrap_err();
        assert!(err.contains("ghost"), "got: {err}");
    }
}
