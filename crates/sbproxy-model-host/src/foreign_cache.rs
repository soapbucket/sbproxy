// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Read-only discovery of model weights other local tools already
//! cached (WOR-1863).
//!
//! Most machines that run models at all already hold gigabytes of
//! weights on disk: Ollama keeps OCI-style manifests plus sha256 blobs
//! under `~/.ollama/models`, LM Studio keeps plain GGUF trees under
//! `~/.cache/lm-studio/models` (or `~/.lmstudio/models`) in
//! `publisher/repo` directories, and the Hugging Face hub cache at
//! `~/.cache/huggingface/hub` uses the
//! `models--Org--Repo/snapshots/<rev>/` layout. This module scans
//! those caches so `sbproxy doctor` can show an operator what is
//! already local before anything is pulled.
//!
//! The scan is strictly read-only: it never writes, never locks, and
//! never follows a symlink whose target resolves outside the cache
//! root being scanned. A file symlink whose target stays inside the
//! root is resolved for its size (the HF hub links snapshot files to
//! `../../blobs/<hash>` in the same root); symlinked directories are
//! never entered, so the walk cannot cycle. Every walk is capped by
//! [`MAX_SCAN_DEPTH`] and [`MAX_SCAN_ENTRIES`] so a pathological
//! cache directory cannot stall the doctor.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ArtifactFormat;

/// Maximum directory depth entered below a cache root. The deepest
/// known real layout is the HF hub's snapshot tree, whose weight files
/// sit four levels down (repo, `snapshots`, revision, one component
/// directory inside the snapshot).
pub const MAX_SCAN_DEPTH: usize = 4;

/// Maximum directory entries visited per cache root before the walk
/// stops early. Purely defensive; real caches hold tens of models,
/// not thousands.
pub const MAX_SCAN_ENTRIES: usize = 10_000;

/// Largest Ollama manifest file the parser will read. Real manifests
/// are a few KiB of JSON; anything larger is skipped as
/// not-a-manifest.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Which tool's on-disk cache a discovered weight file came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCacheSource {
    /// Ollama's blob store under `~/.ollama/models`.
    Ollama,
    /// LM Studio's model tree under `~/.cache/lm-studio/models` or
    /// `~/.lmstudio/models`.
    LmStudio,
    /// The Hugging Face hub cache under `~/.cache/huggingface/hub`.
    HuggingFace,
}

impl ForeignCacheSource {
    /// Human-readable label used in doctor output.
    pub fn label(self) -> &'static str {
        match self {
            ForeignCacheSource::Ollama => "ollama",
            ForeignCacheSource::LmStudio => "lm studio",
            ForeignCacheSource::HuggingFace => "hugging face",
        }
    }
}

/// One model weight file found in a foreign cache. Discovery only
/// reads; the file stays owned and managed by the foreign tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignModelFile {
    /// The cache the file was found in.
    pub source: ForeignCacheSource,
    /// Path to the weight file. For Ollama this is the resolved blob
    /// under `blobs/`; for an HF snapshot symlink it is the snapshot
    /// path, with the size taken from the resolved blob.
    pub path: PathBuf,
    /// The model identity as the owning tool names it: Ollama
    /// `name:tag`, LM Studio `publisher/repo`, HF `Org/Repo`.
    pub repo_or_name: String,
    /// On-disk size of the weight file in bytes.
    pub size_bytes: u64,
    /// Weight format when the file extension (or, for Ollama, the
    /// manifest layer's media type) makes it unambiguous.
    pub format_hint: Option<ArtifactFormat>,
}

/// Scan every known foreign cache location under `home` and return
/// the weight files found, sorted by source, then model name, then
/// path so the output is deterministic. Absent directories are
/// silently skipped; the scan never writes.
pub fn discover(home: &Path) -> Vec<ForeignModelFile> {
    let mut found = discover_ollama(&home.join(".ollama").join("models"));
    found.extend(discover_lm_studio(
        &home.join(".cache").join("lm-studio").join("models"),
    ));
    found.extend(discover_lm_studio(&home.join(".lmstudio").join("models")));
    found.extend(discover_hugging_face(
        &home.join(".cache").join("huggingface").join("hub"),
    ));
    found.sort_by(|a, b| {
        (a.source, &a.repo_or_name, &a.path).cmp(&(b.source, &b.repo_or_name, &b.path))
    });
    found
}

/// Scan an Ollama model store (`<root>/manifests` + `<root>/blobs`).
///
/// Each manifest JSON under `manifests/<registry>/<namespace>/<name>/
/// <tag>` lists OCI-style layers; a layer whose `mediaType` contains
/// `model` carries a `sha256:<hex>` digest that maps to the file
/// `blobs/sha256-<hex>`. Returns one entry per model layer whose blob
/// exists, with the blob's on-disk size. Ollama model layers are GGUF
/// containers, so the format hint is always [`ArtifactFormat::Gguf`].
/// An absent or unreadable root yields an empty list.
pub fn discover_ollama(root: &Path) -> Vec<ForeignModelFile> {
    let manifests = root.join("manifests");
    let mut found = Vec::new();
    for (manifest_path, size) in collect_files(&manifests) {
        if size > MAX_MANIFEST_BYTES {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(layers) = manifest.get("layers").and_then(serde_json::Value::as_array) else {
            continue;
        };
        let name = ollama_model_name(&manifests, &manifest_path);
        for layer in layers {
            let media = layer
                .get("mediaType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if !media.contains("model") {
                continue;
            }
            let Some(hex) = layer
                .get("digest")
                .and_then(serde_json::Value::as_str)
                .and_then(|digest| digest.strip_prefix("sha256:"))
            else {
                continue;
            };
            // Only hex digits may reach the path join, so a hostile
            // digest cannot traverse out of the blob directory.
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let blob = root.join("blobs").join(format!("sha256-{hex}"));
            let Ok(meta) = std::fs::symlink_metadata(&blob) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            found.push(ForeignModelFile {
                source: ForeignCacheSource::Ollama,
                path: blob,
                repo_or_name: name.clone(),
                size_bytes: meta.len(),
                format_hint: Some(ArtifactFormat::Gguf),
            });
        }
    }
    found
}

/// Scan an LM Studio model tree: plain weight files under
/// `publisher/repo` directories. Collects `*.gguf` and
/// `*.safetensors` files with their sizes; an absent root yields an
/// empty list.
pub fn discover_lm_studio(root: &Path) -> Vec<ForeignModelFile> {
    let mut found = Vec::new();
    for (path, size) in collect_files(root) {
        let Some(format) = format_for_extension(&path) else {
            continue;
        };
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let name = lm_studio_name(rel);
        found.push(ForeignModelFile {
            source: ForeignCacheSource::LmStudio,
            path,
            repo_or_name: name,
            size_bytes: size,
            format_hint: Some(format),
        });
    }
    found
}

/// Scan a Hugging Face hub cache: weight files under
/// `models--Org--Repo/snapshots/<rev>/`. Snapshot entries that
/// symlink into the sibling `blobs/` directory resolve to the blob's
/// size. Dataset and space caches (`datasets--`, `spaces--`) are
/// ignored. An absent root yields an empty list.
pub fn discover_hugging_face(root: &Path) -> Vec<ForeignModelFile> {
    let mut found = Vec::new();
    for (path, size) in collect_files(root) {
        let Some(format) = format_for_extension(&path) else {
            continue;
        };
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let Some(first) = rel.components().next() else {
            continue;
        };
        let first = first.as_os_str().to_string_lossy();
        let Some(repo) = first.strip_prefix("models--") else {
            continue;
        };
        let name = repo.replace("--", "/");
        found.push(ForeignModelFile {
            source: ForeignCacheSource::HuggingFace,
            path,
            repo_or_name: name,
            size_bytes: size,
            format_hint: Some(format),
        });
    }
    found
}

/// Model identity from a manifest path relative to the manifests
/// root: `<registry>/<namespace>/<name>/<tag>` becomes `name:tag`,
/// keeping a `namespace/` prefix when it is not the default
/// `library`.
fn ollama_model_name(manifests_root: &Path, manifest_path: &Path) -> String {
    let parts: Vec<String> = manifest_path
        .strip_prefix(manifests_root)
        .map(|rel| {
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    match parts.as_slice() {
        [.., namespace, name, tag] if namespace != "library" => {
            format!("{namespace}/{name}:{tag}")
        }
        [.., name, tag] => format!("{name}:{tag}"),
        [only] => only.clone(),
        [] => manifest_path.display().to_string(),
    }
}

/// `publisher/repo` from a weight file's path relative to the LM
/// Studio root, degrading to the single leading directory or the bare
/// file name when the tree is shallower.
fn lm_studio_name(rel: &Path) -> String {
    let mut dirs = rel
        .parent()
        .into_iter()
        .flat_map(|parent| parent.components())
        .map(|c| c.as_os_str().to_string_lossy().into_owned());
    match (dirs.next(), dirs.next()) {
        (Some(publisher), Some(repo)) => format!("{publisher}/{repo}"),
        (Some(publisher), None) => publisher,
        (None, _) => rel.display().to_string(),
    }
}

/// Map a weight-file extension to its [`ArtifactFormat`], or `None`
/// for anything that is not a recognized weight file.
fn format_for_extension(path: &Path) -> Option<ArtifactFormat> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) if e.eq_ignore_ascii_case("gguf") => Some(ArtifactFormat::Gguf),
        Some(e) if e.eq_ignore_ascii_case("safetensors") => Some(ArtifactFormat::Safetensors),
        _ => None,
    }
}

/// Bounded read-only walk: every regular file under `root` with its
/// size, at most [`MAX_SCAN_DEPTH`] directory levels deep and
/// [`MAX_SCAN_ENTRIES`] entries per call. A file symlink is followed
/// only when its target resolves inside `root`; symlinked directories
/// are never entered. An absent root yields an empty list.
fn collect_files(root: &Path) -> Vec<(PathBuf, u64)> {
    // Canonicalize once so symlink targets can be containment-checked
    // against the real root; failure means the root does not exist.
    let Ok(canonical_root) = std::fs::canonicalize(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut budget = MAX_SCAN_ENTRIES;
    walk(root, &canonical_root, 0, &mut budget, &mut out);
    out
}

/// Recursive helper for [`collect_files`]; `depth` counts directory
/// levels below the root and `budget` counts remaining entries.
fn walk(
    dir: &Path,
    canonical_root: &Path,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(PathBuf, u64)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            if depth < MAX_SCAN_DEPTH {
                walk(&path, canonical_root, depth + 1, budget, out);
            }
        } else if file_type.is_file() {
            if let Ok(meta) = entry.metadata() {
                out.push((path, meta.len()));
            }
        } else if file_type.is_symlink() {
            // Resolve a file symlink only when its target stays inside
            // the scanned root (the HF hub links snapshot files to
            // `../../blobs/<hash>`); anything pointing out of the
            // cache is skipped. Directories reached through symlinks
            // are never entered, so the walk cannot cycle.
            let Ok(resolved) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !resolved.starts_with(canonical_root) {
                continue;
            }
            match std::fs::metadata(&resolved) {
                Ok(meta) if meta.is_file() => out.push((path, meta.len())),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `bytes` at `path`, creating parent directories.
    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn absent_home_discovers_nothing() {
        let home = tempfile::tempdir().unwrap();
        assert!(discover(home.path()).is_empty());
    }

    #[test]
    fn ollama_manifest_resolves_model_blob() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".ollama/models");
        write(
            &root.join("manifests/registry.ollama.ai/library/llama3/latest"),
            br#"{"layers":[
                {"mediaType":"application/vnd.ollama.image.model","digest":"sha256:aabb01","size":11},
                {"mediaType":"application/vnd.ollama.image.template","digest":"sha256:ccdd02","size":1}
            ]}"#,
        );
        write(&root.join("blobs/sha256-aabb01"), b"GGUFweights");
        write(&root.join("blobs/sha256-ccdd02"), b"t");
        let found = discover_ollama(&root);
        assert_eq!(found.len(), 1, "only the model layer resolves: {found:?}");
        assert_eq!(found[0].source, ForeignCacheSource::Ollama);
        assert_eq!(found[0].repo_or_name, "llama3:latest");
        assert_eq!(found[0].size_bytes, 11);
        assert_eq!(found[0].format_hint, Some(ArtifactFormat::Gguf));
        assert!(found[0].path.ends_with("blobs/sha256-aabb01"), "{found:?}");
    }

    #[test]
    fn ollama_non_library_namespace_keeps_prefix() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".ollama/models");
        write(
            &root.join("manifests/registry.ollama.ai/someone/custom/v2"),
            br#"{"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:0f"}]}"#,
        );
        write(&root.join("blobs/sha256-0f"), b"g");
        let found = discover_ollama(&root);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].repo_or_name, "someone/custom:v2");
    }

    #[test]
    fn ollama_missing_blob_and_hostile_digest_are_skipped() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".ollama/models");
        write(
            &root.join("manifests/registry.ollama.ai/library/gone/latest"),
            br#"{"layers":[
                {"mediaType":"application/vnd.ollama.image.model","digest":"sha256:dead"},
                {"mediaType":"application/vnd.ollama.image.model","digest":"sha256:../../escape"}
            ]}"#,
        );
        assert!(discover_ollama(&root).is_empty());
    }

    #[test]
    fn lm_studio_collects_weight_files_with_publisher_repo() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".cache/lm-studio/models");
        write(
            &root.join("TheBloke/Mistral-7B-GGUF/mistral.gguf"),
            b"gguf!",
        );
        write(&root.join("TheBloke/Mistral-7B-GGUF/README.md"), b"docs");
        let found = discover_lm_studio(&root);
        assert_eq!(found.len(), 1, "non-weight files ignored: {found:?}");
        assert_eq!(found[0].source, ForeignCacheSource::LmStudio);
        assert_eq!(found[0].repo_or_name, "TheBloke/Mistral-7B-GGUF");
        assert_eq!(found[0].size_bytes, 5);
        assert_eq!(found[0].format_hint, Some(ArtifactFormat::Gguf));
    }

    #[test]
    fn hugging_face_snapshot_layout_yields_org_repo() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".cache/huggingface/hub");
        write(
            &root.join("models--mistralai--Mistral-7B/snapshots/abc123/model.safetensors"),
            b"tensors",
        );
        write(
            &root.join("datasets--org--set/snapshots/def456/data.safetensors"),
            b"data",
        );
        let found = discover_hugging_face(&root);
        assert_eq!(found.len(), 1, "datasets are ignored: {found:?}");
        assert_eq!(found[0].source, ForeignCacheSource::HuggingFace);
        assert_eq!(found[0].repo_or_name, "mistralai/Mistral-7B");
        assert_eq!(found[0].size_bytes, 7);
        assert_eq!(found[0].format_hint, Some(ArtifactFormat::Safetensors));
    }

    #[cfg(unix)]
    #[test]
    fn hugging_face_blob_symlink_inside_root_resolves() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".cache/huggingface/hub");
        let repo = root.join("models--a--b");
        write(&repo.join("blobs/0123abcd"), b"blob567");
        std::fs::create_dir_all(repo.join("snapshots/rev")).unwrap();
        std::os::unix::fs::symlink(
            "../../blobs/0123abcd",
            repo.join("snapshots/rev/model.safetensors"),
        )
        .unwrap();
        let found = discover_hugging_face(&root);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].repo_or_name, "a/b");
        assert_eq!(found[0].size_bytes, 7);
        assert!(
            found[0].path.ends_with("snapshots/rev/model.safetensors"),
            "reports the snapshot path, not the blob: {found:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_the_root_is_skipped() {
        let home = tempfile::tempdir().unwrap();
        let outside = home.path().join("outside.gguf");
        std::fs::write(&outside, b"outside").unwrap();
        let root = home.path().join(".lmstudio/models");
        std::fs::create_dir_all(root.join("pub/repo")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("pub/repo/link.gguf")).unwrap();
        assert!(discover_lm_studio(&root).is_empty());
    }

    #[test]
    fn walk_respects_the_depth_cap() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".lmstudio/models");
        write(&root.join("shallow.gguf"), b"ok");
        write(&root.join("a/b/c/d/e/deep.gguf"), b"too deep");
        let found = discover_lm_studio(&root);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].path.ends_with("shallow.gguf"));
    }

    #[test]
    fn discover_merges_all_sources_in_stable_order() {
        let home = tempfile::tempdir().unwrap();
        let ollama = home.path().join(".ollama/models");
        write(
            &ollama.join("manifests/registry.ollama.ai/library/tiny/latest"),
            br#"{"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:ab"}]}"#,
        );
        write(&ollama.join("blobs/sha256-ab"), b"g");
        write(&home.path().join(".lmstudio/models/pub/repo/m.gguf"), b"gg");
        let hub = home.path().join(".cache/huggingface/hub");
        write(&hub.join("models--o--r/snapshots/x/w.safetensors"), b"sss");
        let found = discover(home.path());
        let sources: Vec<ForeignCacheSource> = found.iter().map(|f| f.source).collect();
        assert_eq!(
            sources,
            vec![
                ForeignCacheSource::Ollama,
                ForeignCacheSource::LmStudio,
                ForeignCacheSource::HuggingFace,
            ]
        );
    }
}
