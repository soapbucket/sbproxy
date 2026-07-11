// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Model manifest helpers (WOR-1681).
//!
//! The manifest is the operator's fleet fact sheet: which models exist,
//! where their weights come from, and the digests to verify them
//! against. It is the [`crate::catalog::Catalog`] file with the extra
//! per-entry fields ([`crate::catalog::CatalogEntry`] gained `source`,
//! `revision`, `sha256`, `hf_token`, `engine`, `pull`). This module is
//! the pure logic around it: parsing the `source:` scheme, resolving
//! the weight-cache directory precedence, and validating that the
//! `serve:` block only names models the manifest knows.
//!
//! Two pieces are deliberately out of scope here and stay at the wiring
//! layer: resolving an `hf_token` through the SecretResolver, and
//! actually acting on the [`crate::catalog::PullPolicy`]. This module
//! only expresses and validates.

use std::path::PathBuf;

/// A parsed weight `source:` scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceScheme {
    /// Hugging Face repo (`hf:Org/Repo`).
    Hf {
        /// The `Org/Repo` path.
        repo: String,
    },
    /// A local path already on disk (`file:/models/x`), fetched over no
    /// network.
    File {
        /// The local filesystem path.
        path: PathBuf,
    },
    /// ModelScope (`ms:...`), reserved and not yet supported.
    ModelScope {
        /// The raw id after `ms:`.
        id: String,
    },
}

/// Why a `source:` string could not be parsed / is unsupported.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SourceError {
    /// The scheme prefix is not one we recognize.
    #[error("unknown source scheme in '{0}'; expected hf:, file:, or ms:")]
    UnknownScheme(String),
    /// A recognized but not-yet-implemented scheme.
    #[error("source scheme '{0}' is reserved but not yet supported")]
    Unsupported(String),
    /// The scheme body was empty or malformed.
    #[error("malformed source '{0}'")]
    Malformed(String),
}

impl SourceScheme {
    /// Parse a `source:` string. A bare `Org/Repo` (no scheme) is
    /// treated as `hf:` for convenience. `ms:` parses but is reported
    /// unsupported by [`Self::require_supported`].
    pub fn parse(s: &str) -> Result<Self, SourceError> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("hf:") {
            let repo = rest.trim();
            if repo.is_empty() || !repo.contains('/') {
                return Err(SourceError::Malformed(s.to_string()));
            }
            return Ok(SourceScheme::Hf {
                repo: repo.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("file:") {
            let path = rest.trim();
            if path.is_empty() {
                return Err(SourceError::Malformed(s.to_string()));
            }
            return Ok(SourceScheme::File {
                path: PathBuf::from(path),
            });
        }
        if let Some(rest) = s.strip_prefix("ms:") {
            let id = rest.trim();
            if id.is_empty() {
                return Err(SourceError::Malformed(s.to_string()));
            }
            return Ok(SourceScheme::ModelScope { id: id.to_string() });
        }
        // No scheme: treat as an hf repo if it looks like Org/Repo.
        if s.contains('/') && !s.contains(':') {
            return Ok(SourceScheme::Hf {
                repo: s.to_string(),
            });
        }
        Err(SourceError::UnknownScheme(s.to_string()))
    }

    /// Error if this scheme is recognized but not yet runnable (`ms:`).
    pub fn require_supported(&self) -> Result<(), SourceError> {
        match self {
            SourceScheme::ModelScope { .. } => Err(SourceError::Unsupported("ms:".to_string())),
            _ => Ok(()),
        }
    }

    /// True when this source is already on local disk (no network pull).
    pub fn is_local(&self) -> bool {
        matches!(self, SourceScheme::File { .. })
    }
}

/// The default weight-cache directory, following the server-state
/// convention (WOR-1681): an explicit `cache_dir` wins, then `$HF_HOME`
/// when set, then the service path `/var/lib/sbproxy/models`. The
/// `~/.cache/sbproxy/models` fallback for a non-service run is resolved
/// at the wiring layer, which knows the home directory; this pure
/// helper takes the two values it should not read from the environment
/// itself so it stays testable.
pub fn resolve_cache_dir(configured: Option<&str>, hf_home: Option<&str>) -> PathBuf {
    if let Some(c) = configured.filter(|c| !c.trim().is_empty()) {
        return PathBuf::from(c);
    }
    if let Some(h) = hf_home.filter(|h| !h.trim().is_empty()) {
        return PathBuf::from(h);
    }
    PathBuf::from(SERVICE_CACHE_DIR)
}

/// The service weight-cache path, used for root / service installs.
pub const SERVICE_CACHE_DIR: &str = "/var/lib/sbproxy/models";

/// The default weight-cache directory for a *running* host (WOR-1797),
/// reading the environment the pure [`resolve_cache_dir`] cannot: an
/// explicit `cache_dir` wins, then `$HF_HOME`, then the service path
/// `/var/lib/sbproxy/models` when this process can actually write there
/// (a root / service install), else the per-user `~/.cache/sbproxy/models`.
///
/// This is the resolver the runtime and CLI should call so serving works
/// out of the box for a non-root user, instead of failing to create the
/// root-owned service path. It never creates the cache directory itself;
/// the writability check only creates and removes a probe file in an
/// already-existing ancestor of the service path.
pub fn resolve_cache_dir_default(configured: Option<&str>) -> PathBuf {
    if let Some(c) = configured.filter(|c| !c.trim().is_empty()) {
        return PathBuf::from(c);
    }
    if let Some(h) = std::env::var("HF_HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
    {
        return PathBuf::from(h);
    }
    let service = PathBuf::from(SERVICE_CACHE_DIR);
    if ancestor_is_writable(&service) {
        return service;
    }
    if let Some(home) = std::env::var("HOME").ok().filter(|h| !h.trim().is_empty()) {
        return PathBuf::from(home).join(".cache/sbproxy/models");
    }
    service
}

/// Whether this process can write under `path`, probed at the nearest
/// existing ancestor without creating `path` itself. Creates and removes
/// a temp file in that ancestor.
fn ancestor_is_writable(path: &std::path::Path) -> bool {
    let mut probe = path;
    let dir = loop {
        if probe.exists() {
            break probe;
        }
        match probe.parent() {
            Some(p) => probe = p,
            None => return false,
        }
    };
    let test = dir.join(".sbproxy-cache-write-test");
    match std::fs::File::create(&test) {
        Ok(_) => {
            let _ = std::fs::remove_file(&test);
            true
        }
        Err(_) => false,
    }
}

/// Validate that every model a `serve:` block names either resolves in
/// the manifest (by catalog id) or is an inline reference (`hf:` /
/// `file:`). Returns the offending name on the first miss.
pub fn validate_serve_against_manifest(
    serve_models: &[String],
    manifest: &crate::catalog::Catalog,
) -> Result<(), String> {
    for model in serve_models {
        let inline = model.starts_with("hf:") || model.starts_with("file:");
        if inline {
            continue;
        }
        // A catalog id (strip any :QUANT suffix) must be in the manifest.
        let id = model.split(':').next().unwrap_or(model);
        if manifest.get(id).is_none() {
            return Err(format!(
                "serve model '{model}' is not in the manifest and is not an inline hf:/file: reference"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hf_file_and_bare() {
        assert_eq!(
            SourceScheme::parse("hf:Qwen/Qwen3-32B").unwrap(),
            SourceScheme::Hf {
                repo: "Qwen/Qwen3-32B".into()
            }
        );
        assert_eq!(
            SourceScheme::parse("file:/models/qwen").unwrap(),
            SourceScheme::File {
                path: PathBuf::from("/models/qwen")
            }
        );
        // A bare Org/Repo is treated as hf.
        assert_eq!(
            SourceScheme::parse("Qwen/Qwen3-32B").unwrap(),
            SourceScheme::Hf {
                repo: "Qwen/Qwen3-32B".into()
            }
        );
    }

    #[test]
    fn ms_parses_but_is_unsupported() {
        let s = SourceScheme::parse("ms:qwen/Qwen3-32B").unwrap();
        assert!(matches!(s, SourceScheme::ModelScope { .. }));
        assert!(s.require_supported().is_err());
    }

    #[test]
    fn malformed_and_unknown_rejected() {
        assert!(matches!(
            SourceScheme::parse("hf:noslash"),
            Err(SourceError::Malformed(_))
        ));
        assert!(matches!(
            SourceScheme::parse("file:"),
            Err(SourceError::Malformed(_))
        ));
        assert!(matches!(
            SourceScheme::parse("wat"),
            Err(SourceError::UnknownScheme(_))
        ));
    }

    #[test]
    fn file_source_is_local() {
        assert!(SourceScheme::parse("file:/x").unwrap().is_local());
        assert!(!SourceScheme::parse("hf:a/b").unwrap().is_local());
    }

    #[test]
    fn cache_dir_precedence() {
        // configured wins.
        assert_eq!(
            resolve_cache_dir(Some("/custom"), Some("/hfhome")),
            PathBuf::from("/custom")
        );
        // then HF_HOME.
        assert_eq!(
            resolve_cache_dir(None, Some("/hfhome")),
            PathBuf::from("/hfhome")
        );
        // then the service path.
        assert_eq!(
            resolve_cache_dir(None, None),
            PathBuf::from("/var/lib/sbproxy/models")
        );
        // empty strings are ignored.
        assert_eq!(
            resolve_cache_dir(Some("  "), None),
            PathBuf::from("/var/lib/sbproxy/models")
        );
    }

    #[test]
    fn cache_dir_default_honors_explicit_and_ignores_blank() {
        // An explicit cache_dir always wins.
        assert_eq!(
            resolve_cache_dir_default(Some("/custom")),
            PathBuf::from("/custom")
        );
        // A blank string is treated as unconfigured (falls through to the
        // env / service / user-cache resolution, same as None).
        assert_eq!(
            resolve_cache_dir_default(Some("   ")),
            resolve_cache_dir_default(None)
        );
        // The unconfigured default is a real, non-empty weight-cache path
        // (the service path or the per-user cache, depending on the host).
        assert!(!resolve_cache_dir_default(None).as_os_str().is_empty());
    }

    #[test]
    fn example_manifest_parses_with_all_fields() {
        // Locks examples/model-manifest/models.yaml to the parser and
        // covers catalog v2 revision, exact files, source scheme,
        // engine, requirements, and pull policy.
        let yaml = include_str!("../../../examples/model-manifest/models.yaml");
        let cat = crate::catalog::Catalog::from_yaml(yaml).expect("example manifest parses");
        assert_eq!(cat.catalog_revision, "example-model-manifest-2026-07-10");
        let hf = cat.get("qwen2.5-0.5b-instruct").expect("managed Qwen");
        assert_eq!(hf.pull, crate::catalog::PullPolicy::OnBoot);
        let variant = hf.variants.first().expect("exact Qwen variant");
        assert_eq!(variant.id, "q4_k_m");
        assert_eq!(variant.revision, "9217f5db79a29953eb74d5343926648285ec7e67");
        assert_eq!(variant.files[0].size_bytes, 491_400_032);
        // The source scheme parses to an hf repo.
        assert_eq!(
            SourceScheme::parse(&variant.source).unwrap(),
            SourceScheme::Hf {
                repo: "Qwen/Qwen2.5-0.5B-Instruct-GGUF".into()
            }
        );
        // Air-gapped model: file: source + exact file metadata.
        let offline = cat.get("offline-coder").expect("offline");
        let variant = offline.variants.first().expect("offline variant");
        assert!(SourceScheme::parse(&variant.source).unwrap().is_local());
        assert_eq!(variant.files[0].path, "model.gguf");
        assert_eq!(variant.engines, [crate::config::EngineKind::LlamaCpp]);
    }

    #[test]
    fn validate_serve_against_manifest_catches_unknown() {
        let manifest = crate::catalog::Catalog::from_yaml(
            "\
models:
  known-model:
    hf_repo: Org/Known
    quants: [Q4_K_M]
    params: 8B
    license: apache-2.0
    family: test
    min_vram_hint_gib: 6.0
",
        )
        .expect("parse");
        // A manifest id and inline refs pass.
        assert!(validate_serve_against_manifest(
            &[
                "known-model".into(),
                "hf:Org/Repo:Q4".into(),
                "file:/m".into()
            ],
            &manifest
        )
        .is_ok());
        // An unknown id fails.
        let err = validate_serve_against_manifest(&["ghost-model".into()], &manifest).unwrap_err();
        assert!(err.contains("ghost-model"), "got: {err}");
    }
}
