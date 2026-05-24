// SPDX-License-Identifier: BUSL-1.1
//! Config-source loader.
//!
//! The compiler historically accepted a single string of YAML and went
//! straight to parsing. The loader adds an optional `source:` discriminator
//! on [`crate::ConfigFile`] that lets operators load the underlying
//! text from places other than the inline file:
//!
//! * [`crate::ConfigSource::Local`] - keep the historical behaviour;
//!   the file the operator hands the binary is the config.
//! * [`crate::ConfigSource::Git`] - clone a remote repository at an
//!   optional revision and read one file inside it as the config text.
//! * [`crate::ConfigSource::GitOverlay`] - resolve a base source first,
//!   then layer one or more overlay sources on top, merging the YAML
//!   at each step.
//!
//! Everything in this module operates on `String` payloads. The result
//! flows straight back into [`crate::compile_config`], which keeps the
//! existing schema, env-var interpolation, and validation pipeline
//! unchanged.
//!
//! ## Recursion
//!
//! Overlay chains are bounded by [`MAX_RECURSION_DEPTH`]. The cap
//! prevents a malicious or accidental overlay loop from spinning up
//! unbounded git clones.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_yaml::Value as YamlValue;
use tempfile::TempDir;
use thiserror::Error;

use crate::types::ConfigSource;

/// Hard cap on `GitOverlay` nesting depth. The compiler trades the
/// flexibility of arbitrarily deep overlay chains for a predictable
/// upper bound on disk and network use.
pub const MAX_RECURSION_DEPTH: usize = 8;

/// Errors raised by [`load_from_source`].
///
/// Each variant carries a human-readable message; the prefix in the
/// `Display` impl tells operators which stage of the loader failed.
#[derive(Debug, Error)]
pub enum ConfigSourceError {
    /// A git clone (or local-fixture clone) failed. The wrapped string
    /// is the underlying error or the captured stderr from `git`.
    #[error("source.clone: {0}")]
    Clone(String),
    /// Reading the resolved config file off disk failed.
    #[error("source.read: {0}")]
    Read(String),
    /// Merging two YAML documents in a `GitOverlay` chain failed (one
    /// side was not parseable or the YAML root was the wrong shape).
    #[error("source.merge: {0}")]
    Merge(String),
    /// The overlay chain exceeded [`MAX_RECURSION_DEPTH`].
    #[error("source.recursion: max recursion depth exceeded")]
    RecursionLimit,
}

/// Pluggable git clone surface (test seam).
///
/// The default production implementation shells out to `git`. Tests
/// install a fake cloner that copies a fixture directory into the
/// temp dir; the loader logic stays identical.
pub trait Cloner: Send + Sync {
    /// Clone `repo` at `revision` into `dest`. The directory at `dest`
    /// exists and is empty when the cloner is invoked.
    fn clone_into(
        &self,
        repo: &str,
        revision: Option<&str>,
        dest: &Path,
    ) -> Result<(), ConfigSourceError>;
}

/// Production cloner. Shells out to the `git` binary the caller
/// configured on [`FetchContext`].
pub struct GitBinaryCloner {
    /// Path or basename of the git binary to invoke.
    pub git: PathBuf,
}

impl Cloner for GitBinaryCloner {
    fn clone_into(
        &self,
        repo: &str,
        revision: Option<&str>,
        dest: &Path,
    ) -> Result<(), ConfigSourceError> {
        // `Cloner::clone_into` is sync; the loader drives it from a
        // sync context inside an async wrapper. We shell out to the
        // sync `std::process::Command` directly so we never have to
        // ask whether we are nested inside a tokio runtime.
        let mut cmd = std::process::Command::new(&self.git);
        cmd.arg("clone").arg("--depth").arg("1");
        if let Some(rev) = revision {
            cmd.arg("--branch").arg(rev);
        }
        cmd.arg("--").arg(repo).arg(dest);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = cmd
            .output()
            .map_err(|e| ConfigSourceError::Clone(format!("spawn git: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ConfigSourceError::Clone(format!(
                "git clone failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }
}

/// Inputs the loader needs to resolve a [`ConfigSource`].
///
/// The temp-dir root is the parent directory git clones land under;
/// each `Git` invocation creates its own [`TempDir`] inside it so
/// cleanup is automatic on drop. The cloner is the strategy actually
/// used to populate that directory; production code wires
/// [`GitBinaryCloner`], tests wire a fixture-copying stub.
pub struct FetchContext {
    /// Optional override for the temp-dir parent. When `None`, the
    /// OS temp dir is used.
    pub temp_root: Option<PathBuf>,
    /// Cloner strategy used by [`ConfigSource::Git`].
    pub cloner: Box<dyn Cloner>,
}

impl FetchContext {
    /// Build a production fetch context that shells out to `git` on
    /// `PATH`.
    pub fn with_git_binary() -> Self {
        Self {
            temp_root: None,
            cloner: Box::new(GitBinaryCloner {
                git: PathBuf::from("git"),
            }),
        }
    }

    /// Build a fetch context that shells out to a specific git binary.
    pub fn with_git_binary_at(git: impl Into<PathBuf>) -> Self {
        Self {
            temp_root: None,
            cloner: Box::new(GitBinaryCloner { git: git.into() }),
        }
    }

    /// Build a fetch context with a custom cloner. The test suite uses
    /// this seam to install a fixture-copying stub in place of `git`.
    pub fn with_cloner(cloner: Box<dyn Cloner>) -> Self {
        Self {
            temp_root: None,
            cloner,
        }
    }

    fn new_tempdir(&self) -> Result<TempDir, ConfigSourceError> {
        match &self.temp_root {
            Some(root) => {
                TempDir::new_in(root).map_err(|e| ConfigSourceError::Clone(format!("tempdir: {e}")))
            }
            None => TempDir::new().map_err(|e| ConfigSourceError::Clone(format!("tempdir: {e}"))),
        }
    }
}

/// Resolve a [`ConfigSource`] to a YAML/TOML config text.
///
/// The result is the same flavour of text the caller would have
/// otherwise written inline: it flows straight into
/// [`crate::compile_config`]. `inline_text` is the content of the
/// file the operator handed the binary; it is used as the `Local`
/// payload (so the historical "no source field" path still works).
///
/// # Blocking I/O
///
/// Resolving a [`ConfigSource::Git`] source does blocking
/// filesystem work (tempdir creation, `mkdir`, `read_to_string`) and
/// shells out to `git` synchronously through [`Cloner::clone_into`].
/// That work runs inline rather than pulling a tokio runtime dependency
/// into this (public) crate: it happens at config load and reload, never
/// on the per-request path. A caller that drives this from a hot
/// reconcile loop should dispatch it to a blocking thread pool itself.
pub async fn load_from_source(
    source: &ConfigSource,
    inline_text: &str,
    fetch_ctx: &FetchContext,
) -> Result<String, ConfigSourceError> {
    load_with_depth(source, inline_text, fetch_ctx, 0)
}

fn load_with_depth(
    source: &ConfigSource,
    inline_text: &str,
    fetch_ctx: &FetchContext,
    depth: usize,
) -> Result<String, ConfigSourceError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(ConfigSourceError::RecursionLimit);
    }
    match source {
        ConfigSource::Local => Ok(inline_text.to_string()),
        ConfigSource::Git {
            repo,
            revision,
            path,
        } => load_git(repo, revision.as_deref(), path, fetch_ctx),
        ConfigSource::GitOverlay { base, overlays } => {
            let mut acc = load_with_depth(base, inline_text, fetch_ctx, depth + 1)?;
            for overlay in overlays {
                let next = load_with_depth(overlay, inline_text, fetch_ctx, depth + 1)?;
                acc = merge_yaml_text(&acc, &next)?;
            }
            Ok(acc)
        }
    }
}

fn load_git(
    repo: &str,
    revision: Option<&str>,
    path: &str,
    fetch_ctx: &FetchContext,
) -> Result<String, ConfigSourceError> {
    let tempdir = fetch_ctx.new_tempdir()?;
    let dest = tempdir.path().join("repo");
    std::fs::create_dir_all(&dest)
        .map_err(|e| ConfigSourceError::Clone(format!("mkdir target: {e}")))?;
    fetch_ctx.cloner.clone_into(repo, revision, &dest)?;
    let file_path = dest.join(path);
    let text = std::fs::read_to_string(&file_path)
        .map_err(|e| ConfigSourceError::Read(format!("{}: {e}", file_path.display())))?;
    // `tempdir` is dropped here, cleaning up the cloned tree.
    drop(tempdir);
    Ok(text)
}

/// Merge two YAML documents shallow-deep: maps are merged by key with
/// the overlay winning collisions, sequences are replaced wholesale,
/// scalars are overwritten. The result is re-serialised back to YAML
/// text so the rest of the compile path stays string-shaped.
fn merge_yaml_text(base: &str, overlay: &str) -> Result<String, ConfigSourceError> {
    let mut base_val: YamlValue = serde_yaml::from_str(base)
        .map_err(|e| ConfigSourceError::Merge(format!("parse base: {e}")))?;
    let overlay_val: YamlValue = serde_yaml::from_str(overlay)
        .map_err(|e| ConfigSourceError::Merge(format!("parse overlay: {e}")))?;
    merge_yaml_value(&mut base_val, overlay_val);
    serde_yaml::to_string(&base_val)
        .map_err(|e| ConfigSourceError::Merge(format!("serialise result: {e}")))
}

fn merge_yaml_value(base: &mut YamlValue, overlay: YamlValue) {
    match (base, overlay) {
        (YamlValue::Mapping(base_map), YamlValue::Mapping(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) => merge_yaml_value(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_val) => {
            *base_slot = overlay_val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Fixture-copying stub that swaps in for `git clone` in tests.
    /// Each `repo` key maps to a directory layout that is copied into
    /// the destination when the loader asks for it.
    struct FixtureCloner {
        // Maps `repo` URL -> list of (relative path, file contents).
        // Captured calls (repo, revision) for assertion.
        repos: HashMapOfRepos,
        calls: Mutex<Vec<(String, Option<String>)>>,
    }

    type HashMapOfRepos = std::collections::HashMap<String, Vec<(&'static str, &'static str)>>;

    impl FixtureCloner {
        fn new(repos: HashMapOfRepos) -> Self {
            Self {
                repos,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Cloner for FixtureCloner {
        fn clone_into(
            &self,
            repo: &str,
            revision: Option<&str>,
            dest: &Path,
        ) -> Result<(), ConfigSourceError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((repo.to_string(), revision.map(str::to_string)));
            let layout = self
                .repos
                .get(repo)
                .ok_or_else(|| ConfigSourceError::Clone(format!("unknown fixture repo: {repo}")))?;
            for (rel, contents) in layout {
                let target = dest.join(rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ConfigSourceError::Clone(format!("mkdir: {e}")))?;
                }
                std::fs::write(&target, contents)
                    .map_err(|e| ConfigSourceError::Clone(format!("write: {e}")))?;
            }
            Ok(())
        }
    }

    fn ctx_with(cloner: FixtureCloner) -> (FetchContext, Arc<FixtureCloner>) {
        // Wrap in Arc so the test can still inspect call counts after
        // handing ownership of the trait object to `FetchContext`.
        let arc = Arc::new(cloner);
        let trait_obj: Box<dyn Cloner> = Box::new(ArcClonerProxy(arc.clone()));
        (FetchContext::with_cloner(trait_obj), arc)
    }

    /// Thin proxy so the `FixtureCloner` can live behind an `Arc` and
    /// also be passed to `FetchContext` as a `Box<dyn Cloner>`.
    struct ArcClonerProxy(Arc<FixtureCloner>);

    impl Cloner for ArcClonerProxy {
        fn clone_into(
            &self,
            repo: &str,
            revision: Option<&str>,
            dest: &Path,
        ) -> Result<(), ConfigSourceError> {
            // Disambiguate against `ToOwned::clone_into`.
            <FixtureCloner as Cloner>::clone_into(&self.0, repo, revision, dest)
        }
    }

    #[test]
    fn local_round_trips_inline_text() {
        let ctx = FetchContext::with_git_binary();
        let inline = "proxy: {}\norigins: {}\n";
        let result = load_with_depth(&ConfigSource::Local, inline, &ctx, 0).expect("local loads");
        assert_eq!(result, inline);
    }

    #[test]
    fn git_reads_the_requested_file() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/repo.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":8080\"\n")],
        );
        let (ctx, cloner) = ctx_with(FixtureCloner::new(repos));
        let source = ConfigSource::Git {
            repo: "https://example.test/repo.git".into(),
            revision: Some("main".into()),
            path: "sb.yml".into(),
        };
        let result = load_with_depth(&source, "", &ctx, 0).expect("git loads");
        assert!(result.contains("listen"));
        let calls = cloner.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://example.test/repo.git");
        assert_eq!(calls[0].1.as_deref(), Some("main"));
    }

    #[test]
    fn git_overlay_merges_base_and_overlay() {
        let mut repos: HashMapOfRepos = std::collections::HashMap::new();
        repos.insert(
            "https://example.test/base.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":8080\"\norigins:\n  a: {}\n")],
        );
        repos.insert(
            "https://example.test/overlay.git".into(),
            vec![("sb.yml", "proxy:\n  listen: \":9090\"\norigins:\n  b: {}\n")],
        );
        let (ctx, _cloner) = ctx_with(FixtureCloner::new(repos));
        let base = ConfigSource::Git {
            repo: "https://example.test/base.git".into(),
            revision: None,
            path: "sb.yml".into(),
        };
        let overlay = ConfigSource::Git {
            repo: "https://example.test/overlay.git".into(),
            revision: None,
            path: "sb.yml".into(),
        };
        let source = ConfigSource::GitOverlay {
            base: Box::new(base),
            overlays: vec![overlay],
        };
        let merged = load_with_depth(&source, "", &ctx, 0).expect("overlay loads");
        let parsed: YamlValue = serde_yaml::from_str(&merged).expect("parse merged");
        let proxy = parsed.get("proxy").expect("proxy map");
        assert_eq!(
            proxy.get("listen").and_then(YamlValue::as_str),
            Some(":9090"),
            "overlay scalar wins"
        );
        let origins = parsed.get("origins").expect("origins map");
        assert!(origins.get("a").is_some(), "base map key survives");
        assert!(origins.get("b").is_some(), "overlay map key merges in");
    }

    #[test]
    fn recursion_limit_kicks_in_at_nine_levels() {
        // Build an overlay chain 9 levels deep. Each level wraps the
        // previous in another `GitOverlay`. The cap is 8, so the 9th
        // level must trip `RecursionLimit`.
        let mut inner = ConfigSource::Local;
        for _ in 0..9 {
            inner = ConfigSource::GitOverlay {
                base: Box::new(inner),
                overlays: vec![],
            };
        }
        let ctx = FetchContext::with_git_binary();
        let err =
            load_with_depth(&inner, "x: 1\n", &ctx, 0).expect_err("9-deep overlay must error");
        assert!(matches!(err, ConfigSourceError::RecursionLimit));
    }

    #[test]
    fn merge_overlay_replaces_scalars_and_unions_maps() {
        let base = "a: 1\nb:\n  c: 1\n  d: 2\n";
        let overlay = "b:\n  c: 9\ne: 5\n";
        let merged = merge_yaml_text(base, overlay).expect("merge ok");
        let parsed: YamlValue = serde_yaml::from_str(&merged).expect("parse");
        assert_eq!(parsed.get("a").and_then(YamlValue::as_i64), Some(1));
        assert_eq!(parsed.get("e").and_then(YamlValue::as_i64), Some(5));
        let b = parsed.get("b").expect("b");
        assert_eq!(b.get("c").and_then(YamlValue::as_i64), Some(9));
        assert_eq!(b.get("d").and_then(YamlValue::as_i64), Some(2));
    }
}
