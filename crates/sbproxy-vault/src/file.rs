// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! File-format vault backends: YAML and JSON.
//!
//! Operator points the backend at a file containing a map of
//! `name -> secret-value` (string or nested JSON / YAML object). The
//! backend reads the file at construction, parses it into an
//! in-memory map, and serves lookups against the map. The file's
//! modification time is sampled on every read; the backend reloads
//! the file when the mtime advances, so a write-then-read cycle
//! reflects the new value without restarting the proxy.
//!
//! Use cases:
//!
//! * Local development without a cluster vault.
//! * GitOps deployments where the operator commits a JSON / YAML
//!   secret file to a private repository and provisions it onto the
//!   pod through a sidecar (the file's contents stay encrypted at
//!   rest via the operator's existing GitOps secret-encryption
//!   workflow).
//! * Operator workflows that already maintain secrets in a checked-in
//!   `secrets.yaml` and want a provider-specific secret reference.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;

use crate::manager::VaultBackend;

/// Operator-facing config for a YAML or JSON file backend.
#[derive(Debug, Clone)]
pub struct FileVaultConfig {
    /// Path to the secrets file. Must be readable by the process
    /// at construction time.
    pub path: PathBuf,
    /// File format. `yaml` and `json` are interchangeable; the parser
    /// is selected by the explicit format rather than the file
    /// extension so an operator can keep `.txt`-suffixed files
    /// versioned outside the repo's standard format detection.
    pub format: FileFormat,
}

/// Which parser the backend uses for the underlying file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// YAML 1.2 via `serde_yaml`.
    Yaml,
    /// JSON via `serde_json`. Strict shape; comments are not
    /// supported.
    Json,
}

/// File-backed vault. Reads the file at construction, caches the
/// parsed map, and reloads on observed mtime change.
pub struct FileVaultBackend {
    path: PathBuf,
    format: FileFormat,
    state: RwLock<State>,
}

struct State {
    entries: HashMap<String, String>,
    file_mtime: Option<SystemTime>,
    /// `Instant` we last touched the disk. We rate-limit stat
    /// syscalls to once per second so a busy hot path does not stat
    /// on every read.
    last_check: Instant,
}

impl FileVaultBackend {
    /// Build a backend. Reads + parses the file at construction.
    pub fn new(cfg: FileVaultConfig) -> Result<Self> {
        if cfg.path.as_os_str().is_empty() {
            anyhow::bail!("File vault: `path` must not be empty");
        }
        let (entries, mtime) = read_and_parse(&cfg.path, cfg.format)?;
        Ok(Self {
            path: cfg.path,
            format: cfg.format,
            state: RwLock::new(State {
                entries,
                file_mtime: mtime,
                last_check: Instant::now(),
            }),
        })
    }

    /// Reload the file when the on-disk mtime is newer than the
    /// cached mtime. Rate-limited to once per second so a busy hot
    /// path does not stat on every read.
    fn maybe_reload(&self) -> Result<()> {
        // Read the cached state under a read lock first; only escalate
        // to a write lock when we actually need to reload.
        let needs_check = {
            let s = self.state.read();
            s.last_check.elapsed() > std::time::Duration::from_secs(1)
        };
        if !needs_check {
            return Ok(());
        }
        let on_disk_mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        let stale = {
            let s = self.state.read();
            match (s.file_mtime, on_disk_mtime) {
                (Some(cached), Some(disk)) => disk > cached,
                (None, Some(_)) => true,
                _ => false,
            }
        };
        if stale {
            let (entries, mtime) = read_and_parse(&self.path, self.format)?;
            let mut s = self.state.write();
            s.entries = entries;
            s.file_mtime = mtime;
            s.last_check = Instant::now();
        } else {
            let mut s = self.state.write();
            s.last_check = Instant::now();
        }
        Ok(())
    }
}

impl VaultBackend for FileVaultBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.maybe_reload()?;
        let s = self.state.read();
        Ok(s.entries.get(key).cloned())
    }

    fn set(&self, _key: &str, _value: &str) -> Result<()> {
        // File backends are read-only by design: operators commit
        // changes to the file through their GitOps workflow rather
        // than through the proxy. `set` returns a helpful error
        // pointing at this.
        anyhow::bail!(
            "File vault: write path is not supported; commit changes to the secrets file through your GitOps workflow"
        )
    }
}

/// Read the file, parse it into a flat `name -> string` map, and
/// return the parsed entries + the file's mtime.
///
/// Top-level shape: a YAML mapping (or JSON object) where every leaf
/// value renders as a string. Nested objects are serialised back to
/// JSON so a credential that holds a JSON payload can be referenced
/// with `?key=<sub-field>` extraction at the resolver layer.
fn read_and_parse(
    path: &PathBuf,
    format: FileFormat,
) -> Result<(HashMap<String, String>, Option<SystemTime>)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("File vault: reading {}", path.display()))?;
    let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

    let value: serde_json::Value = match format {
        FileFormat::Yaml => serde_yaml::from_slice(&bytes)
            .with_context(|| format!("File vault: parsing YAML at {}", path.display()))?,
        FileFormat::Json => serde_json::from_slice(&bytes)
            .with_context(|| format!("File vault: parsing JSON at {}", path.display()))?,
    };

    let obj = value.as_object().ok_or_else(|| {
        anyhow!(
            "File vault: top-level value at {} must be a mapping / object",
            path.display()
        )
    })?;

    let mut entries = HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        let rendered = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => serde_json::to_string(&other).with_context(|| {
                format!("File vault: serialising entry `{k}` at {}", path.display())
            })?,
        };
        entries.insert(k.clone(), rendered);
    }

    Ok((entries, mtime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str, suffix: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    /// YAML file read: scalar entries surface verbatim; nested
    /// objects render as JSON so a `?key=<sub-field>` reference can
    /// pick a value at resolve time.
    #[test]
    fn yaml_reads_scalars_and_nested_objects() {
        let f = write_tmp(
            r#"
openai_api_key: sk-test
hashi:
  api_key: sk-hashi
  org: acme
"#,
            ".yaml",
        );
        let b = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Yaml,
        })
        .unwrap();
        assert_eq!(b.get("openai_api_key").unwrap().as_deref(), Some("sk-test"));
        // Nested object renders as JSON.
        let hashi = b.get("hashi").unwrap().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&hashi).unwrap();
        assert_eq!(parsed["api_key"], "sk-hashi");
        assert_eq!(parsed["org"], "acme");
    }

    /// JSON file read: same shape as YAML but stricter parsing.
    #[test]
    fn json_reads_scalars_and_nested_objects() {
        let f = write_tmp(
            r#"{"openai_api_key": "sk-test", "hashi": {"api_key": "sk-hashi"}}"#,
            ".json",
        );
        let b = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Json,
        })
        .unwrap();
        assert_eq!(b.get("openai_api_key").unwrap().as_deref(), Some("sk-test"));
        let hashi = b.get("hashi").unwrap().unwrap();
        assert!(hashi.contains("sk-hashi"));
    }

    /// Missing key returns `None` (the resolver treats this as a
    /// miss and falls through).
    #[test]
    fn missing_key_returns_none() {
        let f = write_tmp("openai_api_key: sk-test\n", ".yaml");
        let b = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Yaml,
        })
        .unwrap();
        assert!(b.get("nonexistent").unwrap().is_none());
    }

    /// Empty path is rejected at construction.
    #[test]
    fn empty_path_rejected() {
        let cfg = FileVaultConfig {
            path: PathBuf::new(),
            format: FileFormat::Yaml,
        };
        assert!(FileVaultBackend::new(cfg).is_err());
    }

    /// Non-mapping top-level (a YAML list, a JSON array, a scalar)
    /// is rejected so the operator gets a helpful error rather than
    /// a silent miss on every lookup.
    #[test]
    fn rejects_non_mapping_top_level() {
        let f = write_tmp(r#"["a","b"]"#, ".json");
        let err = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Json,
        })
        .err()
        .expect("non-mapping should be rejected");
        assert!(format!("{err}").contains("mapping"));
    }

    /// Invalid YAML at construction surfaces with the file path so
    /// the operator knows which file to fix.
    #[test]
    fn invalid_yaml_includes_file_path() {
        let f = write_tmp("key: [unbalanced\n", ".yaml");
        let err = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Yaml,
        })
        .err()
        .expect("invalid yaml should be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("parsing YAML"));
    }

    /// `set` is read-only.
    #[test]
    fn set_returns_helpful_error() {
        let f = write_tmp("k: v\n", ".yaml");
        let b = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Yaml,
        })
        .unwrap();
        let err = b.set("k", "v").expect_err("set should fail");
        assert!(format!("{err}").contains("GitOps"));
    }

    /// Hot-reload: writing the file after construction surfaces the
    /// new value on the next read (after the 1-second rate limit
    /// window).
    #[test]
    fn reload_picks_up_new_mtime() {
        let f = write_tmp("openai_api_key: sk-old\n", ".yaml");
        let b = FileVaultBackend::new(FileVaultConfig {
            path: f.path().to_path_buf(),
            format: FileFormat::Yaml,
        })
        .unwrap();
        assert_eq!(b.get("openai_api_key").unwrap().as_deref(), Some("sk-old"));

        // Sleep past the rate-limit window so the next read forces
        // a mtime check; rewrite the file with a future mtime.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(f.path(), b"openai_api_key: sk-new\n").unwrap();
        // bump mtime explicitly via set_file_mtime if available.
        let _ = filetime::set_file_mtime(
            f.path(),
            filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + 2,
                0,
            ),
        );

        assert_eq!(b.get("openai_api_key").unwrap().as_deref(), Some("sk-new"));
    }
}
