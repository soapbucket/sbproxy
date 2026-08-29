//! Durable time-boxed MCP RBAC grants (WOR-2386, MCP02).
//!
//! A `tool_access[]` rule with `ttl` is a grant that expires unless an
//! operator renews it. The ledger records `renewed_at` per
//! `(origin, policy, tool, principal)` so a restart cannot silently
//! extend the window, and so renewal is an admin API rather than a
//! YAML edit.
//!
//! First observation of a still-configured grant seeds `renewed_at`
//! to now. After `ttl` elapses the matching `tools/call` is refused
//! until [`GrantLedger::renew`] runs.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ceiling on live grant rows. A tenant that authenticates as many
/// distinct principals cannot grow this map without bound; further
/// first-observations fail closed as expired.
pub(crate) const MAX_GRANT_ROWS: usize = 10_000;

/// One time-boxed grant's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantKey {
    /// Origin hostname the MCP action is serving.
    pub origin: String,
    /// `rbac_policies` label the matching rule lives under.
    pub policy: String,
    /// Fully-qualified tool name the grant covers.
    pub tool: String,
    /// Virtual-key name or `sub`, matching the quota store's id.
    pub principal_id: String,
}

impl GrantKey {
    /// Stable ledger row id. Hex SHA-256 of the four identity fields
    /// joined with NULs so a field containing a separator cannot alias.
    pub(crate) fn row_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.origin.as_bytes());
        hasher.update([0]);
        hasher.update(self.policy.as_bytes());
        hasher.update([0]);
        hasher.update(self.tool.as_bytes());
        hasher.update([0]);
        hasher.update(self.principal_id.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Persisted grant row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Origin hostname.
    pub origin: String,
    /// RBAC policy label.
    pub policy: String,
    /// Tool name.
    pub tool: String,
    /// Principal id the grant is bound to.
    pub principal_id: String,
    /// Unix seconds of the last renewal (or first observation).
    pub renewed_at_unix: u64,
    /// Configured lifetime in seconds, copied from the rule so a
    /// listing can show expiry without re-reading the policy.
    pub ttl_secs: u64,
}

/// Outcome of consulting the ledger for a time-boxed grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    /// The grant is in force until `expires_at_unix`.
    Active {
        /// Unix seconds when the current window ends.
        expires_at_unix: u64,
    },
    /// The grant's ttl has elapsed since last renewal.
    Expired {
        /// Unix seconds when the window ended.
        expired_at_unix: u64,
    },
    /// The ledger is at [`MAX_GRANT_ROWS`] and this row does not
    /// already exist, so a new observation cannot be recorded.
    Saturated,
}

/// Durable (or in-memory) grant clock.
pub struct GrantLedger {
    entries: Mutex<HashMap<String, GrantRecord>>,
    persist_path: Option<PathBuf>,
}

impl GrantLedger {
    /// Empty in-process ledger. A restart forgets every row, which is
    /// why compile refuses a `ttl` without `grant_ledger.path`.
    pub fn in_memory() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            persist_path: None,
        }
    }

    /// Load a previously persisted ledger, or start empty if the file
    /// is absent. A corrupt file is a hard error so a truncated write
    /// cannot silently reset every grant.
    ///
    /// # Errors
    ///
    /// Returns when the file exists but cannot be read or parsed.
    pub fn load(path: &Path) -> io::Result<Self> {
        let entries = match std::fs::read(path) {
            Ok(bytes) => {
                let rows: Vec<GrantRecord> = serde_json::from_slice(&bytes)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                rows.into_iter()
                    .map(|record| {
                        let key = GrantKey {
                            origin: record.origin.clone(),
                            policy: record.policy.clone(),
                            tool: record.tool.clone(),
                            principal_id: record.principal_id.clone(),
                        };
                        (key.row_id(), record)
                    })
                    .collect()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            entries: Mutex::new(entries),
            persist_path: Some(path.to_path_buf()),
        })
    }

    /// Record first observation or report whether the existing window
    /// is still open.
    pub fn observe(&self, key: &GrantKey, ttl: Duration, now: SystemTime) -> GrantStatus {
        let now_unix = unix_secs(now);
        let ttl_secs = ttl.as_secs().max(1);
        let id = key.row_id();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = entries.get(&id) {
            let expires_at_unix = record.renewed_at_unix.saturating_add(record.ttl_secs);
            if now_unix >= expires_at_unix {
                return GrantStatus::Expired {
                    expired_at_unix: expires_at_unix,
                };
            }
            return GrantStatus::Active { expires_at_unix };
        }
        if entries.len() >= MAX_GRANT_ROWS {
            return GrantStatus::Saturated;
        }
        let record = GrantRecord {
            origin: key.origin.clone(),
            policy: key.policy.clone(),
            tool: key.tool.clone(),
            principal_id: key.principal_id.clone(),
            renewed_at_unix: now_unix,
            ttl_secs,
        };
        entries.insert(id, record);
        drop(entries);
        let _ = self.persist();
        GrantStatus::Active {
            expires_at_unix: now_unix.saturating_add(ttl_secs),
        }
    }

    /// Reset `renewed_at` to `now` for an existing row, or insert one
    /// so an operator can grant before the first call.
    ///
    /// # Errors
    ///
    /// Returns when the ledger is saturated and the row is new, or
    /// when the durable write fails.
    pub fn renew(&self, key: &GrantKey, ttl: Duration, now: SystemTime) -> io::Result<GrantRecord> {
        let now_unix = unix_secs(now);
        let ttl_secs = ttl.as_secs().max(1);
        let id = key.row_id();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = entries.get_mut(&id) {
            record.renewed_at_unix = now_unix;
            record.ttl_secs = ttl_secs;
            let snapshot = record.clone();
            drop(entries);
            self.persist()?;
            return Ok(snapshot);
        }
        if entries.len() >= MAX_GRANT_ROWS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "mcp grant ledger is at capacity",
            ));
        }
        let record = GrantRecord {
            origin: key.origin.clone(),
            policy: key.policy.clone(),
            tool: key.tool.clone(),
            principal_id: key.principal_id.clone(),
            renewed_at_unix: now_unix,
            ttl_secs,
        };
        entries.insert(id, record.clone());
        drop(entries);
        self.persist()?;
        Ok(record)
    }

    /// Reset every row matching `origin`/`policy`/`tool`, optionally
    /// narrowed to one principal. Used by `POST /api/mcp/grants/renew`.
    ///
    /// # Errors
    ///
    /// Returns when no row matches, the ledger is saturated inserting a
    /// new row, or the durable write fails.
    pub fn renew_matching(
        &self,
        origin: &str,
        policy: &str,
        tool: &str,
        principal_id: Option<&str>,
        ttl: Duration,
        now: SystemTime,
    ) -> io::Result<Vec<GrantRecord>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let keys: Vec<GrantKey> = entries
            .values()
            .filter(|record| {
                record.origin == origin
                    && record.policy == policy
                    && record.tool == tool
                    && principal_id
                        .map(|id| record.principal_id == id)
                        .unwrap_or(true)
            })
            .map(|record| GrantKey {
                origin: record.origin.clone(),
                policy: record.policy.clone(),
                tool: record.tool.clone(),
                principal_id: record.principal_id.clone(),
            })
            .collect();
        drop(entries);
        if keys.is_empty() {
            if let Some(principal_id) = principal_id {
                let key = GrantKey {
                    origin: origin.to_string(),
                    policy: policy.to_string(),
                    tool: tool.to_string(),
                    principal_id: principal_id.to_string(),
                };
                return Ok(vec![self.renew(&key, ttl, now)?]);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no matching mcp grant",
            ));
        }
        let mut renewed = Vec::with_capacity(keys.len());
        for key in keys {
            renewed.push(self.renew(&key, ttl, now)?);
        }
        Ok(renewed)
    }

    /// Snapshot of every row, sorted by origin then tool for a stable
    /// admin listing.
    pub fn list(&self) -> Vec<GrantRecord> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows: Vec<GrantRecord> = entries.values().cloned().collect();
        rows.sort_by(|a, b| {
            (&a.origin, &a.policy, &a.tool, &a.principal_id).cmp(&(
                &b.origin,
                &b.policy,
                &b.tool,
                &b.principal_id,
            ))
        });
        rows
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<&GrantRecord> = entries.values().collect();
        persist_json(path, &rows)
    }
}

/// Parse a `tool_access[].ttl` string. Same duration vocabulary as
/// `tool_quotas[].rate.per`.
///
/// # Errors
///
/// Returns when the string is empty or uses an unsupported suffix.
pub fn parse_grant_ttl(s: &str) -> Result<Duration, String> {
    sbproxy_util::parse_duration(s)
}

pub(crate) fn persist_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            sbproxy_util::secure_fs::create_dir_all_owner_only(parent)?;
        }
    }
    let tmp = {
        let mut tmp = path.to_path_buf();
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => {
                tmp.set_extension(format!("{ext}.tmp"));
            }
            None => {
                tmp.set_extension("tmp");
            }
        }
        tmp
    };
    {
        let mut file = sbproxy_util::secure_fs::create_truncate_owner_only(&tmp)?;
        let bytes = serde_json::to_vec(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sbproxy_util::secure_fs::tighten_existing_owner_only(path)?;
    Ok(())
}

pub(crate) fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tool: &str) -> GrantKey {
        GrantKey {
            origin: "mcp.example.com".to_string(),
            policy: "analyst".to_string(),
            tool: tool.to_string(),
            principal_id: "vk_analyst".to_string(),
        }
    }

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn first_observation_seeds_the_clock_and_allows() {
        let ledger = GrantLedger::in_memory();
        let status = ledger.observe(&key("reports.hello"), Duration::from_secs(60), t0());
        assert_eq!(
            status,
            GrantStatus::Active {
                expires_at_unix: 1_700_000_000 + 60
            }
        );
    }

    #[test]
    fn elapsed_ttl_is_expired_until_renewed() {
        let ledger = GrantLedger::in_memory();
        let ttl = Duration::from_secs(60);
        assert!(matches!(
            ledger.observe(&key("reports.hello"), ttl, t0()),
            GrantStatus::Active { .. }
        ));
        let later = t0() + Duration::from_secs(61);
        assert!(matches!(
            ledger.observe(&key("reports.hello"), ttl, later),
            GrantStatus::Expired { .. }
        ));
        ledger
            .renew(&key("reports.hello"), ttl, later)
            .expect("renew");
        assert!(matches!(
            ledger.observe(&key("reports.hello"), ttl, later),
            GrantStatus::Active { .. }
        ));
    }

    #[test]
    fn restart_does_not_reset_the_clock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        let ttl = Duration::from_secs(60);
        let first = GrantLedger::load(&path).expect("load empty");
        first.observe(&key("reports.hello"), ttl, t0());
        let reloaded = GrantLedger::load(&path).expect("reload");
        let later = t0() + Duration::from_secs(61);
        assert!(
            matches!(
                reloaded.observe(&key("reports.hello"), ttl, later),
                GrantStatus::Expired { .. }
            ),
            "reloading from disk must not treat the grant as newly seeded"
        );
    }

    #[test]
    fn distinct_principals_do_not_share_a_window() {
        let ledger = GrantLedger::in_memory();
        let ttl = Duration::from_secs(60);
        let mut other = key("reports.hello");
        other.principal_id = "vk_other".to_string();
        ledger.observe(&key("reports.hello"), ttl, t0());
        let later = t0() + Duration::from_secs(61);
        assert!(matches!(
            ledger.observe(&other, ttl, later),
            GrantStatus::Active { .. }
        ));
    }
}
