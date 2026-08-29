//! Gateway-originated hold for high-risk MCP tool calls (WOR-2454).
//!
//! A hold binds to a **content snapshot** (tool-contract digest plus
//! canonical arguments), not to a tool name. Approving one snapshot
//! cannot release a renamed tool or a call whose arguments changed.
//! The caller's HTTP connection is never held open: the gateway
//! answers immediately with a hold id, and a later retry of the same
//! snapshot consumes an approval. The store is file-backed so a
//! restart does not forget a pending or approved decision.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::grant_ledger::{persist_json, unix_secs};

/// Ceiling on live holds. Past this, a new park fails closed rather
/// than dropping an operator's pending decision to make room.
pub(crate) const MAX_HOLD_ROWS: usize = 10_000;

/// How a hold was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldState {
    /// Waiting for an operator.
    Pending,
    /// Operator approved; the next matching retry consumes this.
    Approved {
        /// Operator identity recorded on the admin call. Not verified.
        by: String,
        /// Unix seconds of the decision.
        at_unix: u64,
    },
    /// Operator refused; a matching retry parks a new hold.
    Denied {
        /// Operator identity recorded on the admin call.
        by: String,
        /// Unix seconds of the decision.
        at_unix: u64,
    },
}

/// One parked (or decided) tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hold {
    /// Opaque hold id returned to the caller.
    pub id: String,
    /// Content snapshot the approval is bound to.
    pub snapshot: String,
    /// Tool-contract digest (rename-proof identity).
    pub tool_digest: String,
    /// Advertised tool name, display only. Never used as the gate.
    pub tool_name: String,
    /// MCP action origin (`server_info.name`), not the request Host.
    pub origin: String,
    /// Caller principal id.
    pub principal_id: String,
    /// Tenant the principal belongs to. Same isolation as the quota store.
    #[serde(default)]
    pub tenant_id: String,
    /// Why the gateway held the call. No arguments, no secrets.
    pub reason: String,
    /// Unix seconds the hold was created.
    pub created_at_unix: u64,
    /// Unix seconds after which the hold is dropped, pending, denied,
    /// or an unused approval alike.
    pub expires_at_unix: u64,
    /// Current decision.
    pub state: HoldState,
}

/// Result of parking a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParkOutcome {
    /// Caller must wait; retry after an operator approves.
    Held {
        /// Hold id to surface on the JSON-RPC error.
        hold_id: String,
        /// Unix seconds the pending hold expires.
        expires_at_unix: u64,
        /// Snapshot the retry must present.
        snapshot: String,
        /// True when this call minted the row. False when it collapsed
        /// onto an already-pending hold, so notifications must not fire
        /// again.
        fresh: bool,
    },
    /// A previous approval for this snapshot was consumed; dispatch.
    Resume,
    /// The store cannot accept another row.
    Saturated,
}

/// Selector that marks a tool as requiring gateway-originated
/// approval. `digest` is the rename-proof form; `name` is a trailing-`*`
/// glob kept for operators who have not yet pinned a lockfile digest,
/// and is documented as the weaker of the two.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalSelector {
    /// Lockfile / contract digest. When set, a rename with the same
    /// contract still requires approval.
    #[serde(default)]
    pub digest: Option<String>,
    /// Tool-name glob (`crm.*`). Weaker than `digest`: a rename
    /// escapes it.
    #[serde(default)]
    pub name: Option<String>,
}

impl ApprovalSelector {
    /// True when this selector matches the live tool.
    pub fn matches(&self, tool_name: &str, tool_digest: &str) -> bool {
        if let Some(digest) = self.digest.as_deref() {
            if digest == tool_digest {
                return true;
            }
        }
        if let Some(pattern) = self.name.as_deref() {
            if sbproxy_util::prefix_glob_match(pattern, tool_name) {
                return true;
            }
        }
        false
    }
}

/// Durable hold table.
pub struct PendingConfirmStore {
    holds: Mutex<HashMap<String, Hold>>,
    persist_path: Option<PathBuf>,
    next_seq: Mutex<u64>,
}

impl PendingConfirmStore {
    /// Empty in-process store. Restarts forget every hold, which is
    /// why compile requires `approval.store` when approval is on.
    pub fn in_memory() -> Self {
        Self {
            holds: Mutex::new(HashMap::new()),
            persist_path: None,
            next_seq: Mutex::new(1),
        }
    }

    /// Load a previously persisted store, or start empty.
    ///
    /// # Errors
    ///
    /// Returns when the file exists but cannot be read or parsed.
    pub fn load(path: &Path) -> io::Result<Self> {
        let holds = match std::fs::read(path) {
            Ok(bytes) => {
                let rows: Vec<Hold> = serde_json::from_slice(&bytes)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                rows.into_iter()
                    .map(|hold| (hold.id.clone(), hold))
                    .collect()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            holds: Mutex::new(holds),
            persist_path: Some(path.to_path_buf()),
            next_seq: Mutex::new(1),
        })
    }

    /// Hash of the tool contract and the call's canonical arguments.
    /// Two calls with the same digest and the same arguments share a
    /// snapshot; a rename that preserves the contract still matches,
    /// and a same-name call with different arguments does not.
    pub fn snapshot(tool_digest: &str, arguments: &Value) -> String {
        let canonical = serde_json_canonicalizer::to_vec(arguments).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"mcp-approval-snapshot-v1");
        hasher.update([0]);
        hasher.update(tool_digest.as_bytes());
        hasher.update([0]);
        hasher.update(&canonical);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Park a call, collapse onto an existing pending hold for the
    /// same snapshot, or consume a prior approval.
    #[allow(clippy::too_many_arguments)] // snapshot identity plus hold metadata
    pub fn park(
        &self,
        tool_digest: &str,
        tool_name: &str,
        origin: &str,
        principal_id: &str,
        tenant_id: &str,
        reason: &str,
        arguments: &Value,
        hold_ttl: Duration,
        now: SystemTime,
    ) -> ParkOutcome {
        let snapshot = Self::snapshot(tool_digest, arguments);
        let now_unix = unix_secs(now);
        let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_pending(&mut holds, now_unix);
        if let Some(hold) = holds.values().find(|h| {
            same_caller(h, &snapshot, origin, principal_id, tenant_id)
                && matches!(h.state, HoldState::Approved { .. })
        }) {
            let id = hold.id.clone();
            let snapshot_hold = hold.clone();
            holds.remove(&id);
            drop(holds);
            if self.persist().is_err() {
                let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
                holds.insert(id, snapshot_hold);
                return ParkOutcome::Saturated;
            }
            return ParkOutcome::Resume;
        }
        if let Some(hold) = holds.values().find(|h| {
            same_caller(h, &snapshot, origin, principal_id, tenant_id)
                && matches!(h.state, HoldState::Pending)
                && h.expires_at_unix > now_unix
        }) {
            return ParkOutcome::Held {
                hold_id: hold.id.clone(),
                expires_at_unix: hold.expires_at_unix,
                snapshot,
                fresh: false,
            };
        }
        holds.retain(|_, hold| {
            !(same_caller(hold, &snapshot, origin, principal_id, tenant_id)
                && matches!(hold.state, HoldState::Denied { .. }))
        });
        if holds.len() >= MAX_HOLD_ROWS {
            return ParkOutcome::Saturated;
        }
        let ttl_secs = hold_ttl.as_secs().max(1);
        let mut seq = self.next_seq.lock().unwrap_or_else(|e| e.into_inner());
        let n = *seq;
        *seq = seq.saturating_add(1);
        drop(seq);
        let id = mint_hold_id(self.persist_path.as_deref(), origin, n, &snapshot);
        let hold = Hold {
            id: id.clone(),
            snapshot: snapshot.clone(),
            tool_digest: tool_digest.to_string(),
            tool_name: tool_name.to_string(),
            origin: origin.to_string(),
            principal_id: principal_id.to_string(),
            tenant_id: tenant_id.to_string(),
            reason: reason.to_string(),
            created_at_unix: now_unix,
            expires_at_unix: now_unix.saturating_add(ttl_secs),
            state: HoldState::Pending,
        };
        holds.insert(id.clone(), hold);
        drop(holds);
        if self.persist().is_err() {
            let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
            holds.remove(&id);
            return ParkOutcome::Saturated;
        }
        ParkOutcome::Held {
            hold_id: id,
            expires_at_unix: now_unix.saturating_add(ttl_secs),
            snapshot,
            fresh: true,
        }
    }

    /// Mark a pending hold approved.
    ///
    /// # Errors
    ///
    /// Returns when the id is unknown, already decided, or expired.
    pub fn approve(&self, id: &str, by: &str, now: SystemTime) -> io::Result<Hold> {
        self.decide(id, by, now, true)
    }

    /// Mark a pending hold denied.
    ///
    /// # Errors
    ///
    /// Returns when the id is unknown, already decided, or expired.
    pub fn deny(&self, id: &str, by: &str, now: SystemTime) -> io::Result<Hold> {
        self.decide(id, by, now, false)
    }

    fn decide(&self, id: &str, by: &str, now: SystemTime, approve: bool) -> io::Result<Hold> {
        let now_unix = unix_secs(now);
        let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
        let hold = holds
            .get_mut(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown mcp approval hold"))?;
        if !matches!(hold.state, HoldState::Pending) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "mcp approval hold is no longer pending",
            ));
        }
        if hold.expires_at_unix <= now_unix {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mcp approval hold has expired",
            ));
        }
        let by = redact_operator(by);
        hold.state = if approve {
            HoldState::Approved {
                by,
                at_unix: now_unix,
            }
        } else {
            HoldState::Denied {
                by,
                at_unix: now_unix,
            }
        };
        let snapshot = hold.clone();
        drop(holds);
        self.persist()?;
        Ok(snapshot)
    }

    /// True when this caller already has a pending (unexpired) or
    /// approved hold for the snapshot. Used to consume an approval
    /// before policy hooks run, so a Cedar `@confirm` retry does not
    /// park a second time.
    pub fn has_live_hold(
        &self,
        snapshot: &str,
        origin: &str,
        principal_id: &str,
        tenant_id: &str,
        now: SystemTime,
    ) -> bool {
        let now_unix = unix_secs(now);
        let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_pending(&mut holds, now_unix);
        holds.values().any(|hold| {
            same_caller(hold, snapshot, origin, principal_id, tenant_id)
                && (matches!(hold.state, HoldState::Approved { .. })
                    || (matches!(hold.state, HoldState::Pending)
                        && hold.expires_at_unix > now_unix))
        })
    }

    /// Snapshot of every hold, newest first.
    pub fn list(&self) -> Vec<Hold> {
        let mut holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_secs(SystemTime::now());
        self.expire_pending(&mut holds, now);
        let mut rows: Vec<Hold> = holds.values().cloned().collect();
        rows.sort_by_key(|hold| std::cmp::Reverse(hold.created_at_unix));
        rows
    }

    fn expire_pending(&self, holds: &mut HashMap<String, Hold>, now_unix: u64) {
        holds.retain(|_, hold| hold.expires_at_unix > now_unix);
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };
        let holds = self.holds.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<&Hold> = holds.values().collect();
        persist_json(path, &rows)
    }
}

/// Hold ids must be unique across MCP actions on one proxy. A
/// per-store sequence plus a snapshot tail collides when two
/// `approval.store` files both park seq 1 of the same snapshot, and
/// admin dispatch matches on id alone.
fn mint_hold_id(path: Option<&Path>, origin: &str, seq: u64, snapshot: &str) -> String {
    let mut hasher = Sha256::new();
    match path {
        Some(path) => hasher.update(path.to_string_lossy().as_bytes()),
        None => hasher.update(b"memory"),
    }
    hasher.update([0]);
    hasher.update(origin.as_bytes());
    hasher.update([0]);
    hasher.update(seq.to_le_bytes());
    hasher.update([0]);
    hasher.update(snapshot.as_bytes());
    format!("hold_{}", hex::encode(&hasher.finalize()[..8]))
}

fn same_caller(
    hold: &Hold,
    snapshot: &str,
    origin: &str,
    principal_id: &str,
    tenant_id: &str,
) -> bool {
    hold.snapshot == snapshot
        && hold.origin == origin
        && hold.principal_id == principal_id
        && hold.tenant_id == tenant_id
}

fn redact_operator(by: &str) -> String {
    let trimmed = by.trim();
    if trimmed.is_empty() {
        return "operator".to_string();
    }
    trimmed.chars().take(128).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn snapshot_binds_to_digest_and_arguments_not_the_name() {
        let args = json!({"target": "acct-1"});
        let a = PendingConfirmStore::snapshot("digest-a", &args);
        let b = PendingConfirmStore::snapshot("digest-a", &args);
        assert_eq!(a, b, "same digest and args must share a snapshot");
        let renamed_same_digest = PendingConfirmStore::snapshot("digest-a", &args);
        assert_eq!(
            a, renamed_same_digest,
            "a rename that preserves the contract digest must not mint a fresh snapshot"
        );
        let different_args =
            PendingConfirmStore::snapshot("digest-a", &json!({"target": "acct-2"}));
        assert_ne!(
            a, different_args,
            "approving one argument set must not release a different call"
        );
        let different_digest = PendingConfirmStore::snapshot("digest-b", &args);
        assert_ne!(
            a, different_digest,
            "a different contract must not share an approval"
        );
    }

    #[test]
    fn park_then_approve_then_retry_resumes_once() {
        let store = PendingConfirmStore::in_memory();
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let first = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        let ParkOutcome::Held {
            hold_id,
            fresh: first_fresh,
            ..
        } = first
        else {
            panic!("expected Held, got {first:?}");
        };
        assert!(first_fresh, "the first park must be a fresh insert");
        store
            .approve(&hold_id, "secops@example.com", t0())
            .expect("approve");
        assert_eq!(
            store.park(
                "digest-a",
                "crm.delete",
                "mcp.example.com",
                "vk_analyst",
                "acme",
                "high-risk tool",
                &args,
                ttl,
                t0(),
            ),
            ParkOutcome::Resume
        );
        let again = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        assert!(
            matches!(again, ParkOutcome::Held { fresh: true, .. }),
            "an approval is single-use; a second call must park again, got {again:?}"
        );
    }

    #[test]
    fn collapsing_onto_a_pending_hold_is_not_fresh() {
        let store = PendingConfirmStore::in_memory();
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let first = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        let ParkOutcome::Held {
            hold_id,
            fresh: true,
            ..
        } = first
        else {
            panic!("expected fresh Held, got {first:?}");
        };
        let second = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        let ParkOutcome::Held {
            hold_id: again,
            fresh: false,
            ..
        } = second
        else {
            panic!("retry on a pending hold must not be fresh, got {second:?}");
        };
        assert_eq!(again, hold_id);
    }

    #[test]
    fn a_rename_with_a_new_digest_does_not_consume_the_old_approval() {
        let store = PendingConfirmStore::in_memory();
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let first = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        let ParkOutcome::Held { hold_id, .. } = first else {
            panic!("expected Held");
        };
        store
            .approve(&hold_id, "secops@example.com", t0())
            .expect("approve");
        let renamed = store.park(
            "digest-b",
            "crm.purge",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        assert!(
            matches!(renamed, ParkOutcome::Held { .. }),
            "binding to the name would have resumed; the digest must not, got {renamed:?}"
        );
    }

    #[test]
    fn restart_keeps_a_pending_hold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("holds.json");
        let ttl = Duration::from_secs(600);
        let first = PendingConfirmStore::load(&path).expect("load empty");
        let parked = first.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &json!({}),
            ttl,
            t0(),
        );
        let ParkOutcome::Held { hold_id, .. } = parked else {
            panic!("expected Held");
        };
        let reloaded = PendingConfirmStore::load(&path).expect("reload");
        reloaded
            .approve(&hold_id, "secops@example.com", t0())
            .expect("approve after restart");
    }

    #[test]
    fn another_principal_cannot_consume_an_approval() {
        let store = PendingConfirmStore::in_memory();
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let first = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_alice",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        let ParkOutcome::Held { hold_id, .. } = first else {
            panic!("expected Held");
        };
        store
            .approve(&hold_id, "secops@example.com", t0())
            .expect("approve");
        let bob = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_bob",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        assert!(
            matches!(bob, ParkOutcome::Held { .. }),
            "Bob must not consume Alice's approval, got {bob:?}"
        );
        let alice = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_alice",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        );
        assert_eq!(alice, ParkOutcome::Resume);
    }

    #[test]
    fn two_store_paths_do_not_mint_the_same_hold_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staging = PendingConfirmStore::load(&dir.path().join("staging.json")).expect("staging");
        let prod = PendingConfirmStore::load(&dir.path().join("prod.json")).expect("prod");
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let ParkOutcome::Held {
            hold_id: staging_id,
            ..
        } = staging.park(
            "digest-a",
            "crm.delete",
            "staging.mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        )
        else {
            panic!("expected Held");
        };
        let ParkOutcome::Held {
            hold_id: prod_id, ..
        } = prod.park(
            "digest-a",
            "crm.delete",
            "prod.mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        )
        else {
            panic!("expected Held");
        };
        assert_ne!(
            staging_id, prod_id,
            "admin dispatch matches on id alone, so two MCP actions must not mint the same id"
        );
        prod.approve(&prod_id, "secops@example.com", t0())
            .expect("approve prod");
        assert!(
            staging
                .approve(&prod_id, "secops@example.com", t0())
                .is_err(),
            "approving prod must not decide the staging hold"
        );
    }

    #[test]
    fn a_denied_hold_is_replaced_on_retry_rather_than_accumulating() {
        let store = PendingConfirmStore::in_memory();
        let args = json!({"n": 1});
        let ttl = Duration::from_secs(600);
        let ParkOutcome::Held { hold_id, .. } = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        ) else {
            panic!("expected Held");
        };
        store
            .deny(&hold_id, "secops@example.com", t0())
            .expect("deny");
        let ParkOutcome::Held {
            hold_id: retry_id, ..
        } = store.park(
            "digest-a",
            "crm.delete",
            "mcp.example.com",
            "vk_analyst",
            "acme",
            "high-risk tool",
            &args,
            ttl,
            t0(),
        )
        else {
            panic!("expected a fresh hold after deny");
        };
        assert_ne!(hold_id, retry_id);
        let stale = store
            .approve(&hold_id, "secops@example.com", t0())
            .expect_err("denied row must be gone so it does not occupy the cap");
        assert_eq!(stale.kind(), std::io::ErrorKind::NotFound);
        store
            .approve(&retry_id, "secops@example.com", t0())
            .expect("retry is the live pending hold");
    }

    #[test]
    fn digest_selector_matches_a_renamed_tool() {
        let selector = ApprovalSelector {
            digest: Some("digest-a".to_string()),
            name: None,
        };
        assert!(selector.matches("crm.purge", "digest-a"));
        assert!(!selector.matches("crm.delete", "digest-b"));
    }
}
