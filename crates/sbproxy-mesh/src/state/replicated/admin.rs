//! Fleet-complete admin operations over the replicated substrate
//! (WOR-1947 AC7): bounded list, replicated delete, and bounded purge.
//!
//! # Pagination model
//!
//! The fleet listing walks every current mesh member in sorted node-ID
//! order and streams each member's shard digest. The page token encodes
//! `(node, after_key)` opaquely; when the token's node has left the
//! cluster by the next request, iteration resumes at the next surviving
//! node ID in sort order, so pagination always terminates and never
//! loops, even while topology changes underneath it.
//!
//! Listing is a union across holders: a key replicated on N nodes
//! appears once per holder, each entry naming the node it came from.
//! That makes the listing complete by construction (any record anyone
//! still holds is visible), at the cost of duplicates that callers
//! collapse by key. Unreachable members are reported by name rather
//! than silently skipped, so "complete" is verifiable by the caller.

use std::collections::BTreeSet;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::ReplicatedStore;

/// Hard cap on one fleet listing page.
const MAX_FLEET_PAGE: usize = 1_000;
/// Hard cap on keys purged by a single purge request.
const MAX_PURGE_KEYS: usize = 10_000;
/// Digest page size used when streaming one member's shard.
const MEMBER_DIGEST_PAGE: usize = 512;

/// One record as seen on one holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStateEntry {
    /// Replicated record key.
    pub key: String,
    /// Mesh member this entry was read from.
    pub holder: String,
    /// Stored logical version on that holder.
    pub logical_version: u64,
    /// Whether the holder's record is a deletion marker.
    pub tombstone: bool,
    /// LWW timestamp of the holder's record.
    pub timestamp_ms: u64,
    /// Node that authored the stored version.
    pub written_by: String,
}

/// One bounded page of the fleet listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatePage {
    /// Entries in `(node, key)` iteration order.
    pub entries: Vec<FleetStateEntry>,
    /// Opaque resume token; `None` when the fleet walk is complete.
    pub next_page_token: Option<String>,
    /// Members that could not be queried on this page. A non-empty list
    /// means the page is complete for reachable members only.
    pub unreachable: Vec<String>,
}

/// Outcome of a bounded fleet purge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPurgeOutcome {
    /// Keys whose replicated delete met the write consistency.
    pub deleted: u64,
    /// Keys whose replicated delete failed (retryable).
    pub failed: u64,
    /// True when the key budget was exhausted before the prefix was;
    /// the caller repeats the purge to continue.
    pub truncated: bool,
}

/// Opaque page-token payload. Serialized to JSON then base64url so key
/// bytes never leak into URL semantics.
#[derive(Debug, Serialize, Deserialize)]
struct FleetPageToken {
    /// Member the walk was on.
    node: String,
    /// Last key returned from that member.
    after: Option<String>,
}

fn encode_token(token: &FleetPageToken) -> Option<String> {
    let json = serde_json::to_vec(token).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

fn decode_token(token: &str) -> Option<FleetPageToken> {
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    serde_json::from_slice(&json).ok()
}

impl ReplicatedStore {
    /// One bounded page of every record any current member still holds.
    pub async fn fleet_state_page(
        &self,
        prefix: &str,
        page_token: Option<&str>,
        limit: usize,
    ) -> FleetStatePage {
        let limit = limit.clamp(1, MAX_FLEET_PAGE);
        let members = self.cache.member_nodes();
        let mut entries: Vec<FleetStateEntry> = Vec::new();
        let mut unreachable: Vec<String> = Vec::new();

        // Resume position: the token's member if it survives, otherwise
        // the next member in sort order (tokens never wedge on departed
        // nodes).
        let resume = page_token.and_then(decode_token);
        let (start_node, mut after): (Option<String>, Option<String>) = match resume {
            None => (members.first().cloned(), None),
            Some(token) => {
                if members.contains(&token.node) {
                    (Some(token.node), token.after)
                } else {
                    (members.iter().find(|m| **m > token.node).cloned(), None)
                }
            }
        };
        let Some(start_node) = start_node else {
            return FleetStatePage {
                entries,
                next_page_token: None,
                unreachable,
            };
        };

        let start_index = members
            .iter()
            .position(|m| *m == start_node)
            .unwrap_or(members.len());
        for member in &members[start_index..] {
            // The last key emitted for THIS member; a cut mid-member must
            // resume after this key, never after another member's key.
            let mut member_cursor: Option<String> = after.take();
            loop {
                let page = if member == self.local_node_id() {
                    Some(self.shard.digest_page(
                        prefix,
                        member_cursor.as_deref(),
                        MEMBER_DIGEST_PAGE,
                    ))
                } else {
                    match self.client_for(member) {
                        None => None,
                        Some(client) => tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            client.sync_digest(
                                prefix.to_string(),
                                member_cursor.clone(),
                                MEMBER_DIGEST_PAGE as u32,
                            ),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok),
                    }
                };
                let Some(page) = page else {
                    unreachable.push(member.clone());
                    break;
                };
                for digest in &page.entries {
                    if entries.len() == limit {
                        return FleetStatePage {
                            next_page_token: encode_token(&FleetPageToken {
                                node: member.clone(),
                                after: member_cursor,
                            }),
                            entries,
                            unreachable,
                        };
                    }
                    entries.push(FleetStateEntry {
                        key: digest.key.clone(),
                        holder: member.clone(),
                        logical_version: digest.logical_version,
                        tombstone: digest.tombstone,
                        timestamp_ms: digest.timestamp_ms,
                        written_by: digest.node_id.clone(),
                    });
                    member_cursor = Some(digest.key.clone());
                }
                if page.next_page_token.is_none() {
                    break;
                }
            }
        }
        FleetStatePage {
            entries,
            next_page_token: None,
            unreachable,
        }
    }

    /// Replicated delete of every distinct key under `prefix`, bounded by
    /// `max` keys. Deletes go through the normal tombstone quorum path,
    /// so a purge observes the same consistency and no-resurrection
    /// guarantees as a single delete.
    pub async fn fleet_purge(&self, prefix: &str, max: usize) -> FleetPurgeOutcome {
        let max = max.clamp(1, MAX_PURGE_KEYS);
        let mut keys: BTreeSet<String> = BTreeSet::new();
        let mut token: Option<String> = None;
        let mut truncated = false;
        loop {
            let page = self
                .fleet_state_page(prefix, token.as_deref(), MAX_FLEET_PAGE)
                .await;
            for entry in &page.entries {
                // Purging a tombstone again is a no-op; skip so the key
                // budget goes to live records.
                if entry.tombstone {
                    continue;
                }
                if keys.len() == max {
                    truncated = true;
                    break;
                }
                keys.insert(entry.key.clone());
            }
            if truncated || page.next_page_token.is_none() {
                break;
            }
            token = page.next_page_token;
        }

        let mut deleted = 0u64;
        let mut failed = 0u64;
        for key in keys {
            match self.delete(&key).await {
                Ok(_) => deleted += 1,
                Err(_) => failed += 1,
            }
        }
        FleetPurgeOutcome {
            deleted,
            failed,
            truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_tokens_round_trip_and_reject_garbage() {
        let token = FleetPageToken {
            node: "node-b".to_string(),
            after: Some("some:key".to_string()),
        };
        let encoded = encode_token(&token).unwrap();
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(decoded.node, "node-b");
        assert_eq!(decoded.after.as_deref(), Some("some:key"));

        assert!(decode_token("not-a-token!!!").is_none());
        assert!(decode_token("").is_none());
    }
}
