// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! East-west MCP federation discovery (WOR-507).
//!
//! Qualys, DX Heroes, and CSA all flag MCP servers as the new
//! shadow IT inside enterprises: nobody discovers them the way
//! Cilium discovers services. SBproxy is uniquely positioned
//! because every east-west hop through it observes the MCP
//! `initialize` JSON-RPC handshake. This module ships the
//! per-workspace inventory the proxy hot path writes to as it
//! sees handshakes, plus the drift detector that emits an audit
//! event when a previously-known server changes its advertised
//! tool list.
//!
//! ## What this module ships
//!
//! * `McpServerObservation`: parsed shape of a single `initialize`
//!   handshake (clientInfo.name, serverInfo.name + version,
//!   protocol_version, advertised tools, first_seen, last_seen).
//! * `parse_initialize_request` / `parse_initialize_response`:
//!   readers that pull the relevant fields out of JSON-RPC bytes
//!   without allocating beyond the matched fields.
//! * `McpDiscoveryInventory`: thread-safe per-workspace inventory
//!   keyed by `(workspace_id, server_url)` with `observe()` and
//!   `snapshot()` accessors.
//! * `McpDiscoveryDrift`: typed drift record emitted by `observe()`
//!   when the new tool list differs from the prior observation.
//!
//! ## What this module does NOT do
//!
//! * Wire the observation calls into the proxy hot path. The
//!   call site is a small follow-up in `sbproxy-core`'s MCP
//!   federation forwarder; this module ships the data + drift
//!   primitives so the hot-path wire-up is a one-liner.
//! * Serve the `/admin/mcp/discovered` HTTP endpoint. The admin
//!   crate consumes `snapshot()`; the route hookup lives there.
//! * Emit audit events to the audit chain. The hot-path caller
//!   hands the returned `McpDiscoveryDrift` to the existing
//!   audit emitter (the trait surface this crate does not
//!   depend on directly).

use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Parsed shape of one observed MCP `initialize` handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerObservation {
    /// Caller-supplied client identity from the request's
    /// `clientInfo.name`. Empty when the request did not include
    /// it.
    pub client_name: String,
    /// Server name from the response's `serverInfo.name`.
    pub server_name: String,
    /// Server version from `serverInfo.version`.
    pub server_version: String,
    /// MCP protocol version the server advertised. Per the spec
    /// this is the version the server agreed to use (the server
    /// may pick a different one than the client requested when
    /// they support different versions).
    pub protocol_version: String,
    /// Tool names the server advertised in its response's
    /// `capabilities.tools.list` block, sorted + deduped for
    /// stable drift detection. Empty when the server returned no
    /// tool list inline (it advertises a separate `tools/list`
    /// endpoint instead).
    pub tools: BTreeSet<String>,
    /// First time this `(workspace_id, server_url)` pair was
    /// observed. Set on insert; never moved.
    pub first_seen: DateTime<Utc>,
    /// Most recent observation time. Updated on every observe()
    /// call for the same key.
    pub last_seen: DateTime<Utc>,
}

/// Drift event emitted by `observe()` when the new observation's
/// `tools` set differs from a prior observation's. Carries the
/// added + removed tool names so the audit consumer can render a
/// human-readable diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpDiscoveryDrift {
    /// Workspace the drift was observed in.
    pub workspace_id: String,
    /// Server URL whose tool list changed.
    pub server_url: String,
    /// Tools present on the new observation but not the prior one.
    pub added_tools: BTreeSet<String>,
    /// Tools present on the prior observation but not the new one.
    pub removed_tools: BTreeSet<String>,
    /// Server-version stamp from the new observation. Useful when
    /// the operator wants to attribute a drift to a known release.
    pub server_version: String,
    /// When the drift was observed.
    pub observed_at: DateTime<Utc>,
}

/// Composite key the inventory buckets observations by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InventoryKey {
    workspace_id: String,
    server_url: String,
}

/// Thread-safe per-workspace MCP server inventory. Writes happen
/// on the proxy hot path (one per observed `initialize`); reads
/// happen on the admin endpoint + the catalogue surface. The
/// implementation is read-mostly so the RwLock is the right
/// primitive; the per-entry record holds an `Arc` so the reader
/// snapshot does not block writes.
#[derive(Debug, Default)]
pub struct McpDiscoveryInventory {
    entries: RwLock<HashMap<InventoryKey, McpServerObservation>>,
}

impl McpDiscoveryInventory {
    /// Build a fresh inventory with no observations recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new observation under `(workspace_id, server_url)`.
    /// Returns `Some(drift)` when the observation's tool list
    /// differs from a prior observation at the same key (the
    /// caller emits the audit event); returns `None` on first
    /// observation or when the tool list is unchanged.
    pub fn observe(
        &self,
        workspace_id: &str,
        server_url: &str,
        observation: McpServerObservation,
    ) -> Option<McpDiscoveryDrift> {
        let key = InventoryKey {
            workspace_id: workspace_id.to_string(),
            server_url: server_url.to_string(),
        };
        let mut entries = self.entries.write().expect("inventory poisoned");
        match entries.get_mut(&key) {
            None => {
                entries.insert(key, observation);
                None
            }
            Some(prior) => {
                let drift = if prior.tools != observation.tools {
                    let added: BTreeSet<String> = observation
                        .tools
                        .difference(&prior.tools)
                        .cloned()
                        .collect();
                    let removed: BTreeSet<String> = prior
                        .tools
                        .difference(&observation.tools)
                        .cloned()
                        .collect();
                    Some(McpDiscoveryDrift {
                        workspace_id: workspace_id.to_string(),
                        server_url: server_url.to_string(),
                        added_tools: added,
                        removed_tools: removed,
                        server_version: observation.server_version.clone(),
                        observed_at: observation.last_seen,
                    })
                } else {
                    None
                };
                // Update the entry: first_seen stays, every other
                // field comes from the new observation.
                let first_seen = prior.first_seen;
                *prior = McpServerObservation {
                    first_seen,
                    ..observation
                };
                drift
            }
        }
    }

    /// Read-only snapshot of every observed (workspace_id,
    /// server_url) pair the inventory has seen. Returned in no
    /// particular order; the admin endpoint sorts as needed.
    pub fn snapshot(&self) -> Vec<DiscoveredServer> {
        let entries = self.entries.read().expect("inventory poisoned");
        entries
            .iter()
            .map(|(key, obs)| DiscoveredServer {
                workspace_id: key.workspace_id.clone(),
                server_url: key.server_url.clone(),
                observation: obs.clone(),
            })
            .collect()
    }

    /// Number of recorded observations. Useful for the admin
    /// endpoint's "discovered_count" header.
    pub fn len(&self) -> usize {
        self.entries.read().expect("inventory poisoned").len()
    }

    /// True when no observation has been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("inventory poisoned").is_empty()
    }
}

/// One row in the admin endpoint's response: the composite key
/// plus the parsed observation. The struct is the wire shape the
/// admin route serialises straight to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredServer {
    /// Workspace the observation belongs to.
    pub workspace_id: String,
    /// Server URL (the proxy's view of the upstream MCP server).
    pub server_url: String,
    /// Parsed observation.
    pub observation: McpServerObservation,
}

/// Parse the `clientInfo.name` field out of an MCP `initialize`
/// JSON-RPC request. Returns an empty string when the field is
/// missing; the proxy still records the observation (with an
/// empty client name) so the inventory does not silently drop
/// requests from older clients that omit `clientInfo`.
pub fn parse_initialize_request(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if value.get("method").and_then(|v| v.as_str()) != Some("initialize") {
        return None;
    }
    Some(
        value
            .get("params")
            .and_then(|p| p.get("clientInfo"))
            .and_then(|c| c.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    )
}

/// Parse the `serverInfo` block + tool list out of an MCP
/// `initialize` JSON-RPC response. Returns the parsed
/// `(server_name, server_version, protocol_version, tools)`
/// tuple. Tool extraction looks at
/// `result.capabilities.tools.list` (the inline-advertised list)
/// AND `result.serverInfo` (used as a hint when the server lists
/// tools elsewhere). Returns `None` when the body is not a
/// `initialize` response shape.
pub fn parse_initialize_response(
    body: &[u8],
) -> Option<(String, String, String, BTreeSet<String>)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let result = value.get("result")?;
    let server_info = result.get("serverInfo")?;
    let server_name = server_info
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let server_version = server_info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let protocol_version = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tools = result
        .get("capabilities")
        .and_then(|c| c.get("tools"))
        .and_then(|t| t.get("list"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some((server_name, server_version, protocol_version, tools))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn sample_observation() -> McpServerObservation {
        McpServerObservation {
            client_name: "cursor-1.0".to_string(),
            server_name: "github-mcp".to_string(),
            server_version: "0.4.2".to_string(),
            protocol_version: "2025-06-18".to_string(),
            tools: ["create_issue", "list_repos"]
                .into_iter()
                .map(String::from)
                .collect(),
            first_seen: now(),
            last_seen: now(),
        }
    }

    /// First observation under a fresh key returns `None`
    /// (no drift) and stores the record.
    #[test]
    fn first_observation_returns_no_drift() {
        let inv = McpDiscoveryInventory::new();
        let obs = sample_observation();
        let drift = inv.observe("ws-acme", "https://github-mcp.example", obs);
        assert!(drift.is_none());
        assert_eq!(inv.len(), 1);
    }

    /// Observation with the SAME tool list returns no drift
    /// (only `last_seen` updates).
    #[test]
    fn unchanged_observation_returns_no_drift() {
        let inv = McpDiscoveryInventory::new();
        let obs = sample_observation();
        inv.observe("ws-acme", "https://github-mcp.example", obs.clone());
        let drift = inv.observe("ws-acme", "https://github-mcp.example", obs);
        assert!(drift.is_none());
    }

    /// Adding a tool produces a drift record with the added
    /// name in `added_tools`. The inventory keeps the new tool
    /// list as the canonical observation.
    #[test]
    fn added_tool_surfaces_in_drift() {
        let inv = McpDiscoveryInventory::new();
        let initial = sample_observation();
        inv.observe("ws-acme", "https://github-mcp.example", initial.clone());
        let mut updated = initial;
        updated.tools.insert("close_issue".to_string());
        let drift = inv
            .observe("ws-acme", "https://github-mcp.example", updated)
            .expect("expected drift on added tool");
        assert_eq!(
            drift.added_tools,
            BTreeSet::from(["close_issue".to_string()])
        );
        assert!(drift.removed_tools.is_empty());
    }

    /// Removing a tool produces a drift record with the removed
    /// name in `removed_tools`.
    #[test]
    fn removed_tool_surfaces_in_drift() {
        let inv = McpDiscoveryInventory::new();
        let initial = sample_observation();
        inv.observe("ws-acme", "https://github-mcp.example", initial.clone());
        let mut updated = initial;
        updated.tools.remove("list_repos");
        let drift = inv
            .observe("ws-acme", "https://github-mcp.example", updated)
            .expect("expected drift on removed tool");
        assert!(drift.added_tools.is_empty());
        assert_eq!(
            drift.removed_tools,
            BTreeSet::from(["list_repos".to_string()])
        );
    }

    /// Same server URL under different workspaces produces
    /// separate inventory entries (the key is composite).
    #[test]
    fn inventory_keys_by_workspace() {
        let inv = McpDiscoveryInventory::new();
        inv.observe("ws-a", "https://github-mcp.example", sample_observation());
        inv.observe("ws-b", "https://github-mcp.example", sample_observation());
        assert_eq!(inv.len(), 2);
    }

    /// `first_seen` is pinned across subsequent observations;
    /// only `last_seen` updates.
    #[test]
    fn first_seen_pinned_on_subsequent_observations() {
        let inv = McpDiscoveryInventory::new();
        let mut initial = sample_observation();
        initial.first_seen = DateTime::from_timestamp(1_717_000_000, 0).unwrap();
        initial.last_seen = initial.first_seen;
        inv.observe("ws-acme", "https://github-mcp.example", initial.clone());
        let mut later = sample_observation();
        later.first_seen = DateTime::from_timestamp(1_717_100_000, 0).unwrap();
        later.last_seen = later.first_seen;
        inv.observe("ws-acme", "https://github-mcp.example", later);
        let snap = inv.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].observation.first_seen.timestamp(), 1_717_000_000);
        assert_eq!(snap[0].observation.last_seen.timestamp(), 1_717_100_000);
    }

    /// `parse_initialize_request` reads the client name out of
    /// a well-formed MCP initialize JSON-RPC body. Returns an
    /// empty string when the request omits `clientInfo`
    /// (older clients do).
    #[test]
    fn parse_initialize_request_reads_client_name() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {"name": "cursor-1.0", "version": "1.0"}
            }
        }"#;
        assert_eq!(
            parse_initialize_request(body).as_deref(),
            Some("cursor-1.0")
        );

        let body_no_client = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }"#;
        assert_eq!(
            parse_initialize_request(body_no_client).as_deref(),
            Some("")
        );
    }

    /// `parse_initialize_request` rejects non-initialize bodies
    /// so the hot-path observation skips request frames that are
    /// not part of the MCP handshake.
    #[test]
    fn parse_initialize_request_rejects_non_initialize() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }"#;
        assert!(parse_initialize_request(body).is_none());
    }

    /// `parse_initialize_response` pulls server name + version
    /// + protocol version + tool list out of a well-formed
    /// response body.
    #[test]
    fn parse_initialize_response_pulls_server_info() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "github-mcp", "version": "0.4.2"},
                "capabilities": {
                    "tools": {
                        "list": [
                            {"name": "create_issue"},
                            {"name": "list_repos"}
                        ]
                    }
                }
            }
        }"#;
        let (name, version, proto, tools) =
            parse_initialize_response(body).expect("parse response");
        assert_eq!(name, "github-mcp");
        assert_eq!(version, "0.4.2");
        assert_eq!(proto, "2025-06-18");
        assert_eq!(tools.len(), 2);
        assert!(tools.contains("create_issue"));
        assert!(tools.contains("list_repos"));
    }

    /// `parse_initialize_response` returns `None` when there is
    /// no `result` block (a JSON-RPC error response or any
    /// other shape).
    #[test]
    fn parse_initialize_response_rejects_error_responses() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "invalid request"}
        }"#;
        assert!(parse_initialize_response(body).is_none());
    }

    /// `snapshot()` is a stable view of the inventory; mutating
    /// the inventory after taking a snapshot does not affect
    /// the returned Vec.
    #[test]
    fn snapshot_is_stable() {
        let inv = McpDiscoveryInventory::new();
        inv.observe(
            "ws-acme",
            "https://github-mcp.example",
            sample_observation(),
        );
        let snap = inv.snapshot();
        // Mutate after snapshot.
        inv.observe("ws-acme", "https://other.example", sample_observation());
        assert_eq!(snap.len(), 1);
        assert_eq!(inv.len(), 2);
    }
}
