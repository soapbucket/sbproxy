// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Time-boxed MCP grant ledger and gateway-originated approval holds
//! (`GET`/`POST /api/mcp/grants`, `GET`/`POST /api/mcp/approvals`).
//!
//! The admin console page is `/admin/ui/mcp-approvals`. JSON routes
//! remain the scripting surface. The caller's MCP HTTP connection is
//! never held open.

use sbproxy_modules::action::{Action, CompiledMcpApproval};
use serde::Deserialize;
use serde_json::json;

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Dispatch grant and approval routes. Returns `None` for paths this
/// module does not own so the caller falls through.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/api/mcp/grants" if method.eq_ignore_ascii_case("GET") => Some(list_grants()),
        "/api/mcp/grants" => Some(method_not_allowed()),
        "/api/mcp/grants/renew" if method.eq_ignore_ascii_case("POST") => Some(renew_grant(body)),
        "/api/mcp/grants/renew" => Some(method_not_allowed()),
        "/api/mcp/approvals" if method.eq_ignore_ascii_case("GET") => Some(list_holds()),
        "/api/mcp/approvals" => Some(method_not_allowed()),
        _ => {
            if let Some(id) = path_only
                .strip_prefix("/api/mcp/approvals/")
                .and_then(|rest| rest.strip_suffix("/approve"))
            {
                return Some(if method.eq_ignore_ascii_case("POST") {
                    decide_hold(id, body, true)
                } else {
                    method_not_allowed()
                });
            }
            if let Some(id) = path_only
                .strip_prefix("/api/mcp/approvals/")
                .and_then(|rest| rest.strip_suffix("/deny"))
            {
                return Some(if method.eq_ignore_ascii_case("POST") {
                    decide_hold(id, body, false)
                } else {
                    method_not_allowed()
                });
            }
            None
        }
    }
}

fn method_not_allowed() -> Resp {
    (
        405,
        "application/json",
        r#"{"error":"method not allowed"}"#.to_string(),
    )
}

fn list_grants() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut grants = Vec::new();
    for (origin, action) in pipeline.config.origins.iter().zip(pipeline.actions.iter()) {
        let Action::Mcp(mcp) = action else {
            continue;
        };
        for record in mcp.grant_ledger.list() {
            grants.push(json!({
                "origin": origin.hostname.as_str(),
                "mcp_server": record.origin,
                "policy": record.policy,
                "tool": record.tool,
                "principal_id": record.principal_id,
                "tenant_id": record.tenant_id,
                "renewed_at": record.renewed_at_unix,
                "ttl_secs": record.ttl_secs,
                "expires_at": record.renewed_at_unix.saturating_add(record.ttl_secs),
            }));
        }
    }
    (
        200,
        "application/json",
        json!({
            "enabled": !grants.is_empty() || pipeline.actions.iter().any(|a| matches!(a, Action::Mcp(_))),
            "grants": grants,
            "console_page": "deferred",
        })
        .to_string(),
    )
}

#[derive(Deserialize)]
struct RenewBody {
    origin: String,
    policy: String,
    tool: String,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

fn renew_grant(body: Option<&str>) -> Resp {
    let Some(body) = body else {
        return (
            400,
            "application/json",
            r#"{"error":"JSON body required"}"#.to_string(),
        );
    };
    let parsed: RenewBody = match serde_json::from_str(body) {
        Ok(body) => body,
        Err(error) => {
            return (
                400,
                "application/json",
                json!({ "error": format!("invalid JSON body: {error}") }).to_string(),
            );
        }
    };
    let pipeline = crate::reload::current_pipeline();
    for (origin, action) in pipeline.config.origins.iter().zip(pipeline.actions.iter()) {
        let Action::Mcp(mcp) = action else {
            continue;
        };
        if origin.hostname.as_str() != parsed.origin && mcp.server_name != parsed.origin {
            continue;
        }
        let Some(policy) = mcp.rbac_policies.get(&parsed.policy) else {
            continue;
        };
        if parsed.principal.is_none() {
            if policy.matching_grant_ttl(None, &parsed.tool).is_none() {
                return (
                    400,
                    "application/json",
                    json!({ "error": "tool has no ttl on this policy" }).to_string(),
                );
            }
        } else if let Some(principal_id) = parsed.principal.as_deref() {
            let principal = grant_principal(principal_id, parsed.tenant.as_deref().unwrap_or(""));
            if policy
                .matching_grant_ttl(Some(&principal), &parsed.tool)
                .is_none()
            {
                return (
                    400,
                    "application/json",
                    json!({ "error": "tool has no ttl on this policy" }).to_string(),
                );
            }
        }
        let ledger_origin = mcp.server_name.as_str();
        match mcp.grant_ledger.renew_matching(
            ledger_origin,
            &parsed.policy,
            &parsed.tool,
            parsed.principal.as_deref(),
            parsed.tenant.as_deref(),
            |key| {
                let principal = grant_principal(&key.principal_id, &key.tenant_id);
                policy.matching_grant_ttl(Some(&principal), &key.tool)
            },
            std::time::SystemTime::now(),
        ) {
            Ok(rows) => {
                return (
                    200,
                    "application/json",
                    json!({ "renewed": rows.len(), "grants": rows }).to_string(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (
                    404,
                    "application/json",
                    json!({ "error": "no matching mcp grant" }).to_string(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                return (
                    400,
                    "application/json",
                    json!({ "error": "tool has no ttl on this policy" }).to_string(),
                );
            }
            Err(error) => {
                return (
                    500,
                    "application/json",
                    json!({ "error": error.to_string() }).to_string(),
                );
            }
        }
    }
    (
        404,
        "application/json",
        json!({ "error": "no matching mcp origin" }).to_string(),
    )
}

fn list_holds() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut holds = Vec::new();
    let mut configured = false;
    for action in &pipeline.actions {
        let Action::Mcp(mcp) = action else {
            continue;
        };
        let Some(approval): Option<&CompiledMcpApproval> = mcp.approval.as_ref() else {
            continue;
        };
        configured = true;
        for hold in approval.store.list() {
            holds.push(json!({
                "id": hold.id,
                "snapshot": hold.snapshot,
                "tool_digest": hold.tool_digest,
                "tool_name": hold.tool_name,
                "origin": hold.origin,
                "principal_id": hold.principal_id,
                "tenant_id": hold.tenant_id,
                "reason": hold.reason,
                "created_at": hold.created_at_unix,
                "expires_at": hold.expires_at_unix,
                "state": hold.state,
            }));
        }
    }
    (
        200,
        "application/json",
        json!({
            "enabled": configured,
            "holds": holds,
            "console_page": "/admin/ui/mcp-approvals",
        })
        .to_string(),
    )
}

#[derive(Deserialize)]
struct DecideBody {
    #[serde(default)]
    approved_by: Option<String>,
}

fn decide_hold(id: &str, body: Option<&str>, approve: bool) -> Resp {
    let by = match body {
        None | Some("") => "operator".to_string(),
        Some(raw) => match serde_json::from_str::<DecideBody>(raw) {
            Ok(body) => body
                .approved_by
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "operator".to_string()),
            Err(error) => {
                return (
                    400,
                    "application/json",
                    json!({ "error": format!("invalid JSON body: {error}") }).to_string(),
                );
            }
        },
    };
    let pipeline = crate::reload::current_pipeline();
    for action in &pipeline.actions {
        let Action::Mcp(mcp) = action else {
            continue;
        };
        let Some(approval) = mcp.approval.as_ref() else {
            continue;
        };
        let result = if approve {
            approval
                .store
                .approve(id, &by, std::time::SystemTime::now())
        } else {
            approval.store.deny(id, &by, std::time::SystemTime::now())
        };
        match result {
            Ok(hold) => {
                return (
                    200,
                    "application/json",
                    serde_json::to_string(&hold)
                        .unwrap_or_else(|_| r#"{"error":"failed to serialize hold"}"#.to_string()),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return (
                    409,
                    "application/json",
                    json!({ "error": "mcp approval hold is no longer pending" }).to_string(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return (
                    410,
                    "application/json",
                    json!({ "error": "mcp approval hold has expired" }).to_string(),
                );
            }
            Err(error) => {
                return (
                    500,
                    "application/json",
                    json!({ "error": error.to_string() }).to_string(),
                );
            }
        }
    }
    (
        404,
        "application/json",
        json!({ "error": "unknown mcp approval hold" }).to_string(),
    )
}

fn grant_principal(principal_id: &str, tenant_id: &str) -> sbproxy_plugin::Principal {
    sbproxy_plugin::Principal {
        tenant_id: sbproxy_plugin::TenantId::from(tenant_id),
        sub: principal_id.to_string(),
        source: sbproxy_plugin::PrincipalSource::VirtualKey,
        virtual_key: Some(sbproxy_plugin::VirtualKeyRef {
            name: principal_id.to_string(),
            allowed_providers: Vec::new(),
        }),
        attrs: sbproxy_plugin::PrincipalAttrs::default(),
    }
}
