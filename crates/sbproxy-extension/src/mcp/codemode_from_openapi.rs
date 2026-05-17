//! Emit Cloudflare-Code-Mode TypeScript directly from an OpenAPI 3.x
//! spec, bypassing the MCP federation hop.
//!
//! WOR-410 emits codemode.ts from a federated MCP tool registry; this
//! module emits the same shape from an OpenAPI spec so an operator can
//! point the gateway at a typed REST API and hand agents a typed
//! codemode module without standing up an intermediate MCP server.
//!
//! The conversion reuses [`super::openapi_convert::openapi_to_mcp_tools`]
//! to turn each `paths.<path>.<method>` entry into a tool definition
//! with a JSON-Schema input, then materialises a [`FederatedTool`] per
//! operation and runs the existing [`super::codemode_ts::emit_codemode_ts`]
//! emitter. The emitted module is byte-for-byte compatible with the
//! MCP-federation-derived output, so the runtime stub, the typing
//! conventions, and the tool-call dispatch are all shared.
//!
//! ## Naming
//!
//! Tool names default to `operationId` when present; operators that
//! prefer the `domain_noun_verb` convention from the [AWS Prescriptive
//! Guidance for MCP] can attach an `x-mcp.name` (or `x-sbproxy-mcp.name`)
//! override on the operation. The override is parsed by
//! [`super::openapi_convert::openapi_to_mcp_tools`] (WOR-485) and
//! surfaces here unchanged.
//!
//! [AWS Prescriptive Guidance for MCP]: https://docs.aws.amazon.com/prescriptive-guidance/latest/mcp-strategies/mcp-tool-strategy-organization.html
//!
//! ## Out of scope
//!
//! The matching HTTP endpoint (`GET /.well-known/mcp/codemode-from-openapi.ts`)
//! and per-tag TypeScript namespacing for very large specs ride
//! follow-up tickets. This module exposes only the library function so
//! callers can hand the emitted string back over their own surface.

use super::codemode_ts::emit_codemode_ts;
use super::federation::FederatedTool;
use super::openapi_convert::openapi_to_mcp_tools;

/// Default `server_name` stamped onto every [`FederatedTool`] the
/// converter manufactures. Surfaces in the JSDoc preamble of each
/// emitted Input interface so a reader of the generated module can tell
/// the tools came from an OpenAPI source rather than an MCP server.
pub const OPENAPI_SOURCE_NAME: &str = "openapi";

/// Emit a codemode.ts module from an OpenAPI 3.x JSON spec.
///
/// `callback_base_url` is the URL the runtime stub uses to reach the
/// gateway. Each emitted tool call POSTs to
/// `{callback_base_url}/call/{tool_name}` which the gateway dispatches
/// through its REST-to-MCP shim back to the underlying API operation.
///
/// Returns the emitted TypeScript module. Returns the empty-module
/// header alone when `spec` has no recognisable operations.
pub fn emit_codemode_from_openapi(spec: &serde_json::Value, callback_base_url: &str) -> String {
    let tools = openapi_to_federated_tools(spec);
    emit_codemode_ts(&tools, callback_base_url)
}

/// Convert an OpenAPI spec into the [`FederatedTool`] shape consumed
/// by [`super::codemode_ts::emit_codemode_ts`]. Exposed for callers
/// that want to combine OpenAPI-derived tools with tools from a live
/// MCP federation before emitting the module.
pub fn openapi_to_federated_tools(spec: &serde_json::Value) -> Vec<FederatedTool> {
    let raw = openapi_to_mcp_tools(spec);
    let mut tools = Vec::with_capacity(raw.len());
    for v in raw {
        let Some(name) = v.get("name").and_then(|n| n.as_str()).map(str::to_string) else {
            continue;
        };
        let description = v
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let input_schema = v
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
        // OpenAPI operations are single-shot today; if the spec
        // declares a streaming response (text/event-stream or
        // application/x-ndjson) we could promote `streaming` to true
        // when WOR-501 follow-up lands the OpenAPI response-media-type
        // walker. Default to false for now so the emitted module shape
        // matches the existing OpenAPI->REST callback convention.
        tools.push(FederatedTool {
            name,
            description,
            input_schema,
            server_name: OPENAPI_SOURCE_NAME.to_string(),
            streaming: false,
        });
    }
    // Sort lexicographically for reproducible output, mirroring the
    // MCP-federation path's `codemode_ts()`.
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> serde_json::Value {
        json!({
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List all users",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": {"type": "integer"}
                            }
                        ]
                    },
                    "post": {
                        "operationId": "createUser",
                        "summary": "Create a user",
                        "parameters": [
                            {
                                "name": "body",
                                "in": "body",
                                "required": true,
                                "schema": {"type": "object"}
                            }
                        ]
                    }
                },
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "description": "Get user by ID",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": true,
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        })
    }

    #[test]
    fn emits_an_input_interface_per_operation() {
        let out = emit_codemode_from_openapi(&spec(), "https://gw.example/.well-known/mcp");
        assert!(out.contains("export interface ListUsersInput"));
        assert!(out.contains("export interface CreateUserInput"));
        assert!(out.contains("export interface GetUserInput"));
    }

    #[test]
    fn emits_namespace_member_per_operation() {
        let out = emit_codemode_from_openapi(&spec(), "https://gw.example/.well-known/mcp");
        assert!(out.contains("listUsers: (input: ListUsersInput): Promise<ListUsersOutput>"));
        assert!(out.contains("createUser: (input: CreateUserInput): Promise<CreateUserOutput>"));
        assert!(out.contains("getUser: (input: GetUserInput): Promise<GetUserOutput>"));
    }

    #[test]
    fn includes_runtime_stub_with_callback_url() {
        let out = emit_codemode_from_openapi(&spec(), "https://gw.example/.well-known/mcp");
        assert!(out.contains("https://gw.example/.well-known/mcp/call/"));
        assert!(out.contains("async function __codemode_call"));
    }

    #[test]
    fn output_is_reproducible_across_invocations() {
        // Two passes against the same spec must produce identical
        // strings so operators can hash the emitted module for Etag
        // computation.
        let a = emit_codemode_from_openapi(&spec(), "x");
        let b = emit_codemode_from_openapi(&spec(), "x");
        assert_eq!(a, b);
    }

    #[test]
    fn tools_appear_in_lexicographic_order() {
        let out = emit_codemode_from_openapi(&spec(), "x");
        let idx_create = out
            .find("createUser:")
            .expect("createUser present in namespace block");
        let idx_get = out
            .find("getUser:")
            .expect("getUser present in namespace block");
        let idx_list = out
            .find("listUsers:")
            .expect("listUsers present in namespace block");
        assert!(idx_create < idx_get);
        assert!(idx_get < idx_list);
    }

    #[test]
    fn empty_paths_yields_a_valid_module_header() {
        let out = emit_codemode_from_openapi(&json!({"openapi": "3.0.0", "paths": {}}), "x");
        // The module still emits the namespace block, just with no
        // members. tsc accepts an empty `as const` object.
        assert!(out.contains("export const codemode = {"));
        assert!(out.contains("} as const;"));
    }

    #[test]
    fn openapi_to_federated_tools_stamps_source_name() {
        let tools = openapi_to_federated_tools(&spec());
        assert_eq!(tools.len(), 3);
        for t in &tools {
            assert_eq!(t.server_name, OPENAPI_SOURCE_NAME);
        }
    }

    #[test]
    fn honours_x_mcp_extension_overrides() {
        // The underlying converter (WOR-485) already recognises
        // `x-mcp.name` overrides; verify the rename surfaces through
        // the OpenAPI->codemode path end to end.
        let s = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": {"name": "fetch_users"}
                    }
                }
            }
        });
        let out = emit_codemode_from_openapi(&s, "x");
        assert!(out.contains("fetch_users:"));
        assert!(!out.contains("listUsers:"));
    }

    #[test]
    fn x_mcp_disabled_operation_is_omitted() {
        let s = json!({
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers", "x-mcp": false},
                    "post": {"operationId": "createUser"}
                }
            }
        });
        let out = emit_codemode_from_openapi(&s, "x");
        assert!(!out.contains("listUsers:"));
        assert!(out.contains("createUser:"));
    }

    #[test]
    fn tag_filter_propagates_from_root_x_mcp_defaults() {
        let s = json!({
            "x-mcp-defaults": {"exclude_tags": ["admin"]},
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers", "tags": ["public"]},
                    "post": {"operationId": "createUser", "tags": ["admin"]}
                }
            }
        });
        let out = emit_codemode_from_openapi(&s, "x");
        assert!(out.contains("listUsers:"));
        assert!(!out.contains("createUser:"));
    }
}
