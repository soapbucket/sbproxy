//! Emit Cloudflare-Code-Mode TypeScript directly from an OpenAPI 3.x
//! spec, bypassing the MCP federation hop.
//!
//! Emits codemode.ts from a federated MCP tool registry; this
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
//! [`super::openapi_convert::openapi_to_mcp_tools`] and
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

use std::collections::HashSet;

use super::codemode_ts::emit_codemode_ts;
use super::federation::FederatedTool;
use super::openapi_convert::openapi_to_mcp_tools;

/// Response media types that signal a streaming response. An operation
/// is treated as streaming for codemode emission iff at least one of
/// its `2xx` responses declares one of these content types.
const STREAMING_MEDIA_TYPES: &[&str] = &["text/event-stream", "application/x-ndjson"];

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
    let streaming_ops = streaming_operation_names(spec);
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
        // An operation is streaming iff at least one of its 2xx
        // responses declares `text/event-stream` or
        // `application/x-ndjson`. The codemode emitter then renders
        // the call as `AsyncIterable<Output>` (WOR-487 follow-up).
        let streaming = streaming_ops.contains(&name);
        tools.push(FederatedTool {
            name,
            description,
            input_schema,
            server_name: OPENAPI_SOURCE_NAME.to_string(),
            streaming,
            // OpenAPI-sourced tools never carry SEP-1865 UI
            // metadata; the field is filled when the federation
            // pulls from an Apps-SDK MCP server.
            meta: None,
        });
    }
    // Sort lexicographically for reproducible output, mirroring the
    // MCP-federation path's `codemode_ts()`.
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

/// Walk the OpenAPI spec and return the set of operation tool names
/// whose responses declare a streaming media type.
///
/// The match key is the same one [`openapi_to_mcp_tools`] uses: the
/// operation's `x-mcp.name` override when present, then `operationId`,
/// then the synthesised `method_path` fallback. Matching the converter
/// here keeps the streaming flag consistent with the emitted tool
/// name, including under WOR-485 overrides.
fn streaming_operation_names(spec: &serde_json::Value) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) else {
        return out;
    };
    for (path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else {
            continue;
        };
        for (method, operation) in methods_obj {
            let Some(op) = operation.as_object() else {
                continue;
            };
            if !operation_is_streaming(op) {
                continue;
            }
            let derived;
            let name: &str = if let Some(override_name) = mcp_override_name(op) {
                override_name
            } else if let Some(id) = op.get("operationId").and_then(|v| v.as_str()) {
                id
            } else {
                derived = format!("{}_{}", method, path.replace('/', "_"));
                &derived
            };
            out.insert(name.to_string());
        }
    }
    out
}

/// True when at least one of the operation's `2xx` responses declares
/// a streaming media type.
fn operation_is_streaming(op: &serde_json::Map<String, serde_json::Value>) -> bool {
    let Some(responses) = op.get("responses").and_then(|r| r.as_object()) else {
        return false;
    };
    for (status, response) in responses {
        if !status.starts_with('2') {
            continue;
        }
        let Some(content) = response.get("content").and_then(|c| c.as_object()) else {
            continue;
        };
        if content
            .keys()
            .any(|k| STREAMING_MEDIA_TYPES.contains(&k.as_str()))
        {
            return true;
        }
    }
    false
}

/// Extract an `x-mcp.name` or `x-sbproxy-mcp.name` override. Mirrors
/// the precedence used by [`openapi_to_mcp_tools`]: the latter wins
/// when both are present.
fn mcp_override_name(op: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
    for key in ["x-mcp", "x-sbproxy-mcp"] {
        if let Some(obj) = op.get(key).and_then(|v| v.as_object()) {
            if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
                // The `x-sbproxy-mcp` pass overrides the `x-mcp` one.
                return Some(name);
            }
        }
    }
    None
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
        // The underlying converter already recognises
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

    // --- Streaming detection ---

    fn streaming_spec() -> serde_json::Value {
        json!({
            "openapi": "3.0.0",
            "paths": {
                "/feed": {
                    "get": {
                        "operationId": "streamFeed",
                        "responses": {
                            "200": {
                                "content": {
                                    "text/event-stream": {"schema": {"type": "string"}}
                                }
                            }
                        }
                    }
                },
                "/logs": {
                    "get": {
                        "operationId": "tailLogs",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/x-ndjson": {"schema": {"type": "object"}}
                                }
                            }
                        }
                    }
                },
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {"schema": {"type": "object"}}
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn sse_response_marks_operation_streaming() {
        let tools = openapi_to_federated_tools(&streaming_spec());
        let by_name: std::collections::HashMap<_, _> =
            tools.iter().map(|t| (t.name.as_str(), t)).collect();
        assert!(by_name["streamFeed"].streaming, "SSE op should stream");
        assert!(by_name["tailLogs"].streaming, "NDJSON op should stream");
        assert!(
            !by_name["listUsers"].streaming,
            "JSON response should not stream"
        );
    }

    #[test]
    fn streaming_op_emits_async_iterable_signature() {
        let out = emit_codemode_from_openapi(&streaming_spec(), "https://gw.example");
        assert!(
            out.contains("streamFeed: (input: StreamFeedInput): AsyncIterable<StreamFeedOutput>"),
            "streaming op should be AsyncIterable, got:\n{}",
            out
        );
        assert!(
            out.contains("tailLogs: (input: TailLogsInput): AsyncIterable<TailLogsOutput>"),
            "ndjson op should be AsyncIterable"
        );
        assert!(
            out.contains("listUsers: (input: ListUsersInput): Promise<ListUsersOutput>"),
            "non-streaming op should keep Promise<>"
        );
        assert!(
            out.contains("async function* __codemode_call_stream"),
            "streaming runtime helper should be emitted"
        );
    }

    #[test]
    fn x_mcp_name_override_carries_through_streaming_detection() {
        // The streaming flag should follow the x-mcp.name override so
        // the emitted module has a consistent name + signature.
        let s = json!({
            "paths": {
                "/feed": {
                    "get": {
                        "operationId": "streamFeed",
                        "x-mcp": {"name": "subscribe_feed"},
                        "responses": {
                            "200": {
                                "content": {
                                    "text/event-stream": {"schema": {"type": "string"}}
                                }
                            }
                        }
                    }
                }
            }
        });
        let tools = openapi_to_federated_tools(&s);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "subscribe_feed");
        assert!(tools[0].streaming);
    }

    #[test]
    fn non_2xx_streaming_response_does_not_promote_streaming() {
        // A 4xx error response with text/event-stream is not a
        // streaming success path; ignore it.
        let s = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "responses": {
                            "200": {
                                "content": {"application/json": {"schema": {"type": "object"}}}
                            },
                            "429": {
                                "content": {"text/event-stream": {"schema": {"type": "string"}}}
                            }
                        }
                    }
                }
            }
        });
        let tools = openapi_to_federated_tools(&s);
        assert!(!tools[0].streaming);
    }
}
