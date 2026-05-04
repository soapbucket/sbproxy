//! Expose REST APIs as MCP servers by wrapping HTTP calls in MCP tool invocations.
//!
//! This module bridges an existing REST/OpenAPI service into the MCP tool
//! protocol. Given an OpenAPI spec and a base URL, it generates MCP tool
//! definitions and a dispatcher that constructs the corresponding HTTP request
//! when a tool is invoked.

/// Configuration for a REST-to-MCP bridge.
pub struct RestToMcpConfig {
    /// Base URL of the REST service (e.g. `https://api.example.com`).
    pub base_url: String,
    /// OpenAPI 3.x spec as a JSON value.
    pub openapi_spec: serde_json::Value,
}

/// Generate MCP tool definitions from an OpenAPI spec.
///
/// Delegates to [`super::openapi_convert::openapi_to_mcp_tools`] and returns
/// the resulting list of tool definition objects.
pub fn create_mcp_handler(config: &RestToMcpConfig) -> Vec<serde_json::Value> {
    super::openapi_convert::openapi_to_mcp_tools(&config.openapi_spec)
}

/// Build the request descriptor that would execute a REST API call.
///
/// Returns a JSON object describing the resolved URL, HTTP method, and
/// arguments.  Actual HTTP I/O is intentionally deferred to the caller so
/// that this function remains synchronous and easily testable.
pub fn execute_tool_as_rest(
    base_url: &str,
    method: &str,
    path: &str,
    args: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "url": format!("{}{}", base_url, path),
        "method": method,
        "args": args,
        "status": "pending"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_spec() -> serde_json::Value {
        json!({
            "openapi": "3.0.0",
            "info": {"title": "Sample", "version": "1"},
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "summary": "List all pets",
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
                        "operationId": "createPet",
                        "summary": "Create a pet"
                    }
                },
                "/pets/{id}": {
                    "get": {
                        "operationId": "getPet",
                        "summary": "Get a pet",
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
    fn create_handler_from_spec_returns_tools() {
        let config = RestToMcpConfig {
            base_url: "https://api.example.com".to_string(),
            openapi_spec: sample_spec(),
        };
        let tools = create_mcp_handler(&config);
        assert!(!tools.is_empty(), "should produce tools from OpenAPI spec");
    }

    #[test]
    fn create_handler_produces_correct_count() {
        let config = RestToMcpConfig {
            base_url: "https://api.example.com".to_string(),
            openapi_spec: sample_spec(),
        };
        let tools = create_mcp_handler(&config);
        assert_eq!(tools.len(), 3, "spec has 3 operations");
    }

    #[test]
    fn create_handler_uses_operation_ids() {
        let config = RestToMcpConfig {
            base_url: "https://api.example.com".to_string(),
            openapi_spec: sample_spec(),
        };
        let tools = create_mcp_handler(&config);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"listPets"));
        assert!(names.contains(&"createPet"));
        assert!(names.contains(&"getPet"));
    }

    #[test]
    fn execute_tool_builds_correct_url() {
        let result = execute_tool_as_rest(
            "https://api.example.com",
            "GET",
            "/pets",
            &json!({"limit": 10}),
        );
        assert_eq!(result["url"], "https://api.example.com/pets");
    }

    #[test]
    fn execute_tool_preserves_method() {
        let result = execute_tool_as_rest(
            "https://api.example.com",
            "POST",
            "/pets",
            &json!({"name": "Fido"}),
        );
        assert_eq!(result["method"], "POST");
    }

    #[test]
    fn execute_tool_preserves_args() {
        let args = json!({"id": "abc123"});
        let result = execute_tool_as_rest("https://api.example.com", "GET", "/pets/abc123", &args);
        assert_eq!(result["args"], args);
    }

    #[test]
    fn execute_tool_status_is_pending() {
        let result = execute_tool_as_rest("https://x.com", "DELETE", "/items/1", &json!({}));
        assert_eq!(result["status"], "pending");
    }

    #[test]
    fn execute_tool_concatenates_base_and_path() {
        let result = execute_tool_as_rest("https://base.io", "GET", "/v2/resource", &json!({}));
        assert_eq!(result["url"], "https://base.io/v2/resource");
    }

    #[test]
    fn create_handler_empty_spec_returns_empty() {
        let config = RestToMcpConfig {
            base_url: "https://api.example.com".to_string(),
            openapi_spec: json!({}),
        };
        let tools = create_mcp_handler(&config);
        assert!(tools.is_empty());
    }
}
