//! Convert OpenAPI 3.x spec to MCP tool definitions.
//!
//! Each path+method combination in an OpenAPI spec becomes a single MCP tool.
//! The tool name is taken from `operationId` when present, otherwise derived
//! from the HTTP method and path.

/// Convert an OpenAPI 3.x JSON spec into a list of MCP tool definition objects.
///
/// Each operation in `spec["paths"]` becomes one tool with `name`,
/// `description`, and `inputSchema` fields.
pub fn openapi_to_mcp_tools(spec: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut tools = Vec::new();
    let paths = match spec.get("paths").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return tools,
    };

    for (path, methods) in paths {
        let methods_obj = match methods.as_object() {
            Some(m) => m,
            None => continue,
        };

        for (method, operation) in methods_obj {
            let op = match operation.as_object() {
                Some(o) => o,
                None => continue,
            };

            // Derive tool name from operationId or fall back to method_path.
            let derived_name;
            let name = if let Some(n) = op.get("operationId").and_then(|v| v.as_str()) {
                n
            } else {
                derived_name = format!("{}_{}", method, path.replace('/', "_"));
                &derived_name
            };

            let description = op
                .get("summary")
                .or_else(|| op.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            tools.push(serde_json::json!({
                "name": name,
                "description": description,
                "inputSchema": build_input_schema(op),
            }));
        }
    }

    tools
}

/// Build an MCP `inputSchema` from OpenAPI operation parameters.
fn build_input_schema(operation: &serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<serde_json::Value> = Vec::new();

    if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
        for param in params {
            let name = match param.get("name").and_then(|n| n.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let schema = match param.get("schema") {
                Some(s) => s.clone(),
                None => serde_json::json!({"type": "string"}),
            };
            properties.insert(name.to_string(), schema);
            if param
                .get("required")
                .and_then(|r| r.as_bool())
                .unwrap_or(false)
            {
                required.push(serde_json::Value::String(name.to_string()));
            }
        }
    }

    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn simple_spec() -> serde_json::Value {
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
    fn parse_simple_spec_returns_tools() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        assert!(!tools.is_empty(), "should produce at least one tool");
    }

    #[test]
    fn multiple_endpoints_produce_multiple_tools() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        // /users GET, /users POST, /users/{id} GET = 3 tools
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn operation_id_used_as_name() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"listUsers"));
        assert!(names.contains(&"createUser"));
        assert!(names.contains(&"getUser"));
    }

    #[test]
    fn missing_operation_id_uses_method_and_path() {
        let spec = json!({
            "paths": {
                "/items": {
                    "delete": {
                        "summary": "Delete items"
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools.len(), 1);
        let name = tools[0]["name"].as_str().unwrap();
        assert!(
            name.contains("delete"),
            "name '{}' should contain 'delete'",
            name
        );
        assert!(
            name.contains("items"),
            "name '{}' should contain 'items'",
            name
        );
    }

    #[test]
    fn required_parameters_in_required_array() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        let get_user = tools
            .iter()
            .find(|t| t["name"] == "getUser")
            .expect("getUser tool should exist");
        let required = &get_user["inputSchema"]["required"];
        let req_arr = required.as_array().unwrap();
        assert!(req_arr.iter().any(|r| r == "id"), "id should be required");
    }

    #[test]
    fn optional_parameters_not_in_required_array() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        let list_users = tools
            .iter()
            .find(|t| t["name"] == "listUsers")
            .expect("listUsers tool should exist");
        let required = &list_users["inputSchema"]["required"];
        let req_arr = required.as_array().unwrap();
        assert!(
            !req_arr.iter().any(|r| r == "limit"),
            "limit should NOT be required"
        );
    }

    #[test]
    fn description_from_summary_or_description() {
        let tools = openapi_to_mcp_tools(&simple_spec());
        let get_user = tools
            .iter()
            .find(|t| t["name"] == "getUser")
            .expect("getUser tool should exist");
        assert_eq!(get_user["description"], "Get user by ID");
    }

    #[test]
    fn empty_spec_returns_empty_vec() {
        let spec = json!({});
        let tools = openapi_to_mcp_tools(&spec);
        assert!(tools.is_empty());
    }
}
