//! Convert OpenAPI 3.x spec to MCP tool definitions.
//!
//! Each path+method combination in an OpenAPI spec becomes a single MCP tool.
//! The tool name is taken from `operationId` when present, otherwise derived
//! from the HTTP method and path.
//!
//! Operators can shape the emission via OpenAPI extensions without forking the
//! spec:
//!
//! * Per-operation `x-mcp` (or `x-sbproxy-mcp` alias) recognises the Speakeasy
//!   `x-speakeasy-mcp` shape. Set the value to `false` to suppress the
//!   operation entirely, or to an object with `name` / `description` / `scope`
//!   keys to override the generated tool fields.
//! * Root-level `x-mcp-defaults` (or `x-sbproxy-mcp-defaults` alias) carries
//!   `include_tags` and `exclude_tags` arrays so an operator can flip whole
//!   OpenAPI tags in or out of the emitted tool set without per-operation
//!   annotation. `include_tags` is an allowlist: when set, every emitted
//!   operation must carry at least one listed tag. `exclude_tags` is a
//!   denylist that applies after `include_tags`.

use std::collections::HashSet;

/// Parsed per-operation `x-mcp` / `x-sbproxy-mcp` overlay.
#[derive(Debug, Default, Clone)]
struct McpOpExtension {
    /// `x-mcp: false` (or the object form `{ "enabled": false }`) suppresses
    /// the operation entirely. None means "no opinion".
    enabled: Option<bool>,
    name: Option<String>,
    description: Option<String>,
    scope: Option<String>,
}

impl McpOpExtension {
    /// Parse a single `x-mcp` / `x-sbproxy-mcp` value. Recognises the boolean
    /// shorthand (`false` = disabled), the boolean `enabled` key, and the
    /// string overrides `name`, `description`, `scope`. Unknown keys are
    /// ignored so the extension can grow without breaking callers.
    fn from_value(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Bool(b) => Self {
                enabled: Some(*b),
                ..Self::default()
            },
            serde_json::Value::Object(map) => Self {
                enabled: map.get("enabled").and_then(|x| x.as_bool()),
                name: map.get("name").and_then(|x| x.as_str()).map(str::to_string),
                description: map
                    .get("description")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                scope: map
                    .get("scope")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            },
            _ => Self::default(),
        }
    }

    /// Merge `other` over `self`. Fields set in `other` take precedence; this
    /// lets `x-sbproxy-mcp` win over `x-mcp` when an operator wants to
    /// disambiguate from Speakeasy's own `x-speakeasy-mcp`.
    fn merge_over(mut self, other: Self) -> Self {
        if other.enabled.is_some() {
            self.enabled = other.enabled;
        }
        if other.name.is_some() {
            self.name = other.name;
        }
        if other.description.is_some() {
            self.description = other.description;
        }
        if other.scope.is_some() {
            self.scope = other.scope;
        }
        self
    }
}

/// Root-level tag filter parsed from `x-mcp-defaults` / `x-sbproxy-mcp-defaults`.
#[derive(Debug, Default, Clone)]
struct TagFilter {
    include: Option<HashSet<String>>,
    exclude: HashSet<String>,
}

impl TagFilter {
    fn from_spec(spec: &serde_json::Value) -> Self {
        let mut filter = Self::default();
        for key in ["x-mcp-defaults", "x-sbproxy-mcp-defaults"] {
            let Some(obj) = spec.get(key).and_then(|v| v.as_object()) else {
                continue;
            };
            if let Some(arr) = obj.get("include_tags").and_then(|v| v.as_array()) {
                let set: HashSet<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                if !set.is_empty() {
                    filter.include = Some(set);
                }
            }
            if let Some(arr) = obj.get("exclude_tags").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        filter.exclude.insert(s.to_string());
                    }
                }
            }
        }
        filter
    }

    /// Whether an operation with the given tag list passes the filter.
    fn admits(&self, op: &serde_json::Map<String, serde_json::Value>) -> bool {
        let tags: Vec<&str> = op
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        if let Some(allow) = &self.include {
            if !tags.iter().any(|t| allow.contains(*t)) {
                return false;
            }
        }
        if tags.iter().any(|t| self.exclude.contains(*t)) {
            return false;
        }
        true
    }
}

/// Convert an OpenAPI 3.x JSON spec into a list of MCP tool definition objects.
///
/// Each operation in `spec["paths"]` becomes one tool with `name`,
/// `description`, and `inputSchema` fields. When the operator attaches a
/// `scope` via `x-mcp.scope`, the emitted object also carries a `scope` field
/// the resolver can filter on.
pub fn openapi_to_mcp_tools(spec: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut tools = Vec::new();
    let tag_filter = TagFilter::from_spec(spec);
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

            let ext = op
                .get("x-mcp")
                .map(McpOpExtension::from_value)
                .unwrap_or_default()
                .merge_over(
                    op.get("x-sbproxy-mcp")
                        .map(McpOpExtension::from_value)
                        .unwrap_or_default(),
                );

            if ext.enabled == Some(false) {
                continue;
            }

            if !tag_filter.admits(op) {
                continue;
            }

            // Derive tool name from the extension override, the operationId,
            // or fall back to `method_path`.
            let derived_name;
            let name: &str = if let Some(n) = ext.name.as_deref() {
                n
            } else if let Some(n) = op.get("operationId").and_then(|v| v.as_str()) {
                n
            } else {
                derived_name = format!("{}_{}", method, path.replace('/', "_"));
                &derived_name
            };

            let description: &str = if let Some(d) = ext.description.as_deref() {
                d
            } else {
                op.get("summary")
                    .or_else(|| op.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            };

            let mut tool = serde_json::json!({
                "name": name,
                "description": description,
                "inputSchema": build_input_schema(op),
            });
            if let Some(scope) = &ext.scope {
                tool.as_object_mut().unwrap().insert(
                    "scope".to_string(),
                    serde_json::Value::String(scope.clone()),
                );
            }
            tools.push(tool);
        }
    }

    tools
}

/// One REST route derived from an OpenAPI operation (WOR-1648): the
/// MCP tool name paired with the HTTP method and path template it
/// dispatches to. Path parameters stay in `{brace}` form; the caller
/// substitutes them from the tool-call arguments at dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiRoute {
    /// MCP tool name (same derivation as `openapi_to_mcp_tools`).
    pub name: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// Path template, e.g. `/pets/{id}`.
    pub path: String,
}

/// Derive the REST routing table from an OpenAPI spec, one entry per
/// operation, using the same tool-name derivation and the same
/// enabled/tag filtering as [`openapi_to_mcp_tools`], so the routes
/// and the emitted tools stay in lockstep (WOR-1648).
pub fn openapi_to_routes(spec: &serde_json::Value) -> Vec<OpenApiRoute> {
    let mut routes = Vec::new();
    let tag_filter = TagFilter::from_spec(spec);
    let paths = match spec.get("paths").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return routes,
    };
    for (path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else {
            continue;
        };
        for (method, operation) in methods_obj {
            let Some(op) = operation.as_object() else {
                continue;
            };
            let ext = op
                .get("x-mcp")
                .map(McpOpExtension::from_value)
                .unwrap_or_default()
                .merge_over(
                    op.get("x-sbproxy-mcp")
                        .map(McpOpExtension::from_value)
                        .unwrap_or_default(),
                );
            if ext.enabled == Some(false) || !tag_filter.admits(op) {
                continue;
            }
            let derived_name;
            let name: &str = if let Some(n) = ext.name.as_deref() {
                n
            } else if let Some(n) = op.get("operationId").and_then(|v| v.as_str()) {
                n
            } else {
                derived_name = format!("{}_{}", method, path.replace('/', "_"));
                &derived_name
            };
            routes.push(OpenApiRoute {
                name: name.to_string(),
                method: method.to_ascii_uppercase(),
                path: path.clone(),
            });
        }
    }
    routes
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

    #[test]
    fn routes_track_the_emitted_tools() {
        let spec = json!({
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1"},
            "paths": {
                "/pets": {"get": {"operationId": "listPets"}},
                "/pets/{id}": {"get": {"operationId": "getPet"}}
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        let routes = openapi_to_routes(&spec);
        // One route per emitted tool, names in lockstep.
        assert_eq!(tools.len(), routes.len());
        let get_pet = routes
            .iter()
            .find(|r| r.name == "getPet")
            .expect("getPet route");
        assert_eq!(get_pet.method, "GET");
        assert_eq!(get_pet.path, "/pets/{id}");
    }

    #[test]
    fn routes_respect_disabled_operations() {
        let spec = json!({
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1"},
            "paths": {
                "/a": {"get": {"operationId": "a"}},
                "/b": {"get": {"operationId": "b", "x-mcp": {"enabled": false}}}
            }
        });
        let routes = openapi_to_routes(&spec);
        let names: Vec<&str> = routes.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(!names.contains(&"b"), "disabled op must not route");
    }

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

    #[test]
    fn x_mcp_false_suppresses_operation() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": false
                    },
                    "post": {
                        "operationId": "createUser"
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(!names.contains(&"listUsers"));
        assert!(names.contains(&"createUser"));
    }

    #[test]
    fn x_mcp_object_enabled_false_suppresses_operation() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": {"enabled": false}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert!(tools.is_empty());
    }

    #[test]
    fn x_mcp_name_overrides_operation_id() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": {"name": "fetch_users"}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "fetch_users");
    }

    #[test]
    fn x_mcp_description_overrides_summary() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "summary text",
                        "x-mcp": {"description": "override text"}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools[0]["description"], "override text");
    }

    #[test]
    fn x_mcp_scope_emitted_on_tool() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": {"scope": "read:users"}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools[0]["scope"], "read:users");
    }

    #[test]
    fn x_sbproxy_mcp_alias_recognised() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-sbproxy-mcp": {"name": "alias_name", "scope": "read:users"}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools[0]["name"], "alias_name");
        assert_eq!(tools[0]["scope"], "read:users");
    }

    #[test]
    fn x_sbproxy_mcp_overrides_x_mcp() {
        let spec = json!({
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "x-mcp": {"name": "from_x_mcp"},
                        "x-sbproxy-mcp": {"name": "from_x_sbproxy_mcp"}
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert_eq!(tools[0]["name"], "from_x_sbproxy_mcp");
    }

    #[test]
    fn x_mcp_defaults_exclude_tags_removes_tagged_operations() {
        let spec = json!({
            "x-mcp-defaults": {"exclude_tags": ["admin"]},
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers", "tags": ["public"]},
                    "post": {"operationId": "createUser", "tags": ["admin"]}
                },
                "/admin/users": {
                    "delete": {"operationId": "deleteUser", "tags": ["admin", "destructive"]}
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"listUsers"));
        assert!(!names.contains(&"createUser"));
        assert!(!names.contains(&"deleteUser"));
    }

    #[test]
    fn x_mcp_defaults_include_tags_acts_as_allowlist() {
        let spec = json!({
            "x-mcp-defaults": {"include_tags": ["public"]},
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers", "tags": ["public"]},
                    "post": {"operationId": "createUser", "tags": ["admin"]}
                },
                "/items": {
                    "get": {"operationId": "listItems"}
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"listUsers"));
        assert!(!names.contains(&"createUser"));
        assert!(
            !names.contains(&"listItems"),
            "operation with no tags is excluded when include_tags is set"
        );
    }

    #[test]
    fn x_mcp_defaults_alias_x_sbproxy_recognised() {
        let spec = json!({
            "x-sbproxy-mcp-defaults": {"exclude_tags": ["internal"]},
            "paths": {
                "/keep": {"get": {"operationId": "keep", "tags": ["public"]}},
                "/drop": {"get": {"operationId": "drop", "tags": ["internal"]}}
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"keep"));
        assert!(!names.contains(&"drop"));
    }

    #[test]
    fn x_mcp_overrides_take_precedence_over_tag_filter_disabled() {
        // An operation with x-mcp: false is dropped even if it would
        // otherwise pass the tag filter, because the per-operation
        // opt-out is the strongest signal.
        let spec = json!({
            "x-mcp-defaults": {"include_tags": ["public"]},
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "tags": ["public"],
                        "x-mcp": false
                    }
                }
            }
        });
        let tools = openapi_to_mcp_tools(&spec);
        assert!(tools.is_empty());
    }
}
