//! Tool registry for MCP servers.

use std::collections::HashMap;

use super::types::Tool;

/// Registry of available MCP tools.
pub struct ToolRegistry {
    tools: HashMap<String, RegisteredTool>,
}

/// A tool paired with its execution handler.
pub struct RegisteredTool {
    /// Tool definition advertised in "tools/list" responses.
    pub tool: Tool,
    /// Strategy used to fulfil "tools/call" requests for this tool.
    pub handler: ToolHandlerType,
}

/// How a tool call is fulfilled.
pub enum ToolHandlerType {
    /// Return a fixed JSON value.
    Static(serde_json::Value),
    /// Forward the call to another origin by name.
    Proxy {
        /// Name of the origin that handles the proxied tool call.
        origin: String,
    },
}

impl ToolRegistry {
    /// Create an empty tool registry.
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool with its handler.
    pub fn register(&mut self, tool: Tool, handler: ToolHandlerType) {
        self.tools
            .insert(tool.name.clone(), RegisteredTool { tool, handler });
    }

    /// Look up a registered tool by name.
    pub fn get(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.get(name)
    }

    /// Return all registered tool definitions.
    pub fn list_tools(&self) -> Vec<&Tool> {
        self.tools.values().map(|r| &r.tool).collect()
    }

    /// Return the number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Return true when no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
