// MCP Cedar schema (default).
//
// This is the default authoring schema for MCP-aware Cedar policies:
// it declares the entity types and actions a policy author writes
// `permit` / `forbid` statements against when governing MCP tool
// calls. Workspaces may extend it with their own namespaced entity
// types and actions; see `McpSchemaConfig::workspace_override` and
// `merged_schema` in `src/cedar/schema/mcp.rs`.
//
// Maintained as a versioned, semver-stable artifact: additive at
// minor releases, breaking only at major.

entity Agent in [AgentClass] = {
    id: String,
    capabilities: Set<String>,
    session_id: String,
    workspace: String,
    tenant: String,
};

entity AgentClass = {
    name: String,
    verified: Bool,
};

entity User = {
    id: String,
    email: String,
    groups: Set<Group>,
};

entity Group;

entity Server = {
    id: String,
    transport: String,
    capabilities: Set<String>,
};

entity Tool = {
    name: String,
    server: Server,
};

entity ToolInvocation = {
    tool: Tool,
    arguments: Set<ArgumentBinding>,
};

entity ArgumentBinding = {
    name: String,
    value: String,
};

action "MCP::Initialize" appliesTo {
    principal: [Agent],
    resource: [Server],
};

action "MCP::ListTools" appliesTo {
    principal: [Agent],
    resource: [Server],
};

action "MCP::CallTool" appliesTo {
    principal: [Agent],
    resource: [ToolInvocation],
};

action "MCP::Ping" appliesTo {
    principal: [Agent],
    resource: [Server],
};
