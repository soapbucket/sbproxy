//! Agent-to-Agent (A2A) capability discovery registry.
//!
//! Agents register their capabilities here so that other agents can discover
//! peers that can perform a given task.

use parking_lot::Mutex;
use std::collections::HashMap;

/// Describes a single capability that an agent exposes.
pub struct AgentCapability {
    /// Human-readable name that identifies the capability.
    pub name: String,
    /// Human-readable description of what the capability does.
    pub description: String,
    /// JSON Schema describing the expected input.
    pub input_schema: serde_json::Value,
    /// JSON Schema describing the produced output.
    pub output_schema: serde_json::Value,
}

/// Central registry of agents and their capabilities.
///
/// # Unbounded: not for live traffic
///
/// An offline primitive with no cap and no eviction:
/// [`AgentRegistry::register`] grows without limit and accepts any agent
/// id and capability an embedder hands it. The bounded equivalent, which
/// compiles one immutable generation from configuration and keys every
/// entry by tenant and origin, is [`crate::toolkit::AiToolkitRuntime`].
pub struct AgentRegistry {
    agents: Mutex<HashMap<String, Vec<AgentCapability>>>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
        }
    }

    /// Register or replace the capability list for `agent_id`.
    pub fn register(&self, agent_id: &str, capabilities: Vec<AgentCapability>) {
        let mut agents = self.agents.lock();
        agents.insert(agent_id.to_string(), capabilities);
    }

    /// Return the capabilities advertised by `agent_id`, or `None` if unknown.
    pub fn discover(&self, agent_id: &str) -> Option<Vec<String>> {
        let agents = self.agents.lock();
        agents
            .get(agent_id)
            .map(|caps| caps.iter().map(|c| c.name.clone()).collect())
    }

    /// Return the IDs of all agents that advertise a capability named
    /// `capability_name`.
    pub fn find_by_capability(&self, capability_name: &str) -> Vec<String> {
        let agents = self.agents.lock();
        agents
            .iter()
            .filter(|(_, caps)| caps.iter().any(|c| c.name == capability_name))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return the IDs of all registered agents.
    pub fn list_agents(&self) -> Vec<String> {
        let agents = self.agents.lock();
        let mut ids: Vec<String> = agents.keys().cloned().collect();
        ids.sort();
        ids
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_cap(name: &str) -> AgentCapability {
        AgentCapability {
            name: name.to_string(),
            description: format!("Does {}", name),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn register_and_discover() {
        let registry = AgentRegistry::new();
        registry.register("agent-a", vec![make_cap("search"), make_cap("summarize")]);
        let caps = registry.discover("agent-a").unwrap();
        assert!(caps.contains(&"search".to_string()));
        assert!(caps.contains(&"summarize".to_string()));
    }

    #[test]
    fn discover_unknown_agent_returns_none() {
        let registry = AgentRegistry::new();
        assert!(registry.discover("ghost").is_none());
    }

    #[test]
    fn find_by_capability_returns_matching_agents() {
        let registry = AgentRegistry::new();
        registry.register("agent-1", vec![make_cap("translate")]);
        registry.register("agent-2", vec![make_cap("search"), make_cap("translate")]);
        registry.register("agent-3", vec![make_cap("search")]);

        let mut agents = registry.find_by_capability("translate");
        agents.sort();
        assert_eq!(agents, vec!["agent-1", "agent-2"]);
    }

    #[test]
    fn find_by_capability_no_match_returns_empty() {
        let registry = AgentRegistry::new();
        registry.register("agent-a", vec![make_cap("search")]);
        let agents = registry.find_by_capability("nonexistent");
        assert!(agents.is_empty());
    }

    #[test]
    fn list_agents_returns_all_ids() {
        let registry = AgentRegistry::new();
        registry.register("alpha", vec![make_cap("x")]);
        registry.register("beta", vec![make_cap("y")]);
        let mut agents = registry.list_agents();
        agents.sort();
        assert_eq!(agents, vec!["alpha", "beta"]);
    }

    #[test]
    fn register_overwrites_previous_capabilities() {
        let registry = AgentRegistry::new();
        registry.register("agent-a", vec![make_cap("old_cap")]);
        registry.register("agent-a", vec![make_cap("new_cap")]);
        let caps = registry.discover("agent-a").unwrap();
        assert!(!caps.contains(&"old_cap".to_string()));
        assert!(caps.contains(&"new_cap".to_string()));
    }
}
