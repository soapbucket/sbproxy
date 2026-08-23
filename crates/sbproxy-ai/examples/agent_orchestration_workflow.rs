//! Runnable demonstration of `sbproxy_ai::agent_orchestration` (WOR-2672):
//! capability discovery, an FSM workflow, and shared-secret agent auth
//! wired together into one triage-then-dispatch pipeline.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sbproxy-ai --example agent_orchestration_workflow
//! ```

use sbproxy_ai::agent_orchestration::{
    generate_agent_token, verify_agent_token, A2AAuthConfig, AgentCapability, AgentRegistry,
    FsmExecution, FsmState, FsmWorkflow,
};
use serde_json::json;
use std::collections::HashMap;

fn main() {
    // --- 1. Capability discovery: which agents can do what ---
    let registry = AgentRegistry::new();
    registry.register(
        "coding-agent",
        vec![AgentCapability {
            name: "write_code".to_string(),
            description: "Generate or fix source code".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
        }],
    );
    registry.register(
        "summarizer-agent",
        vec![AgentCapability {
            name: "summarize".to_string(),
            description: "Condense a long document".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
        }],
    );

    println!(
        "Agents that can write code: {:?}",
        registry.find_by_capability("write_code")
    );
    println!(
        "Agents that can summarize: {:?}",
        registry.find_by_capability("summarize")
    );
    println!("All registered agents: {:?}", registry.list_agents());

    // --- 2. Authenticate a call to the agent the triage step picks ---
    let auth = A2AAuthConfig {
        shared_secret: "operator-managed-secret".to_string(),
    };
    let target_agent = "coding-agent";
    let token = generate_agent_token(target_agent, &auth.shared_secret);
    assert!(verify_agent_token(
        target_agent,
        &token,
        &auth.shared_secret
    ));
    println!("\nIssued a token for {target_agent}: {token}");

    // --- 3. Drive a triage -> dispatch workflow with the FSM orchestrator ---
    let states = vec![
        FsmState {
            name: "triage".to_string(),
            action: "triage-agent".to_string(),
            transitions: [
                ("needs_code".to_string(), "code".to_string()),
                ("needs_summary".to_string(), "summarize".to_string()),
            ]
            .into(),
        },
        FsmState {
            name: "code".to_string(),
            action: "coding-agent".to_string(),
            transitions: HashMap::new(),
        },
        FsmState {
            name: "summarize".to_string(),
            action: "summarizer-agent".to_string(),
            transitions: HashMap::new(),
        },
    ];

    let workflow = FsmWorkflow::new("support-triage", "triage", states, 16)
        .expect("example workflow is valid");
    let mut exec = FsmExecution::new(workflow);
    println!("\nWorkflow starts at: {}", exec.current_state());

    let next = exec.transition("needs_code");
    println!(
        "After 'needs_code': {next:?} (completed: {})",
        exec.is_completed()
    );

    // The "code" state has no transitions, so any result terminates it.
    let terminal = exec.transition("done");
    println!(
        "After 'done': {terminal:?} (completed: {})",
        exec.is_completed()
    );
    println!("History: {:?}", exec.history());
}
