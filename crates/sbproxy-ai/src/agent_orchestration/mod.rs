//! In-process multi-agent workflow orchestration (WOR-2672 port of
//! `sbproxy-enterprise-ai::a2a`).
//!
//! Capability discovery ([`crate::agent_orchestration::discovery`]), an FSM-based workflow
//! orchestrator ([`crate::agent_orchestration::fsm`]), and a shared-secret agent authentication
//! scheme ([`crate::agent_orchestration::auth`]) for building a multi-agent
//! pipeline on top of the AI gateway: a router that calls agent A, feeds its
//! output to agent B, and branches on the result, with each hop authenticated
//! and each capability discoverable before it is invoked. Embedders can use
//! the primitives directly. The production proxy also compiles
//! `proxy.ai_toolkit.agents` and `proxy.ai_toolkit.workflows` into one pipeline
//! generation, requires governed `egress.agent_orchestration` for every agent
//! call, and exposes discovery, validation, and execution through the
//! authenticated `/admin/ai-toolkit` routes and `sbproxy ai workflow` CLI.
//!
//! # Not the same "A2A" as the proxy's `a2a` action
//!
//! SBproxy already ships a distinct, unrelated feature also named A2A: the
//! `a2a` action, `a2a` policy, and `a2a_agent_card_rewrite` transform in
//! `sbproxy-modules` (see `docs/a2a-gateway.md`), which proxy and govern
//! *inbound HTTP* Agent-to-Agent protocol traffic between a caller and an
//! upstream agent, authenticated by RFC 8693 `act` claim chains or trusted
//! reverse-proxy headers.
//!
//! This module is a different concern entirely: an in-process toolkit for
//! deciding which agent to call next, what it can do, and how calls between
//! cooperating agents authenticate. Live workflow execution enters through
//! the authenticated admin API or CLI and makes bounded governed outbound
//! calls. It does not participate in ordinary proxied request dispatch, the
//! `a2a` action, or the AgentCard surface. It was ported into
//! `agent_orchestration` rather than `a2a` specifically to avoid the name
//! collision with that shipped, more mature feature; every type name below is
//! otherwise unchanged from the enterprise source.
//!
//! Self-contained: no dependency on the classifier sidecar or any other
//! WOR-2661 port.
//!
//! See `docs/agent-orchestration.md` and `examples/ai-agent-orchestration/`
//! for the live config, admin, and CLI walkthrough. The lower-level
//! `crates/sbproxy-ai/examples/agent_orchestration_workflow.rs` example uses
//! these primitives directly.

pub mod auth;
pub mod discovery;
pub mod fsm;

pub use auth::{generate_agent_token, verify_agent_token};
pub use discovery::{AgentCapability, AgentRegistry};
pub use fsm::{
    FsmExecution, FsmExecutionError, FsmLimitDimension, FsmState, FsmTransition,
    FsmValidationError, FsmWorkflow,
};
