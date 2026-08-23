//! In-process multi-agent workflow orchestration (WOR-2672 port of
//! `sbproxy-enterprise-ai::a2a`).
//!
//! Capability discovery ([`crate::agent_orchestration::discovery`]), an FSM-based workflow
//! orchestrator ([`crate::agent_orchestration::fsm`]), and a shared-secret agent authentication
//! scheme ([`crate::agent_orchestration::auth`]) for
//! an embedder building a multi-agent pipeline on top of the AI gateway: a
//! router that calls agent A, feeds its output to agent B, and branches on
//! the result, with each hop authenticated and each capability discoverable
//! before it is invoked.
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
//! This module is a different concern entirely: an in-process toolkit an
//! embedder uses to *build* a multi-agent workflow (which agent to call
//! next, what it can do, and a lightweight token scheme for authenticating
//! calls between cooperating agents an operator controls). It does not
//! touch the request path, the `a2a` action, or the AgentCard surface. It
//! was ported into `agent_orchestration` rather than `a2a` specifically to
//! avoid the name collision with that shipped, more mature feature; every
//! type name below is otherwise unchanged from the enterprise source.
//!
//! Self-contained: no dependency on the classifier sidecar or any other
//! WOR-2661 port.
//!
//! See `docs/agent-orchestration.md` and
//! `examples/agent-orchestration-workflow/` for a runnable multi-agent
//! workflow built on these three pieces together.

pub mod auth;
pub mod discovery;
pub mod fsm;

pub use auth::{generate_agent_token, verify_agent_token, A2AAuthConfig};
pub use discovery::{AgentCapability, AgentRegistry};
pub use fsm::{
    FsmExecution, FsmExecutionError, FsmState, FsmTransition, FsmValidationError, FsmWorkflow,
};
