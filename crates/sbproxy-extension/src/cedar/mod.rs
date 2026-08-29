//! Cedar policy engine: compiler, evaluator, request bridge, and schema.
//!
//! [Cedar](https://www.cedarpolicy.com/) is a typed, expression-based
//! authorization policy language. This module wraps the
//! [`cedar_policy`] crate with the pieces sbproxy needs to use Cedar
//! as an MCP tool-call policy engine:
//!
//! - [`compiler`]: pre-compiles Cedar source text into a
//!   `cedar_policy::PolicySet` once, at config-load time, so the
//!   request hot path evaluates against an in-memory policy set
//!   rather than re-parsing on every dispatch. Compilation is the
//!   "validate" half of a validate-before-apply contract: a parse
//!   failure or a schema validation failure should reject the new
//!   policy set outright rather than serve it partially compiled.
//! - [`evaluator`]: holds the compiled `PolicySet` plus an optional
//!   `cedar_policy::Schema` and exposes a single `evaluate(request)`
//!   entry point that wraps `cedar_policy::Authorizer::is_authorized`
//!   and maps the verdict onto [`sbproxy_plugin::PolicyDecision`].
//! - [`request_bridge`]: deterministic, byte-stable conversion from
//!   this module's own [`request_bridge::CedarRequest`] into a
//!   `cedar_policy::Request` plus the matching `cedar_policy::Entities`.
//!   Determinism matters here: an audit trail that replays the same
//!   logical request must produce the same Cedar input every time, and
//!   content-hash-keyed caches need two structurally-equal inputs to
//!   hash identically.
//! - [`cel_bridge`]: a thin `CelPredicate` type reserved for a CEL
//!   expression riding as an inline condition inside a Cedar policy.
//!   CEL is a dependent surface of the Cedar primary path here, not a
//!   peer authoring surface, so this ships as a stub that always
//!   returns `Ok(true)`; wiring it to sbproxy's own [`crate::cel`]
//!   engine (which already wraps the `cel` crate elsewhere in this
//!   crate) is follow-up work.
//! - [`schema`]: the default MCP entity/action schema Cedar policies
//!   are authored against, plus workspace-override merging and the
//!   schema-evolution validate-before-apply check.
//! - [`mod@replay`]: offline evaluation of recorded MCP tool-call samples
//!   against compiled Cedar source. `sbproxy cedar replay` is the
//!   operator surface; this module is the engine so the CLI and the
//!   tests share one verdict mapping.
//! - [`storage`]: storage for Cedar policies minted or edited at
//!   runtime, outside a config reload (WOR-2586). Statically authored
//!   `.cedar` policies compile straight into memory via [`compiler`]
//!   at config-load time and never touch this module; it exists only
//!   for the dynamic case, and its default [`storage::EmbeddedPolicyStore`]
//!   backend is redb, not Postgres, so nothing here requires an
//!   external database to run.
//!
//! This module is wired into the MCP tool-call hot path as a built-in
//! `sbproxy_plugin::mcp::McpPolicyHook` (WOR-2587): see
//! `crate::mcp::cedar_hook::CedarMcpHook`, which wraps [`CedarEvaluator`]
//! and is installed into that registry at the pipeline-publication
//! boundary (`sbproxy_core::reload::load_pipeline`) once a
//! `cedar_policies:` config block compiles successfully. What remains
//! separate, later work is [`storage`]'s dynamic-policy path (see that
//! module's own doc comment) and the CEL-inline-condition bridge
//! ([`cel_bridge`]).

pub mod cel_bridge;
pub mod compiler;
pub mod evaluator;
pub mod replay;
pub mod request_bridge;
pub mod schema;
pub mod storage;

pub use cel_bridge::{CelBridgeError, CelPredicate};
pub use compiler::{compile_all, CompiledPolicySet, CompilerError};
pub use evaluator::{CedarEvaluator, EvaluatorError};
pub use replay::{
    format_text, parse_jsonl, replay, ReplayReport, ReplayRow, ReplaySample, MCP_CALL_TOOL_ACTION,
};
pub use request_bridge::{stub_request_for_unit_tests, CedarRequest, RequestBridgeError};
pub use storage::{EmbeddedPolicyStore, PolicyStore, StoredPolicy};
