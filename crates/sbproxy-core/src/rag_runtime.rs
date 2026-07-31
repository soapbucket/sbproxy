//! Route-scoped RAG runtime registry (WOR-2098).
//!
//! [`RagRuntimeRegistry`] parallels [`CompiledPipeline`]'s per-origin
//! vectors the same way
//! [`CompressionRuntimeRegistry`](crate::compression_runtime::CompressionRuntimeRegistry)
//! does: one slot per compiled origin action plus one slot per compiled
//! forward-rule action, populated only when that exact action is an
//! `ai_proxy` with a configured `rag:` block. The registry is built once
//! per pipeline generation and is immutable afterwards, so a hot reload
//! swaps whole registries and never mutates one that in-flight requests
//! have pinned.
//!
//! Selection is strict: a forward rule without its own `rag:` block has no
//! runtime, and [`RagRuntimeRegistry::get`] never falls back to the origin
//! runtime for it. Retrieval scope is part of the route contract, so an
//! operator who augments `/support/` traffic must not silently augment a
//! carved-out `/health` rule as well.
//!
//! [`CompiledPipeline`]: crate::pipeline::CompiledPipeline

use std::sync::Arc;

use anyhow::Context;
use sbproxy_rag::{RagBuildMode, RagRuntime};

use crate::pipeline::CompiledForwardRule;

/// Immutable RAG runtimes keyed by origin index and optional forward-rule
/// index.
///
/// Built by [`Self::build`] after both the main actions and the forward
/// rules of a pipeline are compiled. `Default` yields an empty registry
/// (every lookup misses), which is what test pipelines constructed via
/// `CompiledPipeline::default()` carry.
#[derive(Default)]
pub struct RagRuntimeRegistry {
    /// Runtime for each origin's main action, parallel to
    /// `CompiledPipeline::actions`. `None` for non-AI actions and for AI
    /// actions without a `rag:` block.
    by_origin: Vec<Option<Arc<RagRuntime>>>,
    /// Runtimes for each origin's forward-rule actions, parallel to
    /// `CompiledPipeline::forward_rules` in both dimensions.
    by_forward_rule: Vec<Vec<Option<Arc<RagRuntime>>>>,
}

impl RagRuntimeRegistry {
    /// Build one immutable runtime per action that configures `rag:`.
    ///
    /// `mode` is [`RagBuildMode::Runtime`] for live pipeline construction
    /// and [`RagBuildMode::Validation`] for validate/plan construction,
    /// which checks every configured provider without dialing embedding,
    /// vector-store, or Redis endpoints.
    ///
    /// Errors name the origin index and, where applicable, the forward-rule
    /// index. `RagBuildError` display text is credential-free by contract,
    /// so the wrapped message never carries a secret value.
    pub fn build(
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
        mode: RagBuildMode,
    ) -> anyhow::Result<Self> {
        let mut by_origin = Vec::with_capacity(actions.len());
        for (origin_idx, action) in actions.iter().enumerate() {
            by_origin.push(
                build_for_action(action, mode)
                    .with_context(|| format!("origin {origin_idx}: ai_proxy rag"))?,
            );
        }
        let mut by_forward_rule = Vec::with_capacity(forward_rules.len());
        for (origin_idx, rules) in forward_rules.iter().enumerate() {
            let mut per_rule = Vec::with_capacity(rules.len());
            for (rule_idx, rule) in rules.iter().enumerate() {
                per_rule.push(build_for_action(&rule.action, mode).with_context(|| {
                    format!("origin {origin_idx}: forward rule {rule_idx}: ai_proxy rag")
                })?);
            }
            by_forward_rule.push(per_rule);
        }
        Ok(Self {
            by_origin,
            by_forward_rule,
        })
    }

    /// The runtime for the action routing selected, if that exact action
    /// configured `rag:`.
    ///
    /// `forward_rule: None` addresses the origin's main action;
    /// `Some(index)` addresses one of its forward rules. A forward rule
    /// without a `rag:` block returns `None` and never inherits the origin
    /// runtime.
    pub fn get(&self, origin: usize, forward_rule: Option<usize>) -> Option<&Arc<RagRuntime>> {
        match forward_rule {
            Some(rule) => self.by_forward_rule.get(origin)?.get(rule)?.as_ref(),
            None => self.by_origin.get(origin)?.as_ref(),
        }
    }
}

/// Build the runtime for one compiled action slot.
///
/// Non-AI actions and AI actions without `rag:` occupy a `None` slot so
/// the registry stays index-parallel with the pipeline's action vectors.
fn build_for_action(
    action: &sbproxy_modules::Action,
    mode: RagBuildMode,
) -> anyhow::Result<Option<Arc<RagRuntime>>> {
    let sbproxy_modules::Action::AiProxy(action) = action else {
        return Ok(None);
    };
    let Some(rag) = action.config.rag.as_ref() else {
        return Ok(None);
    };
    let runtime = RagRuntime::build(rag, mode)?;
    Ok(Some(Arc::new(runtime)))
}
