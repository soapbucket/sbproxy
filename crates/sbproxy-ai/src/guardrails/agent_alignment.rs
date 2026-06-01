//! WOR-801: agent-alignment-check guardrail.
//!
//! A 9th built-in guardrail aimed at the LlamaFirewall (arXiv:2505.03574)
//! "Agent Alignment Checks" use case: when the assistant emits a
//! `tool_calls` array, confirm that the tool the agent picked is
//! consistent with the stated objective. Today's implementation is
//! deterministic (rule-based) so the request-path cost is bounded; the
//! LLM-judge advisory variant is on the roadmap and slots into the
//! same `Guardrail::AgentAlignment` arm.
//!
//! # Checks
//!
//! Operators describe the allowed action surface via three lists +
//! one budget on `AgentAlignmentConfig`:
//!
//! * `allowed_tools` - when non-empty, every tool call must name one
//!   of these tools. Inspired by LlamaFirewall's "stated objective"
//!   binding: the operator declares which tools any agent on this
//!   surface is permitted to invoke.
//! * `denied_tools` - explicit blocklist. A tool call naming one of
//!   these names trips the guardrail even if the allowlist is empty.
//! * `forbidden_arg_substrings` - case-insensitive substring scan
//!   over the JSON-encoded tool arguments. Catches "exfiltrate this
//!   file path"-style goal-hijacking attempts that pass the allow
//!   list because the tool itself is benign (e.g. `web.fetch`) but
//!   the argument is not.
//! * `max_tool_calls_per_turn` - caps the number of tool calls a
//!   single assistant turn can emit. Defends against goal-divergent
//!   tool-spamming.
//!
//! Each violation produces a `GuardrailBlock` whose `reason` names
//! the failing rule + the offending tool name. The reason is safe to
//! log; the rejection envelope returned to the caller is generic.
//!
//! # Modes
//!
//! `AgentAlignmentMode::Block` returns the block from
//! [`AgentAlignmentGuardrail::check_body`], same as every other
//! guardrail; the dispatch loop short-circuits to a 400.
//! `AgentAlignmentMode::Flag` records the metric + log line but
//! returns `None` so the request proceeds; the operator can
//! dashboards on the metric while running the guardrail in dry-run.

use serde::{Deserialize, Serialize};

use super::GuardrailBlock;

/// Action taken on a violation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentAlignmentMode {
    /// Surface the violation as a `GuardrailBlock` so the dispatch
    /// loop short-circuits the request. Production setting once the
    /// operator has tuned the allow / deny / forbid lists.
    Block,
    /// Record the violation (log + metric) but return `None`. Lets
    /// the operator dashboard a candidate ruleset before flipping
    /// it to block. Default because the alignment ruleset is
    /// operator-specific; a wrong-on-day-one default-Block would
    /// 400 every legitimate tool-using agent.
    #[default]
    Flag,
}

/// Operator configuration for the agent-alignment guardrail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAlignmentConfig {
    /// When `false` the guardrail is a no-op even if compiled.
    /// Lets an operator wire the entry and keep it dark while
    /// iterating on the allow list.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Action taken when a tool call violates the configured rules.
    /// See [`AgentAlignmentMode`]; defaults to `Flag` so the
    /// guardrail does not block on first deployment.
    #[serde(default)]
    pub mode: AgentAlignmentMode,
    /// When non-empty, every tool call must name one of these tool
    /// names. Empty disables the allow check; the deny + forbid +
    /// budget rules still apply.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Tool names that always trip the guardrail, even when they
    /// appear in `allowed_tools`. Lets an operator carve a hole in
    /// a broad allowlist without restating it.
    #[serde(default)]
    pub denied_tools: Vec<String>,
    /// Case-insensitive substrings scanned over the JSON-encoded
    /// tool arguments. Empty disables the substring check.
    #[serde(default)]
    pub forbidden_arg_substrings: Vec<String>,
    /// Cap on the number of `tool_calls` a single assistant turn can
    /// emit. 0 disables the budget. Defends against tool-spamming
    /// goal-divergent agents.
    #[serde(default)]
    pub max_tool_calls_per_turn: usize,
}

fn default_enabled() -> bool {
    true
}

impl Default for AgentAlignmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: AgentAlignmentMode::default(),
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
            forbidden_arg_substrings: Vec::new(),
            max_tool_calls_per_turn: 0,
        }
    }
}

/// Compiled agent-alignment guardrail. Built from
/// [`AgentAlignmentConfig`] at config-load time so the
/// per-request check path is allocation-free except for the
/// inevitable JSON arg-encoding scratch buffer.
#[derive(Debug, Clone)]
pub struct AgentAlignmentGuardrail {
    cfg: AgentAlignmentConfig,
    /// Lower-cased allow list for case-insensitive matching.
    allowed_tools_lc: Vec<String>,
    /// Lower-cased deny list.
    denied_tools_lc: Vec<String>,
    /// Lower-cased forbidden-arg substrings. Compared against the
    /// lower-cased JSON encoding of the tool's `arguments` /
    /// `input` field.
    forbidden_arg_substrings_lc: Vec<String>,
}

impl AgentAlignmentGuardrail {
    /// Compile a guardrail from operator config.
    pub fn new(cfg: AgentAlignmentConfig) -> Self {
        let allowed_tools_lc = cfg
            .allowed_tools
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let denied_tools_lc = cfg
            .denied_tools
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let forbidden_arg_substrings_lc = cfg
            .forbidden_arg_substrings
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Self {
            cfg,
            allowed_tools_lc,
            denied_tools_lc,
            forbidden_arg_substrings_lc,
        }
    }

    /// Whether the guardrail is configured to block on violation.
    pub fn is_block_mode(&self) -> bool {
        matches!(self.cfg.mode, AgentAlignmentMode::Block)
    }

    /// Whether the guardrail is enabled at all.
    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Run the alignment check against the raw request body
    /// (provider-shaped, e.g. OpenAI chat completions). Returns
    /// `Some(GuardrailBlock)` when (a) the rules are violated and
    /// (b) the mode is `Block`. In `Flag` mode the helper returns
    /// `None` but [`Self::find_violations`] still reports the
    /// per-tool reasons so the caller can record metrics.
    pub fn check_body(&self, body: &serde_json::Value) -> Option<GuardrailBlock> {
        if !self.cfg.enabled {
            return None;
        }
        let violations = self.find_violations(body);
        if violations.is_empty() {
            return None;
        }
        if !self.is_block_mode() {
            return None;
        }
        // Block: surface the first violation. The full list lives
        // on the access log + metric labels via `find_violations`.
        Some(GuardrailBlock {
            name: "agent_alignment".to_string(),
            reason: violations[0].clone(),
        })
    }

    /// Enumerate every alignment violation across the body. Each
    /// entry is a single-sentence reason suitable for the access
    /// log. Returned regardless of `mode` so the
    /// `Flag` path can still emit metrics + traces; the
    /// `Block` path only consumes the first entry. Returns an empty
    /// vec when the guardrail is `enabled: false` so a dark-launched
    /// entry never produces metrics or log noise.
    pub fn find_violations(&self, body: &serde_json::Value) -> Vec<String> {
        let mut violations = Vec::new();

        if !self.cfg.enabled {
            return violations;
        }

        let Some(messages) = body.get("messages").and_then(|v| v.as_array()) else {
            return violations;
        };

        for msg in messages {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role != "assistant" {
                continue;
            }
            let Some(tool_calls) = msg.get("tool_calls").and_then(|v| v.as_array()) else {
                continue;
            };
            if self.cfg.max_tool_calls_per_turn > 0
                && tool_calls.len() > self.cfg.max_tool_calls_per_turn
            {
                violations.push(format!(
                    "max_tool_calls_per_turn exceeded: {} > {}",
                    tool_calls.len(),
                    self.cfg.max_tool_calls_per_turn
                ));
            }
            for tc in tool_calls {
                let name = extract_tool_name(tc).unwrap_or_default();
                let name_lc = name.to_ascii_lowercase();

                if !self.denied_tools_lc.is_empty() && self.denied_tools_lc.contains(&name_lc) {
                    violations.push(format!("tool {:?} is in denied_tools", name));
                    continue;
                }

                if !self.allowed_tools_lc.is_empty() && !self.allowed_tools_lc.contains(&name_lc) {
                    violations.push(format!("tool {:?} is not in allowed_tools", name));
                    continue;
                }

                if !self.forbidden_arg_substrings_lc.is_empty() {
                    let args_lc = extract_tool_args_json(tc).to_ascii_lowercase();
                    for needle in &self.forbidden_arg_substrings_lc {
                        if args_lc.contains(needle) {
                            violations.push(format!(
                                "tool {:?} arguments contain forbidden substring {:?}",
                                name, needle
                            ));
                        }
                    }
                }
            }
        }

        violations
    }
}

/// Extract the tool name from a tool-call JSON shape. OpenAI carries
/// it at `function.name`; Anthropic uses `name` at the top level; the
/// MCP shape uses `tool` or `name`. Supporting all three keeps the
/// guardrail provider-agnostic.
fn extract_tool_name(tc: &serde_json::Value) -> Option<String> {
    if let Some(name) = tc
        .get("function")
        .and_then(|f| f.get("name"))
        .and_then(|n| n.as_str())
    {
        return Some(name.to_string());
    }
    if let Some(name) = tc.get("name").and_then(|v| v.as_str()) {
        return Some(name.to_string());
    }
    if let Some(name) = tc.get("tool").and_then(|v| v.as_str()) {
        return Some(name.to_string());
    }
    None
}

/// Extract the argument blob for substring scanning. OpenAI carries
/// it at `function.arguments` (JSON-encoded string); Anthropic uses
/// `input` (an object); the MCP shape uses `arguments`. The helper
/// returns the lower-cased JSON encoding so the caller can run one
/// substring scan per call rather than re-encoding for each rule.
fn extract_tool_args_json(tc: &serde_json::Value) -> String {
    if let Some(args) = tc.get("function").and_then(|f| f.get("arguments")) {
        if let Some(s) = args.as_str() {
            return s.to_string();
        }
        return args.to_string();
    }
    if let Some(args) = tc.get("input") {
        return args.to_string();
    }
    if let Some(args) = tc.get("arguments") {
        return args.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_with_tool_calls(calls: serde_json::Value) -> serde_json::Value {
        json!({
            "messages": [
                {"role": "system", "content": "You are a helpful agent."},
                {"role": "user", "content": "Do the thing."},
                {"role": "assistant", "content": null, "tool_calls": calls}
            ]
        })
    }

    #[test]
    fn no_tool_calls_never_flags() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            allowed_tools: vec!["search".into()],
            ..Default::default()
        });
        let body = json!({
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });
        assert!(g.check_body(&body).is_none());
        assert!(g.find_violations(&body).is_empty());
    }

    #[test]
    fn allowed_tool_passes() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            allowed_tools: vec!["search".into(), "fetch".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "search", "arguments": "{}"}}
        ]));
        assert!(g.check_body(&body).is_none());
    }

    #[test]
    fn disallowed_tool_blocks() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            allowed_tools: vec!["search".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "delete_account", "arguments": "{}"}}
        ]));
        let block = g.check_body(&body).expect("expected block");
        assert_eq!(block.name, "agent_alignment");
        assert!(block.reason.contains("delete_account"));
    }

    #[test]
    fn denied_tool_blocks_even_when_allowed() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            allowed_tools: vec!["search".into(), "delete_account".into()],
            denied_tools: vec!["delete_account".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "delete_account", "arguments": "{}"}}
        ]));
        let block = g.check_body(&body).expect("expected block");
        assert!(block.reason.contains("denied_tools"));
    }

    #[test]
    fn forbidden_arg_substring_blocks() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            forbidden_arg_substrings: vec!["/etc/passwd".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "fs.read", "arguments": "{\"path\": \"/etc/passwd\"}"}}
        ]));
        let block = g.check_body(&body).expect("expected block");
        assert!(block.reason.contains("/etc/passwd"));
    }

    #[test]
    fn budget_violation_blocks() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            max_tool_calls_per_turn: 1,
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "a", "arguments": "{}"}},
            {"id": "t2", "function": {"name": "b", "arguments": "{}"}}
        ]));
        let block = g.check_body(&body).expect("expected block");
        assert!(block.reason.contains("max_tool_calls_per_turn"));
    }

    #[test]
    fn flag_mode_returns_none_but_reports_violations() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Flag,
            allowed_tools: vec!["search".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "delete_account", "arguments": "{}"}}
        ]));
        // Flag mode never produces a block...
        assert!(g.check_body(&body).is_none());
        // ...but still reports the violation list so the dispatcher
        // can record the metric / access-log entry.
        let violations = g.find_violations(&body);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("delete_account"));
    }

    #[test]
    fn anthropic_shape_tool_call_is_recognised() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            mode: AgentAlignmentMode::Block,
            allowed_tools: vec!["search".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "name": "search", "input": {"q": "cats"}}
        ]));
        assert!(g.check_body(&body).is_none());
        let block_body = body_with_tool_calls(json!([
            {"id": "t1", "name": "delete_account", "input": {}}
        ]));
        assert!(g.check_body(&block_body).is_some());
    }

    #[test]
    fn disabled_guardrail_is_a_noop() {
        let g = AgentAlignmentGuardrail::new(AgentAlignmentConfig {
            enabled: false,
            mode: AgentAlignmentMode::Block,
            denied_tools: vec!["anything".into()],
            ..Default::default()
        });
        let body = body_with_tool_calls(json!([
            {"id": "t1", "function": {"name": "anything", "arguments": "{}"}}
        ]));
        assert!(g.check_body(&body).is_none());
        assert!(g.find_violations(&body).is_empty());
    }
}
