//! Sandbox configuration for Lua execution.
//!
//! Controls resource limits and capability restrictions for the Lua VM
//! to prevent runaway scripts and restrict access to dangerous APIs.

use sbproxy_config::LuaSandboxConfig;

// --- Sandbox Configuration ---

/// Sandbox configuration for Lua execution.
///
/// This is the in-process representation consumed by [`super::LuaEngine`].
/// Operators configure it through `proxy.scripting.lua.sandbox:` in
/// `sb.yml`; see [`LuaSandboxConfig`] for the on-the-wire shape. The
/// engine prefers bytes for the memory limit so the multiplication
/// happens once at config-compile time rather than on every script
/// invocation.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum execution time per script invocation, in milliseconds.
    pub max_execution_ms: u64,
    /// Maximum allocator footprint of the Lua VM, in bytes.
    pub max_memory: usize,
    /// Whether to expose the Lua pattern API (`string.find` /
    /// `string.match` / `string.gmatch`). When `false`, calling any
    /// of these from a script raises a Lua error.
    pub allow_patterns: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        // Mirror `LuaSandboxConfig::default()` so the in-process
        // defaults track the documented YAML defaults exactly.
        Self::from(&LuaSandboxConfig::default())
    }
}

impl From<&LuaSandboxConfig> for SandboxConfig {
    fn from(cfg: &LuaSandboxConfig) -> Self {
        Self {
            max_execution_ms: cfg.max_execution_ms,
            max_memory: cfg.max_memory_bytes(),
            allow_patterns: cfg.allow_patterns,
        }
    }
}

impl From<LuaSandboxConfig> for SandboxConfig {
    fn from(cfg: LuaSandboxConfig) -> Self {
        SandboxConfig::from(&cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_documented_yaml_defaults() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_execution_ms, 100);
        assert_eq!(config.max_memory, 8 * 1024 * 1024);
        assert!(config.allow_patterns);
    }

    #[test]
    fn from_lua_sandbox_config_converts_mb_to_bytes() {
        let yaml = LuaSandboxConfig {
            max_execution_ms: 250,
            max_memory_mb: 32,
            allow_patterns: false,
        };
        let sandbox = SandboxConfig::from(&yaml);
        assert_eq!(sandbox.max_execution_ms, 250);
        assert_eq!(sandbox.max_memory, 32 * 1024 * 1024);
        assert!(!sandbox.allow_patterns);
    }

    #[test]
    fn custom_config_round_trips() {
        let config = SandboxConfig {
            max_execution_ms: 500,
            max_memory: 5 * 1024 * 1024,
            allow_patterns: false,
        };
        assert_eq!(config.max_execution_ms, 500);
        assert_eq!(config.max_memory, 5 * 1024 * 1024);
        assert!(!config.allow_patterns);
    }
}
