//! Sandbox configuration for Lua execution.
//!
//! Controls resource limits and capability restrictions for the Lua VM
//! to prevent runaway scripts and restrict access to dangerous APIs.

// --- Sandbox Configuration ---

/// Sandbox configuration for Lua execution.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum execution time in milliseconds.
    pub max_execution_ms: u64,
    /// Maximum memory usage in bytes.
    pub max_memory: usize,
    /// Whether to allow string.find/gmatch (potential ReDoS).
    pub allow_patterns: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_execution_ms: 1000,
            max_memory: 10 * 1024 * 1024, // 10MB
            allow_patterns: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_execution_ms, 1000);
        assert_eq!(config.max_memory, 10 * 1024 * 1024);
        assert!(config.allow_patterns);
    }

    #[test]
    fn test_custom_config() {
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
