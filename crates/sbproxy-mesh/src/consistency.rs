//! CRDT consistency mode configuration.
//!
//! Controls whether the proxy uses AP (eventually-consistent CRDT) or CP
//! (strongly-consistent Redis-backed) semantics for shared state. Eventual is
//! the default because it requires no external dependencies and tolerates
//! network partitions gracefully.

/// Consistency mode for shared proxy state.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConsistencyMode {
    /// CRDT-based, AP - tolerates partitions, no external dependency.
    #[default]
    Eventual,
    /// Redis-based, CP - linearizable writes, requires Redis.
    Strong,
}

/// Parse a consistency mode from a string value.
///
/// Accepts `"strong"` or `"cp"` (case-insensitive) for strong mode. All other
/// values, including `"eventual"`, `"ap"`, and empty strings, produce
/// `ConsistencyMode::Eventual`.
pub fn parse_consistency_mode(s: &str) -> ConsistencyMode {
    match s.to_lowercase().as_str() {
        "strong" | "cp" => ConsistencyMode::Strong,
        _ => ConsistencyMode::Eventual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strong_mode() {
        assert_eq!(parse_consistency_mode("strong"), ConsistencyMode::Strong);
        assert_eq!(parse_consistency_mode("STRONG"), ConsistencyMode::Strong);
        assert_eq!(parse_consistency_mode("Strong"), ConsistencyMode::Strong);
    }

    #[test]
    fn parse_cp_alias() {
        assert_eq!(parse_consistency_mode("cp"), ConsistencyMode::Strong);
        assert_eq!(parse_consistency_mode("CP"), ConsistencyMode::Strong);
        assert_eq!(parse_consistency_mode("Cp"), ConsistencyMode::Strong);
    }

    #[test]
    fn parse_eventual_mode() {
        assert_eq!(
            parse_consistency_mode("eventual"),
            ConsistencyMode::Eventual
        );
        assert_eq!(
            parse_consistency_mode("EVENTUAL"),
            ConsistencyMode::Eventual
        );
    }

    #[test]
    fn parse_ap_alias() {
        assert_eq!(parse_consistency_mode("ap"), ConsistencyMode::Eventual);
        assert_eq!(parse_consistency_mode("AP"), ConsistencyMode::Eventual);
    }

    #[test]
    fn default_is_eventual() {
        assert_eq!(parse_consistency_mode(""), ConsistencyMode::Eventual);
        assert_eq!(parse_consistency_mode("unknown"), ConsistencyMode::Eventual);
        assert_eq!(parse_consistency_mode("redis"), ConsistencyMode::Eventual);
    }

    #[test]
    fn default_trait_is_eventual() {
        assert_eq!(ConsistencyMode::default(), ConsistencyMode::Eventual);
    }

    #[test]
    fn modes_are_not_equal() {
        assert_ne!(ConsistencyMode::Eventual, ConsistencyMode::Strong);
    }

    #[test]
    fn modes_clone_correctly() {
        let mode = ConsistencyMode::Strong;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }
}
