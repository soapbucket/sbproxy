//! Intermediate parsed origin representation.
//!
//! `RawOrigin` pairs a hostname with its deserialized config, bridging
//! the gap between YAML parsing and compilation into `CompiledOrigin`.

use compact_str::CompactString;

use crate::types::RawOriginConfig;

/// Parsed but not yet compiled origin. Created from RawOriginConfig + hostname.
#[derive(Debug)]
pub struct RawOrigin {
    /// Hostname this origin serves (the routing key).
    pub hostname: CompactString,
    /// Deserialized YAML config for this origin, prior to compilation.
    pub config: RawOriginConfig,
}
