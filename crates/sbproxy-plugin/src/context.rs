//! Plugin context passed during the provisioning lifecycle phase.

use compact_str::CompactString;

/// Context passed to plugins during provisioning.
///
/// Contains the identifying information for the origin that this
/// plugin instance is associated with.
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Unique identifier for the origin this plugin serves.
    pub origin_id: CompactString,
    /// Workspace that owns this origin.
    pub workspace_id: CompactString,
    /// Hostname that routes to this origin.
    pub hostname: CompactString,
    /// Configuration version (for cache-busting, rollback, etc.).
    pub version: CompactString,
}
