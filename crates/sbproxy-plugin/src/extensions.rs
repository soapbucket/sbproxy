//! Public declarations and inventory records for extension bundles.
//!
//! Link-time declarations borrow static strings so plugin crates can submit
//! them through [`inventory`]. Runtime inventory records own their strings so
//! a pipeline generation can describe dynamically loaded bundles without
//! borrowing loader state.

use serde::{Deserialize, Serialize};

use crate::{PluginError, PluginResult};

/// Schema version emitted by [`ExtensionInventorySnapshot`].
pub const EXTENSION_INVENTORY_SCHEMA_VERSION: u16 = 1;

/// Runtime used to execute an extension bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRuntime {
    /// Native Rust code linked into the proxy binary.
    Rust,
    /// JavaScript or load-time-transpiled TypeScript.
    Javascript,
    /// Native bundle using the versioned envelope WebAssembly ABI.
    Wasm,
    /// HTTP filter using the Proxy-Wasm ABI.
    ProxyWasm,
}

/// Kind of hook exported by an extension bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHookKind {
    /// Request action hook.
    Action,
    /// Authentication provider hook.
    Auth,
    /// Request or response policy hook.
    Policy,
    /// Body transform hook.
    Transform,
    /// Request enrichment hook.
    Enricher,
    /// Process or pipeline startup hook.
    Startup,
    /// Identity resolution hook.
    Identity,
    /// Machine-learning classification hook.
    MlClassifier,
    /// Anomaly detection hook.
    AnomalyDetector,
    /// Model Context Protocol policy hook.
    Mcp,
    /// Proxy-Wasm HTTP filter.
    ProxyWasmFilter,
    /// AI tool-call event hook.
    AiToolCall,
    /// AI guardrail-input event hook.
    AiGuardrailInput,
    /// AI guardrail-output event hook.
    AiGuardrailOutput,
    /// AI streaming event hook.
    AiStreamEvent,
    /// AI stream-close event hook.
    AiClose,
}

/// How hooks sharing a match key participate in dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionDispatch {
    /// Exactly one registration may own the match key.
    Exclusive,
    /// Every registration runs in deterministic order.
    Chain,
}

/// Body access required by an extension hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionBodyMode {
    /// The hook does not inspect or change a body.
    None,
    /// The hook requires the complete buffered body.
    Buffered,
    /// The hook can process body chunks as they arrive.
    Streamed,
}

/// Execution limits and phase for an extension hook.
///
/// Link-time declarations use the default `&'static str` phase. Owned
/// inventory records use `ExtensionExecution<String>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionExecution<P = &'static str> {
    /// Pipeline phase in which the hook runs.
    pub phase: P,
    /// Body access mode required by the hook.
    pub body_mode: ExtensionBodyMode,
    /// Hook timeout in milliseconds, when independently bounded.
    pub timeout_ms: Option<u64>,
    /// Maximum buffered body size, when the hook buffers a body.
    pub max_buffer_bytes: Option<u64>,
}

impl ExtensionExecution<&'static str> {
    /// Convert a static declaration into an owned inventory value.
    pub fn to_owned(&self) -> ExtensionExecution<String> {
        ExtensionExecution {
            phase: self.phase.to_owned(),
            body_mode: self.body_mode,
            timeout_ms: self.timeout_ms,
            max_buffer_bytes: self.max_buffer_bytes,
        }
    }
}

/// One hook exported by a link-time extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExtensionHookDeclaration {
    /// Stable hook identifier, unique within the linked binary.
    pub id: &'static str,
    /// Dispatch interface implemented by the hook.
    pub kind: ExtensionHookKind,
    /// Whether the hook is exclusive or participates in a chain.
    pub dispatch: ExtensionDispatch,
    /// Stable lookup key used to attach or invoke the hook.
    pub match_key: &'static str,
    /// Hook phase and resource limits.
    pub execution: ExtensionExecution,
    /// Declared host capabilities required by the hook.
    pub capabilities: &'static [&'static str],
}

/// Link-time declaration for one extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExtensionBundleDeclaration {
    /// Stable bundle identifier.
    pub id: &'static str,
    /// Human-readable bundle name.
    pub name: &'static str,
    /// Bundle version.
    pub version: &'static str,
    /// Package or crate name, when it differs from the bundle identifier.
    pub package: Option<&'static str>,
    /// Runtime used by the bundle.
    pub runtime: ExtensionRuntime,
    /// Hooks exported by the bundle.
    pub hooks: &'static [ExtensionHookDeclaration],
}

inventory::collect!(ExtensionBundleDeclaration);

fn sort_and_validate_extension_declarations(
    mut declarations: Vec<&'static ExtensionBundleDeclaration>,
) -> PluginResult<Vec<&'static ExtensionBundleDeclaration>> {
    declarations.sort();
    if let Some(duplicate) = declarations
        .windows(2)
        .find(|pair| pair[0].id == pair[1].id)
    {
        return Err(PluginError::Config(format!(
            "duplicate extension bundle id: {}",
            duplicate[0].id
        )));
    }
    Ok(declarations)
}

/// Return link-time extension declarations in deterministic order.
///
/// ## Errors
///
/// Returns [`PluginError::Config`] when more than one linked declaration
/// uses the same stable bundle ID.
pub fn collect_linked_extension_declarations(
) -> PluginResult<Vec<&'static ExtensionBundleDeclaration>> {
    let declarations = inventory::iter::<ExtensionBundleDeclaration>
        .into_iter()
        .collect::<Vec<_>>();
    sort_and_validate_extension_declarations(declarations)
}

/// Where a bundle or hook registration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRegistrationSource {
    /// Registration linked into the proxy binary.
    LinkTime,
    /// Bundle loaded from a configured directory.
    Directory,
    /// Bundle loaded from a pinned Git source.
    Git,
}

/// Lifecycle state reported for a bundle or hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionState {
    /// Present in the binary or configured source.
    Installed,
    /// Loaded and available for attachment.
    Available,
    /// Attached to the running pipeline generation.
    Active,
    /// Failed to load, validate, or initialize.
    Failed,
    /// Hidden by a higher-precedence registration.
    Shadowed,
    /// Discovered by doctor without a running-generation evaluation.
    NotEvaluated,
    /// Loaded successfully but not attached by the configuration.
    Unconsumed,
}

/// Perspective represented by an extension inventory snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionScopeMode {
    /// Snapshot of the active pipeline generation.
    Running,
    /// Diagnostic snapshot produced by doctor.
    Doctor,
}

/// Metadata describing the perspective of an inventory snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventoryScope {
    /// Whether the snapshot describes a running generation or doctor result.
    pub mode: ExtensionScopeMode,
    /// Version of the proxy that produced the snapshot.
    pub proxy_version: String,
    /// Active or inspected configuration revision, when known.
    pub config_revision: Option<String>,
}

/// Aggregate counts for an extension inventory snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventorySummary {
    /// Number of bundles in the snapshot.
    pub bundles: u32,
    /// Number of hooks in the snapshot.
    pub hooks: u32,
    /// Number of active hooks.
    pub active: u32,
    /// Number of available hooks.
    pub available: u32,
    /// Number of failed bundles or hooks.
    pub failed: u32,
    /// Number of registration collisions.
    pub collisions: u32,
}

/// Load result attached to a bundle inventory record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionLoadRecord {
    /// Load or validation phase that produced the result.
    pub phase: String,
    /// Stable status label for the result.
    pub status: String,
    /// Sanitized bounded detail, when additional context is safe to expose.
    pub detail: Option<String>,
}

/// Owned inventory record for one extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionBundleRecord {
    /// Stable bundle identifier.
    pub id: String,
    /// Human-readable bundle name.
    pub name: String,
    /// Bundle version.
    pub version: String,
    /// Package or artifact name, when present.
    pub package: Option<String>,
    /// Bundle source.
    pub source: ExtensionRegistrationSource,
    /// Runtime used by the bundle.
    pub runtime: ExtensionRuntime,
    /// Current bundle state.
    pub state: ExtensionState,
    /// Stable IDs of hooks exported by this bundle.
    pub hook_ids: Vec<String>,
    /// Bundle load result.
    pub load: ExtensionLoadRecord,
}

/// Owned inventory record for one extension hook.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionHookRecord {
    /// Stable hook identifier.
    pub id: String,
    /// Stable identifier of the containing bundle.
    pub bundle_id: String,
    /// Dispatch interface implemented by the hook.
    pub kind: ExtensionHookKind,
    /// Registration source for the hook.
    pub registration: ExtensionRegistrationSource,
    /// Whether the hook is exclusive or chained.
    pub dispatch: ExtensionDispatch,
    /// Lookup key used to attach or invoke the hook.
    pub match_key: String,
    /// Position in the resolved chain, when attached.
    pub position: Option<u32>,
    /// Current hook state.
    pub state: ExtensionState,
    /// Sanitized bounded detail about the current state.
    pub detail: Option<String>,
    /// Runtime used by the hook.
    pub runtime: ExtensionRuntime,
    /// Owned execution phase and limits.
    pub execution: ExtensionExecution<String>,
    /// Declared host capabilities required by the hook.
    pub capabilities: Vec<String>,
}

/// One collision between registrations sharing a match key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionCollision {
    /// Lookup key claimed by multiple registrations.
    pub match_key: String,
    /// Stable IDs of the registrations that claimed the key.
    pub registrations: Vec<String>,
    /// Winning registration ID, when the collision was resolved.
    pub winner: Option<String>,
    /// Stable explanation of the resolution or rejection.
    pub resolution: String,
}

/// Versioned extension inventory shared by admin and doctor surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventorySnapshot {
    /// Inventory schema version.
    pub schema_version: u16,
    /// Perspective and proxy metadata for this snapshot.
    pub scope: ExtensionInventoryScope,
    /// Aggregate inventory counts.
    pub summary: ExtensionInventorySummary,
    /// Bundle records sorted by stable bundle ID.
    pub bundles: Vec<ExtensionBundleRecord>,
    /// Hook records sorted by stable hook ID.
    pub hooks: Vec<ExtensionHookRecord>,
    /// Collision records sorted by match key.
    pub collisions: Vec<ExtensionCollision>,
}

impl ExtensionInventorySnapshot {
    /// Sort every inventory vector deterministically and validate stable IDs.
    ///
    /// ## Errors
    ///
    /// Returns [`PluginError::Config`] when two bundle records share an ID or
    /// two hook records share an ID.
    pub fn sort_stably(&mut self) -> PluginResult<()> {
        for bundle in &mut self.bundles {
            bundle.hook_ids.sort();
        }
        for hook in &mut self.hooks {
            hook.capabilities.sort();
        }
        for collision in &mut self.collisions {
            collision.registrations.sort();
        }
        self.bundles.sort();
        self.hooks.sort();
        self.collisions.sort();

        if let Some(duplicate) = self
            .bundles
            .windows(2)
            .find(|pair| pair[0].id == pair[1].id)
        {
            return Err(PluginError::Config(format!(
                "duplicate extension bundle id: {}",
                duplicate[0].id
            )));
        }
        if let Some(duplicate) = self.hooks.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(PluginError::Config(format!(
                "duplicate extension hook id: {}",
                duplicate[0].id
            )));
        }
        Ok(())
    }
}

/// Runtime observation used to assemble bundle and hook inventory state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionObservation {
    /// Stable bundle identifier associated with the observation.
    pub bundle_id: String,
    /// Stable hook identifier, absent for bundle-level observations.
    pub hook_id: Option<String>,
    /// State observed for the bundle or hook.
    pub state: ExtensionState,
    /// Position in a resolved hook chain, when attached.
    pub position: Option<u32>,
    /// Lifecycle or execution phase that produced the observation.
    pub phase: String,
    /// Stable status label for the observation.
    pub status: String,
    /// Sanitized bounded detail, when available.
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    static DUPLICATE_BUNDLE_A: ExtensionBundleDeclaration = ExtensionBundleDeclaration {
        id: "duplicate-fixture-bundle",
        name: "Duplicate fixture A",
        version: "1.0.0",
        package: None,
        runtime: ExtensionRuntime::Rust,
        hooks: &[],
    };

    static DUPLICATE_BUNDLE_B: ExtensionBundleDeclaration = ExtensionBundleDeclaration {
        id: "duplicate-fixture-bundle",
        name: "Duplicate fixture B",
        version: "2.0.0",
        package: None,
        runtime: ExtensionRuntime::Javascript,
        hooks: &[],
    };

    fn bundle(id: &str, hook_ids: &[&str]) -> ExtensionBundleRecord {
        ExtensionBundleRecord {
            id: id.to_owned(),
            name: id.to_owned(),
            version: "1.0.0".to_owned(),
            package: None,
            source: ExtensionRegistrationSource::LinkTime,
            runtime: ExtensionRuntime::Rust,
            state: ExtensionState::Installed,
            hook_ids: hook_ids.iter().map(|value| (*value).to_owned()).collect(),
            load: ExtensionLoadRecord {
                phase: "link".to_owned(),
                status: "ok".to_owned(),
                detail: None,
            },
        }
    }

    fn hook(id: &str, capabilities: &[&str]) -> ExtensionHookRecord {
        ExtensionHookRecord {
            id: id.to_owned(),
            bundle_id: "bundle".to_owned(),
            kind: ExtensionHookKind::Policy,
            registration: ExtensionRegistrationSource::LinkTime,
            dispatch: ExtensionDispatch::Exclusive,
            match_key: id.to_owned(),
            position: None,
            state: ExtensionState::Installed,
            detail: None,
            runtime: ExtensionRuntime::Rust,
            execution: ExtensionExecution {
                phase: "request".to_owned(),
                body_mode: ExtensionBodyMode::None,
                timeout_ms: None,
                max_buffer_bytes: None,
            },
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    #[test]
    fn inventory_snapshot_sorts_stable_id_vectors() {
        let mut snapshot = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Running,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![bundle("z", &["z-hook", "a-hook"]), bundle("a", &[])],
            hooks: vec![hook("z-hook", &["write", "read"]), hook("a-hook", &[])],
            collisions: vec![
                ExtensionCollision {
                    match_key: "z-key".to_owned(),
                    registrations: vec!["z".to_owned(), "a".to_owned()],
                    winner: None,
                    resolution: "rejected".to_owned(),
                },
                ExtensionCollision {
                    match_key: "a-key".to_owned(),
                    registrations: vec!["z".to_owned()],
                    winner: None,
                    resolution: "z-resolution".to_owned(),
                },
                ExtensionCollision {
                    match_key: "a-key".to_owned(),
                    registrations: vec!["a".to_owned()],
                    winner: None,
                    resolution: "a-resolution".to_owned(),
                },
            ],
        };

        snapshot.sort_stably().unwrap();

        assert_eq!(
            snapshot
                .bundles
                .iter()
                .map(|bundle| bundle.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        assert_eq!(snapshot.bundles[1].hook_ids, ["a-hook", "z-hook"]);
        assert_eq!(
            snapshot
                .hooks
                .iter()
                .map(|hook| hook.id.as_str())
                .collect::<Vec<_>>(),
            ["a-hook", "z-hook"]
        );
        assert_eq!(snapshot.hooks[1].capabilities, ["read", "write"]);
        assert_eq!(
            snapshot
                .collisions
                .iter()
                .map(|collision| collision.match_key.as_str())
                .collect::<Vec<_>>(),
            ["a-key", "a-key", "z-key"]
        );
        assert_eq!(snapshot.collisions[0].registrations, ["a"]);
        assert_eq!(snapshot.collisions[1].registrations, ["z"]);
        assert_eq!(snapshot.collisions[2].registrations, ["a", "z"]);
    }

    #[test]
    fn declaration_collection_rejects_duplicate_bundle_ids() {
        let error = sort_and_validate_extension_declarations(vec![
            &DUPLICATE_BUNDLE_B,
            &DUPLICATE_BUNDLE_A,
        ])
        .unwrap_err();

        assert!(matches!(
            error,
            crate::PluginError::Config(message)
                if message == "duplicate extension bundle id: duplicate-fixture-bundle"
        ));
    }

    #[test]
    fn inventory_snapshot_rejects_duplicate_bundle_and_hook_ids() {
        let mut duplicate_bundles = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Doctor,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![bundle("duplicate", &[]), bundle("duplicate", &["hook"])],
            hooks: Vec::new(),
            collisions: Vec::new(),
        };
        let bundle_error = duplicate_bundles.sort_stably().unwrap_err();
        assert!(matches!(
            bundle_error,
            crate::PluginError::Config(message)
                if message == "duplicate extension bundle id: duplicate"
        ));

        let mut duplicate_hooks = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Doctor,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: Vec::new(),
            hooks: vec![hook("duplicate", &[]), hook("duplicate", &["write"])],
            collisions: Vec::new(),
        };
        let hook_error = duplicate_hooks.sort_stably().unwrap_err();
        assert!(matches!(
            hook_error,
            crate::PluginError::Config(message)
                if message == "duplicate extension hook id: duplicate"
        ));
    }
}
