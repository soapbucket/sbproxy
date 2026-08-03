//! Internal wrappers for dynamically dispatched action and policy hooks.
//!
//! Linked plugins use the same wrappers with no dynamic metadata. Dynamic
//! bundle compilation retains the manifest execution contract so the HTTP
//! pipeline can plan request-body access without widening the public plugin
//! traits.

use sbproxy_config::{BundleBodyMode, FailureMode};
use sbproxy_plugin::{ActionHandler, PolicyEnforcer};

/// Manifest-derived execution metadata for one dynamic bundle hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicHookMetadata {
    bundle_id: String,
    hook_type: String,
    body_mode: BundleBodyMode,
    max_buffer_bytes: usize,
    failure_posture: FailureMode,
}

impl DynamicHookMetadata {
    /// Construct validated metadata retained by dynamic bundle compilation.
    #[must_use]
    pub fn new(
        bundle_id: impl Into<String>,
        hook_type: impl Into<String>,
        body_mode: BundleBodyMode,
        max_buffer_bytes: usize,
        failure_posture: FailureMode,
    ) -> Self {
        Self {
            bundle_id: bundle_id.into(),
            hook_type: hook_type.into(),
            body_mode,
            max_buffer_bytes,
            failure_posture,
        }
    }

    /// Return the manifest bundle identifier.
    #[must_use]
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Return the hook's configured type name.
    #[must_use]
    pub fn hook_type(&self) -> &str {
        &self.hook_type
    }

    /// Return the declared request-body access mode.
    #[must_use]
    pub const fn body_mode(&self) -> BundleBodyMode {
        self.body_mode
    }

    /// Return the maximum bytes the hook may buffer.
    #[must_use]
    pub const fn max_buffer_bytes(&self) -> usize {
        self.max_buffer_bytes
    }

    /// Return the manifest posture for hook failures.
    #[must_use]
    pub const fn failure_posture(&self) -> FailureMode {
        self.failure_posture
    }
}

/// A dynamically dispatched action plus optional bundle metadata.
pub struct PluginAction {
    handler: Box<dyn ActionHandler>,
    dynamic_hook: Option<DynamicHookMetadata>,
}

impl PluginAction {
    /// Wrap a linked plugin action, preserving its legacy body behavior.
    #[must_use]
    pub fn linked(handler: Box<dyn ActionHandler>) -> Self {
        Self {
            handler,
            dynamic_hook: None,
        }
    }

    /// Wrap a dynamic bundle action and retain its execution metadata.
    #[must_use]
    pub fn dynamic(handler: Box<dyn ActionHandler>, metadata: DynamicHookMetadata) -> Self {
        Self {
            handler,
            dynamic_hook: Some(metadata),
        }
    }

    /// Borrow the action handler.
    #[must_use]
    pub fn handler(&self) -> &dyn ActionHandler {
        self.handler.as_ref()
    }

    /// Return dynamic bundle metadata, or none for linked plugins.
    #[must_use]
    pub fn dynamic_hook(&self) -> Option<&DynamicHookMetadata> {
        self.dynamic_hook.as_ref()
    }
}

/// A dynamically dispatched policy plus optional bundle metadata.
pub struct PluginPolicy {
    enforcer: Box<dyn PolicyEnforcer>,
    dynamic_hook: Option<DynamicHookMetadata>,
}

impl PluginPolicy {
    /// Wrap a linked plugin policy, preserving its legacy body behavior.
    #[must_use]
    pub fn linked(enforcer: Box<dyn PolicyEnforcer>) -> Self {
        Self {
            enforcer,
            dynamic_hook: None,
        }
    }

    /// Wrap a dynamic bundle policy and retain its execution metadata.
    #[must_use]
    pub fn dynamic(enforcer: Box<dyn PolicyEnforcer>, metadata: DynamicHookMetadata) -> Self {
        Self {
            enforcer,
            dynamic_hook: Some(metadata),
        }
    }

    /// Borrow the policy enforcer.
    #[must_use]
    pub fn enforcer(&self) -> &dyn PolicyEnforcer {
        self.enforcer.as_ref()
    }

    /// Consume the wrapper and return its enforcer and metadata.
    #[must_use]
    pub fn into_parts(self) -> (Box<dyn PolicyEnforcer>, Option<DynamicHookMetadata>) {
        (self.enforcer, self.dynamic_hook)
    }
}
