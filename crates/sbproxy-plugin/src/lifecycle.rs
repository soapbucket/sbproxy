//! Lifecycle traits used by both built-in modules and third-party plugins.
//!
//! The lifecycle phases are:
//! 1. **Provision** - Dependency injection via [`Provisioner`]
//! 2. **Validate** - Config validation via [`Validator`]
//! 3. **Init** - Background work startup via [`Initializable`]
//! 4. **Cleanup** - Teardown on config reload / shutdown via [`Cleanable`]

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::context::PluginContext;

/// Phase 1: Dependency injection.
///
/// Called once after construction to provide shared resources
/// (metrics handles, config references, etc.).
pub trait Provisioner {
    /// Provision this module with shared resources from the context.
    fn provision(&mut self, ctx: &PluginContext) -> Result<()>;
}

/// Phase 2: Config validation.
///
/// Called after provisioning to ensure the module's configuration is valid
/// before any requests are served.
pub trait Validator {
    /// Validate the module's configuration. Returns an error if invalid.
    fn validate(&self) -> Result<()>;
}

/// Phase 3: Background work startup (async).
///
/// Called after validation to start any background tasks
/// (cache warming, connection pools, periodic refreshes, etc.).
pub trait Initializable: Send {
    /// Initialize background work for this module.
    fn init(
        &mut self,
        ctx: &PluginContext,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Cleanup on config reload or shutdown.
///
/// Called when the module is being torn down to release resources,
/// cancel background tasks, and flush pending data.
pub trait Cleanable: Send {
    /// Clean up resources held by this module.
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}
