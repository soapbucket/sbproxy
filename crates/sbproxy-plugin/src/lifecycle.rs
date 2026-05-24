//! Lifecycle traits used by both built-in modules and third-party plugins.
//!
//! The lifecycle phases run in a fixed order, Provision then Validate
//! then Init then Cleanup:
//!
//! 1. **Provision** - Dependency injection via [`Provisioner`]
//! 2. **Validate** - Config validation via [`Validator`]
//! 3. **Init** - Background work startup via [`Initializable`]
//! 4. **Cleanup** - Teardown on config reload / shutdown via [`Cleanable`]
//!
//! Provision runs once after construction, Validate runs only after a
//! successful Provision, Init runs only after a successful Validate, and
//! Cleanup runs last (on config reload or shutdown). A failure in
//! Provision, Validate, or Init aborts the sequence for that module, so
//! later phases do not run; Cleanup still runs for any module that was
//! provisioned.

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
    ///
    /// ## Errors
    ///
    /// Returns an error when a required resource cannot be obtained or
    /// wired up (a missing dependency, an invalid handle, etc.). A
    /// failure here aborts the lifecycle for this module before
    /// [`Validator::validate`] runs.
    fn provision(&mut self, ctx: &PluginContext) -> Result<()>;
}

/// Phase 2: Config validation.
///
/// Called after provisioning to ensure the module's configuration is valid
/// before any requests are served.
pub trait Validator {
    /// Validate the module's configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error when the configuration is invalid (out-of-range
    /// values, mutually exclusive options set together, references to
    /// resources that do not exist, etc.). A failure here aborts the
    /// lifecycle for this module before [`Initializable::init`] runs, so
    /// no requests are served against an invalid config.
    fn validate(&self) -> Result<()>;
}

/// Phase 3: Background work startup (async).
///
/// Called after validation to start any background tasks
/// (cache warming, connection pools, periodic refreshes, etc.).
pub trait Initializable: Send {
    /// Initialize background work for this module.
    ///
    /// ## Errors
    ///
    /// Returns an error when background startup fails (a connection pool
    /// cannot be opened, a cache cannot be warmed, a periodic task
    /// cannot be spawned, etc.). A failure here aborts the lifecycle for
    /// this module; the caller should run [`Cleanable::cleanup`] to
    /// release anything that was partially started.
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
    ///
    /// ## Errors
    ///
    /// Returns an error when teardown could not complete cleanly (a
    /// pending flush failed, a background task did not stop within its
    /// budget, etc.). Because cleanup runs on reload and shutdown, the
    /// caller typically logs the error and proceeds rather than aborting
    /// the reload; implementations should still release every resource
    /// they can before returning `Err`.
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}
