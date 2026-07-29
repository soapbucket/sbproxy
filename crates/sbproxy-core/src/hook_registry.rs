//! Compile-time registration of a pipeline lifecycle hook.
//!
//! Extensions call the `register_startup_hook!` macro at module scope with a
//! factory function; the macro submits a [`StartupHookFactory`] to the
//! `inventory` registry. At runtime [`collect_startup_hook`] walks the
//! registry and returns the first (typically only) registered factory's
//! output. Builds without an extension register nothing and `collect_startup_hook`
//! returns `None`.
//!
//! Only one startup hook per binary is meaningful. If multiple extensions
//! register one, the first discovered wins and the rest are silently dropped.

use std::sync::Arc;

use crate::hooks::PipelineLifecycleHook;

/// Inventory record used to collect the pipeline lifecycle hook at runtime.
///
/// `factory` is a bare function pointer (not a closure) so the record can
/// live in a `static` submitted via `inventory::submit!`. The function
/// instantiates a fresh `Arc<dyn PipelineLifecycleHook>` on each call.
pub struct StartupHookFactory {
    /// Bare function pointer that produces a startup hook instance on each call.
    pub factory: fn() -> Arc<dyn PipelineLifecycleHook>,
}

inventory::collect!(StartupHookFactory);

/// Register a `PipelineLifecycleHook` factory at module scope.
///
/// `$factory` must be a function item (not a closure capturing state) with
/// signature `fn() -> Arc<dyn PipelineLifecycleHook>`. The macro wraps it
/// into a `StartupHookFactory` and submits it via `inventory::submit!`
/// so `collect_startup_hook` can discover it at runtime.
#[macro_export]
macro_rules! register_startup_hook {
    ($factory:expr) => {
        inventory::submit! {
            $crate::hook_registry::StartupHookFactory {
                factory: || {
                    let f: fn() -> std::sync::Arc<dyn $crate::hooks::PipelineLifecycleHook> = $factory;
                    f()
                },
            }
        }
    };
}

/// Collect the single registered startup hook.
///
/// Returns `None` if no extension registered one
/// or the first factory's output otherwise. Call once during process
/// startup and stash the `Arc` on the pipeline.
pub fn collect_startup_hook() -> Option<Arc<dyn PipelineLifecycleHook>> {
    inventory::iter::<StartupHookFactory>
        .into_iter()
        .next()
        .map(|f| (f.factory)())
}
