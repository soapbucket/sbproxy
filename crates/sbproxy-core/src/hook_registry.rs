//! Compile-time registration of a pipeline lifecycle hook.
//!
//! Extensions call the `register_startup_hook!` macro at module scope with a
//! factory function; the macro submits a [`StartupHookFactory`] to the
//! `inventory` registry. At runtime [`collect_startup_hook`] walks the
//! registry and returns the only registered factory's output. Builds without
//! an extension register nothing and `collect_startup_hook` returns `None`.
//!
//! Only one startup hook per binary is meaningful. Multiple registrations
//! reject pipeline construction instead of making link order observable.

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
/// Returns `None` if no extension registered one or the factory's output
/// otherwise. Call for each candidate and stash the `Arc` on the pipeline.
///
pub fn collect_startup_hook() -> Option<Arc<dyn PipelineLifecycleHook>> {
    try_collect_startup_hook().expect("linked pipeline startup hooks must be unique")
}

/// Collect the startup hook while reporting registration collisions.
///
/// # Errors
///
/// Returns an error when more than one linked startup hook is registered.
pub fn try_collect_startup_hook() -> anyhow::Result<Option<Arc<dyn PipelineLifecycleHook>>> {
    collect_startup_hook_from(inventory::iter::<StartupHookFactory>)
}

fn collect_startup_hook_from<'a>(
    factories: impl IntoIterator<Item = &'a StartupHookFactory>,
) -> anyhow::Result<Option<Arc<dyn PipelineLifecycleHook>>> {
    let mut factories = factories.into_iter();
    let first = factories.next();
    if factories.next().is_some() {
        anyhow::bail!("multiple linked pipeline startup hooks are registered");
    }
    Ok(first.map(|factory| (factory.factory)()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureHook;

    #[async_trait::async_trait]
    impl PipelineLifecycleHook for FixtureHook {
        async fn on_startup(
            &self,
            _pipeline: &mut crate::pipeline::CompiledPipeline,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn on_reload(
            &self,
            _pipeline: &mut crate::pipeline::CompiledPipeline,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn fixture_hook() -> Arc<dyn PipelineLifecycleHook> {
        Arc::new(FixtureHook)
    }

    #[test]
    fn startup_hook_collision_rejects_the_candidate() {
        let first = StartupHookFactory {
            factory: fixture_hook,
        };
        let second = StartupHookFactory {
            factory: fixture_hook,
        };

        let error = match collect_startup_hook_from([&first, &second]) {
            Ok(_) => panic!("two linked startup hooks must reject the candidate"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "multiple linked pipeline startup hooks are registered"
        );
    }
}
