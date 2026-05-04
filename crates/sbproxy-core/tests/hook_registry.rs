use async_trait::async_trait;
use sbproxy_core::hook_registry::collect_startup_hook;
use sbproxy_core::hooks::EnterpriseStartupHook;
use sbproxy_core::register_startup_hook;
use std::sync::Arc;

struct DummyHook;

#[async_trait]
impl EnterpriseStartupHook for DummyHook {
    async fn on_startup(
        &self,
        _p: &mut sbproxy_core::pipeline::CompiledPipeline,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn on_reload(
        &self,
        _p: &mut sbproxy_core::pipeline::CompiledPipeline,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

register_startup_hook!(|| Arc::new(DummyHook));

#[test]
fn collected_hook_is_present() {
    let hook = collect_startup_hook().expect("a hook was registered");
    assert!(Arc::strong_count(&hook) >= 1);
}
