//! WOR-227 scaffold. Binary-side hook for the built-in admin UI.
//!
//! The route handler lives in `sbproxy_core::admin_ui` (where the
//! admin dispatcher runs); this module is a one-line re-export so
//! the literal file path called out in the WOR-227 plan resolves
//! and so future binary-only wiring (custom build args, feature
//! forwarding to ancillary crates) has somewhere to land without
//! churning the admin module on the core side.
//!
//! See `sbproxy_core::admin_ui` for the actual `include_dir!`
//! invocation and the SPA fallback semantics.

// Allow: these re-exports document the scaffold's binary-side
// surface for the WOR-227 follow-up tickets. Today nothing inside
// the binary consumes them (the route is registered core-side via
// the admin dispatcher), so rustc reports them as unused. The
// follow-up that lands the real handler removes the allow.
#[allow(unused_imports)]
pub use sbproxy_core::admin_ui::{dispatch, UI_PREFIX};
