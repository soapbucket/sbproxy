//! WOR-227 scaffold. Binary-side hook for the chat playground stub.
//!
//! Like `ui.rs` next door, this module re-exports the real handler
//! from `sbproxy_core::admin_playground` so the literal file path
//! in the WOR-227 plan resolves and so the cargo feature surface
//! has a clear binary-side anchor. The `POST /admin/api/playground/chat`
//! route returns 501 today; the follow-up ticket wires it through
//! `proxy_router.oneshot`.

// Allow: these re-exports document the scaffold's binary-side
// surface for the WOR-227 follow-up tickets. Today nothing inside
// the binary consumes them (the route is registered core-side via
// the admin dispatcher), so rustc reports them as unused. The
// follow-up that lands the real handler removes the allow.
#[allow(unused_imports)]
pub use sbproxy_core::admin_playground::{dispatch, CHAT_PATH};
