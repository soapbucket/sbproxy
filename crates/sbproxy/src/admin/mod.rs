//! WOR-227 scaffold. Binary-side re-exports for the admin UI mount
//! and the chat playground stub.
//!
//! The actual route handlers live in `sbproxy-core` next to the
//! existing admin dispatcher (`crate::admin::handle_admin_request`)
//! because that is where the request router runs. The `sbproxy`
//! binary itself does not own a request loop; it boots the core and
//! exits. These modules exist on the binary side so the cargo
//! feature surface (`--features embed-admin-ui`) and the literal
//! file paths called out in the WOR-227 plan have a home.
//!
//! Follow-up tickets put the real React views and the
//! `proxy_router.oneshot` integration behind these same paths
//! without changing the route shape.

pub mod playground;
pub mod ui;
