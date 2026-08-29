//! Typed request-enrichment producers: GeoIP and User-Agent parsing.
//!
//! ## Why this is not a `RequestEnricher` trait
//!
//! An earlier design (`sbproxy-plugin::RequestEnricher`) let any
//! plugin hang arbitrary output on a request via `&mut dyn Any`. It
//! was removed rather than wired, because nothing out-of-tree could
//! downcast the result; see `sbproxy/CLAUDE.md`'s "Conventions"
//! section and `sbproxy-plugin::registry`'s
//! `every_plugin_kind_has_a_typed_build_path` test.
//!
//! GeoIP and User-Agent parsing produce concrete, closed-shape data
//! (a country code, an ASN, a browser/OS/device triple), so they get
//! a narrower deal: pure functions and structs here, each wrapped as
//! a built-in [`crate::policy::Policy`] variant
//! (`Policy::GeoIp` / `Policy::UserAgent`) dispatched the same way
//! every other built-in policy is, in
//! `crates/sbproxy-modules/src/compile.rs`. The enforcer side
//! (`crates/sbproxy-core/src/builtin_enforcers/{geoip,user_agent}.rs`)
//! writes the result onto two typed, closed-shape consumers instead
//! of a generic bag:
//!
//! - [`sbproxy_plugin::RequestContextView`]'s `geo_country` /
//!   `geo_asn` / `ua_headless_library` fields, read by any
//!   `AnomalyDetectorHook` or `IdentityResolverHook` a plugin
//!   registers.
//! - `RequestContext::trust_headers`, the same upstream-header
//!   injection sink `exposed_credentials` and forward-auth already
//!   use, for operators who want the raw geo / UA data forwarded to
//!   their origin.
//!
//! Both modules are pure: no I/O beyond an optional local `.mmdb`
//! file read at startup, and no network calls per request.

pub mod geoip;
pub mod uaparser;
