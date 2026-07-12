//! sbproxy-config: Configuration parsing, compilation, and validation.
//!
//! This crate handles:
//! - Parsing YAML config files into typed structs ([`types`])
//! - Intermediate representation ([`raw`])
//! - Compiling configs into immutable, performance-optimized snapshots ([`snapshot`], [`compiler`])
//! - The repo-native [`listing::Listing`] primitive

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cluster;
pub mod compiler;
pub mod duration;
pub mod listing;
pub mod litellm;
pub mod model_host;
pub mod plan;
pub mod raw;
pub mod snapshot;
pub mod source;
pub mod types;
pub mod validate;

pub use cluster::*;
pub use compiler::*;
pub use listing::{
    is_well_placed_skill_url, load_listing_file, load_listings_from_repo, validate_listings,
    Listing, ListingAccessPlan, ListingAuth, ListingFreeTier, ListingLifecycle, ListingLoadError,
    ListingMetadata, ListingPaidTier, ListingPublish, ListingRegistry, ListingResource,
    ListingSpec, LoadedListing, NoopRevisionResolver, Revision, RevisionMode, RevisionResolver,
    StaticRevisionResolver, LISTINGS_DIRNAME, LISTING_API_VERSION, LISTING_KIND,
};
pub use model_host::*;
pub use plan::{
    compute_baseline_revision, plan, plan_with_options, render_text, BlastRadius, BlastRadiusRule,
    PlanEntry, PlanFile, PlanKind, PlanReport, PlanSummary, BLAST_RADIUS_MATRIX,
};
pub use raw::*;
pub use snapshot::*;
pub use source::{
    load_from_source, ConfigSourceError, FetchContext, GitBinaryCloner, MAX_RECURSION_DEPTH,
};
pub use types::*;
pub use validate::{
    validate, PlanFinding, Severity, ValidationOptions, KNOWN_ACTION_TYPES, KNOWN_AUTH_TYPES,
    KNOWN_POLICY_TYPES, KNOWN_TRANSFORM_TYPES,
};
