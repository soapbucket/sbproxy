//! sbproxy-config: Configuration parsing, compilation, and validation.
//!
//! This crate handles:
//! - Parsing YAML config files into typed structs ([`types`])
//! - Intermediate representation ([`raw`])
//! - Compiling configs into immutable, performance-optimized snapshots ([`snapshot`], [`compiler`])
//! - The repo-native [`listing::Listing`] primitive
//! - Signed configuration bundles published by a config authority
//!   ([`config_bundle`])
//! - Durable publication state for a config authority: the revision
//!   counter, the last two bundles, and the subscriber registry
//!   ([`config_authority`])
//! - Merging an authority-supplied document into a locally owned one
//!   ([`config_merge`])
//! - Resolving a `source:` block, including a git repository, into the
//!   config document that actually compiles ([`source`])
//! - The JSON Schema for the config file, generated from the same types
//!   the binary parses with ([`schema`])

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cluster;
pub mod compiler;
pub mod config_authority;
pub mod config_bundle;
pub mod config_merge;
pub mod duration;
pub mod key_registry;
pub mod listing;
pub mod litellm;
pub mod model_host;
pub mod plan;
pub mod raw;
pub mod schema;
pub mod snapshot;
pub mod source;
pub mod types;
pub mod validate;

pub use cluster::*;
pub use compiler::*;
pub use config_authority::{
    AuthorityStore, AuthorityStoreError, CredentialSeed, IssuedSubscriberCredential,
    SubscriberAuthError, SubscriberRecord, AUTHORITY_STATE_SCHEMA_VERSION, CREDENTIAL_ID_BYTES,
    CREDENTIAL_SECRET_BYTES, MAX_SUBSCRIBERS, SUBSCRIBER_TOKEN_PREFIX,
};
pub use config_bundle::{
    is_valid_bundle_identifier, BundleAlgorithm, BundleError, BundleMode, ConfigBundle,
    ConfigBundleCursor, ConfigBundleSigner, CursorError, SignedConfigBundle, VerifyingKeyMaterial,
    VerifyingKeySet, CONFIG_BUNDLE_CLOCK_SKEW_MS, CONFIG_BUNDLE_CONTEXT,
    CONFIG_BUNDLE_SCHEMA_VERSION, MAX_CONFIG_YAML_BYTES,
};
pub use config_merge::{
    changed_leaf_paths, denied_paths_in, merge_config, BaseOrigin, MergeError, MergeMode,
    MergeOutcome, Provenance, ProvenanceMap, AUTHORITY_DENIED_PATHS,
};
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
pub use schema::{config_json_schema, CONFIG_SCHEMA_FILE};
pub use snapshot::*;
pub use source::{
    credential_references, is_full_commit_sha, load_from_source, load_source_blocking,
    parse_source_head, redact_repo, refresh_interval, resolve_document, scrub_credentials, Cloner,
    ConfigSourceError, FetchContext, FetchRequest, GitBinaryCloner, ResolvedDocument,
    ResolvedRevision, MAX_RECURSION_DEPTH,
};
pub use types::*;
pub use validate::{
    validate, PlanFinding, Severity, ValidationOptions, KNOWN_ACTION_TYPES, KNOWN_AUTH_TYPES,
    KNOWN_POLICY_TYPES, KNOWN_TRANSFORM_TYPES,
};
