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
//! - Resolving an externally authored config fragment against a
//!   caller-supplied binding set, with no access to the process
//!   environment ([`confined_template`])
//! - A durable, node-local, content-addressed ring of applied config
//!   revisions, used to find the last known good document
//!   ([`revision_store`])
//! - Resolving a `source:` block, including a git repository, into the
//!   config document that actually compiles ([`source`])
//! - The exact, typed settlement configuration under `proxy.payments`
//!   ([`payments`])
//! - The JSON Schema for the config file, generated from the same types
//!   the binary parses with ([`schema`])

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cache_identity;
pub mod cluster;
pub mod compiler;
pub mod config_authority;
pub mod config_bundle;
pub mod config_merge;
pub mod confined_template;
pub mod duration;
pub mod extensions;
pub mod key_registry;
pub mod listing;
pub mod litellm;
pub mod model_host;
pub mod owasp_api_pack;
pub mod payments;
pub mod plan;
pub mod raw;
pub mod revision_store;
pub mod schema;
mod secret_refs;
pub mod snapshot;
pub mod source;
#[cfg(test)]
mod test_env;
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
pub use confined_template::{resolve_confined_fragment, ConfinedTemplateError};
pub use extensions::*;
pub use listing::{
    is_well_placed_skill_url, load_listing_file, load_listings_from_repo, validate_listings,
    Listing, ListingAccessPlan, ListingAuth, ListingFreeTier, ListingLifecycle, ListingLoadError,
    ListingMetadata, ListingPaidTier, ListingPublish, ListingRegistry, ListingResource,
    ListingSpec, LoadedListing, NoopRevisionResolver, Revision, RevisionMode, RevisionResolver,
    StaticRevisionResolver, LISTINGS_DIRNAME, LISTING_API_VERSION, LISTING_KIND,
};
pub use model_host::*;
pub use payments::{
    iso_4217_decimals, settlement_amount, AdvertisedRailName, AmountConversionError, BreakerConfig,
    DirectPaymentIntentConfig, LightningBackend, LightningClnRailConfig, LightningLndRailConfig,
    PaymentAuthProtocolConfig, PaymentProtocolsConfig, PaymentRailsConfig, PaymentsConfig,
    PaymentsConfigError, PaymentsWorkerConfig, RecoveryEncryptionConfig, StripeMeterReporterConfig,
    StripeRailConfig, UsageReportersConfig, X402FacilitatorConfig, X402RailConfig,
    MAX_AUTHORIZATION_TIMEOUT_MS, MAX_PAYMENT_BODY_BYTES, MAX_SETTLEMENT_DECIMALS,
    MAX_X402_EXTRA_JCS_BYTES, PAYMENT_AUTH_DRAFT, PAYMENT_AUTH_INTENT, PAYMENT_AUTH_METHOD,
    STRIPE_API_VERSION, X402_SCHEME,
};
pub use plan::{
    compute_baseline_revision, plan, plan_with_options, render_text, BlastRadius, BlastRadiusRule,
    PlanEntry, PlanFile, PlanKind, PlanReport, PlanSummary, BLAST_RADIUS_MATRIX,
};
pub use raw::*;
pub use revision_store::{
    AppendMetadata, RevisionEntry, RevisionState, RevisionStore, RevisionStoreError, SoakVerdict,
};
pub use schema::{config_json_schema, CONFIG_SCHEMA_FILE};
pub use snapshot::*;
pub use source::{
    credential_references, is_full_commit_sha, load_from_source, load_source_blocking,
    materialize_git_tree, parse_source_head, redact_repo, refresh_interval, resolve_document,
    scrub_credentials, Cloner, ConfigSourceError, FetchContext, FetchRequest, GitBinaryCloner,
    GitTreeRequest, MaterializedGitTree, ResolvedDocument, ResolvedRevision, MAX_RECURSION_DEPTH,
};
pub use types::*;
pub use validate::{
    reserved_builtin_hook_names, validate, PlanFinding, Severity, ValidationOptions,
    KNOWN_ACTION_TYPES, KNOWN_AUTH_TYPES, KNOWN_POLICY_TYPES, KNOWN_TRANSFORM_TYPES,
};
