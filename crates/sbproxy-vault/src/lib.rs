//! sbproxy-vault: Secret management and secure variable interpolation.

#![allow(unsafe_code)]
// Volatile zeroization uses narrowly-scoped unsafe writes so secrets are not optimized away.
#![warn(missing_docs)]

pub mod aws;
pub mod convergent;
pub mod file;
pub mod gcp;
pub mod hashicorp;
pub mod k8s;
pub mod local;
pub mod manager;
pub mod metadata;
pub mod resolver;
pub mod rotation;
pub mod scope;
pub mod secret_string;
pub mod vault_ref;

pub use aws::{AwsAuth, AwsSecretsManagerBackend, AwsSecretsManagerConfig, DEFAULT_AWS_CACHE_TTL};
pub use convergent::ConvergentFingerprinter;
pub use file::{FileFormat, FileVaultBackend, FileVaultConfig};
pub use gcp::{
    GcpSecretManagerAuth, GcpSecretManagerBackend, GcpSecretManagerConfig, DEFAULT_GCP_CACHE_TTL,
};
pub use hashicorp::{
    HashiCorpAuth, HashiCorpConfig, HashiCorpVaultBackend, KvEngine, DEFAULT_CACHE_TTL,
};
pub use k8s::{
    KubernetesAuth, KubernetesSecretsBackend, KubernetesSecretsConfig, DEFAULT_K8S_CACHE_TTL,
};
pub use local::LocalVault;
pub use manager::{VaultBackend, VaultManager};
pub use metadata::{SecretMeta, SecretMetadataTracker};
pub use resolver::{install_process_resolver, process_resolver, ResolveFallback, SecretResolver};
pub use rotation::RotationManager;
pub use scope::{auto_scope, parse_scope, validate_access, SecretScope};
pub use secret_string::SecretString;
pub use vault_ref::{
    legacy_vault_env_name, legacy_vault_reference_replacement, looks_like_secret_reference_uri,
    looks_like_vault_uri, migrate_legacy_vault_references_in_text, LegacyVaultReferenceMigration,
    LegacyVaultReferenceReplacement, VaultProviderType, VaultRef, VaultRefError,
    LEGACY_VAULT_REFERENCE_REMOVAL_VERSION,
};
