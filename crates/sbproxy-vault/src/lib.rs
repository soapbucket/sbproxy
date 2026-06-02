//! sbproxy-vault: Secret management and secure variable interpolation.

#![allow(unsafe_code)]
// Volatile zeroization uses narrowly-scoped unsafe writes so secrets are not optimized away.
#![warn(missing_docs)]

pub mod aws;
pub mod convergent;
pub mod hashicorp;
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
pub use hashicorp::{
    HashiCorpAuth, HashiCorpConfig, HashiCorpVaultBackend, KvEngine, DEFAULT_CACHE_TTL,
};
pub use local::LocalVault;
pub use manager::{VaultBackend, VaultManager};
pub use metadata::{SecretMeta, SecretMetadataTracker};
pub use resolver::{ResolveFallback, SecretResolver};
pub use rotation::RotationManager;
pub use scope::{auto_scope, parse_scope, validate_access, SecretScope};
pub use secret_string::SecretString;
pub use vault_ref::{looks_like_vault_uri, VaultRef, VaultRefError};
