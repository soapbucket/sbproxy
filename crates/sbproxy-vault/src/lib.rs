//! sbproxy-vault: Secret management and secure variable interpolation.

#![warn(missing_docs)]

pub mod convergent;
pub mod local;
pub mod manager;
pub mod metadata;
pub mod resolver;
pub mod rotation;
pub mod scope;
pub mod secret_string;

pub use convergent::ConvergentFingerprinter;
pub use local::LocalVault;
pub use manager::{VaultBackend, VaultManager};
pub use metadata::{SecretMeta, SecretMetadataTracker};
pub use resolver::{ResolveFallback, SecretResolver};
pub use rotation::RotationManager;
pub use scope::{auto_scope, parse_scope, validate_access, SecretScope};
pub use secret_string::SecretString;
