//! Canonical cluster configuration and legacy mesh compatibility lowering.

use std::collections::{BTreeMap, BTreeSet};

use http::Uri;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KeyCacheTier, MeshClusterConfig, ProxyServerConfig};

const DEFAULT_GOSSIP_PORT: u16 = 7946;
const DEFAULT_TRANSPORT_PORT: u16 = 8946;
const DEFAULT_SNAPSHOT_TTL_SECS: u64 = 30;
const DEFAULT_PUBLISH_INTERVAL_SECS: u64 = 5;
const DEFAULT_DEAD_PEER_GC_SECS: u64 = 300;
const DEFAULT_TLS_SERVER_NAME: &str = "sbproxy-mesh";
const MAX_CLUSTER_ROLES: usize = 3;
const MAX_CLUSTER_LABELS: usize = 64;
const MAX_CLUSTER_SEEDS: usize = 128;
const MAX_IDENTITY_LEN: usize = 128;
const MAX_LABEL_KEY_LEN: usize = 128;
const MAX_LABEL_VALUE_LEN: usize = 256;

const fn default_gossip_port() -> u16 {
    DEFAULT_GOSSIP_PORT
}

const fn default_transport_port() -> u16 {
    DEFAULT_TRANSPORT_PORT
}

const fn default_snapshot_ttl_secs() -> u64 {
    DEFAULT_SNAPSHOT_TTL_SECS
}

const fn default_publish_interval_secs() -> u64 {
    DEFAULT_PUBLISH_INTERVAL_SECS
}

const fn default_dead_peer_gc_secs() -> u64 {
    DEFAULT_DEAD_PEER_GC_SECS
}

fn default_tls_server_name() -> String {
    DEFAULT_TLS_SERVER_NAME.to_string()
}

/// Stable role assigned to one cluster node.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// Accept public gateway traffic and apply caller policy.
    Gateway,
    /// Host managed model replicas.
    Worker,
    /// Enroll nodes or publish signed deployment revisions.
    Authority,
}

/// Peer-security mode for the cluster substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterSecurityMode {
    /// Mutually authenticated TLS with operator or enrollment-issued material.
    Mtls,
    /// AES-GCM wire encryption using one shared development secret.
    SharedKey,
}

/// Canonical peer-security configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterSecurityConfig {
    /// Selected peer-security mode.
    pub mode: ClusterSecurityMode,
    /// Explicitly acknowledge that shared-key mode is for development.
    #[serde(default)]
    pub development: bool,
    /// Shared secret reference for authenticated UDP gossip and development transport.
    #[serde(default)]
    pub shared_key: Option<String>,
    /// This node's PEM certificate chain for mTLS.
    #[serde(default)]
    pub cert_file: Option<String>,
    /// This node's PEM private key for mTLS.
    #[serde(default)]
    pub key_file: Option<String>,
    /// PEM CA certificate used to verify every peer.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Cluster SAN bound into every enrolled peer identity.
    #[serde(default = "default_tls_server_name")]
    pub server_name: String,
}

/// Optional one-time enrollment authority configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterEnrollmentConfig {
    /// Durable authority directory created by `sbproxy cluster init`.
    pub authority_dir: String,
    /// Permit plaintext HTTP enrollment for local development only.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

/// Signed deployment-authority configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterDeploymentAuthorityConfig {
    /// Ed25519 private signing-key file, valid only on an authority node.
    #[serde(default)]
    pub signing_key_file: Option<String>,
    /// Ed25519 public verification-key file installed on every node.
    pub verifying_key_file: String,
}

/// Stable `proxy.cluster` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterConfig {
    /// Logical cluster identity. Every member must use the same value.
    pub cluster_id: String,
    /// Stable unique node identity.
    #[serde(default)]
    pub node_id: String,
    /// Roles this process performs.
    #[serde(default)]
    pub roles: BTreeSet<ClusterRole>,
    /// Bounded labels used by placement and failure-domain spreading.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Static gossip seed addresses in `host:port` form.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// UDP SWIM gossip listener port.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,
    /// TCP typed-state and cache transport port.
    #[serde(default = "default_transport_port")]
    pub transport_port: u16,
    /// Address advertised to peers in `host:port` form.
    #[serde(default)]
    pub advertise_addr: Option<String>,
    /// Typed-state transport address advertised to peers in `host:port` form.
    /// Defaults to the gossip-advertised host and `transport_port`.
    #[serde(default)]
    pub transport_advertise_addr: Option<String>,
    /// Private model-plane listener in IP:port form.
    #[serde(default)]
    pub model_bind: Option<String>,
    /// Private model-plane endpoint advertised by worker nodes.
    #[serde(default)]
    pub model_endpoint: Option<String>,
    /// Writable durable state stored with this installed node identity.
    #[serde(default)]
    pub state_dir: Option<String>,
    /// Explicit peer-security policy.
    pub security: ClusterSecurityConfig,
    /// Lifetime of a published node model snapshot.
    #[serde(default = "default_snapshot_ttl_secs")]
    pub snapshot_ttl_secs: u64,
    /// Worker snapshot publication cadence.
    #[serde(default = "default_publish_interval_secs")]
    pub publish_interval_secs: u64,
    /// Time to retain dead peers in the routing membership table before GC.
    /// The operator model directory retains a longer-lived tombstone.
    #[serde(default = "default_dead_peer_gc_secs")]
    pub dead_peer_gc_secs: u64,
    /// Optional one-time enrollment authority.
    #[serde(default)]
    pub enrollment: Option<ClusterEnrollmentConfig>,
    /// Optional signed model deployment authority.
    #[serde(default)]
    pub deployment_authority: Option<ClusterDeploymentAuthorityConfig>,
}

/// Canonical cluster configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid cluster configuration: {message}")]
pub struct ClusterConfigError {
    message: String,
}

impl ClusterConfigError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn conflict(
        field: &str,
        canonical: impl std::fmt::Debug,
        legacy: impl std::fmt::Debug,
    ) -> Self {
        Self::invalid(format!(
            "proxy.cluster {field} {canonical:?} conflicts with key_management.cache.mesh {field} {legacy:?}"
        ))
    }
}

impl ClusterConfig {
    /// Validate the complete canonical cluster before startup or reload.
    pub fn validate(&self) -> Result<(), ClusterConfigError> {
        validate_identity("cluster_id", &self.cluster_id)?;
        validate_identity("node_id", &self.node_id)?;
        if self.roles.is_empty() || self.roles.len() > MAX_CLUSTER_ROLES {
            return Err(ClusterConfigError::invalid(
                "roles must contain at least one supported role",
            ));
        }
        if self.labels.len() > MAX_CLUSTER_LABELS {
            return Err(ClusterConfigError::invalid(format!(
                "labels may contain at most {MAX_CLUSTER_LABELS} entries"
            )));
        }
        for (key, value) in &self.labels {
            validate_label(key, value)?;
        }
        if self.seeds.len() > MAX_CLUSTER_SEEDS {
            return Err(ClusterConfigError::invalid(format!(
                "seeds may contain at most {MAX_CLUSTER_SEEDS} entries"
            )));
        }
        for seed in &self.seeds {
            validate_host_port("seed", seed)?;
        }
        if self.gossip_port == 0 {
            return Err(ClusterConfigError::invalid("gossip_port must be positive"));
        }
        if self.transport_port == 0 {
            return Err(ClusterConfigError::invalid(
                "transport_port must be positive",
            ));
        }
        if let Some(address) = self.advertise_addr.as_deref() {
            validate_host_port("advertise_addr", address)?;
        }
        if let Some(address) = self.transport_advertise_addr.as_deref() {
            validate_host_port("transport_advertise_addr", address)?;
        }
        if let Some(endpoint) = self.model_endpoint.as_deref() {
            validate_model_endpoint(endpoint, self.security.mode)?;
        }
        if let Some(bind) = self.model_bind.as_deref() {
            if !self.roles.contains(&ClusterRole::Worker) {
                return Err(ClusterConfigError::invalid(
                    "model_bind requires the worker role",
                ));
            }
            if self.model_endpoint.is_none() {
                return Err(ClusterConfigError::invalid(
                    "model_bind requires model_endpoint for peer discovery",
                ));
            }
            validate_model_bind(bind)?;
        }
        let state_dir = self.state_dir.as_deref().ok_or_else(|| {
            ClusterConfigError::invalid(
                "state_dir is required for durable cluster identity and snapshot generations",
            )
        })?;
        validate_nonempty("state_dir", state_dir)?;
        if state_dir.len() > 4_096 || state_dir.chars().any(char::is_control) {
            return Err(ClusterConfigError::invalid(
                "state_dir must be a bounded path without control characters",
            ));
        }
        if self.publish_interval_secs == 0 {
            return Err(ClusterConfigError::invalid(
                "publish_interval_secs must be positive",
            ));
        }
        if self.snapshot_ttl_secs < self.publish_interval_secs.saturating_mul(2) {
            return Err(ClusterConfigError::invalid(
                "snapshot_ttl_secs must cover at least two publish intervals",
            ));
        }
        if self.dead_peer_gc_secs == 0 || self.dead_peer_gc_secs > 86_400 {
            return Err(ClusterConfigError::invalid(
                "dead_peer_gc_secs must be between 1 and 86400 seconds",
            ));
        }
        validate_security(&self.security)?;
        if let Some(enrollment) = &self.enrollment {
            if !self.roles.contains(&ClusterRole::Authority) {
                return Err(ClusterConfigError::invalid(
                    "enrollment authority requires the authority role",
                ));
            }
            validate_nonempty("enrollment.authority_dir", &enrollment.authority_dir)?;
            if enrollment.allow_insecure_http
                && self.security.mode != ClusterSecurityMode::SharedKey
            {
                return Err(ClusterConfigError::invalid(
                    "enrollment.allow_insecure_http is valid only in development shared_key mode",
                ));
            }
        }
        if let Some(authority) = &self.deployment_authority {
            if self.state_dir.is_none() {
                return Err(ClusterConfigError::invalid(
                    "deployment_authority requires state_dir for monotonic cursor storage",
                ));
            }
            validate_nonempty(
                "deployment_authority.verifying_key_file",
                &authority.verifying_key_file,
            )?;
            validate_bounded_path(
                "deployment_authority.verifying_key_file",
                &authority.verifying_key_file,
            )?;
            if let Some(signing_key) = authority.signing_key_file.as_deref() {
                if !self.roles.contains(&ClusterRole::Authority) {
                    return Err(ClusterConfigError::invalid(
                        "deployment signing key requires the authority role",
                    ));
                }
                validate_nonempty("deployment_authority.signing_key_file", signing_key)?;
                validate_bounded_path("deployment_authority.signing_key_file", signing_key)?;
            }
        }
        Ok(())
    }
}

fn validate_bounded_path(field: &str, value: &str) -> Result<(), ClusterConfigError> {
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(ClusterConfigError::invalid(format!(
            "{field} must be a bounded path without control characters"
        )));
    }
    Ok(())
}

fn validate_identity(field: &str, value: &str) -> Result<(), ClusterConfigError> {
    validate_nonempty(field, value)?;
    if value.len() > MAX_IDENTITY_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ClusterConfigError::invalid(format!(
            "{field} must contain at most {MAX_IDENTITY_LEN} ASCII letters, digits, dots, dashes, or underscores"
        )));
    }
    Ok(())
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), ClusterConfigError> {
    if value.trim().is_empty() {
        return Err(ClusterConfigError::invalid(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn validate_label(key: &str, value: &str) -> Result<(), ClusterConfigError> {
    if key.is_empty()
        || key.len() > MAX_LABEL_KEY_LEN
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
    {
        return Err(ClusterConfigError::invalid(format!(
            "label key {key:?} is invalid or exceeds {MAX_LABEL_KEY_LEN} bytes"
        )));
    }
    if value.is_empty() || value.len() > MAX_LABEL_VALUE_LEN || value.chars().any(char::is_control)
    {
        return Err(ClusterConfigError::invalid(format!(
            "label {key:?} value is empty, contains a control character, or exceeds {MAX_LABEL_VALUE_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_host_port(field: &str, value: &str) -> Result<(), ClusterConfigError> {
    let (host, port) = value.rsplit_once(':').ok_or_else(|| {
        ClusterConfigError::invalid(format!("{field} {value:?} must use host:port form"))
    })?;
    if host.trim().is_empty()
        || port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
        || value.chars().any(char::is_whitespace)
    {
        return Err(ClusterConfigError::invalid(format!(
            "{field} {value:?} must use a nonempty host and positive port"
        )));
    }
    Ok(())
}

fn validate_model_endpoint(
    endpoint: &str,
    security_mode: ClusterSecurityMode,
) -> Result<(), ClusterConfigError> {
    let uri = endpoint.parse::<Uri>().map_err(|error| {
        ClusterConfigError::invalid(format!("model_endpoint {endpoint:?} is invalid: {error}"))
    })?;
    let expected_scheme = match security_mode {
        ClusterSecurityMode::Mtls => "https",
        ClusterSecurityMode::SharedKey => "http",
    };
    if uri.authority().is_none()
        || uri.scheme_str() != Some(expected_scheme)
        || uri.path() != "/"
        || uri.query().is_some()
        || endpoint.contains('#')
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(ClusterConfigError::invalid(
            "model_endpoint must be an absolute origin using HTTPS for mTLS or HTTP for development shared_key mode",
        ));
    }
    Ok(())
}

fn validate_model_bind(bind: &str) -> Result<(), ClusterConfigError> {
    let address = bind.parse::<std::net::SocketAddr>().map_err(|_| {
        ClusterConfigError::invalid("model_bind must use an IP:port socket address")
    })?;
    if address.port() == 0 {
        return Err(ClusterConfigError::invalid(
            "model_bind port must be positive",
        ));
    }
    Ok(())
}

fn validate_security(security: &ClusterSecurityConfig) -> Result<(), ClusterConfigError> {
    match security.mode {
        ClusterSecurityMode::Mtls => {
            for (field, value) in [
                ("security.cert_file", security.cert_file.as_deref()),
                ("security.key_file", security.key_file.as_deref()),
                ("security.ca_file", security.ca_file.as_deref()),
            ] {
                validate_nonempty(field, value.unwrap_or_default())?;
            }
            validate_nonempty("security.server_name", &security.server_name)?;
            validate_nonempty(
                "security.shared_key",
                security.shared_key.as_deref().unwrap_or_default(),
            )?;
            validate_shared_key_reference(security.shared_key.as_deref().unwrap_or_default())?;
        }
        ClusterSecurityMode::SharedKey => {
            if !security.development {
                return Err(ClusterConfigError::invalid(
                    "shared_key mode requires development: true",
                ));
            }
            validate_nonempty(
                "security.shared_key",
                security.shared_key.as_deref().unwrap_or_default(),
            )?;
            validate_shared_key_reference(security.shared_key.as_deref().unwrap_or_default())?;
            if security.cert_file.is_some()
                || security.key_file.is_some()
                || security.ca_file.is_some()
            {
                return Err(ClusterConfigError::invalid(
                    "mTLS file fields are invalid in shared_key mode",
                ));
            }
        }
    }
    Ok(())
}

fn validate_shared_key_reference(reference: &str) -> Result<(), ClusterConfigError> {
    let reference = reference.trim();
    if reference.contains("${") {
        return Err(ClusterConfigError::invalid(
            "security.shared_key contains an unresolved environment reference",
        ));
    }
    if reference.starts_with("vault://") {
        return Err(ClusterConfigError::invalid(
            "security.shared_key does not resolve vault:// directly; inject it with env: or file:",
        ));
    }
    if reference.starts_with("env:") || reference.starts_with("file:") {
        return Ok(());
    }
    if reference.len() < 16 {
        return Err(ClusterConfigError::invalid(
            "inline security.shared_key must contain at least 16 bytes of entropy",
        ));
    }
    Ok(())
}

/// Origin of the effective process cluster configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterConfigSource {
    /// Stable `proxy.cluster` configuration.
    Canonical,
    /// Compatibility lowering from `key_management.cache.mesh`.
    LegacyMesh,
    /// Canonical configuration also consumed by a matching legacy mesh cache.
    CanonicalWithLegacy,
}

/// One actionable compatibility diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfigDiagnostic {
    /// Stable machine-readable diagnostic code.
    pub code: &'static str,
    /// Human-readable migration guidance.
    pub message: String,
}

/// Resolved peer-security input before core reads secret or PEM material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveClusterSecurity {
    /// Mutually authenticated TLS, optionally layered with legacy wire encryption.
    Mtls {
        /// This node's certificate file.
        cert_file: String,
        /// This node's private-key file.
        key_file: String,
        /// Peer CA file.
        ca_file: String,
        /// Cluster SAN bound into every enrolled peer identity.
        server_name: String,
        /// Optional shared-key reference retained for legacy defense in depth.
        shared_key: Option<String>,
    },
    /// Explicit development shared-key mode.
    SharedKey {
        /// Secret reference or inline development value.
        reference: String,
        /// Explicit development acknowledgement.
        development: bool,
    },
    /// Compatibility-only plaintext legacy mesh mode.
    LegacyPlaintext,
}

/// Security mode after canonical or compatibility lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveClusterSecurityMode {
    /// Mutually authenticated TLS.
    Mtls,
    /// Explicit development shared key.
    SharedKey,
    /// Compatibility-only plaintext legacy mesh.
    LegacyPlaintext,
}

impl EffectiveClusterSecurity {
    /// Security mode used by this resolved configuration.
    pub const fn mode(&self) -> EffectiveClusterSecurityMode {
        match self {
            Self::Mtls { .. } => EffectiveClusterSecurityMode::Mtls,
            Self::SharedKey { .. } => EffectiveClusterSecurityMode::SharedKey,
            Self::LegacyPlaintext => EffectiveClusterSecurityMode::LegacyPlaintext,
        }
    }
}

/// Complete effective cluster input consumed by core startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveClusterConfig {
    /// Syntax sources that produced this input.
    pub source: ClusterConfigSource,
    /// Logical cluster identity.
    pub cluster_id: String,
    /// Explicit node ID, or `None` for the legacy hostname default.
    pub node_id: Option<String>,
    /// Stable process roles.
    pub roles: BTreeSet<ClusterRole>,
    /// Placement labels.
    pub labels: BTreeMap<String, String>,
    /// Static seed peers.
    pub seeds: Vec<String>,
    /// Gossip listener port.
    pub gossip_port: u16,
    /// Typed-state transport listener port.
    pub transport_port: u16,
    /// Advertised peer address.
    pub advertise_addr: Option<String>,
    /// Advertised typed-state transport address.
    pub transport_advertise_addr: Option<String>,
    /// Private model-plane listener.
    pub model_bind: Option<String>,
    /// Private model-plane endpoint.
    pub model_endpoint: Option<String>,
    /// Writable node-identity state directory.
    pub state_dir: Option<String>,
    /// Peer-security source material.
    pub security: EffectiveClusterSecurity,
    /// Snapshot lifetime.
    pub snapshot_ttl_secs: u64,
    /// Snapshot cadence.
    pub publish_interval_secs: u64,
    /// Dead routing-member retention before SWIM GC.
    pub dead_peer_gc_secs: u64,
    /// Optional enrollment authority.
    pub enrollment: Option<ClusterEnrollmentConfig>,
    /// Optional deployment authority.
    pub deployment_authority: Option<ClusterDeploymentAuthorityConfig>,
    /// Actionable compatibility diagnostics.
    pub diagnostics: Vec<ClusterConfigDiagnostic>,
}

/// Process-owned fields that cannot change through hot reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterRestartFingerprint {
    /// Logical cluster identity.
    pub cluster_id: String,
    /// Installed node identity.
    pub node_id: Option<String>,
    /// Process roles.
    pub roles: BTreeSet<ClusterRole>,
    /// Placement labels bound to the installed identity.
    pub labels: BTreeMap<String, String>,
    /// Static discovery seeds.
    pub seeds: Vec<String>,
    /// SWIM listener port.
    pub gossip_port: u16,
    /// Typed-state listener port.
    pub transport_port: u16,
    /// Advertised peer address.
    pub advertise_addr: Option<String>,
    /// Advertised typed-state transport address.
    pub transport_advertise_addr: Option<String>,
    /// Private model-plane listener.
    pub model_bind: Option<String>,
    /// Advertised private model endpoint.
    pub model_endpoint: Option<String>,
    /// Writable node-identity state directory.
    pub state_dir: Option<String>,
    /// Dead routing-member retention before SWIM GC.
    pub dead_peer_gc_secs: u64,
    /// Peer-security source material.
    pub security: EffectiveClusterSecurity,
    /// Enrollment authority loaded at startup.
    pub enrollment: Option<ClusterEnrollmentConfig>,
    /// Deployment signing authority loaded at startup.
    pub deployment_authority: Option<ClusterDeploymentAuthorityConfig>,
}

impl EffectiveClusterConfig {
    /// Return only the fields whose live replacement would split process state.
    pub fn restart_fingerprint(&self) -> ClusterRestartFingerprint {
        ClusterRestartFingerprint {
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            roles: self.roles.clone(),
            labels: self.labels.clone(),
            seeds: self.seeds.clone(),
            gossip_port: self.gossip_port,
            transport_port: self.transport_port,
            advertise_addr: self.advertise_addr.clone(),
            transport_advertise_addr: self.transport_advertise_addr.clone(),
            model_bind: self.model_bind.clone(),
            model_endpoint: self.model_endpoint.clone(),
            state_dir: self.state_dir.clone(),
            dead_peer_gc_secs: self.dead_peer_gc_secs,
            security: self.security.clone(),
            enrollment: self.enrollment.clone(),
            deployment_authority: self.deployment_authority.clone(),
        }
    }
}

/// Resolve canonical and legacy mesh configuration into one process handle.
pub fn resolve_effective_cluster(
    proxy: &ProxyServerConfig,
) -> Result<Option<EffectiveClusterConfig>, ClusterConfigError> {
    let legacy = proxy.key_management.as_ref().and_then(|keys| {
        (keys.enabled && keys.cache.tier == KeyCacheTier::Mesh)
            .then_some((&keys.cache.mesh_node_id, keys.cache.mesh.as_ref()))
            .and_then(|(node_id, mesh)| mesh.map(|mesh| (node_id.as_deref(), mesh)))
    });

    match (proxy.cluster.as_ref(), legacy) {
        (None, None) => Ok(None),
        (Some(canonical), None) => {
            canonical.validate()?;
            validate_enrollment_admin(proxy, canonical)?;
            Ok(Some(lower_canonical(
                canonical,
                ClusterConfigSource::Canonical,
            )))
        }
        (None, Some((node_id, mesh))) => Ok(Some(lower_legacy(node_id, mesh))),
        (Some(canonical), Some((legacy_node_id, mesh))) => {
            canonical.validate()?;
            validate_enrollment_admin(proxy, canonical)?;
            let mut effective =
                lower_canonical(canonical, ClusterConfigSource::CanonicalWithLegacy);
            ensure_legacy_matches(&effective, legacy_node_id, mesh)?;
            effective.diagnostics.push(legacy_diagnostic());
            Ok(Some(effective))
        }
    }
}

fn validate_enrollment_admin(
    proxy: &ProxyServerConfig,
    cluster: &ClusterConfig,
) -> Result<(), ClusterConfigError> {
    let Some(enrollment) = cluster.enrollment.as_ref() else {
        return Ok(());
    };
    let admin = proxy.admin.as_ref().filter(|admin| admin.enabled);
    if admin.is_none() {
        return Err(ClusterConfigError::invalid(
            "cluster enrollment requires proxy.admin.enabled: true",
        ));
    }
    if !enrollment.allow_insecure_http && admin.and_then(|admin| admin.tls.as_ref()).is_none() {
        return Err(ClusterConfigError::invalid(
            "production cluster enrollment requires proxy.admin.tls or explicit development allow_insecure_http",
        ));
    }
    Ok(())
}

fn lower_canonical(config: &ClusterConfig, source: ClusterConfigSource) -> EffectiveClusterConfig {
    EffectiveClusterConfig {
        source,
        cluster_id: config.cluster_id.clone(),
        node_id: Some(config.node_id.clone()),
        roles: config.roles.clone(),
        labels: config.labels.clone(),
        seeds: config.seeds.clone(),
        gossip_port: config.gossip_port,
        transport_port: config.transport_port,
        advertise_addr: config.advertise_addr.clone(),
        transport_advertise_addr: config.transport_advertise_addr.clone(),
        model_bind: config.model_bind.clone(),
        model_endpoint: config.model_endpoint.clone(),
        state_dir: config.state_dir.clone(),
        security: lower_canonical_security(&config.security),
        snapshot_ttl_secs: config.snapshot_ttl_secs,
        publish_interval_secs: config.publish_interval_secs,
        dead_peer_gc_secs: config.dead_peer_gc_secs,
        enrollment: config.enrollment.clone(),
        deployment_authority: config.deployment_authority.clone(),
        diagnostics: Vec::new(),
    }
}

fn lower_canonical_security(security: &ClusterSecurityConfig) -> EffectiveClusterSecurity {
    match security.mode {
        ClusterSecurityMode::Mtls => EffectiveClusterSecurity::Mtls {
            cert_file: security.cert_file.clone().unwrap_or_default(),
            key_file: security.key_file.clone().unwrap_or_default(),
            ca_file: security.ca_file.clone().unwrap_or_default(),
            server_name: security.server_name.clone(),
            shared_key: security.shared_key.clone(),
        },
        ClusterSecurityMode::SharedKey => EffectiveClusterSecurity::SharedKey {
            reference: security.shared_key.clone().unwrap_or_default(),
            development: security.development,
        },
    }
}

fn lower_legacy(node_id: Option<&str>, mesh: &MeshClusterConfig) -> EffectiveClusterConfig {
    EffectiveClusterConfig {
        source: ClusterConfigSource::LegacyMesh,
        cluster_id: "legacy-mesh".to_string(),
        node_id: node_id.map(str::to_string),
        roles: BTreeSet::from([ClusterRole::Gateway, ClusterRole::Worker]),
        labels: BTreeMap::new(),
        seeds: mesh.seeds.clone(),
        gossip_port: mesh.gossip_port,
        transport_port: mesh.transport_port,
        advertise_addr: mesh.advertise_addr.clone(),
        transport_advertise_addr: mesh.transport_advertise_addr.clone(),
        model_bind: None,
        model_endpoint: None,
        state_dir: None,
        security: lower_legacy_security(mesh),
        snapshot_ttl_secs: DEFAULT_SNAPSHOT_TTL_SECS,
        publish_interval_secs: DEFAULT_PUBLISH_INTERVAL_SECS,
        dead_peer_gc_secs: DEFAULT_DEAD_PEER_GC_SECS,
        enrollment: None,
        deployment_authority: None,
        diagnostics: vec![legacy_diagnostic()],
    }
}

fn lower_legacy_security(mesh: &MeshClusterConfig) -> EffectiveClusterSecurity {
    match &mesh.peer_tls {
        Some(tls) => EffectiveClusterSecurity::Mtls {
            cert_file: tls.cert_file.clone(),
            key_file: tls.key_file.clone(),
            ca_file: tls.ca_file.clone(),
            server_name: tls.server_name.clone(),
            shared_key: mesh.shared_key.clone(),
        },
        None => match &mesh.shared_key {
            Some(reference) => EffectiveClusterSecurity::SharedKey {
                reference: reference.clone(),
                development: true,
            },
            None => EffectiveClusterSecurity::LegacyPlaintext,
        },
    }
}

fn legacy_diagnostic() -> ClusterConfigDiagnostic {
    ClusterConfigDiagnostic {
        code: "legacy_mesh_config",
        message: "key_management.cache.mesh is deprecated; move cluster identity, discovery, listeners, and security to proxy.cluster".to_string(),
    }
}

fn ensure_legacy_matches(
    canonical: &EffectiveClusterConfig,
    legacy_node_id: Option<&str>,
    mesh: &MeshClusterConfig,
) -> Result<(), ClusterConfigError> {
    if let Some(legacy_node_id) = legacy_node_id {
        if canonical.node_id.as_deref() != Some(legacy_node_id) {
            return Err(ClusterConfigError::conflict(
                "node_id",
                &canonical.node_id,
                legacy_node_id,
            ));
        }
    }
    compare("seeds", &canonical.seeds, &mesh.seeds)?;
    compare("gossip_port", canonical.gossip_port, mesh.gossip_port)?;
    compare(
        "transport_port",
        canonical.transport_port,
        mesh.transport_port,
    )?;
    compare(
        "advertise_addr",
        &canonical.advertise_addr,
        &mesh.advertise_addr,
    )?;
    compare(
        "transport_advertise_addr",
        &canonical.transport_advertise_addr,
        &mesh.transport_advertise_addr,
    )?;
    if mesh.peer_tls.is_some() || mesh.shared_key.is_some() {
        let legacy_security = lower_legacy_security(mesh);
        compare("security", &canonical.security, &legacy_security)?;
    }
    Ok(())
}

fn compare<T: PartialEq + std::fmt::Debug>(
    field: &str,
    canonical: T,
    legacy: T,
) -> Result<(), ClusterConfigError> {
    if canonical != legacy {
        return Err(ClusterConfigError::conflict(field, canonical, legacy));
    }
    Ok(())
}
