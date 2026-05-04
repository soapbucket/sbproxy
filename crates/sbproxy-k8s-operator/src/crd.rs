//! CRD type definitions for the sbproxy OSS operator.
//!
//! Two custom resources are defined under the `sbproxy.dev` API group at
//! version `v1alpha1`:
//!
//! - [`SBProxy`]: a desired proxy deployment.
//! - [`SBProxyConfig`]: a versioned `sb.yml` document referenced by an [`SBProxy`].
//!
//! The CRD YAML is generated from these types via `kube-derive`. Run
//! `cargo run -p sbproxy-k8s-operator -- print-crds > deploy/crds/sbproxy.yaml`
//! to refresh the on-disk copy under `deploy/crds/`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// --- SBProxy ---

/// Desired state for a single sbproxy deployment.
///
/// The operator owns a Deployment + Service + ConfigMap triple per `SBProxy`.
/// Spec changes drive reconciliation; status is reserved for future use.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "sbproxy.dev",
    version = "v1alpha1",
    kind = "SBProxy",
    plural = "sbproxies",
    singular = "sbproxy",
    shortname = "sbp",
    namespaced,
    status = "SBProxyStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct SBProxySpec {
    /// Number of proxy replicas to run. Defaults to 1.
    #[serde(default = "default_replicas")]
    pub replicas: i32,

    /// Container image (including tag) for the proxy pod. Required.
    pub image: String,

    /// Name of an `SBProxyConfig` in the same namespace whose `spec.config`
    /// will be mounted as the proxy's `sb.yml`. Required.
    pub config_ref: String,

    /// Optional Kubernetes-style resource requests/limits for the proxy container.
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,

    /// Optional service port. Defaults to 8080.
    #[serde(default = "default_port")]
    pub port: i32,

    /// Optional reference to a Kubernetes Secret holding the basic
    /// auth credentials for the proxy's `/admin/reload` endpoint.
    ///
    /// When set and the proxy exposes its admin port, the operator
    /// prefers a hot-reload (POST /admin/reload) over a rollout
    /// restart on `SBProxyConfig.spec.config` changes. The Secret
    /// at `secretRef.name` must contain a key whose value is the
    /// full basic-auth header value (e.g. `Basic YWRtaW46c2VjcmV0`).
    /// The operator falls back to rollout-restart if the reload
    /// endpoint returns anything other than 200.
    #[serde(default)]
    pub admin_auth_secret_ref: Option<AdminAuthSecretRef>,

    /// Optional admin server port the proxy exposes for
    /// `/admin/reload` and `/api/health/targets`. Defaults to 9090
    /// when `admin_auth_secret_ref` is set; ignored otherwise. The
    /// operator never exposes the admin port through the public
    /// Service; it dials the pod IP directly via the cluster
    /// network.
    #[serde(default = "default_admin_port")]
    pub admin_port: i32,
}

/// Reference to a Kubernetes Secret holding admin credentials.
///
/// The Secret is expected to live in the same namespace as the
/// `SBProxy` resource. Cross-namespace refs are rejected at
/// reconcile time so a misconfigured manifest cannot read secrets
/// from arbitrary namespaces.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuthSecretRef {
    /// Secret name in the same namespace as the SBProxy.
    pub name: String,

    /// Key inside the Secret whose value is the full basic-auth
    /// header (e.g. `Basic YWRtaW46c2VjcmV0`). Defaults to
    /// `authorization` so a Secret of shape
    /// `data: { authorization: <base64-of-Basic-...-> }` works
    /// out of the box.
    #[serde(default = "default_admin_auth_key")]
    pub key: String,
}

/// Mirror of `core/v1.ResourceRequirements` flattened to plain string maps so
/// the CRD schema does not pull in the full `k8s-openapi` JSON schema for that
/// type. The operator translates this into the real type at apply time.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRequirements {
    /// Resource requests. Keys are resource names (e.g. `cpu`, `memory`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub requests: std::collections::BTreeMap<String, String>,

    /// Resource limits. Keys are resource names (e.g. `cpu`, `memory`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub limits: std::collections::BTreeMap<String, String>,
}

/// Status reported by the operator. Currently records the last reconciled
/// config hash so operators can confirm a rollout happened.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SBProxyStatus {
    /// Hash of the last `SBProxyConfig.spec.config` rolled out. Empty if the
    /// referenced config has never been resolved.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_hash: String,

    /// Last error observed during reconcile, if any. Cleared on successful runs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

// --- SBProxyConfig ---

/// A versioned `sb.yml` document, mounted into pods owned by an [`SBProxy`]
/// via a generated ConfigMap.
///
/// The operator does not deeply validate `spec.config`. The proxy parses it on
/// reload and rejects malformed input there. Apply-time validation is limited
/// to "is this a non-empty string".
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "sbproxy.dev",
    version = "v1alpha1",
    kind = "SBProxyConfig",
    plural = "sbproxyconfigs",
    singular = "sbproxyconfig",
    shortname = "sbpc",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct SBProxyConfigSpec {
    /// The full `sb.yml` document as a YAML string. Required.
    pub config: String,
}

// --- Defaults ---

fn default_replicas() -> i32 {
    1
}

fn default_port() -> i32 {
    8080
}

fn default_admin_port() -> i32 {
    9090
}

fn default_admin_auth_key() -> String {
    "authorization".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn sbproxy_crd_yaml_is_well_formed() {
        // CustomResourceExt::crd() yields the v1 CustomResourceDefinition for
        // the resource. Round-tripping through serde_yaml exercises every
        // generated schema chunk.
        let crd = SBProxy::crd();
        let yaml = serde_yaml::to_string(&crd).expect("serialize SBProxy CRD");
        assert!(yaml.contains("sbproxies.sbproxy.dev"));
        assert!(yaml.contains("v1alpha1"));
    }

    #[test]
    fn sbproxyconfig_crd_yaml_is_well_formed() {
        let crd = SBProxyConfig::crd();
        let yaml = serde_yaml::to_string(&crd).expect("serialize SBProxyConfig CRD");
        assert!(yaml.contains("sbproxyconfigs.sbproxy.dev"));
        assert!(yaml.contains("v1alpha1"));
    }

    #[test]
    fn sbproxy_spec_roundtrip_with_defaults() {
        // Minimal spec: only `image` and `configRef` are required. Defaults
        // for replicas and port should fill in.
        let yaml = r#"
image: ghcr.io/soapbucket/sbproxy:latest
configRef: my-config
"#;
        let spec: SBProxySpec = serde_yaml::from_str(yaml).expect("parse spec");
        assert_eq!(spec.replicas, 1);
        assert_eq!(spec.port, 8080);
        assert_eq!(spec.image, "ghcr.io/soapbucket/sbproxy:latest");
        assert_eq!(spec.config_ref, "my-config");
    }
}
