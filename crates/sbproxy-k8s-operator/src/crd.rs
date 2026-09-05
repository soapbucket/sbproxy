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
/// When `spec.clustering.enabled` is true the Deployment is replaced by a
/// StatefulSet plus a headless Service and a shared-key Secret, so replicas
/// form a gossip mesh with stable per-pod DNS identities. Spec changes drive
/// reconciliation; status is reserved for future use.
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

    /// Optional mesh clustering for multi-replica deployments.
    ///
    /// When present and `enabled: true`, the operator reconciles a
    /// StatefulSet (stable per-pod identity) plus a headless Service
    /// for gossip instead of a Deployment, generates a shared cluster
    /// key Secret when none is referenced, and injects a rendered
    /// `proxy.cluster` block into the mounted `sb.yml` so the replicas
    /// form a mesh without hand-written peer configuration. Absent or
    /// `enabled: false` keeps the plain-Deployment path unchanged.
    #[serde(default)]
    pub clustering: Option<ClusteringSpec>,
}

/// Mesh clustering knobs for an `SBProxy`.
///
/// The operator renders the full `proxy.cluster` block itself; these
/// fields only override the ports and naming inputs of that rendering.
/// Any user-supplied `proxy.cluster` block inside the referenced
/// `SBProxyConfig` is replaced by the rendered one while clustering is
/// enabled, so the mesh topology always matches the StatefulSet.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusteringSpec {
    /// Turn mesh clustering on. Defaults to false.
    #[serde(default)]
    pub enabled: bool,

    /// UDP gossip listener port carried into `proxy.cluster.gossip_port`
    /// and exposed on the headless Service. Defaults to 7946.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: i32,

    /// TCP typed-state transport port carried into
    /// `proxy.cluster.transport_port` and exposed on the headless
    /// Service. Defaults to 8946.
    #[serde(default = "default_transport_port")]
    pub transport_port: i32,

    /// Optional name of an existing Secret in the same namespace whose
    /// `cluster-key` entry holds the shared cluster key. When unset the
    /// operator generates a `<sbproxy-name>-cluster-key` Secret once and
    /// reuses it for the lifetime of the SBProxy, so rescheduled pods
    /// always rejoin with the same key.
    #[serde(default)]
    pub cluster_secret_ref: Option<String>,

    /// Cluster DNS domain used when rendering the stable per-pod seed
    /// addresses (`<pod>.<headless-svc>.<ns>.svc.<domain>`). Defaults to
    /// `cluster.local`; override only on clusters with a custom domain.
    #[serde(default = "default_cluster_domain")]
    pub cluster_domain: String,
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

/// Status reported by the operator, so `kubectl get sbproxy -o yaml` answers
/// two different questions: what the operator has seen, and what it has
/// finished delivering.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SBProxyStatus {
    /// Hash of the `SBProxyConfig.spec.config` the operator has finished
    /// delivering. Written only after the ConfigMap, Service, and workload
    /// have all been applied, or after every pod has accepted a hot reload.
    /// Empty until the first rollout completes. A rolling restart is still
    /// asynchronous after the apply lands, so pair this with the workload's
    /// own rollout status when you need to know the pods have caught up.
    /// When this trails `observedConfigHash`, the operator could not finish
    /// delivering; check `lastError` and the operator log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_hash: String,

    /// Hash of the `SBProxyConfig.spec.config` the operator most recently
    /// read and validated. Written before anything is applied, so it says
    /// only that the operator has seen this config, never that it reached the
    /// pods.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_config_hash: String,

    /// Last error observed during reconcile, if any. Cleared only once a
    /// rollout completes, so an empty value and a `configHash` that matches
    /// `observedConfigHash` together mean the fleet is on the config you
    /// applied.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,

    /// Kubernetes-style conditions.
    ///
    /// One type today, `ConfigFallbackActive`: `True` while a
    /// pod owned by this `SBProxy` is serving a configuration its boot
    /// fallback restored from the node's revision ring rather than the
    /// document this operator applied. While it is `True` the operator
    /// stops pushing configuration to this `SBProxy`, because a node
    /// that rescued itself has not drifted on purpose and reapplying the
    /// document it could not compile would restart it into the same
    /// crash loop.
    ///
    /// The condition is the operator-visible signal, so an alert can
    /// fire on "a node in this cluster is running on fallback" without
    /// scraping the proxy directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// One Kubernetes-style status condition.
///
/// Modeled by hand rather than reused from `k8s_openapi`, whose
/// `metav1.Condition` requires `lastTransitionTime` as a `Time` and does
/// not derive `JsonSchema` at the pinned feature set. The field names
/// and semantics match the upstream convention, so `kubectl wait
/// --for=condition=ConfigFallbackActive` works.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type, for example `ConfigFallbackActive`.
    #[serde(rename = "type")]
    pub type_: String,
    /// `True`, `False`, or `Unknown`.
    pub status: String,
    /// Machine-readable, CamelCase reason for the current status.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Human-readable detail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// RFC 3339 timestamp of the last status change.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_transition_time: String,
    /// `metadata.generation` the condition was computed against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl SBProxyStatus {
    /// The config hash the operator has finished delivering, or `None` when
    /// nothing has been delivered yet.
    ///
    /// The emptiness rule lives here rather than at the call site because it
    /// is a property of the field: `configHash` is
    /// `skip_serializing_if = "String::is_empty"`, so a CR carrying a status
    /// for `lastError` alone round-trips back with `config_hash` as `""`.
    /// Treating that as a delivered hash would compare a real hash against
    /// an empty string on every pass, which reads as "the config changed"
    /// forever.
    ///
    /// An empty `observedConfigHash` disqualifies the hash too, and that
    /// rule is what makes an operator upgrade safe. Before `configHash`
    /// meant "delivered" it was written straight after validation and meant
    /// only "seen", so a CR whose last pre-upgrade pass stamped a hash and
    /// then failed its ConfigMap apply carries a `configHash` the pods never
    /// received. Read as delivered, that value pins the pod template where
    /// it is and suppresses the hot reload, and the fleet stays on the old
    /// config while the CR reads healthy. Every pass of an operator that
    /// separates the two writes `observedConfigHash` first, so its presence
    /// is the proof that `configHash` was written under the newer meaning.
    /// The cost when it is absent is one redundant delivery, in the same
    /// direction the code is already wrong in.
    pub fn delivered_config_hash(&self) -> Option<&str> {
        if self.config_hash.is_empty() || self.observed_config_hash.is_empty() {
            return None;
        }
        Some(self.config_hash.as_str())
    }
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
    ///
    /// Bounded at the CRD schema level to 1 MiB so the API server
    /// rejects an oversized or malicious document at admission rather than
    /// mounting it into every proxy pod. Any real `sb.yml` is far smaller.
    #[schemars(length(max = 1_048_576))]
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

fn default_gossip_port() -> i32 {
    7946
}

fn default_transport_port() -> i32 {
    8946
}

fn default_cluster_domain() -> String {
    "cluster.local".to_string()
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
        assert!(
            spec.clustering.is_none(),
            "clustering must default to absent so existing manifests are unchanged"
        );
    }

    #[test]
    fn clustering_spec_defaults_fill_in() {
        let yaml = r#"
image: ghcr.io/soapbucket/sbproxy:latest
configRef: my-config
replicas: 3
clustering:
  enabled: true
"#;
        let spec: SBProxySpec = serde_yaml::from_str(yaml).expect("parse spec");
        let clustering = spec.clustering.expect("clustering parsed");
        assert!(clustering.enabled);
        assert_eq!(clustering.gossip_port, 7946);
        assert_eq!(clustering.transport_port, 8946);
        assert_eq!(clustering.cluster_secret_ref, None);
        assert_eq!(clustering.cluster_domain, "cluster.local");
    }

    #[test]
    fn clustering_spec_enabled_defaults_to_false() {
        // A present-but-empty clustering block must not flip the
        // workload to a StatefulSet.
        let yaml = r#"
image: ghcr.io/soapbucket/sbproxy:latest
configRef: my-config
clustering: {}
"#;
        let spec: SBProxySpec = serde_yaml::from_str(yaml).expect("parse spec");
        assert!(!spec.clustering.expect("clustering parsed").enabled);
    }
}
