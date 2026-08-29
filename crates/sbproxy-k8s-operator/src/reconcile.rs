//! Reconciliation logic.
//!
//! Pure rendering functions live here so they can be unit-tested without a
//! cluster. The kube-runtime `Controller` wiring (watches, error policy,
//! requeue cadence) lives in `main.rs` and calls into this module to build
//! the desired Deployment / Service / ConfigMap triple for each `SBProxy`,
//! or the StatefulSet / headless Service / Secret / ConfigMap set when
//! `spec.clustering.enabled` is true.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, StatefulSet, StatefulSetSpec, StatefulSetUpdateStrategy,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, EnvVar,
    EnvVarSource, HTTPGetAction, ObjectFieldSelector, Pod, PodSpec, PodTemplateSpec, Probe,
    ResourceRequirements as K8sResourceRequirements, Secret, SecretKeySelector, Service,
    ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::Resource;

use crate::crd::{ClusteringSpec, Condition, SBProxy, SBProxyConfig, SBProxyStatus};

// --- Hot-reload decision ---

/// Decide whether the upcoming reconcile should prefer a hot-reload
/// over a rollout-restart.
///
/// Hot-reload is preferred when:
/// 1. The `SBProxy` has `spec.adminAuthSecretRef` set (so the
///    operator can authenticate against `/admin/reload`).
/// 2. There is an existing Deployment (a first apply has to create
///    the pods before anything can be reloaded into them).
/// 3. Only the underlying `sb.yml` changed (the existing
///    Deployment's image, replicas, resources match the desired
///    Deployment).
/// 4. The config the pods are serving is not already the new one.
///
/// When any of those conditions fails we fall back to the
/// rollout-restart path so a config-incompatible pod is never left
/// running.
///
/// The `running_config_hash` argument comes from [`running_config_hash`],
/// which reads `status.configHash`, and is deliberately not the pod
/// template's `sbproxy.dev/config-hash` annotation. A hot reload does not
/// touch the pod template, by design: changing it is what rolls the pods,
/// which is the restart the reload exists to avoid. Gate 4 read that
/// annotation until now, so it compared the new config against a value that
/// could never advance on the hot-reload path. It was therefore permanently
/// true, and every 300s requeue plus every watch event on the SBProxy,
/// ConfigMap, Service, Deployment, or SBProxyConfig reloaded the whole fleet
/// again, rebuilding each handler chain and dropping warmed per-process
/// state for a config the pods already ran.
pub fn should_hot_reload(
    sbproxy: &SBProxy,
    existing_deploy: Option<&Deployment>,
    desired_deploy: &Deployment,
    running_config_hash: Option<&str>,
    new_config_hash: &str,
) -> bool {
    // Gate 1: adminAuthSecretRef must be configured.
    if sbproxy.spec.admin_auth_secret_ref.is_none() {
        return false;
    }

    // Gate 2: an existing Deployment must be readable. First-apply
    // always falls through to the rollout path so the proxy actually
    // gets created.
    let existing = match existing_deploy {
        Some(d) => d,
        None => return false,
    };

    // Gate 3: only the config changed. We compare the parts of the
    // Deployment spec the operator owns - image, replicas, resource
    // requests/limits, container args - against the desired spec.
    // Anything else (config hash on its own) is considered a
    // hot-reload-eligible change.
    if !deployment_spec_matches_except_config_hash(existing, desired_deploy) {
        return false;
    }

    // Gate 4: the config actually changed. Hot-reload is wasted
    // work otherwise.
    match running_config_hash {
        Some(running) => running != new_config_hash,
        // No hash recorded yet (a first reconcile, or a Deployment created
        // by an operator old enough to predate the field) => treat as a
        // config change so the reload still flushes any drift.
        None => true,
    }
}

/// Compare two Deployments and return true if every operator-owned
/// field matches except the `sbproxy.dev/config-hash` annotation
/// on the pod template (which always reflects the current config).
fn deployment_spec_matches_except_config_hash(a: &Deployment, b: &Deployment) -> bool {
    let (a_spec, b_spec) = match (&a.spec, &b.spec) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };

    // Replicas.
    if a_spec.replicas != b_spec.replicas {
        return false;
    }

    // Container shape (image, args, resources). We only compare the
    // first container; the operator never adds sidecars.
    let a_pod = match a_spec.template.spec.as_ref() {
        Some(s) => s,
        None => return false,
    };
    let b_pod = match b_spec.template.spec.as_ref() {
        Some(s) => s,
        None => return false,
    };
    let a_c = match a_pod.containers.first() {
        Some(c) => c,
        None => return false,
    };
    let b_c = match b_pod.containers.first() {
        Some(c) => c,
        None => return false,
    };
    if a_c.image != b_c.image || a_c.args != b_c.args || a_c.resources != b_c.resources {
        return false;
    }

    true
}

/// Read the prior `sbproxy.dev/config-hash` annotation off an
/// existing Deployment, if any. Used to skip hot-reloads when
/// the config hasn't actually changed.
pub fn previous_config_hash(deploy: &Deployment) -> Option<String> {
    deploy
        .spec
        .as_ref()?
        .template
        .metadata
        .as_ref()?
        .annotations
        .as_ref()?
        .get(CONFIG_HASH_ANNOTATION)
        .cloned()
}

/// Annotation key stamped onto pod templates so that updating the underlying
/// config triggers a rolling restart.
///
/// It records the config the pods were *started* with, which is not always
/// the config they are serving: a hot reload swaps the config inside the
/// running processes and deliberately leaves this alone, because changing it
/// is the rolling restart. [`running_config_hash`] is the one to read when
/// the question is what the fleet is actually running.
pub const CONFIG_HASH_ANNOTATION: &str = "sbproxy.dev/config-hash";

/// The hash of the `sb.yml` the operator has finished delivering to this
/// `SBProxy`, or `None` when nothing has been delivered yet.
///
/// Read off `status.configHash`, which the reconcile writes only once the
/// ConfigMap, Service, and workload have all been applied, or once every pod
/// has accepted a hot reload. That is the whole reason the field is the right
/// source for the hot-reload decision and the pod-template annotation is not:
/// it advances on both delivery paths, and the annotation advances on only
/// one of them.
///
/// A status write is best effort, so a dropped one leaves this trailing by a
/// pass and costs one redundant hot reload. That is a bounded degradation in
/// the same direction the old code was wrong in, not a new failure mode.
///
/// [`SBProxyStatus::delivered_config_hash`] also refuses a `configHash` with
/// no `observedConfigHash` beside it, which is the shape a pre-upgrade
/// operator left behind when it stamped the hash before applying anything.
/// Note what that implies for an install whose CRD has not been upgraded
/// alongside the operator image: the apiserver prunes the unknown
/// `observedConfigHash` field, this reads `None` on every pass, and the
/// fleet is hot-reloaded once per requeue again. Loud and wasteful rather
/// than silently stuck, and it stops the moment the CRD is applied.
pub fn running_config_hash(sbproxy: &SBProxy) -> Option<&str> {
    sbproxy
        .status
        .as_ref()
        .and_then(SBProxyStatus::delivered_config_hash)
}

/// The hash to stamp on the pod template of the workload about to be applied.
///
/// Usually the new config hash, which is what makes a config edit roll the
/// pods. The exception is the pass right after a successful hot reload: the
/// pods are already serving `new_config_hash` while their template still
/// carries whatever they were started with, and re-stamping the current hash
/// would change the pod template and roll the whole fleet for a config it is
/// already running, undoing exactly what the hot reload bought.
///
/// So when the pods already run the new config and a template hash exists,
/// keep the template hash. Every other case, including a first apply and a
/// hot reload that failed, uses the new hash and rolls.
pub fn rollout_config_hash<'a>(
    existing_template_hash: Option<&'a str>,
    running_config_hash: Option<&str>,
    new_config_hash: &'a str,
) -> &'a str {
    match (existing_template_hash, running_config_hash) {
        (Some(template), Some(running)) if running == new_config_hash => template,
        _ => new_config_hash,
    }
}

/// Label that marks every owned object so kubectl filtering and the operator's
/// own list-watch selectors are consistent.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

/// Value of [`MANAGED_BY_LABEL`].
pub const MANAGED_BY_VALUE: &str = "sbproxy-k8s-operator";

/// Standard label set applied to every owned object.
pub fn standard_labels(sbproxy_name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "sbproxy".to_string());
    labels.insert(
        "app.kubernetes.io/instance".to_string(),
        sbproxy_name.to_string(),
    );
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    labels
}

/// Compute a stable hash of an `sb.yml` document body. Used to drive
/// rollout-restart on config change.
///
/// We use a non-cryptographic hash on purpose: this is for change detection,
/// not integrity. `DefaultHasher` is sufficient and avoids pulling sha2 into
/// the operator's dependency tree.
pub fn config_hash(config: &str) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    config.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Build the desired ConfigMap for an `SBProxy` + `SBProxyConfig` pair.
///
/// The ConfigMap is named after the `SBProxy` (not the `SBProxyConfig`) so
/// pod volume references stay stable even if the spec.configRef changes.
pub fn desired_configmap(sbproxy: &SBProxy, config: &SBProxyConfig) -> ConfigMap {
    desired_configmap_with_body(sbproxy, &config.spec.config)
}

/// Build the desired ConfigMap from an explicit `sb.yml` body.
///
/// The non-clustered path passes the referenced `SBProxyConfig` document
/// through untouched; the clustered path passes the rendered document from
/// [`render_clustered_config`] instead.
pub fn desired_configmap_with_body(sbproxy: &SBProxy, body: &str) -> ConfigMap {
    let name = configmap_name(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();
    let mut data = BTreeMap::new();
    data.insert("sb.yml".to_string(), body.to_string());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name),
            namespace,
            labels: Some(standard_labels(
                sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"),
            )),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Build the desired Service for an `SBProxy`.
pub fn desired_service(sbproxy: &SBProxy) -> Service {
    let name = service_name(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();
    let port = sbproxy.spec.port;

    let mut selector = BTreeMap::new();
    selector.insert(
        "app.kubernetes.io/instance".to_string(),
        sbproxy.metadata.name.clone().unwrap_or_default(),
    );
    selector.insert("app.kubernetes.io/name".to_string(), "sbproxy".to_string());

    Service {
        metadata: ObjectMeta {
            name: Some(name),
            namespace,
            labels: Some(standard_labels(
                sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"),
            )),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(selector),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port,
                target_port: Some(IntOrString::Int(port)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the desired Deployment for an `SBProxy` and a config hash.
///
/// The hash is stamped on the pod template's annotations so any change to the
/// underlying `SBProxyConfig` triggers a rolling restart.
pub fn desired_deployment(sbproxy: &SBProxy, config_hash: &str) -> Deployment {
    let name = deployment_name(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();
    let labels = standard_labels(sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"));

    let mut pod_annotations = BTreeMap::new();
    pod_annotations.insert(CONFIG_HASH_ANNOTATION.to_string(), config_hash.to_string());

    let resources = sbproxy
        .spec
        .resources
        .as_ref()
        .map(translate_resources)
        .unwrap_or_default();

    let container = Container {
        name: "sbproxy".to_string(),
        image: Some(sbproxy.spec.image.clone()),
        args: Some(vec![
            "--config".to_string(),
            "/etc/sbproxy/sb.yml".to_string(),
        ]),
        ports: Some(vec![ContainerPort {
            name: Some("http".to_string()),
            container_port: sbproxy.spec.port,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }]),
        volume_mounts: Some(vec![VolumeMount {
            name: "config".to_string(),
            mount_path: "/etc/sbproxy".to_string(),
            read_only: Some(true),
            ..Default::default()
        }]),
        resources: Some(resources),
        ..Default::default()
    };

    let configmap = configmap_name(sbproxy);
    let volume = Volume {
        name: "config".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: configmap,
            ..Default::default()
        }),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(name),
            namespace,
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(sbproxy.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(pod_annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(vec![volume]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Translate the CRD-shaped resource spec into a `core/v1.ResourceRequirements`.
fn translate_resources(r: &crate::crd::ResourceRequirements) -> K8sResourceRequirements {
    let to_map = |m: &BTreeMap<String, String>| -> Option<BTreeMap<String, Quantity>> {
        if m.is_empty() {
            None
        } else {
            Some(
                m.iter()
                    .map(|(k, v)| (k.clone(), Quantity(v.clone())))
                    .collect(),
            )
        }
    };
    K8sResourceRequirements {
        requests: to_map(&r.requests),
        limits: to_map(&r.limits),
        ..Default::default()
    }
}

// --- Clustered (mesh) reconciliation ---
//
// When `spec.clustering.enabled` is true the operator swaps the Deployment
// for a StatefulSet + headless Service + shared-key Secret and injects a
// rendered `proxy.cluster` block into the mounted `sb.yml`. A StatefulSet
// (not a Deployment) is used deliberately: mesh peers need a stable
// identity that survives pod rescheduling, and only StatefulSet pods get
// a stable ordinal name plus a stable per-pod DNS record
// (`<pod>.<headless-svc>.<ns>.svc.<domain>`) through the headless
// Service. With a Deployment, pod names and IPs change on every
// reschedule, so seed lists rot and a restarted pod rejoins as a new
// ghost identity instead of itself.

/// Environment variable carrying the pod's own name via the downward API.
///
/// The rendered `proxy.cluster.node_id` and `proxy.cluster.advertise_addr`
/// reference it as `${SBPROXY_POD_NAME}`, which the proxy's config loader
/// interpolates from the environment at startup. One shared ConfigMap
/// therefore yields a distinct stable identity per StatefulSet pod.
pub const POD_NAME_ENV: &str = "SBPROXY_POD_NAME";

/// Environment variable the rendered `proxy.cluster.security.shared_key`
/// reference (`env:SBPROXY_CLUSTER_KEY`) resolves at proxy startup. The
/// StatefulSet injects it from the cluster shared-key Secret.
pub const CLUSTER_KEY_ENV: &str = "SBPROXY_CLUSTER_KEY";

/// Key inside the cluster shared-key Secret that holds the key material.
pub const CLUSTER_KEY_SECRET_KEY: &str = "cluster-key";

/// Writable emptyDir mount path backing the cluster state directory.
pub const CLUSTER_STATE_MOUNT_PATH: &str = "/var/lib/sbproxy";

/// `proxy.cluster.state_dir` rendered into clustered pods. The mesh
/// creates the directory on first start; node identity is pinned by the
/// explicit `node_id`, so losing the emptyDir on reschedule is safe.
pub const CLUSTER_STATE_DIR: &str = "/var/lib/sbproxy/cluster";

/// True when this `SBProxy` asks for the clustered (mesh) topology.
pub fn clustering_enabled(sbproxy: &SBProxy) -> bool {
    sbproxy.spec.clustering.as_ref().is_some_and(|c| c.enabled)
}

/// Effective clustering knobs, defaulting every field when the block is
/// absent. Callers on the clustered path use this so a partially
/// specified `spec.clustering` behaves like the documented defaults.
fn clustering_spec(sbproxy: &SBProxy) -> ClusteringSpec {
    sbproxy
        .spec
        .clustering
        .clone()
        .unwrap_or_else(|| ClusteringSpec {
            enabled: false,
            gossip_port: 7946,
            transport_port: 8946,
            cluster_secret_ref: None,
            cluster_domain: "cluster.local".to_string(),
        })
}

/// StatefulSet name for the clustered path. Deliberately the same
/// `<name>-proxy` as [`deployment_name`]: a StatefulSet and a Deployment
/// are distinct kinds, so the names never collide in the API, and sharing
/// the name makes the clustering on/off transition an explicit
/// delete-then-apply of the same workload identity.
pub fn statefulset_name(sbproxy: &SBProxy) -> String {
    deployment_name(sbproxy)
}

/// Headless Service name (`<name>-mesh`) that gives StatefulSet pods
/// their stable per-pod DNS records for gossip and mesh transport.
pub fn headless_service_name(sbproxy: &SBProxy) -> String {
    format!(
        "{}-mesh",
        sbproxy.metadata.name.as_deref().unwrap_or("sbproxy")
    )
}

/// Name of the Secret holding the shared cluster key: the user-supplied
/// `spec.clustering.clusterSecretRef` when set, or the operator-generated
/// `<name>-cluster-key` otherwise.
pub fn cluster_secret_name(sbproxy: &SBProxy) -> String {
    if let Some(reference) = sbproxy
        .spec
        .clustering
        .as_ref()
        .and_then(|c| c.cluster_secret_ref.as_deref())
    {
        return reference.to_string();
    }
    format!(
        "{}-cluster-key",
        sbproxy.metadata.name.as_deref().unwrap_or("sbproxy")
    )
}

/// True when the operator must generate the shared-key Secret itself:
/// clustering is on, no user-managed Secret is referenced, and the
/// generated Secret does not exist yet. An existing Secret is always
/// reused so pods rescheduled at any point rejoin with the same key.
pub fn needs_generated_cluster_secret(sbproxy: &SBProxy, existing: Option<&Secret>) -> bool {
    clustering_enabled(sbproxy)
        && sbproxy
            .spec
            .clustering
            .as_ref()
            .is_some_and(|c| c.cluster_secret_ref.is_none())
        && existing.is_none()
}

/// Generate fresh shared-key material: 32 random bytes, hex-encoded.
pub fn generate_cluster_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the operator-generated shared-key Secret. Owned by the
/// `SBProxy` so deleting the CR cascades; the reconciler only creates
/// it when absent and never overwrites existing key material.
pub fn desired_cluster_secret(sbproxy: &SBProxy, key_material: &str) -> Secret {
    let mut string_data = BTreeMap::new();
    string_data.insert(CLUSTER_KEY_SECRET_KEY.to_string(), key_material.to_string());
    Secret {
        metadata: ObjectMeta {
            name: Some(cluster_secret_name(sbproxy)),
            namespace: sbproxy.metadata.namespace.clone(),
            labels: Some(standard_labels(
                sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"),
            )),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        string_data: Some(string_data),
        ..Default::default()
    }
}

/// Build the headless Service (`clusterIP: None`) that backs the
/// StatefulSet's stable per-pod DNS names.
///
/// `publishNotReadyAddresses: true` keeps peer DNS records resolvable
/// while a pod is starting, so mesh bootstrap during a cold start or a
/// full restart is not gated on readiness that the mesh itself feeds.
pub fn desired_headless_service(sbproxy: &SBProxy) -> Service {
    let clustering = clustering_spec(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();

    let mut selector = BTreeMap::new();
    selector.insert(
        "app.kubernetes.io/instance".to_string(),
        sbproxy.metadata.name.clone().unwrap_or_default(),
    );
    selector.insert("app.kubernetes.io/name".to_string(), "sbproxy".to_string());

    Service {
        metadata: ObjectMeta {
            name: Some(headless_service_name(sbproxy)),
            namespace,
            labels: Some(standard_labels(
                sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"),
            )),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            publish_not_ready_addresses: Some(true),
            selector: Some(selector),
            ports: Some(vec![
                ServicePort {
                    name: Some("gossip".to_string()),
                    port: clustering.gossip_port,
                    target_port: Some(IntOrString::Int(clustering.gossip_port)),
                    protocol: Some("UDP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("mesh".to_string()),
                    port: clustering.transport_port,
                    target_port: Some(IntOrString::Int(clustering.transport_port)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Validate and narrow the CRD's i32 ports into the u16 range the
/// cluster config schema uses.
fn clustering_ports(clustering: &ClusteringSpec) -> Result<(u16, u16), String> {
    let gossip_raw = clustering.gossip_port;
    let transport_raw = clustering.transport_port;
    let gossip = u16::try_from(gossip_raw)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| format!("clustering.gossipPort {gossip_raw} must be in 1-65535"))?;
    let transport = u16::try_from(transport_raw)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| format!("clustering.transportPort {transport_raw} must be in 1-65535"))?;
    if gossip == transport {
        return Err(format!(
            "clustering.gossipPort and clustering.transportPort must differ (both {gossip})"
        ));
    }
    Ok((gossip, transport))
}

/// Build the typed `proxy.cluster` block for this `SBProxy`.
///
/// Constructing `sbproxy_config::ClusterConfig` (rather than a free-form
/// YAML mapping) guarantees every rendered key exists in the config
/// schema: a schema rename breaks this crate at compile time instead of
/// producing a silently ignored field.
///
/// Identity fields are rendered as `${SBPROXY_POD_NAME}` references. The
/// proxy interpolates `${VAR}` from the environment before parsing
/// (`sbproxy-config/src/compiler.rs`), and the StatefulSet injects the
/// pod name via the downward API, so each replica resolves a distinct
/// stable `node_id` and `advertise_addr` from one shared document.
/// Cluster validation runs at proxy startup, after interpolation.
///
/// Seeds list every ordinal's stable DNS name, own address included: the
/// mesh bootstrap filters the node's own advertised address out of the
/// seed set (`sbproxy-mesh/src/bootstrap.rs`), and a full list means any
/// pod can rejoin through whichever peers are up. Seeding only pod-0
/// would make pod-0's own restart bootstrap a second single-node
/// cluster, which is exactly the split-brain this layout avoids.
fn desired_cluster_block(
    sbproxy: &SBProxy,
    clustering: &ClusteringSpec,
) -> Result<sbproxy_config::ClusterConfig, String> {
    use sbproxy_config::{ClusterConfig, ClusterRole, ClusterSecurityConfig, ClusterSecurityMode};

    let (gossip_port, transport_port) = clustering_ports(clustering)?;
    let name = sbproxy.metadata.name.as_deref().unwrap_or("sbproxy");
    let namespace = sbproxy.metadata.namespace.as_deref().unwrap_or("default");
    let sts = statefulset_name(sbproxy);
    let headless = headless_service_name(sbproxy);
    let domain = clustering.cluster_domain.as_str();

    let replicas = sbproxy.spec.replicas.max(1);
    // The cluster config schema caps `seeds` at 128 entries.
    if replicas > 128 {
        return Err(format!(
            "clustering supports at most 128 replicas (got {replicas})"
        ));
    }
    let seeds = (0..replicas)
        .map(|ordinal| format!("{sts}-{ordinal}.{headless}.{namespace}.svc.{domain}:{gossip_port}"))
        .collect();

    Ok(ClusterConfig {
        cluster_id: name.to_string(),
        node_id: format!("${{{POD_NAME_ENV}}}"),
        roles: BTreeSet::from([ClusterRole::Gateway]),
        labels: BTreeMap::new(),
        seeds,
        gossip_port,
        transport_port,
        advertise_addr: Some(format!(
            "${{{POD_NAME_ENV}}}.{headless}.{namespace}.svc.{domain}:{gossip_port}"
        )),
        transport_advertise_addr: None,
        model_bind: None,
        model_endpoint: None,
        state_dir: Some(CLUSTER_STATE_DIR.to_string()),
        // Shared-key mode is the operator-manageable security mode: the
        // key lives in a Kubernetes Secret, so any rescheduled or scaled
        // pod picks it up again with zero coordination. The mTLS mode
        // needs per-node certificate issuance and the enrollment
        // authority mints one-time tokens per node, neither of which an
        // operator can replay for a rescheduled pod without becoming a
        // certificate authority. The schema requires the explicit
        // `development: true` acknowledgement for shared-key mode.
        security: ClusterSecurityConfig {
            mode: ClusterSecurityMode::SharedKey,
            development: true,
            shared_key: Some(format!("env:{CLUSTER_KEY_ENV}")),
            cert_file: None,
            key_file: None,
            ca_file: None,
            server_name: "sbproxy-mesh".to_string(),
            // The historical derivation. A rendered manifest must not
            // change an existing cluster's wire key on upgrade; see
            // docs/mesh-replication.md for the staged flip.
            key_derivation: sbproxy_config::types::MeshKeyDerivation::Sha256,
        },
        // Mirror the schema defaults in sbproxy-config/src/cluster.rs so
        // the rendered document is explicit and deterministic.
        snapshot_ttl_secs: 30,
        publish_interval_secs: 5,
        dead_peer_gc_secs: 300,
        enrollment: None,
        deployment_authority: None,
        replication: None,
    })
}

/// Render the clustered `sb.yml`: the user's `SBProxyConfig` document
/// with the operator-owned `proxy.cluster` block injected.
///
/// Any user-supplied `proxy.cluster` block is replaced, not merged: the
/// mesh topology must match the StatefulSet the operator runs, and a
/// half-merged block would be neither. The rendered document is parsed
/// back through `sbproxy_config::ConfigFile` as a drift guard before it
/// is accepted.
pub fn render_clustered_config(sbproxy: &SBProxy, user_config: &str) -> Result<String, String> {
    let clustering = clustering_spec(sbproxy);
    let cluster = desired_cluster_block(sbproxy, &clustering)?;
    let cluster_value =
        serde_yaml::to_value(&cluster).map_err(|e| format!("serialize cluster block: {e}"))?;

    let doc: serde_yaml::Value =
        serde_yaml::from_str(user_config).map_err(|e| format!("config parse error: {e}"))?;
    let mut root = match doc {
        serde_yaml::Value::Mapping(m) => m,
        serde_yaml::Value::Null => serde_yaml::Mapping::new(),
        _ => return Err("sb.yml root must be a YAML mapping".to_string()),
    };
    let mut proxy = match root.remove("proxy") {
        Some(serde_yaml::Value::Mapping(m)) => m,
        Some(serde_yaml::Value::Null) | None => serde_yaml::Mapping::new(),
        Some(_) => return Err("proxy must be a YAML mapping".to_string()),
    };
    proxy.insert(
        serde_yaml::Value::String("cluster".to_string()),
        cluster_value,
    );
    root.insert(
        serde_yaml::Value::String("proxy".to_string()),
        serde_yaml::Value::Mapping(proxy),
    );

    let rendered = serde_yaml::to_string(&serde_yaml::Value::Mapping(root))
        .map_err(|e| format!("serialize rendered config: {e}"))?;

    // Drift guard: the rendered document must still parse into the
    // config schema. Catches schema-shape regressions at reconcile time
    // instead of crash-looping every pod.
    serde_yaml::from_str::<sbproxy_config::ConfigFile>(&rendered)
        .map_err(|e| format!("rendered config failed schema parse: {e}"))?;

    Ok(rendered)
}

/// Build the desired StatefulSet for a clustered `SBProxy`.
///
/// Differences from the Deployment path, each load-bearing for the mesh:
///
/// - `serviceName` points at the headless Service so every pod gets a
///   stable DNS record that the rendered seeds and advertise address use.
/// - `podManagementPolicy: OrderedReady` plus the default
///   `RollingUpdate` strategy roll pods one at a time, highest ordinal
///   first, waiting for readiness between steps, so a rolling restart
///   never takes two mesh members down at once.
/// - A readiness probe on the data plane's `/health` gates each step of
///   the roll; a liveness probe restarts a wedged pod.
/// - The pod name is injected as [`POD_NAME_ENV`] (downward API) and the
///   shared cluster key as [`CLUSTER_KEY_ENV`] (Secret reference), which
///   the rendered config consumes.
/// - An emptyDir at [`CLUSTER_STATE_MOUNT_PATH`] backs
///   `proxy.cluster.state_dir`.
pub fn desired_statefulset(sbproxy: &SBProxy, config_hash: &str) -> StatefulSet {
    let clustering = clustering_spec(sbproxy);
    let name = statefulset_name(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();
    let labels = standard_labels(sbproxy.metadata.name.as_deref().unwrap_or("sbproxy"));

    let mut pod_annotations = BTreeMap::new();
    pod_annotations.insert(CONFIG_HASH_ANNOTATION.to_string(), config_hash.to_string());

    let resources = sbproxy
        .spec
        .resources
        .as_ref()
        .map(translate_resources)
        .unwrap_or_default();

    let container = Container {
        name: "sbproxy".to_string(),
        image: Some(sbproxy.spec.image.clone()),
        args: Some(vec![
            "--config".to_string(),
            "/etc/sbproxy/sb.yml".to_string(),
        ]),
        ports: Some(vec![
            ContainerPort {
                name: Some("http".to_string()),
                container_port: sbproxy.spec.port,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ContainerPort {
                name: Some("gossip".to_string()),
                container_port: clustering.gossip_port,
                protocol: Some("UDP".to_string()),
                ..Default::default()
            },
            ContainerPort {
                name: Some("mesh".to_string()),
                container_port: clustering.transport_port,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ]),
        env: Some(vec![
            EnvVar {
                name: POD_NAME_ENV.to_string(),
                value_from: Some(EnvVarSource {
                    field_ref: Some(ObjectFieldSelector {
                        field_path: "metadata.name".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: CLUSTER_KEY_ENV.to_string(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: cluster_secret_name(sbproxy),
                        key: CLUSTER_KEY_SECRET_KEY.to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".to_string(),
                mount_path: "/etc/sbproxy".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "cluster-state".to_string(),
                mount_path: CLUSTER_STATE_MOUNT_PATH.to_string(),
                ..Default::default()
            },
        ]),
        readiness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/health".to_string()),
                port: IntOrString::Int(sbproxy.spec.port),
                ..Default::default()
            }),
            initial_delay_seconds: Some(1),
            period_seconds: Some(5),
            ..Default::default()
        }),
        liveness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/health".to_string()),
                port: IntOrString::Int(sbproxy.spec.port),
                ..Default::default()
            }),
            initial_delay_seconds: Some(5),
            period_seconds: Some(10),
            ..Default::default()
        }),
        resources: Some(resources),
        ..Default::default()
    };

    let volumes = vec![
        Volume {
            name: "config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: configmap_name(sbproxy),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "cluster-state".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        },
    ];

    StatefulSet {
        metadata: ObjectMeta {
            name: Some(name),
            namespace,
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference(sbproxy)]),
            ..Default::default()
        },
        spec: Some(StatefulSetSpec {
            replicas: Some(sbproxy.spec.replicas),
            service_name: headless_service_name(sbproxy),
            pod_management_policy: Some("OrderedReady".to_string()),
            update_strategy: Some(StatefulSetUpdateStrategy {
                type_: Some("RollingUpdate".to_string()),
                ..Default::default()
            }),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(pod_annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Mirror of [`should_hot_reload`] for the clustered StatefulSet path.
///
/// The gates are identical; only the workload kind differs. Note that a
/// change touching the rendered `proxy.cluster` block (replica count,
/// ports, secret reference) always changes the StatefulSet spec too, so
/// it fails gate 3 and takes the rollout path; the proxy additionally
/// refuses `/admin/reload` for process-owned cluster changes, which
/// turns any remaining edge into the rollout fallback.
pub fn should_hot_reload_statefulset(
    sbproxy: &SBProxy,
    existing: Option<&StatefulSet>,
    desired: &StatefulSet,
    running_config_hash: Option<&str>,
    new_config_hash: &str,
) -> bool {
    if sbproxy.spec.admin_auth_secret_ref.is_none() {
        return false;
    }
    let existing = match existing {
        Some(s) => s,
        None => return false,
    };
    if !statefulset_spec_matches_except_config_hash(existing, desired) {
        return false;
    }
    match running_config_hash {
        Some(running) => running != new_config_hash,
        None => true,
    }
}

/// Compare two StatefulSets on every operator-owned field except the
/// pod template's config-hash annotation. Mirrors
/// [`deployment_spec_matches_except_config_hash`] and additionally
/// compares container env, because the clustered pod spec carries the
/// Secret reference there.
fn statefulset_spec_matches_except_config_hash(a: &StatefulSet, b: &StatefulSet) -> bool {
    let (a_spec, b_spec) = match (&a.spec, &b.spec) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };

    if a_spec.replicas != b_spec.replicas || a_spec.service_name != b_spec.service_name {
        return false;
    }

    let a_pod = match a_spec.template.spec.as_ref() {
        Some(s) => s,
        None => return false,
    };
    let b_pod = match b_spec.template.spec.as_ref() {
        Some(s) => s,
        None => return false,
    };
    let a_c = match a_pod.containers.first() {
        Some(c) => c,
        None => return false,
    };
    let b_c = match b_pod.containers.first() {
        Some(c) => c,
        None => return false,
    };
    if a_c.image != b_c.image
        || a_c.args != b_c.args
        || a_c.resources != b_c.resources
        || a_c.env != b_c.env
    {
        return false;
    }

    true
}

/// Read the prior `sbproxy.dev/config-hash` annotation off an existing
/// StatefulSet, if any. StatefulSet counterpart of
/// [`previous_config_hash`].
pub fn previous_config_hash_statefulset(sts: &StatefulSet) -> Option<String> {
    sts.spec
        .as_ref()?
        .template
        .metadata
        .as_ref()?
        .annotations
        .as_ref()?
        .get(CONFIG_HASH_ANNOTATION)
        .cloned()
}

/// Owned-object naming. Suffixed so a single SBProxy's Service, Deployment,
/// and ConfigMap don't clash on the same name.
pub fn deployment_name(sbproxy: &SBProxy) -> String {
    format!(
        "{}-proxy",
        sbproxy.metadata.name.as_deref().unwrap_or("sbproxy")
    )
}

/// ConfigMap name derived from the SBProxy name.
pub fn configmap_name(sbproxy: &SBProxy) -> String {
    format!(
        "{}-config",
        sbproxy.metadata.name.as_deref().unwrap_or("sbproxy")
    )
}

/// Service name derived from the SBProxy name.
pub fn service_name(sbproxy: &SBProxy) -> String {
    format!(
        "{}-svc",
        sbproxy.metadata.name.as_deref().unwrap_or("sbproxy")
    )
}

/// Build an OwnerReference pointing at the parent `SBProxy`. Setting this on
/// every owned object means a `kubectl delete sbproxy <name>` cascades to the
/// Deployment, Service, and ConfigMap automatically.
fn owner_reference(sbproxy: &SBProxy) -> OwnerReference {
    OwnerReference {
        api_version: SBProxy::api_version(&()).to_string(),
        kind: SBProxy::kind(&()).to_string(),
        name: sbproxy.metadata.name.clone().unwrap_or_default(),
        uid: sbproxy.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Preview-validate an `SBProxyConfig.spec.config` document.
///
/// Parses the YAML into the config schema and runs the static validator
/// (`sbproxy_config::validate`, which checks against the `KNOWN_*_TYPES`
/// tables and needs no runtime module registry). Returns `Ok(())` when the
/// document parses and has no error-severity findings, or a human-readable
/// error string otherwise. The reconciler records this in `status.lastError`
/// and skips the rollout, so a malformed config is caught here instead of
/// crash-looping every replica.
pub fn validate_config_yaml(yaml: &str) -> Result<(), String> {
    let config: sbproxy_config::ConfigFile =
        serde_yaml::from_str(yaml).map_err(|e| format!("config parse error: {e}"))?;
    let findings = sbproxy_config::validate(&config, &sbproxy_config::ValidationOptions::default());
    let errors: Vec<String> = findings
        .iter()
        .filter(|f| f.severity == sbproxy_config::Severity::Error)
        .map(|f| format!("{} ({})", f.message, f.path))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Certificate-store backends that live and die with a single pod.
///
/// `redb` and `sqlite` are embedded files, `memory` is process state, and
/// an omitted `storage_backend` parses as `redb`. `file` is deliberately
/// not on this list: pointing it at an RWX volume is one of the documented
/// ways to share one store across replicas.
const POD_LOCAL_ACME_BACKENDS: [&str; 3] = ["memory", "redb", "sqlite"];

/// Refuse a multi-replica `SBProxy` whose config drives ACME from a
/// pod-local certificate store.
///
/// Two separate things break at `replicas: 2` on a local store, and
/// neither is visible to `sbproxy_config::validate`, because the replica
/// count is not in the `sb.yml` at all. The operator is the only component
/// holding both halves, so the pairing is checked here.
///
/// The first is issuance. Every replica keeps its own store, so every
/// replica opens its own order for the same hostname, and Let's Encrypt
/// caps duplicate certificates for one hostname set at 5 per week. The
/// second is validation. The CA fetches
/// `/.well-known/acme-challenge/<token>` through the Service, which
/// load-balances it across every ready pod. Answering that fetch from any
/// pod is what the shared store buys: the replica driving the order
/// publishes the token to it, and the rest read it back. On separate local
/// stores the fetch usually lands on a pod that never saw the token, and
/// the authorization fails.
///
/// Returns `Ok(())` for a single replica, for a config with no `acme`
/// block or a disabled one, for any shared backend, and for a document
/// that does not parse. That last case belongs to
/// [`validate_config_yaml`], which reports it with the parser's own
/// message; reporting it again here would overwrite a precise error with
/// a vaguer one.
pub fn check_acme_storage_for_replicas(sbproxy: &SBProxy, config_yaml: &str) -> Result<(), String> {
    let replicas = sbproxy.spec.replicas;
    if replicas <= 1 {
        return Ok(());
    }
    let Ok(config) = serde_yaml::from_str::<sbproxy_config::ConfigFile>(config_yaml) else {
        return Ok(());
    };
    let Some(acme) = config.proxy.acme.as_ref().filter(|a| a.enabled) else {
        return Ok(());
    };
    // Serde fills in `redb` when the key is absent, so an empty value can
    // only come from an explicit `storage_backend: ""`. Normalize it to the
    // default rather than waving an unrecognized backend through the guard.
    let backend = match acme.storage_backend.trim() {
        "" => "redb",
        other => other,
    };
    if !POD_LOCAL_ACME_BACKENDS.contains(&backend) {
        return Ok(());
    }
    Err(format!(
        "spec.replicas is {replicas} and proxy.acme.enabled is true with \
         storage_backend \"{backend}\", which is local to one pod. Each replica \
         would open its own order for the same hostname, and an HTTP-01 \
         challenge load-balanced to a replica that did not open it cannot be \
         answered. Use a shared store (file on an RWX volume, redis, s3, gcs, \
         or azure), set spec.replicas to 1, or issue certificates with \
         cert-manager and leave proxy.acme disabled. See docs/kubernetes.md."
    ))
}

// --- WOR-2467: boot fallback is local recovery, not drift ---

/// Condition type stamped on `SBProxy.status.conditions` while any of
/// its pods is serving a configuration its boot fallback restored.
///
/// The name is part of the operator's contract: an alert rule and a
/// `kubectl wait --for=condition=...` both spell it, so it is a constant
/// rather than a string literal at each call site.
pub const FALLBACK_CONDITION_TYPE: &str = "ConfigFallbackActive";

/// What `GET /admin/config/fallback` reports for one pod.
///
/// Deserialized leniently: an older proxy that predates the `reason`
/// field still answers the three fields this needs, and an operator who
/// upgrades the controller first must not have every node read as
/// undecidable.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct FallbackReport {
    /// Whether this pod is serving a config its boot fallback restored.
    #[serde(default)]
    pub active: bool,
    /// Ring revision it fell back to.
    #[serde(default)]
    pub revision: Option<u64>,
    /// That revision's content digest.
    #[serde(default)]
    pub digest: Option<String>,
    /// Why the configured document did not boot.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Longest `reason` this operator will carry out of a pod answer.
///
/// The node bounds its own reason to 512 characters, but the pod is the
/// untrusted end of this call: `resp.json()` reads whatever body
/// arrives, and the value goes straight into a Kubernetes condition
/// message that `kubectl describe` prints raw. Upstream `metav1`
/// bounds a condition message at 32768; this is far under it, and
/// matches what a node that is behaving produces.
const MAX_REPORTED_REASON_CHARS: usize = 512;

impl FallbackReport {
    /// The same report with every operator-carried string bounded to
    /// 512 characters and stripped of control characters.
    ///
    /// Applied at the edge, where the value is read, rather than at the
    /// point it is rendered, so nothing downstream has to remember.
    #[must_use]
    pub fn bounded(self) -> Self {
        Self {
            reason: self.reason.as_deref().map(bounded_reason),
            digest: self.digest.as_deref().map(bounded_reason),
            ..self
        }
    }
}

/// Truncate to 512 characters on a character boundary and replace
/// control characters, which reach a terminal verbatim through
/// `kubectl describe`.
fn bounded_reason(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    match trimmed.char_indices().nth(MAX_REPORTED_REASON_CHARS) {
        Some((cut, _)) => format!("{}...", &trimmed[..cut]),
        None => trimmed.to_string(),
    }
}

/// One pod's answer, with the pod it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodFallback {
    /// Pod name, for the condition message.
    pub pod: String,
    /// What that pod reported.
    pub report: FallbackReport,
}

/// Whether this pod is one the operator's own workload created.
///
/// # Why the label is not enough
///
/// `read_fallback_reports` used to select pods by
/// `app.kubernetes.io/instance=<name>` alone. A label is a value anyone
/// with pod-create in the namespace can type, so any pod answering
/// `{"active":true}` on the admin port halted config delivery for the
/// whole `SBProxy` and was handed the operator's admin credential on
/// every pass. The label answers "who does this claim to belong to";
/// the controller owner reference answers "what actually created it".
///
/// This checks the controller reference names one of the two workloads
/// this operator creates: the StatefulSet by exact name in the
/// clustered shape, or a ReplicaSet whose name is the Deployment's plus
/// the pod-template hash Kubernetes appends.
///
/// # What this cannot see
///
/// It is not proof of provenance and must not be described as one.
/// Kubernetes does not validate `ownerReferences` on create, so a
/// principal who can already create pods in the namespace can write
/// whichever reference they like. What this removes is the accidental
/// case, which is the likely one: a pod that happens to carry the same
/// instance label. Against a hostile principal the real boundary is
/// namespace RBAC, and the write gate this now sits behind bounds how
/// many passes a deposed replica spends probing.
#[must_use]
pub fn pod_is_operator_owned(pod: &Pod, deployment: &str, statefulset: &str) -> bool {
    pod.metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|owner| {
            if owner.controller != Some(true) {
                return false;
            }
            match owner.kind.as_str() {
                "StatefulSet" => owner.name == statefulset,
                // Kubernetes names a Deployment's ReplicaSet
                // `<deployment>-<pod-template-hash>`, so the prefix plus
                // a non-empty suffix is the whole shape available here.
                "ReplicaSet" => owner
                    .name
                    .strip_prefix(deployment)
                    .and_then(|rest| rest.strip_prefix('-'))
                    .is_some_and(|hash| !hash.is_empty()),
                _ => false,
            }
        })
}

/// The pod, if any, whose fallback pin suspends config reconciliation
/// for this `SBProxy`.
///
/// # Why a suspension and not a refusal
///
/// A controller that owns desired state and a node that rescues itself
/// will fight, and the field's answer to that fight is well documented.
/// With Argo CD's `selfHeal` enabled a manual `kubectl rollout undo` is
/// detected as drift and reverted straight back to what Git says; the
/// documented workflow is not to fight it but to suspend reconciliation
/// first (`argocd app set <app> --sync-policy none`), act, then update
/// Git. Argo's own recommended starting posture is `selfHeal: false`,
/// for the same reason this epic ships `auto_revert` off.
///
/// So the answer is a **suspension state the controller reads**, not a
/// refusal the controller cannot see. Refusing auto-revert on the node
/// is necessary and not sufficient: it does nothing about a controller
/// that keeps reapplying the config the node cannot compile.
///
/// # Why the pin and not health
///
/// **Boot fallback is local recovery, not drift.** A node that could not
/// compile its configuration and came up on its last good one has not
/// diverged from desired state on purpose. A controller that reads that
/// as drift reapplies the broken config and restarts the node into the
/// same crash loop, which is the failure this epic exists to prevent,
/// reintroduced one layer up. A pod that is merely unhealthy, with no
/// pin, has said nothing about its configuration and is reconciled
/// normally.
#[must_use]
pub fn fallback_suspension(pods: &[PodFallback]) -> Option<&PodFallback> {
    pods.iter().find(|pod| pod.report.active)
}

/// The `ConfigFallbackActive` condition for `SBProxy.status.conditions`.
///
/// Produced in both directions: an alert fires on `status == "True"`,
/// and the condition has to go back to `"False"` when the node returns
/// to its configured document rather than lingering as a stale `"True"`
/// nobody clears.
///
/// `last_transition_time` is supplied by the caller rather than read
/// from the clock here, so the shape is testable.
#[must_use]
pub fn fallback_condition(
    pods: &[PodFallback],
    observed_generation: Option<i64>,
    now: &str,
    previous: Option<&Condition>,
) -> Condition {
    let pinned = fallback_suspension(pods);
    let (status, reason, message) = match pinned {
        Some(pinned) => (
            "True",
            "NodeOnFallbackConfig",
            format!(
                "pod {} is serving revision {} from its config revision ring, not the \
                 configured document; config reconciliation is suspended for this SBProxy \
                 until the pin is cleared with DELETE /admin/config/fallback. the configured \
                 document failed with: {}",
                pinned.pod,
                pinned
                    .report
                    .revision
                    .map_or_else(|| "unknown".to_string(), |revision| revision.to_string()),
                pinned
                    .report
                    .reason
                    .as_deref()
                    .unwrap_or("no reason reported by the node"),
            ),
        ),
        None => (
            "False",
            "RunningConfiguredDocument",
            "no pod reports a boot fallback pin; config reconciliation is live".to_string(),
        ),
    };
    // The timestamp moves only on a real transition. Restamping it
    // every pass costs two things: the field stops answering "how long
    // has this node been pinned", which is the one question a condition
    // timestamp exists for; and because the value genuinely changes,
    // every pass becomes a real status write that the operator's own
    // watch re-enqueues, so the object never settles to its requeue
    // interval and each self-triggered pass re-runs the credentialed
    // pod fan-out and a full server-side apply.
    let last_transition_time = match previous {
        Some(previous)
            if previous.status == status && !previous.last_transition_time.is_empty() =>
        {
            previous.last_transition_time.clone()
        }
        _ => now.to_string(),
    };
    Condition {
        type_: FALLBACK_CONDITION_TYPE.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time,
        observed_generation,
    }
}

/// The `SBProxy`'s current `ConfigFallbackActive` condition, if it has
/// one.
#[must_use]
pub fn current_fallback_condition(sbproxy: &SBProxy) -> Option<&Condition> {
    sbproxy
        .status
        .as_ref()?
        .conditions
        .iter()
        .find(|condition| condition.type_ == FALLBACK_CONDITION_TYPE)
}

/// The status merge patch that writes `condition`, or `None` when the
/// CR already carries exactly it.
///
/// Returning `None` is the half that keeps the operator from
/// re-triggering its own watch: a patch whose body is identical to what
/// is already stored still bumps `resourceVersion` and still wakes the
/// controller.
#[must_use]
pub fn fallback_condition_patch(
    condition: &Condition,
    previous: Option<&Condition>,
) -> Option<serde_json::Value> {
    if previous == Some(condition) {
        return None;
    }
    // A plain JSON merge patch replaces the whole list. This operator
    // owns the only condition type on this CR, so writing the list
    // whole is correct today; a second type would have to merge into
    // the existing list first.
    Some(serde_json::json!({ "status": { "conditions": [condition] } }))
}

/// Refuse a config that arms node-side auto-revert while this operator
/// owns the document.
///
/// `proxy.config_history.soak.auto_revert` lets a node undo a
/// configuration on its own after a failed soak. Under operator
/// ownership that is a race the node cannot win: the next reconcile
/// reapplies the ConfigMap the node just reverted away from, and the two
/// take turns. Accepting the key and then losing that race is worse than
/// refusing it, and refusing it quietly is worse still, because nothing
/// would tell the operator why their setting did nothing.
///
/// The owner is named in the error, and so is the path that does work.
///
/// Returns `Ok(())` for a document that does not parse, which belongs to
/// [`validate_config_yaml`] and its more precise message.
pub fn check_auto_revert_under_operator_ownership(config_yaml: &str) -> Result<(), String> {
    let Ok(config) = serde_yaml::from_str::<sbproxy_config::ConfigFile>(config_yaml) else {
        return Ok(());
    };
    let Some(history) = config.proxy.config_history.as_ref() else {
        return Ok(());
    };
    if !history.soak.auto_revert {
        return Ok(());
    }
    Err(
        "proxy.config_history.soak.auto_revert is true, but this SBProxy's configuration is \
         owned by the sbproxy Kubernetes operator, which reapplies the ConfigMap on every \
         reconcile. A node that reverts its own config loses that race, and the two take \
         turns. Set it to false and roll back through the control plane instead: \
         `sbproxy config authority rollback --to-revision N` for a fleet, or \
         `POST /admin/config/rollback` on a node this operator does not own. See \
         docs/config-rollback.md."
            .to_string(),
    )
}

// --- Status patches ---
//
// The `SBProxy` status carries two hashes because a reconcile pass has two
// interesting moments and operators ask about both. Keeping the two patch
// bodies here, named for the moment each belongs to, is what stops the
// "rolled out" claim from drifting back to the top of the pass: the early
// call site has no way to spell `configHash`.

/// Status patch for the point in the pass where the config has been read,
/// rendered, and validated, and nothing has been applied yet.
///
/// Deliberately does not carry `configHash` and does not clear `lastError`.
/// Both are documented as end-of-rollout signals: an operator who sees
/// `configHash: H1` with an empty `lastError` reads that as "the pods are on
/// H1". Writing them here made a 403 on the very next ConfigMap patch report
/// a completed rollout while every pod kept serving the previous config.
pub fn observed_status_patch(config_hash: &str) -> serde_json::Value {
    serde_json::json!({ "status": { "observedConfigHash": config_hash } })
}

/// Status patch for the point where the ConfigMap, Service, and workload have
/// all been applied, or every pod has accepted a hot reload.
///
/// This is the only producer of `configHash`, and the only place `lastError`
/// is cleared.
pub fn rolled_out_status_patch(config_hash: &str) -> serde_json::Value {
    serde_json::json!({ "status": { "configHash": config_hash, "lastError": "" } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{SBProxyConfigSpec, SBProxySpec};
    use kube::api::ObjectMeta;

    fn fixture_sbproxy() -> SBProxy {
        SBProxy {
            metadata: ObjectMeta {
                name: Some("demo".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("00000000-0000-0000-0000-000000000001".to_string()),
                ..Default::default()
            },
            spec: SBProxySpec {
                replicas: 2,
                image: "ghcr.io/soapbucket/sbproxy:0.1.0".to_string(),
                config_ref: "demo-config".to_string(),
                resources: None,
                port: 8080,
                admin_auth_secret_ref: None,
                admin_port: 9090,
                clustering: None,
            },
            status: None,
        }
    }

    fn fixture_clustered_sbproxy() -> SBProxy {
        let mut sbp = fixture_sbproxy();
        sbp.spec.replicas = 3;
        sbp.spec.clustering = Some(crate::crd::ClusteringSpec {
            enabled: true,
            gossip_port: 7946,
            transport_port: 8946,
            cluster_secret_ref: None,
            cluster_domain: "cluster.local".to_string(),
        });
        sbp
    }

    fn fixture_sbproxyconfig() -> SBProxyConfig {
        SBProxyConfig {
            metadata: ObjectMeta {
                name: Some("demo-config".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: SBProxyConfigSpec {
                // Map-form origins: the schema `origins` is a
                // hostname-keyed map, and the proxy rejects the
                // Go-era list form this fixture used to carry.
                config: "origins:\n  \"example.com\":\n    action:\n      type: proxy\n      url: https://example.org\n"
                    .to_string(),
            },
        }
    }

    #[test]
    fn validate_config_yaml_accepts_minimal_config() {
        // An empty origins map is a well-formed config with no findings.
        assert!(validate_config_yaml("origins: {}\n").is_ok());
    }

    #[test]
    fn validate_config_yaml_rejects_malformed_yaml() {
        // WOR-611: a parse failure is reported (and the reconciler records it
        // in status) instead of crash-looping every pod.
        let err = validate_config_yaml("origins:\n  example.com: [unterminated")
            .expect_err("malformed YAML must be rejected");
        assert!(err.contains("parse error"), "unexpected error: {err}");
    }

    #[test]
    fn config_hash_is_stable_and_change_sensitive() {
        let h1 = config_hash("foo");
        let h2 = config_hash("foo");
        let h3 = config_hash("bar");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn desired_configmap_carries_owner_and_data() {
        let sbp = fixture_sbproxy();
        let cfg = fixture_sbproxyconfig();
        let cm = desired_configmap(&sbp, &cfg);

        assert_eq!(cm.metadata.name.as_deref(), Some("demo-config"));
        assert_eq!(cm.metadata.namespace.as_deref(), Some("default"));
        let data = cm.data.as_ref().expect("data populated");
        assert_eq!(data.get("sb.yml"), Some(&cfg.spec.config));
        let owners = cm.metadata.owner_references.as_ref().expect("owners");
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].name, "demo");
        assert_eq!(owners[0].controller, Some(true));
    }

    #[test]
    fn desired_service_targets_correct_port() {
        let sbp = fixture_sbproxy();
        let svc = desired_service(&sbp);
        let spec = svc.spec.expect("svc spec");
        let ports = spec.ports.expect("ports");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[0].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn desired_deployment_stamps_config_hash() {
        let sbp = fixture_sbproxy();
        let hash = config_hash("any body");
        let deploy = desired_deployment(&sbp, &hash);
        let template = deploy.spec.expect("deploy spec").template;
        let meta = template.metadata.expect("template meta");
        let annotations = meta.annotations.expect("annotations");
        assert_eq!(annotations.get(CONFIG_HASH_ANNOTATION), Some(&hash));
    }

    #[test]
    fn desired_deployment_replicas_match_spec() {
        let sbp = fixture_sbproxy();
        let deploy = desired_deployment(&sbp, "deadbeef");
        assert_eq!(deploy.spec.unwrap().replicas, Some(2));
    }

    fn fixture_sbproxy_with_admin_auth() -> SBProxy {
        let mut sbp = fixture_sbproxy();
        sbp.spec.admin_auth_secret_ref = Some(crate::crd::AdminAuthSecretRef {
            name: "demo-admin".to_string(),
            key: "authorization".to_string(),
        });
        sbp.spec.admin_port = 9090;
        sbp
    }

    fn fixture_clustered_sbproxy_with_admin_auth() -> SBProxy {
        let mut sbp = fixture_clustered_sbproxy();
        sbp.spec.admin_auth_secret_ref = Some(crate::crd::AdminAuthSecretRef {
            name: "demo-admin".to_string(),
            key: "authorization".to_string(),
        });
        sbp.spec.admin_port = 9090;
        sbp
    }

    #[test]
    fn should_hot_reload_false_without_admin_auth() {
        let sbp = fixture_sbproxy(); // no admin_auth_secret_ref
        let desired = desired_deployment(&sbp, "new-hash");
        let existing = desired_deployment(&sbp, "old-hash");
        assert!(!should_hot_reload(
            &sbp,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));
    }

    #[test]
    fn should_hot_reload_false_on_first_apply() {
        let sbp = fixture_sbproxy_with_admin_auth();
        let desired = desired_deployment(&sbp, "new-hash");
        // existing_deploy is None => first apply must rollout, not hot-reload.
        assert!(!should_hot_reload(&sbp, None, &desired, None, "new-hash"));
    }

    #[test]
    fn should_hot_reload_false_when_image_changes() {
        let mut sbp_old = fixture_sbproxy_with_admin_auth();
        sbp_old.spec.image = "ghcr.io/soapbucket/sbproxy:0.1.0".to_string();
        let existing = desired_deployment(&sbp_old, "old-hash");

        let mut sbp_new = fixture_sbproxy_with_admin_auth();
        sbp_new.spec.image = "ghcr.io/soapbucket/sbproxy:0.2.0".to_string();
        let desired = desired_deployment(&sbp_new, "new-hash");

        assert!(!should_hot_reload(
            &sbp_new,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));
    }

    #[test]
    fn should_hot_reload_false_when_replicas_change() {
        let mut sbp_old = fixture_sbproxy_with_admin_auth();
        sbp_old.spec.replicas = 2;
        let existing = desired_deployment(&sbp_old, "old-hash");

        let mut sbp_new = fixture_sbproxy_with_admin_auth();
        sbp_new.spec.replicas = 5;
        let desired = desired_deployment(&sbp_new, "new-hash");

        assert!(!should_hot_reload(
            &sbp_new,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));
    }

    #[test]
    fn should_hot_reload_true_when_only_config_changes() {
        let sbp = fixture_sbproxy_with_admin_auth();
        let existing = desired_deployment(&sbp, "old-hash");
        let desired = desired_deployment(&sbp, "new-hash");

        assert!(should_hot_reload(
            &sbp,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));
    }

    #[test]
    fn should_hot_reload_false_when_config_unchanged() {
        let sbp = fixture_sbproxy_with_admin_auth();
        let existing = desired_deployment(&sbp, "same-hash");
        let desired = desired_deployment(&sbp, "same-hash");

        assert!(!should_hot_reload(
            &sbp,
            Some(&existing),
            &desired,
            Some("same-hash"),
            "same-hash"
        ));
    }

    // --- Hot-reload idempotence ---

    /// The status a pass leaves behind once it has finished delivering a
    /// config by either route: `observedConfigHash` from the pre-apply write
    /// and `configHash` from the post-apply one.
    fn delivered(sbp: &SBProxy, config_hash: &str) -> SBProxy {
        let mut sbp = sbp.clone();
        sbp.status = Some(SBProxyStatus {
            config_hash: config_hash.to_string(),
            // Written first on every pass that reaches the rolled-out patch,
            // so a real CR never carries one without the other.
            observed_config_hash: config_hash.to_string(),
            ..Default::default()
        });
        sbp
    }

    /// The status shape an operator build that predates `observedConfigHash`
    /// left behind: `configHash` stamped straight after validation, so it
    /// says "seen", not "delivered".
    fn seen_by_a_pre_upgrade_operator(sbp: &SBProxy, config_hash: &str) -> SBProxy {
        let mut sbp = sbp.clone();
        sbp.status = Some(SBProxyStatus {
            config_hash: config_hash.to_string(),
            ..Default::default()
        });
        sbp
    }

    #[test]
    fn the_pass_after_a_hot_reload_does_not_reload_the_fleet_again() {
        // The wiring this fixes, spelled out. Pass 1 hot-reloaded H0 -> H1
        // and deliberately skipped the Deployment patch, because advancing
        // the pod template is the rolling restart the reload existed to
        // avoid. So the template still reads H0 and always will.
        let sbp = fixture_sbproxy_with_admin_auth();
        let existing = desired_deployment(&sbp, "H0");
        let template_hash = previous_config_hash(&existing);
        assert_eq!(template_hash.as_deref(), Some("H0"));

        // Pass 2, 300 seconds later, with nothing changed.
        let sbp = delivered(&sbp, "H1");
        let running = running_config_hash(&sbp);
        let desired = desired_deployment(
            &sbp,
            rollout_config_hash(template_hash.as_deref(), running, "H1"),
        );

        // The old caller passed the pod-template annotation here. It is
        // permanently H0 on this path, so gate 4 was permanently true and
        // every requeue and every watch event reloaded the whole fleet
        // again, rebuilding each handler chain and dropping warmed state.
        let gated_on_template = should_hot_reload(
            &sbp,
            Some(&existing),
            &desired,
            template_hash.as_deref(),
            "H1",
        );
        assert!(
            gated_on_template,
            "the pod-template annotation is exactly the value that can never \
             advance on the hot-reload path"
        );

        // Reading what was actually delivered makes the pass idempotent.
        assert!(
            !should_hot_reload(&sbp, Some(&existing), &desired, running, "H1"),
            "a second identical pass must do no work"
        );

        // And the apply that follows must not roll the pods either: the pod
        // template it sends has to be byte-identical to the live one.
        assert_eq!(
            serde_json::to_value(&existing).unwrap()["spec"]["template"],
            serde_json::to_value(&desired).unwrap()["spec"]["template"],
            "re-stamping the current hash would restart the fleet for a \
             config it is already running"
        );
    }

    #[test]
    fn a_further_config_edit_after_a_hot_reload_still_reloads() {
        // The fix must not turn into "never reload again". H1 was delivered;
        // the user edits the config to H2.
        let sbp = delivered(&fixture_sbproxy_with_admin_auth(), "H1");
        let existing = desired_deployment(&sbp, "H0");
        let running = running_config_hash(&sbp);
        let desired = desired_deployment(
            &sbp,
            rollout_config_hash(previous_config_hash(&existing).as_deref(), running, "H2"),
        );
        assert!(should_hot_reload(
            &sbp,
            Some(&existing),
            &desired,
            running,
            "H2"
        ));
    }

    #[test]
    fn a_config_the_pods_have_not_been_given_still_rolls_them() {
        // Nothing delivered yet, or a hot reload that failed: the template
        // hash moves, which is what the rolling restart is triggered by.
        assert_eq!(rollout_config_hash(Some("H0"), None, "H1"), "H1");
        assert_eq!(rollout_config_hash(Some("H0"), Some("H0"), "H1"), "H1");
        assert_eq!(rollout_config_hash(None, None, "H1"), "H1");
        // Delivered by a hot reload: hold the template still.
        assert_eq!(rollout_config_hash(Some("H0"), Some("H1"), "H1"), "H0");
        // No template to hold onto (a first apply) uses the new hash even
        // when status claims delivery, so the annotation is never absent.
        assert_eq!(rollout_config_hash(None, Some("H1"), "H1"), "H1");
    }

    #[test]
    fn running_config_hash_ignores_an_empty_status_field() {
        let sbp = fixture_sbproxy_with_admin_auth();
        assert_eq!(running_config_hash(&sbp), None, "no status at all");
        // `configHash` is `skip_serializing_if = "String::is_empty"`, so a CR
        // that has a status for `lastError` alone deserializes to an empty
        // string here. Treating that as a delivered hash would compare a
        // real hash against "" and reload forever.
        assert_eq!(running_config_hash(&delivered(&sbp, "")), None);
        assert_eq!(running_config_hash(&delivered(&sbp, "H1")), Some("H1"));
    }

    #[test]
    fn a_config_hash_written_before_the_field_meant_delivered_is_not_trusted() {
        // The upgrade hazard. The previous operator stamped `configHash`
        // straight after validation, so a CR whose last pre-upgrade pass
        // then failed its ConfigMap apply carries a hash the pods never
        // received. Read as delivered, gate 4 goes false and
        // `rollout_config_hash` pins the pod template where it is, so the
        // apply is a no-op and the fleet stays on the old config while
        // `kubectl get sbproxy` reads healthy: `configHash` set, no
        // `lastError`. Nothing short of a pod restart moves it.
        let sbp = seen_by_a_pre_upgrade_operator(&fixture_sbproxy_with_admin_auth(), "H1");
        assert_eq!(
            running_config_hash(&sbp),
            None,
            "a hash with no observedConfigHash beside it was written under the \
             old meaning and says nothing about what the pods have"
        );

        let existing = desired_deployment(&sbp, "H0");
        let template_hash = previous_config_hash(&existing);
        let running = running_config_hash(&sbp);
        let desired = desired_deployment(
            &sbp,
            rollout_config_hash(template_hash.as_deref(), running, "H1"),
        );
        assert!(
            should_hot_reload(&sbp, Some(&existing), &desired, running, "H1"),
            "the first pass after the upgrade has to deliver H1 rather than \
             assume it already landed"
        );
        // And if the reload cannot run, the template moves and the pods roll.
        assert_eq!(
            rollout_config_hash(template_hash.as_deref(), running, "H1"),
            "H1"
        );
    }

    #[test]
    fn the_clustered_path_is_idempotent_the_same_way() {
        let sbp = fixture_clustered_sbproxy_with_admin_auth();
        let existing = desired_statefulset(&sbp, "H0");
        let template_hash = previous_config_hash_statefulset(&existing);

        let sbp = delivered(&sbp, "H1");
        let running = running_config_hash(&sbp);
        let desired = desired_statefulset(
            &sbp,
            rollout_config_hash(template_hash.as_deref(), running, "H1"),
        );

        let gated_on_template = should_hot_reload_statefulset(
            &sbp,
            Some(&existing),
            &desired,
            template_hash.as_deref(),
            "H1",
        );
        assert!(
            gated_on_template,
            "same defect, same shape, on the StatefulSet path"
        );
        assert!(!should_hot_reload_statefulset(
            &sbp,
            Some(&existing),
            &desired,
            running,
            "H1"
        ));
        assert_eq!(
            serde_json::to_value(&existing).unwrap()["spec"]["template"],
            serde_json::to_value(&desired).unwrap()["spec"]["template"]
        );
    }

    #[test]
    fn previous_config_hash_reads_annotation() {
        let sbp = fixture_sbproxy();
        let deploy = desired_deployment(&sbp, "abcdef");
        assert_eq!(previous_config_hash(&deploy).as_deref(), Some("abcdef"));
    }

    // --- Clustered (mesh) reconciliation ---

    #[test]
    fn clustering_disabled_produces_exactly_todays_objects() {
        // The desired objects for a clustering-free SBProxy and for one
        // with an explicit `enabled: false` block must be identical to
        // each other: the clustered path must not leak into the plain
        // Deployment path in any form.
        let plain = fixture_sbproxy();
        let mut disabled = fixture_sbproxy();
        disabled.spec.clustering = Some(crate::crd::ClusteringSpec {
            enabled: false,
            gossip_port: 7946,
            transport_port: 8946,
            cluster_secret_ref: None,
            cluster_domain: "cluster.local".to_string(),
        });

        assert!(!clustering_enabled(&plain));
        assert!(!clustering_enabled(&disabled));

        let cfg = fixture_sbproxyconfig();
        let hash = config_hash(&cfg.spec.config);
        assert_eq!(
            serde_json::to_value(desired_deployment(&plain, &hash)).unwrap(),
            serde_json::to_value(desired_deployment(&disabled, &hash)).unwrap()
        );
        assert_eq!(
            serde_json::to_value(desired_service(&plain)).unwrap(),
            serde_json::to_value(desired_service(&disabled)).unwrap()
        );
        assert_eq!(
            serde_json::to_value(desired_configmap(&plain, &cfg)).unwrap(),
            serde_json::to_value(desired_configmap(&disabled, &cfg)).unwrap()
        );

        // The non-clustered ConfigMap carries the user document verbatim.
        let cm = desired_configmap(&plain, &cfg);
        assert_eq!(
            cm.data.unwrap().get("sb.yml"),
            Some(&cfg.spec.config),
            "non-clustered sb.yml must be byte-identical to the user document"
        );
    }

    #[test]
    fn render_clustered_config_injects_expected_cluster_block() {
        let sbp = fixture_clustered_sbproxy();
        let cfg = fixture_sbproxyconfig();
        let rendered = render_clustered_config(&sbp, &cfg.spec.config).expect("render");

        // Identity comes from the pod name via the downward API.
        assert!(rendered.contains("cluster_id: demo"), "{rendered}");
        assert!(rendered.contains("${SBPROXY_POD_NAME}"), "{rendered}");

        // One stable DNS seed per ordinal, replicas = 3.
        for ordinal in 0..3 {
            let seed = format!("demo-proxy-{ordinal}.demo-mesh.default.svc.cluster.local:7946");
            assert!(
                rendered.contains(&seed),
                "missing seed {seed} in {rendered}"
            );
        }
        assert!(
            !rendered.contains("demo-proxy-3."),
            "must not seed beyond the replica count: {rendered}"
        );

        // Ports, state dir, and shared-key security.
        assert!(rendered.contains("gossip_port: 7946"), "{rendered}");
        assert!(rendered.contains("transport_port: 8946"), "{rendered}");
        assert!(rendered.contains("state_dir:"), "{rendered}");
        assert!(rendered.contains("/var/lib/sbproxy/cluster"), "{rendered}");
        assert!(rendered.contains("mode: shared_key"), "{rendered}");
        assert!(rendered.contains("development: true"), "{rendered}");
        assert!(rendered.contains("env:SBPROXY_CLUSTER_KEY"), "{rendered}");

        // The user's origins survive the injection.
        assert!(rendered.contains("example.com"), "{rendered}");
    }

    #[test]
    fn render_clustered_config_replaces_user_cluster_block() {
        let sbp = fixture_clustered_sbproxy();
        let user = "proxy:\n  cluster:\n    cluster_id: hand-rolled\n    security:\n      mode: shared_key\norigins: {}\n";
        let rendered = render_clustered_config(&sbp, user).expect("render");
        assert!(
            !rendered.contains("hand-rolled"),
            "user-supplied proxy.cluster must be replaced: {rendered}"
        );
        assert!(rendered.contains("cluster_id: demo"), "{rendered}");
    }

    #[test]
    fn render_clustered_config_rejects_out_of_range_ports() {
        let mut sbp = fixture_clustered_sbproxy();
        sbp.spec.clustering.as_mut().unwrap().gossip_port = 99_999;
        let err = render_clustered_config(&sbp, "origins: {}\n")
            .expect_err("out-of-range port must be rejected");
        assert!(err.contains("gossipPort"), "unexpected error: {err}");

        let mut sbp = fixture_clustered_sbproxy();
        sbp.spec.clustering.as_mut().unwrap().transport_port = 7946;
        let err = render_clustered_config(&sbp, "origins: {}\n")
            .expect_err("colliding ports must be rejected");
        assert!(err.contains("must differ"), "unexpected error: {err}");
    }

    #[test]
    fn desired_headless_service_is_headless_with_both_ports() {
        let sbp = fixture_clustered_sbproxy();
        let svc = desired_headless_service(&sbp);
        assert_eq!(svc.metadata.name.as_deref(), Some("demo-mesh"));
        let spec = svc.spec.expect("svc spec");
        assert_eq!(spec.cluster_ip.as_deref(), Some("None"));
        assert_eq!(spec.publish_not_ready_addresses, Some(true));
        let ports = spec.ports.expect("ports");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].name.as_deref(), Some("gossip"));
        assert_eq!(ports[0].port, 7946);
        assert_eq!(ports[0].protocol.as_deref(), Some("UDP"));
        assert_eq!(ports[1].name.as_deref(), Some("mesh"));
        assert_eq!(ports[1].port, 8946);
        assert_eq!(ports[1].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn desired_statefulset_wires_identity_and_roll_gating() {
        let sbp = fixture_clustered_sbproxy();
        let hash = config_hash("body");
        let sts = desired_statefulset(&sbp, &hash);

        assert_eq!(sts.metadata.name.as_deref(), Some("demo-proxy"));
        let spec = sts.spec.expect("sts spec");
        assert_eq!(spec.replicas, Some(3));
        assert_eq!(spec.service_name, "demo-mesh");
        assert_eq!(spec.pod_management_policy.as_deref(), Some("OrderedReady"));
        assert_eq!(
            spec.update_strategy
                .as_ref()
                .and_then(|s| s.type_.as_deref()),
            Some("RollingUpdate")
        );

        let template_meta = spec.template.metadata.as_ref().expect("template meta");
        assert_eq!(
            template_meta
                .annotations
                .as_ref()
                .and_then(|a| a.get(CONFIG_HASH_ANNOTATION)),
            Some(&hash)
        );

        let pod = spec.template.spec.as_ref().expect("pod spec");
        let container = pod.containers.first().expect("container");

        let env = container.env.as_ref().expect("env");
        let pod_name = env
            .iter()
            .find(|e| e.name == POD_NAME_ENV)
            .expect("pod name env");
        assert_eq!(
            pod_name
                .value_from
                .as_ref()
                .and_then(|v| v.field_ref.as_ref())
                .map(|f| f.field_path.as_str()),
            Some("metadata.name")
        );
        let key = env
            .iter()
            .find(|e| e.name == CLUSTER_KEY_ENV)
            .expect("cluster key env");
        let key_ref = key
            .value_from
            .as_ref()
            .and_then(|v| v.secret_key_ref.as_ref())
            .expect("secret key ref");
        assert_eq!(key_ref.name, "demo-cluster-key");
        assert_eq!(key_ref.key, CLUSTER_KEY_SECRET_KEY);

        // Readiness gates the roll; both probes hit the data plane.
        let readiness = container.readiness_probe.as_ref().expect("readiness");
        assert_eq!(
            readiness.http_get.as_ref().and_then(|h| h.path.as_deref()),
            Some("/health")
        );
        assert!(container.liveness_probe.is_some());

        // Config plus writable cluster state.
        let mounts = container.volume_mounts.as_ref().expect("mounts");
        assert!(mounts
            .iter()
            .any(|m| m.mount_path == CLUSTER_STATE_MOUNT_PATH));
        let volumes = pod.volumes.as_ref().expect("volumes");
        assert!(volumes.iter().any(|v| v.empty_dir.is_some()));
        assert!(volumes.iter().any(|v| v.config_map.is_some()));
    }

    #[test]
    fn cluster_secret_generated_when_absent_and_reused_when_present() {
        let sbp = fixture_clustered_sbproxy();

        // Absent: the operator must generate one.
        assert!(needs_generated_cluster_secret(&sbp, None));

        // Present: never regenerate, so rescheduled pods keep the key.
        let existing = desired_cluster_secret(&sbp, "0123456789abcdef0123456789abcdef");
        assert!(!needs_generated_cluster_secret(&sbp, Some(&existing)));

        // User-referenced: the operator never creates anything.
        let mut user_ref = fixture_clustered_sbproxy();
        user_ref
            .spec
            .clustering
            .as_mut()
            .unwrap()
            .cluster_secret_ref = Some("my-own-key".to_string());
        assert!(!needs_generated_cluster_secret(&user_ref, None));
        assert_eq!(cluster_secret_name(&user_ref), "my-own-key");

        // Generated Secret shape.
        assert_eq!(existing.metadata.name.as_deref(), Some("demo-cluster-key"));
        let owners = existing.metadata.owner_references.as_ref().expect("owners");
        assert_eq!(owners[0].name, "demo");
        assert_eq!(
            existing
                .string_data
                .as_ref()
                .and_then(|d| d.get(CLUSTER_KEY_SECRET_KEY))
                .map(String::as_str),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn generate_cluster_key_is_hex_and_unique() {
        let a = generate_cluster_key();
        let b = generate_cluster_key();
        assert_eq!(a.len(), 64, "32 bytes hex-encoded");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two generated keys must differ");
    }

    #[test]
    fn statefulset_drift_comparison_detects_operator_owned_changes() {
        let sbp = fixture_clustered_sbproxy();

        // Identical except config hash: matches.
        let existing = desired_statefulset(&sbp, "old-hash");
        let desired = desired_statefulset(&sbp, "new-hash");
        assert!(statefulset_spec_matches_except_config_hash(
            &existing, &desired
        ));

        // Image drift.
        let mut changed = fixture_clustered_sbproxy();
        changed.spec.image = "ghcr.io/soapbucket/sbproxy:0.2.0".to_string();
        assert!(!statefulset_spec_matches_except_config_hash(
            &existing,
            &desired_statefulset(&changed, "new-hash")
        ));

        // Replica drift.
        let mut changed = fixture_clustered_sbproxy();
        changed.spec.replicas = 5;
        assert!(!statefulset_spec_matches_except_config_hash(
            &existing,
            &desired_statefulset(&changed, "new-hash")
        ));

        // Env drift (secret reference changed).
        let mut changed = fixture_clustered_sbproxy();
        changed.spec.clustering.as_mut().unwrap().cluster_secret_ref =
            Some("other-key".to_string());
        assert!(!statefulset_spec_matches_except_config_hash(
            &existing,
            &desired_statefulset(&changed, "new-hash")
        ));
    }

    #[test]
    fn should_hot_reload_statefulset_mirrors_deployment_gates() {
        let mut sbp = fixture_clustered_sbproxy();
        sbp.spec.admin_auth_secret_ref = Some(crate::crd::AdminAuthSecretRef {
            name: "demo-admin".to_string(),
            key: "authorization".to_string(),
        });
        let existing = desired_statefulset(&sbp, "old-hash");
        let desired = desired_statefulset(&sbp, "new-hash");

        // Config-only change with admin auth: hot-reload.
        assert!(should_hot_reload_statefulset(
            &sbp,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));

        // First apply: rollout.
        assert!(!should_hot_reload_statefulset(
            &sbp, None, &desired, None, "new-hash"
        ));

        // No admin auth: rollout.
        let plain = fixture_clustered_sbproxy();
        assert!(!should_hot_reload_statefulset(
            &plain,
            Some(&existing),
            &desired,
            Some("old-hash"),
            "new-hash"
        ));

        // Unchanged config: nothing to reload.
        assert!(!should_hot_reload_statefulset(
            &sbp,
            Some(&existing),
            &desired_statefulset(&sbp, "old-hash"),
            Some("old-hash"),
            "old-hash"
        ));
    }

    #[test]
    fn previous_config_hash_statefulset_reads_annotation() {
        let sbp = fixture_clustered_sbproxy();
        let sts = desired_statefulset(&sbp, "abcdef");
        assert_eq!(
            previous_config_hash_statefulset(&sts).as_deref(),
            Some("abcdef")
        );
    }

    // --- ACME on a multi-replica fleet ---

    /// An `sb.yml` that enables ACME on the named certificate-store backend.
    fn acme_config_yaml(backend: &str) -> String {
        format!(
            "proxy:\n  acme:\n    enabled: true\n    email: ops@example.com\n    storage_backend: {backend}\norigins: {{}}\n"
        )
    }

    #[test]
    fn multi_replica_local_acme_store_is_refused() {
        let sbp = fixture_sbproxy();
        assert_eq!(sbp.spec.replicas, 2, "fixture is a two-replica fleet");

        for backend in ["redb", "sqlite", "memory"] {
            let err = check_acme_storage_for_replicas(&sbp, &acme_config_yaml(backend))
                .expect_err("a pod-local cert store must be refused above one replica");
            assert!(
                err.contains("spec.replicas is 2"),
                "unexpected error: {err}"
            );
            assert!(err.contains(backend), "unexpected error: {err}");
            assert!(
                err.contains("cert-manager"),
                "the refusal must name the recommended way out: {err}"
            );
        }

        // An omitted storage_backend parses as redb, so it is refused too.
        let omitted =
            "proxy:\n  acme:\n    enabled: true\n    email: ops@example.com\norigins: {}\n";
        let err = check_acme_storage_for_replicas(&sbp, omitted)
            .expect_err("an omitted storage_backend defaults to redb and must be refused");
        assert!(err.contains("redb"), "unexpected error: {err}");
    }

    #[test]
    fn multi_replica_shared_acme_store_reconciles() {
        let sbp = fixture_sbproxy();
        for backend in ["file", "redis", "s3", "gcs", "azure"] {
            assert!(
                check_acme_storage_for_replicas(&sbp, &acme_config_yaml(backend)).is_ok(),
                "{backend} is reachable from every replica and must reconcile"
            );
        }
    }

    #[test]
    fn single_replica_local_acme_store_reconciles() {
        // One replica is the case dataplane ACME is built for: nothing to
        // coordinate, so a local store is the right answer.
        let mut sbp = fixture_sbproxy();
        sbp.spec.replicas = 1;
        assert!(check_acme_storage_for_replicas(&sbp, &acme_config_yaml("redb")).is_ok());

        // Scaled to zero is not a fleet either.
        sbp.spec.replicas = 0;
        assert!(check_acme_storage_for_replicas(&sbp, &acme_config_yaml("redb")).is_ok());
    }

    #[test]
    fn multi_replica_without_acme_is_untouched() {
        // The guard must not refuse what already runs: a config with no
        // acme block, or one that is present but disabled.
        let sbp = fixture_sbproxy();
        let cfg = fixture_sbproxyconfig();
        assert!(check_acme_storage_for_replicas(&sbp, &cfg.spec.config).is_ok());

        let disabled =
            "proxy:\n  acme:\n    enabled: false\n    storage_backend: redb\norigins: {}\n";
        assert!(check_acme_storage_for_replicas(&sbp, disabled).is_ok());

        // A document that does not parse belongs to validate_config_yaml,
        // which reports it with the parser's own message.
        assert!(check_acme_storage_for_replicas(&sbp, "origins:\n  x: [unterminated").is_ok());
    }

    // --- Status patches ---

    #[test]
    fn the_pre_apply_status_patch_cannot_claim_a_rollout() {
        // The failure this prevents: validation passes, the ConfigMap apply
        // then 403s, and `kubectl get sbproxy demo -o yaml` shows
        // `configHash: H1` with an empty `lastError`, which the CRD documents
        // as "the rollout happened". The pods are still on H0.
        let patch = observed_status_patch("H1");
        let status = patch.get("status").expect("a status patch");

        assert_eq!(
            status.get("observedConfigHash").and_then(|v| v.as_str()),
            Some("H1"),
            "the pre-apply write says the operator has seen H1"
        );
        assert!(
            status.get("configHash").is_none(),
            "configHash is the rolled-out signal and must not be written before \
             anything is applied"
        );
        assert!(
            status.get("lastError").is_none(),
            "a merge patch with lastError: \"\" clears a real error before the \
             pass that would have fixed it has run"
        );
    }

    #[test]
    fn the_post_apply_status_patch_stamps_the_hash_and_clears_the_error() {
        let patch = rolled_out_status_patch("H1");
        let status = patch.get("status").expect("a status patch");

        assert_eq!(
            status.get("configHash").and_then(|v| v.as_str()),
            Some("H1")
        );
        assert_eq!(status.get("lastError").and_then(|v| v.as_str()), Some(""));
        assert!(
            status.get("observedConfigHash").is_none(),
            "the pre-apply write already recorded it; re-writing it here would \
             hide a pass that stamped one and not the other"
        );
    }

    // --- WOR-2467: the fallback pin suspends config delivery ---

    fn pod_on_fallback(name: &str) -> PodFallback {
        PodFallback {
            pod: name.to_string(),
            report: FallbackReport {
                active: true,
                revision: Some(7),
                digest: Some("sha256:abc".to_string()),
                reason: Some("unknown action type: statik".to_string()),
            },
        }
    }

    fn healthy_pod(name: &str) -> PodFallback {
        PodFallback {
            pod: name.to_string(),
            report: FallbackReport::default(),
        }
    }

    #[test]
    fn a_pinned_pod_suspends_config_delivery_and_an_unpinned_one_does_not() {
        assert!(fallback_suspension(&[]).is_none(), "no pods, no suspension");
        assert!(
            fallback_suspension(&[healthy_pod("a"), healthy_pod("b")]).is_none(),
            "pods that report no pin are reconciled normally",
        );
        let mixed = [healthy_pod("a"), pod_on_fallback("b")];
        let pinned =
            fallback_suspension(&mixed).expect("one pinned pod suspends the whole SBProxy");
        assert_eq!(pinned.pod, "b");
    }

    /// The suspension is keyed on the pin, never on health. A pod that is
    /// merely unhealthy has said nothing about its configuration, and
    /// freezing config delivery for it would mean an unreachable replica
    /// could stop a fix from reaching the healthy ones.
    #[test]
    fn an_unhealthy_pod_with_no_pin_is_reconciled_normally() {
        let merely_broken = PodFallback {
            pod: "crashlooping".to_string(),
            report: FallbackReport {
                active: false,
                revision: Some(3),
                digest: Some("sha256:def".to_string()),
                reason: None,
            },
        };
        assert!(
            fallback_suspension(&[merely_broken]).is_none(),
            "a revision in the report is not a pin; only `active` is",
        );
    }

    #[test]
    fn the_condition_names_the_fallback_revision_and_the_compile_failure() {
        let condition = fallback_condition(
            &[pod_on_fallback("edge-0")],
            Some(4),
            "2026-08-28T00:00:00Z",
            None,
        );
        assert_eq!(condition.type_, FALLBACK_CONDITION_TYPE);
        assert_eq!(condition.status, "True");
        assert_eq!(condition.reason, "NodeOnFallbackConfig");
        assert_eq!(condition.observed_generation, Some(4));
        assert_eq!(condition.last_transition_time, "2026-08-28T00:00:00Z");
        let message = condition.message.as_str();
        assert!(message.contains("edge-0"), "{message}");
        assert!(message.contains("revision 7"), "{message}");
        assert!(
            message.contains("unknown action type: statik"),
            "the condition has to say why the configured document failed: {message}",
        );
        assert!(
            message.contains("DELETE /admin/config/fallback"),
            "and how to resume: {message}",
        );
    }

    /// A condition that only ever went True would leave every CR that had
    /// one bad boot looking permanently broken, and an alert on it firing
    /// forever.
    #[test]
    fn the_condition_clears_when_no_pod_reports_a_pin() {
        let condition =
            fallback_condition(&[healthy_pod("edge-0")], None, "2026-08-28T00:00:00Z", None);
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "RunningConfiguredDocument");
        assert_eq!(
            condition.observed_generation, None,
            "a CR with no generation gets no observedGeneration rather than a zero",
        );

        // The same shape with no pods at all: a first pass before any pod
        // exists must not read as "on fallback".
        assert_eq!(
            fallback_condition(&[], None, "2026-08-28T00:00:00Z", None).status,
            "False",
        );
    }

    #[test]
    fn a_node_missing_its_reason_still_gets_a_condition_that_names_the_pod() {
        let bare = PodFallback {
            pod: "edge-9".to_string(),
            report: FallbackReport {
                active: true,
                revision: None,
                digest: None,
                reason: None,
            },
        };
        let message = fallback_condition(&[bare], None, "2026-08-28T00:00:00Z", None).message;
        assert!(message.contains("edge-9"), "{message}");
        assert!(message.contains("revision unknown"), "{message}");
        assert!(
            message.contains("no reason reported by the node"),
            "{message}"
        );
    }

    /// An older proxy that predates the `reason` field still answers the
    /// three fields the decision needs. Reading its body as undecidable
    /// would suspend config delivery across a fleet mid-upgrade.
    #[test]
    fn a_fallback_body_without_a_reason_field_still_deserializes() {
        let report: FallbackReport =
            serde_json::from_str(r#"{"active":true,"revision":3,"digest":"d","suspended":[]}"#)
                .expect("an older proxy's body still parses");
        assert!(report.active);
        assert_eq!(report.revision, Some(3));
        assert_eq!(report.reason, None);
    }

    fn pod_named(name: &str, owner_kind: &str, owner_name: &str, controller: bool) -> Pod {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": "sbproxy",
                "labels": { "app.kubernetes.io/instance": "edge" },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": owner_kind,
                    "name": owner_name,
                    "uid": "0000-1111",
                    "controller": controller,
                }],
            },
        }))
        .expect("pod fixture")
    }

    /// A label is a value anyone with pod-create in the namespace can
    /// type, and the operator sends its admin credential to whatever
    /// answers. The controller owner reference is what actually created
    /// the pod.
    #[test]
    fn only_a_pod_the_operators_own_workload_created_is_probed() {
        assert!(
            pod_is_operator_owned(
                &pod_named("edge-0", "ReplicaSet", "edge-sbproxy-7d9f8c", true),
                "edge-sbproxy",
                "edge-sbproxy",
            ),
            "a Deployment's ReplicaSet is named <deployment>-<pod-template-hash>",
        );
        assert!(
            pod_is_operator_owned(
                &pod_named("edge-0", "StatefulSet", "edge-sbproxy", true),
                "edge-sbproxy",
                "edge-sbproxy",
            ),
            "the clustered shape is owned by the StatefulSet directly",
        );

        for (pod, why) in [
            (
                pod_named("rogue", "ReplicaSet", "attacker-rs", true),
                "a ReplicaSet this operator did not create",
            ),
            (
                pod_named("rogue", "Job", "edge-sbproxy", true),
                "an owner kind this operator never creates",
            ),
            (
                pod_named("rogue", "ReplicaSet", "edge-sbproxy-7d9f8c", false),
                "an owner reference that is not the controller",
            ),
            (
                pod_named("rogue", "ReplicaSet", "edge-sbproxy", true),
                "the Deployment name with no pod-template hash after it",
            ),
            (
                pod_named("rogue", "ReplicaSet", "edge-sbproxy-evil-x", true),
                "a name that merely starts with the deployment's",
            ),
        ] {
            // The last case is admitted by the prefix rule on purpose:
            // Kubernetes owns that name shape, and the check is not a
            // proof of provenance. What it removes is the accidental
            // collision, which is the likely case.
            let owned = pod_is_operator_owned(&pod, "edge-sbproxy", "edge-sbproxy");
            if why == "a name that merely starts with the deployment's" {
                assert!(owned, "documented limit of the prefix rule: {why}");
            } else {
                assert!(!owned, "must not be probed: {why}");
            }
        }

        // A pod with no owner reference at all: the shape a bare
        // `kubectl run` produces, and the one this closes.
        let bare: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "rogue",
                "labels": { "app.kubernetes.io/instance": "edge" },
            },
        }))
        .expect("pod fixture");
        assert!(!pod_is_operator_owned(
            &bare,
            "edge-sbproxy",
            "edge-sbproxy"
        ));
    }

    /// The timestamp answers "how long has this been pinned", so it
    /// moves on a transition and not on a pass. Restamping it also made
    /// every write a real change that the operator's own watch
    /// re-enqueued.
    #[test]
    fn the_condition_timestamp_moves_only_when_the_status_does() {
        let pinned = [pod_on_fallback("edge-0")];
        let first = fallback_condition(&pinned, Some(1), "2026-08-28T00:00:00Z", None);
        assert_eq!(first.last_transition_time, "2026-08-28T00:00:00Z");

        let later = fallback_condition(&pinned, Some(1), "2026-08-28T09:30:00Z", Some(&first));
        assert_eq!(
            later.last_transition_time, "2026-08-28T00:00:00Z",
            "still pinned, so the clock does not restart",
        );

        let cleared = fallback_condition(
            &[healthy_pod("edge-0")],
            Some(1),
            "2026-08-28T09:30:00Z",
            Some(&later),
        );
        assert_eq!(
            cleared.last_transition_time, "2026-08-28T09:30:00Z",
            "the status really changed, so the timestamp does too",
        );
    }

    /// An identical patch still bumps `resourceVersion`, which the
    /// operator's own watch reads as a change. Skipping the write is
    /// what lets an SBProxy settle to its requeue interval.
    #[test]
    fn an_unchanged_condition_is_not_written_back() {
        let pinned = [pod_on_fallback("edge-0")];
        let first = fallback_condition(&pinned, Some(1), "2026-08-28T00:00:00Z", None);
        assert!(
            fallback_condition_patch(&first, None).is_some(),
            "a CR with no condition yet has to be written",
        );

        let again = fallback_condition(&pinned, Some(1), "2026-08-28T09:30:00Z", Some(&first));
        assert_eq!(
            fallback_condition_patch(&again, Some(&first)),
            None,
            "nothing changed, so nothing is written and the watch does not re-fire",
        );

        // A spec edit changes observedGeneration, which is a real write.
        let regenerated =
            fallback_condition(&pinned, Some(2), "2026-08-28T09:30:00Z", Some(&first));
        assert!(fallback_condition_patch(&regenerated, Some(&first)).is_some());

        let patch = fallback_condition_patch(&first, None).expect("a patch");
        assert_eq!(
            patch["status"]["conditions"][0]["type"],
            FALLBACK_CONDITION_TYPE,
        );
    }

    /// The pod is the untrusted end of the probe, and its `reason` goes
    /// into a condition message `kubectl describe` prints raw.
    #[test]
    fn a_pod_supplied_reason_is_bounded_and_stripped_before_it_reaches_a_condition() {
        let hostile = FallbackReport {
            active: true,
            revision: Some(7),
            digest: Some("d".repeat(4_000)),
            reason: Some(format!("line\u{1b}[2Jone\n{}", "x".repeat(10_000))),
        };
        let bounded = hostile.bounded();
        let reason = bounded.reason.expect("a reason");
        assert_eq!(reason.chars().count(), MAX_REPORTED_REASON_CHARS + 3);
        assert!(
            !reason.chars().any(char::is_control),
            "control characters reach a terminal verbatim through kubectl describe",
        );
        assert_eq!(
            bounded.digest.expect("a digest").chars().count(),
            MAX_REPORTED_REASON_CHARS + 3,
        );

        // A well-behaved node's report is unchanged.
        let ordinary = FallbackReport {
            active: true,
            revision: Some(7),
            digest: Some("sha256:abc".to_string()),
            reason: Some("unknown action type: statik".to_string()),
        };
        assert_eq!(ordinary.clone().bounded(), ordinary);
    }

    #[test]
    fn auto_revert_is_refused_under_operator_ownership_and_named_with_its_owner() {
        let armed =
            "proxy:\n  config_history:\n    enabled: true\n    soak:\n      auto_revert: true\n";
        let error = check_auto_revert_under_operator_ownership(armed)
            .expect_err("auto_revert under operator ownership is a race the node loses");
        assert!(error.contains("auto_revert"), "{error}");
        assert!(
            error.contains("sbproxy Kubernetes operator"),
            "the refusal names the owner: {error}",
        );
        assert!(
            error.contains("sbproxy config authority rollback --to-revision N")
                && error.contains("POST /admin/config/rollback"),
            "and points at the path that does work: {error}",
        );
    }

    #[test]
    fn auto_revert_off_and_absent_blocks_and_unparseable_documents_are_all_allowed() {
        for allowed in [
            "proxy: {}\n",
            "proxy:\n  config_history:\n    enabled: true\n",
            "proxy:\n  config_history:\n    enabled: true\n    soak:\n      auto_revert: false\n",
            // Belongs to validate_config_yaml and its more precise message.
            "\t: [unbalanced\n",
        ] {
            check_auto_revert_under_operator_ownership(allowed)
                .unwrap_or_else(|error| panic!("{allowed:?} must be allowed: {error}"));
        }
    }
}
