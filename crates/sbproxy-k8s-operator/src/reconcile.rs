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
    EnvVarSource, HTTPGetAction, ObjectFieldSelector, PodSpec, PodTemplateSpec, Probe,
    ResourceRequirements as K8sResourceRequirements, Secret, SecretKeySelector, Service,
    ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::Resource;

use crate::crd::{ClusteringSpec, SBProxy, SBProxyConfig};

// --- Hot-reload decision ---

/// Decide whether the upcoming reconcile should prefer a hot-reload
/// over a rollout-restart.
///
/// Hot-reload is preferred when:
/// 1. The `SBProxy` has `spec.adminAuthSecretRef` set (so the
///    operator can authenticate against `/admin/reload`).
/// 2. There is an existing Deployment (we can read the previous
///    config hash from its pod-template annotations).
/// 3. Only the underlying `sb.yml` changed (the existing
///    Deployment's image, replicas, resources match the desired
///    Deployment).
///
/// When any of those conditions fails we fall back to the
/// rollout-restart path so a config-incompatible pod is never left
/// running.
pub fn should_hot_reload(
    sbproxy: &SBProxy,
    existing_deploy: Option<&Deployment>,
    desired_deploy: &Deployment,
    previous_config_hash: Option<&str>,
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
    match previous_config_hash {
        Some(prev) => prev != new_config_hash,
        // No previous hash recorded => treat as a config change so
        // the reload still flushes any drift.
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
pub const CONFIG_HASH_ANNOTATION: &str = "sbproxy.dev/config-hash";

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
    previous_config_hash: Option<&str>,
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
    match previous_config_hash {
        Some(prev) => prev != new_config_hash,
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
}
