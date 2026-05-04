//! Reconciliation logic.
//!
//! Pure rendering functions live here so they can be unit-tested without a
//! cluster. The kube-runtime `Controller` wiring (watches, error policy,
//! requeue cadence) lives in `main.rs` and calls into this module to build
//! the desired Deployment / Service / ConfigMap triple for each `SBProxy`.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, PodSpec, PodTemplateSpec,
    ResourceRequirements as K8sResourceRequirements, Service, ServicePort, ServiceSpec, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::Resource;

use crate::crd::{SBProxy, SBProxyConfig};

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
    let name = configmap_name(sbproxy);
    let namespace = sbproxy.metadata.namespace.clone();
    let mut data = BTreeMap::new();
    data.insert("sb.yml".to_string(), config.spec.config.clone());

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
            },
            status: None,
        }
    }

    fn fixture_sbproxyconfig() -> SBProxyConfig {
        SBProxyConfig {
            metadata: ObjectMeta {
                name: Some("demo-config".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: SBProxyConfigSpec {
                config: "origins:\n  - host: example.com\n    upstream:\n      url: https://example.org\n"
                    .to_string(),
            },
        }
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
}
