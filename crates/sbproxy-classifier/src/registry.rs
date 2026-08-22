//! Multi-tenant registry: tenant id (an origin's hostname, by convention)
//! to per-tenant heuristic classification state.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `registry.rs`,
//! dropped to the fields this port serves: a compiled [`Classifier`] (label
//! patterns) and [`Normalizer`] (regex rules) per tenant. The enterprise
//! version also carries a `ModelSelectionState` for per-origin overrides of
//! named embedding / judge / intent / content-type ONNX models; this port
//! does not carry the LLM-judge backend or a named-model registry (out of
//! WOR-2665's scope, see `docs/classifier-sidecar.md`), so there is nothing
//! for that override to select between.
//!
//! Every tenant is registered at runtime via the TCP `register` command (or
//! the future gRPC equivalent); there is no config file and no hostname
//! pattern matching here, mirroring the enterprise design exactly.
//!
//! The registry is protected by a single [`RwLock`]:
//! - Reads dominate (one per inbound classify call), so the writer-rare
//!   pattern of `RwLock` wins over `Mutex` here.
//! - Entries are wrapped in [`Arc`] so a handler can snapshot a `Tenant`
//!   reference, release the lock, and run inference without holding the
//!   registry locked for the duration.
//!
//! Registration is additive (insert or replace). Deletion is explicit.
//! There is no default tenant: a classify request for an unregistered
//! tenant id is an error, not a silent fallback to some other tenant's
//! patterns.

use crate::config::{ClassificationConfig, LabelConfig, NormalizationConfig, NormalizationRule};
use crate::heuristic::Classifier;
use crate::normalize::Normalizer;
use crate::protocol::{TenantConfig, TenantInfo};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Internal config used to build a [`Tenant`] from the wire-protocol
/// [`TenantConfig`].
struct TenantBuildConfig {
    labels: Vec<LabelConfig>,
    classification: ClassificationConfig,
    normalization: NormalizationConfig,
}

/// A compiled tenant with its own classifier and normalizer.
pub struct Tenant {
    pub classifier: Classifier,
    pub normalizer: Normalizer,
    pub label_names: Vec<String>,
}

/// Thread-safe registry of tenant configs.
pub struct Registry {
    tenants: RwLock<HashMap<String, Arc<Tenant>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl Registry {
    /// Create an empty registry. Tenants are registered at runtime.
    pub fn new_empty() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a tenant by id. Returns `None` if the tenant is not
    /// registered, or if `tenant_id` is absent/empty.
    pub fn get(&self, tenant_id: Option<&str>) -> Option<Arc<Tenant>> {
        match tenant_id {
            Some(id) if !id.is_empty() => {
                let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
                tenants.get(id).cloned()
            }
            _ => {
                warn!("classify request with no tenant id");
                None
            }
        }
    }

    /// Register or update a tenant from an inline config. Compiles regex
    /// patterns immediately, so subsequent classify requests are fast.
    pub fn register(&self, tenant_id: &str, tenant_config: &TenantConfig) -> Result<(), String> {
        let build = Self::tenant_config_to_build(tenant_config)?;
        let tenant = Self::build_tenant(&build);

        info!(
            tenant = %tenant_id,
            labels = tenant.label_names.len(),
            "registered tenant"
        );

        let mut tenants = self.tenants.write().unwrap_or_else(|e| e.into_inner());
        tenants.insert(tenant_id.to_string(), Arc::new(tenant));
        Ok(())
    }

    /// Remove a tenant. Future requests for this tenant id are refused
    /// (there is no fallback tenant).
    pub fn delete(&self, tenant_id: &str) -> bool {
        let mut tenants = self.tenants.write().unwrap_or_else(|e| e.into_inner());
        let existed = tenants.remove(tenant_id).is_some();
        if existed {
            info!(tenant = %tenant_id, "deleted tenant");
        }
        existed
    }

    /// List all registered tenants.
    pub fn list(&self) -> Vec<TenantInfo> {
        let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
        tenants
            .iter()
            .map(|(id, t)| TenantInfo {
                id: id.clone(),
                labels: t.label_names.clone(),
            })
            .collect()
    }

    /// Number of currently registered tenants.
    pub fn tenant_count(&self) -> usize {
        self.tenants.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn tenant_config_to_build(tc: &TenantConfig) -> Result<TenantBuildConfig, String> {
        if tc.labels.is_empty() {
            return Err("tenant config must have at least one label".to_string());
        }

        let labels = tc
            .labels
            .iter()
            .map(|l| LabelConfig {
                name: l.name.clone(),
                patterns: l.patterns.clone(),
                weight: l.weight,
            })
            .collect();

        let classification = match &tc.classification {
            Some(c) => ClassificationConfig {
                confidence_threshold: c.confidence_threshold,
                default_label: c.default_label.clone(),
                default_boost: c.default_boost,
            },
            None => ClassificationConfig::default(),
        };

        let normalization = match &tc.normalization {
            Some(n) => NormalizationConfig {
                unicode_nfkc: n.unicode_nfkc,
                trim: n.trim,
                rules: n
                    .rules
                    .iter()
                    .map(|r| NormalizationRule {
                        name: r.name.clone(),
                        pattern: r.pattern.clone(),
                        replace: r.replace.clone(),
                        enabled: r.enabled,
                    })
                    .collect(),
            },
            None => NormalizationConfig::default(),
        };

        Ok(TenantBuildConfig {
            labels,
            classification,
            normalization,
        })
    }

    fn build_tenant(build: &TenantBuildConfig) -> Tenant {
        let classifier = Classifier::from_labels(
            &build.labels,
            build.classification.confidence_threshold,
            &build.classification.default_label,
            build.classification.default_boost,
        );
        // Read back from the compiled classifier rather than re-deriving
        // from `build.labels`: the two are equivalent today, but this way
        // `label_names` can never drift from what the classifier actually
        // knows about if the two are ever changed independently.
        let label_names = classifier.label_names();
        Tenant {
            classifier,
            normalizer: Normalizer::from_config(&build.normalization),
            label_names,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TenantClassification, TenantLabel};

    fn sample_config() -> TenantConfig {
        TenantConfig {
            labels: vec![TenantLabel {
                name: "greeting".to_string(),
                patterns: vec![r"(?i)^(hi|hello)\b".to_string()],
                weight: 1.0,
            }],
            classification: Some(TenantClassification {
                confidence_threshold: 0.1,
                default_label: "greeting".to_string(),
                default_boost: 0.9,
            }),
            normalization: None,
        }
    }

    #[test]
    fn unregistered_tenant_returns_none() {
        let registry = Registry::new_empty();
        assert!(registry.get(Some("nobody.example")).is_none());
    }

    #[test]
    fn missing_tenant_id_returns_none() {
        let registry = Registry::new_empty();
        assert!(registry.get(None).is_none());
        assert!(registry.get(Some("")).is_none());
    }

    #[test]
    fn register_then_get_round_trips() {
        let registry = Registry::new_empty();
        registry
            .register("tenant.example", &sample_config())
            .expect("valid config registers");
        let tenant = registry.get(Some("tenant.example")).expect("registered");
        assert_eq!(tenant.label_names, vec!["greeting".to_string()]);
        assert_eq!(registry.tenant_count(), 1);
    }

    #[test]
    fn register_rejects_empty_label_list() {
        let registry = Registry::new_empty();
        let config = TenantConfig {
            labels: vec![],
            classification: None,
            normalization: None,
        };
        let err = registry
            .register("tenant.example", &config)
            .expect_err("empty labels must be rejected");
        assert!(err.contains("at least one label"));
    }

    #[test]
    fn register_is_additive_and_overwrites_by_id() {
        let registry = Registry::new_empty();
        registry.register("a.example", &sample_config()).unwrap();
        registry.register("b.example", &sample_config()).unwrap();
        assert_eq!(registry.tenant_count(), 2);

        // Re-registering the same id replaces, not appends.
        registry.register("a.example", &sample_config()).unwrap();
        assert_eq!(registry.tenant_count(), 2);
    }

    #[test]
    fn delete_removes_a_registered_tenant() {
        let registry = Registry::new_empty();
        registry
            .register("tenant.example", &sample_config())
            .unwrap();
        assert!(registry.delete("tenant.example"));
        assert!(registry.get(Some("tenant.example")).is_none());
        assert_eq!(registry.tenant_count(), 0);
    }

    #[test]
    fn delete_of_unknown_tenant_is_false_not_an_error() {
        let registry = Registry::new_empty();
        assert!(!registry.delete("nobody.example"));
    }

    #[test]
    fn list_reports_every_registered_tenant() {
        let registry = Registry::new_empty();
        registry.register("a.example", &sample_config()).unwrap();
        registry.register("b.example", &sample_config()).unwrap();
        let mut ids: Vec<String> = registry.list().into_iter().map(|t| t.id).collect();
        ids.sort();
        assert_eq!(ids, vec!["a.example".to_string(), "b.example".to_string()]);
    }
}
