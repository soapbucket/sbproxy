use std::collections::BTreeMap;

use sbproxy_config::{ManagedDeploymentConfig, ModelHostAuthority, ModelHostControlConfig};
use sbproxy_model_host::{
    compile_desired_state, Catalog, DesiredStateError, LegacyServeInput, ManagedProviderInput,
    ModelHostConfig, RuntimeDesiredInput,
};

fn canonical_host() -> ModelHostControlConfig {
    ModelHostControlConfig {
        authority: ModelHostAuthority::FileManaged,
        deployments: BTreeMap::from([(
            "coder".to_string(),
            ManagedDeploymentConfig {
                model: "qwen2.5-0.5b-instruct".to_string(),
                variant: Some("q4_k_m".to_string()),
                warm: true,
                max_concurrency: Some(4),
                ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").expect("deployment defaults")
            },
        )]),
        ..ModelHostControlConfig::default()
    }
}

fn managed(origin: &str, provider: &str, deployment: &str) -> ManagedProviderInput {
    ManagedProviderInput {
        origin: origin.to_string(),
        provider: provider.to_string(),
        deployment: deployment.to_string(),
        models: vec!["coder".to_string()],
    }
}

fn legacy(origin: &str, provider: &str, model: &str) -> LegacyServeInput {
    let config: ModelHostConfig = serde_yaml::from_str(&format!(
        r#"
models:
  - model: {model}
    name: coder
"#
    ))
    .expect("legacy serve config");
    LegacyServeInput {
        origin: origin.to_string(),
        provider: provider.to_string(),
        config,
    }
}

fn input(
    canonical: Option<ModelHostControlConfig>,
    managed_providers: Vec<ManagedProviderInput>,
    legacy_providers: Vec<LegacyServeInput>,
) -> RuntimeDesiredInput {
    RuntimeDesiredInput {
        source_revision: "test-config-sha".to_string(),
        canonical,
        managed_providers,
        legacy_providers,
    }
}

#[test]
fn desired_canonical_deployments_validate_managed_routes_from_all_origins() {
    let state = compile_desired_state(
        input(
            Some(canonical_host()),
            vec![
                managed("origin-a", "local", "coder"),
                managed("origin-b", "local", "coder"),
            ],
            Vec::new(),
        ),
        &Catalog::builtin(),
    )
    .expect("complete desired state");

    assert_eq!(state.revision.deployments.len(), 1);
    assert_eq!(state.routes.len(), 2, "both origins remain routable");
    assert_eq!(
        state
            .route_for("origin-a", "local", "coder")
            .expect("origin-a route")
            .deployment,
        "coder"
    );
    assert_eq!(state.revision.deployments["coder"].max_concurrency, Some(4));
}

#[test]
fn desired_rejects_a_managed_provider_for_an_undeclared_deployment() {
    let error = compile_desired_state(
        input(
            Some(canonical_host()),
            vec![managed("origin-a", "local", "missing")],
            Vec::new(),
        ),
        &Catalog::builtin(),
    )
    .expect_err("undeclared reference must fail the whole revision");

    assert!(matches!(
        error,
        DesiredStateError::UndeclaredDeployment { ref deployment, .. }
            if deployment == "missing"
    ));
}

#[test]
fn desired_legacy_ids_are_stable_and_equivalent_origins_deduplicate() {
    let first = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![
                legacy("origin-a", "local", "qwen3-8b"),
                legacy("origin-b", "local", "qwen3-8b"),
            ],
        ),
        &Catalog::builtin(),
    )
    .expect("equivalent legacy providers");
    let again = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![legacy("origin-a", "local", "qwen3-8b")],
        ),
        &Catalog::builtin(),
    )
    .expect("same legacy provider");

    let first_ids = first.revision.deployments.keys().collect::<Vec<_>>();
    let again_ids = again.revision.deployments.keys().collect::<Vec<_>>();
    assert_eq!(first_ids, again_ids);
    assert_eq!(first.routes.len(), 2);
    assert!(first_ids[0].starts_with("legacy-local-coder-"));
}

#[test]
fn desired_rejects_conflicting_legacy_routes_instead_of_picking_an_origin() {
    let error = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![
                legacy("origin-a", "local", "qwen3-8b"),
                legacy("origin-b", "local", "qwen3-14b"),
            ],
        ),
        &Catalog::builtin(),
    )
    .expect_err("one public route cannot select two deployments");

    assert!(matches!(
        error,
        DesiredStateError::Conflict { ref field, .. } if field == "route local/coder"
    ));
}

#[test]
fn desired_rejects_conflicting_legacy_host_policies() {
    let mut first = legacy("origin-a", "local-a", "qwen3-8b");
    first.config.cache_dir = Some("/cache/a".to_string());
    let mut second = legacy("origin-b", "local-b", "qwen3-14b");
    second.config.cache_dir = Some("/cache/b".to_string());

    let error = compile_desired_state(
        input(None, Vec::new(), vec![first, second]),
        &Catalog::builtin(),
    )
    .expect_err("host policy must be merged explicitly");

    assert!(matches!(
        error,
        DesiredStateError::Conflict { ref field, .. } if field == "legacy host policy"
    ));
}
