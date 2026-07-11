// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeSet;

use sbproxy_model_host::{
    capability_registry, AcceleratorKind, ArtifactFormat, Catalog, ComputeCapability, EngineChoice,
    EngineKind, ResolveArtifactRequest, SupportLevel, WorkerProfile,
};

const REVISION: &str = "9217f5db79a29953eb74d5343926648285ec7e67";
const GGUF_SHA256: &str = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db";
const SAFE_SHA256: &str = "6e112429856bc65e3837a9f38d6f6b71ffdda832cb46299a12f4fa8f6352516e";

fn catalog(yaml_models: &str) -> Catalog {
    Catalog::from_yaml(&format!(
        "schema_version: 2\ncatalog_revision: test-catalog-v2\nmodels:\n{yaml_models}"
    ))
    .expect("catalog v2 fixture parses")
}

fn request(model: &str) -> ResolveArtifactRequest {
    ResolveArtifactRequest {
        model: model.to_string(),
        variant: None,
        engine: EngineChoice::Auto,
        replicas: 1,
        heterogeneous_variants: false,
    }
}

fn metal_worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: AcceleratorKind::Metal,
        compute_capability: None,
        memory_bytes: 24 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::LlamaCpp]),
    }
}

fn cuda_worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: AcceleratorKind::Cuda,
        compute_capability: Some(ComputeCapability { major: 8, minor: 9 }),
        memory_bytes: 24 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::Vllm, EngineKind::LlamaCpp]),
    }
}

fn two_variant_model() -> String {
    format!(
        "  coder:\n    params: 8B\n    license: apache-2.0\n    family: qwen\n    context_length: 32768\n    variants:\n      - id: awq\n        format: safetensors\n        quant: AWQ\n        engines: [vllm]\n        source: hf:Qwen/Qwen3-8B-AWQ\n        revision: 4da05a8edb55c6046cce958586c33b61da07bb79\n        files:\n          - path: model-00001-of-00002.safetensors\n            sha256: {SAFE_SHA256}\n            size_bytes: 4853922024\n        requirements:\n          accelerators: [cuda]\n          min_compute_capability: {{ major: 7, minor: 5 }}\n          min_memory_bytes: 8589934592\n        stability: preview\n        certification: fixture-cuda\n      - id: q4_k_m\n        format: gguf\n        quant: Q4_K_M\n        engines: [llama_cpp]\n        source: hf:Qwen/Qwen2.5-0.5B-Instruct-GGUF\n        revision: {REVISION}\n        files:\n          - path: qwen2.5-0.5b-instruct-q4_k_m.gguf\n            sha256: {GGUF_SHA256}\n            size_bytes: 491400032\n        requirements:\n          accelerators: [cpu, metal, cuda]\n          min_memory_bytes: 1073741824\n        stability: preview\n        certification: fixture-portable\n"
    )
}

#[test]
fn v2_resolution_returns_one_typed_exact_artifact() {
    let catalog = catalog(&two_variant_model());
    let mut pinned = request("coder");
    pinned.variant = Some("q4_k_m".to_string());

    let resolved = catalog
        .resolve_artifact(&pinned, &metal_worker())
        .expect("pinned portable variant resolves");

    assert_eq!(resolved.catalog_revision, "test-catalog-v2");
    assert_eq!(resolved.logical_model, "coder");
    assert_eq!(resolved.variant_id, "q4_k_m");
    assert_eq!(resolved.format, ArtifactFormat::Gguf);
    assert_eq!(resolved.engine, EngineKind::LlamaCpp);
    assert_eq!(resolved.revision, REVISION);
    assert_eq!(resolved.files.len(), 1);
    assert_eq!(resolved.files[0].sha256, GGUF_SHA256);
    assert_eq!(resolved.files[0].size_bytes, 491_400_032);
    assert_eq!(resolved.artifact_digest.len(), 64);
}

#[test]
fn apple_auto_resolution_cannot_select_vllm_only_safetensors() {
    let catalog = catalog(&two_variant_model());

    let resolved = catalog
        .resolve_artifact(&request("coder"), &metal_worker())
        .expect("portable GGUF remains compatible");

    assert_eq!(resolved.variant_id, "q4_k_m");
    assert_eq!(resolved.engine, EngineKind::LlamaCpp);
}

#[test]
fn cuda_resolution_returns_only_a_variant_present_in_the_catalog() {
    let catalog = catalog(&two_variant_model());
    let resolved = catalog
        .resolve_artifact(&request("coder"), &cuda_worker())
        .expect("first compatible exact variant resolves");
    assert_eq!(resolved.variant_id, "awq");
    assert_eq!(resolved.quant, "AWQ");

    let mut absent = request("coder");
    absent.variant = Some("fp8".to_string());
    let error = catalog
        .resolve_artifact(&absent, &cuda_worker())
        .expect_err("an absent repository variant cannot be invented");
    assert!(error.to_string().contains("fp8"));
    assert!(error.to_string().contains("awq, q4_k_m"));
}

#[test]
fn replicated_auto_selection_requires_an_explicit_variant_pin() {
    let catalog = catalog(&two_variant_model());
    let mut replicated = request("coder");
    replicated.replicas = 2;

    let error = catalog
        .resolve_artifact(&replicated, &cuda_worker())
        .expect_err("replicated homogeneous deployments must pin a variant");
    assert!(error.to_string().contains("pin a variant"));

    replicated.variant = Some("q4_k_m".to_string());
    let cuda = catalog
        .resolve_artifact(&replicated, &cuda_worker())
        .expect("pinned variant resolves on CUDA");
    let metal = catalog
        .resolve_artifact(&replicated, &metal_worker())
        .expect("same pinned variant resolves on Metal");
    assert_eq!(cuda.variant_id, metal.variant_id);
    assert_eq!(cuda.artifact_digest, metal.artifact_digest);
}

#[test]
fn heterogeneous_replicas_may_auto_select_per_worker() {
    let catalog = catalog(&two_variant_model());
    let mut request = request("coder");
    request.replicas = 2;
    request.heterogeneous_variants = true;

    let cuda = catalog
        .resolve_artifact(&request, &cuda_worker())
        .expect("CUDA auto selection");
    let metal = catalog
        .resolve_artifact(&request, &metal_worker())
        .expect("Metal auto selection");
    assert_eq!(cuda.variant_id, "awq");
    assert_eq!(metal.variant_id, "q4_k_m");
}

#[test]
fn safetensors_are_preferred_and_pickle_requires_opt_in() {
    let with_both = catalog(&format!(
        "  safe-first:\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    context_length: 4096\n    allow_pickle: true\n    variants:\n      - id: pickle\n        format: pickle\n        quant: fp16\n        engines: [vllm]\n        source: hf:Org/Pickle\n        revision: {REVISION}\n        files:\n          - path: pytorch_model.bin\n            sha256: {GGUF_SHA256}\n            size_bytes: 100\n        requirements:\n          accelerators: [cuda]\n          min_memory_bytes: 100\n        stability: preview\n        certification: fixture\n      - id: safe\n        format: safetensors\n        quant: fp16\n        engines: [vllm]\n        source: hf:Org/Safe\n        revision: {REVISION}\n        files:\n          - path: model.safetensors\n            sha256: {SAFE_SHA256}\n            size_bytes: 100\n        requirements:\n          accelerators: [cuda]\n          min_memory_bytes: 100\n        stability: preview\n        certification: fixture\n"
    ));
    assert_eq!(
        with_both
            .resolve_artifact(&request("safe-first"), &cuda_worker())
            .expect("safe variant resolves")
            .variant_id,
        "safe"
    );

    let pickle_only = catalog(&format!(
        "  pickle-only:\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    context_length: 4096\n    variants:\n      - id: pickle\n        format: pickle\n        quant: fp16\n        engines: [vllm]\n        source: hf:Org/Pickle\n        revision: {REVISION}\n        files:\n          - path: pytorch_model.bin\n            sha256: {GGUF_SHA256}\n            size_bytes: 100\n        requirements:\n          accelerators: [cuda]\n          min_memory_bytes: 100\n        stability: preview\n        certification: fixture\n"
    ));
    let error = pickle_only
        .resolve_artifact(&request("pickle-only"), &cuda_worker())
        .expect_err("pickle is refused without logical-model opt-in");
    assert!(error.to_string().contains("allow_pickle"));
}

#[test]
fn stable_hf_variants_require_immutable_complete_metadata() {
    let invalid = "schema_version: 2\ncatalog_revision: invalid\nmodels:\n  bad:\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    context_length: 4096\n    variants:\n      - id: unstable\n        format: gguf\n        quant: Q4\n        engines: [llama_cpp]\n        source: hf:Org/Repo\n        revision: main\n        files:\n          - path: ../escape.gguf\n            sha256: short\n            size_bytes: 0\n        requirements:\n          accelerators: [cpu]\n          min_memory_bytes: 1\n        stability: stable\n        certification: fixture\n".to_string();

    let error = Catalog::from_yaml(&invalid).expect_err("invalid stable variant is rejected");
    let message = error.to_string();
    assert!(message.contains("bad"));
    assert!(message.contains("unstable"));
    assert!(message.contains("revision") || message.contains("path"));
}

#[test]
fn v1_catalogs_keep_legacy_resolution_and_report_preview_migration() {
    let loaded = Catalog::from_yaml_with_diagnostics(
        "models:\n  legacy:\n    hf_repo: Org/Legacy\n    quants: [Q4_K_M]\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    min_vram_hint_gib: 1.0\n",
    )
    .expect("v1 catalog remains readable");

    let legacy = loaded.catalog.resolve("legacy").expect("legacy adapter");
    assert_eq!(legacy.hf_repo, "Org/Legacy");
    assert_eq!(legacy.quant, "Q4_K_M");
    assert_eq!(loaded.diagnostics.len(), 1);
    assert!(loaded.diagnostics[0].to_string().contains("preview"));

    let error = loaded
        .catalog
        .resolve_artifact(&request("legacy"), &cuda_worker())
        .expect_err("incomplete v1 data cannot become a verified artifact");
    assert!(error.to_string().contains("catalog v2"));
}

#[test]
fn canonical_artifact_digest_is_stable_across_reloads() {
    let yaml = two_variant_model();
    let first = catalog(&yaml)
        .resolve_artifact(&request("coder"), &cuda_worker())
        .expect("first resolution");
    let second = catalog(&yaml)
        .resolve_artifact(&request("coder"), &cuda_worker())
        .expect("second resolution");

    assert_eq!(first, second);
    assert_eq!(first.artifact_digest, second.artifact_digest);
}

#[test]
fn built_in_catalog_contains_a_real_pinned_bootstrap_variant() {
    let built_in = Catalog::builtin();
    assert_eq!(built_in.schema_version, 2);
    let mut pinned = request("qwen2.5-0.5b-instruct");
    pinned.variant = Some("q4_k_m".to_string());
    let artifact = built_in
        .resolve_artifact(&pinned, &metal_worker())
        .expect("built-in bootstrap resolves");

    assert_eq!(artifact.stability, SupportLevel::Preview);
    assert_eq!(artifact.revision, REVISION);
    assert_eq!(artifact.files[0].sha256, GGUF_SHA256);
    assert_eq!(artifact.files[0].size_bytes, 491_400_032);

    let capability = capability_registry()
        .entries()
        .iter()
        .find(|entry| entry.id == "manifest.catalog_v2")
        .expect("catalog v2 capability is registered");
    assert_eq!(capability.status, SupportLevel::Stable);
    capability
        .consumer
        .expect("stable catalog v2 has an executable consumer")
        .assert_behavior()
        .expect("catalog v2 consumer contract executes");
}
