# Model-host capability matrix
*Last modified: 2026-07-13*

*Generated from the executable registry; do not hand-edit.*

Registry version: `1`

## Product capabilities

| Capability | Domain | Status | Evidence | Summary |
| --- | --- | --- | --- | --- |
| `manifest.serve_model_declarations` | `manifest` | `stable` | contract.serve_models_change_desired_deployments | Serve model declarations change normalized desired model names. |
| `manifest.canonical_desired_state` | `manifest` | `stable` | contract.canonical_desired_state_reconciles_atomically<br>test.runtime_reconcile<br>test.model_host_reload | Canonical proxy.model_host deployments compile into one atomic runtime revision. |
| `manifest.legacy_catalog_resolution` | `manifest` | `stable` | contract.catalog_id_resolves_exact_repo | Legacy catalog IDs resolve during the migration window. |
| `manifest.catalog_v2` | `manifest` | `stable` | contract.catalog_v2_selects_exact_artifact<br>test.catalog_v2 | Catalog v2 resolves pinned logical models to exact immutable artifacts. |
| `artifact.legacy_download` | `artifact` | `preview` | none | Legacy file downloads lack the complete atomic artifact contract. |
| `artifact.verified_acquisition` | `artifact` | `stable` | contract.verified_artifact_policy_blocks_unauthorized_network<br>test.artifact_manager<br>test.artifact_policy | Managed artifacts are exact, atomic, resumable, and policy enforced. |
| `artifact.cache_addressing` | `artifact` | `stable` | contract.cache_directory_changes_artifact_path | Explicit cache directories deterministically change artifact paths. |
| `artifact.cache_budget` | `artifact` | `stable` | contract.cache_budget_protects_active_artifacts<br>test.artifact_gc | Cache collection enforces LRU budgets without deleting protected artifacts. |
| `artifact.exact_removal` | `artifact` | `stable` | contract.exact_removal_protects_references<br>test.artifact_manager<br>test.models_lifecycle_cli | Exact cache removal is idempotent and rejects configured, resident, pinned, locked, leased, or active artifacts. |
| `engine.typed_managed_drivers` | `engine` | `stable` | contract.managed_drivers_expose_typed_capabilities<br>test.engine_drivers | Managed engines share typed detect, provision, launch, health, and shutdown contracts over verified local artifacts. |
| `engine.llama_cpp_managed` | `engine` | `preview` | test.engine_drivers<br>test.cuda_build<br>cert.apple_metal.2026-07-11 | Managed llama.cpp supports digest-verified binary acquisition and Linux CUDA source builds; Apple Metal is certified while live CUDA remains deferred. |
| `engine.vllm_uv` | `engine` | `preview` | test.engine_drivers | Managed vLLM can use a pinned uv environment; live NVIDIA certification remains deferred. |
| `engine.vllm_container` | `engine` | `preview` | test.engine_drivers | Digest-pinned private container plans use read-only artifacts and selected devices; live NVIDIA certification remains deferred. |
| `engine.sglang` | `engine` | `preview` | test.engine_drivers | Managed SGLang serves safetensors weights on a CUDA worker from a pinned uv environment or a digest-pinned container, mirroring vLLM and adding RadixAttention prefix caching; live NVIDIA certification remains deferred. |
| `lifecycle.atomic_reconciliation` | `lifecycle` | `stable` | contract.canonical_desired_state_reconciles_atomically<br>test.runtime_reconcile<br>test.model_host_reload | Startup, file reload, SIGHUP, and admin reload prepare a complete revision before commit; pre-commit failures do not publish the candidate. |
| `lifecycle.single_node_residency` | `lifecycle` | `stable` | contract.eviction_changes_admission | Single-node residency honors the global resident limit and configured eviction policy across devices. |
| `lifecycle.keep_alive` | `lifecycle` | `stable` | contract.keep_alive_starts_after_last_permit<br>test.local_admission<br>test.runtime_reconcile | Keep-alive starts after the last completed request and never expires active or queued work. |
| `cluster.managed_replicas` | `cluster` | `stable` | contract.cluster_placement_converges<br>test.placement<br>test.runtime_reconcile<br>test.cluster_control_plane<br>test.model_cluster_control | Managed replicas use versioned worker snapshots, deterministic placement and spread, readiness-gated rollout, and authenticated cluster health status. |
| `cluster.remote_dispatch` | `cluster` | `preview` | test.model_plane_envelope<br>test.model_plane_transport<br>test.managed_replica_routing<br>test.managed_replica_dispatch<br>test.model_cluster_dispatch | Authenticated HTTP/2 local and peer dispatch, coordinated cold starts, streaming cancellation, and pre-output failover have local test coverage; a dedicated executable consumer contract and live production certification remain incomplete. |
| `policy.local_provider_governance` | `policy` | `preview` | test.managed_replica_dispatch<br>test.admin_model_host<br>test.model_cluster_dispatch | Managed routes preserve gateway provider and model policy, expose topology-free logical discovery, and emit bounded route metadata; strict distributed limits and full key introspection remain deferred. |
| `admin.model_status` | `admin` | `stable` | contract.status_reports_stable_lifecycle<br>test.models_lifecycle_cli<br>test.admin_model_host | Authenticated admin status, load, stop, drain, and reset adapt the shared runtime lifecycle. |
| `admin.model_management` | `admin` | `preview` | contract.canonical_desired_state_reconciles_atomically<br>test.admin_model_management<br>test.ui_model_management | Backend E2E covers authenticated full-map revision conflicts and restart persistence; UI unit and component contracts cover mode-aware catalog evidence, lifecycle state, conflict recovery, removal guards, and cluster authority proof. |
| `platform.apple_metal` | `platform` | `stable` | contract.catalog_v2_selects_exact_artifact<br>test.engine_drivers<br>cert.apple_metal.2026-07-11 | Apple Metal completed a real managed gateway completion, status, stop, cache-reuse, and Ctrl-C shutdown gate on Apple M4 Max. |
| `platform.nvidia_cuda` | `platform` | `preview` | test.cuda_build<br>test.local_admission | NVIDIA discovery, vLLM, and CUDA llama.cpp have deterministic coverage; live GCP certification is reserved for the final PR group. |
| `lifecycle.priority_admission` | `lifecycle` | `stable` | contract.priority_gate_changes_dispatch | Configured local concurrency changes request admission. |
| `lifecycle.model_cli` | `lifecycle` | `stable` | contract.exact_removal_protects_references<br>test.models_lifecycle_cli | Pull, list, show, remove, process status, and stop commands use versioned JSON and shared artifact or runtime contracts. |
| `admin.value_report` | `admin` | `stable` | contract.reference_price_records_savings<br>test.value_ledger | A configured cloud reference prices each local completion as dollars saved, recorded per model and served on the admin value route. |

## Configuration fields

| Field | Status | Capability | Consumer contract |
| --- | --- | --- | --- |
| `serve.models` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.catalog_file` | `preview` | `manifest.catalog_v2` | `none` |
| `serve.cache_dir` | `stable` | `artifact.cache_addressing` | `contract.cache_directory_changes_artifact_path` |
| `serve.cache_budget_gib` | `config_only` | `artifact.cache_budget` | `none` |
| `serve.eviction` | `stable` | `lifecycle.single_node_residency` | `contract.eviction_changes_admission` |
| `serve.engines` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.max_concurrent_requests` | `stable` | `lifecycle.priority_admission` | `contract.priority_gate_changes_dispatch` |
| `serve.queue_timeout_ms` | `stable` | `lifecycle.priority_admission` | `contract.priority_gate_changes_dispatch` |
| `serve.models[].model` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.models[].name` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.models[].variant` | `stable` | `manifest.catalog_v2` | `contract.catalog_v2_selects_exact_artifact` |
| `serve.models[].engine` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].keep_alive` | `stable` | `lifecycle.keep_alive` | `contract.keep_alive_starts_after_last_permit` |
| `serve.models[].max_context` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].extra_args` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].kv_quant` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].speculative` | `unsupported` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].chunked_prefill` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].lora_adapters` | `unsupported` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].pinned` | `preview` | `lifecycle.single_node_residency` | `none` |
| `serve.models[].tool_call_parser` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].swap_space_gib` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].cpu_offload_gib` | `preview` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].max_loras` | `unsupported` | `engine.typed_managed_drivers` | `none` |
| `serve.models[].gguf_file` | `preview` | `artifact.legacy_download` | `none` |
| `serve.models[].reference` | `stable` | `admin.value_report` | `contract.reference_price_records_savings` |
