# Model-host capability matrix
*Last modified: 2026-07-10*

*Generated from the executable registry; do not hand-edit.*

Registry version: `1`

## Product capabilities

| Capability | Domain | Status | Evidence | Summary |
| --- | --- | --- | --- | --- |
| `manifest.serve_model_declarations` | `manifest` | `stable` | contract.serve_models_change_desired_deployments | Serve model declarations change normalized desired model names. |
| `manifest.legacy_catalog_resolution` | `manifest` | `stable` | contract.catalog_id_resolves_exact_repo | Legacy catalog IDs resolve during the migration window. |
| `manifest.catalog_v2` | `manifest` | `stable` | contract.catalog_v2_selects_exact_artifact<br>test.catalog_v2 | Catalog v2 resolves pinned logical models to exact immutable artifacts. |
| `artifact.legacy_download` | `artifact` | `preview` | none | Legacy file downloads lack the complete atomic artifact contract. |
| `artifact.verified_acquisition` | `artifact` | `stable` | contract.verified_artifact_policy_blocks_unauthorized_network<br>test.artifact_manager<br>test.artifact_policy | Managed artifacts are exact, atomic, resumable, and policy enforced. |
| `artifact.cache_addressing` | `artifact` | `stable` | contract.cache_directory_changes_artifact_path | Explicit cache directories deterministically change artifact paths. |
| `artifact.cache_budget` | `artifact` | `config_only` | none | Cache budget is parsed but safe protected collection is not yet active. |
| `engine.managed_launch` | `engine` | `preview` | none | llama.cpp and vLLM launch paths require managed-artifact hardening. |
| `engine.container_launch` | `engine` | `config_only` | none | Container launch configuration is not an executable stable path. |
| `lifecycle.single_node_residency` | `lifecycle` | `stable` | contract.eviction_changes_admission | Single-node residency honors the configured eviction policy. |
| `lifecycle.keep_alive` | `lifecycle` | `preview` | none | Keep-alive is visible in status but idle unload is not complete. |
| `cluster.managed_replicas` | `cluster` | `unsupported` | none | Managed multi-node placement and dispatch are not available in PR 1. |
| `policy.local_provider_governance` | `policy` | `preview` | none | Local providers remain behind the existing gateway policy path. |
| `admin.model_status` | `admin` | `preview` | none | Read-only local model status is available. |
| `admin.model_management` | `admin` | `unsupported` | none | Model mutation API and UI land in the operator-product PR. |
| `platform.host_probe` | `platform` | `preview` | none | CPU, Apple, and NVIDIA probes require final platform certification. |
| `lifecycle.priority_admission` | `lifecycle` | `stable` | contract.priority_gate_changes_dispatch | Configured local concurrency changes request admission. |

## Configuration fields

| Field | Status | Capability | Consumer contract |
| --- | --- | --- | --- |
| `serve.models` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.catalog_file` | `preview` | `manifest.catalog_v2` | `none` |
| `serve.cache_dir` | `stable` | `artifact.cache_addressing` | `contract.cache_directory_changes_artifact_path` |
| `serve.cache_budget_gib` | `config_only` | `artifact.cache_budget` | `none` |
| `serve.eviction` | `stable` | `lifecycle.single_node_residency` | `contract.eviction_changes_admission` |
| `serve.engines` | `preview` | `engine.managed_launch` | `none` |
| `serve.max_concurrent_requests` | `stable` | `lifecycle.priority_admission` | `contract.priority_gate_changes_dispatch` |
| `serve.queue_timeout_ms` | `preview` | `lifecycle.priority_admission` | `none` |
| `serve.models[].model` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.models[].name` | `stable` | `manifest.serve_model_declarations` | `contract.serve_models_change_desired_deployments` |
| `serve.models[].engine` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].keep_alive` | `preview` | `lifecycle.keep_alive` | `none` |
| `serve.models[].max_context` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].extra_args` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].kv_quant` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].speculative` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].chunked_prefill` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].lora_adapters` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].pinned` | `preview` | `lifecycle.single_node_residency` | `none` |
| `serve.models[].tool_call_parser` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].swap_space_gib` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].cpu_offload_gib` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].max_loras` | `preview` | `engine.managed_launch` | `none` |
| `serve.models[].gguf_file` | `preview` | `artifact.legacy_download` | `none` |
