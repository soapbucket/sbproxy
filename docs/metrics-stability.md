# Metrics stability
*Last modified: 2026-07-19*

*Generated from the executable metric registry. Do not hand-edit; run `cargo run -q -p sbproxy-observe --bin generate-metrics-stability > docs/metrics-stability.md`.*

Every metric SBproxy emits, what writes it, and what we promise about its name.

## Prefixes

Two name prefixes are sanctioned. `sbproxy_` covers the proxy and its gateway surfaces. `mesh_` covers the clustering substrate (membership, replication, and cross-node transport); every `mesh_` family carries `beta` name compatibility while that subsystem is young.

## Support

`stable` means production code increments the metric, proven by a drift guard that resolves the writer against the source tree and requires a call site outside tests.

`config_only` means the family is declared and scraped but nothing increments it. It reads zero, always. No dashboard or alert rule may read one.

## Compatibility

`stable` names will not be renamed or removed without a deprecation period: the replacement ships alongside the original in a minor release, and the original is removed no earlier than the next major. Label sets on stable metrics may gain labels in a minor release; losing one follows the same deprecation path.

`beta` names are functional and may still be renamed or relabeled in a minor release, with a changelog entry.

`alpha` names may be renamed, relabeled, or removed in any release.

## Catalogue

| Metric | Type | Support | Compat | Labels | Description |
| --- | --- | --- | --- | --- | --- |
| `mesh_addr_map_updates_total` | Counter | `stable` | `beta` | `kind` | Peer address map updates driven by gossip learnings, by kind (learned or rewritten). |
| `mesh_anti_entropy_keys_total` | Counter | `stable` | `beta` | `direction` | Records reconciled by replicated-substrate anti-entropy, by push or pull direction. |
| `mesh_anti_entropy_rounds_total` | Counter | `stable` | `beta` | none | Completed replicated-substrate maintenance rounds (handoff, anti-entropy, tombstone GC). |
| `mesh_cold_start_snapshots_total` | Counter | `stable` | `beta` | `outcome` | Snapshots encountered during cold-start hydration, by outcome (merged, stale, corrupt). |
| `mesh_compression_coordination_total` | Counter | `stable` | `beta` | `event` | Mesh compression session coordination contention and rejected updates, by closed event (contention, lease_expiry, stale_version, fence_rejection). |
| `mesh_crypto_decrypt_failed_total` | Counter | `stable` | `beta` | `kind` | Mesh messages dropped because AEAD decryption failed, by crypto boundary (gossip or transport). |
| `mesh_dead_peers_gc_total` | Counter | `stable` | `beta` | none | Dead peers removed from the peer table by the garbage collector. |
| `mesh_dissemination_updates_applied_total` | Counter | `stable` | `beta` | `transition` | Inbound gossip peer updates that changed local peer state, by transition. |
| `mesh_dissemination_updates_ignored_total` | Counter | `stable` | `beta` | `reason` | Inbound gossip peer updates dropped without a local state change, by reason. |
| `mesh_dissemination_updates_sent_total` | Counter | `stable` | `beta` | `kind` | Peer updates piggybacked onto outgoing gossip messages, by carrier (ping or ack). |
| `mesh_enrollment_total` | Counter | `stable` | `beta` | `outcome`, `reason` | One-time cluster enrollment attempts as seen by the enrollment authority, by outcome and bounded failure reason. |
| `mesh_federation_peers` | Gauge | `stable` | `beta` | `state` | Known federation peer clusters, by state. |
| `mesh_federation_pull_total` | Counter | `stable` | `beta` | `outcome` | Federation peer pull attempts, by outcome. |
| `mesh_federation_push_total` | Counter | `stable` | `beta` | `outcome` | Federation leader summary and heartbeat pushes, by outcome. |
| `mesh_gossip_probe_duration_seconds` | Histogram | `stable` | `beta` | `target` | Gossip probe round-trip time to a peer, in seconds. |
| `mesh_gossip_retry_total` | Counter | `stable` | `beta` | `target` | Gossip probe retries against a peer (indirect PING-REQ fan-outs after a direct timeout). |
| `mesh_handoff_keys_total` | Counter | `stable` | `beta` | `outcome` | Replicated records handed off after ring changes, by outcome (moved or retained). |
| `mesh_node_isolated` | Gauge | `stable` | `beta` | `node_id` | 1 while this node is in split-brain quarantine, 0 when healthy. |
| `mesh_owner_route_total` | Counter | `stable` | `beta` | `outcome` | Owner-routed typed-state operations, by routing outcome (local, remote, or unreachable). |
| `mesh_peer_count` | Gauge | `stable` | `beta` | `state` | Peer count by membership state, refreshed each SWIM sweep tick. |
| `mesh_peer_evicted_total` | Counter | `stable` | `beta` | `reason` | Peers evicted from the membership list and hash ring, by reason. |
| `mesh_peer_state_transitions_total` | Counter | `stable` | `beta` | `from`, `to` | SWIM peer state transitions observed locally, by prior and new state. |
| `mesh_persistence_bytes_total` | Counter | `stable` | `beta` | none | Bytes of mesh state written in successful Redis snapshots. |
| `mesh_persistence_snapshots_total` | Counter | `stable` | `beta` | `outcome` | Redis snapshot writes of mesh state, by outcome. |
| `mesh_probe_direct_success_total` | Counter | `stable` | `beta` | `target` | Direct SWIM pings whose ACK arrived inside the timeout window. |
| `mesh_probe_direct_timeout_total` | Counter | `stable` | `beta` | `target` | Direct SWIM pings that timed out and triggered the indirect fallback. |
| `mesh_probe_indirect_success_total` | Counter | `stable` | `beta` | `target` | Indirect PING-REQ probes that resolved the target alive. |
| `mesh_replica_shard_entries` | Gauge | `stable` | `beta` | none | Records held by the local replicated-substrate shard, refreshed each maintenance round. |
| `mesh_replication_read_repairs_total` | Counter | `stable` | `beta` | none | Stale replicas repaired in line by quorum reads. |
| `mesh_replication_writes_total` | Counter | `stable` | `beta` | `outcome` | Replicated substrate writes, by coordinator outcome (acked or quorum_failed). |
| `mesh_tombstone_gc_total` | Counter | `stable` | `beta` | `outcome` | Ack-aware tombstone garbage collection decisions (collected or deferred). |
| `mesh_transport_rpc_duration_seconds` | Histogram | `stable` | `beta` | `op` | Successful cross-node cache RPC duration, by operation. Healthy same-zone means sit well under 5ms; a mean near 40ms is the delayed-ACK/Nagle transport stall signature and warrants an alert. |
| `mesh_transport_rpc_errors_total` | Counter | `stable` | `beta` | `kind` | Cross-node cache RPC failures, by transport phase. |
| `sbproxy_a2a_chain_depth` | Histogram | `stable` | `beta` | `route`, `spec` | Distribution of A2A chain depth observed at the proxy. |
| `sbproxy_a2a_denied_total` | Counter | `stable` | `beta` | `route`, `reason` | A2A hops denied by the a2a policy, labelled by route and reason. |
| `sbproxy_a2a_hops_total` | Counter | `stable` | `beta` | `route`, `spec`, `decision` | A2A hops observed by the proxy, labelled by route, spec, and policy decision. |
| `sbproxy_acme_renewal_duration_seconds` | Histogram | `stable` | `beta` | `result` | ACME renewal full-flow duration, by outcome. |
| `sbproxy_acme_renewals_total` | Counter | `stable` | `beta` | `result` | ACME certificate renewal attempts, by outcome. |
| `sbproxy_active_connections` | Gauge | `stable` | `stable` | none | Current active connections. |
| `sbproxy_agent_budget_decisions_total` | Counter | `stable` | `beta` | `agent_id`, `outcome` | agent_budget policy verdicts, labelled by agent and outcome. |
| `sbproxy_agent_detect_inference_seconds` | Histogram | `stable` | `stable` | none | Agent-detect scorer inference latency in seconds. |
| `sbproxy_agent_detect_score` | Histogram | `stable` | `stable` | none | Agent-detect scorer output score, scaled 0-100. |
| `sbproxy_agent_detect_total` | Counter | `stable` | `stable` | `agent_id`, `provenance` | Agent-detect scorer verdicts by agent id and provenance. |
| `sbproxy_agent_skill_digest_mismatch_total` | Counter | `stable` | `beta` | `skill` | Agent Skills artifact digest mismatches detected at serve time. |
| `sbproxy_ai_audio_seconds_attributed_total` | Counter | `stable` | `beta` | `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id` | AI audio seconds consumed (realtime + audio surfaces), partitioned by attribution tag. |
| `sbproxy_ai_budget_utilization_ratio` | Gauge | `stable` | `stable` | `scope` | Budget utilization as ratio 0-1. |
| `sbproxy_ai_cache_results_total` | Counter | `stable` | `stable` | `provider`, `cache_type`, `result` | AI response cache results. |
| `sbproxy_ai_cascade_tier_outcomes_total` | Counter | `stable` | `beta` | `tier`, `outcome` | Cascade routing tier outcomes (accepted | retry | cost_cap). |
| `sbproxy_ai_compression_duration_seconds` | Histogram | `stable` | `beta` | `tenant_id`, `api_key_id`, `lever`, `outcome`, `backend` | AI context compression lever duration in seconds. |
| `sbproxy_ai_compression_lever_total` | Counter | `stable` | `beta` | `tenant_id`, `api_key_id`, `lever`, `outcome`, `reason`, `backend` | AI context compression lever invocations by closed outcome. |
| `sbproxy_ai_compression_ratio` | Histogram | `stable` | `beta` | `tenant_id`, `api_key_id`, `lever` | Final-to-initial SBproxy token-estimate ratio for applied AI context compression levers. |
| `sbproxy_ai_compression_redis_coordination_total` | Counter | `stable` | `beta` | `event` | Redis compression coordination contention and rejected updates. |
| `sbproxy_ai_compression_request_levers_run` | Histogram | `stable` | `beta` | `tenant_id`, `api_key_id`, `outcome`, `backend` | Number of context compression levers executed per request. |
| `sbproxy_ai_compression_request_tokens_saved` | Histogram | `stable` | `beta` | `tenant_id`, `api_key_id`, `outcome`, `backend` | Initial-to-final reduction in SBproxy's model-aware token estimate once per compression request. |
| `sbproxy_ai_compression_requests_total` | Counter | `stable` | `beta` | `tenant_id`, `api_key_id`, `outcome`, `backend`, `cache_bypass` | Requests that executed a non-empty AI context compression pipeline. |
| `sbproxy_ai_compression_selection_total` | Counter | `stable` | `beta` | `tenant_id`, `source`, `outcome` | AI request compression policy resolutions by closed source and outcome. |
| `sbproxy_ai_compression_state_operation_duration_seconds` | Histogram | `stable` | `beta` | `backend`, `operation`, `outcome` | External AI compression state operation duration in seconds. |
| `sbproxy_ai_compression_state_operations_total` | Counter | `stable` | `beta` | `backend`, `operation`, `outcome` | External AI compression state operations by backend and closed outcome. |
| `sbproxy_ai_compression_tokens_saved_total` | Counter | `stable` | `beta` | `tenant_id`, `api_key_id`, `lever` | Reduction in SBproxy's model-aware token estimate from applied AI context compression levers. |
| `sbproxy_ai_compression_tokens_total` | Counter | `stable` | `beta` | `tenant_id`, `api_key_id`, `lever`, `direction` | SBproxy model-aware token estimates before and after an applied AI context compression lever. |
| `sbproxy_ai_compression_value_cost_saved_micros_total` | Counter | `stable` | `beta` | `tenant_id`, `origin`, `model`, `lever`, `token_count_precision` | Gross known-price target-model input cost avoided by successful AI context compression, in micro-USD. |
| `sbproxy_ai_compression_value_tokens_saved_total` | Counter | `stable` | `beta` | `tenant_id`, `origin`, `model`, `lever`, `token_count_precision` | Estimated target-model input tokens avoided by successful AI context compression. |
| `sbproxy_ai_context_poisoning_findings_total` | Counter | `stable` | `beta` | `rule_id`, `action` | Context-poisoning guardrail findings. |
| `sbproxy_ai_cost_dollars_attributed_total` | Counter | `stable` | `beta` | `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id` | AI cost in USD, partitioned by attribution tag. |
| `sbproxy_ai_cost_saved_micros_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `model` | Micro-USD avoided by a semantic-cache hit. |
| `sbproxy_ai_cost_usd_micros_total` | Counter | `stable` | `beta` | `provider`, `model`, `tenant_id` | Derived AI request cost in micro-USD. |
| `sbproxy_ai_failovers_total` | Counter | `stable` | `beta` | `from_provider`, `to_provider`, `reason` | Provider failover events. |
| `sbproxy_ai_guardrail_blocks_total` | Counter | `stable` | `stable` | `category` | Guardrail block events. |
| `sbproxy_ai_inter_token_latency_seconds` | Histogram | `stable` | `beta` | `provider`, `model` | AI streaming average inter-token latency (TPOT). |
| `sbproxy_ai_lb_decisions_total` | Counter | `stable` | `beta` | `strategy`, `provider` | AI router provider selections by strategy. |
| `sbproxy_ai_native_bypass_total` | Counter | `stable` | `beta` | `inbound_format`, `provider_format` | AI requests that bypassed the hub format round-trip when client format matched provider format. |
| `sbproxy_ai_output_throughput_tokens_per_second` | Histogram | `stable` | `beta` | `provider`, `model` | AI streaming output throughput (completion tokens / generation duration). |
| `sbproxy_ai_price_source_total` | Counter | `stable` | `alpha` | `source` | Cost estimates by the price-table layer that produced the price. |
| `sbproxy_ai_provider_attempts_total` | Counter | `stable` | `beta` | `provider`, `outcome` | AI provider attempts during failover/selection, by provider and outcome. |
| `sbproxy_ai_provider_errors_total` | Counter | `stable` | `stable` | `provider`, `error_kind` | Per-provider AI error events. |
| `sbproxy_ai_ratelimit_rejected_total` | Counter | `stable` | `beta` | `axis`, `key_hash`, `tenant`, `model` | AI gateway rate-limit rejections, partitioned by axis. |
| `sbproxy_ai_realtime_audio_seconds_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `provider`, `direction` | Cumulative audio seconds forwarded over Realtime sessions. |
| `sbproxy_ai_realtime_frames_forwarded_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `provider`, `direction`, `kind` | Cumulative frames forwarded over Realtime sessions. |
| `sbproxy_ai_realtime_session_duration_seconds` | Histogram | `stable` | `stable` | `provider`, `close_reason` | Wall-clock duration of a Realtime WebSocket session, recorded on close. |
| `sbproxy_ai_realtime_sessions_active` | Gauge | `stable` | `stable` | none | Currently open OpenAI Realtime API WebSocket sessions. |
| `sbproxy_ai_request_duration_attributed_seconds` | Histogram | `stable` | `beta` | `provider`, `model`, `surface`, `tenant_id`, `api_key_id` | AI upstream request latency, partitioned by surface + tenant + credential. |
| `sbproxy_ai_request_duration_seconds` | Histogram | `stable` | `beta` | `provider`, `model` | AI request latency. |
| `sbproxy_ai_requests_attributed_total` | Counter | `stable` | `beta` | `provider`, `model`, `surface`, `tenant_id`, `api_key_id`, `outcome` | AI requests partitioned by attribution + outcome. |
| `sbproxy_ai_reversible_redaction_miss_total` | Counter | `stable` | `beta` | `rule` | Reversible PII placeholders that appeared in the upstream response but did not match a request-side capture entry. |
| `sbproxy_ai_semantic_cache_similarity` | Histogram | `stable` | `beta` | `provider` | Cosine similarity of semantic-cache hits. |
| `sbproxy_ai_shadow_inflight` | Gauge | `stable` | `beta` | none | Currently in-flight shadow request tasks supervised by the AI client. |
| `sbproxy_ai_stream_guardrail_skipped_total` | Counter | `stable` | `beta` | `guardrail` | Output guardrails skipped on streaming responses via stream_policy: off. |
| `sbproxy_ai_stream_guardrail_violations_total` | Counter | `stable` | `beta` | `guardrail` | Streaming output guardrail violations, by guardrail type. |
| `sbproxy_ai_surface_request_duration_seconds` | Histogram | `stable` | `stable` | `surface`, `method` | AI request latency partitioned by classified surface. |
| `sbproxy_ai_surface_requests_total` | Counter | `stable` | `stable` | `surface`, `method` | AI gateway requests partitioned by classified surface. |
| `sbproxy_ai_token_estimate_error_ratio` | Histogram | `stable` | `beta` | `model` | Relative error of pre-request token estimate vs upstream usage.prompt_tokens. |
| `sbproxy_ai_tokens_attributed_total` | Counter | `stable` | `beta` | `provider`, `model`, `surface`, `direction`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id` | AI tokens consumed, partitioned by attribution tag. |
| `sbproxy_ai_tokens_saved_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `model`, `kind` | Tokens avoided by a semantic-cache hit. |
| `sbproxy_ai_ttft_seconds` | Histogram | `stable` | `stable` | `provider`, `model` | AI streaming time to first token. |
| `sbproxy_ai_usage_parse_miss_total` | Counter | `stable` | `beta` | `provider`, `surface` | 2xx AI responses on a token surface that carried no parseable usage block (budget debited from an estimate). |
| `sbproxy_ai_wasted_cost_dollars_total` | Counter | `stable` | `beta` | `kind`, `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment` | Estimated USD cost of AI spend classified as wasted. |
| `sbproxy_ai_wasted_tokens_total` | Counter | `stable` | `beta` | `kind`, `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment` | AI tokens classified as wasted, by waste class. |
| `sbproxy_audit_emit_duration_seconds` | Histogram | `stable` | `beta` | `channel`, `outcome` | Wall-clock latency of one audit-channel emission. |
| `sbproxy_auth_results_total` | Counter | `stable` | `stable` | `origin`, `auth_type`, `result` | Auth check results. |
| `sbproxy_boilerplate_stripped_bytes_total` | Counter | `stable` | `beta` | `hostname` | Bytes removed by the boilerplate transform, by hostname. |
| `sbproxy_bot_auth_directory_fetch_failures_total` | Counter | `stable` | `beta` | `url` | Bot-auth hosted key-directory fetches that failed (the verifier serves stale or fails per nonce_policy). |
| `sbproxy_bot_auth_nonce_replay_total` | Counter | `stable` | `beta` | `policy` | Web Bot Auth signatures rejected (or logged) because the nonce was already observed. |
| `sbproxy_bytes_total` | Counter | `stable` | `stable` | `origin`, `direction` | Bytes transferred. |
| `sbproxy_cache_reserve_evictions_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve explicit deletions. |
| `sbproxy_cache_reserve_hits_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve hits served after a hot-cache miss. |
| `sbproxy_cache_reserve_misses_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve misses (hot + reserve both empty). |
| `sbproxy_cache_reserve_writes_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve writes (admitted entries). |
| `sbproxy_cache_results_total` | Counter | `stable` | `beta` | `origin`, `result` | HTTP response cache outcomes (hit or miss), by origin. |
| `sbproxy_capture_budget_dropped_total` | Counter | `stable` | `beta` | `workspace`, `dimension` | Capture envelope dimensions dropped because the per-workspace budget was exhausted. |
| `sbproxy_capture_dropped_total` | Counter | `stable` | `beta` | `workspace`, `dimension`, `reason` | Capture envelope dimensions dropped during capture, by reason. |
| `sbproxy_cert_expiry_seconds` | Gauge | `stable` | `beta` | none | Seconds until the active certificate for the host expires; negative when expired. |
| `sbproxy_circuit_breaker_transitions_total` | Counter | `stable` | `beta` | `origin`, `from_state`, `to_state` | Circuit breaker state transitions, by origin and from/to state. |
| `sbproxy_clock_skew_seconds` | Gauge | `config_only` (nothing emits this yet) | `alpha` | none | Local clock offset from the SNTP reference, in seconds. |
| `sbproxy_compression_decisions_total` | Counter | `stable` | `beta` | `codec`, `result` | Compression middleware decisions, by codec and outcome. |
| `sbproxy_compression_ratio` | Histogram | `stable` | `beta` | `codec` | Achieved compression ratio (post_size / pre_size) when compression was applied. |
| `sbproxy_config_reload_total` | Counter | `stable` | `beta` | `result` | Config reload attempts, by result. |
| `sbproxy_errors_total` | Counter | `stable` | `beta` | `hostname`, `error_type` | Total errors. |
| `sbproxy_governance_fail_open_total` | Counter | `stable` | `beta` | `key_id` | Governed admissions that bypassed reservation because the governance backend was unavailable and failure_mode is allow_unreserved. |
| `sbproxy_grpc_status_total` | Counter | `stable` | `beta` | `code` | Observed gRPC status codes, by canonical name. |
| `sbproxy_hooks_channel_dropped_total` | Counter | `stable` | `beta` | `reason` | Bounded channel sends dropped on the hot path, labelled by drop reason. |
| `sbproxy_http_framing_blocks_total` | Counter | `stable` | `beta` | `reason`, `tenant` | Requests rejected by the http_framing policy (request smuggling defense). |
| `sbproxy_idempotency_cache_duration_seconds` | Histogram | `stable` | `beta` | `backend` | Idempotency cache lookup duration, by backend. |
| `sbproxy_idempotency_cache_results_total` | Counter | `stable` | `beta` | `backend`, `result` | Idempotency cache outcomes, by backend and result. |
| `sbproxy_inference_duration_seconds` | Histogram | `stable` | `beta` | `kind`, `backend`, `model` | Local inference latency in seconds. |
| `sbproxy_inference_requests_total` | Counter | `stable` | `beta` | `kind`, `backend`, `model`, `result` | Local inference call counts. |
| `sbproxy_judge_budget_exhausted_total` | Counter | `stable` | `beta` | `tenant` | Judge calls denied because the per-tenant budget was empty. |
| `sbproxy_judge_calls_total` | Counter | `stable` | `beta` | `provider`, `verdict`, `cached` | Judge backend invocations. |
| `sbproxy_judge_cost_usd` | Counter | `stable` | `beta` | `provider` | Judge backend cost per decision in USD. |
| `sbproxy_judge_latency_seconds` | Histogram | `stable` | `beta` | `provider`, `cached` | Judge backend round-trip latency. |
| `sbproxy_jwks_unknown_kid_refetch_total` | Counter | `stable` | `beta` | `result` | JWKS refreshes triggered by tokens whose kid was absent from the local cache. |
| `sbproxy_label_cardinality_overflow_per_tenant_total` | Counter | `stable` | `beta` | `metric`, `label`, `tenant_id` | Per-tenant overflow demotions (`sbproxy_label_cardinality_overflow_total` with the tenant_id label). |
| `sbproxy_label_cardinality_overflow_total` | Counter | `stable` | `beta` | `metric`, `label` | Number of label values demoted to __other__ because the per-label budget was exhausted. |
| `sbproxy_ledger_redeem_duration_seconds` | Histogram | `stable` | `beta` | `host`, `outcome` | Wall-clock latency of a single ledger token redemption. |
| `sbproxy_managed_replica_attempts_total` | Counter | `stable` | `beta` | `provider`, `deployment`, `route_class`, `outcome` | Managed model replica attempts by provider, deployment, route class, and bounded outcome. |
| `sbproxy_managed_replica_failovers_total` | Counter | `stable` | `beta` | `provider`, `deployment`, `reason` | Safe pre-output managed replica handovers by provider, deployment, and bounded reason. |
| `sbproxy_mcp_federation_peers_up` | Gauge | `stable` | `beta` | none | Live MCP federation peers as of the last refresh. |
| `sbproxy_mcp_policy_hook_invocations_total` | Counter | `stable` | `beta` | `verdict`, `mcp_server`, `tool_name` | MCP pre-tool-call policy hook invocations by verdict, upstream MCP server, and tool. |
| `sbproxy_mcp_resource_fetch_total` | Counter | `stable` | `beta` | `result` | MCP resource-fetch attempts, by outcome. |
| `sbproxy_mcp_tool_compat_verdicts_total` | Counter | `stable` | `beta` | `grade`, `outcome` | Tool-versioning oracle verdicts, by computed grade and outcome. |
| `sbproxy_mcp_tool_cost_usd_total` | Counter | `stable` | `beta` | `tool`, `server` | MCP tool-call cost in USD, by tool and owning server. |
| `sbproxy_mcp_tool_dispatch_duration_seconds` | Histogram | `stable` | `beta` | `tool` | MCP tool dispatch duration, by tool name. |
| `sbproxy_mcp_tool_dispatch_total` | Counter | `stable` | `beta` | `tool`, `result` | MCP tool dispatch attempts, by tool name and outcome. |
| `sbproxy_mcp_tool_version_calls_total` | Counter | `stable` | `beta` | `tool`, `version`, `via`, `deprecated` | Rollout-plane tool calls, by tool, served version, resolution rung, and deprecation. |
| `sbproxy_mcp_upstream_io_failures_total` | Counter | `stable` | `beta` | `kind` | MCP upstream IO failures absorbed by deadlines and byte caps, by kind. |
| `sbproxy_metrics_render_failures_total` | Counter | `stable` | `beta` | `reason` | Failures to encode the Prometheus scrape body. |
| `sbproxy_mirror_state_drift_total` | Counter | `stable` | `beta` | none | Times the mirror_pending slot was unexpectedly empty when the pipeline tried to fire a shadow request. |
| `sbproxy_model_host_active_requests` | Gauge | `stable` | `beta` | `deployment` | Requests holding an active managed-model permit. |
| `sbproxy_model_host_admission_rejections_total` | Counter | `stable` | `beta` | `deployment`, `priority`, `reason` | Managed-model admission rejections by deployment, priority, and reason. |
| `sbproxy_model_host_deployment_state` | Gauge | `stable` | `beta` | `deployment`, `engine`, `state` | One-hot managed-model deployment lifecycle state. |
| `sbproxy_model_host_ensure_failures_total` | Counter | `stable` | `alpha` | `reason` | Model ensure-ready failures by reason. |
| `sbproxy_model_host_evictions_total` | Counter | `stable` | `alpha` | `reason` | Model evictions by reason. |
| `sbproxy_model_host_gpu_memory_occupancy` | Gauge | `stable` | `beta` | `device` | GPU occupied-memory fraction (0.0-1.0), by device. |
| `sbproxy_model_host_gpu_utilization` | Gauge | `stable` | `alpha` | `device` | GPU compute utilization fraction (0.0-1.0), by device. |
| `sbproxy_model_host_gpu_vram_bytes` | Gauge | `stable` | `alpha` | `device`, `kind` | GPU memory in bytes, by device and kind (total/free). |
| `sbproxy_model_host_launches_total` | Counter | `stable` | `alpha` | `engine`, `model`, `outcome` | Engine launch attempts by engine, model, and outcome. |
| `sbproxy_model_host_load_queue_depth` | Gauge | `config_only` (nothing emits this yet) | `alpha` | `model` | Requests queued while a model loads, by model. |
| `sbproxy_model_host_lora_evictions_total` | Counter | `stable` | `alpha` | none | LoRA adapters evicted from a base engine's cache to make room. |
| `sbproxy_model_host_lora_loads_total` | Counter | `stable` | `alpha` | none | LoRA adapters loaded onto a base engine (dynamic-paging cache misses). |
| `sbproxy_model_host_queued_requests` | Gauge | `stable` | `beta` | `deployment` | Requests waiting in a managed-model admission queue. |
| `sbproxy_model_host_resident_adapters` | Gauge | `stable` | `alpha` | none | LoRA adapters currently loaded across all base engines. |
| `sbproxy_model_host_resident_models` | Gauge | `stable` | `alpha` | none | Local models currently loaded and Ready. |
| `sbproxy_model_host_time_to_ready_seconds` | Histogram | `stable` | `alpha` | `engine`, `model` | Time from engine launch to Ready, by engine and model. |
| `sbproxy_model_host_weight_download_bytes_total` | Counter | `stable` | `alpha` | none | Bytes downloaded by model-host weight pre-fetches. |
| `sbproxy_model_host_weight_download_failures_total` | Counter | `stable` | `alpha` | none | Model-host weight pre-fetches that failed. |
| `sbproxy_model_host_weight_download_seconds` | Histogram | `stable` | `alpha` | none | Model-host weight pre-fetch duration in seconds. |
| `sbproxy_model_plane_peer_dispatch_seconds` | Histogram | `stable` | `beta` | `outcome` | Private model-plane peer dispatch duration to response headers by outcome. |
| `sbproxy_model_plane_rejections_total` | Counter | `stable` | `beta` | `code`, `retry_class` | Private model-plane request refusals by bounded code and retry class. |
| `sbproxy_model_plane_stream_cancellations_total` | Counter | `stable` | `beta` | `route_class` | Managed response streams dropped before completion by route class. |
| `sbproxy_mtls_cert_cache_evictions_total` | Counter | `stable` | `beta` | none | Number of mTLS client cert metadata entries evicted by the LRU bound. |
| `sbproxy_mtls_handshake_total` | Counter | `stable` | `beta` | `result` | mTLS client-certificate verification outcomes. |
| `sbproxy_object_authz_violations_total` | Counter | `stable` | `beta` | `origin`, `kind` | Object/function-level authorization violations, by kind (bola, bfla, enumeration). |
| `sbproxy_ocsp_fetch_total` | Counter | `stable` | `beta` | `result` | OCSP fetch attempts, by outcome. |
| `sbproxy_ocsp_staple_age_seconds` | Gauge | `stable` | `beta` | `host` | Age of the cached OCSP staple for the host, in seconds. |
| `sbproxy_operator_leader_is_leader` | Gauge | `stable` | `beta` | none | 1 when this operator replica currently holds the leader lease. |
| `sbproxy_operator_leader_transitions_total` | Counter | `stable` | `beta` | `result` | Leader-election lifecycle events on this replica. |
| `sbproxy_operator_reconcile_duration_seconds` | Histogram | `stable` | `beta` | `kind` | Operator reconcile duration, by CRD kind. |
| `sbproxy_operator_reconcile_total` | Counter | `stable` | `beta` | `kind`, `result` | Operator reconcile attempts, by CRD kind and outcome. |
| `sbproxy_origin_active_connections` | Gauge | `stable` | `beta` | `origin` | In-flight requests per origin. |
| `sbproxy_origin_request_duration_seconds` | Histogram | `stable` | `beta` | `origin`, `method`, `status` | Request latency per origin. |
| `sbproxy_origin_requests_total` | Counter | `stable` | `beta` | `origin`, `method`, `status` | Total HTTP requests per origin. |
| `sbproxy_outbound_request_duration_seconds` | Histogram | `stable` | `beta` | `host`, `method`, `status` | Wall-clock latency of one outbound upstream request. |
| `sbproxy_outbound_webhook_attempts_total` | Counter | `stable` | `beta` | `tenant_id`, `event_type`, `result` | Outbound webhook delivery attempts grouped by tenant, event type, and result. |
| `sbproxy_phase_duration_seconds` | Histogram | `stable` | `stable` | `phase`, `origin` | Intra-request phase duration, partitioned by phase + origin. |
| `sbproxy_plugin_init_duration_seconds` | Histogram | `stable` | `beta` | `kind`, `plugin`, `result` | Plugin factory init duration, by kind, plugin name, and outcome. |
| `sbproxy_plugin_init_total` | Counter | `stable` | `beta` | `kind`, `plugin`, `result` | Plugin factory init attempts, by kind, plugin name, and outcome. |
| `sbproxy_plugin_registered_total` | Counter | `stable` | `beta` | `kind`, `plugin` | Known plugin registrations, by kind and plugin name. |
| `sbproxy_policy_audit_events_dropped_total` | Counter | `stable` | `beta` | `tenant` | Policy verdict audit events dropped because the bus queue was full. |
| `sbproxy_policy_audit_events_total` | Counter | `stable` | `beta` | `verdict`, `surface`, `policy_id` | Policy decisions emitted on the audit event bus, labelled by verdict, surface, and policy_id. |
| `sbproxy_policy_decision_duration_seconds` | Histogram | `stable` | `beta` | `surface` | Wall-clock latency of policy decisions. |
| `sbproxy_policy_evaluation_duration_seconds` | Histogram | `stable` | `beta` | `origin`, `verdict` | Wall-clock latency of one full policy-chain evaluation. |
| `sbproxy_policy_triggers_total` | Counter | `stable` | `stable` | `origin`, `policy_type`, `action`, `agent_id`, `agent_class` | Policy enforcement results. |
| `sbproxy_projection_render_failures_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `projection` | Well-known projection render failures, by projection. |
| `sbproxy_rate_limit_decisions_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `policy`, `result` | Rate-limit middleware decisions, by policy and outcome. |
| `sbproxy_rate_limit_suspend_total` | Counter | `stable` | `beta` | `workspace` | Workspace auto-suspend transitions. |
| `sbproxy_rate_limit_total` | Counter | `stable` | `beta` | `workspace`, `result` | Workspace rate-limit budget outcomes by workspace and result (soft/throttle). |
| `sbproxy_redis_kv_connections_total` | Counter | `stable` | `beta` | `result` | Redis KV connection attempts by result. |
| `sbproxy_redis_kv_operation_duration_seconds` | Histogram | `stable` | `beta` | `operation` | Redis KV operation duration in seconds. |
| `sbproxy_redis_kv_operation_errors_total` | Counter | `stable` | `beta` | `operation`, `reason` | Redis KV operation failures by operation and reason. |
| `sbproxy_request_duration_seconds` | Histogram | `stable` | `stable` | `hostname` | Request latency. |
| `sbproxy_requests_total` | Counter | `stable` | `stable` | `hostname`, `method`, `status`, `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape` | Total HTTP requests. |
| `sbproxy_response_body_bytes` | Histogram | `stable` | `beta` | `direction` | Response body size, by compression direction. |
| `sbproxy_script_compile_total` | Counter | `stable` | `beta` | `engine`, `result` | Script-engine compile attempts, by engine and outcome. |
| `sbproxy_script_duration_seconds` | Histogram | `stable` | `beta` | `engine` | Script-engine invocation duration, by engine. |
| `sbproxy_script_invocations_total` | Counter | `stable` | `beta` | `engine`, `result` | Script-engine invocations, by engine and outcome. |
| `sbproxy_script_reloads_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `engine`, `result` | Script-engine hot-reload events, by engine and outcome. |
| `sbproxy_semantic_cache_results_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `source`, `result` | Semantic-cache hit/miss/error counts. |
| `sbproxy_serve_lane_admissions_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `priority`, `decision` | Served-lane admission gate decisions by priority lane. |
| `sbproxy_silent_degradations_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `op` | Best-effort operations that failed and were previously dropped silently, by op. |
| `sbproxy_sink_install_failures_total` | Counter | `stable` | `beta` | none | Failed installs of the process-wide telemetry sink dispatcher. |
| `sbproxy_synthetic_probe_failures_total` | Counter | `stable` | `beta` | `reason` | Synthetic readiness probe failures by reason. |
| `sbproxy_telemetry_dropped_total` | Counter | `stable` | `beta` | `kind`, `reason` | Telemetry records dropped or sinks that failed to set up, by kind and reason. |
| `sbproxy_tokens_attributed_total` | Counter | `stable` | `beta` | `project`, `user`, `tag`, `direction` | AI token usage attributed to a credential's project / user / tag. |
| `sbproxy_transport_duration_seconds` | Histogram | `config_only` (nothing emits this yet) | `alpha` | `protocol`, `result` | Transport-layer request duration, by protocol and outcome. |
| `sbproxy_transport_requests_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `protocol`, `result` | Transport-layer requests, by protocol and outcome. |
| `sbproxy_unrouted_requests_total` | Counter | `stable` | `beta` | `reason` | Requests rejected before origin resolution, by reason. |
| `sbproxy_vault_resolution_duration_seconds` | Histogram | `stable` | `beta` | `backend`, `result` | Vault resolution duration, by backend and outcome. |
| `sbproxy_vault_resolution_total` | Counter | `stable` | `beta` | `backend`, `result` | Vault resolution attempts, by backend and outcome. |
| `sbproxy_waf_persistent_blocks_total` | Counter | `stable` | `beta` | `origin`, `tenant`, `event`, `key_kind` | WAF persistent (time-boxed) block actions, by lifecycle event and key kind. |
