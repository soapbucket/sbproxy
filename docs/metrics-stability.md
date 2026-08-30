# Metrics stability
*Last modified: 2026-08-28*

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

## Deprecation schedule

The tiers above say what may change. This says when, so a cost report built on a `stable` name can be planned around rather than hoped for.

A `stable` metric name, or a label on one, is retired in four steps, and every step is visible from outside this repository:

1. The replacement family ships in a minor release and writes alongside the original. Both carry the same values for the whole window.
2. That same release marks the original deprecated here and in its changelog entry, naming the replacement and the earliest release that may remove it.
3. The window stays open for at least two further minor releases and at least 90 days, whichever ends later.
4. Removal lands in a major release. Never a minor, never a patch.

Gaining a label is not a deprecation and opens no window: new labels go on the end of the set, every existing query keeps matching, and the release notes it. Removing or reordering one renames every series in the family, so it takes all four steps above.

`beta` and `alpha` names get no window at all. A `beta` name changes with a changelog entry in the release that changes it; an `alpha` name changes without one.

The set of `stable` names, and the label prefix each one carried at promotion, is frozen in a build guard, so a rename, a removal, or a label reorder fails the build rather than waiting on review to notice.

## Catalog

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
| `mesh_transport_inbound_rejected_total` | Counter | `stable` | `beta` | `reason` | Inbound cache RPC connections refused or torn down by an admission or deadline bound, by reason (connection_limit, handshake_timeout, handshake_failed, idle_timeout, frame_timeout, write_timeout). Any sustained connection_limit rate means peers are being turned away; the peer address is in the log line, never in a label. |
| `mesh_transport_rpc_duration_seconds` | Histogram | `stable` | `beta` | `op` | Successful cross-node cache RPC duration, by operation. Healthy same-zone means sit well under 5ms; a mean near 40ms is the delayed-ACK/Nagle transport stall signature and warrants an alert. |
| `mesh_transport_rpc_errors_total` | Counter | `stable` | `beta` | `kind` | Cross-node cache RPC failures, by transport phase. The five timeout_ kinds (timeout_lock, timeout_connect, timeout_tls, timeout_write, timeout_read) are the deadline half of the same set: a peer that answered with nothing rather than with a refusal. |
| `sbproxy_a2a_chain_depth` | Histogram | `stable` | `beta` | `route`, `spec` | Distribution of A2A chain depth observed at the proxy. |
| `sbproxy_a2a_denied_total` | Counter | `stable` | `beta` | `route`, `reason` | A2A hops denied by the a2a policy, labeled by route and reason. |
| `sbproxy_a2a_hops_total` | Counter | `stable` | `beta` | `route`, `spec`, `decision` | A2A hops observed by the proxy, labeled by route, spec, and policy decision. |
| `sbproxy_a2a_methods_total` | Counter | `stable` | `beta` | `route`, `method` | A2A 1.0 JSON-RPC methods observed by the proxy, labeled by route and method. |
| `sbproxy_agent_registry_entries` | Gauge | `stable` | `beta` | `collection` | Agents the registry currently knows about, by collection: the verified catalog, or one of the registration queue's four states. |
| `sbproxy_agent_registry_operations_total` | Counter | `stable` | `beta` | `op`, `outcome` | Agent registry and registration-queue operations by operation and outcome, including every refusal the queue's state machine and the feed verifier produce. |
| `sbproxy_acme_renewal_duration_seconds` | Histogram | `stable` | `beta` | `result` | ACME renewal full-flow duration, by outcome. |
| `sbproxy_acme_renewals_total` | Counter | `stable` | `beta` | `result` | ACME certificate renewal attempts, by outcome. |
| `sbproxy_action_abtest_variant_selected_total` | Counter | `stable` | `alpha` | `origin`, `variant` | abtest action variant selections, by origin and configured variant name. |
| `sbproxy_action_https_proxy_decisions_total` | Counter | `stable` | `alpha` | `origin`, `decision` | https_proxy action allow/deny decisions, by origin and decision. |
| `sbproxy_active_connections` | Gauge | `stable` | `stable` | none | Current active connections. |
| `sbproxy_admin_request_export_rows_total` | Counter | `stable` | `beta` | `format` | Rows written by admin request-log exports, by format. |
| `sbproxy_admin_request_exports_total` | Counter | `stable` | `beta` | `format` | Admin request-log exports served, by format. |
| `sbproxy_admin_chargeback_export_refusals_total` | Counter | `stable` | `beta` | `format`, `reason` | Admin chargeback export refusals, by format and closed reason. |
| `sbproxy_agent_budget_decisions_total` | Counter | `stable` | `beta` | `agent_id`, `outcome` | agent_budget policy verdicts, labeled by agent and outcome. |
| `sbproxy_agent_detect_inference_seconds` | Histogram | `stable` | `stable` | none | Agent-detect scorer inference latency in seconds. |
| `sbproxy_agent_detect_score` | Histogram | `stable` | `stable` | none | Agent-detect scorer output score, scaled 0-100. |
| `sbproxy_agent_detect_total` | Counter | `stable` | `stable` | `agent_id`, `provenance` | Agent-detect scorer verdicts by agent id and provenance. |
| `sbproxy_agent_reputation_score` | Gauge | `stable` | `beta` | `tenant_id`, `agent_class` | Agent-class reputation in [0.0, 1.0] over the anomaly detector's rolling window; 1.0 is a class that has produced nothing. |
| `sbproxy_agent_skill_digest_mismatch_total` | Counter | `stable` | `beta` | `skill` | Agent Skills artifact digest mismatches detected at serve time. |
| `sbproxy_aggregate_compose_duration_seconds` | Histogram | `stable` | `beta` | none | Wall-clock time for one aggregation round, fetches included. |
| `sbproxy_aggregate_entries` | Gauge | `stable` | `beta` | `outcome` | origin_sources entries by the outcome of the last aggregation round. |
| `sbproxy_aggregate_published_revision` | Gauge | `stable` | `beta` | none | Config-authority revision the aggregator last published. |
| `sbproxy_aggregate_rounds_total` | Counter | `stable` | `beta` | `outcome` | Aggregation rounds by what the round decided to do. |
| `sbproxy_ai_admission_decisions_total` | Counter | `stable` | `beta` | `surface`, `reason`, `outcome` | Pre-provider AI gateway admission decisions: a request refused at the inbound native-format shim before any provider saw it, by inbound surface and bounded reason code. |
| `sbproxy_ai_audio_seconds_attributed_total` | Counter | `stable` | `beta` | `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id` | AI audio seconds consumed (realtime + audio surfaces), partitioned by attribution tag. |
| `sbproxy_ai_budget_utilization_ratio` | Gauge | `stable` | `stable` | `scope` | Budget utilization as a fraction of the limit; above 1 is over budget. |
| `sbproxy_ai_cache_results_total` | Counter | `stable` | `stable` | `provider`, `cache_type`, `result` | AI response cache results. |
| `sbproxy_ai_cascade_tier_outcomes_total` | Counter | `stable` | `beta` | `tier`, `outcome` | Cascade routing tier outcomes (accepted, retry, cost_cap, credential_lock, data_posture, disabled, not_found, unhealthy). |
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
| `sbproxy_ai_chargeback_entries_evicted_total` | Counter | `stable` | `beta` | `origin` | Raw chargeback entries evicted from bounded in-memory retention, by owning origin. |
| `sbproxy_ai_chargeback_rollups_collapsed_total` | Counter | `stable` | `beta` | `dimension`, `origin` | Chargeback events folded into a bounded overflow rollup by workspace or team dimension, by owning origin. |
| `sbproxy_ai_chargeback_refusals_total` | Counter | `stable` | `beta` | `reason`, `origin` | Chargeback rows refused before exact accounting could commit, by closed reason and owning origin. |
| `sbproxy_ai_chargeback_incomplete_total` | Counter | `stable` | `beta` | `reason`, `origin` | Chargeback incompleteness causes observed on the live record and retention path, by owning origin. |
| `sbproxy_ai_context_poisoning_findings_total` | Counter | `stable` | `beta` | `rule_id`, `action` | Context-poisoning guardrail findings. |
| `sbproxy_ai_context_poisoning_blocked_total` | Counter | `stable` | `beta` | none | Requests blocked by the context-poisoning guardrail (a finding whose configured action is deny). |
| `sbproxy_ai_cost_dollars_attributed_total` | Counter | `stable` | `stable` | `origin`, `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id`, `agent_id` | AI cost in USD, partitioned by attribution tag. |
| `sbproxy_ai_cost_saved_micros_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `model` | Micro-USD avoided by a semantic-cache hit. |
| `sbproxy_ai_cost_usd_micros_total` | Counter | `stable` | `beta` | `provider`, `model`, `tenant_id` | Derived AI request cost in micro-USD. |
| `sbproxy_ai_data_posture_filter_total` | Counter | `stable` | `beta` | `constraint`, `outcome`, `tenant` | AI requests whose provider candidate set the data-posture constraint narrowed (outcome filtered) or refused outright (outcome refused), by resolved tenant. |
| `sbproxy_ai_failovers_total` | Counter | `stable` | `beta` | `from_provider`, `to_provider`, `reason` | Provider failover events. |
| `sbproxy_ai_gateway_decisions_total` | Counter | `stable` | `beta` | `decision`, `reason` | AI gateway admission decisions, including pre-provider rejections. |
| `sbproxy_ai_guardrail_blocks_total` | Counter | `stable` | `stable` | `category` | Guardrail block events. |
| `sbproxy_ai_parallel_moderation_total` | Counter | `stable` | `beta` | `outcome` | Inspect-only input hooks that ran alongside the upstream call, by allow, block, cancelled_upstream, or refused. |
| `sbproxy_ai_safety_guardrail_verdicts_total` | Counter | `stable` | `beta` | `guardrail`, `class`, `backend`, `verdict` | Built-in safety guardrail evaluations by class, backend, and verdict. |
| `sbproxy_ai_external_guardrail_verdicts_total` | Counter | `stable` | `beta` | `provider`, `phase`, `outcome` | External guardrail evaluations by provider, phase, and outcome. |
| `sbproxy_ai_inter_token_latency_seconds` | Histogram | `stable` | `beta` | `provider`, `model` | AI streaming average inter-token latency (TPOT). |
| `sbproxy_ai_intent_detection_source_total` | Counter | `stable` | `beta` | `source` | Intent-detection dispatches by healthy classifier hook, unconfigured heuristic, or degraded heuristic fallback. |
| `sbproxy_ai_quality_routing_decisions_total` | Counter | `stable` | `beta` | `outcome` | Quality-hook routing decisions by selected or fallback outcome. |
| `sbproxy_ai_toolkit_operations_total` | Counter | `stable` | `beta` | `capability`, `outcome` | AI toolkit operations by capability (workflow, evaluation, prompt_rollout) and terminal outcome (success, invalid, unauthorized, not_found, egress_refused, timeout, body_too_large, response_too_large, busy, agent_failed, internal). |
| `sbproxy_classifier_admission_queue` | Gauge | `stable` | `beta` | `cmd` | Rich-sidecar requests currently waiting for a bounded inference slot, by command. |
| `sbproxy_classifier_admission_refusals_total` | Counter | `stable` | `beta` | `cmd`, `reason` | Rich-sidecar requests refused by bounded admission, by command and closed reason. |
| `sbproxy_classifier_attempts_total` | Counter | `stable` | `beta` | `transport`, `cmd` | Rich classifier sidecar request attempts observed at a typed transport boundary. |
| `sbproxy_classifier_client_fallback_total` | Counter | `stable` | `beta` | `reason` | Classifier calls served by the in-process fallback because the configured sidecar did not answer, by closed reason (connect, timeout, rpc, protocol, invalid_request, empty_response). |
| `sbproxy_classifier_completions_total` | Counter | `stable` | `beta` | `transport`, `cmd` | Rich classifier sidecar requests whose successful response reached the transport completion boundary. |
| `sbproxy_classifier_errors_total` | Counter | `stable` | `beta` | `transport`, `cmd`, `reason` | Rich classifier sidecar requests that could not complete, by transport, command, and bounded reason. |
| `sbproxy_classifier_quality_score` | Histogram | `stable` | `beta` | `transport` | Heuristic quality scores returned by the rich classifier sidecar, by transport. |
| `sbproxy_classifier_requests_total` | Counter | `stable` | `beta` | `transport`, `cmd` | Successful rich classifier sidecar requests, by transport and command; an error rate needs `sbproxy_classifier_attempts_total` as its denominator, not this. |
| `sbproxy_classifier_safety_verdicts_total` | Counter | `stable` | `beta` | `verdict` | Per-token streaming safety verdicts emitted by the rich classifier sidecar (`safe`, `blocked`, or `unsafe_continued`). |
| `sbproxy_classifier_startup_owner_info` | Gauge | `stable` | `beta` | `entrypoint`, `owner` | Release entrypoint ownership of the prepared rich-classifier runtime capability. |
| `sbproxy_classifier_terminal_outcomes_total` | Counter | `stable` | `beta` | `transport`, `cmd`, `stage`, `reason` | Rich classifier sidecar requests finalized unsuccessfully, by typed transport, command, stage, and bounded reason. |
| `sbproxy_classifier_tenants` | Gauge | `stable` | `beta` | none | Tenants currently registered with the rich classifier sidecar. |
| `sbproxy_ai_key_fallbacks_total` | Counter | `stable` | `beta` | `provider`, `outcome` | AI provider-key fallback decisions, by the provider entry whose own key was refused and the outcome (`engaged` when the operator's `fallback_credential_id` resolved and the retry was queued, `unavailable` when it did not and the provider's rejection stands). `unavailable` is the alertable one: it means the house credential is broken and the only other evidence is a `401` that reads like the tenant's fault. |
| `sbproxy_ai_lb_decisions_total` | Counter | `stable` | `beta` | `strategy`, `provider` | AI router provider selections by strategy. |
| `sbproxy_ai_license_leak_findings_total` | Counter | `stable` | `beta` | `mode`, `method` | License-leak guardrail confident matches, by the disposition applied (`block`, `redact`, `warn`, `log`) and the detector that fired (`substring`, `heuristic`, `shingle`). Counts every confident match, including the `warn` and `log` dispositions that never reach `sbproxy_ai_guardrail_blocks_total`, so an operator can watch calibration volume on a route before promoting it from `warn` to `block`. Both labels are closed enums, so cardinality is bounded whatever the model returns. |
| `sbproxy_ai_model_group_selections_total` | Counter | `stable` | `alpha` | `group`, `provider` | Named model group member selections: which group a request addressed and which provider's deployment served it. Both labels are operator-declared config names. |
| `sbproxy_ai_prefix_affinity_decisions_total` | Counter | `stable` | `beta` | `outcome` | Prefix-affinity selections by cache-location outcome. |
| `sbproxy_ai_prefix_affinity_evictions_total` | Counter | `stable` | `beta` | `reason` | Entries evicted from the bounded prefix-affinity table. |
| `sbproxy_ai_cache_affinity_decisions_total` | Counter | `stable` | `beta` | `outcome` | Caller-keyed prompt-cache affinity selections by lease outcome. |
| `sbproxy_ai_cache_affinity_evictions_total` | Counter | `stable` | `beta` | `reason` | Leases removed from the bounded prompt-cache affinity table. |
| `sbproxy_ai_service_tier_decisions_total` | Counter | `stable` | `beta` | `disposition` | Upstream attempts whose service tier the operator's provider entry decided. |
| `sbproxy_ai_quota_pool_fail_open_total` | Counter | `stable` | `beta` | `pool` | Quota-pool admissions allowed while the shared backend was unavailable. |
| `sbproxy_ai_quota_pool_overshare_total` | Counter | `stable` | `beta` | `pool` | Soft quota-pool admissions beyond a member entitlement. |
| `sbproxy_ai_routing_fallbacks_total` | Counter | `stable` | `beta` | `strategy`, `reason` | AI routing selections that used an explicit fallback path. |
| `sbproxy_ai_routing_policy_decisions_total` | Counter | `stable` | `beta` | `outcome`, `reason_code` | Operator AI routing-policy decisions by outcome and reason code. |
| `sbproxy_ai_model_directory_exclusions_total` | Counter | `stable` | `alpha` | `exclusion_reason` | Directory nodes excluded from model routing, by exclusion reason. |
| `sbproxy_ai_multipart_inspection_skipped_total` | Counter | `stable` | `beta` | `check`, `surface` | Request-body inspection skipped because the AI request body was multipart, by inspection kind and classified surface. |
| `sbproxy_ai_native_bypass_total` | Counter | `stable` | `beta` | `inbound_format`, `provider_format` | AI requests that bypassed the hub format round-trip when client format matched provider format. |
| `sbproxy_ai_output_throughput_tokens_per_second` | Histogram | `stable` | `beta` | `provider`, `model` | AI streaming output throughput (completion tokens / generation duration). |
| `sbproxy_ai_price_ceiling_total` | Counter | `stable` | `alpha` | `outcome` | Per-request price-ceiling guard outcomes: `candidate_excluded` (a routing candidate priced over the ceiling and dropped), `refused` (every candidate over it, so the request answered 402), `invalid_header` (an unusable `x-sbproxy-max-price`), and `unsupported_surface` (a header ceiling on a surface the estimate cannot price). |
| `sbproxy_ai_price_source_total` | Counter | `stable` | `alpha` | `source` | Cost estimates by the price-table layer that produced the price. |
| `sbproxy_ai_provider_attempts_total` | Counter | `stable` | `beta` | `provider`, `outcome` | AI provider attempts during failover/selection, by provider and outcome (`success`, `error`, `client_disconnected`, `moderation_cancelled`). |
| `sbproxy_ai_provider_cooldowns_total` | Counter | `stable` | `beta` | `provider`, `cause` | Providers parked out of rotation by `resilience.cooldown_policy`, by the classified failure that parked them. The circuit breaker's counterpart for the cooldown axis; without it a rotated credential parks the whole pool on a log line nobody can alert on. |
| `sbproxy_ai_provider_errors_total` | Counter | `stable` | `stable` | `provider`, `error_kind` | Per-provider AI error events. |
| `sbproxy_ai_rag_context_bytes` | Histogram | `stable` | `beta` | none | Bytes of rendered RAG context injected into the request body. |
| `sbproxy_ai_rag_latency_seconds` | Histogram | `stable` | `beta` | `stage`, `provider` | RAG retrieval latency in seconds, by stage (embedding, search, total) and provider. |
| `sbproxy_ai_rag_requests_total` | Counter | `stable` | `beta` | `embedding`, `vector_store`, `outcome` | AI requests that ran RAG retrieval, by embedding provider, vector store, and closed outcome (retrieved, no_match, stale, continued, error). |
| `sbproxy_ai_ratelimit_rejected_total` | Counter | `stable` | `beta` | `axis`, `key_hash`, `tenant`, `model` | AI gateway rate-limit rejections, partitioned by axis. |
| `sbproxy_ai_reasoning_policy_attempts_total` | Counter | `stable` | `beta` | `provider`, `outcome` | AI provider attempts by concise-reasoning policy outcome. |
| `sbproxy_ai_realtime_audio_seconds_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `provider`, `direction` | Cumulative audio seconds forwarded over Realtime sessions. |
| `sbproxy_ai_realtime_frames_forwarded_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `provider`, `direction`, `kind` | Cumulative frames forwarded over Realtime sessions. |
| `sbproxy_ai_realtime_session_duration_seconds` | Histogram | `stable` | `stable` | `provider`, `close_reason` | Wall-clock duration of a Realtime WebSocket session, recorded on close. |
| `sbproxy_ai_realtime_sessions_active` | Gauge | `stable` | `stable` | none | Currently open OpenAI Realtime API WebSocket sessions. |
| `sbproxy_ai_replica_selection_excluded_total` | Counter | `stable` | `alpha` | `stage` | Managed-replica candidates excluded before rendezvous ranking, by stage. |
| `sbproxy_ai_request_duration_attributed_seconds` | Histogram | `stable` | `beta` | `provider`, `model`, `surface`, `tenant_id`, `api_key_id` | AI upstream request latency, partitioned by surface + tenant + credential. |
| `sbproxy_ai_request_duration_seconds` | Histogram | `stable` | `beta` | `provider`, `model` | AI request latency. |
| `sbproxy_ai_request_timeout_override_total` | Counter | `stable` | `alpha` | `outcome` | Per-request `x-sbproxy-timeout-ms` outcomes: `applied` (honored, replacing the provider's `timeout_ms`), `ignored_override_disabled` (the origin has not opted in, so the header was dropped), `over_ceiling` (above `max_request_timeout_ms`, refused with 400 rather than clamped), `invalid_header` (not a positive integer, refused with 400). |
| `sbproxy_ai_requests_attributed_total` | Counter | `stable` | `beta` | `origin`, `provider`, `model`, `surface`, `tenant_id`, `api_key_id`, `outcome` | AI requests partitioned by attribution + outcome. |
| `sbproxy_ai_reversible_redaction_miss_total` | Counter | `stable` | `beta` | `rule` | Reversible PII placeholders that appeared in the upstream response but did not match a request-side capture entry. |
| `sbproxy_ai_semantic_cache_similarity` | Histogram | `stable` | `beta` | `provider` | Cosine similarity of semantic-cache hits. |
| `sbproxy_ai_semantic_route_decisions_total` | Counter | `stable` | `beta` | `outcome` | Semantic-route selections by decision outcome. |
| `sbproxy_ai_semantic_route_similarity` | Histogram | `stable` | `beta` | `provider` | Best exemplar cosine similarity of scored semantic-route requests. |
| `sbproxy_ai_shadow_dropped_total` | Counter | `stable` | `beta` | `reason` | Configured shadow requests skipped or dropped before dispatch, by closed reason. |
| `sbproxy_ai_shadow_calls_total` | Counter | `stable` | `beta` | `target`, `status_class`, `finish_reason` | Completed shadow evaluation calls by target, status class, and finish reason. |
| `sbproxy_ai_shadow_latency_seconds` | Histogram | `stable` | `beta` | `target` | Shadow evaluation call latency by target, in seconds. |
| `sbproxy_ai_shadow_inflight` | Gauge | `stable` | `beta` | none | Currently in-flight shadow request tasks supervised by the AI client. |
| `sbproxy_ai_shadow_timeout_total` | Counter | `stable` | `beta` | none | Shadow tasks canceled after their wall-clock supervisor timeout. |
| `sbproxy_ai_stream_guardrail_skipped_total` | Counter | `stable` | `beta` | `guardrail` | Output guardrails skipped on streaming responses via stream_policy: off. |
| `sbproxy_ai_stream_guardrail_violations_total` | Counter | `stable` | `beta` | `guardrail` | Streaming output guardrail violations, by guardrail type. |
| `sbproxy_ai_stream_guardrail_decode_fallback_total` | Counter | `stable` | `beta` | none | Streaming chunks where guardrails fell back to raw-frame matching because delta decoding failed. |
| `sbproxy_ai_stream_tool_frames_discarded_total` | Counter | `stable` | `beta` | `cause` | Tool-call frames an enforcing `ai_tool_call` hook or an agent-alignment guard held back that never reached the client, by cause: `blocked` (a guardrail or extension ended the stream, which drops held frames by design) and `unjudged` (the stream ended with a held call the guard session never returned a verdict for). `unjudged` should be zero; a non-zero rate means a client received an assistant turn whose tool call the gateway silently deleted. |
| `sbproxy_ai_stream_post_commit_failures_total` | Counter | `stable` | `alpha` | `provider`, `cause` | Streaming responses that failed after the gateway committed to a provider, by cause: `upstream_timeout` (a transport budget cut a running generation), `upstream_error` (a reset or truncated provider stream), `guardrail` (the gateway ended the stream on an output guardrail or stream-safety verdict), `client_disconnected` (the caller hung up and the relay's next write to it failed), `gateway_error` (the relay's own failure, correlating with no provider error), `abandoned` (the request was dropped before the relay reached an ending of its own). An upstream read failure takes precedence over the other causes. Failover is impossible past the commit point, so these are the failures `sbproxy_ai_failovers_total` can never carry. |
| `sbproxy_ai_surface_request_duration_seconds` | Histogram | `stable` | `stable` | `surface`, `method` | AI request latency partitioned by classified surface. |
| `sbproxy_ai_surface_requests_total` | Counter | `stable` | `stable` | `surface`, `method` | AI gateway requests partitioned by classified surface. |
| `sbproxy_ai_token_estimate_error_ratio` | Histogram | `stable` | `beta` | `model` | Relative error of pre-request token estimate vs upstream usage.prompt_tokens. |
| `sbproxy_ai_tokens_attributed_total` | Counter | `stable` | `stable` | `origin`, `provider`, `model`, `surface`, `direction`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id`, `agent_id` | AI tokens consumed, partitioned by attribution tag. |
| `sbproxy_ai_tokens_saved_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `model`, `kind` | Tokens avoided by a semantic-cache hit. |
| `sbproxy_ai_translation_dropped_total` | Counter | `stable` | `beta` | `surface`, `field` | Request fields dropped while translating an inbound AI body (Anthropic Messages, OpenAI Responses) to the canonical chat shape, by inbound surface and dropped-field class. |
| `sbproxy_ai_ttft_seconds` | Histogram | `stable` | `stable` | `provider`, `model` | AI streaming time to first token. |
| `sbproxy_ai_usage_parse_miss_total` | Counter | `stable` | `beta` | `provider`, `surface`, `usage_source` | 2xx AI responses on a token surface that carried no parseable usage block, by what was billed instead: `estimated` (the gateway's own tokenizer count of the delivered text) or `absent` (nothing could be counted, so nothing was billed). |
| `sbproxy_ai_wasted_cost_dollars_total` | Counter | `stable` | `beta` | `kind`, `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment` | Estimated USD cost of AI spend classified as wasted. |
| `sbproxy_ai_wasted_tokens_total` | Counter | `stable` | `beta` | `kind`, `provider`, `model`, `surface`, `project`, `feature`, `team`, `agent_type`, `environment` | AI tokens classified as wasted, by waste class. |
| `sbproxy_anomaly_detected_total` | Counter | `stable` | `beta` | `kind`, `severity` | Behavioral anomalies flagged by a registered detector hook, by kind and severity. |
| `sbproxy_anomaly_key_budget_spent_total` | Counter | `stable` | `beta` | none | Requests that arrived for an agent class the anomaly detector had no tracking slot for. Non-zero means windows are being displaced, which churns the baseline a `reputation.deny_below` floor reads; a key with no window has no score, and no score is admitted. |
| `sbproxy_anomaly_tracked_keys` | Gauge | `stable` | `beta` | none | (tenant, agent class) pairs the anomaly detector currently holds a 28-day window for. The detector's resident set is this times the per-key window, so it is the figure to size the process against; the cap is 512. |
| `sbproxy_audit_chain_read_total` | Counter | `stable` | `beta` | `channel`, `outcome` | Audit-chain read attempts, by verification outcome (verified, broken, unreadable, denied). |
| `sbproxy_audit_emit_duration_seconds` | Histogram | `stable` | `beta` | `channel`, `outcome` | Wall-clock latency of one audit-channel emission. |
| `sbproxy_audit_write_failures_total` | Counter | `stable` | `beta` | `channel` | Audit emissions that did not reach a sink they were promised, by audit channel; healthy systems read 0. |
| `sbproxy_auth_results_total` | Counter | `stable` | `stable` | `origin`, `auth_type`, `result` | Auth check results. |
| `sbproxy_boilerplate_stripped_bytes_total` | Counter | `stable` | `beta` | `hostname` | Bytes removed by the boilerplate transform, by hostname. |
| `sbproxy_bot_auth_directory_fetch_failures_total` | Counter | `stable` | `beta` | `url` | Bot-auth hosted key-directory fetches that failed (the verifier serves stale or fails per nonce_policy). |
| `sbproxy_bot_auth_nonce_replay_total` | Counter | `stable` | `beta` | `policy` | Web Bot Auth signatures rejected (or logged) because the nonce was already observed. |
| `sbproxy_break_glass_grants_total` | Counter | `stable` | `alpha` | `event` | Break-glass grant transitions, by event (requested, approved, activated, denied, used, expired, reviewed, reviewed_without_roster, refused). |
| `sbproxy_break_glass_open` | Gauge | `stable` | `alpha` | `state` | Break-glass grants currently open, by state (pending_approval, active, awaiting_review). |
| `sbproxy_budget_share_fail_open_total` | Counter | `stable` | `beta` | `op` | Shared budget store operations that failed and fell open to per-instance enforcement, by operation: `read`, `write`, or `mirror_dropped` (a streamed settlement handed its mirror write to a detached task that never ran, which a shutting-down runtime does). |
| `sbproxy_budget_share_unavailable` | Gauge | `stable` | `beta` | none | 1 while shared budget enforcement is degraded to per-instance tracking, 0 when the shared store answered. |
| `sbproxy_bytes_total` | Counter | `stable` | `stable` | `origin`, `direction` | Bytes transferred. |
| `sbproxy_cache_reserve_degraded` | Gauge | `stable` | `beta` | `backend` | Whether the configured Cache Reserve backend is degraded. `backend` is the provider (`memory`, `filesystem`, `redis`, `s3`, `gcs`, `azure`, `local`, or `object_store` for a provider this build does not name), not the client library in front of it. |
| `sbproxy_cache_reserve_errors_total` | Counter | `stable` | `beta` | `origin`, `operation` | Cache Reserve operations the backend refused, by operation (`put`, `get`, `delete`, `sweep`, `init`); the reserve is best-effort, so this is the only signal a failing cold tier gives. `init` under origin `__init__` means the backend never built, which every other reserve family reports as flat zero. |
| `sbproxy_cache_reserve_evictions_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve explicit deletions. |
| `sbproxy_cache_reserve_health_transitions_total` | Counter | `stable` | `beta` | `backend`, `state`, `reason` | Cache Reserve backend health transitions by bounded reason. `backend` carries the same closed provider vocabulary as `sbproxy_cache_reserve_degraded`. |
| `sbproxy_cache_reserve_hits_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve hits served after a hot-cache miss. |
| `sbproxy_cache_reserve_misses_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve misses (hot + reserve both empty). |
| `sbproxy_cache_reserve_writes_total` | Counter | `stable` | `stable` | `origin` | Cache Reserve writes (admitted entries). |
| `sbproxy_cache_results_total` | Counter | `stable` | `beta` | `origin`, `result` | HTTP response cache outcomes (hit or miss), by origin. |
| `sbproxy_capture_budget_dropped_total` | Counter | `stable` | `beta` | `workspace`, `dimension` | Capture envelope dimensions dropped because the per-workspace budget was exhausted. |
| `sbproxy_capture_dropped_total` | Counter | `stable` | `beta` | `workspace`, `dimension`, `reason` | Capture envelope dimensions dropped during capture, by reason. |
| `sbproxy_cert_expiry_seconds` | Gauge | `stable` | `beta` | none | Seconds until the active certificate for the host expires; negative when expired. |
| `sbproxy_cert_store_degraded` | Gauge | `stable` | `beta` | `backend` | 1 when the configured certificate store could not be opened and an in-memory fallback is in use, 0 when the configured backend opened. |
| `sbproxy_circuit_breaker_transitions_total` | Counter | `stable` | `beta` | `origin`, `from_state`, `to_state` | Circuit breaker state transitions, by origin and from/to state. |
| `sbproxy_clock_skew_seconds` | Gauge | `config_only` (nothing emits this yet) | `alpha` | none | Local clock offset from the SNTP reference, in seconds. |
| `sbproxy_comp_marketplace_manifest_serves_total` | Counter | `stable` | `beta` | `outcome` | IAB CoMP marketplace manifest serves, by outcome. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither. |
| `sbproxy_comp_marketplace_quote_requests_total` | Counter | `stable` | `beta` | `outcome` | IAB CoMP marketplace quote outcomes, including the oversize-body refusal. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither. |
| `sbproxy_comp_marketplace_redeem_requests_total` | Counter | `stable` | `beta` | `outcome` | IAB CoMP marketplace redeem outcomes, including the oversize-body refusal. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither. |
| `sbproxy_compression_decisions_total` | Counter | `stable` | `beta` | `codec`, `result` | Compression middleware decisions, by codec and outcome. |
| `sbproxy_compression_ratio` | Histogram | `stable` | `beta` | `codec` | Achieved compression ratio (post_size / pre_size) when compression was applied. |
| `sbproxy_config_authority_announce_total` | Counter | `stable` | `beta` | `result` | Config revision announcements published to the cluster, by result. |
| `sbproxy_config_bundle_age_seconds` | Gauge | `stable` | `beta` | none | Seconds since this node received the config bundle it currently serves. |
| `sbproxy_config_bundle_applied_degraded_total` | Counter | `stable` | `beta` | none | Config bundles applied while at least one subsystem stayed on prior state. |
| `sbproxy_config_bundle_applied_total` | Counter | `stable` | `beta` | none | Config bundles applied with every subsystem reloaded cleanly. |
| `sbproxy_config_bundle_fetch_total` | Counter | `stable` | `beta` | `result` | Config bundle fetch cycles, by result. |
| `sbproxy_config_bundle_gossip_total` | Counter | `stable` | `beta` | `outcome` | Cluster config-revision announcement probes, by outcome. |
| `sbproxy_config_bundle_revision` | Gauge | `stable` | `beta` | none | Authority revision of the config bundle this node currently serves. |
| `sbproxy_config_history_entries` | Gauge | `stable` | `beta` | none | Entries currently held in the config revision ring. |
| `sbproxy_config_lkg_revision` | Gauge | `stable` | `beta` | none | Config ring revision the last-known-good pointer names, or -1 when it names none. |
| `sbproxy_config_soak_verdict_total` | Counter | `stable` | `beta` | `verdict`, `signal` | Config soak outcomes, by verdict and reporting signal. |
| `sbproxy_config_apply_total` | Counter | `stable` | `beta` | `outcome` | Config rollback attempts, by outcome: applied for an operator rollback, reverted for an automatic one after a failed soak, declined for an armed node that decided not to revert, rejected for a refusal. |
| `sbproxy_config_rejected_total` | Counter | `stable` | `beta` | `reason` | Config candidates refused before applying, by reason. |
| `sbproxy_config_fallback_active` | Gauge | `stable` | `beta` | none | 1 while this node serves a config its boot fallback restored from the revision ring. |
| `sbproxy_config_reload_total` | Counter | `stable` | `beta` | `result` | Config reload attempts, by result. |
| `sbproxy_config_revision_info` | Gauge | `stable` | `beta` | `revision`, `digest`, `provenance` | Current entry in the config revision ring; always 1, the revision/digest/provenance are the labels. |
| `sbproxy_config_source_fetch_total` | Counter | `stable` | `beta` | `kind`, `result` | Config source resolutions, by source kind and result. |
| `sbproxy_config_source_revision_info` | Gauge | `stable` | `beta` | `sha` | Commit the config source resolved to; always 1, the commit is the label. |
| `sbproxy_cors_refusals_total` | Counter | `stable` | `beta` | `reason` | Responses the CORS middleware refused to add headers to, by reason. |
| `sbproxy_credential_read_audit_records_total` | Counter | `stable` | `alpha` | `outcome` | Read-audit detail records for credential resolution, by outcome (emitted, suppressed, failed). |
| `sbproxy_credential_read_total` | Counter | `stable` | `alpha` | `outcome` | Credential resolutions counted for the read audit, by outcome (ok, refused, error). Unconditional; the chained detail record is rate limited. |
| `sbproxy_credential_resolution_duration_seconds` | Histogram | `stable` | `beta` | `cache`, `outcome` | Wall-clock latency of one bound-credential resolution, by which cache layer answered and the real outcome. |
| `sbproxy_egress_refused_total` | Counter | `stable` | `beta` | `purpose`, `reason`, `tenant`, `origin` | Outbound dials refused by purpose-scoped egress authorization, by purpose, closed reason, tenant, and origin. |
| `sbproxy_embedded_store_operations_total` | Counter | `stable` | `beta` | `store`, `op`, `outcome` | Embedded key-value store operations, by store, operation, and outcome (ok, error, or a bounded ephemeral store refusing a write at its cap). |
| `sbproxy_event_ingest_events_total` | Counter | `stable` | `beta` | `target`, `outcome` | Request events handed to an optional ingest sink (NATS or ClickHouse), by target and outcome: published, dropped at a full queue, errored, or reconnected. |
| `sbproxy_errors_total` | Counter | `stable` | `beta` | `hostname`, `error_type` | Total errors. |
| `sbproxy_events_dropped_total` | Counter | `stable` | `beta` | `sink`, `reason` | Proxy events the events: egress did not deliver, by sink (file or webhook) and closed reason. |
| `sbproxy_evidence_seq_tenant_cap_total` | Counter | `stable` | `beta` | none | Evidence sequence lookups for a tenant past the tracked-tenant cap, sharing the overflow counter. |
| `sbproxy_ext_authz_decisions_total` | Counter | `stable` | `beta` | `outcome` | External-authorization callout outcomes; `fail_open` counts requests admitted without a decision. |
| `sbproxy_fallback_total` | Counter | `stable` | `beta` | `trigger`, `origin`, `tenant` | fallback_origin responses served, by trigger (`status` when the primary answered with a status listed under `on_status`, `error` when it failed outright and `on_error` caught it), origin, and tenant. A fallback is a degraded response by construction, so its rate is the first number worth alerting on when a primary starts failing; before this the only evidence was a boolean on an access-log row. |
| `sbproxy_federation_entity_statement_verifications_total` | Counter | `stable` | `beta` | `outcome` | OpenID Federation entity-statement JWS verification outcomes, covering both self-signed entity configurations and subordinate statements. Written only when proxy.federation.peer_trust is configured; a deployment that publishes its own statement and verifies nobody leaves this empty. |
| `sbproxy_federation_peer_decisions_total` | Counter | `stable` | `beta` | `outcome` | OpenID Federation peer-trust admission decisions on the proxy request path: trusted when the caller's named entity chained to a pinned anchor and satisfied every required trust mark, refused otherwise. Empty until proxy.federation.peer_trust is configured. |
| `sbproxy_federation_trust_chain_resolutions_total` | Counter | `stable` | `beta` | `outcome` | OpenID Federation trust-chain resolution outcomes, one per resolver call. Written only when proxy.federation.peer_trust is configured; empty on a deployment that publishes its own statement and verifies nobody. |
| `sbproxy_federation_trust_mark_verifications_total` | Counter | `stable` | `beta` | `outcome` | OpenID Federation trust-mark JWS verification outcomes. Offline signature check only; live revocation status is a separate call this crate does not make. Written only when proxy.federation.peer_trust.required_trust_marks names one; empty otherwise. |
| `sbproxy_federation_well_known_cache_remaining_seconds` | Gauge | `stable` | `beta` | none | Remaining lifetime of the entity configuration most recently served from cache, in seconds, sampled on every successful serve. Pinned near zero means the refresh margin is too close to the lifetime for the request rate. |
| `sbproxy_federation_well_known_serves_total` | Counter | `stable` | `beta` | `outcome` | GET /.well-known/openid-federation outcomes. |
| `sbproxy_gateway_reconcile_duration_seconds` | Histogram | `stable` | `beta` | `kind` | Gateway API reconcile latency in seconds, by the Kubernetes resource kind that triggered the pass. Answers whether a reconcile is outrunning the resync interval. |
| `sbproxy_gateway_reconcile_total` | Counter | `stable` | `beta` | `kind`, `result` | Gateway API reconcile attempts, by triggering resource kind and outcome. `kind` is one of GatewayClass, Gateway, HTTPRoute, GRPCRoute, or periodic, so cardinality is bounded by a closed set. |
| `sbproxy_gateway_status_writes_total` | Counter | `stable` | `beta` | `kind`, `result` | Patches to the `/status` subresource, by resource kind and outcome. A rising error count here is usually RBAC missing the status subresource rather than anything wrong with the reconcile. |
| `sbproxy_gateway_watch_errors_total` | Counter | `stable` | `beta` | `kind` | Watch stream errors, by Kubernetes resource kind. Distinct from a reconcile error: these come from the API server connection itself, so a rising count against a flat reconcile count means the controller has gone blind rather than broken. |
| `sbproxy_geoip_lookup_total` | Counter | `stable` | `beta` | `result` | geoip policy lookups, by outcome (hit, miss, no_database, no_client_ip). |
| `sbproxy_governance_fail_open_total` | Counter | `stable` | `beta` | `key_id` | Governed admissions that bypassed reservation because the governance backend was unavailable and failure_mode is allow_unreserved. |
| `sbproxy_grpc_status_total` | Counter | `stable` | `beta` | `code` | Observed gRPC status codes, by canonical name. |
| `sbproxy_hooks_channel_dropped_total` | Counter | `stable` | `beta` | `reason` | Bounded channel sends dropped on the hot path, labeled by drop reason. |
| `sbproxy_http_framing_blocks_total` | Counter | `stable` | `beta` | `reason`, `tenant` | Requests rejected by the http_framing policy (request smuggling defense). |
| `sbproxy_idempotency_cache_duration_seconds` | Histogram | `stable` | `beta` | `backend` | Idempotency cache lookup duration, by backend. |
| `sbproxy_idempotency_cache_results_total` | Counter | `stable` | `beta` | `backend`, `result` | Idempotency cache outcomes, by backend and result. |
| `sbproxy_inbound_key_requests_total` | Counter | `stable` | `beta` | `provider`, `key_mode`, `tenant_id`, `api_key_id` | Requests partitioned by caller credential mode and recognized provider. |
| `sbproxy_inference_duration_seconds` | Histogram | `stable` | `beta` | `kind`, `backend`, `model` | Local inference latency in seconds. |
| `sbproxy_inference_requests_total` | Counter | `stable` | `beta` | `kind`, `backend`, `model`, `result` | Local inference call counts. |
| `sbproxy_judge_budget_exhausted_total` | Counter | `stable` | `beta` | `tenant` | Judge calls denied because the per-tenant budget was empty. |
| `sbproxy_judge_calls_total` | Counter | `stable` | `beta` | `provider`, `verdict`, `cached` | Judge backend invocations. |
| `sbproxy_judge_cost_usd` | Counter | `stable` | `beta` | `provider` | Judge backend cost per decision in USD. |
| `sbproxy_judge_latency_seconds` | Histogram | `stable` | `beta` | `provider`, `cached` | Judge backend round-trip latency. |
| `sbproxy_jwks_unknown_kid_refetch_total` | Counter | `stable` | `beta` | `result` | JWKS refreshes triggered by tokens whose kid was absent from the local cache. |
| `sbproxy_key_cache_invalidation_failures_total` | Counter | `stable` | `alpha` | `scope` | Keystore cache-tier invalidations that did not reach the shared tier or its peers, by scope (key or all). |
| `sbproxy_key_lookup_cache_total` | Counter | `stable` | `beta` | `kind`, `outcome` | Keystore TTL-cache lookups, by record kind and which layer answered (hit, negative_hit, tier_hit, miss, error). |
| `sbproxy_key_operations_total` | Counter | `stable` | `beta` | `operation`, `outcome` | Admin key-lifecycle operations, by operation and by what the handler actually returned (ok, refused, error). |
| `sbproxy_key_policy_stored_rejections_total` | Counter | `stable` | `alpha` | `reason` | Stored key records rejected while lowering to an effective policy, by reason. |
| `sbproxy_key_rotation_age_days` | Gauge | `stable` | `alpha` | `kind` | Days since the oldest record of this kind was minted or rotated, by kind (key, credential). |
| `sbproxy_key_store_outage_total` | Counter | `stable` | `beta` | `entrypoint`, `posture`, `outcome` | Inbound-key resolutions that could not reach the virtual key store, by entrypoint, configured failure posture, and what the posture decided. |
| `sbproxy_key_store_unavailable` | Gauge | `stable` | `beta` | `posture` | 1 while the last inbound-key resolution could not reach the virtual key store; the posture label is what that costs. |
| `sbproxy_kya_verdicts_total` | Counter | `stable` | `beta` | `verdict` | Know Your Agent token verification verdicts; the issuer is deliberately not a label. |
| `sbproxy_label_cardinality_budget` | Gauge | `stable` | `beta` | `label` | Cap the accepted unique values for a label name are counted against. Denominator for sbproxy_label_cardinality_unique_values. |
| `sbproxy_label_cardinality_overflow_per_tenant_total` | Counter | `stable` | `beta` | `metric`, `label`, `tenant_id` | Per-tenant overflow demotions (`sbproxy_label_cardinality_overflow_total` with the tenant_id label). |
| `sbproxy_label_cardinality_overflow_total` | Counter | `stable` | `beta` | `metric`, `label` | Number of label values demoted to __other__ because the per-label budget was exhausted. |
| `sbproxy_label_cardinality_unique_values` | Gauge | `stable` | `beta` | `label` | Unique values a label name has accepted so far. Divided by sbproxy_label_cardinality_budget it gives how close the label is to collapsing new values into __other__, which is a warning the overflow counter can only give after the fact. |
| `sbproxy_lb_zone_locality_total` | Counter | `stable` | `beta` | `origin`, `verdict` | Load-balancer selections the zone-locality stage shaped, by verdict: local (narrowed to the proxy's own zone) or spilled (no same-zone target was healthy, so selection widened across zones). rate(...{verdict="spilled"}[5m]) > 0 is a cross-zone spill in progress, which the debug log and the admin ring cannot report on a release binary with the admin server off. |
| `sbproxy_ledger_redeem_duration_seconds` | Histogram | `stable` | `beta` | `host`, `outcome` | Wall-clock latency of a single ledger token redemption. |
| `sbproxy_managed_replica_attempts_total` | Counter | `stable` | `beta` | `provider`, `deployment`, `route_class`, `outcome` | Managed model replica attempts by provider, deployment, route class, and bounded outcome. |
| `sbproxy_managed_replica_failovers_total` | Counter | `stable` | `beta` | `provider`, `deployment`, `reason` | Safe pre-output managed replica handovers by provider, deployment, and bounded reason. |
| `sbproxy_mcp_federation_peers_up` | Gauge | `stable` | `beta` | none | Live MCP federation peers as of the last refresh. |
| `sbproxy_mcp_gateway_authorize_requests_total` | Counter | `stable` | `beta` | `outcome` | MCP OAuth broker /authorize outcomes. Coarse by design: the per-rejection reason is in the paired decision-event log line, not a second label. |
| `sbproxy_mcp_gateway_decisions_total` | Counter | `stable` | `beta` | `surface`, `decision` | MCP OAuth enforcement decisions that no HTTP status alone reports: the resource server's 401, the per-operation scope refusal and its fail-open twin, the /authorize and /par limiter, the session-capacity refusal, the AS-metadata stale fallback, the device-consent CSRF refusal, an unresolvable client-id metadata document on /authorize or /token, and a URL-shaped client_id longer than this broker accepts on either. The unresolvable case answers a fixed string on the wire, because the detail would name the address a client-chosen URL resolved to, so this counter is the only place its rate is visible. |
| `sbproxy_mcp_gateway_dpop_proofs_total` | Counter | `stable` | `beta` | `outcome` | RFC 9449 DPoP proof verification outcomes at the MCP OAuth broker. |
| `sbproxy_mcp_gateway_revocation_introspection_requests_total` | Counter | `stable` | `beta` | `endpoint`, `outcome` | MCP OAuth broker /revoke and /introspect outcomes, by endpoint. |
| `sbproxy_mcp_gateway_sessions_active` | Gauge | `stable` | `beta` | none | In-flight authorization sessions held by the MCP OAuth broker's in-memory session store. A deployment on the storage-backed store leaves this at zero: counting there needs a SCAN. |
| `sbproxy_mcp_gateway_token_requests_total` | Counter | `stable` | `beta` | `outcome` | MCP OAuth broker /token outcomes. Coarse by design: the per-rejection reason is in the paired decision-event log line, not a second label. |
| `sbproxy_mcp_policy_hook_invocations_total` | Counter | `stable` | `beta` | `verdict`, `mcp_server`, `tool_name` | MCP pre-tool-call policy hook invocations by verdict, upstream MCP server, and tool. |
| `sbproxy_mcp_resource_fetch_total` | Counter | `stable` | `beta` | `result` | MCP resource-fetch attempts, by outcome. |
| `sbproxy_mcp_poison_indicators_total` | Counter | `stable` | `beta` | `field`, `indicator`, `kind` | Static tool-poisoning indicators in advertised MCP tool text, by field and indicator. |
| `sbproxy_mcp_concealed_text_findings_total` | Counter | `stable` | `beta` | `field`, `class`, `kind` | Advertised MCP tool text carrying characters hidden from a reader, by field and class. |
| `sbproxy_mcp_tool_compat_verdicts_total` | Counter | `stable` | `beta` | `grade`, `outcome` | Tool-versioning oracle verdicts, by computed grade and outcome. |
| `sbproxy_mcp_evidence_fail_closed_total` | Counter | `stable` | `beta` | `tenant` | MCP tool calls refused because fail-closed evidence delivery failed, by tenant. |
| `sbproxy_mcp_argument_policy_total` | Counter | `stable` | `beta` | `tenant`, `rule`, `verdict` | MCP argument-policy rule triggers, by tenant, rule name, and verdict. |
| `sbproxy_mcp_flow_total` | Counter | `stable` | `beta` | `tenant`, `rule`, `verdict` | MCP session-flow enforcement triggers, by tenant, rule id, and verdict. |
| `sbproxy_mcp_session_registry_saturated_total` | Counter | `stable` | `beta` | none | MCP session mints refused because the session registry was at capacity, globally or for the caller's tenant. |
| `sbproxy_mcp_peer_registry_saturated_total` | Counter | `stable` | `beta` | none | MCP peer-profile observations that could not be tracked because the peer registry was at capacity, globally or for the caller's tenant. |
| `sbproxy_mcp_tool_quota_registry_saturated_total` | Counter | `stable` | `beta` | none | MCP tools/call refused because the per-tool quota store was at capacity, globally or for the caller's tenant. |
| `sbproxy_mcp_content_filter_total` | Counter | `stable` | `beta` | `tenant`, `category`, `verdict` | MCP content-filter (secrets/pii) triggers, by tenant, category, and verdict. |
| `sbproxy_mcp_result_policy_total` | Counter | `stable` | `beta` | `tenant`, `rule`, `verdict` | MCP result-policy rule triggers, by tenant, rule name, and verdict. |
| `sbproxy_mcp_grant_expired_total` | Counter | `stable` | `beta` | `tenant`, `policy` | MCP tools/call refused because a time-boxed RBAC grant elapsed, by tenant and policy. |
| `sbproxy_mcp_approval_hold_total` | Counter | `stable` | `beta` | `tenant`, `outcome` | MCP tools/call parked for operator approval, by tenant and outcome. |
| `sbproxy_mcp_tool_cost_usd_total` | Counter | `stable` | `beta` | `tool`, `server` | MCP tool-call cost in USD, by tool and owning server. |
| `sbproxy_mcp_tool_dispatch_duration_seconds` | Histogram | `stable` | `beta` | `tool` | MCP tool dispatch duration, by tool name. |
| `sbproxy_mcp_tool_dispatch_total` | Counter | `stable` | `beta` | `tool`, `result` | MCP tool dispatch attempts, by tool name and outcome. |
| `sbproxy_mcp_tool_version_calls_total` | Counter | `stable` | `beta` | `tool`, `version`, `via`, `deprecated` | Rollout-plane tool calls, by tool, served version, resolution rung, and deprecation. |
| `sbproxy_mcp_upstream_io_failures_total` | Counter | `stable` | `beta` | `kind` | MCP upstream IO failures absorbed by deadlines and byte caps, by kind. |
| `sbproxy_meter_append_duration_seconds` | Histogram | `stable` | `beta` | none | Time to append one entry to the meter's signed chain, including lock wait. |
| `sbproxy_meter_chain_gap_total` | Counter | `stable` | `beta` | `tenant_id`, `failure_mode` | Records the meter owed and could not write, by tenant and the posture in force. |
| `sbproxy_meter_chain_seq` | Gauge | `stable` | `beta` | none | Head sequence number of the meter's signed chain. |
| `sbproxy_meter_divergence_total` | Counter | `stable` | `beta` | `tenant_id` | Windows in which counted units and chained units disagreed, by tenant. |
| `sbproxy_meter_incoherent_receipts_total` | Counter | `stable` | `beta` | `tenant_id`, `failure_mode` | Receipts refused on decode because a unit's declared provenance contradicts its evidence, by tenant and the posture in force. |
| `sbproxy_meter_receipts_total` | Counter | `stable` | `beta` | `tenant_id`, `outcome`, `billable` | Metered attempts, by tenant, outcome, and the operator's billing answer for it. |
| `sbproxy_meter_units_total` | Counter | `stable` | `beta` | `tenant_id`, `unit`, `source` | Units the meter counted, by tenant, operator-chosen unit name, and provenance. |
| `sbproxy_metrics_render_failures_total` | Counter | `stable` | `beta` | `reason` | Failures to encode the Prometheus scrape body. |
| `sbproxy_mirror_state_drift_total` | Counter | `stable` | `beta` | none | Times the mirror_pending slot was unexpectedly empty when the pipeline tried to fire a shadow request. |
| `sbproxy_model_host_active_requests` | Gauge | `stable` | `beta` | `deployment` | Requests holding an active managed-model permit. |
| `sbproxy_model_host_admission_rejections_total` | Counter | `stable` | `beta` | `deployment`, `priority`, `reason` | Managed-model admission rejections by deployment, priority, and reason. |
| `sbproxy_model_host_artifact_errors_total` | Counter | `stable` | `alpha` | `artifact_error_kind` | Model artifact acquisition failures by ArtifactError kind. |
| `sbproxy_model_host_deployment_state` | Gauge | `stable` | `beta` | `deployment`, `engine`, `state` | One-hot managed-model deployment lifecycle state. |
| `sbproxy_model_host_ensure_failures_total` | Counter | `stable` | `alpha` | `reason` | Model ensure-ready failures by reason. |
| `sbproxy_model_host_evictions_total` | Counter | `stable` | `alpha` | `reason` | Model evictions by reason. |
| `sbproxy_model_host_gpu_memory_occupancy` | Gauge | `stable` | `beta` | `device` | GPU occupied-memory fraction (0.0-1.0), by device. |
| `sbproxy_model_host_gpu_utilization` | Gauge | `stable` | `alpha` | `device` | GPU compute utilization fraction (0.0-1.0), by device. |
| `sbproxy_model_host_gpu_vram_bytes` | Gauge | `stable` | `alpha` | `device`, `kind` | GPU memory in bytes, by device and kind (total/free). |
| `sbproxy_model_host_launches_total` | Counter | `stable` | `alpha` | `engine`, `model`, `outcome` | Engine launch attempts by engine, model, and outcome. |
| `sbproxy_model_host_load_queue_depth` | Gauge | `stable` | `alpha` | `model` | Requests queued while a model loads, by model. |
| `sbproxy_model_host_lora_evictions_total` | Counter | `stable` | `alpha` | none | LoRA adapters evicted from a base engine's cache to make room. |
| `sbproxy_model_host_lora_loads_total` | Counter | `stable` | `alpha` | none | LoRA adapters loaded onto a base engine (dynamic-paging cache misses). |
| `sbproxy_model_host_placement_rejections_total` | Counter | `stable` | `alpha` | `deployment`, `placement_reason` | Placement plan node rejections by deployment and reason. |
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
| `sbproxy_notify_deliveries_total` | Counter | `stable` | `beta` | `outcome` | Outbound webhook notification deliveries by outcome (delivered, retried, deadlettered, dropped), plus the admin mutations that manage the subscriptions. |
| `sbproxy_notify_queue` | Gauge | `stable` | `beta` | `collection` | Notifier state by collection: configured webhook subscriptions, and deliveries sitting in the deadletter queue. |
| `sbproxy_oauth_introspection_results_total` | Counter | `stable` | `beta` | `result` | RFC 7662 token-introspection results; `cached` is a verdict answered without reaching the authorization server and `no_token` is a request that presented none. |
| `sbproxy_object_authz_enumeration_tracker_saturated_total` | Counter | `stable` | `beta` | none | Enumeration observations the object_authz policy could not track because the per-principal tracker was at capacity with live windows. |
| `sbproxy_object_authz_violations_total` | Counter | `stable` | `beta` | `origin`, `kind`, `enforced` | Object/function-level authorization violations, by kind (bola, bfla, enumeration) and enforcement disposition (enforced=true refused the request; enforced=false was audited only). |
| `sbproxy_ocsp_fetch_total` | Counter | `stable` | `beta` | `result` | OCSP fetch attempts, by outcome. |
| `sbproxy_ocsp_staple_age_seconds` | Gauge | `stable` | `beta` | `host` | Age of the cached OCSP staple for the host, in seconds. Published once a minute by the refresh task; absent until the first successful fetch, so never-stapled is distinguishable from stale. |
| `sbproxy_olp_decisions_total` | Counter | `stable` | `beta` | `endpoint`, `outcome` | RSL Open Licensing Protocol endpoint outcomes by endpoint (`token`, `key`, `introspect`, `revoke`) and outcome (`ok`, `rejected`, `rate_limited`, `error`). `rate_limited` is the per-source token budget on `POST /.well-known/olp/token` refusing a mint; it is its own value rather than a `rejected` so an operator can tell a flood from a broken client. Written by the proxy request path for an origin with an `olp:` block; empty on a deployment that configures none. |
| `sbproxy_operator_leader_is_leader` | Gauge | `stable` | `beta` | none | 1 when this operator replica currently holds the leader lease. |
| `sbproxy_operator_leader_transitions_total` | Counter | `stable` | `beta` | `result` | Leader-election lifecycle events on this replica. |
| `sbproxy_operator_reconcile_duration_seconds` | Histogram | `stable` | `beta` | `kind` | Operator reconcile duration, by CRD kind. |
| `sbproxy_operator_reconcile_total` | Counter | `stable` | `beta` | `kind`, `result` | Operator reconcile attempts, by CRD kind and outcome. |
| `sbproxy_origin_active_connections` | Gauge | `stable` | `beta` | `origin` | In-flight requests per origin. |
| `sbproxy_origin_request_duration_seconds` | Histogram | `stable` | `beta` | `origin`, `method`, `status` | Request latency per origin. |
| `sbproxy_origin_requests_total` | Counter | `stable` | `beta` | `origin`, `method`, `status` | Total HTTP requests per origin. |
| `sbproxy_origin_source_entries` | Gauge | `stable` | `beta` | `tier`, `pinned` | Project repositories declared under origin_sources, by runtime tier and whether the entry is pinned to an immutable revision. |
| `sbproxy_outbound_request_duration_seconds` | Histogram | `stable` | `beta` | `host`, `method`, `status` | Wall-clock latency of one outbound upstream request. |
| `sbproxy_payment_provider_calls_total` | Counter | `stable` | `beta` | `rail`, `operation`, `provider_class` | Payment provider calls that left the process, by rail, operation, and provider class. |
| `sbproxy_payment_rail_enabled` | Gauge | `stable` | `beta` | `rail` | 1 for each settlement rail this build compiled and this configuration registered, 0 otherwise. |
| `sbproxy_payment_recovery_total` | Counter | `stable` | `beta` | `operation`, `outcome` | Durable rows the settlement recovery worker moved, by recovery operation and committed outcome. `outcome="failed"` is the exception and counts sweeps rather than rows: one per sweep of that operation that returned a store error and moved nothing. |
| `sbproxy_payment_settlement_total` | Counter | `stable` | `beta` | `rail`, `operation`, `outcome` | Payment settlement transitions, by rail, deciding step, and outcome. The request-path gate reports `challenge` and `redeem`; the recovery sweep reports the reconciled attempt's own operation. |
| `sbproxy_payment_worker_drain_clean` | Gauge | `stable` | `beta` | none | 1 when the settlement worker drained inside its shutdown deadline, 0 when it was abandoned mid tick. |
| `sbproxy_payment_worker_ticks_total` | Counter | `stable` | `beta` | none | Completed settlement recovery worker ticks. |
| `sbproxy_phase_duration_seconds` | Histogram | `stable` | `stable` | `phase`, `origin` | Intra-request phase duration, partitioned by phase + origin. |
| `sbproxy_plugin_init_duration_seconds` | Histogram | `stable` | `beta` | `kind`, `plugin`, `result` | Plugin factory init duration, by kind, plugin name, and outcome. |
| `sbproxy_plugin_init_total` | Counter | `stable` | `beta` | `kind`, `plugin`, `result` | Plugin factory init attempts, by kind, plugin name, and outcome. |
| `sbproxy_plugin_registered_total` | Counter | `stable` | `beta` | `kind`, `plugin` | Known plugin registrations, by kind and plugin name. |
| `sbproxy_policy_audit_events_dropped_total` | Counter | `stable` | `beta` | `tenant` | Policy verdict audit events dropped because the bus queue was full. |
| `sbproxy_policy_audit_events_total` | Counter | `stable` | `beta` | `verdict`, `surface`, `policy_id` | Policy decisions emitted on the audit event bus, labeled by verdict, surface, and policy_id. |
| `sbproxy_decision_audit_events_dropped_total` | Counter | `stable` | `alpha` | `event`, `tenant` | Decision audit records dropped before publication, by decision event and tenant. |
| `sbproxy_decision_audit_events_total` | Counter | `stable` | `alpha` | `event`, `outcome` | Decision audit records published on the audit bus, by decision event and outcome. |
| `sbproxy_policy_decision_duration_seconds` | Histogram | `stable` | `beta` | `surface` | Wall-clock latency of policy decisions. |
| `sbproxy_policy_evaluation_duration_seconds` | Histogram | `stable` | `beta` | `origin`, `verdict` | Wall-clock latency of one full policy-chain evaluation. |
| `sbproxy_policy_panic_total` | Counter | `stable` | `beta` | `policy` | Policy enforcer panics contained on the serving path, by policy type. |
| `sbproxy_policy_triggers_total` | Counter | `stable` | `stable` | `origin`, `policy_type`, `action`, `agent_id`, `agent_class` | Policy enforcement results. |
| `sbproxy_prompt_injection_blocks_total` | Counter | `stable` | `beta` | `scan_path`, `tenant` | Requests blocked by the prompt_injection_v2 policy, by scan path (header_scan, body_scan, ai_body, a2a). |
| `sbproxy_prompt_injection_classifier_failures_total` | Counter | `stable` | `alpha` | `scan_path`, `action`, `stage`, `reason`, `outcome`, `tenant` | Unavailable prompt-injection classifier stages, with closed failure and policy-outcome labels. |
| `sbproxy_prompt_injection_v2_results_total` | Counter | `stable` | `alpha` | `action`, `label`, `detector` | Body-aware prompt-injection detector results, by action taken, detection label, and detector name. |
| `sbproxy_projection_render_failures_total` | Counter | `stable` | `alpha` | `projection` | Well-known projection render failures, by projection. |
| `sbproxy_rate_limit_cluster_peer_denials_total` | Counter | `stable` | `alpha` | none | Mesh rate-limit denials that needed peer counts, so the approximation is observable. |
| `sbproxy_rate_limit_decisions_total` | Counter | `stable` | `alpha` | `policy`, `result` | Rate-limit middleware decisions, by policy and outcome. |
| `sbproxy_rate_limit_suspend_total` | Counter | `stable` | `beta` | `workspace` | Workspace auto-suspend transitions. |
| `sbproxy_rate_limit_total` | Counter | `stable` | `beta` | `workspace`, `result` | Workspace rate-limit budget outcomes by workspace and result (soft/throttle). |
| `sbproxy_redis_kv_connections_total` | Counter | `stable` | `beta` | `result` | Redis KV connection attempts by result. |
| `sbproxy_redis_kv_operation_duration_seconds` | Histogram | `stable` | `beta` | `operation` | Redis KV operation duration in seconds. |
| `sbproxy_redis_kv_operation_errors_total` | Counter | `stable` | `beta` | `operation`, `reason` | Redis KV operation failures by operation and reason. |
| `sbproxy_request_body_drain_timeout_total` | Counter | `stable` | `beta` | none | Times the post-response drain of a client's request body hit its bound and the connection was closed with bytes unread. |
| `sbproxy_request_duration_seconds` | Histogram | `stable` | `stable` | `hostname` | Request latency. |
| `sbproxy_requests_total` | Counter | `stable` | `stable` | `hostname`, `method`, `status`, `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape` | Total HTTP requests. |
| `sbproxy_response_body_bytes` | Histogram | `stable` | `beta` | `direction` | Response body size, by compression direction. |
| `sbproxy_root_of_trust_liveness` | Gauge | `stable` | `alpha` | none | 1 when the last customer-managed root-of-trust probe reached and was authorized by the external key service, 0 otherwise. |
| `sbproxy_root_of_trust_operations_total` | Counter | `stable` | `alpha` | `operation`, `outcome` | Customer-managed root-of-trust operations, by operation (wrap, unwrap, unwrap_cached) and outcome. |
| `sbproxy_script_compile_total` | Counter | `stable` | `beta` | `engine`, `result` | Script-engine compile attempts, by engine and outcome. |
| `sbproxy_script_duration_seconds` | Histogram | `stable` | `beta` | `engine` | Script-engine invocation duration, by engine. |
| `sbproxy_script_invocations_total` | Counter | `stable` | `beta` | `engine`, `result` | Script-engine invocations, by engine and outcome. |
| `sbproxy_script_reloads_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `engine`, `result` | Script-engine hot-reload events, by engine and outcome. |
| `sbproxy_decision_event_total` | Counter | `stable` | `alpha` | `event`, `engine`, `outcome`, `origin`, `tenant` | Decision events by pipeline point, engine, and outcome. |
| `sbproxy_decision_event_duration_seconds` | Histogram | `stable` | `alpha` | `event`, `engine`, `origin` | Decision event evaluation latency. |
| `sbproxy_decision_event_fail_open_total` | Counter | `stable` | `alpha` | `event`, `engine`, `origin`, `tenant` | Decision events that proceeded without the decision being made. |
| `sbproxy_deprecated_requests_total` | Counter | `stable` | `beta` | `origin`, `route`, `past_sunset`, `outcome` | Requests that resolved to a deprecated route, by request Host, matched announcement, whether the hit landed after the announced sunset, and whether it was served or refused with 410. |
| `sbproxy_semantic_cache_results_total` | Counter | `stable` | `beta` | `tenant`, `origin`, `source`, `result` | Semantic-cache hit/miss/error counts. |
| `sbproxy_serve_lane_admissions_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `priority`, `decision` | Served-lane admission gate decisions by priority lane. |
| `sbproxy_security_headers_csp_emitted_total` | Counter | `stable` | `beta` | `mode`, `tenant` | Content-Security-Policy headers emitted by the security_headers policy, by mode (enforce, report_only). |
| `sbproxy_signature_legacy_derivation_total` | Counter | `stable` | `beta` | `component` | RFC 9421 signatures accepted only against the pre-conformance derivation of a request-target component, by component. |
| `sbproxy_silent_degradations_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `op` | Best-effort operations that failed and were previously dropped silently, by op. |
| `sbproxy_sink_install_failures_total` | Counter | `stable` | `beta` | none | Failed installs of the process-wide telemetry sink dispatcher. |
| `sbproxy_storage_op_duration_seconds` | Histogram | `stable` | `alpha` | `op`, `backend`, `kind` | Latency of storage backend operations, by operation, backend, and record kind. |
| `sbproxy_storage_op_errors_total` | Counter | `stable` | `alpha` | `op`, `backend`, `kind`, `error_kind` | Errors returned by storage backend operations, by operation, backend, record kind, and error variant. |
| `sbproxy_synthetic_probe_failures_total` | Counter | `stable` | `beta` | `reason` | Synthetic readiness probe failures by reason. |
| `sbproxy_target_health_state` | Gauge | `stable` | `beta` | `origin`, `target` | Per-target tri-state health on LiteLLM's 0/1/2 scale: 0 healthy, 1 degraded (circuit breaker half-open), 2 excluded from selection (probe-unhealthy, outlier-ejected, or breaker open). Sampled at scrape time from the same pipeline walk that renders GET /api/health/targets. `origin` is the configured origin id, not the request Host. `target` is the configured target URL, or the load balancer's own url#index identifier when one origin configures that URL more than once. |
| `sbproxy_telemetry_dropped_total` | Counter | `stable` | `beta` | `kind`, `reason` | Telemetry records dropped or sinks that failed to set up, by kind and reason. |
| `sbproxy_tokens_attributed_total` | Counter | `stable` | `beta` | `project`, `user`, `tag`, `direction` | AI token usage attributed to a credential's project / user / tag. |
| `sbproxy_transform_pdf_decode_errors_total` | Counter | `stable` | `alpha` | `error_kind` | pdf_markdown transform decode failures, by the stage that failed (`empty_body`, `document_parse`, `content_extract`). `error_kind` is a closed enum and carries nothing read out of the document. Absent until an origin configures a `pdf_markdown` transform, which needs the optional `transform-pdf` build. |
| `sbproxy_transform_pdf_pages_decoded_total` | Counter | `stable` | `alpha` | none | Pages the pdf_markdown transform successfully projected to Markdown. Unlabeled: `Transform::apply` is handed no origin, and a label that only ever holds one value is worse than none. Absent until an origin configures a `pdf_markdown` transform, which needs the optional `transform-pdf` build. |
| `sbproxy_transport_duration_seconds` | Histogram | `config_only` (nothing emits this yet) | `alpha` | `protocol`, `result` | Transport-layer request duration, by protocol and outcome. |
| `sbproxy_transport_requests_total` | Counter | `config_only` (nothing emits this yet) | `alpha` | `protocol`, `result` | Transport-layer requests, by protocol and outcome. |
| `sbproxy_trust_tier_requests_total` | Counter | `stable` | `beta` | `tier` | Requests partitioned by the conservative trust-tier decision. |
| `sbproxy_unrouted_requests_total` | Counter | `stable` | `beta` | `reason` | Requests rejected before origin resolution, by reason. |
| `sbproxy_upstream_status_retries_total` | Counter | `stable` | `beta` | `origin`, `status` | Upstream retries triggered by a configured response status, by origin and matched status. |
| `sbproxy_upstream_timeout_retries_total` | Counter | `stable` | `beta` | `origin`, `phase` | Upstream retries triggered by a timeout-classed failure, by origin and phase (connect or upstream). |
| `sbproxy_vault_resolution_duration_seconds` | Histogram | `stable` | `beta` | `backend`, `result` | Vault resolution duration, by backend and outcome. |
| `sbproxy_vault_resolution_total` | Counter | `stable` | `beta` | `backend`, `result` | Vault resolution attempts, by backend and outcome. |
| `sbproxy_usage_bridge_enqueued_total` | Counter | `stable` | `beta` | `tenant_id`, `reporter`, `resource_type`, `result` | Billable units the request path queued for a usage reporter, by tenant, reporter, resource type, and whether the row was new. |
| `sbproxy_usage_bridge_gap_total` | Counter | `stable` | `beta` | `tenant_id`, `failure_mode` | Billable units that could not be queued for a usage reporter, by tenant and the posture in force. |
| `sbproxy_user_agent_headless_total` | Counter | `stable` | `beta` | `library` | user_agent_parser policy runs where a headless-automation-library token matched (headless_chrome, phantomjs, puppeteer, playwright, selenium). |
| `sbproxy_user_agent_parse_total` | Counter | `stable` | `beta` | `device_type` | user_agent_parser policy runs, by parsed device_type. |
| `sbproxy_waf_persistent_blocks_total` | Counter | `stable` | `beta` | `origin`, `tenant`, `event`, `key_kind` | WAF persistent (time-boxed) block actions, by lifecycle event and key kind. |
| `sbproxy_websocket_teardowns_total` | Counter | `stable` | `beta` | `reason`, `direction`, `tenant`, `origin` | WebSocket upgrades refused or tunnels torn down by the gateway, by closed reason, direction, tenant, and origin. Covers both upgrade surfaces: the `websocket` action and AI realtime. |
