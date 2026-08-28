# Decision record contract
*Last modified: 2026-08-16*

*Generated from the executable decision contract. Do not hand-edit; run `cargo run -q -p sbproxy-observe --bin generate-decision-contract > docs/decision-records.md`.*

What a consumer may rely on from the decision-audit feed. Retrofitting a field into a shipped record breaks every rule selecting on it, so this page is a promise rather than a description, and a drift guard proves the code still keeps it.

## Coverage

| Event | Publishes | Notes |
| --- | --- | --- |
| `auth` | yes |  |
| `policy` | with `policy_record_format: decision` | Always reaches the audit bus. Under the default `legacy` format it arrives as `policy_verdict_event` on its own prefix instead of on this feed. |
| `rate_limit` | as `policy` | Runs in the policy chain. Select on `unmapped.policy_id`; a separate emitter would put two records on the bus for one decision. |
| `waf` | as `policy` | Runs in the policy chain. Select on `unmapped.policy_id`; a separate emitter would put two records on the bus for one decision. |
| `cache.key` | yes |  |
| `cache.admit` | yes |  |
| `cache.reserve.health` | yes |  |
| `route.decide` | yes |  |
| `ai.guardrail.input` | yes |  |
| `ai.guardrail.output` | yes |  |
| `ai.tool_call` | yes |  |
| `ai.stream.event` | never | Fires once per streamed chunk, so it is refused ahead of both the per-event map and the master switch. `ai.close` carries the stream's summary once instead. |
| `ai.close` | yes |  |
| `ai.failure` | yes |  |
| `ai.admission` | yes |  |
| `transform` | not yet | No emitter. Enabling it publishes nothing. |
| `action` | not yet | No emitter. Enabling it publishes nothing. |
| `log.custom_field` | not yet | No emitter. Enabling it publishes nothing. |
| `mcp.tool` | yes |  |
| `payment.lifecycle` | no, by design | Recorded on the durable settlement store. This feed drops records under load, which is the wrong trade for money. |
| `anomaly` | yes |  |

## Structured detail

Every field below rides under OCSF `unmapped`, which the spec defines as the container for attributes a class does not define. The class has no home for a model id, a tool name, or an authentication method, and OCSF has no AI class and no financial class to graduate them into. `duration` is the one attribute that looks mappable and is not: OCSF populates it only for aggregate events, so a per-decision latency there would be a correct number under a wrong meaning.

### `policy`

- `unmapped.policy_id`
- `unmapped.policy_surface`
- `unmapped.verdict`
- `unmapped.decision_latency_ms`

Only under `policy_record_format: decision`. `policy_id` is the module that decided, which is how `waf` and the rate-limit family are selected now that they have no separate event. `verdict` is the policy's own tag and is not the record outcome: a faulted engine still returns a verdict while the decision outcome is `error`.

### `anomaly`

- `unmapped.anomaly_kind`
- `unmapped.reputation_bucket`
- `unmapped.verdict`
- `unmapped.identity_source`

Two decisions on one event. A detection record carries `anomaly_kind` and a `verdict` holding the severity, and its outcome is always an allow, because a verdict is an observation and the request proceeds. An admission record carries `reputation_bucket` and a `verdict` holding the action, and its outcome is a deny. `identity_source` is on both, because the class the score is keyed on is a claim unless that source is a verified one. Neither the fields nor the `reason` carry the raw score, the TLS fingerprint, or the client address: those are caller-chosen values on a record that ships unredacted, and none of them is a term a rule can select on. The fingerprint that fired stays on the local log line.

### `auth`

- `unmapped.auth_type`

The method, never the subject. Details ship unredacted, and a resolved principal is the one value on this path that is both attacker-influenced and frequently personal; anything about who authenticated is in the scrubbed reason. Published on allow and deny alike.

### `route.decide`

- `unmapped.requested_model`
- `unmapped.selected_model`
- `unmapped.selected_provider`
- `unmapped.tier_count`
- `unmapped.dropped`

`requested_model` against `selected_model` is the field comparison behind "every decision that moved a request off the model it asked for". `dropped` non-zero means the plan that ran is not the plan the operator wrote.

### `cache.key`

- `unmapped.skip_lookup`
- `unmapped.vary_count`

`vary_count` zero means the policy ran and added no dimensions, which is a different fact from the policy not running.

### `cache.admit`

- `unmapped.stored`
- `unmapped.ttl_secs`
- `unmapped.swr_secs`

An absent `ttl_secs` means the decision settled no TTL and the origin's configured value applies. A zero would claim the decision chose none.

### `cache.reserve.health`

- `unmapped.backend`
- `unmapped.state`
- `unmapped.reason_code`

One record per health transition, never per reserve operation. `backend`, `state`, and `reason_code` are closed proxy-authored vocabularies; raw SDK, filesystem, and configuration errors never enter structured detail.

### `ai.guardrail.input`

- `unmapped.guardrail`
- `unmapped.flagged_count`
- `unmapped.guardrail_spans`
- `unmapped.guardrail_spans_dropped`

`guardrail` names the one that blocked and is absent on an allow, because no single guardrail owns a decision they all passed. `flagged_count` carries the near-miss signal on both, which is what makes an allow record worth storing. `guardrail_spans` (WOR-2492) is the blocking guardrail instance's bounded detection positions -- entity type, byte offset, byte length -- over the scanned pre-redaction text; never the matched value, and only the `pii` guardrail populates it today. On this event the offsets index the guardrail pipeline's own message-text extraction, not the raw request body: the text content parts of the parsed `messages`, joined with newlines, which excludes non-text multimodal parts, unparseable message elements, the top-level `system` field, and tool-call arguments. Non-chat surfaces scan the surface's input text field (`prompt`, `input`, or `query`) instead. Neither record carries the scanned text, so an offset locates a match only within that derived text. Capped at 32 spans per record; `guardrail_spans_dropped` is the count past the cap.

### `ai.guardrail.output`

- `unmapped.guardrail`
- `unmapped.flagged_count`
- `unmapped.guardrail_spans`
- `unmapped.guardrail_spans_dropped`

As the input event, with one coordinate-space difference: here the `guardrail_spans` offsets index the raw response body bytes the consumer holds (a body that is not valid UTF-8 yields no spans). Not published for a non-2xx response, because the evaluator returns before inspecting one and a record there would claim an allow no guardrail issued.

### `ai.tool_call`

- `unmapped.tool`
- `unmapped.verdict`

One record per judged streamed tool call, not per chunk. `verdict` is the guard's own word (`clean`, `blocked`, `flagged`), so a flag-mode judgement that left the stream untouched is still countable.

### `mcp.tool`

- `unmapped.tool`
- `unmapped.tool_server`
- `unmapped.verdict`

`verdict` is the dispatch label rather than the outcome, because only it separates the gateway refusing a call (`policy_denied`, `tool_not_found`) from the upstream failing one the gateway allowed (`tool_error`).

### `ai.failure`

- `unmapped.selected_provider`
- `unmapped.verdict`

`selected_provider` names which provider's response failed. `verdict` carries the classified failure kind (`rate_limited`, `content_filter`, `upstream_5xx`, `provider_error`), a closed vocabulary rather than the raw upstream status text, which can carry a prompt fragment. The record's own `outcome` is always `error`: this is an upstream fact, not a proxy policy decision.

### `ai.admission`

- `unmapped.surface`
- `unmapped.verdict`

The pre-provider refusal record. `surface` is the inbound AI surface the request arrived on, the same vocabulary `sbproxy_ai_surface_requests_total` uses, so a refusal rate is a join rather than a guess: `messages` or `responses` for a refusal at the native-format shim, and any JSON surface, `chat_completions` included, for one at the shared stored-prompt resolver. `verdict` is the refusal's bounded reason code (`tools_mcp_unsupported`, `previous_response_id_unsupported`, `conversation_unsupported`, `store_unsupported`, `prompt_object_unresolved`, `malformed_json`, `body_not_object`, `role_missing`, `role_unsupported`, `prompt_reference_not_found`, `prompt_object_unrenderable`, `prompt_render_failed`, and `malformed_request` for a refusal whose site has not been coded yet). The refusal message is deliberately not a field: it interpolates caller bytes on several of those codes, and details ship unredacted. Coverage is the three inbound native-shim refusal arms plus the two stored-prompt resolver arms; a request refused later by a model gate, guardrail, budget, or policy records under that plane's own event.

### `ai.close`

- `unmapped.verdict`

`verdict` carries the terminal `finish_reason` (`stop`, `length`, `tool_calls`, `content_filter`, ...). Token counts and cost are not duplicated here: they already have an authoritative home in the access log and the usage ledger, and this record's job is marking that the stream reached its end, not re-billing it.

## Envelope

| Field | What it carries |
| --- | --- |
| `class_uid / class_name` | Always API Activity (6003). |
| `metadata.correlation_uid` | The request id. Joins every decision made on one request, and joins them to the access log. |
| `metadata.uid` | One UUID per record, for idempotent ingest. |
| `cloud.org.name` | Tenant. Never empty; single-tenant deployments carry the default tenant. |
| `api.service.name` | The origin's configured id, never the request Host. Under a wildcard origin the Host is attacker-chosen. |
| `api.operation` | The decision event's stable label. |
| `policy.name` | The decision event's stable label. |
| `policy.uid` | The rule id, when the engine exposes one. |
| `policy.desc / message` | The reason, scrubbed. Prose for a human; do not write rules against it, because rewording a script silently breaks a regex. |
| `disposition_id / is_alert` | Security Control profile. `is_alert` is true for the outcomes that refused or faulted. |
| `actor.process.name` | The engine that decided. |
| `unmapped` | Per-event structured detail, absent when the event has none. See the table above. |

## What may change without warning

- The wording of any `reason`. It is prose for a human. Rules belong on fields.
- The addition of a new field under `unmapped`, which is additive and cannot break a rule selecting on the fields already here.
- The addition of a new decision event.

## What does not change without a deprecation window

- Removing or renaming a field named on this page.
- Moving a field out of `unmapped` into a mapped OCSF attribute.
- Changing which event publishes a given decision.
- The stderr prefixes the bundled drain stamps.

The `policy_record_format` migration is the worked example of what that window looks like: both shapes selectable, one record either way, the old one the default for a release, and a startup warning naming the setting.
