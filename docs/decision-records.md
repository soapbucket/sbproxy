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
| `route.decide` | yes |  |
| `ai.guardrail.input` | yes |  |
| `ai.guardrail.output` | yes |  |
| `ai.tool_call` | yes |  |
| `ai.stream.event` | never | Fires once per streamed chunk, so it is refused ahead of both the per-event map and the master switch. `ai.close` carries the stream's summary once instead. |
| `ai.close` | yes |  |
| `ai.failure` | yes |  |
| `transform` | not yet | No emitter. Enabling it publishes nothing. |
| `action` | not yet | No emitter. Enabling it publishes nothing. |
| `log.custom_field` | not yet | No emitter. Enabling it publishes nothing. |
| `mcp.tool` | yes |  |
| `payment.lifecycle` | no, by design | Recorded on the durable settlement store. This feed drops records under load, which is the wrong trade for money. |

## Structured detail

Every field below rides under OCSF `unmapped`, which the spec defines as the container for attributes a class does not define. The class has no home for a model id, a tool name, or an authentication method, and OCSF has no AI class and no financial class to graduate them into. `duration` is the one attribute that looks mappable and is not: OCSF populates it only for aggregate events, so a per-decision latency there would be a correct number under a wrong meaning.

### `policy`

- `unmapped.policy_id`
- `unmapped.policy_surface`
- `unmapped.verdict`
- `unmapped.decision_latency_ms`

Only under `policy_record_format: decision`. `policy_id` is the module that decided, which is how `waf` and the rate-limit family are selected now that they have no separate event. `verdict` is the policy's own tag and is not the record outcome: a faulted engine still returns a verdict while the decision outcome is `error`.

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

### `ai.guardrail.input`

- `unmapped.guardrail`
- `unmapped.flagged_count`
- `unmapped.guardrail_spans`
- `unmapped.guardrail_spans_dropped`

`guardrail` names the one that blocked and is absent on an allow, because no single guardrail owns a decision they all passed. `flagged_count` carries the near-miss signal on both, which is what makes an allow record worth storing. `guardrail_spans` (WOR-2492) is the deciding guardrail's bounded detection positions -- entity type, byte offset, byte length -- over the scanned pre-redaction text; never the matched value, and only the `pii` guardrail populates it today. Capped at 32 spans per record; `guardrail_spans_dropped` is the count past the cap.

### `ai.guardrail.output`

- `unmapped.guardrail`
- `unmapped.flagged_count`
- `unmapped.guardrail_spans`
- `unmapped.guardrail_spans_dropped`

As the input event. Not published for a non-2xx response, because the evaluator returns before inspecting one and a record there would claim an allow no guardrail issued.

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
