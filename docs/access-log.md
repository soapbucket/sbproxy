# Access log

*Last modified: 2026-08-27*

![a GET and a POST proxied through an origin that emits a structured JSON access-log line for each](assets/access-log.gif)

stdout JSON lines, ready for any log shipper ([config](../examples/access-log/)).

Structured-JSON access logs give every completed request a single line on
stdout, ready to ship to ELK, Loki, Datadog, or any pipeline that already
speaks JSON. The proxy emits the line via the `access_log` tracing target
so log routers can split access logs from application logs without
additional plumbing.

## Default behavior

Off. SBproxy emits no access-log lines unless the top-level `access_log`
block is present and `enabled: true`. Metrics, traces, and the audit log
are unaffected by this knob.

## Enabling

Add the block to `sb.yml`:

```yaml
access_log:
  enabled: true

origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
```

A request to `api.example.com` now produces one JSON object on stdout.
[Calling it](#calling-it) below shows a real one, captured end to end.

The three `*_ms` phase fields (`auth_ms`, `upstream_ttfb_ms`,
`response_filter_ms`) split `latency_ms` into the parts of the
pipeline that contributed to it. They are emitted whenever the
matching phase ran on the request; an origin with no auth provider
omits `auth_ms`, an early WAF block omits `upstream_ttfb_ms` and
`response_filter_ms`, a cache hit served from the proxy omits both
upstream fields. The same observations also feed the
`sbproxy_phase_duration_seconds` Prometheus histogram (see
[metrics-stability.md](./metrics-stability.md)) so the aggregate
view does not require log scraping.

Optional fields (`provider`, `model`, `tokens_in`, `tokens_out`,
`cache_result`, `trace_id`, `request_headers`, `response_headers`,
`upstream_host`) are omitted when not applicable, keeping non-AI lines
compact.

## Calling it

The runnable configuration is
[`examples/access-log/`](../examples/access-log/). It turns the block on and
adds the filters, sampling, and header capture described below, in front of a
plain proxy origin. Start it:

```bash
make run CONFIG=examples/access-log/sb.yml
```

Then send an ordinary request. Nothing about the client changes; the log line
is a side effect of the response completing:

```bash
curl -s -o /dev/null -H 'Host: api.local' http://127.0.0.1:8080/anything
```

One JSON object appears on the proxy's stdout. It is a single line on the
wire, shown here wrapped:

```json
{
  "timestamp": "2026-08-01T14:56:33.863503+00:00",
  "request_id": "019fbdd3ab8272e2a87d91f409911437",
  "origin": "api.local",
  "method": "GET",
  "path": "/anything",
  "protocol": "HTTP/1.1",
  "host": "api.local",
  "user_agent": "curl/8.18.0",
  "status": 200,
  "response_content_type": "application/json; charset=utf-8",
  "latency_ms": 196.17337500000002,
  "upstream_ttfb_ms": 195.80141700000001,
  "response_filter_ms": 0.060958,
  "bytes_in": 0,
  "bytes_out": 2596,
  "client_ip": "127.0.0.1",
  "trace_id": "a242bdd5b2a948b683f9020924010054",
  "envelope_request_id": "01KYYX7AWCH1C2E5GFP6BCJEGC",
  "session_id": "01KYYX7AWCXXJ74WD2AAZV6EHT",
  "tenant_id": "__default__",
  "principal_kind": "none",
  "key_mode": "none",
  "served_from_cache": false,
  "fallback_triggered": false,
  "retry_count": 0,
  "request_headers": {"user-agent": "curl/8.18.0"},
  "response_headers": {
    "content-length": "2596",
    "content-type": "application/json; charset=utf-8"
  }
}
```

Every value there varies per run except the shapes. `timestamp`,
`request_id`, `trace_id`, `envelope_request_id`, `session_id`, and the three
`*_ms` numbers differ on every request, and `bytes_out` follows whatever the
upstream returned.

What is worth checking against your own run is which fields are *absent*.
`auth_ms` is missing because this origin has no auth provider. `query` is
missing because the request had none. `scheme` is missing because an HTTP/1.1
request line carries a path rather than an absolute URI. `provider`, `model`,
and the token counts are missing because this is not an AI route, and
`cache_result` is missing because no response cache is configured. That is the
`skip_serializing_if` behavior in practice: a non-AI, unauthenticated,
uncached proxy hop carries the populated fields and nothing else.

`request_headers` and `response_headers` are present only because the example
configures `capture_headers`. It asks for `user-agent`, `x-request-id`, and
`x-ratelimit-*` on the request side, and only `user-agent` was sent, so only
that one appears. A header the allowlist does not name is never logged.

Now ask the upstream for a failure:

```bash
curl -s -o /dev/null -H 'Host: api.local' http://127.0.0.1:8080/status/500
```

The line for that response differs in three places:

```json
{
  "path": "/status/500",
  "status": 500,
  "response_content_type": "text/plain; charset=utf-8",
  "error_class": "upstream_5xx",
  "bytes_out": 97
}
```

`error_class` appears only on a failure and is the field to alert on. Note
what does *not* appear: `upstream_status` stays absent, because the proxy
passed the upstream's 500 through unchanged and the field is only emitted
when the status the client sees differs from the one the upstream sent. A
retry chain, a fallback, or a `response_modifier` that rewrote the status is
what makes it show up, and its absence here is the signal that nothing
rewrote anything.

## Filters

`status_codes` and `methods` narrow the set of requests that get logged:

```yaml
access_log:
  enabled: true
  status_codes: [500, 502, 503, 504]
  methods: ["POST", "PUT", "PATCH", "DELETE"]
```

Empty or omitted lists match every value. Method comparison is
case-insensitive.

## Sampling

`sample_rate` is a probability in `[0.0, 1.0]` applied after the
status/method filters:

```yaml
access_log:
  enabled: true
  sample_rate: 0.05    # log 5% of matching requests
```

`1.0` (the default) logs every match. `0.0` is equivalent to disabling
emission entirely.

### Forced emission

Two knobs bypass `sample_rate` after the status/method filters match:

```yaml
access_log:
  enabled: true
  sample_rate: 0.05
  slow_request_threshold_ms: 1000
  always_log_errors: true
```

`slow_request_threshold_ms` logs every matching request whose end-to-end
latency is at or above the threshold. `always_log_errors: true` logs
every matching `5xx` response. Both knobs are off by default, preserving
the sampler-only behavior for existing configs.

## Header capture

Opt in by listing header names in `access_log.capture_headers.request`
and / or `access_log.capture_headers.response`. Captured values land in
the `request_headers` and `response_headers` fields of the emitted entry.

```yaml
access_log:
  enabled: true
  capture_headers:
    request: ["user-agent", "x-request-id", "x-ratelimit-*"]
    response: ["x-sbproxy-cache", "content-length"]
    max_value_bytes: 1024
    redact_pii: false
```

Three pattern shapes are accepted:

* Exact name: `"user-agent"`, `"x-cache"`.
* `"*"`: capture every header (subject to the sensitive-header denylist
  below).
* Trailing glob: `"x-ratelimit-*"` captures every header whose name
  starts with the prefix before the `*`. Only one trailing `*` is
  supported; embedded wildcards are treated as literal.

Header names are matched case-insensitively. Captured values are
truncated to `max_value_bytes` (default 1024) with a trailing `"..."`
that counts toward the cap.

A hardcoded denylist of sensitive headers (`authorization`, `cookie`,
`set-cookie`, `proxy-authorization`, `x-api-key`, `x-sb-api`) is excluded from `*`
and glob matches. An exact name opts a denied header into capture, and the
proxy logs a `WARN` at config load so the choice is visible. There are two
hard exclusions: `dpop` is never loggable, and every header configured as a
primary credential carrier under `key_management.inbound` remains excluded
even when named exactly. The warning calls out these limits rather than
promising that a carrier value will be captured.

When `redact_pii: true`, the `sbproxy-security` PII redactor runs over
captured header values. `redact_pii_rules` (empty by default) optionally
restricts the rule set; accepted names are `email`, `us_ssn`,
`credit_card`, `phone_us`, `ipv4`, `openai_key`, `anthropic_key`,
`aws_access`, `github_token`.

## Record shape

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | string | RFC 3339 (UTC) of when the response was sent. |
| `request_id` | string | Unique per request. Reuses the propagated request-id header when set; otherwise a fresh UUIDv7 rendered as 32 lowercase hex characters with no hyphens. |
| `origin` | string | Hostname routing matched. |
| `method` | string | HTTP method. |
| `path` | string | Request path, no query string. |
| `status` | int | HTTP response status code. |
| `latency_ms` | float | Wall-clock end-to-end latency in milliseconds. |
| `auth_ms` | float? | Time spent in the auth check (provider dispatch, JWT verify, forward-auth subrequest, OIDC cookie open). Absent when the origin has no auth provider. |
| `upstream_ttfb_ms` | float? | Time from request start to the first byte of the upstream response header. Absent when the request never reached an upstream (early auth/policy short-circuit, cache hit). |
| `response_filter_ms` | float? | Time spent running response transforms between first upstream byte and end of `response_filter`. Absent when no response_filter ran. |
| `query` | string? | Request query string without the leading `?`. Captured separately from `path` so per-route aggregations on `path` are not split by every distinct query. Absent when no query was supplied. |
| `protocol` | string? | HTTP version on the wire (`HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`). |
| `scheme` | string? | Scheme the client used to reach the proxy (`http` or `https`). Distinct from `upstream_host`'s scheme. |
| `host` | string? | Client-supplied `Host` header. May differ from `origin` (the matched virtual-host pattern, which can be a wildcard) and from `upstream_host` (where the proxy forwarded to). |
| `user_agent` | string? | Client `User-Agent` header. Pulled out as a primary field because nearly every analytics consumer wants it; the header allowlist still works as a redundant capture path. |
| `referer` | string? | Client `Referer` header (the canonical RFC 7231 misspelling). |
| `upstream_status` | int? | The status on the upstream response as the proxy received it, present on any row where that differs from `status`. Absent when the proxy passed the upstream status through unchanged, and absent when no upstream answered at all. Anything that replaces the status the client sees, after an upstream has answered, puts a value here, so treat the difference as the rule rather than memorizing a list: a `fallback_origin` on its `on_status` trigger, a `status` response modifier, a metering refusal under `failure_mode: closed`, a `closed` transform that failed after the response header had already committed, and a Proxy-Wasm filter answering with its own local response all qualify. `fallback_origin`'s `on_error` trigger does not: it fires before any upstream answered, so there is no upstream status to record. Two translations happen before this is recorded and so do not show up here: a Proxy-Wasm filter rewriting `:status` on the upstream's own response, and the gRPC-to-HTTP status mapping on a `transcode` origin. |
| `response_content_type` | string? | Response `Content-Type` as sent to the client. |
| `response_content_encoding` | string? | Response `Content-Encoding` (`gzip`, `br`, `zstd`, ...) when the body was compressed; absent when uncompressed. |
| `bytes_in` | int | Inbound request body bytes (post header-decode). |
| `bytes_out` | int | Bytes written to the client. |
| `client_ip` | string | Post-trust-boundary client IP. |
| `provider` | string? | AI provider when an AI gateway route handled the request. |
| `model` | string? | Selected AI model identifier. |
| `tokens_in` | int? | Prompt tokens, when known. |
| `tokens_out` | int? | Completion tokens, when known. |
| `usage_source` | string? | Where `tokens_in` and `tokens_out` came from on an AI request: `measured` (the provider reported them), `estimated` (it did not, so the gateway counted the delivered text with the model's tokenizer) or `absent` (neither, and nothing was billed). Absent whenever the row carries no `tokens_in` / `tokens_out` of its own, which includes every non-AI request and an AI origin with no `budget:` block, since the buffered relay stamps both together. Only `measured` counts reach invoicing, the usage sinks and the ledger; see [ai-gateway.md](ai-gateway.md#what-a-stream-is-billed). |
| `trace_id` | string? | W3C trace id when distributed tracing is active, for span correlation. |
| `cache_result` | string? | One of `hit`, `miss`, `stale`, `bypass` for cached responses. |
| `config_revision` | string? | Short hex tag identifying the set of origins this node was serving when the request landed. The same value webhooks and alerts carry. During a rolling change that adds, removes or renames an origin, the fleet's lines show two of these at once, which is what separates "the rollout is half finished" from "something is broken". A rollout that only changes behavior behind existing hostnames does not move it, so this field cannot stage-track that kind of change; `/admin/drift` compares the loaded bytes and can. |
| `cache_config_fingerprint` | string? | Digest of the serving origin's cache-relevant config, and the last segment of every response-cache key it produces. Two nodes logging different values for one origin are reading and writing separate entry sets. Absent for origins with no response cache. See [Which config changes rotate the cache](configuration.md#which-config-changes-rotate-the-cache). |
| `upstream_host` | string? | Upstream host the proxy contacted; absent on short-circuited requests (auth deny, WAF block, cache hit). |
| `zone_locality` | string? | How the zone-locality stage shaped the load-balancer selection: `local` (narrowed to the proxy's own zone) or `spilled` (no same-zone target was healthy, so selection widened across zones). Absent when the stage did not engage, which is every request on an unzoned proxy or an unlabeled pool. The same two strings appear on the admin request log and on the `verdict` label of `sbproxy_lb_zone_locality_total`, so a spilled line joins to the series that alerted. See [Routing](routing.md). |
| `request_headers` | object? | Captured request headers, lowercased keys. Absent when no allowlist or no matches. |
| `response_headers` | object? | Captured response headers, same shape as `request_headers`. |
| `attribution` | object? | Resolved business attribution tags (project, feature, okr, team, customer, environment, agent_type, risk_tier, trace_id) merged from the credential `attrs:` and `SB-Attr-*` headers. Same tag set the per-attribution spend metric is labeled by. Absent when none resolved. |
| `custom` | object? | Operator-defined custom fields from `observability.log.custom_fields:`. See below. Absent when none configured or none resolved. |
| `envelope_request_id` | string? | Capture envelope ULID, distinct from `request_id` (UUIDv7). Joins this line to the typed capture-envelope stream. |
| `session_id` | string? | Session identifier: caller-supplied, or auto-generated for anonymous traffic. |
| `parent_session_id` | string? | Parent session identifier; never auto-generated. Absent when the request carried none. |
| `tenant_id` | string | Tenant resolved from the matched origin's `tenant_id`. `__default__` for single-tenant deployments. Empty (and omitted) for log rows emitted before the request matched an origin, such as an early 404 on an unknown host. |
| `principal_kind` | string? | Which kind of principal authenticated the request: `bearer`, `api_key`, `jwt`, `basic_auth`, `oidc`, `forward_auth`, `ldap_auth`, `bot_auth`, `digest`, `cap`, `noop`, `virtual_key`, or `none`. `none` covers origins with no auth provider configured. |
| `api_key_id` | string? | Stable identifier of the credential (virtual key) that authenticated the request, mirroring the `api_key_id` metric label. Never the raw secret. Absent for un-credentialed requests. |
| `key_provider` | string? | Recognized native provider label when the request was governed by [native-key policy](key-management.md#attributing-native-provider-keys). Never contains credential material. |
| `key_mode` | string? | Inbound credential mode: `none`, `minted`, or `native`. |
| `credential_source` | string? | Which secret the AI attempt presented upstream, the outbound counterpart to `key_mode`: `provider_entry` (the provider entry's own `api_key`), `native_caller` (a caller-owned native provider key), or `fallback` (the operator's `fallback_credential_id`, presented after the entry's own key was refused). Absent on requests the AI gateway did not dispatch. Never credential material. See [multi-tenant.md](multi-tenant.md#when-a-tenants-provider-key-is-refused). |
| `served_from_cache` | bool? | `true` when the response came from cache (hot or reserve) without contacting the upstream. |
| `fallback_triggered` | bool? | `true` when a `fallback_origin` served the response instead of the primary upstream: either the primary failed outright (`on_error`) or it answered with a status listed under `on_status`. On the second, the primary's own status is in `upstream_status`. |
| `retry_count` | int? | Number of upstream retries attempted before the terminal outcome. `0` means the first attempt succeeded. |
| `error_class` | string? | Compact failure label when the response was not a 2xx (`auth_denied`, `rate_limited`, `waf_blocked`, `upstream_5xx`, `upstream_timeout`, `validator_failed`, ...). Absent for successful requests; see [Calling it](#calling-it) above for a worked example. |

A larger set of additional fields, one field or a handful per feature, are
documented alongside the feature that produces them rather than repeated
here in full:

* Agent detection: `agent_id`, `agent_class`, `agent_vendor`. See
  [agent-budget.md](agent-budget.md).
* AI cost, surface, and guardrails: `cost_usd_micros`, `ai_surface`,
  `guardrail_category`, `guardrail_action`. See [guardrails.md](guardrails.md).
* Content shaping: `content_shape` (the pricing-pass shape), `shape` (the
  shape the body transformer actually ran), `stripped_bytes` (boilerplate
  transform). See [content-for-agents.md](content-for-agents.md).
* Payment settlement and crawler pricing: `payment_rail`, `tier`, `price`,
  `currency`, `rail`, `txhash`, `redeemed_token_id`,
  `settlement_receipt_digest`. See [payment-settlement.md](payment-settlement.md)
  and [ai-crawl-control.md](ai-crawl-control.md).
* OLP and CAP tokens: `license_token_id`, `cap_token_id`. See
  [cap.md](cap.md).
* A2A envelope linkage: `a2a_context_id`, `a2a_identity_verified`. See
  [a2a-gateway.md](a2a-gateway.md).
* Stored prompts: `prompt_name`, `prompt_version`.
* Per-credential attribution (the fields the unified `attribution` object
  above superseded but still ships for existing consumers):
  `project`, `user`, `team`, `tags`, `metadata`. See
  [clickhouse-attribution.md](clickhouse-attribution.md).
* Caller-supplied custom properties from `X-Sb-Property-*` headers:
  `properties`. See [headers-reference.md](headers-reference.md).
* Multi-tenant and routing detail: `workspace_id`, `auth_type`,
  `forward_rule_idx`.
* End-user identity: `user_id`, `user_id_source`.
* Geo and classifier signal (optional policies): `request_geo`,
  `classifier_prompt`, `classifier_intent`. See
  [classifier-sidecar.md](classifier-sidecar.md).

All of the above follow the same `skip_serializing_if` rule as the core
table: absent from the line whenever the owning feature is off or did not
fire for that request.

Optional fields are omitted from the JSON object when their value is
`None`.

## Custom fields

![a request carrying X-Tier: gold whose value lands in the log line's custom object](assets/custom-log-fields.gif)

`custom_fields` computes per-request values without forking the schema ([config](../examples/custom-log-fields/)).

`observability.log.custom_fields:` adds operator-defined keys to each
line's `custom` object, so you can pivot logs on dimensions the built-in
schema does not carry (region, deployment, a derived tier, a routing
decision) without forking the binary. Each field's value is computed per
request from either a static string with `${...}` variable interpolation
or a script.

```yaml
proxy:
  observability:
    log:
      custom_fields:
        - name: region                       # static value + interpolation
          value: "${env.REGION}"
        - name: caller_tier                  # CEL expression
          engine: cel
          source: '"x-tier" in request.headers ? request.headers["x-tier"] : "standard"'
        - name: route_class                  # Lua script (returns the value)
          engine: lua
          source: 'return string.find(ctx.request.method, "GET") and "read" or "write"'
        - name: upper_method                 # JS script
          engine: js
          source: "ctx.request.method.toUpperCase()"
```

Rules:

- Each field sets exactly one of `value` or (`source` + `engine`).
  Both, or neither, is a config error.
- `engine` is one of `cel`, `lua`, `js`. WASM is not supported for log
  fields because it is a compiled module, not inline source.
- Static `value` interpolation variables: `${env.NAME}`, `${tenant_id}`,
  `${method}`, `${path}`, `${host}`, `${status}`, `${provider}`,
  `${model}`, `${request.header.NAME}`, `${attribution.KEY}`. An
  unresolved variable becomes the empty string.
- CEL expressions see the context keys as top-level variables
  (`request`, `response`, `tenant_id`, `provider`, `model`,
  `attribution`). Lua and JS scripts see the whole context as a `ctx`
  global and `return` (Lua) / evaluate to (JS) the value to log.
- A field whose script errors, or that resolves to the empty string, is
  omitted from the line rather than failing the request.
- Custom values pass through the same redaction as every other field.
- The request-header context omits every configured primary credential
  carrier before interpolation or a script runs. `${request.header.NAME}`
  therefore resolves to an empty string for a carrier, and
  `request.headers["name"]` is absent in CEL, Lua, and JavaScript. A
  `provider_hints[].also_header` is matching metadata, not a primary carrier,
  so it remains available unless the same name is configured as a carrier.

### Scopes

`custom_fields:` can be declared at three scopes: `proxy.observability.log`,
`tenants[].observability.log`, and `origins.<host>.observability.log`. They
compose per request as **proxy then tenant then origin**: the tenant set is
resolved from the request's `tenant_id`, the origin set from the matched
origin, and a more-specific scope's field overrides a less-specific field
of the same `name` (the broader definition is not evaluated at all for that
name). Fields with distinct names from every scope are unioned. This is the
same composition order redaction uses (see the sink-scope and tenant/origin
redaction sections in the observability guide).

A worked example covering all three scopes is in
`examples/custom-log-fields/`.

## Redaction

Every line goes through two passes before it reaches stdout, and the
second one depends on the first.

The **value pass** scans the rendered line for credential shapes and
replaces the value with `[REDACTED]`. It is the same pass that protects
metric labels, audit events, and the YAML that
[`GET /admin/config`](admin-api-reference.md#get-put-adminconfig)
returns. It knows Anthropic (`sk-ant-`), OpenAI (`sk-`), Stripe
(`sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`, `rk_live_`,
`rk_test_`), GitHub (`ghp_`, `gho_`, `ghr_`, `ghs_`), AWS access key
ids (`AKIA...`), a 40-character AWS secret key under a label containing
"secret", `Authorization: Bearer` and `Basic` values, and any value
written under a recognized name: `api_key`, `password`, `master_key`,
`signing_key`, `shared_key`, `virtual_key`, `challenge_binding_key`,
`signing_secret`, `client_secret`, `session_token`, or a bare `token`.

It also masks a credential carried in a URL's userinfo, which is the one
thing it recognizes by position rather than by shape or by name:
`https://sbproxy:hvs.MUSTNOTAPPEAR...@vault.internal:8200` comes out as
`https://[REDACTED]@vault.internal:8200`. The scheme and everything from
the last `@` of the authority on survive, so the host stays readable, and
a password containing its own `@` does not leak its tail. The user is
masked along with the password.

The authority is matched by an allowlist rather than by scanning to the
next delimiter. A byte continues it only if it is one of `[A-Za-z0-9]`,
`-`, `.`, `_`, `~`, `%`, `:`, or `@`, which is a strict subset of what RFC
3986 permits there. Everything else ends the run.

That set is this surface's. The config routes take a wider one, described
in [configuration.md](configuration.md#config_history), because a rendered
config document has no field whose delimiters a caller chose: the value is
a whole scalar and the renderer picked what surrounds it. Here the `query`
field holds the client's raw query string, so `&` and `=` are live bytes an
attacker supplies, and admitting them would let a mask delete a caller's
own parameters out of their own log record.

The set is *not* "every byte that is not structure", and that distinction
matters: `:` is JSON structure and is in the set, because a URL needs it.
What holds the line is narrower and stronger. Neither `"` nor `\` is in
the set, a JSON string ends only at an unescaped `"`, and every escape
begins with `\`, so a deleted span cannot leave the string token it
started in. The other serializations are held by their own delimiters
being absent from the set: whitespace and `,` end a YAML flow scalar and
a logfmt pair, and `&` and `=` end a query parameter. Three consequences
worth knowing:

* An `@` outside the authority is never reached, so
  `https://api.example.com?notify=ops@example.com` and the same URL with a
  path or a `#fragment` come back untouched.
* The closing `"` of a JSON string always ends the run, so this pass
  cannot reach the next field of a record. That is not incidental: the
  field pass below only runs on a line that still parses, so a value pass
  that ran past a key separator would drop the whole record's field
  denylist, and this rule is the only one here with no key name to anchor
  on.
* `&` and `=` end the run, which matters because the `query` field holds
  the client's raw query string with the leading `?` already stripped.
  With those two in the set, `u=https://a.example&op=drop_all&next=b@c`
  masked to `u=https://[REDACTED]@c` and a caller could delete their own
  query parameters from their own record by choosing their order.

The stated cost, the same one the `password` pattern carries: userinfo that
literally contains one of the excluded bytes ends the run there, so the URL
is emitted unmasked rather than masked halfway. That includes every
non-ASCII byte, so `https://usér:pw@host` is not masked at all.

The **field pass** then parses the line as JSON and masks whole values
by field name. That is the layer covering `prompt`, `messages`,
`cookie`, `authorization`, a captured `x-api-key` header, and
everything else listed under
[Redaction policy](observability.md#redaction-policy). It runs only if
the line still parses, which is why the value pass never consumes the
`":"` between a key and its value: a key and its separator come back
byte for byte and only the value is replaced. A mask that broke the
line would take the whole field pass down with it and ship the `prompt`
in the clear.

Three things the value pass does not catch:

* **A bare JWT.** There is no JWT shape pattern. `eyJhbGciOi...` is
  masked when it follows `Bearer ` or sits under one of the names
  above, and is emitted as written otherwise.
* **A credential under an unrecognized name.** `external_id` (the AWS
  STS assume-role external id) and `secret_id` (the Vault AppRole
  secret id) are both live examples, and both are left out on purpose:
  the same two names are non-secret identifiers elsewhere in the
  product, and masking them by name would hide settlement
  reconciliation ids an operator needs to read. Write those fields as
  `${VAR}` or `vault://` references, which the redactor preserves and
  which never hold the value in the first place.
* **The tail of a value containing `"`, `'`, `,` or `;`.** The value
  run stops at those four characters because they are structure in
  JSON, in YAML flow style, and in logfmt. `password: p@ss,word` comes
  out as `password: [REDACTED],word`.

For all three, add the field name under
`proxy.observability.log.redact.fields:`, which matches on the name and
never reads the value, or mask at your log shipper.

The PII redactor described under [Header capture](#header-capture) runs
before secret redaction, but only over captured header values. Other
fields (`path`, `request_id`, `client_ip`) are not PII-redacted.

## Routing the lines

Every line carries `target = "access_log"` in tracing metadata. Common
patterns:

* Filter via `RUST_LOG=info,access_log=info,sbproxy=warn` to keep
  operator logs quiet while keeping access logs.
* Use the JSON log subscriber (default in `sbproxy-observe`) and let
  your collector tag by `target`.
* Pipe stdout through `vector` or `fluent-bit` to split on `target`.

### File output

To write access logs directly to disk instead of the tracing target:

```yaml
access_log:
  enabled: true
  output:
    type: file
    path: /var/log/sbproxy/access.log
    max_size_mb: 100
    max_backups: 7
    compress: true
```

When the active file reaches `max_size_mb`, SBproxy rotates it before
writing the next line. Rotated files use suffixes like
`access.log.1` or `access.log.1.gz`; `max_backups` caps how many
rotated files are retained. `compress: true` gzips rotated files.

The active file and every rotated copy are created owner-only
(`0600`), and a directory SBproxy creates for them is `0700`. An
access-log line carries the path, the identity, and the decision for
one request, which is a record an operator asked to keep rather than
to publish. A file that is already on disk at a wider mode is
tightened when the sink next opens it rather than inherited, so a log
shipper or backup job running as a different user loses access the
first time that happens after an upgrade. Run those readers as the
proxy user, or point `path` at a fifo or `/dev/stdout`, which are left
exactly as the operator set them. A directory that already exists
keeps its mode, so a shared `/var/log` is never narrowed.

Rotated backups are swept as well as created. An uncompressed rotation
is a rename, which keeps the inode and therefore the mode, so backups
written by a build that predates this behavior would otherwise carry
their old `0644` forward for as many rotations as `max_backups`
allows: ten weekly files, each holding a week of every request's path
and identity, world-readable for ten more weeks. Every backup from
`.1` to `.max_backups` is made owner-only at each rotation. A backup
that cannot be tightened, because it sits on a filesystem without
permission bits or is owned by another account, is logged by name with
a warning and does not stop the rotation that keeps the live log
bounded.

Omitting `output` keeps the default behavior: emit JSON through the
`access_log` tracing target.
