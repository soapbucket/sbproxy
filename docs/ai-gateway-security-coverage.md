# AI gateway security coverage

*Last modified: 2026-08-21*

This page proves what the gateway enforces in the AI traffic path, not what a
feature list claims: every row below points at a named test or a signal you
can go check yourself, and every named limit is paired with the engineering
reason that behavior is honest and what compensates for it. Three phrases
carry the whole vocabulary. **Enforced** means the control runs in the
traffic path and a test or a signal proves it. **Enforced, with named
limits** means the same, plus a stated boundary and why crossing it costs
more than it buys. **Out of gateway scope** means the risk lives in the
application or the provider, and a proxy sitting on the request path cannot
own it.

## The eight controls no published list covers

An OWASP list describes risks to the traffic passing through a gateway. It
does not describe the gateway itself, and a proxy sitting on every request
has failure modes that an application-security taxonomy was never written to
catch. This is the set we hold ourselves to, written so an operator running
a different gateway can lift the checklist and grade their own deployment
against it.

### 1. Credential custody

Callers authenticate to the gateway; the gateway holds the provider
credentials, and the two never trade places. Inbound keys are stored as
HMAC-SHA256 hashes under a server-side pepper, so a store compromise yields
no reversible secret. Upstream provider credentials sit in an AEAD envelope.
No log line, metric label, or cache key carries either one; the label that
does travel is a policy-bucket id, not the key.

Config: `key_management:` (`pepper`, `crypto.master_key`) plus a
`credentials:` block (`type: ai_provider`). Signal:
`sbproxy_inbound_key_requests_total{provider,key_mode,tenant_id,api_key_id}`,
where `api_key_id` is the secret-free bucket id. Proof:
`crates/sbproxy-keystore/src/crypto.rs::verify_rejects_wrong_pepper`,
`::envelope_rejects_wrong_master_and_wrong_record`,
`::key_crypto_handle_combines_hash_and_envelope`.
[key-management.md](key-management.md).
[`examples/ai-dynamic-keys/`](../examples/ai-dynamic-keys/).

### 2. Cross-tenant boundaries

Cache keys bind tenant and credential scope through domain-separated
digests, so a tenant or credential change produces a different namespace
rather than a collision. Request budgets key by tenant. A panicking tenant
policy denies that one request with a 500 instead of taking the process
down with it.

Config: `tenants:` scope resolution as described in multi-tenant.md. Signal:
`sbproxy_policy_panic_total{policy}`. Proof:
`crates/sbproxy-ai/src/semantic_cache/identity.rs::namespace_changes_with_tenant`.
[multi-tenant.md](multi-tenant.md).
[`examples/multi-tenant-saas/`](../examples/multi-tenant-saas/).

Named limit: co-tenancy is still soft isolation. Tenants share one process,
so a fault outside policy evaluation, not the panic-catch this control adds,
can still reach every tenant. That is why the recommendation stands
regardless: run one process per trust boundary for tenants that do not
trust each other. A gateway cannot turn a shared process into hard
isolation by adding more catch blocks to it.

### 3. Routing decisions leave a record

`route.decide`, `cache.key`, and `cache.admit` are decision-audit points.
Opt one in and it publishes an OCSF record naming the rule and the reason
it fired; whether or not the audit feed is on, a metric family counts every
arm the decision could take, including declines, faults, and timeouts, so a
quiet feed is distinguishable from a feed that never wired up.

Config: `proxy.observability.log.decision_audit.events.route.decide: true`
(composes across origin, tenant, and proxy scope, per event label). Signal:
`sbproxy_decision_event_total{event="route.decide",outcome}`,
`sbproxy_decision_audit_events_total{event,outcome}`.
[observability.md](observability.md#one-family-for-every-decision-event),
[decision-records.md](decision-records.md).

Named limit: twelve of the twenty possible decision events publish under
their own label today (`auth`, `cache.admit`, `cache.key`, `cache.reserve.health`, `route.decide`,
`ai.guardrail.input`, `ai.guardrail.output`, `ai.tool_call`, `ai.close`,
`ai.failure`, `ai.admission`, `mcp.tool`), plus `policy` under the newer
record format. The other seven are not one undifferentiated leftover; the
code names four deliberate states for them.
`waf` and `rate_limit` are superseded by policy: both already run in the
policy chain and publish as a `policy` record naming which one fired, so a
second emitter would double-record one decision rather than add coverage.
`payment.lifecycle` is recorded durably elsewhere: money lands on the
durable settlement store, and this feed drops records under load, which is
the wrong trade for a receipt. `ai.stream.event` never publishes: it fires
once per streamed chunk, so config load refuses `ai.stream.event: true`
outright rather than accept an ingest bill (`ai.close` carries the
stream's summary once instead). The remaining three, `transform`,
`action`, and `log.custom_field`, are genuinely unwired, no emitter yet.
An `events:` key naming a label this proxy does
not recognize fails config load; a known but unwired label loads and
warns at boot instead, because refusing every label a later release might
wire would block pre-configuring it today. Proof:
`crates/sbproxy-config/src/compiler.rs::decision_audit_refuses_an_unknown_event_label`
(the unrecognized-label refusal),
`::decision_audit_refuses_the_per_chunk_stream_event` (the
`ai.stream.event` refusal), and
`crates/sbproxy-core/src/server/tests.rs::a_superseded_event_is_reported_separately_from_an_unwired_one`,
`::the_unwired_warning_follows_the_policy_record_format` (the boot warn,
which lives in `lifecycle.rs::warn_unwired_decision_audit_events`).

### 4. Denial of wallet is enforcement, not observation

Budgets deny at the cap across seven scopes (workspace, API key, user,
model, origin, tag, agent), and `on_exceed: block` actually blocks rather
than logging past it. Degraded enforcement is alertable rather than silent:
per-instance counters multiply the cap by replica count unless a shared
store backs them, and a store outage degrades to the per-instance floor
with a metric that says so.

Config: `budget: on_exceed: block` plus `limits: [...]` under `action`.
Signal: `sbproxy_budget_share_fail_open_total{op}`,
`sbproxy_budget_share_unavailable`. Proof:
`e2e/tests/ai_budget.rs::budget_block_returns_402_after_cap_exceeded`.
[ai-gateway.md](ai-gateway.md#budgets).
[`examples/ai-budget/`](../examples/ai-budget/),
[`examples/ai-predictive-budget/`](../examples/ai-predictive-budget/).

### 5. Streaming parity

A guardrail verdict on a streamed response must equal the verdict the same
bytes would get buffered whole. A mode that cannot keep that promise is
refused at config compile rather than approximated: `stream_policy: chunk`
is rejected on a classifier-backed guard because full-text classification
is not prefix-stable, and the config never loads to find that out at
request time.

Config: `guardrails: output: [...] stream_policy: close | chunk | off`.
Signal:
`sbproxy_ai_safety_guardrail_verdicts_total{guardrail,class,backend,verdict}`.
Proof:
`crates/sbproxy-ai/src/guardrails/stream.rs::streamed_verdicts_match_buffered_for_all_chunkings`.
[ai-gateway.md](ai-gateway.md#streaming-policy).
[`examples/ai-streaming/`](../examples/ai-streaming/),
[`examples/ai-safety-classifiers/`](../examples/ai-safety-classifiers/).

### 6. Telemetry does not leak the traffic it audits

Secret-regex and field-key redaction run before observability fan-out, on
every emitter: access log, error log, security audit, and trace alike. A
value redacted from one never reappears in another. Prompt-linked audit
carries digests and lengths; verbatim content is an explicit opt-in, never
a default.

Config: `proxy.observability.log.redact.fields`, `.patterns`, `.pii`.
Proof: `e2e/tests/redaction.rs::redaction_per_sink_fan_out`.
[observability.md](observability.md#redaction-policy).
[`examples/pii-redaction/`](../examples/pii-redaction/).

### 7. Egress is inventoried

Every outbound destination the gateway reaches, across ten wired egress
purposes (AI providers, the dual-LLM quarantine judge, OpenAPI-backed MCP
tools, token exchange, webhooks, usage sinks, model artifact downloads,
engine artifact downloads, extension bundle hooks, and the OTLP telemetry
exporters), is recorded with its authorization status and last-seen time,
readable from the admin API.

Config: the top-level `egress:` block arms six of the ten through five
sub-blocks (`ai_providers`, `usage_sinks` covers both usage sinks and
webhooks including the `events:` sink, `model_artifacts`,
`token_exchange` for every token endpoint, the non-MCP resolver's and
the MCP run-as-user exchange's alike, `telemetry`), each
`mode: deny_by_default`. OpenAPI-backed MCP tools and the dual-LLM
quarantine judge arm from a per-server or per-action `egress:` block
instead. Extension bundle hooks are always armed
automatically from the bundle's own outbound grant. Engine artifact
downloads pass no authorizer today and cannot be armed by any config.
Signal: `GET /api/egress`,
`sbproxy_egress_refused_total{purpose,reason,tenant,origin}`. Proof:
`crates/sbproxy-security/src/egress.rs::egress_seen_records_a_single_sighting_with_counts`,
`::serialized_sighting_never_carries_userinfo_or_query` (the inventory
itself never carries a credential embedded in a dialed URL).
[configuration.md](configuration.md#egress-allowlists),
[admin-api-reference.md](admin-api-reference.md#get-apiegress).

Named limit: traffic that never reaches the gateway is invisible to it, an
authorizer can only authorize what it is handed. `sbproxy ai ledger
reconcile` compensates after the fact: it compares the gateway's own usage
ledger against a usage export downloaded directly from the provider and
flags provider-billed usage the ledger never recorded, which is exactly the
shape a bypass leaves behind. The deployment recipe, a network policy that
permits provider egress only from the gateway's own identity, is part of
the control rather than an afterthought.
[threat-model.md](threat-model.md#current-wave-notes),
[ai-usage-ledger.md](ai-usage-ledger.md#reconciling-against-a-provider-export).

### 8. Change control is tamper-evident

Security, config, key-mutation, and admin-action records each append, when
the operator opts that channel in, to their own SHA-256 hash-chained,
Ed25519-signed file. A chain that cannot open fails the boot rather than
silently running without it. An append failure after boot is a non-ok
outcome on the emit metric, so a quiet alert means an intact trail rather
than a broken sensor.

Config: `audit: sink: chain`, `path`, `sign_with`, plus `config_path`,
`key_path`, `admin_path` to opt in the other three channels. Signal:
`sbproxy_audit_emit_duration_seconds{channel,outcome!="ok"}`. Proof, one
test per channel:
`crates/sbproxy-observe/src/audit_chain.rs::a_signed_chain_of_denials_verifies_against_its_key`
(security),
`::an_installed_config_chain_takes_what_append_config_audit_is_given`
(config),
`::an_installed_key_chain_takes_what_append_key_audit_is_given` (key),
`::an_installed_admin_chain_takes_what_append_admin_audit_is_given`
(admin), and `::a_torn_final_line_keeps_the_chain_closed` for the
boot-refuses-on-corruption property. [audit-log.md](audit-log.md).
[`examples/audit-log/`](../examples/audit-log/).

Named limit: each channel is opt-in, and none is chained until its path is
set, so a deployment that never names one keeps that channel as a tracing
stream only. There is also no rotation or segmentation: each chain is one
file that grows, because truncating it is by construction indistinguishable
from tampering with it. Size it accordingly and archive by copy, never by
trim.

## OWASP LLM Top 10 (2026) mapping

The public taxonomy, current as of the 2026-08-03 edition. Each row links
to a section carrying its coverage word (enforced, enforced with named
limits, or out of gateway scope), the risk in one line, what the gateway
enforces with the config keys that turn it on, where to turn it on, the
named proof, and the honest limits. The third column here is what's
enforced in one clause, not a repeated grade.

| # | Risk | What sbproxy enforces |
|---|---|---|
| [LLM01](#llm01-prompt-injection) | Prompt Injection | Input/output injection guardrail, double-pass RAG screening, multipart refusal on JSON-only surfaces |
| [LLM02](#llm02-sensitive-information-disclosure) | Sensitive Information Disclosure | `pii:` body redaction, plus secret-regex and field-key redaction on every log emitter |
| [LLM03](#llm03-excessive-agency) | Excessive Agency | Per-tool RBAC with default-deny, resolved-model gates, per-agent budgets on verified identity |
| [LLM04](#llm04-supply-chain) | Supply Chain | Default-deny, DNS-pinned egress authorizer across ten purposes, with per-hop redirect re-authorization |
| [LLM05](#llm05-model--data-poisoning) | Model & Data Poisoning | Out of gateway scope: risk lives with the model provider's training pipeline |
| [LLM06](#llm06-misinformation) | Misinformation | Out of gateway scope: risk lives in the model's own generation |
| [LLM07](#llm07-unbounded-consumption) | Unbounded Consumption | Budgets deny at the cap across seven scopes; per-instance until a shared store is present |
| [LLM08](#llm08-hidden-context-exposure) | Hidden Context Exposure | Domain-separated cache-key digests, digest-only prompt-linked audit |
| [LLM09](#llm09-vector--embedding-weaknesses) | Vector & Embedding Weaknesses | Pre- and post-retrieval guardrail passes, tenant-scoped vector search |
| [LLM10](#llm10-improper-output-handling) | Improper Output Handling | Output guardrails with streaming/buffered verdict parity; blocked responses never cache |

### LLM01: Prompt Injection

*Enforced, with named limits.*

**Risk.** Attacker-controlled text in a prompt, or in retrieved context,
tries to override the model's instructions or exfiltrate what it was told
not to repeat.

**What sbproxy enforces.** The built-in `injection` guardrail runs on input
and output, in `mode: keyword` or `mode: classifier`, with streaming
verdict parity. A `rag:` route runs input guardrails twice: once over the
original request, so a rejected prompt never causes embedding egress, and
again over the augmented request, so retrieved text gets the same screening
user text got. A multipart `Content-Type` on a JSON-only surface such as
`chat_completions` is refused with `403` before any guardrail, budget, or
upstream work runs, so a caller cannot relabel a request past body
inspection.

**Turn it on.** `guardrails: input: - type: injection` (add `mode:
classifier` with a pinned ONNX model for the enforcing path); `rag:` on an
`ai_proxy` origin for the double-pass screening.
[guardrails.md](guardrails.md), [ai-gateway.md](ai-gateway.md#guardrails),
[rag.md](rag.md). Examples:
[`ai-guardrails/`](../examples/ai-guardrails/),
[`ai-rag-local/`](../examples/ai-rag-local/).

**Proof.**
`e2e/tests/ai_rag.rs::original_guardrail_blocks_before_embedding_egress`,
`::retrieved_poison_is_blocked_before_model_egress`,
`crates/sbproxy-core/src/server/ai_dispatch.rs::multipart_on_a_json_surface_is_refused_and_not_counted_as_skipped`,
`crates/sbproxy-ai/src/guardrails/stream.rs::streamed_verdicts_match_buffered_for_all_chunkings`.

**Limits.** `mode: keyword`, the default, is case-insensitive substring
matching; it does not understand paraphrase, obfuscation, or translation,
and the docs say so rather than describing it as detection. `mode:
classifier` ships no first-party injection model in the binary; the
operator supplies the artifact. Rationale: shipping a bundled
injection-detection model would be a claim about accuracy against traffic
we have never seen, for every deployment that runs it. The classifier hook
and the guardrail mesh's quorum fusion exist so an operator can attach a
detector they trust, or combine several weak ones, instead of trusting one
we picked for them.

### LLM02: Sensitive Information Disclosure

*Enforced, with named limits.*

**Risk.** A prompt or a completion carries a secret, PII, or other
sensitive data that leaks into a log, a cache, or a downstream sink.

**What sbproxy enforces.** The `pii:` block redacts AI request and response
bodies for well-known shapes (SSN, Luhn-validated card numbers, phone,
IPv4, common API key formats). Secret-regex and field-key redaction cover
structured logs, access log lines, and request-event sinks independently of
that block. Prompt-linked audit records carry salted digests of the
content, never the content itself.

**Turn it on.** `pii: enabled: true` on an `ai_proxy` origin;
`proxy.observability.log.redact:` for the log-side pass, which runs
whether or not `pii:` is configured. [ai-gateway.md](ai-gateway.md),
[observability.md](observability.md#redaction-policy). Example:
[`pii-redaction/`](../examples/pii-redaction/).

**Proof.** `e2e/tests/redaction.rs::redaction_per_sink_fan_out`.

**Limits.** The `dlp` policy scans the request URI, the request headers,
and, on by default (`scan_body: true`), the buffered request body, capped
at the first 16 KiB (`body_max_bytes`), where most PII shapes sit. Its
actions are tag and block; it never masks. It is request-side only:
`direction: response` or `both` is accepted and warned about at config
load, and the request-side scan runs regardless, because the policy
enforcement phase has no response body to hand it. So `pii:` remains the
masking control and the response-direction control, and `dlp` is the
request-side detect-and-refuse one; the two stay separate rather than one
doing both jobs partway.

### LLM03: Excessive Agency

*Enforced, with named limits.*

**Risk.** An agent or a tool call reaches further than the caller should be
allowed to: a tool nobody granted, a model outside its allow list, or spend
attributed to the wrong identity.

**What sbproxy enforces.** MCP tool access runs through per-tool RBAC with
`default_allow: false`, so a tool nobody granted is refused rather than
reachable. Every model gate, `allowed_models`, `blocked_models`, credential
model lists, budgets, and per-model rate limits, judges the resolved model
id, so an alias is never a way around a block list. Per-agent budgets key
on a verified caller identity (a peer in `proxy.trusted_proxies`, or the
RFC 8693 `act` chain of a signed token); an unverified caller pools into a
shared, still-capped bucket instead of spending against a name it did not
prove.

**Turn it on.** `rbac_policies:` under an `mcp` action;
`allowed_models`/`blocked_models` on a `credentials:` entry;
`scope: agent` under `budget.limits`. [mcp-security.md](mcp-security.md),
[mcp.md](mcp.md#federated_servers),
[ai-gateway.md](ai-gateway.md#budgets). Example:
[`admin-mcp/`](../examples/admin-mcp/).

**Proof.**
`crates/sbproxy-extension/src/mcp/access_control.rs::default_deny_unknown_caller_denied`,
`::default_deny_empty_allowed_means_deny_all` for the RBAC seam;
`e2e/tests/ai_budget.rs::budget_block_returns_402_after_cap_exceeded` for
the agent-budget enforcement path.

**Limits.** None of this reaches a credential the agent already holds and
types into a tool argument as plain text: a tool description reads as
instruction to the model, and a secret already inside that conversation
never crosses a seam a gateway policy can inspect. Rationale and
compensation: [mcp-security.md](mcp-security.md#credentials-reaching-a-tool-that-should-not-see-them)
is explicit that this stays the caller's responsibility, and the
recommendation is to keep long-lived secrets out of agent context in the
first place rather than to expect a proxy to unsee one already there.

### LLM04: Supply Chain

*Enforced, with named limits.*

**Risk.** The gateway or something it calls on your behalf reaches an
outbound destination it should not: a compromised registry, a redirected
webhook, a rebound DNS answer.

**What sbproxy enforces.** A default-deny, DNS-pinned egress authorizer
covers ten wired purposes once armed (see [control 7](#7-egress-is-inventoried)
above for which config surface arms which purpose; engine artifact
downloads cannot be armed today and stay ungated). Every redirect hop is
re-authorized as a new destination, capped at
ten hops, with credentials stripped on any cross-origin hop, including
vendor header names such as `x-api-key` that an HTTP client's own
stripping does not cover. OTLP telemetry exporters are authorized once at
boot, where each is constructed; a denied endpoint refuses boot naming it,
rather than starting and silently exporting nowhere useful. Self-hosted
model and engine artifacts are pinned by SHA-256 and signature-verified
before the model host serves them.

**Turn it on.** The top-level `egress:` block, `mode: deny_by_default` per
purpose. [configuration.md](configuration.md#egress-allowlists),
[threat-model.md](threat-model.md#current-wave-notes).

**Proof.**
`crates/sbproxy-security/src/egress.rs::dial_time_rebind_is_refused_with_dns_pin_mismatch`,
`::cross_origin_redirect_strips_credentials`,
`crates/sbproxy-observe/src/telemetry.rs::denied_telemetry_endpoint_is_stamped_and_would_refuse_boot`.

**Limits.** No model weights ship in this repository, so there is nothing
here to attest about training data; that risk is [LLM05](#llm05-model--data-poisoning),
out of gateway scope. Four credential-bearing consumers (AI providers,
usage sinks and webhooks, token exchange, artifact downloads) authorize
against a live DNS resolver behind a 30-second cache but are not
dial-pinned the way the OpenAPI tool path is. Rationale: dial pinning needs
one HTTP client per destination, and these four share one long-lived
client each because the AI client is the hottest outbound path in the
proxy; a client per destination would rebuild TLS and abandon the
connection pool on every dial, a latency regression on every AI request to
close a window the resolver cache already narrows to its TTL. It
compensates in two ways: the allowlist, scheme, and port checks still
hold, so exploiting the gap requires already being on the operator's
allowlist, and the per-destination client cache that would close it is
scoped and stated rather than left implicit.
[threat-model.md](threat-model.md#current-wave-notes).

### LLM05: Model & Data Poisoning

*Out of gateway scope.*

**Risk lives** with the model provider's training pipeline for hosted
models, or with whatever fine-tunes or indexes a corpus for a self-hosted
one. By the time a poisoned model or a poisoned document reaches the
gateway, the poisoning already happened upstream of it.

**What sbproxy contributes adjacent to it.** For self-hosted model
artifacts, the model host pins by SHA-256 and verifies signatures before
serving; that is supply-chain integrity for the artifact
([LLM04](#llm04-supply-chain)), not a claim about what the model learned.
For gateway-performed RAG, retrieved text passes the same input guardrails
user text does before it is injected as context
([LLM09](#llm09-vector--embedding-weaknesses)); that screens the delivery
mechanism, not the corpus it draws from. A proxy on the request path
cannot attest what a hosted vendor trained on, or audit a corpus it never
indexed.

### LLM06: Misinformation

*Out of gateway scope.*

**Risk lives** in the model's own generation. Whether an answer is correct
is a property of the model and the prompt, not of the network path a
request took to reach it.

**What sbproxy contributes adjacent to it.** Shadow evaluation mirrors a
sampled request to a second provider for latency, cost, and output
comparison, and judge-model routing selects among providers on the same
basis. Neither is built as a correctness check, and neither is claimed as
one: a routing feature is not a fact-checker, and describing it as such
would be exactly the kind of claim this page exists to avoid making.
[ai-gateway.md](ai-gateway.md#shadow-eval).

### LLM07: Unbounded Consumption

*Enforced, with named limits.*

**Risk.** A caller, or a compromised credential, runs up spend or resource
consumption with no ceiling, whether that is deliberate denial-of-wallet or
an accidental runaway agent loop.

**What sbproxy enforces.** Budgets deny at the cap across seven scopes
(workspace, API key, user, model, origin, tag, agent) with `on_exceed:
block | log | downgrade`. Soft-landing thresholds taper before the hard
cap: a warn threshold logs, a downgrade threshold rewrites the model, and
only the cap itself blocks. Realtime WebSocket requests run the same
hard-limit preflight before the upgrade. Counters are cluster-shared
whenever a Redis key store is present, with no extra configuration needed.

**Turn it on.** `budget: on_exceed: block` plus `limits: [...]` under
`action`; `soft_landing:` for the taper.
[ai-gateway.md](ai-gateway.md#budgets). Examples:
[`ai-budget/`](../examples/ai-budget/),
[`ai-predictive-budget/`](../examples/ai-predictive-budget/).

**Proof.** `e2e/tests/ai_budget.rs::budget_block_returns_402_after_cap_exceeded`.

**Limits.** Counters are per-instance by default, so a cluster of N
replicas enforces roughly N times a configured cap until a Redis-backed key
store is present. If that store becomes briefly unreachable, enforcement
degrades to the per-instance floor rather than failing open entirely, and
`sbproxy_budget_share_fail_open_total{op}` and
`sbproxy_budget_share_unavailable` say so on a dashboard instead of in
silence. GET and multipart AI surfaces do not debit token budgets, because
byte-transparent forwarding never parses a token count to charge; Realtime
frames are the same case, metered at the connection preflight rather than
per frame. The floor that does apply, the per-instance count, the
preflight check, still holds while the gap is visible.

### LLM08: Hidden Context Exposure

*Enforced, with named limits.*

**Risk.** A system prompt, injected RAG context, or other server-side
detail leaks to a caller who should not see it, through an error message,
a cache key, or a log line.

**What sbproxy enforces.** System prompts and injected RAG context are not
echoed through the gateway's generic error path; private detail stays in
bounded logs and metrics. Cache keys are domain-separated digests
(`semantic_prompt_digest`, `semantic_origin_route_digest`, and similar)
that carry no prompt, tenant, subject, or model text, only a hash of it.
Prompt-linked audit lines carry salted digests and lengths, never content.

**Turn it on.** This is default behavior on the caching and audit paths;
there is no separate flag. [ai-gateway.md](ai-gateway.md#caching),
[audit-log.md](audit-log.md).

**Proof.**
`crates/sbproxy-ai/src/semantic_cache/identity.rs::namespace_changes_with_tenant`,
`::namespace_changes_with_api_key_id`.

**Limits.** One field on the audit trail is operator-authored rather than
system-generated: a policy's deny `reason`. It is written verbatim, in the
tracing target and in the signed chain alike, so a deny message that
interpolates request data carries that data into both. Rationale: a deny
reason is deliberately human-written text meant to explain a decision, and
silently truncating or hashing it would defeat the reason the audit trail
exists. Compensation: the same `redact.patterns:` regex masks that cover
log lines also run over this field, so a rule written for one covers the
other on the same reload; write deny messages that name the rule rather
than the content, and add a pattern for anything else.
[audit-log.md](audit-log.md#what-a-record-may-contain).

### LLM09: Vector & Embedding Weaknesses

*Enforced.*

**Risk.** A retrieval-augmented pipeline embeds or indexes something an
attacker controls, or serves a tenant's vectors to a caller who should not
reach them.

**What sbproxy enforces.** A `rag:` route runs input guardrails before
embedding, so a rejected prompt causes no embedding egress, and again over
the augmented request, so retrieved text gets the same screening as user
text before it reaches the model. Vector search is tenant-scoped: the
tenant filter comes only from the origin's own configured `tenant_id`,
never from a caller-supplied value.

**Turn it on.** `rag:` on an `ai_proxy` origin, with `filters.tenant_field`
set. [rag.md](rag.md). Example:
[`ai-rag-local/`](../examples/ai-rag-local/).

**Proof.**
`e2e/tests/ai_rag.rs::original_guardrail_blocks_before_embedding_egress`,
`::retrieved_poison_is_blocked_before_model_egress`,
`::rag_injects_tenant_scoped_context_before_provider_dispatch`.

### LLM10: Improper Output Handling

*Enforced, with named limits.*

**Risk.** Model output reaches a client, or gets admitted to cache, without
validation: an unvalidated payload, broken JSON hitting a downstream
parser, or a flagged fragment slipping through a stream.

**What sbproxy enforces.** Output guardrails, including schema validation,
run on streaming responses with the same verdict the buffered path would
reach. A live-evaluated guard withholds only the violating chunk and
everything after it. A classifier-backed close-policy guard holds the
entire response body, so a block releases no bytes at all. A blocked
response is never admitted to cache.

**Turn it on.** `guardrails: output: - type: schema` (or any output
guardrail type). [ai-gateway.md](ai-gateway.md#streaming-policy),
[guardrails.md](guardrails.md). Examples:
[`ai-guardrails/`](../examples/ai-guardrails/),
[`ai-safety-classifiers/`](../examples/ai-safety-classifiers/).

**Proof.**
`crates/sbproxy-ai/src/guardrails/stream.rs::streamed_verdicts_match_buffered_for_all_chunkings`.

**Limits.** Response headers may already be sent by the time a streaming
block fires, so a blocked stream ends empty rather than getting re-statused
to an error code; the client sees a truncated stream, not a 4xx. Rationale:
HTTP has no way to rewrite a status line after the first byte of a chunked
body has gone out, so once headers are sent the only fail-closed option is
to stop the body rather than claim a status that was never true. The
alternative, buffering every response before sending headers so a status
code is always still available, would remove streaming's latency benefit
from every request to protect the rare one that gets blocked.

## Signals

| Control | Log target | Metric |
|---|---|---|
| Multipart surface refusal | `security_audit` (`multipart_disallowed_surface`, policy_denied via events sink) | `sbproxy_audit_emit_duration_seconds{channel="security"}` (no dedicated counter; the security-channel audit-emission metric below) |
| Multipart inspection skip (allowed surfaces) | none | `sbproxy_ai_multipart_inspection_skipped_total{check,surface}`, legitimate multipart traffic that skipped body inspection, not a refusal |
| Budget fail-open | `sbproxy::budget` WARN on transition | `sbproxy_budget_share_fail_open_total{op}`, `sbproxy_budget_share_unavailable` |
| Tenant throttle | decision events | `sbproxy_rate_limit_total{workspace}`, `sbproxy_rate_limit_decisions_total{policy}` |
| Policy panic | `security_audit` ERROR | `sbproxy_policy_panic_total{policy}` |
| Egress sightings | `sbproxy::egress` WARN on refusal | `sbproxy_egress_refused_total{purpose,reason,tenant,origin}`, inventory at `GET /api/egress` |
| Audit chain health | `security_audit` / `config_audit` / `key_audit` / `sbproxy::admin::audit` | `sbproxy_audit_emit_duration_seconds{channel,outcome!="ok"}` |
| RAG retrieval outcome | `sbproxy_ai_rag` target | `sbproxy_ai_rag_requests_total{embedding,vector_store,outcome}` |
| Routing decision audit | `decision_audit_event:` (stderr) | `sbproxy_decision_event_total{event,engine,outcome,origin,tenant}`, `sbproxy_decision_audit_events_total{event,outcome}` |
| Inbound key resolution | access log, request events | `sbproxy_inbound_key_requests_total{provider,key_mode,tenant_id,api_key_id}` |
