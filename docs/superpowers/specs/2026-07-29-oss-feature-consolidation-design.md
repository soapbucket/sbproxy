# OSS feature consolidation design

*Last modified: 2026-07-29*

## Goal

Move the current RAG, distributed semantic cache, vendor guardrail, and
payment settlement work into the Apache-2.0 `sbproxy` repository as working
runtime features. Remove the current OSS-versus-enterprise product split from
the repository and website. Finish with a full documentation pass that makes
SBproxy's role clear: it is an open source Enterprise AI Gateway for API,
MCP and agent, and AI model traffic.

In this description, "Enterprise AI Gateway" describes the workloads and
operating requirements SBproxy handles. It is not the name of a separate
edition. A paid service or other commercial offering may exist in the future,
but no current SBproxy feature is documented as belonging to one.

## Scope

This epic includes:

- the hardened outbound HTTP client needed by provider integrations;
- first-party guardrail adapters connected to the existing OSS guardrail
  pipeline;
- a RAG runtime with embedding and vector-store drivers, typed configuration,
  and request-path integration;
- Redis and mesh backends for the existing semantic cache;
- Stripe, x402, MPP, and Lightning settlement adapters connected to a durable
  asynchronous settlement worker;
- removal of `docs/enterprise.md`, the `/enterprise` website route, references
  to `sbproxy-enterprise`, and claims about a current proprietary tier;
- a final audit and consolidation of the public documentation, examples,
  navigation, generated indexes, and VHS recordings.

This epic does not move the old repository wholesale. It excludes duplicate
mesh and cache implementations, disconnected registries, fake success
responses, placeholder providers, private test keys, and unrelated billing,
reporting, identity, or dashboard work. Historical changelog entries remain
when they describe a released fact, but dead links and current product claims
are corrected.

Google Model Armor is not advertised until it has a real provider
implementation. Phoenixd is not advertised as a Lightning adapter because the
old repository has no `PhoenixdNode`. AP2, ACP, revenue analytics, and
merchant-of-record reporting are outside the payment settlement scope unless
an implementation dependency requires a small shared type.

## Migration and licensing rules

The old repository's root license is proprietary even though many individual
files and crate manifests carry Apache-2.0 markers. This design records the
project owner's direction to publish the selected Soap Bucket-owned
implementations in the Apache-2.0 repository.

Approval of this written specification by the repository owner is the
explicit relicensing and provenance decision for Soap Bucket-owned code in
the four scoped feature areas. It grants no rights to third-party code or to
files whose ownership cannot be established.

Every migrated file must pass a provenance check before it lands:

1. Confirm that Soap Bucket owns the implementation and that the file does not
   carry a Proprietary or BUSL header.
2. Preserve useful authorship history in the commit or pull request and add
   the repository's Apache-2.0 SPDX header where that convention applies.
3. Reimplement a small component when its ownership or license is unclear.
4. Exclude committed PEM fixtures, demo signing seeds, credentials, generated
   secrets, and unrelated private configuration.
5. Preserve third-party notices. The vendored LND protobuf either receives
   the upstream Lightning Labs MIT attribution and NOTICE entry or is fetched
   from a verified upstream source during the build.

No code from a Proprietary or older BUSL blob is copied based only on a
similar filename.

## Target architecture

```text
sbproxy binary
├── sbproxy-core
│   ├── sbproxy-modules      API, MCP, agent, and 402 policy
│   ├── sbproxy-ai           guardrails and semantic cache
│   ├── sbproxy-rag          retrieval orchestration
│   └── sbproxy-billing      settlement registry and adapters
├── sbproxy-mesh             distributed state and ownership
├── sbproxy-storage          durable intents, replay state, and receipts
├── sbproxy-httpkit          bounded outbound HTTP clients
└── sbproxy-observe          metrics, events, and audit records
```

`sbproxy-billing` does not depend on `sbproxy-core`, `sbproxy-modules`, or
`sbproxy-ai`. Core translates the existing 402 policy output into
billing-owned settlement intents. This direction keeps the crate graph
acyclic and keeps payment network calls out of the proxy hot path.

`sbproxy-rag` may depend on the public embedding abstraction in `sbproxy-ai`.
`sbproxy-ai` does not depend on `sbproxy-rag`. Core owns the request
orchestration and decides when retrieval runs.

The existing `sbproxy-mesh` remains the only distributed-state substrate.
Semantic cache work adds an adapter to it instead of importing the older mesh
implementation.

## Shared outbound HTTP

`sbproxy-httpkit` gains two constructors:

- a bounded client for ordinary provider traffic;
- a token-bearing client with stricter redirect and logging behavior.

Both apply explicit connect, request, and idle timeouts; bounded redirects;
connection-pool limits; proxy and DNS policy; TLS verification; and safe
defaults for credentials. Provider-specific code may narrow a timeout but
does not create an unbounded `reqwest::Client` or log authorization material.

This foundation lands with the first guardrail adapters and is reused by RAG
and payment providers.

## Vendor guardrails

The OSS runtime already has a connected external guardrail pipeline with
timeout and fail-mode behavior. The migration extends that path. It does not
copy the old parallel registry.

The target adapter set is:

- Aporia and Lakera, retaining and strengthening the existing OSS support;
- Azure AI Content Safety;
- Amazon Bedrock Guardrails;
- CrowdStrike;
- Mistral moderation;
- Pangea;
- Patronus;
- Prompt Security;
- a documented generic webhook contract.

Each adapter owns only request shaping, authentication, and response parsing.
The shared pipeline owns URL validation, body limits, timeout behavior,
fail-open or fail-closed policy, verdict normalization, metrics, and audit
events. Secrets use the existing secret-reference system and never appear in
configuration examples as live values.

An adapter becomes documented only when a local HTTP contract test proves its
request, authentication, response, timeout, and malformed-response behavior
through the real guardrail pipeline.

## RAG runtime

The old RAG crate has useful drivers but no complete retrieval flow. The OSS
runtime completes the sequence:

1. Extract the configured query from the incoming AI request.
2. Embed the query with Bedrock, Cohere, OpenAI, Vertex, or a compatible local
   embedding source.
3. Query Chroma, Pinecone, Qdrant, Redis, or Weaviate through a bounded
   vector-store interface.
4. Apply tenant filters, result count and size limits, score thresholds, and
   deterministic ordering.
5. Render the selected chunks into the configured prompt template.
6. Send the enriched request through the existing guardrail, budget, routing,
   streaming, usage, and audit path.

RAG configuration is route scoped and opt-in. Existing configurations retain
their behavior. The compiled runtime resolves providers and validates
templates at load time. A retrieval failure follows an explicit per-route
policy: fail closed, continue without context, or use a bounded stale result.
The default is fail closed when RAG is enabled.

Retrieved content is untrusted input. The runtime preserves tenant isolation,
caps chunk and aggregate bytes, rejects unsafe provider URLs, records source
identifiers without logging full private content, and sends the final prompt
through the configured guardrails.

## Distributed semantic cache

The existing local semantic cache remains the canonical implementation.
Configuration adds a backend choice:

- memory, preserving today's behavior;
- Redis, for deployments that share a Redis service;
- mesh, using the current `sbproxy-mesh` membership and ownership layer.

All backends implement one cache-store contract for lookup, insert, scoped
purge, health, and statistics. Keys bind the normalized request to tenant,
credential scope, model and provider compatibility, semantic-cache
configuration version, and response-policy identity. A hit can never cross
one of those boundaries.

Random-projection LSH and key-template ideas from the old adapter may be
reused after tenant and collision tests. Mesh ownership and handoff come from
the current OSS mesh. A peer or Redis failure becomes a cache miss unless an
operator selects a stricter policy. Corrupt, incompatible, or ambiguously
scoped entries are rejected.

Cluster tests run at least two local nodes and prove a remote hit, TTL expiry,
owner failure, handoff, tenant isolation, and cluster-wide purge through the
same request path used by the proxy.

## Payment settlement

`sbproxy-billing` owns rail-neutral money, usage, intent, receipt, refund,
webhook, reconciliation, idempotency, and replay types. Its default feature
set is empty. The binary exposes explicit compile gates for payments and for
each provider:

- Stripe;
- x402;
- MPP;
- Lightning, with separate LND and CLN gates.

Runtime configuration chooses from the adapters compiled into the binary.
Startup rejects a configured adapter that is not compiled or cannot construct
its credentials and provider client.

The request path verifies local proof material, applies replay protection,
writes a durable settlement intent, and returns the existing 402 or
authorization result. A background worker claims the intent, calls the rail,
stores the receipt, emits metrics and audit events, and retries with a bounded
policy. Provider calls do not run synchronously in the ordinary proxy path.
Any rail that truly requires synchronous remote authorization must declare a
short timeout, circuit breaker, and fail-closed behavior.

Migration order inside the payment pull request is:

1. money, intent, idempotency, replay, registry, and durable outbox contracts;
2. x402 verification, facilitator failover, and reorg handling;
3. Stripe settlement, webhooks, and refunds;
4. MPP preview, settlement, pagination, and disputes;
5. Lightning settlement through CLN and LND.

The old empty reconciliation reports do not migrate. Each rail either returns
real provider-backed reconciliation data or an explicit unsupported result.
Lightning cannot return a successful refund receipt without a payer
destination. It returns a typed error instead. There are no ignored happy-path
tests for a rail that the documentation calls supported.

## Product truth and website

The OSS repository removes:

- `docs/enterprise.md`;
- current links to that page;
- current feature claims that describe a proprietary implementation;
- sibling-repository checks and `sbproxy-enterprise` crate-graph rules;
- enterprise-only startup-hook names where the hook is now a normal extension
  or native runtime hook.

The website removes the `/enterprise` route, page, canonical URL, sitemap
entry, navigation links, pricing links, and generated text. `/contact` and
`/pricing` must not redirect to it. If those pages remain, they describe OSS
deployment help or possible future services without assigning current
features to a paid edition.

The separate repository may remain as a private historical source during the
migration. The public project does not link to it. Archiving or deleting that
repository is a separate owner action after parity is verified.

## Documentation information architecture

The final phase audits all public Markdown pages, website documentation,
generated indexes, and example directories. The current set has more than
one hundred public Markdown pages and more than one hundred eighty example
directories. The audit classifies each item as canonical, merge, redirect,
historical, generated, or delete.

Stale `sbproxy-rust` and active Go-implementation wording is removed. A Go
reference remains only when migration or compatibility history needs it, and
then it points to `https://github.com/soapbucket/sbproxy-go`.

The target navigation is a flat file layout presented through a small number
of reader paths:

```text
Documentation
├── Start
│   ├── Getting started
│   ├── Core concepts
│   └── One complete gateway walkthrough
├── Traffic
│   ├── API traffic
│   ├── MCP and agent traffic
│   ├── AI model traffic
│   └── Agent and crawler traffic to your content
├── Traffic lifecycle
│   ├── Accept and identify
│   ├── Inspect and govern
│   ├── Route, retrieve, and serve
│   ├── Optimize and cache
│   ├── Observe, account, and settle
│   └── Operate and scale
├── Operate
│   ├── Deploy and upgrade
│   ├── Observe and troubleshoot
│   └── Secure and recover
└── Reference
    ├── Configuration
    ├── Providers and protocols
    ├── Admin API
    └── Compatibility and migrations
```

The file layout stays flat to match repository convention. Navigation and
cross-links provide the hierarchy.

The root README, documentation index, getting-started guide, core concepts,
and the traffic hubs carry the main product explanation. The canonical hubs
are a new `api-gateway.md`, the existing `mcp.md` and `ai-gateway.md`, and
`content-for-agents.md` for AI callers reaching operator-owned content.
Technical references add one short line that places the feature in the
relevant traffic stage when that context helps. They do not repeat a
marketing paragraph on every page.

The core message is factual:

- one proxy and one configuration model govern ordinary APIs, MCP and agent
  calls, and AI model traffic;
- policies apply before, during, and after an upstream call;
- SBproxy can identify callers, inspect content, route and transform traffic,
  add retrieval context, cache safely, stream responses, record outcomes, and
  settle paid access;
- operators can run the Apache-2.0 binary on their own infrastructure without
  changing every application SDK.

Claims must point to implemented configuration, a tested example, or a
reference page. Unsupported or planned behavior is labeled clearly or
removed.

## Consolidation and deletion rules

A public page is merged or removed when it duplicates a canonical page,
documents an internal implementation checkpoint, describes behavior that
never shipped, or cannot answer a distinct reader task. Before deletion:

1. Move any unique and accurate material into its canonical destination.
2. Update repository, website, generated, and example links.
3. Add a website redirect when an indexed public URL has a useful replacement.
4. Do not redirect `/enterprise`; remove that product route.
5. Regenerate `llms.txt`, `llms-full.txt`, website data, and the sitemap.
6. Run link, anchor, snippet, schema, and example validation.

Detailed references remain separate when operators need them during an
incident or while editing configuration. Concision does not justify mixing a
runbook, protocol contract, and beginner walkthrough into one long page.

The first consolidation targets are the clusters with clear canonical owners:

- fold the five estate quickstarts into the API, MCP and agent, AI model, and
  content traffic hubs;
- merge five framework-specific pages into `connect-clients.md`, keeping only
  the tested setup differences for each client;
- merge `admin-api-guide.md` into the task sections of `admin.md`, while
  keeping `admin-api-reference.md` as the schema reference;
- move the thin AI governance, routing, resilience, budget, and ledger pages
  into a smaller set of AI gateway guides;
- move use-case walkthrough prose into the matching runnable example README;
- consolidate individual policy pages into `policy.md` when they do not need
  a distinct incident or protocol reference;
- merge challenge and rail material into a new payment settlement guide;
- remove `enterprise.md` and the time-sensitive `comparison.md`;
- keep migration and benchmark evidence outside the beginner navigation.

`features.md` currently has many inbound links and owns forty-one VHS
placements. Its accurate capability material and recordings move to the
traffic hubs before the file is removed. Existing public paths with a useful
replacement may keep a short moved-page stub for one release. Internal
planning artifacts never appear in public navigation or generated
`llms-full.txt`.

## Examples and recordings

The surviving documentation centers on four golden walkthroughs:

1. Gateway basics. Rename the existing credential-free
   `enterprise-ai-gateway` example to `all-traffic-gateway` and retain its
   progressive API, OpenAPI-backed MCP, and OpenAI-compatible AI flow.
2. AI you call. Walk a local request through credentials, input guardrails,
   routing and fallback, provider streaming, output guardrails, semantic
   cache, RAG, and usage accounting.
3. AI that calls you. Walk through Web Bot Auth, MCP discovery and policy,
   agent-aware content, 402 negotiation, and real local settlement.
4. AI you run. Walk through model-host checks, admission, acquisition,
   startup, routing, and observation, with CPU or mock CI and clearly labeled
   optional GPU certification.

Each walkthrough includes:

- the problem and a small architecture diagram;
- prerequisites with credential-free local defaults;
- a complete, validated `sb.yml`;
- a field-by-field explanation of what the configuration changes and why;
- exact start, request, expected-response, log, and metrics commands;
- failure cases and the first troubleshooting check;
- cleanup commands;
- a deterministic smoke test used by CI.

Provider credentials from `test/.env` may be used for secret-gated tests, but
they are never printed, copied into examples, recorded in VHS output, or
committed.

VHS tapes use local deterministic fixtures wherever possible. Recordings show
the command, meaningful output, and verification without long install or
compile sequences. Generated assets are rebuilt after the runtime and docs
stabilize, then checked for stale commands and accidental credentials.

The personal-voice pass comes after accuracy and consolidation. Public prose
uses plain language, varied sentence rhythm, specific claims, and direct
instructions. It removes AI writing tics, filler, repetitive signposting, and
em or en dashes. Functional reference material stays direct rather than
trying to sound conversational. Each rewritten hub receives a final
AI-smell review, with a target score no higher than 15 out of 100.

The current walkthrough set has a functional-doc AI-smell baseline of about
29 out of 80, driven by repeated templates, uniform section rhythm, and
mechanical catalogs. The four walkthroughs replace those templates with
specific goals and verification.

## Configuration accuracy

The generated JSON Schema is the field-level source of truth. The current
handwritten `configuration.md` is too large to maintain as a second schema:
an audit found 939 typed property paths and 186 leaf names absent from that
page. The rewrite turns `configuration.md` into a concise map of configuration
anatomy, precedence, scoping, reload behavior, and worked combinations. It
links each field family to generated schema reference.

Every public YAML block is either:

- validated directly against the current schema;
- sourced from a validated example file; or
- labeled as a partial fragment with enough parent context for the reader to
  place it correctly.

The repository currently has 567 YAML fences that docs CI does not validate.
The final docs phase adds snippet validation and runs the example configuration
sweep on examples-only changes. The `examples/README.md` front page becomes
the four walkthrough routes plus a compact generated catalog, rather than a
hand-maintained table of every directory.

## Failure behavior

Existing configurations keep their behavior unless an operator enables a new
feature. New provider integrations fail at configuration load when required
fields, credentials, compiled features, or safe URL policy are missing.

At runtime:

- guardrails follow the configured fail mode and record provider failures;
- RAG follows its explicit retrieval failure policy;
- semantic cache infrastructure failures become misses by default;
- payment proof or persistence failures fail closed;
- asynchronous provider failures remain durable, visible, and retryable
  without charging twice.

No adapter returns a synthetic safe verdict, empty reconciliation, fake
refund receipt, or successful startup merely to satisfy an interface.

## Verification

Inner-loop testing stays selective:

- changed-crate checks and unit tests;
- local HTTP or gRPC contract tests for one provider at a time;
- focused config and example validation;
- two-node semantic-cache tests;
- one proxy lifecycle test for each new runtime path;
- docs link, anchor, generated-index, and VHS tape checks.

Before each pull request is merged, run formatting, targeted Clippy, affected
crate tests, and the relevant end-to-end files. The final branch also runs the
workspace CI lane once. Live provider tests are separate secret-gated jobs and
do not replace deterministic local tests.

The baseline before implementation is:

- targeted `cargo check` for `sbproxy-httpkit`, `sbproxy-ai`,
  `sbproxy-mesh`, and `sbproxy-modules`: passed;
- 3,271 targeted library tests across those crates: passed;
- six tests skipped by the existing test configuration.
- all 181 example configurations in the config validation sweep: passed;
- the configuration reader consistency check: passed.

The example result proves schema compilation, not runtime behavior. Golden
walkthroughs need request and response assertions through a running proxy.

## Delivery sequence

The work is one migration epic delivered in reviewable dependency order:

1. OSS product truth, shared outbound HTTP, and connected vendor guardrails.
2. RAG crate, configuration, runtime integration, and focused docs.
3. Redis and mesh semantic-cache backends with cross-node tests.
4. Payment settlement crate, adapters, durable worker, and lifecycle tests.
5. Repository-wide documentation and example consolidation.
6. A separate website pull request, because `www.sbproxy.dev` is a different
   repository, merged with the final documentation phase.

Every runtime pull request updates the narrow reference and example needed to
operate its feature. The final documentation pull request performs the broad
information-architecture, voice, cross-link, recording, and deletion pass
after all feature claims can be checked against the merged runtime.
