# Enterprise
*Last modified: 2026-05-03*

What's in OSS, what the enterprise tier adds, and how to talk to us
about it.

## OSS is the whole runtime

The full SBproxy data plane is open source and self-hostable. Routing,
AI gateway, MCP gateway, guardrails, security policies, and scripting
(CEL, Lua, JavaScript, WebAssembly) all ship in this repository. There
is no feature ceiling on the runtime itself.

The enterprise tier adds capabilities that only matter once you are
running SBproxy at organizational scale or under regulator pressure.
None of them are required to use SBproxy in production.

## What enterprise adds

### Cluster substrate

Gossip mesh membership, consistent-hash routing across nodes, leader
election, federation, five service-discovery providers, and a
cluster-distributed semantic cache with LSH-bucketed embeddings,
cluster-wide purge propagation, and per-origin and per-model TTL
layering.

### Regulated-enterprise auth

SAML, Biscuit, and three OAuth flows (authorization code, client
credentials, device code) on top of the OSS auth surface. ext_authz
delegation. SPIFFE workload identity. HSM availability probe.
Multi-source entitlements drawn from Redis, the mesh, a CDB store,
and Postgres.

### Vendor guardrail integrations

Aporia, Azure Content Safety, Bedrock Guardrails, CrowdStrike, Lakera,
Mistral, Model Armor, Pangea, and Patronus. Plus the first-party
guardrails that already ship in OSS.

### Evaluation runtime

Datasets, experiments, prompt scoring, and an LLM-as-judge harness for
running offline evaluations against captured traffic.

### RAG runtime

Five embedding providers (Bedrock, Cohere, OpenAI, Vertex, custom) and
five vector stores (Chroma, Pinecone, Qdrant, Redis, Weaviate). Built-in
chunking and a retrieval pipeline.

### Operations layer

Kubernetes operator with full CRDs. Classifier sidecar (gRPC embed and
classify). GPU-aware and LoRA-aware routing. Bandit routing. Named
support contact, SLA, security review, and onboarding.

## Extension points OSS exposes

If you want to build something equivalent on top of OSS rather than
buy enterprise, the runtime exposes the same hooks the enterprise
crates use:

- The `extensions` opaque map on `proxy.*` and per-origin config is
  unparsed by OSS. Enterprise crates read their own keys here. See
  [`config-reference.md`](config-reference.md).
- The `EnterpriseStartupHook::on_startup` slot in `sbproxy-core` is
  the entry point for plugins that need to register before the request
  pipeline starts. See [`architecture.md`](architecture.md).
- The plugin trait registry in `sbproxy-plugin` exposes the same
  surface for actions, auth providers, policies, transforms, and
  request enrichers that the enterprise modules use.

## How to get it

- Web: https://sbproxy.dev/enterprise
- Email: hello@soapbucket.com
