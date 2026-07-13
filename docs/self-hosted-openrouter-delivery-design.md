# Self-hosted OpenRouter delivery design
*Last modified: 2026-07-13*

*Status: Approved delivery design. The implemented operator-product slice is
labeled below. Remote distributed inference and live hardware certification
remain roadmap gates, not shipped claims. Stable product claims remain
controlled by the executable capability registry and certification evidence.*

## Decision

SBproxy will provide an OpenAI-compatible router for models running on
operator-controlled hardware. One implementation will support:

- One Apple Silicon Mac running llama.cpp.
- One NVIDIA GPU VM running vLLM or llama.cpp.
- Symmetric clusters where every node can accept traffic and host models.
- Split clusters with gateway-only and worker-only nodes.
- Fallback chains that mix managed replicas with unmanaged or cloud providers.

Single-node serving is the one-node implementation of the same deployment,
directory, routing, policy, and observability contracts used by a cluster.
When clustering is disabled, SBproxy starts no gossip, peer-transport, or
distributed-state tasks.

The delivery roadmap uses seven sequential, independently reviewable pull requests.
Live GCP validation is reserved for the final certification pull request.

## Source and baseline

This design is the delivery contract for:

- [WOR-1835](https://linear.app/soapbucket/issue/WOR-1835/self-hosted-openrouter-managed-models-and-governed-multi-node), the canonical self-hosted OpenRouter epic.
- [WOR-1652](https://linear.app/soapbucket/issue/WOR-1652/model-host-local-model-serving-vllm-first-epic), the preceding single-node model-host epic.

The source audit was refreshed against `origin/main` commit
`70f967514a5e2686dd693d312f27873f6e7f60bf`. That commit includes PR #675,
which added advanced dynamic-key fields, priority admission lanes, serving
metrics, and corrected Apple Silicon probes. This design retains those
features as foundations and does not reimplement them.

The existing model-host, AI router, dynamic key plane, SWIM mesh, distributed
cache, health feedback, hot-reload pipeline, metrics, and admin site are the
starting seams. New work replaces first-config-wins state and config-only
claims with executable contracts.

## Scope

### Canonical scope

All 23 WOR-1835 children, SH-01 through SH-23, remain in scope. The program
also absorbs production-critical outcomes still open under WOR-1652:

- Manifest and immutable variant semantics from WOR-1681.
- A shared `models pull` workflow from WOR-1682.
- Explicit engine provisioning from WOR-1684.
- The self-hosting guide and truthful parity map from WOR-1685.
- Safetensors-first supply-chain enforcement from WOR-1666.
- Exact token counting needed by governed TPM limits from WOR-1671.
- Hybrid local-to-cloud policy and value reporting from WOR-1657 and WOR-1665.
- Documentation, examples, and schema regeneration from WOR-1661.
- CUDA-capable llama.cpp acquisition on Linux/NVIDIA from WOR-1813.

These outcomes are implemented through the WOR-1835 architecture instead of
preserving obsolete `serve:`-only boundaries.

### Explicit deferrals

The following WOR-1652 research tracks are not required for the production
contract and remain separate backlog work:

- WOR-1670, profiled throughput-aware fit prediction.
- WOR-1674, speculative-decoding planning.
- WOR-1675, managed local embeddings and rerankers.
- WOR-1677, multi-tier streamed weight loading.
- WOR-1678, automatic chunked-prefill tuning.

Deferral does not permit hidden stubs or stable claims. Any existing field
related to a deferred feature must either execute correctly, remain explicitly
preview, or be removed from stable configuration and UI.

### Non-goals

- Training or fine-tuning.
- Splitting one model across physical nodes.
- Cross-node vLLM tensor parallelism.
- General-purpose Kubernetes orchestration.
- Cloud VM provisioning or autoscaling from SBproxy.
- Strong-consensus orchestration for arbitrary jobs.
- Replacing Prometheus for long-term fleet telemetry.
- Managing Ollama as an engine. Unmanaged Ollama remains a provider.
- Bit-identical output across quantizations.

## Product outcome

An operator can install SBproxy, select a compatible model, and receive an
OpenAI-compatible endpoint on hardware they control. Adding nodes does not
change client keys, logical model names, policy, routing rules, metrics, or the
admin workflow.

The result must be:

- Easy: common paths do not require quantization, engine, or GPU-fit expertise.
- Truthful: accepted stable configuration executes end to end.
- Governed: one effective key policy applies to local, peer, and external routes.
- Resilient: failures do not expose engines, bypass policy, or replay streams.
- Observable: one control surface explains desired, cached, loading, resident,
  routed, blocked, and failed state.

## Architecture boundaries

    Client -> gateway policy and reservation -> provider router -> ModelDirectory
                                                               |-> local runtime -> engine
                                                               \-> private model plane -> remote runtime -> engine

    ClusterHandle -> node snapshots -> ModelDirectory
    CLI and admin -> runtime, directory, artifact, deployment, and job services

### Local model domain

`sbproxy-model-host` owns:

- Catalog v2 and executable variant selection.
- Artifact resolution, acquisition, verification, cache accounting, and jobs.
- Managed llama.cpp and vLLM engine drivers.
- Reconcileable desired state.
- Residency, queues, lifecycle, and worker-local admission.
- Hardware telemetry used for admission and published status.

It does not own mesh bootstrap, admin HTTP handlers, or UI state.

### Cluster substrate

`sbproxy-mesh` gains a shared `ClusterHandle`. It wraps either a local
implementation or the existing live `MeshNode` substrate. Core startup creates
one handle and supplies it to keys, model snapshots, metrics, and other
distributed consumers.

`ClusterHandle` owns node identity, roles, labels, discovery, liveness, peer
identity, encrypted transport, and typed distributed state. It does not decide
model fit or request admission.

### Routing integration

`sbproxy-ai` defines the model-directory and replica-routing interfaces.
`sbproxy-core` composes the local runtime with cluster snapshots and provides
local or authenticated peer dispatch.

The gateway evaluates caller policy before topology. A selected worker performs
hard local admission. Eventual placement may temporarily overprovision, but it
cannot authorize a request, exceed worker capacity, or make an unreachable
replica eligible.

### Governance

The ingress gateway compiles `EffectiveKeyPolicy` and reserves strict limits
before provider or replica selection. A remote worker receives a signed,
short-lived dispatch envelope. It never receives the caller's raw key and never
charges usage a second time.

### Control surfaces

CLI, admin API, admin UI, metrics, and documentation are adapters over the same
runtime services. They cannot create their own lifecycle state or claim support
that is absent from the executable capability registry.

## Core contracts

The detailed implementation plans may refine Rust module placement, but the
following semantic contracts are stable.

### Capability registry

A versioned registry describes catalog, artifact, engine, lifecycle, cluster,
policy, admin, and platform capabilities as `stable`, `preview`,
`config_only`, or `unsupported`. Stable entries identify executable evidence.
CLI and admin responses consume this registry.

### Model catalog v2

A logical model contains immutable artifact variants. Each variant declares:

- Format and compatible engine.
- Exact source revision and files.
- Digests and byte sizes.
- Accelerator and engine requirements.
- Context and license metadata.
- Stability and certification state.

Resolution returns one `ResolvedArtifact`. Auto selection considers only
variants that the selected engine can run on the current worker. A pinned
deployment resolves identically across replicas unless heterogeneous variants
are explicitly enabled.

### Deployment revision

All desired-state sources compile to a versioned `DeploymentRevision` with:

- Source mode and source revision.
- Logical deployments and pinned catalog revision.
- Replica counts and placement constraints.
- Pull, warm, keep-alive, concurrency, and queue behavior.
- Engine overrides and rollout policy.
- A content digest used for comparison, signing, and audit.

The runtime publishes a revision only after complete validation. Validation
failures occur before revision publication and leave the current revision
pointer unchanged.

### Operation job

Pull, verify, provision, launch, load, drain, stop, rollout, and deletion use
durable job identities. Jobs retain terminal timestamps and errors for a
bounded history. CLI and admin consume the same job and event model.

### Node model snapshot

Workers publish versioned, expiring snapshots containing roles, labels,
model-plane endpoint, engine capabilities, hardware, artifact state, replica
state, active requests, queue depth, loaded adapters, and bounded error codes.

Membership supplies candidate node IDs. Snapshot generation prevents stale
replacement. Suspect, dead, expired, incompatible, or unreachable nodes are
excluded from new requests.

### Dispatch envelope

Remote requests carry an audience-bound, expiring, replay-limited, signed
envelope containing request identity, governed key identity, tenant,
policy revision, deployment, model, priority, and a maximum hop count of one.

## Desired-state ownership

SBproxy supports three explicit deployment-authority modes.

| Mode | Persistent authority | Admin behavior |
| --- | --- | --- |
| `admin_managed` | Versioned durable SBproxy deployment store | Browse catalog evidence; create, edit, replace, load, stop, reset, and remove deployments through full-map compare-and-swap |
| `file_managed` | `sb.yml`, a deployment file, or an external GitOps process | Persistent fields are read-only; changes use config review and the shared apply or reload path |
| `cluster_authority` | One configured authority signs restricted complete deployment bundles | The authority UI can publish; verifier nodes show the coherent proof and remain read-only |

The admin server never silently rewrites `sb.yml`.

Admin mutations use optimistic revision checks, strict desired-state and active
catalog validation, tracing audit events, and explicit post-conflict
comparisons. Cluster bundles may contain only model deployments, catalog
revision, and placement rules. They cannot contain secrets, arbitrary proxy
configuration, or private keys.

The model-management UI supports:

- Catalog evidence with support, certification, exact-variant availability,
  engine and accelerator compatibility, download size, minimum memory, and
  license acknowledgement.
- Auto or explicit artifact-variant selection without substituting evidence
  when an exact pin is unavailable.
- Full deployment creation and editing for replicas, placement labels and
  spread, pull and warm behavior, keepalive, concurrency, queueing, engine,
  and rollout.
- Load, stop, reset, and guarded deployment removal.
- Conflict comparison that preserves the attempted map and form, reloads the
  latest proof, and requires an explicit retry.
- A cluster health rail, prominent unhealthy-node alerts, the complete roster,
  stale-evidence warnings, rollout detail, and independent fleet metrics.

Removal is disabled while runtime evidence is stale or the deployment is
ready, preparing, or draining. Conflict retry repeats the same safety check.

## Runtime flows

### File-managed reload

    read sb.yml
      -> compile config, routes, catalog, and desired deployments
      -> prepare the complete runtime candidate
      -> commit the runtime revision
      -> publish the request pipeline

File reload has no deployment-store compare-and-swap and no signed-bundle
cursor. Parse, validation, and preparation failures occur before runtime and
pipeline publication. Runtime commit can stop an old recreate generation;
SBproxy attempts to restore it if activation fails, but rollback can fail and
leave the current runtime degraded. The file remains authoritative, so recovery
means correcting it or its runtime dependencies and reloading explicitly.

### Admin-managed replacement

    authenticate strict full-map PUT
      -> validate desired state and active catalog references
      -> compare expected_revision under the commit lock
      -> prepare the complete runtime candidate
      -> deployment-store compare-and-swap
      -> activate the prepared runtime revision
      -> return the committed revision and plan

Body, validation, cursor, and preparation failures occur before the durable
compare-and-swap. A race aborts staged work. Activation occurs after the store
advances. It attempts to preserve unaffected generations and restore prior
recreate generations on error, but rollback can fail. A failed request can
therefore leave the durable revision advanced and runtime degraded. Recovery
starts with the desired-state GET, runtime status, and logs, followed by a
corrected full-map write from the current revision or a controlled restart.

### Cluster-authority publication and application

    authority POST
      -> validate the restricted bundle and revision
      -> sign and verify the envelope
      -> publish content, then its current pointer
      -> return 202 published

    each node
      -> read pointer and content
      -> verify identity, signature, digest, revision, and catalog
      -> prepare local placement and runtime
      -> persist local generation fences and bundle cursor
      -> activate the local runtime revision
      -> mark the verified bundle active

The `202` response proves signing and cluster-state publication only. It does
not prove node application. A node can reject the candidate before activation,
or its local cursor can advance before an activation failure. Runtime rollback
can also fail and leave that node degraded. Cluster status, rather than the
publication response, proves placement, readiness, and rollout.

After a successful runtime activation, reconciliation preserves unaffected
engines. Additions prepare before becoming eligible. Replacements become ready
before the old generation drains, subject to the documented handoff timeout.
Removal stops new admissions before bounded drain and shutdown.

### Artifact and launch

    resolve
      -> acquire one per-digest lock
      -> write partial bytes
      -> verify immutable revision and digest
      -> atomically publish ready bytes
      -> provision engine
      -> launch and probe
      -> publish ready replica

A ready cache hit performs no weight-network request. Concurrent callers attach
to the same job. Missing manual artifacts, offline policy violations, and
digest mismatches fail before an engine reads the path.

### Request

    authenticate key
      -> compile effective policy
      -> reserve strict limits
      -> select provider
      -> expand and select eligible replica
      -> dispatch locally or over the private model plane
      -> stream
      -> commit actual usage and release unused reservation

Provider and logical-model policy run before replica selection. Worker-local
admission remains authoritative for memory, queue, lifecycle, and engine
health.

## Failure and security rules

- Failover is allowed only before response headers or tokens.
- Mid-stream failure is surfaced without replay and records partial outcome.
- Engine ports bind to loopback or a private container network.
- Production peer inference requires mTLS and a valid dispatch envelope.
- Authentication, replay, or policy-context failures are security events, not
  capacity failures.
- Strict distributed limits fail closed on backend outage unless an explicit,
  audited failure mode is configured.
- Reservation leases bound the effect of a crashed gateway.
- Unknown GPU compute utilization is not treated as idle.
- Raw keys, secrets, prompts, private worker addresses, and unbounded labels do
  not enter status, traces, metrics, or job records.
- Artifact and engine failures retain stable reason codes and remediation.
- Admin mutation conflicts, validation failures, authorization failures, and
  asynchronous jobs have distinct response contracts.

## Compatibility

New stable configuration centers on `proxy.model_host` and `proxy.cluster`.
Existing provider `serve:` blocks lower into normalized deployments for one
documented migration window. Existing unmanaged local and cloud providers keep
their current behavior.

Legacy compatibility may not preserve an inert field. A legacy field must
lower to live behavior, produce actionable migration rejection, or be removed
from stable schema and UI.

## Seven-pull-request delivery

Each pull request starts from the merged predecessor, passes the full
repository gate, includes docs and schemas for its stable slice, and does not
advertise the next slice as stable.

This program design does not replace task-level planning. Each pull request
receives its own implementation plan with exact files, interfaces, tests, and
commit checkpoints before that slice changes production code.

### PR 1: Foundations

Primary Linear scope: SH-01, SH-02, SH-03, SH-06, plus WOR-1681, WOR-1682,
and WOR-1666 outcomes.

Deliver:

- Executable capability registry.
- Catalog v2 and deterministic variant resolution.
- Deployment-source contract and admin-managed durable revision store.
- Atomic artifact manager, operation jobs, locks, resume, verification, and GC.
- Enforced on-boot, on-demand, manual, file, and offline behavior.
- CLI pull workflow using the shared artifact manager.

Exit: catalog selection and `models pull` work end to end without launching an
engine. Cache restart, concurrency, digest mismatch, manual, and denied-network
tests pass.

### PR 2: Local runtime

Primary Linear scope: SH-04, SH-05, SH-07, SH-17, plus WOR-1684 and WOR-1813
outcomes.

Deliver:

- Typed llama.cpp and vLLM engine drivers.
- Reconcileable process-wide runtime manager.
- Local admission, priority queue integration, lifecycle, and telemetry.
- One-command run workflow and complete model lifecycle CLI.
- Admin-managed local deployment reconciliation.
- Linux/NVIDIA llama.cpp acquisition that can use CUDA-capable releases.

Exit: the Mac path serves a real request, simulated NVIDIA tests pass, hot
reload preserves unaffected engines, and no engine sees unverified bytes.

### PR 3: Cluster control plane

Primary Linear scope: SH-08, SH-09, and SH-10.

Deliver:

- Shared local or distributed `ClusterHandle`.
- Node enrollment and identity lifecycle.
- Versioned node snapshots and lock-free model directory.
- Deterministic placement, spread, rollout, and generation rules.
- Local and signed cluster-authority deployment sources.

Exit: multi-process tests converge assignments, exclude stale or dead replicas,
minimize placement movement, and drain old generations safely.

### PR 4: Distributed data plane

Primary Linear scope: SH-11, SH-12, SH-13, and SH-16.

Deliver:

- Authenticated private HTTP/2 model plane.
- Dispatch-envelope signing, validation, replay protection, and cancellation.
- Managed replica expansion inside provider routing.
- Local fast path, remote streaming, cold-start coordination, and backpressure.
- OpenRouter-style logical model listing, safe route headers, and stable errors.

Exit: a simulated three-node topology streams through a remote worker and
fails over before output without exposing an engine or public key.

### PR 5: Governance

Primary Linear scope: SH-14 and SH-15, plus the remaining production outcomes
from WOR-1657 and WOR-1671.

Deliver:

- Complete server-derived effective key policy.
- Exact token accounting for governed TPM behavior.
- Strict atomic reserve, commit, release, and lease operations.
- Cluster revocation propagation and consistency reporting.
- Hybrid local-to-cloud policy, accounting rates, and route traces.

Exit: policy and limits behave identically through local, peer, and external
routes. Concurrency tests prove strict allowances are not exceeded.

### PR 6: Operator product, implemented slice

Primary Linear scope: SH-18, SH-19, SH-20, SH-21, and SH-22, plus WOR-1685,
WOR-1661, and WOR-1665 outcomes.

Implemented in this slice:

- Authenticated catalog evidence and complete desired-state APIs.
- Durable `admin_managed` replacement with revision conflict handling and
  restart recovery.
- Mode-aware model management for admin, file, cluster authority, and cluster
  verifier nodes.
- Catalog, deployment, runtime, lifecycle, conflict, and removal-safety UI.
- Cluster health, complete roster, unhealthy-node alerts, stale evidence,
  rollout state, coherent authority proof, and separate fleet metrics UI.
- Contract, backend E2E, and UI unit/component evidence, plus regenerated public
  capability and documentation artifacts.

This slice does not promote the roadmap's remote peer inference, managed
service packaging, GPU worker image, or live hardware certification outcomes.
Those keep their own delivery and evidence gates.

### PR 7: Certification

Primary Linear scope: SH-23.

Deliver:

- Clean Apple Silicon certification.
- GCP T4 and L4 single-node certification.
- GCP split and symmetric three-node failure drills.
- Rolling deployment, key-revoke, and strict-budget concurrency evidence.
- Final capability matrix, support boundaries, and release documentation.

Exit: every promoted stable claim has reproducible evidence recording binary,
engine, model, artifact digest, hardware, command, timing, and result. GCP
resources are created only for this phase and torn down afterward.

## Verification

### Local and CI tiers

1. Unit and property tests cover catalog, placement, policy, reservations,
   signatures, state machines, and metric cardinality.
2. Integration tests use mock artifact servers, fake engines, temporary
   caches, Redis, cancellation, restart, and denied-network fixtures.
3. Multi-process tests run gateway and worker nodes with ephemeral
   certificates, stale snapshots, network faults, and rolling revisions.
4. Every pull request runs formatting, workspace build, non-e2e nextest,
   doctests, clippy with warnings denied, rustdoc with warnings denied, UI
   typecheck and component tests, schema checks, and docs/example gates.

### Final live tiers

- Supported Apple Silicon versions and memory classes.
- GCP `n1-standard-8` plus one `nvidia-tesla-t4` for the 16 GB,
  lower-memory, no-FP8 lane.
- GCP `g2-standard-8` with one L4 for the 24 GB vLLM lane.
- GCP `g2-standard-24` with two L4 GPUs for within-node multi-GPU.
- One `e2-standard-4` gateway plus two `g2-standard-8` workers for the
  split-cluster lane.
- Three `g2-standard-8` hybrid nodes behind one client entry point for the
  symmetric-cluster lane.
- Air-gapped staged artifact behavior.

The G2 shapes and GPU counts are pinned to the current
[Compute Engine GPU machine-type table](https://cloud.google.com/compute/docs/gpus).
The certification scripts verify regional availability and quota before
creating resources but do not silently substitute a different GPU class.

## Documentation contract

Every pull request includes:

- Public documentation for stable behavior.
- Migration notes for changed configuration.
- Admin API schemas and CLI JSON contracts.
- Runnable examples and troubleshooting.
- Capability-registry changes that match executable evidence.

Stable documentation contains no hidden source-tree prerequisite, unresolved
symbolic value, or capability that is only parsed or displayed.

## Definition of finished

The program is finished when:

- All seven pull requests are merged or ready with clean required gates.
- Apple Silicon and GCP certification evidence is complete.
- The three-node kill, rolling update, key revocation, and strict-budget
  concurrency drills pass.
- Admin and CLI operate on the same desired state, jobs, and runtime truth.
- External and unmanaged providers remain compatible.
- The final capability matrix lists only proven stable behavior.
- GCP resources are torn down after evidence capture.
- Linear issues close only when their acceptance criteria have evidence.
- Deferred research tickets contain explicit rationale and are not reported as
  completed by this program.

## Linear stewardship

At the start of each pull request, the mapped Linear children move to active
work. The pull request description lists exact acceptance criteria and evidence
paths. A child moves to Done only when all of its criteria pass. Partial work is
reported in a comment and remains open.

WOR-1835 remains the canonical epic. WOR-1652 closes when its production
outcomes are either evidenced through this program or explicitly deferred as
research with links to the responsible tickets.
