# Model host security

*Last modified: 2026-07-11*

The model host starts inference processes beside a gateway that may hold cloud
provider credentials. Treat write access to `sb.yml`, the deployment revision
store, engine paths, and the artifact cache as privileged operator access.

This page describes the local runtime and cluster control-plane boundary. It is
intentionally blunt: a compromised trusted config can select an explicit engine
executable or cluster identity, so configuration integrity is part of the
process-execution trust root.

## Trust boundaries

Five inputs matter:

1. Desired state selects models, engines, cache roots, and process policy.
2. The catalog identifies immutable model artifacts and allowed formats.
3. Engine acquisition selects an executable, uv environment, or container image.
4. Requests arrive through the gateway and must stay outside process control.
5. Cluster identity, membership, snapshots, and signed desired state determine
   which worker may prepare a replica.

The first three and cluster identity are operator-controlled supply-chain
inputs. Request callers are untrusted. They may choose only a public model
exposed by a configured provider; they cannot supply an engine, artifact path,
device, port, peer identity, or argv.

## Configuration is privileged

Canonical engine configuration has a typed shape:

```yaml
proxy:
  model_host:
    engines:
      llama_cpp:
        launch: binary
        version: b9905
        acceleration: metal
        # path: /opt/sbproxy/engines/llama-server
      vllm:
        launch: uv
        version: 0.10.0
        acceleration: cuda
```

There is no free-form shell command. Engine kind, launch method, acceleration,
image, version, digest, path, and shared-memory size are typed fields. The
runtime constructs the remaining argv and environment.

An explicit `path` is still executable authority. SBproxy checks that it is an
executable file and uses it as the selected engine; it does not prove that an
operator path contains an authentic llama.cpp or vLLM binary. Restrict config
writers, make engine directories root-owned, and prefer pinned managed
acquisition when config comes through automation.

Legacy `serve.models[].extra_args` receives a fixed allowlist. Flags that can
replace the model, host, port, API key, network, mount, device selection, or
runtime-owned lifecycle settings are rejected during candidate preparation.
Unsupported LoRA, speculative, chunked-prefill, parser, swap, and offload fields
also fail preparation instead of disappearing silently.

## No shell boundary

The process layer receives an executable plus tokenized arguments and a typed
environment map. It clears the gateway environment, restores only an audited
operating-system baseline such as `PATH`, locale, and temporary-directory
settings, then adds driver-owned overrides. Cloud credentials held by the
gateway are not inherited by an engine. The runner calls the operating-system
process API directly. Shell metacharacters inside one argument remain data
because `/bin/sh`, `bash`, and PowerShell are not involved.

This blocks command injection through argument punctuation, but it does not make
an unsafe engine flag harmless. The allowlist remains necessary because an
engine can interpret its own arguments.

## Model artifact integrity

Stable managed deployments use catalog v2. Each variant pins:

- source and immutable source revision;
- every repository-relative file path;
- exact byte length and SHA-256;
- artifact format, quantization, engine compatibility, and worker requirements;
- support and certification identifiers.

The artifact manager downloads into a partial area under a cross-process lock.
Resume is allowed only while URL, entity tag, expected digest, expected size,
and completed length still agree. It verifies every file before atomically
publishing a content-addressed snapshot.

llama.cpp receives one GGUF path from that snapshot. vLLM receives the snapshot
root as a read-only model location. A managed driver cannot fall back to the
catalog repository after resolution.

Safetensors and GGUF are non-executable data formats. Pickle remains dangerous:
the logical catalog model must opt in, and the artifact is scanned before
publication. Do not accept an unreviewed pickle allowlist in a multi-tenant
environment.

### Cache deletion

Exact removal acquires the cache mutation lock, artifact digest lock, and an
exclusive digest lease, then rechecks protection. A prepared or running engine
keeps a shared lease in another process. Configured, resident, pinned, locked,
downloading, verifying, leased, and deleting artifacts fail closed. A queued
pull also blocks removal before a ready snapshot exists. Shared blobs are
reclaimed only after the last snapshot reference disappears.

The CLI can query the authenticated admin status before deletion, but the
configuration file is the durable protection source. Supply `-f sb.yml` when
removing from the cache used by a running file-managed gateway.

## Engine supply chain

### llama.cpp binary and source build

The driver can use a trusted explicit path, a compatible `PATH` executable, or a
pinned release. Built-in b9905 prebuilt assets and the Linux CUDA source archive
have checked-in SHA-256 digests. A custom release may carry an expected digest.
Acquirers share an identity-scoped lock, stage away from the ready path, verify
the archive, and publish only a complete executable directory.

A release version without a digest is weaker than a digest-pinned release. The
availability report says so and provides remediation. Pin the digest for a
production supply-chain policy.

### vLLM uv environment

Managed uv mode pins the vLLM package version and keeps its environment under
the engine cache. Compatibility probing reports the Python, torch, CUDA, and
vLLM relationship before launch. Package-index integrity and the uv download
source remain part of the operator's network and mirror policy.

### vLLM container

Container launch requires `repository@sha256:<64 hex>`. Tags and `latest` are
rejected. The runtime:

- creates an internal private network;
- publishes the engine port on loopback only;
- mounts the verified artifact snapshot read-only;
- scopes the selected NVIDIA devices;
- validates shared-memory size against host capacity;
- builds tokenized Docker or Podman argv without a shell.

The container runtime daemon is a privileged trust boundary. Anyone who can
control its socket may already have host-level authority.

## Process lifecycle

The process runner keeps the last 64 KiB of stderr in memory. It does not leave a
predictable engine log file in the temporary directory. Readiness races the
child exit, so a broken engine fails early instead of waiting through the full
health timeout. Shutdown first asks the child process group to exit, then uses a
bounded force-kill backstop. The group guard prevents the runtime from targeting
the gateway's own process group. On Linux, a parent-death signal also kills the
engine process leader if the gateway exits without running normal shutdown.

Crash retries use bounded exponential backoff. Exhaustion produces retained
`crash_loop` state and requires an explicit reset after the cause is corrected.
This prevents a bad artifact or incompatible runtime from becoming an endless
spawn loop.

The gateway holds a per-request admission permit through the response stream.
Drain blocks new work and waits for those permits. Keep-alive cannot evict a
deployment with active or queued requests.

## Reload and rollback

Every startup and reload path builds a complete candidate. Catalog, routes,
engine policy, artifacts, capacity, and warm deployments must prepare before the
runtime swaps. Rolling replacements prove overlap capacity before launch.
Recreate replacements stop the old generation first and restart it if the warm
replacement fails. A failure tears down staged work and preserves the last good
routes and resident generations.

This transaction protects availability. It does not turn an untrusted config
into safe input. A malicious candidate can still consume download, build, or
preparation resources before it fails, so config write access must remain
restricted.

## Credentials and local admin

Hugging Face credentials exist only in the transport request. Secret values are
zeroized on drop, redacted from errors, and omitted from partial, snapshot, and
job metadata.

`sbproxy run` generates a 32-byte random admin password, writes its temporary
config with owner-only permissions on Unix, binds admin to loopback, and removes
the temporary directory when the handler returns on success or failure. The
password appears in the terminal because the operator needs it for lifecycle
commands. Do not redirect that banner into a world-readable log.

For a persistent config, use an environment or secret-backend reference and keep
the admin listener on `127.0.0.1`. Remote admin needs TLS, an IP allowlist, and
separate named operators. Model lifecycle routes use the same authentication
and audit boundary as the rest of `/admin/*`.

## Cluster identity and authority

Canonical production clustering uses two independent protections:

- mutually authenticated TLS secures typed-state transport and verifies every
  peer certificate against the installed cluster CA and server-name SAN;
- an authenticated cluster gossip key encrypts and authenticates UDP membership
  messages before they can influence the stable node-ID ring.

Missing or invalid production material fails startup. Shared-key-only mode must
be marked as development and is not a production peer-identity claim. Cluster
identity, roles, labels, advertised addresses, endpoints, and security material
are restart-required, so a reload cannot partially split a running process from
its installed identity.

Enrollment creates the worker key locally, sends only its signing request, and
installs the CA-signed result. Tokens are random, expiring, one-time values; the
authority stores their hashes and consumes a token atomically. Requested roles
and labels must be an exact subset of the token grant. An authority role is
never inferred or granted by a worker token.

Worker snapshots are strict, bounded, versioned, path-free documents. They
contain capabilities, capacity, artifact identities, replica state, health, and
the active deployment digest, but no local paths, credentials, private keys, or
engine handles. Publisher node ID and snapshot identity must agree. Expired,
malformed, incompatible, unreachable, suspect, dead, and unhealthy records are
excluded from placement while remaining visible to operators.

Cluster-authority desired state uses a separate Ed25519 key pair. The private
key exists only on a node with the authority role. Bundles deny unknown fields
at every level and can contain only a catalog revision, monotonic revision,
model declarations, and placement rules. Readers verify canonical content
digest, signature, key ID, signer node ID, publisher identity, schema, bounds,
expiry, and a durable monotonic cursor before runtime preparation. Failed
verification or preparation retains the last good bundle. Non-authority admin
writes fail with `deployment_authority_read_only`.

PR 3 does not carry inference requests between nodes. The advertised private
model endpoint is authenticated placement data, not yet a dispatch channel.
Request-envelope signing, replay protection, cancellation, and remote streaming
belong to the distributed data-plane PR and must land before any remote serving
claim is promoted.

## Remaining hardening

These controls are not part of the current stable runtime and cluster-control
contract:

- Linux cgroup CPU and memory limits per engine process;
- dropping ambient capabilities and switching to a dedicated Unix user;
- seccomp or another syscall sandbox for native engines;
- signature verification for every engine release and package index;
- a rootless container requirement;
- persistent desired-state mutation with review and approval in the admin UI;
- authenticated request authorization for multi-node model dispatch.

Live NVIDIA and multi-node validation runs on GCP in the final PR group. Until
that evidence is recorded, NVIDIA uv, container, and CUDA source-build paths
remain preview even though their deterministic process and isolation contracts
run in CI.

## Related

- [model-host.md](model-host.md) covers configuration and operation.
- [model-host-capabilities.md](model-host-capabilities.md) is generated from the
  executable support registry.
- [model-host-certification.md](model-host-certification.md) records the hardware
  validation procedure and evidence boundary.
- [threat-model.md](threat-model.md) covers the broader gateway trust model.
