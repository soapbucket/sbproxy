# Model host security

*Last modified: 2026-07-10*

The model host starts inference processes beside a gateway that may hold cloud
provider credentials. Treat write access to `sb.yml`, the deployment revision
store, engine paths, and the artifact cache as privileged operator access.

This page describes the current single-node boundary. It is intentionally
blunt: a compromised trusted config can select an explicit engine executable,
so configuration integrity is part of the process-execution trust root.

## Trust boundaries

Four inputs matter:

1. Desired state selects models, engines, cache roots, and process policy.
2. The catalog identifies immutable model artifacts and allowed formats.
3. Engine acquisition selects an executable, uv environment, or container image.
4. Requests arrive through the gateway and must stay outside process control.

The first three are operator-controlled supply-chain inputs. Request callers are
untrusted. They may choose only a public model exposed by a configured provider;
they cannot supply an engine, artifact path, device, port, or argv.

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

The process layer receives an executable plus tokenized arguments and an
environment map. It calls the operating-system process API directly. Shell
metacharacters inside one argument remain data because `/bin/sh`, `bash`, and
PowerShell are not involved.

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

Exact removal acquires the cache mutation lock and artifact digest lock, then
rechecks protection. Configured, resident, pinned, locked, downloading,
verifying, and deleting artifacts fail closed. A queued pull also blocks removal
before a ready snapshot exists. Shared blobs are reclaimed only after the last
snapshot reference disappears.

The CLI can query the authenticated admin status before deletion, but the
configuration file is the durable protection source. Supply `-f sb.yml` when
removing from the cache used by a running file-managed gateway.

## Engine supply chain

### llama.cpp binary and source build

The driver can use a trusted explicit path, a compatible `PATH` executable, or a
pinned release. A custom release may carry an expected SHA-256. Linux CUDA
source builds use an official tag archive URL and mandatory source digest; the
built-in tag has a checked-in archive digest. Builders share a lock, stage away
from the ready path, and publish only an executable final file.

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

The process runner keeps a bounded stderr tail for diagnosis. Readiness races
the child exit, so a broken engine fails early instead of waiting through the
full health timeout. Shutdown first asks the child process group to exit, then
uses a bounded force-kill backstop. The group guard prevents the runtime from
targeting the gateway's own process group.

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
runtime swaps. A failure tears down staged work and preserves the last good
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
config with owner-only permissions on Unix, and binds admin to loopback. The
password appears in the terminal because the operator needs it for lifecycle
commands. Do not redirect that banner into a world-readable log.

For a persistent config, use an environment or secret-backend reference and keep
the admin listener on `127.0.0.1`. Remote admin needs TLS, an IP allowlist, and
separate named operators. Model lifecycle routes use the same authentication
and audit boundary as the rest of `/admin/*`.

## Remaining hardening

These controls are not part of the current stable single-node contract:

- Linux cgroup CPU and memory limits per engine process;
- dropping ambient capabilities and switching to a dedicated Unix user;
- seccomp or another syscall sandbox for native engines;
- signature verification for every engine release and package index;
- a rootless container requirement;
- persistent desired-state mutation with review and approval in the admin UI;
- peer identity, transport encryption, and authorization for multi-node model
  dispatch.

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
