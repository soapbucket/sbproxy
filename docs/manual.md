# SBproxy Runtime Manual

*Last modified: 2026-08-29*

Vendor: Soap Bucket LLC - [www.soapbucket.com](https://www.soapbucket.com)

This manual is the operational reference for running SBproxy in production. It covers installation, CLI usage, runtime behavior, observability, TLS, connection tuning, and deployment patterns. The proxy is built on Cloudflare's Pingora framework.

For configuration, see [configuration.md](configuration.md). For features, see [features.md](features.md). For architecture, see [architecture.md](architecture.md). For upgrade notes, see [upgrade.md](upgrade.md).

---

## Table of contents

1. [Installation](#1-installation)
2. [CLI reference](#2-cli-reference)
3. [Runtime behavior](#3-runtime-behavior)
4. [Logging](#4-logging)
5. [Metrics and observability](#5-metrics-and-observability)
6. [Health checks](#6-health-checks)
7. [TLS and certificates](#7-tls-and-certificates)
8. [Connection tuning](#8-connection-tuning)
9. [Hot reload](#9-hot-reload)
10. [Feature flags](#10-feature-flags)
11. [Docker deployment](#11-docker-deployment)
12. [Kubernetes deployment](#12-kubernetes-deployment)
13. [Environment variables reference](#13-environment-variables-reference)

---

## 1. Installation

This section is the canonical install reference; other docs link here rather than repeating it.

### Install script

The quickest path for Linux on amd64 or arm64, and macOS on Apple Silicon. The
script detects the platform, fetches the matching release binary, and drops it
in `~/.local/bin`:

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

On a Linux host with an NVIDIA GPU, the installer makes a best-effort attempt
to prepare the optional container runtime used for managed model serving. Set
`SBPROXY_SKIP_GPU_SETUP=1` to skip that step. It does not affect the gateway
binary installation.

Intel macOS binaries are not published. Use the Linux amd64 container or build
from source on an Intel Mac.

### Homebrew

```bash
brew install soapbucket/tap/sbproxy
```

### Binary download

The releases page publishes three archives: Linux amd64, Linux arm64, and
macOS arm64. The Linux artifacts target the GNU ABI and require glibc 2.36 or
newer. Download the archive for your platform, extract it, and put `sbproxy`
somewhere in your `PATH`.

```bash
# Linux (amd64)
curl -L https://github.com/soapbucket/sbproxy/releases/latest/download/sbproxy_linux_amd64.tar.gz | tar -xz
sudo mv sbproxy /usr/local/bin/sbproxy

# macOS (arm64)
curl -L https://github.com/soapbucket/sbproxy/releases/latest/download/sbproxy_darwin_arm64.tar.gz | tar -xz
sudo mv sbproxy /usr/local/bin/sbproxy
```

Verify the installation:

```bash
sbproxy --version
```

### Docker

The official image runs the matching Linux release binary on a distroless
Debian 12 base; there is no shell or package manager in the runtime layer.

The image has no default config path, so every `docker run` must name the config explicitly, either as `serve -f <path>` or as a positional argument. Mount your config at `/etc/sbproxy` and point the command at it:

```bash
# Pull the image
docker pull soapbucket/sbproxy:latest

# Run with a specific config file
docker run --rm \
  -p 8080:8080 \
  -v /path/to/sb.yml:/etc/sbproxy/sb.yml:ro \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml

# Run with a local config directory (certs, includes) mounted alongside
docker run --rm \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /path/to/config:/etc/sbproxy:ro \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

Features that persist state on disk (the [dynamic key management](key-management.md) keystore, usage rollups) default their paths to `/var/lib/sbproxy`. Mount a volume there so that state survives container replacement:

```bash
docker run --rm \
  -p 8080:8080 \
  -v /path/to/config:/etc/sbproxy:ro \
  -v sbproxy-state:/var/lib/sbproxy \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

Images up to v1.9.0 ship without the `/var/lib/sbproxy` directory, and the container runs as a nonroot user that cannot create it, so on those versions the mount is required for these features to start at all.

Three PowerShell notes for Windows:

- Quote the host path in the volume flag (`-v C:\Users\you\proxy:/etc/sbproxy:ro`).
- `curl` is an alias for `Invoke-WebRequest` and rejects flags like `-H`; call `curl.exe` explicitly when testing the proxy (real curl ships with Windows 10 and later).
- `export` does not exist in PowerShell. Set variables with `$env:NAME = "value"`, or pass them into the container with `-e NAME` or `--env-file`. Save any env file as UTF-8 without a byte order mark: Docker silently ignores every line of the UTF-16 files Windows PowerShell 5 produces by default with `>` redirection.

### From source

Building from source requires a recent stable Rust toolchain (`rustup` install).

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
# Binary at target/release/sbproxy

# Install to a system path
install -m 0755 target/release/sbproxy /usr/local/bin/sbproxy
```

`make run CONFIG=<path>` is a convenience wrapper that builds and starts the proxy with a chosen config file.

---

## 2. CLI reference

The binary exposes a small surface. Runtime policy lives in `sb.yml`;
operator commands also inspect and explicitly pull managed artifacts.

```
sbproxy --config <path>
sbproxy serve -f <path> [--log-level <level>] [--request-log-level <level>]
                        [--log-format compact|pretty|json]
                        [--shutdown-grace-ms <ms>] [--grace-time <secs>]
                        [--disable-sb-flags]
sbproxy validate <path> [--format text|json] [--no-fetch]
sbproxy --config <path> --check
sbproxy --config <path> --locked
sbproxy plan -f <yaml> [--against <yaml>] [--format json|text] [--out <plan-file>] [--no-fetch]
sbproxy plan -f <yaml> --explain-origin <host> [--format json|text]
sbproxy aggregate [<path>] [--out <file>] [--dry-run] [--explain <host>]
                        [--watch] [--polls <n>] [--mode overlay|replace]
                        [--admin-url <url>] [--username <u>] [--password <p>]
                        [--format text|json]
sbproxy apply -f <yaml> [--admin-url <url>] [--username <u>] [--password <p>]
                        [--validate-only]
sbproxy apply -p <plan-file> [--admin-url <url>] [--validate-only]
sbproxy config {migrate|import-litellm|print}
sbproxy config history [--admin-url <url>] [--format text|json]
sbproxy config show <revision> [--admin-url <url>] [--format text|json]
sbproxy config rollback [--to <rev|digest|last-known-good>] [--expected-current <rev>]
                        [--confirm <rev>] [--lineage <uuid>] [--force]
                        [--admin-url <url>] [--format text|json]
sbproxy config diff [<rev>] [--from <rev>] [--to <rev>] [--admin-url <url>]
                        [--format text|json]
sbproxy config authority init --dir <path> [--key-id <id>] [--authority-id <id>]
                              [--force] [--format text|json]
sbproxy config authority publish -f <payload.yml> [--mode overlay|replace]
                              [--validate-only] [--admin-url <url>]
                              [--username <u>] [--password <p>] [--format text|json]
sbproxy config authority status [--admin-url <url>] [--format text|json]
sbproxy config authority rollback [--admin-url <url>] [--format text|json]
sbproxy config authority subscriber add <subscriber-id> [--admin-url <url>]
                              [--format text|json]
sbproxy config authority subscriber list [--admin-url <url>] [--format text|json]
sbproxy config authority subscriber revoke {--credential-id <id> | --subscriber-id <id>}
                              [--admin-url <url>] [--format text|json]
sbproxy config pull <path> --dry-run [--format text|json]
sbproxy projections render --kind <kind> --config <path> [--hostname <h>]
sbproxy run <catalog-id> [--name <alias>] [--variant <id>]
                           [--engine auto|vllm|sglang|llama_cpp|mistralrs]
                           [--accel auto|cuda|metal|cpu]
                           [--port <port>] [--admin-port <port>]
                           [--cache-dir <path>] [--dry-run]
sbproxy models [list|show <id>|pull [<id>...]|remove <id>|ps|stop <deployment>|
                lock|verify-lock|prune]
sbproxy mcp {lock|verify-lock} [--out <path> | --lockfile <path>] [--format text|json]
sbproxy cedar replay -f <yaml> --against <traffic.jsonl> [--baseline <yaml>]
                        [--origin <host>] [--format text|json]
sbproxy rego test <path> [--min-coverage <pct>] [--format text|json]
sbproxy cluster {init|token create|enroll|status}
sbproxy update [--self] [--engines] [--models] [--check] [--yes]
                        [--cache-dir <path>] [--format text|json]
sbproxy ai ledger <subcommand>
sbproxy ai prompt optimize --prompt <path> --eval-set <path> --endpoint <url>
                        --task-model <model> --name <name> --prompt-version <v>
                        --output <path> [--metric exact-match|contains|json-exact]
sbproxy audit verify <path> [--channel security|config|key|admin]
                        [--signing-seed-hex <hex>] [--format text|json]
sbproxy admin hash-password [--password <value> | --password-stdin]
sbproxy doctor [<config>] [--format text|json] [--strict]
sbproxy connect [<client>...] [--base-url <url>] [--model <id>] [--dry-run]
                        [--format text|json]
sbproxy disconnect [<client>...] [--dry-run] [--format text|json]
sbproxy service install <catalog-id> [--name <alias>] [--variant <id>]
                              [--engine auto|vllm|sglang|llama_cpp|mistralrs]
                              [--accel auto|cuda|metal|cpu]
                              [--port <port>] [--admin-port <port>]
                              [--cache-dir <path>] [--dry-run] [--format text|json]
sbproxy service uninstall [--format text|json]
sbproxy service status [--format text|json]
sbproxy completions {bash|zsh|fish|powershell|elvish}
sbproxy version
sbproxy --version
sbproxy --help
```

The full subcommand set, one line each:

| Subcommand | What it does |
|------------|--------------|
| `serve` | Run the proxy. Synonym for the no-subcommand run form. |
| `validate` | Validate an `sb.yml` without starting the proxy. |
| `plan` | Diff a proposed config against a baseline. |
| `apply` | Validate and reload a config in place; the same primitive the SIGHUP handler and file watcher use. |
| `config` | Config maintenance: `migrate` rewrites deprecated syntax to the current form, `import-litellm` converts a LiteLLM `config.yaml` into an sbproxy `sb.yml`, `print` shows the effective config with secret values masked, `authority` operates a config authority (generate its key, publish, watch the rollout, roll back, manage subscriber credentials), `pull --dry-run` previews the bundle a subscriber would apply next, `history` lists the revisions recorded in a running proxy's `proxy.config_history` ring, `show <revision>` prints one of those revisions' stored document. |
| `projections` | Render projection documents (robots.txt, llms.txt, ...) for an origin without starting the proxy. |
| `run` | Resolve a certified artifact, generate local admin auth, warm a canonical managed deployment, then print an OpenAI-compatible endpoint. |
| `models` | List and show catalog entries, pull or remove exact artifacts, inspect running deployments, drain and stop one, write or check a lockfile (`lock`, `verify-lock`), or reclaim unreferenced cache blobs (`prune`). |
| `mcp` | Federated MCP tool-catalog lockfile: `lock` discovers the configured servers and pins every advertised tool at its current contract digest; `verify-lock` re-discovers and diffs against the committed baseline without starting a listener, exiting 2 on drift, for CI. |
| `cedar` | Cedar policy tools: `cedar replay -f <yaml> --against <traffic.jsonl>` evaluates recorded MCP tool-call samples against `cedar_policies` in the YAML. Optional `--baseline` diffs each verdict. Exit 0 when every `expected` label holds and no baseline verdict moved; 1 when a sample missed or a verdict changed; 2 when the sample, the YAML, or the Cedar source could not be compiled. See [cedar-policy.md](cedar-policy.md). |
| `rego` | `rego test <path>` is the offline `opa test` analogue: runs one or more YAML fixture files against the Rego module(s) they name and prints a per-module line-coverage summary, without touching `sb.yml` or a running proxy. See [scripting.md §3a](scripting.md#3a-rego-policies). |
| `cluster` | Initialize cluster identity, create one-time enrollment tokens, enroll nodes, or inspect the complete roster, placement, and unhealthy-node alerts. |
| `update` | Update the engines and cached models (add `--self` for the binary): check the engine release feed and cached models, then fetch, verify, and swap what is out of date, with confirmation. `--check` reports only. Pinned or `path`/`brew`/`apt`-managed artifacts are reported, never replaced, unless the run targets them. |
| `ai` | AI gateway tools: `ai ledger` verifies the usage ledger's hash chain, aggregates the value ledger into a savings report, or reconciles usage against a provider export; `ai prompt optimize` compiles a shorter static system prompt against a customer-owned evaluation set. |
| `audit` | Audit-trail tools: `audit verify` re-derives a tamper-evident audit chain from genesis and reports the first record that does not check out; `--channel` picks the trail (`security` by default, or `config`, `key`, `admin`). |
| `admin` | Admin-account maintenance: `hash-password` prints the `password_hash` value for `proxy.admin.operators[].password_hash`. |
| `doctor` | Diagnose what this binary can do on the current host. |
| `connect` | Point the coding agents installed on this machine at this gateway. Detects Codex, Claude Code, Cursor, Cline, and Copilot; writes `$CODEX_HOME/sbproxy.config.toml` (a Codex profile of its own, never your `config.toml`) through a temp file and a rename, taking a one-time `.sbproxy.bak` copy first; prints the exports or the settings-screen fields for the rest. `--dry-run` shows the unified diff and writes nothing. No credential is read or written: the config names the environment variable each client reads its key from. See [use-case-connect-coding-agents.md](use-case-connect-coding-agents.md). |
| `disconnect` | Remove what `connect` wrote and name what to clear by hand. The profile is copied to `<path>.sbproxy.removed` before it goes, so a hand edit made after connecting survives the removal; the one-time `.sbproxy.bak`, which holds the file as it was before the first `connect`, is left in place. |
| `service` | Install, remove, or check a per-user `launchd` agent (macOS only) that runs a certified catalog model in the background; reuses the same secure config generation as `run`. |
| `completions` | Print a shell-completion script for the requested shell. |
| `version` | Print the version line. Synonym for `--version`. |

Argv parsing is `clap` derive, so every subcommand also accepts
`--help` for a focused usage block (`sbproxy plan --help`,
`sbproxy projections render --help`, etc.).

For managed models, `sbproxy models pull -f sb.yml` selects canonical
deployments and compatibility `serve:` entries plus the catalog's `on_boot`
set. It inherits exact variant and engine pins, cache location, budget, and
protection, verifies artifacts, and starts no engine. See
[model-host.md](model-host.md).

For a cluster authority and worker:

```bash
sbproxy cluster init --dir /var/lib/sbproxy/cluster \
  --cluster-id production-models --node-id authority-a
export SBPROXY_CLUSTER_TOKEN="$(sbproxy cluster token create \
  --dir /var/lib/sbproxy/cluster \
  --role worker --label zone=us-central1-b)"
sbproxy cluster enroll --url https://authority.internal:9090 \
  --node-id worker-b --role worker --label zone=us-central1-b \
  --out /var/lib/sbproxy/cluster
sbproxy cluster status --format json
```

Enrollment tokens are one-time and secret. Prefer
`SBPROXY_CLUSTER_TOKEN` to a command-line value. `cluster status` uses
`SB_ADMIN_URL`, `SB_ADMIN_USERNAME`, and `SB_ADMIN_PASSWORD` by default and
preserves every unhealthy member in the node list while also returning a
dedicated alert collection. See [model-host.md](model-host.md#cluster-configuration).

### `serve` - start the proxy

The default mode. Reads the config file, compiles the pipeline, and
starts the configured listeners. Either `--config <path>` (canonical)
or `-f <path>` (alias) works; a positional path is also accepted. When
no path is given on the command line, the binary falls back to
`SB_CONFIG_FILE`.

```bash
sbproxy --config /etc/sbproxy/sb.yml
sbproxy serve -f /etc/sbproxy/sb.yml
sbproxy serve -f /etc/sbproxy/sb.yml --log-level debug --request-log-level info --grace-time 30
SB_CONFIG_FILE=/etc/sbproxy/sb.yml sbproxy
```

### `validate` - check configuration without starting

Loads and compiles the config without binding any listener. Exits 0 if
the file compiles, 2 otherwise. Suitable for CI gates before a
rolling deployment. Managed-model configuration also runs through the same
desired-state semantic validation used at boot.

```bash
sbproxy validate /etc/sbproxy/sb.yml
sbproxy --config /etc/sbproxy/sb.yml --check
```

Add `--format json` to emit a single JSON object instead of the human
line, so CI can parse the result. A valid config prints
`{"path":"...","valid":true}`; an invalid one prints
`{"error":"...","path":"...","valid":false}` and still exits 2. The
default is `--format text`.

```bash
sbproxy validate /etc/sbproxy/sb.yml --format json
```

Add `--no-fetch` to validate the pointer file alone, without resolving a
`source:` block. Use this on a machine with no network access or no
credential for the source repository, rather than let a git-sourced
config validate a document it never actually fetched.

```bash
sbproxy validate /etc/sbproxy/sb.yml --no-fetch
```

### `plan` - diff a proposed config against a baseline

Compiles the proposed YAML, parses both baseline and proposed into
`ConfigFile`, runs plan-time semantic validation (orphan refs, missing
secrets, unknown module types), and emits a structured diff. Output is
a terraform-style text diff by default; `--format json` emits the
stable plan envelope for tooling. `--out <file>` writes the JSON
plan-file envelope (which records the baseline revision) so a later
`sbproxy apply -p <file>` can replay against the same baseline and
refuse on drift.

```bash
sbproxy plan -f proposed.yml
sbproxy plan -f proposed.yml --against live.yml --format json
sbproxy plan -f proposed.yml --out /tmp/sb.plan
sbproxy plan -f proposed.yml --no-fetch
```

`--no-fetch` skips resolving a `source:` block on either side of the
diff. Without it, a git-sourced config is planned against the document
the repository actually serves, not the pointer file on disk.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No changes between baseline and proposed. |
| 1 | CLI / IO error. |
| 2 | Changes present (informational, not an error). |
| 3 | Semantic-validation errors. The findings section spells out which rules fired. |

When `--against` is omitted, the baseline is empty, so every origin in
the proposed config surfaces as `added`. The `--running` baseline
(pulled from a live admin socket) is deferred.

A Cedar-only edit on `origins.*.action.cedar_policies` is classified
**Reload** (`Cedar MCP policies recompile on reload`) and named as
Cedar, not an opaque action-body tweak. Preview the same source
against recorded tool calls with `sbproxy cedar replay` (see below).

### `cedar replay` - evaluate recorded MCP tool calls against Cedar

Reads `origins.*.action.cedar_policies.policies` from `-f` / `--config`
and evaluates a JSONL traffic sample. Each line is
`{principal, resource, expected?, action?, id?}`. `principal` and
`resource` are Cedar UIDs (`Agent::"anonymous"`,
`ToolInvocation::"demo/search_repos"`). `action` defaults to
`Action::"MCP::CallTool"`. Samples do not carry arguments: the live
hook evaluates against an empty Cedar context.

```bash
sbproxy cedar replay -f proposed.yml --against traffic.jsonl
sbproxy cedar replay -f proposed.yml --against traffic.jsonl \
  --baseline live.yml --format json
sbproxy cedar replay -f proposed.yml --against traffic.jsonl \
  --origin mcp.example.com
```

`--baseline` diffs each sample's verdict against that file's Cedar
source. A moved verdict is a policy-change preview (exit 1), the
analogue of a traffic replay before `apply`. `--origin` restricts extraction to one hostname when several origins
carry Cedar. When more than one origin has `cedar_policies`,
`--origin` is required: replay compiles one live hook, not a merged
PolicySet of every origin.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Every `expected` label held, and (with `--baseline`) no verdict moved. |
| 1 | A sample missed its `expected` label, or a baseline verdict changed. |
| 2 | The sample, the YAML, or the Cedar source could not be parsed or compiled. |

Runnable: [`examples/cedar-replay/`](../examples/cedar-replay/). Dedicated page: [cedar-policy.md](cedar-policy.md).

### `aggregate` - compose project-owned origin profiles

Fetches every project repository the runtime document's `origin_sources:`
block names, composes the `origins:` map from the platform floor and the
project profiles, and either publishes the result through the config
authority or writes it to a file. See
[configuration.md](configuration.md#project-owned-origin-profiles).

```bash
sbproxy aggregate -f /etc/sbproxy/sb.yml                       # publish
sbproxy aggregate -f /etc/sbproxy/sb.yml --out composed.yml    # write a file
sbproxy aggregate -f /etc/sbproxy/sb.yml --out composed.yml --dry-run
sbproxy aggregate -f /etc/sbproxy/sb.yml --explain checkout.example.com
sbproxy aggregate -f /etc/sbproxy/sb.yml --watch
```

`--out` is the offline path: the written document is ordinary config
that boots and reloads normally, and it carries neither composition
block, because a composed output is not a source of further composition.
What gets **published** is narrower than what `--out` writes: the
`origins:` map plus `origin_defaults`, built up rather than cut down, so
a node's own `proxy:` block never travels to the fleet.
The same inputs at the same revisions produce a byte-identical file, so
a CI diff means something. `--dry-run` prints what would change against
a file already there and writes nothing.

`--explain <host>` prints which composition layer set each leaf of one
composed origin, and for the two layers a project authored, the
repository and the resolved commit. `sbproxy plan --explain-origin
<host>` prints the same thing from the verb an operator already reaches
for; it fetches, so it is refused under `--no-fetch`.

`--watch` polls each entry on the configured interval, coalesces a burst
of movement into one composition, and publishes only when the composed
document changed. It re-reads the runtime document every cycle, so an
edit plus a reload reaches the aggregator without a restart. `--polls
<n>` stops after that many poll cycles, for a cron-shaped invocation.
`--watch` refuses to combine with `--out`, `--dry-run` or `--explain`
rather than ignoring them. A proxy that both declares `origin_sources`
entries and publishes a config authority runs the same loop in process at
boot, so `--watch` is for a deployment that runs the aggregator
separately.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Published, written, or the composition was unchanged and nothing needed publishing. |
| 1 | CLI / IO error, or a credential that would not resolve. |
| 2 | `--dry-run` found changes (informational, not an error). |
| 3 | The composition was refused, or the authority refused the composed document. Nothing was published and nothing was written. |

### `apply` - validate, then apply to a running proxy

Two flows:

```bash
sbproxy apply -f proposed.yml          # validate + reload from YAML
sbproxy apply -p /tmp/sb.plan          # replay a plan file
```

`apply -f` validates the proposed YAML, runs plan-time semantic
checks, then pushes the config to a running proxy over the admin API
(`PUT /admin/config`) and reports what the server did with it.
`apply -p` reads a plan file from a prior `plan --out`, recomputes the
plan against the current baseline, and refuses (exit 5) if the recorded
`baseline_revision` no longer matches the live one. Both flows take an
exclusive `flock(2)` on `<yaml_path>.applylock` so two operators cannot
race the same apply.

The admin endpoint defaults to `http://127.0.0.1:9090`; override it with
`--admin-url` or `SB_ADMIN_URL`, and supply credentials with
`--username` / `--password` or `SB_ADMIN_USERNAME` / `SB_ADMIN_PASSWORD`.
If no proxy answers, apply exits 7 and applies nothing rather than
reporting a success it did not achieve.

Use `--validate-only` where there is no proxy to apply to, which is the
normal case in CI. It runs every check and stops, contacting nothing.

Earlier versions did not contact the proxy at all: apply compiled the
config into its own short-lived process, swapped that process's pipeline,
printed success, and exited. A running server noticed only if its file
watcher happened to see the file, so exit 0 was not evidence the config
had been accepted or even seen. If you have a CI step calling `apply` as
a validation gate, switch it to `--validate-only`.

The `-p` form is intentionally env-var driven for the YAML path and
baseline: the plan file does not embed an on-disk path, so the
operator points apply at the YAML through `SB_APPLY_CONFIG` and
optionally overrides the baseline with `SB_APPLY_BASELINE`.

```bash
SB_APPLY_CONFIG=/etc/sbproxy/sb.yml sbproxy apply -p /tmp/sb.plan
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Applied cleanly, or validated cleanly under `--validate-only`. |
| 1 | CLI / IO error. |
| 3 | Semantic-validation errors. Apply refused, nothing sent. |
| 4 | The proxy refused the config. Nothing was applied. |
| 5 | Plan file is stale. Rerun `plan` and re-apply. |
| 6 | Another `apply` already holds the applylock. |
| 7 | No proxy answered at the admin URL. Nothing was applied. |
| 8 | Applied, but a subsystem kept stale state. See the warning on stderr. |

### `config authority` - operate a config authority

A config authority signs one configuration and the fleet verifies and
applies it. The schema, the wire contract, the deny list, and the
subscriber side are documented in
[configuration.md](configuration.md#config-authority-fleet-configuration-distribution);
this section is the operator surface over it.

```bash
# Once, on the node that will publish.
sbproxy config authority init --dir /etc/sbproxy/authority \
  --authority-id control-plane-eu

# Once per subscriber. Prints the credential exactly once.
export SB_CONFIG_AUTHORITY_TOKEN="$(sbproxy config authority subscriber add edge-01)"

# Every change.
sbproxy config authority publish -f fleet.yml --mode overlay
sbproxy config authority status
sbproxy config authority rollback
```

Every command except `init` talks to the authority's admin API and
reports what the server returned. None of them changes process-local
state and calls that success: if the admin API cannot be reached, the
command exits 7 and says nothing was changed. The endpoint defaults to
`http://127.0.0.1:9090`; override it with `--admin-url` or `SB_ADMIN_URL`,
and supply credentials with `--username` / `--password` or
`SB_ADMIN_USERNAME` / `SB_ADMIN_PASSWORD`. A publishing node refuses the
shipped default admin password, so an authority always has a real one.

`--format json` is available on every one of these commands and emits a
single object on stdout.

#### `config authority init`

Generates an Ed25519 key pair, writes `authority-signing.key` owner-only
(0600) and `authority-keys.json` for distribution, and prints what to
copy where. Local: it writes two files and contacts nothing, because a
signing key that traveled over a network to reach its own authority has
been somewhere else.

The default `--key-id` is derived from the new public key
(`authority-<12 chars>`), so a rotation never collides with the key it
replaces. Pass `--key-id` to choose your own. `--authority-id` only
affects the printed config snippet.

It refuses to overwrite an existing signing key. `--force` rotates: the
new signing key replaces the old one and the new verifying key is *added*
to `authority-keys.json` alongside the old entry, so subscribers that
still trust the old key keep verifying while they are updated. Drop the
old entry a window later. The signing seed is printed by neither format.

If the directory is reachable by other accounts on the host, `init` says
so. It is a warning rather than a refusal: the key file itself is
owner-only, and the loader refuses one that is not.

#### `config authority publish`

`-f <payload.yml>` is the payload subscribers apply, not this node's own
config file. Before anything is sent, publish runs the same three checks
the authority runs (`compile_config`, then the per-origin module
constructors, then the model-host desired-state checks), through the same
function the server route calls. A payload that would be refused is
therefore refused here, and no revision number is spent on it. An
unresolved `${VAR}` is a warning, not a refusal, because it may well
resolve on the subscriber.

`--mode` must match the `mode` each subscriber is configured for, or they
refuse the bundle rather than guess. `--validate-only` runs every check
and stops, contacting nothing, which is the CI form.

#### `config authority status`

Current revision and digest, the signing key id, the previous revision,
the highest revision ever reserved, and every subscriber's last-seen
revision with a `current` / `behind` / `never fetched` verdict. That last
column is fleet drift, visible from a terminal.

No secret appears in the output. Subscriber records carry a credential
*id*, never the credential, and the authority stores only a SHA-256
fingerprint of it in the first place. The verifying material is the
public half of the signing key.

#### `config authority rollback`

Republishes the previous stored revision's payload. The store keeps the
current bundle and the one before it for exactly this.

The new revision number is *above* the one it replaces. A subscriber's
anti-replay cursor refuses any revision that is not greater than the one
it applied, so re-serving the old number would reach only the nodes that
had not yet taken the revision being undone, which is the opposite of
what you want at that moment. The output names all three numbers: what
was restored, what it replaced, and what it was published as.

The payload is revalidated on the way through, because a payload that
published cleanly before a binary upgrade need not still construct after
one.

#### `config authority subscriber`

`add <subscriber-id>` registers a node and mints its credential. The
credential is printed **once**, here, and is not recoverable: the
authority keeps only a fingerprint. In `--format text` it goes alone to
stdout (so `export TOKEN="$(...)"` works) and the note saying so goes to
stderr. Give it to the node as
`proxy.config_authority.upstream.credential` by secret reference, not
inline.

`list` is the roster with each node's last-seen revision. `revoke`
takes either `--credential-id` (one credential, which is how a rotation
retires the old one) or `--subscriber-id` (every credential that node
holds). A revoked node keeps serving what it already applied; it stops
receiving updates.

#### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Done, or a no-op. |
| 1 | CLI / IO error, including naming no revoke selector. |
| 3 | Refused locally, nothing sent: a payload that would not publish, or an `init` that would clobber a signing key. |
| 4 | The authority answered and refused. Nothing changed on it. |
| 7 | Nothing answered at the admin URL. Nothing was changed. |

### `config pull` - preview the next bundle without applying it

```bash
sbproxy config pull /etc/sbproxy/sb.yml --dry-run
```

Runs a real subscriber cycle up to the point of applying: a conditional
`GET` against the authority named in `proxy.config_authority.upstream`,
signature and schema and digest and replay verification, the merge over
this node's local document, and the unresolved-`${VAR}` screen. Then it
prints the resulting plan diff, in `plan`'s format, and stops.

Nothing is applied. The bundle cache is not written, the replay cursor is
not advanced, and no reload happens. This is the one command in the group
that is local, and it is local because it applies nothing: a short-lived
CLI process cannot swap a running proxy's pipeline, and applying a bundle
is the proxy's own poll loop's job. `--dry-run` is required for that
reason, and the output says plainly that nothing was applied.

The config path comes from the positional argument, then `-f/--config`,
then `SB_CONFIG_FILE`.

Because the fetch is conditional on this node's persisted cursor, a node
that already holds the current revision gets a `304` and the command
reports "no changes" rather than re-printing a diff of what it is already
serving.

| Code | Meaning |
|------|---------|
| 0 | Nothing to apply: the authority is serving the revision this node already holds. |
| 1 | CLI / IO error, including a missing `--dry-run` or no `upstream` block. |
| 2 | Changes present. The diff is on stdout. Nothing was applied. |
| 3 | The bundle or the merged document was refused. The reason names which check fired. |
| 7 | The authority could not be reached. Nothing was applied. |

### `config history` / `config show` - inspect a running proxy's applied revisions

Both talk to the admin API of an already-running proxy, the same way
`apply` and `config authority status` do: `--admin-url` or `SB_ADMIN_URL`,
credentials from `--username`/`--password` or
`SB_ADMIN_USERNAME`/`SB_ADMIN_PASSWORD`. Neither reads a local YAML file.
They require `proxy.config_history.enabled` on the node they talk to; a
node with history disabled has nothing recorded to show.

```bash
sbproxy config history
sbproxy config history --format json

sbproxy config show 42
sbproxy config show 42 --format json
```

`history` lists every revision recorded in `proxy.config_history`'s ring,
newest first: revision number, state, blast radius, provenance, applied-at
timestamp, actor, and digest. `show <revision>` prints one revision's
stored document, selected from the same ring by the revision number
`history` lists; a revision that has aged out under
`proxy.config_history.keep` is no longer available. `--format json` on
`show` prints the admin API's full detail envelope (`entry`, `document`,
`plan_text`) rather than just the document.

### `config rollback` / `config diff` - move a running proxy back to a stored revision

Same admin-API plumbing as `config history`, and the same requirement:
`proxy.config_history.enabled` on the node being talked to.

```bash
# What would change, before anything does. Reads only.
sbproxy config diff 41
sbproxy config diff --from 38 --to 41

# Back to whatever the soak last promoted.
sbproxy config rollback --to last-known-good

# To a named revision, refusing if somebody else moved this node first.
sbproxy config rollback --to 41 --expected-current 43

# A restart-class or breaking rollback needs the revision typed back.
sbproxy config rollback --to 41 --confirm 41
```

`--to` accepts a revision number, a content digest, or the literal
`last-known-good`, which is the default. The restored document is applied
through the ordinary reload transaction and soaks like any other candidate,
history stays append-only (the rollback appends a new entry and marks the
revision it left as `reverted`), and the node's own config **file** is not
rewritten, which the text output says in a warning line. Fix the source of
truth before the next reload trigger re-applies it.

`--expected-current` is optimistic concurrency: the call is refused when
that is not the revision running, so two operators reaching for rollback
during one incident do not silently undo each other. Omitting it proceeds.

`config diff` takes the target as a positional or as `--to`, and defaults
`--from` to what the proxy is running. Two stored revisions need not be
adjacent. It exits `0` when the two documents are identical and `2` when
they differ, following `plan`'s convention, so a script can branch on
whether a rollback is a no-op.

| Exit code | `config rollback` |
|---|---|
| 0 | Applied. |
| 4 | Refused: an unknown revision, a stale `--expected-current`, a lineage break, an unconfirmed restart-class change, or a document that no longer compiles. The refusal body names what is available or both sides of the mismatch. |
| 7 | The admin API could not be reached. Nothing was applied. |

### `projections render` - serve-time documents on demand

Renders the per-origin projection document (robots.txt, llms.txt,
llms-full.txt, licenses, TDMRep) to stdout without binding any
listener. Useful for previewing the surface a crawler will see, or for
piping into a CI fixture comparison.

```bash
sbproxy projections render --kind robots --config sb.yml
sbproxy projections render --kind llms-full --config sb.yml --hostname api.example.com
```

When `--hostname` is omitted, the first origin in the config is
chosen. Accepted `--kind` values: `robots`, `llms`, `llms-full`,
`licenses`, `tdmrep`.

### `run` - one managed model without a config file

`run` accepts a certified catalog v2 ID. It resolves an exact artifact against
the current worker, generates an authenticated loopback admin listener, writes
a private temporary canonical config, and sets the deployment to pull on boot
and warm. The success banner waits for runtime state `ready`.

```bash
sbproxy run qwen2.5-0.5b-instruct --variant q4_k_m
sbproxy run qwen2.5-0.5b-instruct --name coder --port 8081
sbproxy run qwen2.5-0.5b-instruct --dry-run
```

The ready banner includes the endpoint, generated admin URL and credential,
curl request, `OPENAI_BASE_URL`, and `OPENAI_API_KEY`. A raw `hf:` reference is
rejected because it lacks the complete catalog v2 identity. The private
temporary config is removed whenever the command returns, including startup and
readiness failures.

### `service` - run a model as a background launchd agent (macOS)

`service install` takes the same model/engine/accel/port/variant surface as
`run` (flattened onto the same flags) and generates the identical secure
config: loopback bind, admin enabled with a random local password. The
difference is what happens to the result: `run` serves it in the
foreground of the current process; `install` persists the config and
wraps it in a per-user `launchd` agent instead, so it keeps running (and
restarts on failure or reboot) after the terminal closes.

```bash
sbproxy service install qwen2.5-0.5b-instruct --variant q4_k_m
sbproxy service status
sbproxy service uninstall
```

`install` writes four things under `$HOME`:

- The config: `~/Library/Application Support/sbproxy/service/sb.yml`.
  Unlike `run`'s private temporary config, this one is not removed on
  exit; `launchd` rereads it on every future load, so it has to outlive
  the command that wrote it. A prior install's config is replaced
  outright, along with the admin password embedded in it.
- The agent definition: `~/Library/LaunchAgents/dev.sbproxy.agent.plist`,
  labeled `dev.sbproxy.agent`. One agent per host: installing again
  replaces it rather than adding a second one, mirroring how `run` serves
  one model at a time. The plist sets `RunAtLoad` and `KeepAlive`, so
  `launchd` starts it now and relaunches it if the process ever exits.
- Logs: `~/Library/Logs/sbproxy/service.log` (stdout) and
  `service.err.log` (stderr), where `launchd` redirects the child
  process's output.
- The environment file:
  `~/Library/Application Support/sbproxy/service/env`, mode 0600. A
  `launchd` agent inherits almost nothing from the shell that installed
  it, so an `HF_TOKEN` exported in a terminal is invisible to the agent
  and a gated model fails to pull with no obvious cause. Put it here
  instead, one `KEY=value` per line. This is a declarative file, not a shell
  script: values are literal, and `export`, quotes, expansion, commands, and
  inline comments are rejected. Duplicate keys are rejected too, so startup
  and cleanup cannot choose different values. The file is created once with
  a commented template and never rewritten, so a token set here survives
  reinstalling to change the model or the port. If you set
  `SBPROXY_ENGINE_OWNERSHIP_DIR`, use an absolute path. Both the service and
  `service uninstall` read that value from this file.

The agent starts a small built-in bootstrap that parses this file as data,
sets the validated values, and then replaces itself with `sbproxy serve`.
Before that replacement, it takes the private
`~/Library/Application Support/sbproxy/service/lifecycle.lock` and durably
registers its exact process generation in `uninstall-state.json`. The state
keeps bootstrap registrations separate from process generations observed
later by uninstall, so an observation cannot be mistaken for proof that a
gateway cooperates with the lock. Nothing in the environment file is evaluated
by a shell, credentials stay out of the plist, and `launchd` supervises the
proxy at the same pid. The plist also raises `ExitTimeOut` above the proxy's
default shutdown grace, so `launchd` cannot SIGKILL a drain that is still in
progress.

Managed engine ownership is durable across gateway death. Each engine record
contains the owner and engine PID plus their process-start fingerprints;
the record reaches durable storage before the engine can execute.
`service uninstall` takes the same lifecycle lock and captures the exact
process-start identity of the gateway reported by `launchd`. Before it calls
`launchctl unload`, that identity must already be in the bootstrap-registration
set read under the lock; a current-looking plist on disk is not enough. After
the job exits, uninstall reaps only the process groups tied to exact recorded
gateway generations. It reads
`SBPROXY_ENGINE_OWNERSHIP_DIR` from the service environment file, not from the
shell running the uninstall command. The lock stays held while uninstall reads
the registry, verifies the first launchd PID it sees, unloads the job, and
confirms that the job is gone. A `KeepAlive` replacement therefore either
registered before uninstall took the lock, or cannot execute while unload is
in progress. The plist and retry record stay in place until exact-owner cleanup
succeeds.
A loaded job with no PID, an owner-registry overflow, or an unload that makes
no bounded progress fails closed and leaves both retry handles in place. The
stable lock file is deliberately retained after success; unlinking a lock path
could let future processes lock different file objects.

An agent installed by an older release uses a shell command and never ran this
registration bootstrap. A failed or interrupted reinstall can also leave an
older generation running behind a newer plist. In either case, if the exact
loaded generation is missing from the bootstrap-registration set, the current
CLI stops before calling `launchctl` and keeps the plist and lifecycle state.
Reinstall the intended model with the current
`sbproxy service install <model>`, wait for `sbproxy service status` to report
it running, then retry `service uninstall`.

The reaper signals a process group only while the recorded engine PID still has
the recorded start fingerprint. If the PID changed and the group is empty, the
obsolete record can be removed. If the group is still occupied but the exact
leader cannot be proved, cleanup fails closed and keeps the record for an
operator to inspect. It never uses a process-name sweep.

`--dry-run` (inherited from `run`'s flags) prints the plist and the
generated config without installing or loading anything. `service
status` asks `launchctl list` whether the agent is registered and
running, and exits 0 when it is running, 1 otherwise (registered-but-
stopped and never-installed alike), so it composes with
`sbproxy service status || <restart it>` in a script. `service uninstall`
accepts an agent that is already unloaded and resumes an interrupted cleanup
from its retry record. All three subcommands refuse to run on a non-macOS host,
since `launchd` is macOS-only; use `run` or `serve` elsewhere.

### `models` - artifact and runtime lifecycle

All JSON forms use `schema_version: 1` and a command name. Progress from pulls
stays on stderr.

```bash
sbproxy models list --format json
sbproxy models show qwen2.5-0.5b-instruct --format json

sbproxy models pull -f /etc/sbproxy/sb.yml --format json
sbproxy models pull qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --offline \
  --format json

sbproxy models remove qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  -f /etc/sbproxy/sb.yml \
  --format json
```

Removal is exact and idempotent. It refuses configured, resident, pinned,
locked, leased, or active artifacts. A prepared or running engine holds a
cross-process digest lease. Supplying the active config with `-f` gives the
command its durable protection set; `--admin-url` and admin credentials add the
live resident set.

`ps` and `stop` use the authenticated admin API:

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090
export SB_ADMIN_USERNAME=admin
export SB_ADMIN_PASSWORD='replace-me'

sbproxy models ps --format json
sbproxy models stop local-qwen --format json
```

`stop` drains active requests before stopping the engine and leaves verified
weights in cache.

`lock`, `verify-lock`, and `prune` manage a lockfile pinning the exactly
resolved serving stack, independent of the artifact commands above:

```bash
sbproxy models lock -f /etc/sbproxy/sb.yml --out sbproxy-models.lock
sbproxy models verify-lock --lockfile sbproxy-models.lock
sbproxy models prune --dry-run
```

`lock` requires `-f/--config`: it resolves every configured serve/deployment
entry against the catalog and writes each one's exact artifact digest,
variant, and engine to the lockfile (default path
`sbproxy-models.lock` next to the config). `verify-lock` reads a lockfile
(same default path resolution) and diffs it against the verified local
cache, printing `ok` or a `missing` / `digest_mismatch` drift per model;
it exits `0` when every model matches and `2` when any has drifted.
`prune` reclaims content-addressed weight blobs that no cached artifact
references; `--dry-run` reports what would be reclaimed without deleting
anything.

The lockfile is what the global `--locked` flag enforces at boot: passed to
`serve` (or the no-subcommand run form), it refuses to start unless every
configured serve entry resolves to the artifact digest recorded in
`sbproxy-models.lock`, exiting `2` on drift or on a missing lockfile. Other
subcommands ignore `--locked`.

```bash
sbproxy --config sb.yml --locked
```

### `doctor` - what can this binary do on this host

Prints a host-capability report: the capability features the binary
was compiled with, the devices the managed runtime would see, which
inference engine binaries (`vllm`, `llama-server`) resolve on `PATH`,
the default model-weight cache directory, and a final verdict on
whether a local deployment could admit a model on this host, with
every blocker listed when it could not.

```bash
sbproxy doctor
sbproxy doctor --format json
sbproxy doctor --strict /etc/sbproxy/sb.yml
```

Collection is read-only: no engine starts, nothing is written. The
released binary ships with GPU discovery compiled in and loads the
NVIDIA driver library at runtime (falling back to `nvidia-smi`), so
the same artifact reports "ready" on a GPU host and lists what is
missing everywhere else. Without `--strict` it always exits 0 once the
report is produced; "this host cannot serve local models" is a finding,
not an error. See [model-host.md](model-host.md) for canonical managed
configuration.

#### `--strict`: the managed-worker startup gate

`--strict` adds a `startup gate` block and exits 3 if any check blocks.
It is meant for a VM bootstrap or a container entrypoint that should
refuse to come up rather than fail at the first customer request. A
worker that boots into a broken GPU configuration joins the cluster,
advertises itself as eligible, and then fails every dispatch, which
reads as a routing bug from the gateway side.

Six checks, each named so a script can grep for one:

| Check | Blocks when |
|---|---|
| `driver` | the config asks for CUDA and no NVIDIA driver is installed |
| `visible_devices` | CUDA is asked for and the probe sees no accelerator, the usual sign a container was not given the devices |
| `cuda_compatibility` | a configured model has no viable engine on this host |
| `shared_memory` | `/dev/shm` is smaller than the largest `engines.*.shm_size_gib` the config asks for |
| `cache_mount` | the weight-cache mount cannot hold `cache_budget_gib` |
| `model_plane_identity` | `proxy.cluster` names mTLS or shared-key material that is not readable |
| `unpinned_weights` | a node holding the `worker` role serves an unpinned raw `hf:` or `file:` reference without `serve.allow_unpinned_refs` |

Each check compares the config's own demands against the host, so a
config that asks for nothing local is not penalized: a check that does
not apply reports `skip`, never a hollow `pass`. Both config forms are
read, the inline provider-level `serve:` block and the canonical
`proxy.model_host` block.

Exit codes are distinct so a bootstrap can tell a hardware refusal from
a config mistake without parsing output: `3` for a startup blocker, `1`
when a configured model has no viable engine, `2` when the config could
not be read.

A missing engine *binary* is deliberately not a blocker. Acquisition
fetches it at the first request, so failing the boot over it would be
wrong.

`unpinned_weights` is scoped to the `worker` role on purpose. A raw
reference runs the engine in repo mode, where the container gets DNS and
external egress instead of an isolated network, the weight cache is
mounted writable instead of read-only, and no digest is verified because
sbproxy never sees the download. That is the right trade for
`sbproxy run <model>` on a workstation and for evaluating a model with no
catalog entry, so neither is affected. It is the wrong trade for a
long-lived fleet worker, which now has to say `serve.allow_unpinned_refs:
true` to accept it. See [security-model-host.md](security-model-host.md).

The same host state is checked at startup and on every hot reload. When a
managed deployment is missing a prerequisite, candidate preparation reports
the model, engine, availability state, and blocker. A failed reload preserves
the last good runtime.

#### Engine acquisition

The managed runtime resolves an engine in this order:

- An explicit trusted binary path wins: set `engines.<kind>.acquire.path` with
  `engines.<kind>.acquire.source: path`.
- A compatible binary on `PATH` is next for ordinary binary launch.
- llama.cpp can fetch a pinned CPU or Metal release. Built-in prebuilt assets
  have checked-in digests and identity-scoped caches. On a compatible NVIDIA
  Linux host, it can instead build digest-pinned source with CUDA.
- vLLM can use a version-pinned managed uv environment or a digest-pinned
  private container.

GPU drivers are never installed by sbproxy; a missing driver is reported with
guidance only. The NVIDIA certification procedure targets vLLM or SGLang, not
the llama.cpp CUDA path. See [model-host.md](model-host.md) for canonical
fields, per-engine details, and host prerequisites.

Live single-GPU NVIDIA serving is recorded on an L4 as of 2026-07-30. Multi-GPU
is not, so `platform.nvidia_cuda` stays at `preview` in the capability matrix.
[model-host-certification.md](model-host-certification.md) has the evidence and
what is still missing.

### `update` - keep the binary, engines, and models current

`sbproxy update` checks the engine release feed and the cached models,
then fetches, verifies, and swaps what is out of date. With no target
flag it covers the engines and the cached models; `--self` adds the
sbproxy binary. `--engines` or `--models` narrow the run to that target.

```bash
# Report only, mutate nothing (the dry-run freshness report).
sbproxy update --check

# Update engines and models, confirming each swap.
sbproxy update

# Update the binary too, without prompts.
sbproxy update --self --yes
```

Every swap is verified before it lands. An engine prebuilt and the
sbproxy release archive are checked against their published SHA-256
before the atomic replace, and a model re-pull runs through the same
weight manager (and per-file digest verification) as `models pull`. The
binary is replaced by writing the new file next to the running one and
renaming it into place, so the swap is atomic on a POSIX host.

Pinning always wins. An artifact that another tool owns, a binary already
on `PATH`, or one installed by `brew` or `apt`, is reported as managed
elsewhere and is never overwritten. An artifact pinned to an explicit
version or digest is held on a blanket `sbproxy update` and moves only
when the run names it (for example `sbproxy update --engines`). A newer
llama.cpp tag has no vendored digest, so pin `engines.llama_cpp.acquire.sha256`
to verify a moved engine, or leave the engine on its digest-pinned
default.

Behavior is tuned by the optional `update:` config block:

```yaml
update:
  # stable (default) | latest | pinned. `pinned` freezes every artifact;
  # only a run that explicitly targets one may move it.
  channel: stable
  # When true, a background freshness check runs on the interval below and
  # reports to the logs and `sbproxy doctor`. A background check never
  # swaps anything; applying an update is always an explicit run.
  auto: false
  # How often the background check runs. Humanized (6h, 1d) or bare
  # seconds. Only consulted when auto is true. Defaults to once a day.
  check_interval_secs: 1d
```

With `auto: true`, an `sbproxy update` run reports only and swaps nothing,
so an unattended host never mutates a binary out from under itself.
`--format json` always emits the machine-readable freshness report and
takes no action; the acting path prints its progress on the text path.

### `admin hash-password` - hash an operator password

Prints the `password_hash` value to paste into
`proxy.admin.operators[].password_hash`. Takes exactly one input source:

```bash
sbproxy admin hash-password --password 'correct horse battery staple'

# Prefer stdin over --password: a literal value on the command line
# stays in the shell history.
printf '%s' 'correct horse battery staple' | sbproxy admin hash-password --password-stdin
```

The hash is HMAC-SHA256 of the password, keyed with the pepper, then
hex-encoded. The pepper is resolved the same way the running server
resolves it, so a hash printed here verifies against a server booted
from the same config: pass `-f/--config` and, when that file sets
`key_management.crypto.pepper`, the command reads it from there; without
`-f`, or when the config has no `key_management` block, it falls back to
a fixed default pepper built into the binary. That default is the same
in every install, so a `password_hash` hashed against it is
offline-crackable by anyone with the source; pin
`key_management.crypto.pepper` before relying on this for anything
beyond local development. See [admin.md](admin.md#authentication-and-roles).

### `ai ledger` and `ai prompt optimize` - AI gateway tools

```bash
sbproxy ai ledger verify /var/lib/sbproxy/usage-ledger.jsonl
sbproxy ai ledger report /var/lib/sbproxy/value-ledger.redb --format json
sbproxy ai ledger reconcile /var/lib/sbproxy/usage-ledger.jsonl \
  --provider-export openai-usage-export.json --strict
```

`ledger verify` re-derives the verifiable usage ledger's hash chain (and,
with `--signing-seed-hex`, its signatures) and reports the first broken
entry. It reads the file directly, offline, and exits `0` when the ledger
verifies, `1` otherwise. `ledger report` aggregates a value ledger (the
redb file the AI handler keeps at `<cache_dir>/value-ledger.redb`) into
the same per-model savings report the admin `GET /admin/model-host/value`
route serves, with no server running; a missing file reports an empty
ledger rather than an error. `ledger reconcile` compares the usage
ledger against a downloaded provider usage export, per day and model, to
surface spend the ledger never saw: see
[ai-usage-ledger.md](ai-usage-ledger.md#reconciling-against-a-provider-export)
for the export format and what the result does and does not prove.

```bash
sbproxy ai prompt optimize \
  --prompt system-prompt.txt \
  --eval-set eval.jsonl \
  --endpoint https://api.example.com/v1 \
  --task-model gpt-4o-mini \
  --name support-agent \
  --prompt-version v3 \
  --output optimized.json
```

`prompt optimize` compiles a shorter static system prompt against a
customer-owned JSONL evaluation set, evaluating candidates against the
`--task-model` through the given `--endpoint` and stopping once the
aggregate quality drop would exceed `--noise-tolerance` (default `0.02`).
The result is a JSON artifact at `--output` recording the prompt-store
`--name` and `--prompt-version`.

### `audit verify` - check the security audit chain

```bash
sbproxy audit verify /var/lib/sbproxy/audit-chain.jsonl
sbproxy audit verify /var/lib/sbproxy/audit-chain.jsonl --signing-seed-hex "$SIGNING_SEED_HEX"
sbproxy audit verify /var/lib/sbproxy/config-audit.jsonl --channel config
```

Re-derives a tamper-evident audit chain from genesis and reports the
first record that does not check out. `--channel` picks which chain the
file at `<path>` is: `security` (the default, the trail
`audit.sink: chain` writes to the file named by `audit.path`), `config`
(the trail `audit.config_path` writes), `key` (`audit.key_path`), or
`admin` (`audit.admin_path`). Each channel writes a different payload
shape to its own file, so pass the channel that matches the file; see
[audit-log.md](audit-log.md) for what each trail records. Reads the file
and nothing else: no config, no admin API, no running proxy, so an
auditor with a copy of the chain and the public key can run this against
a file the proxy that wrote it no longer has. Without
`--signing-seed-hex` only the hash chain is checked; passing it also
verifies every signature. Exits `0` when the trail verifies, `1`
otherwise.

### `completions` - shell tab-completion scripts

Writes a `clap_complete`-generated completion script to stdout for
the requested shell. Pipe it into the shell's completion sink and the
binary, every subcommand, and every flag become tab-completable.

```bash
sbproxy completions bash > /etc/bash_completion.d/sbproxy
sbproxy completions zsh > "${fpath[1]}/_sbproxy"
sbproxy completions fish > ~/.config/fish/completions/sbproxy.fish
```

Accepted shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.
Homebrew users get completions wired automatically at install time;
the manual paths above are for source builds.

### Flags

Each flag has an environment-variable fallback. The command-line value
wins; if no flag is set, the env var is used; otherwise the documented
default applies.

#### `-f`, `--config` (path)

Path to the YAML config. Required for `serve`; optional for `validate`
when the path is given positionally.

- **Default:** none. Falls back to `SB_CONFIG_FILE`.
- **Environment:** `SB_CONFIG_FILE`

```bash
sbproxy --config /etc/sbproxy/sb.yml
SB_CONFIG_FILE=/etc/sbproxy/sb.yml sbproxy
```

#### `--log-level` (string)

Filter passed to `tracing-subscriber`. Accepts a bare level
(`info`, `debug`, `trace`, `warn`, `error`) or a per-target filter
string (`sbproxy=debug,h2=warn,pingora=info`).

The official release binary has a compile-time maximum of `info` for SBproxy's
own tracing calls, so `debug` and `trace` cannot restore SBproxy events that
were removed at compile time. Dependencies built without that ceiling may
still emit at those levels. Use a development build (`cargo build`) when you
need SBproxy-internal debug or trace events.

- **Default:** `info`.
- **Priority:** `--log-level` > `SB_LOG_LEVEL` > `RUST_LOG` >
  `proxy.observability.log.level` > `info`.
- **Environment:** `SB_LOG_LEVEL`

```bash
sbproxy --config sb.yml --log-level debug
SB_LOG_LEVEL=sbproxy=trace sbproxy --config sb.yml
```

#### `--log-format` (`compact`, `pretty`, `json`)

Selects the `tracing-subscriber` output format.

- `compact` (default): one short line per event. Best for tailing a
  terminal.
- `pretty`: multi-line with span trees. Best for local debugging.
- `json`: structured records. Best for shipping to a log aggregator
  (Loki, Datadog, CloudWatch).

Invalid values fail the parse with a clap error listing the accepted
names, so the proxy never starts with a silently ignored selector.

- **Default:** `compact`.
- **Priority:** `--log-format` > `SB_LOG_FORMAT` >
  `proxy.observability.log.format` > `compact`.
- **Environment:** `SB_LOG_FORMAT`

```bash
sbproxy --config sb.yml --log-format json
SB_LOG_FORMAT=pretty sbproxy --config sb.yml
```

#### `--request-log-level` (string)

Convenience filter for the `access_log` tracing target. This is appended
to the effective `--log-level` / `SB_LOG_LEVEL` / `RUST_LOG` filter as
`access_log=<level>`, so power users can still pass the full
per-target filter themselves.

- **Default:** unset; access logs inherit the effective global filter.
- **Priority:** `--request-log-level` > `SB_REQUEST_LOG_LEVEL` > unset.
- **Environment:** `SB_REQUEST_LOG_LEVEL`

```bash
sbproxy --config sb.yml --log-level warn --request-log-level debug
SB_REQUEST_LOG_LEVEL=trace sbproxy --config sb.yml
```

#### `--shutdown-grace-ms` (milliseconds)

Milliseconds Pingora waits for in-flight requests to complete on
SIGTERM before closing connections. Applied to both Pingora's
`grace_period_seconds` and `graceful_shutdown_timeout_seconds`
(rounded up to the next whole second). Supersedes `--grace-time`.

- **Default:** `30000` (30 seconds), matching Kubernetes' default
  `terminationGracePeriodSeconds` so a pod eviction in a
  default-configured cluster drains cleanly. Set to `0` for instant
  shutdown in test runners.
- **Environment:** `SBPROXY_SHUTDOWN_GRACE_MS`
- **Priority:** CLI flag wins over the env var; either wins over the
  legacy `--grace-time` / `SB_GRACE_TIME`.

```bash
sbproxy --config sb.yml --shutdown-grace-ms 30000
SBPROXY_SHUTDOWN_GRACE_MS=60000 sbproxy --config sb.yml
```

When SBproxy receives SIGTERM or SIGINT it emits a structured
`shutdown_signal_received` tracing event that includes the resolved
grace budget so operators can confirm the drain started before the
orchestrator's hard kill.

#### `--grace-time` (seconds, legacy)

Seconds Pingora waits for in-flight requests to complete on SIGTERM
before closing connections. Kept for back-compat; new deployments
should use `--shutdown-grace-ms` (which is the spelling the
Kubernetes operator and the docs lead with).

- **Default:** unset, so `--shutdown-grace-ms` resolves to its 30s
  default. Setting `--grace-time` suppresses the 30s default so the
  legacy value wins.
- **Environment:** `SB_GRACE_TIME`

```bash
sbproxy --config sb.yml --grace-time 30
SB_GRACE_TIME=60 sbproxy --config sb.yml
```

#### `--disable-sb-flags` (bare flag)

Lock off the per-request feature-flag surface (`x-sb-flags` header and
`?_sb.<k>` query params). When set, every built-in flag reads `false`
and the `extra` map is empty; CEL expressions that branch on
`features.*` see the same shape as a request with no flags. Use this
to harden production deployments that do not expect clients to drive
proxy behavior.

- **Default:** off; the flag surface is active.
- **Environment:** `SB_DISABLE_SB_FLAGS` (accepts `1`, `true`, `yes`,
  `on`, case-insensitive).
- **Priority:** CLI flag wins over the env var.

```bash
sbproxy --config sb.yml --disable-sb-flags
SB_DISABLE_SB_FLAGS=1 sbproxy --config sb.yml
```

See [§10. Feature flags](#10-feature-flags) for the surface the kill
switch disables.

#### `--check`

Validates the config and exits without starting the listener. Equivalent
to `sbproxy validate <path>`. Exit status 0 on success, 2 on a config
that fails to compile.

```bash
sbproxy --config sb.yml --check
```

### Planned, not yet wired

The following flag appears in older release notes but is not honored
by the current binary:

- `--config-dir` / `SB_CONFIG_DIR`. Pass an absolute or relative path
  to `--config`; the loader does not search a directory for known
  filenames.

---

## 3. Runtime behavior

### CPU detection

SBproxy sizes its Pingora worker pool to `std::thread::available_parallelism()`, which honors cgroup CPU quotas on Linux. In a container with a 2-CPU quota, the proxy spawns workers that match the actual available CPU capacity instead of getting throttled. To override (pin a benchmark to a known worker count, or cap workers below the cgroup quota), set `SB_WORKER_THREADS` to a positive integer:

```bash
SB_WORKER_THREADS=4 sbproxy --config sb.yml
```

Values that are not positive integers are ignored and the auto-detected value is used. There is no equivalent CLI flag; this is an environment-only knob because it is rarely changed and its right value is deployment-shape-specific.

In environments without cgroup CPU quotas (bare metal, macOS), the proxy falls back to the number of logical CPUs as reported by the OS.

### Worker stack size

Each Pingora worker polls the whole request path on one stack: the request filter, the module chain, the AI dispatch, the streaming relay, and every future they await are all live frames while a request is in flight. SBproxy gives each worker 8 MiB, which is the same size Linux gives a process's main thread by default. Override it with `SB_WORKER_STACK_BYTES`:

```bash
SB_WORKER_STACK_BYTES=16777216 sbproxy --config sb.yml
```

Values that are not positive integers are ignored and the default is used, the same way `SB_WORKER_THREADS` behaves. So is anything below one 4 KiB page: that is a size written in the wrong unit rather than a stack any thread can run on, and it is refused with a warning naming the value rather than by refusing to start, because an environment typo should not stop a proxy.

Raising this costs reserved address space, not memory. A thread stack is an anonymous mapping the kernel commits page by page as it is touched, so resident memory tracks how deep a request actually goes and not how much was reserved. Sixteen workers at 8 MiB reserve 128 MiB of a 64-bit process's 128 TiB address space and resident nothing extra.

Two reasons to raise it:

- The proxy logs `the request path is using most of a worker's stack`. That line is emitted once per process, when a request first passes three quarters of the worker stack, and it carries the bytes used and the stack size. It is a warning rather than an error: nothing has failed yet, but a stack overflow aborts the process without unwinding and leaves no diagnosis, so this is the last chance to act on it.
- A debug build. Debug frames are several times larger than release frames, so a proxy built with `cargo build` (no `--release`) reaches depths the shipped binary never does.

There is no equivalent config key or CLI flag; this is an environment-only knob for the same reason `SB_WORKER_THREADS` is.

### Startup sequence

SBproxy initializes subsystems in a fixed order. A config or pipeline
compile error aborts startup; most optional subsystems (telemetry, key
plane, pipeline lifecycle hooks) log and degrade instead of blocking.

1. **Config load and compile**: reads the single YAML file named by
   `--config` / `SB_CONFIG_FILE`, interpolates `${ENV}` references, and
   compiles it. A compile error is fatal.
2. **Observability wiring**: applies the metrics cardinality limiter
   (`proxy.metrics`), the log redaction state
   (`proxy.observability.log.redact`), per-tenant cardinality caps, and
   the declared log sinks.
3. **Scripting limits**: installs the Lua sandbox budgets from
   `proxy.scripting.lua.sandbox`.
4. **AI provider catalog**: loads the embedded provider catalog, or the
   override file named by `proxy.ai_providers_file` when readable.
5. **Rate-limit budgets, key plane, session ledger**: installs the
   workspace rate-limit budget registry, the dynamic key plane
   (`proxy.key_management`), and the session-ledger sink when enabled.
   These keep accumulated state across reloads.
6. **Detection singletons**: installs the agent-class resolver, the
   TLS-fingerprint catalog, and the agent-detect scorer.
7. **Pipeline compile**: builds the routing pipeline (origins, actions,
   auth, policies) and loads `listings/*.yaml` from the config file's
   directory. A pipeline compile error is fatal.
8. **Hot reload**: stores the pipeline in the hot-reload slot, starts
   the config file watcher, and installs the SIGHUP handler.
9. **TLS**: initializes TLS state when `https_bind_port`,
   `tls_cert_file`, or an enabled `proxy.acme` block is present.
10. **Listeners**: creates the Pingora server (worker count from
    `SB_WORKER_THREADS` or auto-detection, worker stack size from
    `SB_WORKER_STACK_BYTES` or the 8 MiB default), binds the plain HTTP
    listener on `http_bind_port`, and adds the HTTPS listener (manual
    certs or the ACME dynamic-certificate resolver, with optional
    mTLS). No QUIC port is bound. Config compilation rejects
    `proxy.http3.enabled: true` because HTTP/3 is not served.
11. **Admin server**: when `proxy.admin.enabled: true`, spawns the
    embedded admin listener (default `127.0.0.1:9090`) and registers
    the component health probes that `/readyz` and `/health` report.
12. **Background tasks**: starts the ACME renewal task when an enabled
    `acme` block is present, and the OCSP-stapling refresh task when
    `tls_cert_file` is set, then hands control to Pingora's run loop.
    See [OCSP stapling](#ocsp-stapling) for which certificates the
    second one covers.

Startup progress is visible in the log; the listener bind is announced
with a line like:

```
INFO starting sbproxy on 0.0.0.0:8080
```

### Signal handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown (drain in-flight requests up to the grace budget) |
| `SIGINT` (Ctrl+C) | Fast shutdown (drop in-flight requests immediately) |
| `SIGHUP` | Full config reload: recompile the YAML and hot-swap the pipeline |

Pingora handles SIGTERM and SIGINT itself; SBproxy subscribes to the
server's execution-phase broadcast and mirrors each phase into
structured tracing events (`shutdown_signal_received` on a graceful
SIGTERM, then `shutdown_started`, `shutdown_grace_period`,
`shutdown_runtimes`, and finally `shutdown_complete`) so operators can
confirm the drain started and finished.

### Graceful shutdown

On `SIGTERM`, SBproxy proceeds as follows:

1. The `shutdown_signal_received` event is logged with
   `signal=SIGTERM` and the resolved `grace_seconds` budget.
2. Pingora stops accepting new connections and waits up to the
   resolved grace budget (`--shutdown-grace-ms`, default 30 seconds)
   for in-flight requests to complete. The budget is applied to both
   Pingora's `grace_period_seconds` and
   `graceful_shutdown_timeout_seconds`.
3. The remaining shutdown phases are logged as they occur; the final
   `shutdown_complete` event marks the point where every listener and
   service runtime has exited.
4. The process exits with code `0` on clean shutdown.

On `SIGINT`, Pingora skips the grace window and tears down listeners immediately; in-flight requests see a connection close. Use this only for fast local-dev shutdowns.

---

## 4. Logging

### One subscriber, two targets

SBproxy logs through a single `tracing` subscriber. Application events
(lifecycle, config, errors) go to the default targets; per-request
access-log lines go to the dedicated `access_log` target so log
routers can split the two without extra plumbing.

The output format is `compact` by default (one short line per event).
Switch with `--log-format pretty` for local debugging or
`--log-format json` for a log aggregator; the env fallback is
`SB_LOG_FORMAT`.

### Log levels and filters

The filter is a standard `tracing-subscriber` directive: a bare level
(`info`, `debug`, `trace`, `warn`, `error`) or a per-target filter
string (`sbproxy=debug,h2=warn`).

- `--log-level` / `SB_LOG_LEVEL` sets the global filter (wins over
  `RUST_LOG`; default `info`).
- `--request-log-level` / `SB_REQUEST_LOG_LEVEL` appends an
  `access_log=<level>` directive so access logs can be tuned
  independently of the application log:

```bash
# Quiet application log, verbose request log
sbproxy serve -f sb.yml --log-level warn --request-log-level debug
```

The same two knobs exist in YAML under `proxy.observability.log`,
which also carries redaction, sink fan-out, and custom access-log
fields. CLI flags and env vars win over the YAML values, so a
deployment that already exports `RUST_LOG` keeps getting `RUST_LOG`.

```yaml
proxy:
  observability:
    log:
      level: info        # trace | debug | info | warn | error
      format: compact    # compact | pretty | json
```

A config reload picks up a changed `level` and cannot pick up a
changed `format`, which needs a restart. The full order, including
what a reload does to a level set through the admin API, is in
[observability.md](observability.md).

At runtime, the filter can be changed without a restart through the
admin API: `PUT /admin/log-level` with `{"level": "debug"}` (see
[admin-api-reference.md](admin-api-reference.md)). The same release-build
ceiling applies: changing a filter never restores compile-stripped events.

### Access logs

Structured JSON access logging is opt-in via the top-level
`access_log` block. The full record schema (phase timings, AI token
fields, header capture) and the filter semantics live in
[access-log.md](access-log.md); the two knobs most deployments touch
are sampling and the output sink:

```yaml
access_log:
  enabled: true
  sample_rate: 0.01
  always_log_errors: true
  slow_request_threshold_ms: 1000
```

`always_log_errors` and `slow_request_threshold_ms` force matching
requests through before the sampler runs.

By default, access-log lines are emitted via the `access_log` tracing
target. To write them directly to a rotating file instead:

```yaml
access_log:
  enabled: true
  output:
    type: file
    path: /var/log/sbproxy/access.log
    max_size_mb: 100
    max_backups: 5
    compress: true
```

---

## 5. Metrics and observability

### Prometheus metrics

The proxy serves `/metrics` on its main HTTP port (`http_bind_port`, default `8080`). When the embedded admin server is enabled, the same series are mirrored on the admin listener so operators can scrape through the access-controlled port instead. Scrapes are not throttled.

```
GET http://localhost:8080/metrics
```

Label cardinality is capped by `metrics.max_cardinality_per_label` (default `1000`). The `hostname` label uses its ADR budget by default and can be overridden with `metrics.cardinality.hostname_cap`. Values past the effective cap collapse into the literal `__other__`.

#### Hostname-scoped metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_requests_total` | Counter | `hostname`, `method`, `status`, `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape` |
| `sbproxy_request_duration_seconds` | Histogram | `hostname` |
| `sbproxy_errors_total` | Counter | `hostname`, `error_type` |
| `sbproxy_active_connections` | Gauge | (none) |
| `sbproxy_cache_results_total` | Counter | `origin`, `result` (`hit`, `miss`) |
| `sbproxy_ai_tokens_attributed_total` | Counter | `provider`, `model`, `surface`, `direction` (`input`, `output`), attribution labels |

#### Agent detection metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_agent_detect_total` | Counter | `agent_id`, `provenance` |
| `sbproxy_agent_detect_score` | Histogram | (none) |
| `sbproxy_agent_detect_inference_seconds` | Histogram | (none) |

#### Per-origin metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_origin_requests_total` | Counter | `origin`, `method`, `status` |
| `sbproxy_origin_request_duration_seconds` | Histogram | `origin`, `method`, `status` |
| `sbproxy_origin_active_connections` | Gauge | `origin` |
| `sbproxy_bytes_total` | Counter | `origin`, `direction` (`in`, `out`) |
| `sbproxy_auth_results_total` | Counter | `origin`, `auth_type`, `result` (`allow`, `deny`) |
| `sbproxy_policy_triggers_total` | Counter | `origin`, `policy_type`, `action`, `agent_id`, `agent_class` |
| `sbproxy_cache_results_total` | Counter | `origin`, `result` |
| `sbproxy_circuit_breaker_transitions_total` | Counter | `origin`, `from_state`, `to_state` |

### Example Prometheus scrape config

```yaml
scrape_configs:
  - job_name: sbproxy
    static_configs:
      - targets: ["sbproxy-pod:8080"]
    scrape_interval: 15s
```

### OpenTelemetry tracing

SBproxy exports distributed traces via OTLP. Configure in `sb.yml`:

```yaml
proxy:
  observability:
    telemetry:
      enabled: true
      endpoint: "http://otel-collector:4317"
      transport: grpc        # grpc | http
      service_name: sbproxy
      sample_rate: 1.0       # 1.0 = 100%, 0.1 = 10%
      always_sample_errors: true
      keep_over_budget_usd: 1.00
      keep_slower_than_secs: 2.0
      resource_attrs:
        deployment.environment: production
```

For HTTP export:

```yaml
proxy:
  observability:
    telemetry:
      enabled: true
      endpoint: "https://otel-collector.example.com:4318/v1/traces"
      transport: http
```

### Admin API

The embedded admin server (separate from `/metrics` above; lives on
its own port) exposes operator routes for request log, per-target
health, hot reload, drift detection, and the emitted OpenAPI
document. See [admin-api-reference.md](admin-api-reference.md) for
the full per-route schema and [section 9](#9-hot-reload) for the
hot-reload workflow.

---

## 6. Health checks

SBproxy serves probe endpoints on two listeners. The main data plane
(`http_bind_port`, default `8080`) serves `/metrics` and keeps a minimal
`/health` compatibility response for requests whose `Host` does not match a
configured origin. A matched origin owns `/health` like every other route, so
an application's health endpoint remains reachable through the proxy. The
embedded admin listener (`proxy.admin`, default
`127.0.0.1:9090`) serves the full probe set unauthenticated, alongside
its authenticated operator routes. All responses are
`application/json`.

### Endpoints

| Endpoint        | Listener | Aliases    | Purpose                | Success | Failure |
|-----------------|----------|-----------|-------------------------|---------|---------|
| `/health`       | data plane | (none)  | Unrouted-host liveness fallback; otherwise routed to the origin | `200` for fallback | never for fallback |
| `/livez`        | admin    | `/live`   | Liveness; process is up  | `200`   | never   |
| `/readyz`       | admin    | `/ready`  | Readiness; ready to serve | `200`   | `503`   |
| `/healthz`      | admin    | (none)    | Liveness; trivial body   | `200`   | never   |
| `/health`       | admin    | (none)    | Rich operator health     | `200`   | `503`   |

The bare `/live` and `/ready` aliases return identical bodies to
`/livez` and `/readyz`. On the admin listener, `/health` is the rich
operator/SIEM endpoint. On the data plane, an unrouted Host receives the fixed
liveness body (`{"status":"ok"}`); a Host that matches an origin reaches that
origin's `/health` route. K8s readiness probes should hit `/readyz` and
liveness probes `/livez` when the admin listener is reachable from
the kubelet. If they use the data-plane fallback instead, keep the probe Host
outside the configured origin set (the default pod-IP Host normally does) or
choose an application health route deliberately (see [section
12](#12-kubernetes-deployment)).

### `/livez`

Returns `200` as long as the binary is running, regardless of registry
state. Used for "should I restart this pod?". The body is intentionally
a single field so a load balancer can pattern-match it cheaply.

```json
{"alive": true}
```

### `/healthz`

Pure liveness. Returns `200` with body `{"status":"ok"}` whenever the
binary is running.

```json
{"status": "ok"}
```

### `/health` (admin listener)

Rich health report for humans, dashboards, and SIEM ingestion. It
includes the binary version, embedded git revision, current timestamp,
process uptime, and the same component checks used by readiness:

```json
{
  "status": "ok",
  "version": "1.5.0",
  "build_hash": "5e8cfa8",
  "timestamp": "2026-05-04T18:30:00Z",
  "uptime_seconds": 12345,
  "checks": [
    {"name": "usage_ledger", "status": "healthy"},
    {"name": "mesh_quorum", "status": "not_configured", "detail": "mesh not enabled"}
  ]
}
```

When any readiness component is unhealthy, `/health` returns `503` and
the top-level `status` is `"unready"`. `/healthz` remains a fixed-size
liveness response for load balancers.

### `/readyz`

Walks the registered component readiness probes (agent registry,
bot-auth key directory, usage ledger, mesh quorum, synthetic pipeline
probe, etc.) and returns `200` only when every probe reports ready
(`healthy`, `degraded`, and `not_configured` all count as ready). The
body's `components` field is an array, sorted by component name, so a
dashboard can surface which component failed:

```json
{
  "status": "ok",
  "components": [
    {"name": "agent_registry", "status": "healthy"},
    {"name": "usage_ledger", "status": "not_configured", "detail": "no ledger append yet"}
  ]
}
```

`usage_ledger` covers the verifiable usage chain this proxy appends to,
and nothing else. The AI-crawl redeem ledger is a separate service with
no readiness component, so a dead redeem endpoint leaves `/readyz`
green; watch that one through its own metrics instead.

When a component is `unhealthy`, the envelope's `status` flips to
`"unready"` and the response is `503`:

```json
{
  "status": "unready",
  "components": [
    {"name": "agent_registry", "status": "healthy"},
    {"name": "mesh_quorum", "status": "unhealthy", "detail": "isolated: 0 of 1 min peers alive"}
  ]
}
```

The set of components depends on which features the live config
enabled; a deployment with no mesh or ledger reports those probes as
`not_configured` rather than dropping them.

### Load balancer target health checks

Configure per-origin health checks for load balancer targets under the origin's action:

```yaml
origins:
  "api.example.com":
    action:
      type: load_balancer
      targets:
        - url: https://backend-1.internal
        - url: https://backend-2.internal
      health_check:
        path: /health
        interval: 10s
        timeout: 3s
        healthy_threshold: 2
        unhealthy_threshold: 3
        expected_status: 200
```

Unhealthy targets drop out of rotation. Per-target health state is exposed through the admin API's `GET /api/health/targets` route (see [admin-api-reference.md](admin-api-reference.md)); there is no per-target Prometheus metric.

### Component registration

Subsystems register named health probes with the health registry. The registered names appear in `/readyz`'s `components` array and `/health`'s `checks` array. Components report `"healthy"`, `"degraded"`, `"unhealthy"`, or `"not_configured"` status strings; only `"unhealthy"` fails readiness.

---

## 7. TLS and certificates

### Manual TLS

Provide a PEM certificate chain and key as file paths under `proxy`.
Setting `https_bind_port` requires either the manual pair or an
enabled `acme` block:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert_file: certs/server-cert.pem
  tls_key_file: certs/server-key.pem
```

The HTTPS listener negotiates HTTP/2 and HTTP/1.1 via ALPN. There are
no YAML knobs for minimum TLS version or cipher suites; the rustls
defaults apply.

### ACME auto-TLS

SBproxy works with any ACME-compatible certificate authority; the
default directory is Let's Encrypt production. Certificates are issued
per hostname in the config, stored in the configured backing store,
and renewed automatically. Until the first issuance completes, the
listener serves a self-signed fallback certificate so handshakes do
not fail outright. Issued and renewed certificates are swapped in live
via SNI, with no restart.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  acme:
    enabled: true
    email: ops@example.com
    # directory_url: https://acme-v02.api.letsencrypt.org/directory
    # challenge_types: ["http-01"]
    # storage_backend: redb
    # storage_path: /var/lib/sbproxy/certs
    # renew_before_days: 30
```

Field reference:

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch for ACME-managed certificates |
| `email` | (empty) | Account contact registered with the ACME directory |
| `directory_url` | Let's Encrypt production | ACME directory URL |
| `challenge_types` | `["http-01"]` | Allowed challenge types in priority order. `http-01` is the only type the proxy drives today; `tls-alpn-01` parses but is not served |
| `storage_backend` | `redb` | Backing store for issued certificates |
| `storage_path` | `/var/lib/sbproxy/certs` | Where the store lives, interpreted per backend: a directory (`redb`, `sqlite`, `file`), a `host:port` (`redis`), or a bucket URL like `s3://bucket/prefix` (`s3`, `gcs`, `azure`) |
| `renew_before_days` | `30` | Days before expiry to attempt renewal |

The `http-01` challenge is answered on the plain HTTP listener, so
keep `http_bind_port` reachable from the CA. For Let's Encrypt
staging, point `directory_url` at
`https://acme-staging-v02.api.letsencrypt.org/directory`. The Docker
Compose stack ships a Pebble test CA for local development
(`https://pebble:14000/dir`).

`http-01` is the only challenge type the proxy drives, so this block
cannot obtain a wildcard certificate; Let's Encrypt issues those over
DNS-01 alone. On Kubernetes, issue certificates with
[cert-manager](https://cert-manager.io/) and terminate TLS at the
Ingress instead of enabling this block. See
[kubernetes.md](kubernetes.md#tls-certificates).

### OCSP stapling

Stapling reaches one certificate, the manual fallback loaded from
`tls_cert_file`. With that pair configured, SBproxy fetches an OCSP
response for it at startup, refreshes every 12 hours, and attaches the
result to the fallback certificate so later handshakes carry it.

Certificates issued by the `acme` block are served without a stapled
response, as is any certificate selected by SNI. A deployment that uses
`acme` and no `tls_cert_file` staples nothing at all.

There is no configuration key to turn stapling on or off. It follows
from `tls_cert_file` being set, and the startup log says which case a
given deployment is in:

```text
INFO OCSP stapling is inactive: it reaches the manual fallback certificate only, and no proxy.tls_cert_file is configured. Every certificate this proxy serves, including every ACME-issued one, is served without a stapled response. served=3 stapled=0 covered=0
```

`served` counts every certificate the resolver can present, the
fallback included. `stapled` counts how many of those currently carry a
response. `covered` is how many the refresh task can reach at all.

The request is the RFC 6960 one that names the certificate: a POST of
`application/ocsp-request` to the responder URL in the certificate's
Authority Information Access extension, carrying a `CertID` built from
the leaf's serial number together with hashes of its issuer's name and
public key. That issuer comes out of `tls_cert_file` itself, so the
file has to hold the full chain, leaf first. A file holding only the
leaf is refused with a message saying so, because without the issuer
there is no public key to hash and so no way to say which certificate
the question is about.

Reaching the responder is still not the same as getting something
worth stapling, so three things are checked before anything is
attached. The HTTP status has to be 200. The body has to parse as a
successful basic OCSP response. And the response has to be about the
certificate that was asked about, which is what stops a responder, or
anything on the plaintext hop to it, from answering `good` for some
other certificate. Anything refused is counted under
`sbproxy_ocsp_fetch_total{result="unknown_status"}` and never reaches
a handshake. A response a client cannot tie to the certificate in
front of it is worse than no response at all, because a client that
checks the staple rejects a certificate that is otherwise valid.

What SBproxy does not check is the responder's own signature. A client
that reads the staple verifies that itself against the issuer, so a
forged response cannot make a revoked certificate look good. What it
can do is cost connections to the clients that check, which is why the
three checks above matter even without it.

Two metrics report the state:

| Metric | Meaning |
|--------|---------|
| `sbproxy_ocsp_fetch_total{result}` | Fetch attempts by outcome: `ok`, `no_responder`, `parse_error`, `http_error`, `unknown_status` |
| `sbproxy_ocsp_staple_age_seconds{host}` | Age of the cached response, labeled `_fallback`. Absent until a fetch succeeds, so a deployment that never stapled is distinguishable from one whose staple went stale |

### Mutual TLS (mTLS) for inbound connections

To require clients to present certificates when connecting to SBproxy,
add a `proxy.mtls` block. It applies to the HTTPS listener (manual
certs or ACME) and requires `https_bind_port`:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert_file: certs/server-cert.pem
  tls_key_file: certs/server-key.pem
  mtls:
    client_ca_file: certs/ca-cert.pem
    require: true
    allowed_cn_patterns:
      - "^service-[a-z]+$"
```

Field reference:

| Field | Default | Description |
|-------|---------|-------------|
| `client_ca_file` | (required) | PEM CA bundle used to verify client certificates |
| `require` | `true` | When `true`, the handshake fails without a valid client cert. When `false`, certless clients connect and the upstream sees `X-Client-Cert-Verified: 0` so it can decide |
| `allowed_cn_patterns` | `[]` | Regex allowlist for the client certificate CN. Empty accepts any CN signed by the CA |

Verified client-certificate metadata is forwarded to the upstream as
`X-Client-Cert-*` headers.

### Generating development certificates

The repository includes a script that generates a local CA, a server
certificate, and a client certificate for development and mTLS
testing:

```bash
./scripts/generate-certs.sh
# Generates in ./certs/:
#   ca-cert.pem, ca-key.pem
#   server-cert.pem, server-key.pem
#   client-cert.pem, client-key.pem
```

---

## 8. Connection tuning

Pingora owns the runtime's upstream connection pool. The legacy
per-origin `connection_pool` shape remains parseable, and one field in it
is read.

| Field | Default | Description |
|-------|---------|-------------|
| `idle_timeout_secs` | `90` | Live. Legacy spelling of `timeouts.idle_ms`, in seconds; feeds the resolved upstream idle deadline when `idle_ms` is unset. Setting both fails config load |
| `max_connections` | - | Refused. Setting it fails config load; the keepalive pool is sized once for the process, not per origin |
| `max_lifetime_secs` | - | Refused. Setting it fails config load; the pool has no age-based eviction |

Prefer `timeouts.idle_ms` in new configs. For the two refused fields,
reach for a `concurrent_limit` policy to bound an origin's in-flight
requests, and `timeouts.idle_ms` to retire pooled connections. Buffer
sizes and handshake timeouts follow Pingora's runtime defaults.

### HTTP/3 (QUIC)

HTTP/3 is not served by this build. No QUIC listener is started and no
`Alt-Svc` header is advertised. The `proxy.http3` shape is retained for
forward compatibility, but config compilation rejects `enabled: true`
and says so plainly. HTTP/2 is the highest version served. The
reserved shape is:

```yaml
proxy:
  http3:
    enabled: false         # true is rejected during config compilation
    idle_timeout_secs: 30
    max_streams: 100
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Reserved activation flag. Must remain false in this build |
| `idle_timeout_secs` | `30` | Reserved idle timeout for QUIC connections |
| `max_streams` | `100` | Reserved maximum concurrent QUIC streams per connection |

---

## 9. Hot reload

### File watcher

SBproxy watches the directory containing the configuration file via `notify`, rather than the file itself, so an atomic-rename save or a Kubernetes ConfigMap symlink swap is still seen. Watching the directory also means every unrelated file in it reports an event, so two things decide whether a reload actually happens.

A save arrives as a burst of events, not one event, so the watcher waits for the burst to go quiet (250 ms, capped at 2 seconds for a directory that never goes quiet) before reading. Back-to-back editor writes therefore coalesce into a single reload rather than one apiece, and the read sees a finished file rather than one still being written.

It then compares the file's content against what is currently loaded, and does nothing when they match. Activity on a neighboring file, or a no-op save of the config itself, costs no reload. This matters beyond efficiency: a reload swaps the compiled pipeline, which ends every live MCP session and makes callers re-initialize.

When the content has genuinely changed, the swap is atomic, and a config that fails to compile leaves the previous pipeline serving.

### SIGHUP trigger

Send `SIGHUP` to manually trigger a configuration reload without modifying any file:

```bash
kill -HUP $(pgrep sbproxy)
```

### Admin endpoint trigger

When the embedded admin server is enabled (`proxy.admin.enabled: true`), an authenticated `POST /admin/reload` re-reads the same on-disk config the file watcher monitors and hot-swaps the pipeline.

```bash
curl -X POST \
  -u admin:secret \
  http://127.0.0.1:9090/admin/reload
```

Successful responses return JSON with the new revision tag:

```json
{"config_revision":"a3f2d1c0","loaded_at":"2026-04-26T18:32:11Z"}
```

Status codes:

| Code | Meaning |
|------|---------|
| 200 | Reload succeeded; the response body carries `config_revision` and `loaded_at`. |
| 400 | YAML parse error. The response sanitizes the file path so error envelopes never leak the absolute path on disk. |
| 401 | Missing or invalid basic auth. |
| 405 | Wrong HTTP method (only `POST` is accepted). |
| 409 | Another reload is already in flight. The proxy serializes the file watcher and the admin route on the same single-flight guard. |
| 500 | Pipeline compile or filesystem read failed. |
| 503 | Admin server is running without a configured `config_path` (typical for embedded test fixtures). |

The reload endpoint uses the same auth, IP filter, and rate limiter as the read-only admin routes. The single-flight guard means a manual reload during a file-watcher reload does not race; one wins, the other returns `409`. This is the integration point the Kubernetes operator uses to drive hot-reload on `kubectl apply` instead of triggering a rolling restart - see [kubernetes.md](kubernetes.md).

For the complete per-route schema of every admin endpoint (`/api/requests`, `/api/health`, `/api/health/targets`, `/api/stats`, `/api/openapi.{json,yaml}`, `/admin/reload`, `/admin/drift`, plus the unauthenticated probe routes), see [admin-api-reference.md](admin-api-reference.md).

### What reloads

Every reload path (SIGHUP, file watcher, `sbproxy apply`,
`POST /admin/reload`) runs the same primitive: recompile the YAML and
atomically swap the live pipeline. That covers most of the config
surface:

| Change Type | Reload Behavior |
|-------------|-----------------|
| Origins: routing, upstream URLs, actions, auth, policies | Hot-reloaded; the new pipeline serves the next request |
| AI provider catalog (`proxy.ai_providers_file`) | Hot-reloaded |
| Agent classes, detection settings, key management, log redaction, sinks, Lua sandbox limits | Hot-reloaded |
| Listener and server-level settings: `http_bind_port`, `https_bind_port`, TLS listener shape, `proxy.admin`, worker threads | Requires process restart |
| Rate-limit budget accumulators, session-ledger sink registration | Registered at startup; state survives reloads, registration changes need a restart |

The runtime log filter is not part of config reload; change it with
`--log-level` at start or `PUT /admin/log-level` at runtime.

When a reload completes, the log includes the line `config reloaded
successfully`, and the `sbproxy_config_reload_total{result="success"}`
counter increments. If the reload fails (for example, malformed YAML),
the watcher logs `reload failed; serving prior pipeline` with the
error, `sbproxy_config_reload_total{result="failure"}` increments, and
the previous configuration stays active.

---

## 10. Feature flags

Feature flags are per-request hints that alter proxy behavior. Clients inject them via a request header or query parameters, and CEL expressions and Lua scripts read them through the `features` namespace.

### Built-in flags

| Flag | Key | Effect |
|------|-----|--------|
| Debug | `debug` | Enables per-request debug logging and adds debug headers to responses |
| Trace | `trace` | Enables distributed trace propagation and detailed span events |
| No-Cache | `no-cache` | Bypasses the response cache for this request (cache-control: no-cache semantics) |

### Setting flags via header

Clients can set flags per-request using the `x-sb-flags` header. Multiple flags are comma-separated or semicolon-separated:

```bash
# Enable debug for this request
curl -H "x-sb-flags: debug" https://api.example.com/endpoint

# Enable multiple flags
curl -H "x-sb-flags: debug, trace" https://api.example.com/endpoint

# Flag with a value
curl -H "x-sb-flags: no-cache, env=staging" https://api.example.com/endpoint
```

### Setting flags via query parameter

The magic query parameter prefix `_sb.` is recognized:

```bash
curl "https://api.example.com/endpoint?_sb.debug&_sb.no-cache"
```

### Using flags in CEL expressions

The `features` namespace exposes the parsed flags. Built-ins are
booleans; extra `key=value` pairs are strings. Hyphenated keys like
`no-cache` need bracket access because hyphens are not valid CEL
identifiers:

```yaml
policies:
  - type: expression
    expression: 'features.debug == false'
    deny_status: 403
```

Available accessors:

| CEL              | Type   | Meaning |
|------------------|--------|---------|
| `features.debug`     | bool   | `x-sb-flags: debug` or `?_sb.debug`. |
| `features.trace`     | bool   | `x-sb-flags: trace` or `?_sb.trace`. |
| `features["no-cache"]` | bool | `x-sb-flags: no-cache` or `?_sb.no-cache`. |
| `features.any_set`   | bool   | True when any flag (built-in or extra) is set. |
| `features["env"]`, etc. | string | Free-form `k=v` pairs from the header / query. Empty string when not provided. |

When the kill switch (`--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1`)
is engaged, all built-ins read `false` and `extra` is empty.

### Workspace-level feature flags (planned)

Earlier release notes described workspace-level flags propagating over a
message bus. That is not implemented, and the message bus it assumed does
not exist: `proxy.messenger_settings` is refused at config load. Only
per-request header and query parsing is wired today.

---

## 11. Docker deployment

### Single container

Mount a config directory containing `sb.yml`, map the listener ports, and pass
the startup command explicitly. The published `soapbucket/sbproxy` and
`ghcr.io/soapbucket/sbproxy` images set the `sbproxy` entrypoint but no default
command. Their image metadata exposes 8080 and 9090; Docker can map any ports
you configure.

```bash
docker run -d \
  --name sbproxy \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy:/etc/sbproxy:ro \
  -e SB_LOG_LEVEL=info \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

For a read-only config with a writable ACME certificate store (the default `proxy.acme.storage_path` is `/var/lib/sbproxy/certs`):

```bash
docker run -d \
  --name sbproxy \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy/sb.yml:/etc/sbproxy/sb.yml:ro \
  -v sbproxy-acme-certs:/var/lib/sbproxy/certs \
  -e SB_LOG_LEVEL=info \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

### Docker Compose stack

The repository ships a Docker Compose stack for local development at
[`docker/docker-compose.yml`](../docker/docker-compose.yml). It runs
six services on a shared bridge network:

- **sbproxy**: the proxy itself, built from the repository and started
  with the stack's `docker/sb.yml`, ports `8080` and `8443` mapped.
- **pebble**: a Let's Encrypt Pebble test ACME server for exercising
  the ACME issuance path locally (directory on port `14000`).
- **redis**: shared-state backend for the L2 cache and distributed
  rate limiting.
- **prometheus**: scrapes the proxy using `docker/prometheus.yml`
  (port `9090`).
- **grafana**: dashboards with anonymous admin access for local use,
  pre-provisioned with the Prometheus datasource (port `3000`).
- **jaeger**: all-in-one trace backend with OTLP intake on `4317` and
  the UI on `16686`.

Start and stop the stack:

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml down
```

### Building the Docker image

```bash
make docker
# Equivalent to:
docker build -f Dockerfile.cloudbuild -t sbproxy:dev .
```

This locally built image uses a multi-stage build: the builder stages compile the
binary and the embedded admin UI, and the final image is
`gcr.io/distroless/cc-debian12`, with no shell or package manager. The
default command is `serve -f /etc/sbproxy/sb.yml`, so mounting a
config at that path is enough for this local image. The published release
images are assembled separately in `.github/workflows/release.yml` and do not
set that command.

---

## 12. Kubernetes deployment

### Deployment and Service

A minimal Deployment and Service for SBproxy. Prometheus scrapes `/metrics` on the main HTTP port.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sbproxy
  namespace: proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sbproxy
  template:
    metadata:
      labels:
        app: sbproxy
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: sbproxy
          image: soapbucket/sbproxy:1.13.0
          args: ["serve", "-f", "/etc/sbproxy/sb.yaml"]
          env:
            - name: SB_LOG_LEVEL
              value: info
            - name: SBPROXY_SHUTDOWN_GRACE_MS
              value: "30000"
            - name: SB_WORKER_THREADS
              valueFrom:
                resourceFieldRef:
                  resource: limits.cpu
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: https
              containerPort: 8443
              protocol: TCP
          volumeMounts:
            - name: config
              mountPath: /etc/sbproxy
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
            successThreshold: 1
          resources:
            requests:
              cpu: 250m
              memory: 128Mi
            limits:
              cpu: "2"
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: sbproxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: sbproxy
  namespace: proxy
spec:
  selector:
    app: sbproxy
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
    - name: https
      port: 443
      targetPort: https
      protocol: TCP
```

### Probes

The example above probes `/health` on the serving port (`8080`). Kubernetes
uses the pod IP as the Host, so it receives the fixed `200` liveness fallback
unless that IP is itself configured as an origin. If you configure pod-IP
origins or set an explicit matching Host header, `/health` routes to that
origin instead; use the admin probes below or make the application's response
part of your readiness contract.

The richer `/livez` and `/readyz` endpoints live on the embedded admin
listener, not the serving port. To use them as probes, enable the
admin server and make it reachable from the kubelet: set
`proxy.admin.enabled: true`, `bind: "0.0.0.0"`, and an `allow_ips`
list covering the node network (the probe endpoints themselves are
unauthenticated, but the admin listener's IP allowlist applies to
every connection). Both of those fields make the admin surface
reachable off loopback, so the same config needs a real `password`:
the default `changeme` is a validation error once either one is set
(see [admin.md](admin.md#the-default-credentials-are-refused-off-loopback)).
Then point the probes at port `9090`:

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

`/readyz` folds in the registered component probes (usage ledger, mesh
quorum, synthetic pipeline), so it can take a pod out of rotation on a
component failure instead of only on process death. See
[section 6](#6-health-checks).

### UDP support for HTTP/3

HTTP/3 is currently disabled pending native Pingora HTTP/3, so no QUIC/UDP listener is started today and the UDP wiring below is not needed yet. It is documented for when HTTP/3 returns.

HTTP/3 uses QUIC over UDP. Kubernetes Services with `type: ClusterIP` do not support UDP and TCP on the same port number by default; you need separate Service objects, or `type: LoadBalancer` with a cloud provider that supports mixed protocols.

For AWS Network Load Balancer with mixed protocol support:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sbproxy-nlb
  namespace: proxy
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: "ip"
spec:
  type: LoadBalancer
  selector:
    app: sbproxy
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
    - name: https-tcp
      port: 443
      targetPort: 8443
      protocol: TCP
    - name: https-udp
      port: 443
      targetPort: 8443
      protocol: UDP
```

### Resource recommendations

Starting-point guidelines. Actual requirements depend on traffic volume, origin count, and enabled features. See [performance.md](performance.md) for benchmark data.

| Workload | CPU Request | CPU Limit | Memory Request | Memory Limit |
|----------|-------------|-----------|----------------|--------------|
| Low traffic (< 1k rps) | 100m | 500m | 64Mi | 256Mi |
| Medium traffic (1k-10k rps) | 250m | 2000m | 128Mi | 512Mi |
| High traffic (10k+ rps) | 500m | 4000m | 256Mi | 1Gi |

When running in a CPU-limited container, set `SB_WORKER_THREADS` via `resourceFieldRef` as shown in the Deployment example above. The proxy's worker pool then matches the actual CPU limit rather than the node's total CPU count.

### ConfigMap for configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sbproxy-config
  namespace: proxy
data:
  sb.yaml: |
    proxy:
      http_bind_port: 8080
      https_bind_port: 8443
      acme:
        enabled: true
        email: ops@example.com
        # The config mount is read-only; point the certificate
        # store at a writable volume (an emptyDir loses certs on
        # pod restart, a PVC keeps them).
        storage_path: /var/lib/sbproxy/certs

    origins:
      "api.example.com":
        action:
          type: proxy
          url: https://backend.internal
```

### PodDisruptionBudget

Ensure at least one replica is available during rolling updates:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: sbproxy-pdb
  namespace: proxy
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: sbproxy
```

---

## 13. Environment variables reference

The binary reads fifteen environment variables, most of them fallbacks
for CLI flags. Variables are applied at process start; changes require a
restart.

| Variable | CLI Flag | Default | Description |
|----------|----------|---------|-------------|
| `SB_CONFIG_FILE` | `-f`, `--config` | (empty) | Path to `sb.yml`. Required if no flag and no positional arg. |
| `SB_LOG_LEVEL` | `--log-level` | `info` | Filter for `tracing-subscriber`. Wins over `RUST_LOG`. |
| `SB_LOG_FORMAT` | `--log-format` | `compact` | Output format for the tracing subscriber: `compact`, `pretty`, or `json`. |
| `SB_REQUEST_LOG_LEVEL` | `--request-log-level` | (unset) | Appends an `access_log=<level>` target filter for request/access logs. |
| `SBPROXY_SHUTDOWN_GRACE_MS` | `--shutdown-grace-ms` | `30000` | SIGINT/SIGTERM drain budget in milliseconds. Wins over `SB_GRACE_TIME`. |
| `SB_GRACE_TIME` | `--grace-time` | (unset) | Legacy Pingora grace period and shutdown timeout in seconds. Superseded by `SBPROXY_SHUTDOWN_GRACE_MS`. |
| `SB_WORKER_THREADS` | (none) | (auto) | Override the auto-detected Pingora worker thread count. Positive integers only. |
| `SB_WORKER_STACK_BYTES` | (none) | `8388608` | Stack in bytes for every Pingora worker, blocking-pool and offload thread. A value below one 4 KiB page, which is a size written in the wrong unit, is ignored with a warning and the default is used. See [worker stack size](#worker-stack-size). |
| `SB_DISABLE_SB_FLAGS` | `--disable-sb-flags` | `false` | Lock off the per-request `x-sb-flags` surface. Accepts `1`, `true`, `yes`, `on`. |
| `SB_ADMIN_URL` | `--admin-url` | `http://127.0.0.1:9090` | Admin API base URL for the commands that talk to a running proxy: `apply`, `models ps` / `stop` / `remove`, `cluster status`, and every `config authority` subcommand. |
| `SB_ADMIN_USERNAME` | `--username` | `admin` | Admin Basic Auth username for the same commands. |
| `SB_ADMIN_PASSWORD` | `--password` | (unset) | Admin Basic Auth password for the same commands. Never printed, and cleared from memory once the request header is built. |
| `SB_APPLY_CONFIG` | (none) | (unset) | Path to the proposed YAML used by `sbproxy apply -p <plan-file>`. Required for the `-p` flow because the plan file does not embed the YAML path. |
| `SB_APPLY_BASELINE` | (none) | (unset) | Optional baseline override for `sbproxy apply -p`. When set, apply compares the plan's recorded baseline revision against this YAML's revision; otherwise the empty config is the baseline. |
| `SBPROXY_CLUSTER_TOKEN` | `--token` | (unset) | One-time enrollment token for `sbproxy cluster enroll`. Prefer this over a command-line value, which stays in shell history. |

In addition, the standard `RUST_LOG` env var is honored when neither
`--log-level` nor `SB_LOG_LEVEL` is set, and
`proxy.observability.log.level` is honored when none of the three is.

### OpenTelemetry configuration

SBproxy does not read the standard `OTEL_*` SDK environment variables.
The OTLP exporter (endpoint, transport, service name, sampling,
resource attributes) is configured entirely in YAML under
`proxy.observability.telemetry`; see
[section 5](#5-metrics-and-observability).

### Quick reference - common configurations

Minimal production startup:

```bash
SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
SB_LOG_LEVEL=info \
SBPROXY_SHUTDOWN_GRACE_MS=30000 \
sbproxy
```

Debug troubleshooting session:

```bash
SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
SB_LOG_LEVEL=debug \
sbproxy
```

Validate before deploy:

```bash
sbproxy validate /deploy/sb.yml
echo "Exit code: $?"
```

Container with the canonical environment:

```bash
docker run --rm \
  -e SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
  -e SB_LOG_LEVEL=info \
  -e SBPROXY_SHUTDOWN_GRACE_MS=30000 \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy:/etc/sbproxy:ro \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

### HTTP/3 limitations

HTTP/3 is currently disabled entirely until native QUIC support lands in Pingora. No QUIC listener is started, so there is no HTTP/3 dispatch path and the previous per-auth and per-action limitations over HTTP/3 do not currently apply. All traffic is served over HTTP/1.1 and HTTP/2, where every auth and action module is supported. These limitations will be revisited when HTTP/3 returns.

---

*For configuration file reference, see [configuration.md](configuration.md).*
*For scripting (CEL, Lua, JavaScript, WASM) reference, see [scripting.md](scripting.md).*
*For AI gateway setup, see [ai-gateway.md](ai-gateway.md).*
*For troubleshooting and runbooks, see [troubleshooting.md](troubleshooting.md).*
