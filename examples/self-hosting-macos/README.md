# Self-host on a Mac, admin included

*Last modified: 2026-07-09*

Stand up a self-hosted model on an Apple Silicon Mac with the embedded
admin API and UI switched on. One binary from Homebrew, one config
file: the gateway acquires llama.cpp and the weights on the first
request and serves the model on Metal. The admin surface gives you the
request log, usage counters, and config view on loopback.

## Prerequisites

An Apple Silicon Mac (M1 or later). The Q4_K_M quant of Qwen3-8B needs
about 6 GiB of unified memory. Check what this host can serve first:

```bash
brew install soapbucket/tap/sbproxy
sbproxy doctor
```

`doctor` should show Metal as available and llama.cpp as fetchable.

## Run

From this directory:

```bash
sbproxy sb.yml
```

The proxy listens on `http://127.0.0.1:8080` and the admin server on
`http://127.0.0.1:9090` (loopback only by default).

## First request

The first request pulls the pinned llama.cpp macos-arm64 release and
the GGUF weights (~5 GiB), so expect it to take a few minutes; watch
the acquisition progress in the gateway log. After the engine is warm:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-8b","messages":[{"role":"user","content":"Hi"}]}' \
  | jq -r '.choices[0].message.content'
```

## Admin surface

Open the UI at <http://127.0.0.1:9090/admin/ui> and log in with
`admin` / `change-this` (rotate the password in `sb.yml` before real
use). The same endpoints answer over curl:

```bash
curl -s -u admin:change-this http://127.0.0.1:9090/metrics | head
```

The admin server binds loopback only by default. To reach it from
another machine, set `bind:`, add an `allow_ips:` CIDR allowlist, and
serve it over TLS; `docs/admin.md` walks through that hardening.

## Usage ledger

Every completed call appends to a hash-chained ledger the admin UI's
usage view reads from. Inspect and verify it:

```bash
jq -r '.event.model' /tmp/sb-macos-ledger.jsonl | sort | uniq -c
sbproxy ai ledger verify /tmp/sb-macos-ledger.jsonl
```

## What it shows

- A served provider with no `base_url`: the gateway spawns the engine
  and resolves its loopback port itself.
- Engine and weights acquired on demand; Metal on Apple Silicon.
- The embedded admin API + UI on a loopback port, with the usage
  ledger wired in.

For the hybrid shape (local model plus cloud spill in one fallback
array), see [`examples/self-hosting/`](../self-hosting/) and
[`docs/self-hosting.md`](../../docs/self-hosting.md).
