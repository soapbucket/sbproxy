# Air-gapped AI gateway

*Last modified: 2026-07-06*

![Air-gapped AI gateway](../../docs/assets/use-case-air-gapped.gif)

An AI gateway with no route out and nothing to say to the outside world.
The only provider is a `serve:` block, the weights come from a `file:`
source pinned by per-file sha256 digests in [`models.yaml`](models.yaml)
(the manifest doubles as a supply-chain allowlist, `pull: manual` closes
the last fetch path), and guardrails run in process. The compose file
makes the posture physical: an internal-only network the kernel will not
route past.

Full walkthrough: [`docs/use-case-air-gapped.md`](../../docs/use-case-air-gapped.md).

## Run

From the repo root:

```bash
sbproxy examples/use-case-air-gapped/sb.yml
```

Or with Docker Compose, from this directory (stage the demo weights
first so the `file:` source has something to verify):

```bash
mkdir -p weights/qwen3-coder-gguf
printf 'demo weights\n' > weights/qwen3-coder-gguf/model.gguf
docker compose run --rm sbproxy models pull offline-coder \
  --variant demo_q4 \
  --catalog-file /etc/sbproxy/models.yaml \
  --cache-dir /var/lib/sbproxy/models \
  --offline
docker compose up
```

The explicit pull copies the read-only source into the content-addressed
cache, checks its 13-byte length and SHA-256, and atomically publishes
the snapshot. `--offline` makes a transport call impossible. Because
the manifest says `pull: manual`, skipping this step makes the runtime
fail closed instead of acquiring on the first request.

## What to expect

`sbproxy validate sb.yml` prints `ok`, and `sbproxy plan -f` reports one
added origin with zero findings, both with no network access. A prompt
injection attempt gets `400 Bad Request` with
`"type":"guardrail_violation"` before it goes anywhere (in this config
there is nowhere for it to go). Under compose, the gateway answers on
the internal network while any request to the outside world fails, and
that failure is the point:

```bash
docker compose exec client curl -sS --max-time 5 https://test.sbproxy.dev
# exits nonzero: timeout or resolution failure, nothing routes out
```

The 13-byte demo file proves the offline acquisition and policy chain;
it is not a real GGUF and cannot produce tokens. Replace it and the
manifest size/digest with a vetted GGUF for inference. On a host with
no usable worker or engine, the proxy boots, logs a warning naming the
blocker, and clean prompts return 502. See
[`docs/model-host.md`](../../docs/model-host.md).
