# Model manifest

*Last modified: 2026-07-10*

This example uses a catalog v2 manifest as the immutable source of
truth for managed model bytes. `models.yaml` names the logical models
and exact variants; `sb.yml` selects the variants this node serves.

The included Qwen variant is a real pinned GGUF with its exact size and
SHA-256. The offline entry is intentionally a template: replace its
digest, size, source path, revision, and certification before using it.

## Inspect and pull

From the repository root:

```bash
sbproxy models show qwen2.5-0.5b-instruct \
  --catalog-file examples/model-manifest/models.yaml

sbproxy models pull qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --catalog-file examples/model-manifest/models.yaml \
  --cache-dir /var/lib/sbproxy/models
```

`models pull` resolves the variant against this worker, downloads to a
partial, verifies the declared byte length and SHA-256, and only then
publishes the immutable snapshot. Repeating the command verifies and
reuses the cache. Add `--offline` to guarantee that only verified cache
hits and `file:` sources can succeed. `HF_TOKEN` or
`HUGGING_FACE_HUB_TOKEN` is passed only to the transport for a gated
explicit pull and is never persisted in job or cache metadata.

## Run

```bash
make run CONFIG=examples/model-manifest/sb.yml
```

`catalog_file: models.yaml` resolves relative to the directory holding
`sb.yml`, not the process working directory. Because the Qwen entry is
`pull: on_boot`, startup does not publish the request pipeline until its
artifact is verified. Warming does not allocate a port, reserve VRAM,
or start llama.cpp. The first request performs fit and residency
planning, then launches llama.cpp with only the verified local GGUF
path.

## Catalog v2 fields

Each logical model supplies `params`, `license`, `family`, and
`context_length`. Each variant supplies:

- `id`, `format`, `quant`, and the allowlisted `engines`;
- an immutable `source` and `revision`;
- every required file with exact `path`, `size_bytes`, and `sha256`;
- accelerator, memory, and optional CUDA compute requirements;
- a support level and certification identifier.

`pull` is model policy: `on_boot` warms before startup completes,
`on_demand` acquires before first launch, and `manual` permits only an
explicit `sbproxy models pull` on a cache miss.

See [the model-host reference](../../docs/model-host.md) and [the
security model](../../docs/security-model-host.md).
