# Model manifest

*Last modified: 2026-07-04*

The manifest is the operator's model list: which models exist, where
their weights come from, and the digests to verify them against. It is
the fleet fact sheet. `sb.yml` is the box fact sheet, what this box
serves and where its cache lives. A provider's `serve.catalog_file`
points at the manifest.

## Status

This example exercises the manifest **config surface**: the source
scheme, revision pin, per-file digests, the gated-repo token reference,
the default engine, and the pull policy all parse and validate. Acting
on them (the actual weight fetch, token resolution through the secret
resolver, and pull-policy execution) is the runtime half and needs a
GPU host to run end to end. See
[`docs/model-host.md`](../../docs/model-host.md).

## What the manifest carries

Each entry in [`models.yaml`](models.yaml) has:

- `source` - `hf:Org/Repo` for a hub pull, `file:/path` for weights
  already on disk (no network), `ms:` reserved for ModelScope.
- `revision` - the repo revision to pin (a branch, tag, or commit).
- `sha256` - per-file digests. A curated manifest with digests doubles
  as a supply-chain allowlist.
- `hf_token` - a gated-repo token as a secret reference (`${ENV}`,
  `secret:`, `vault://`), resolved at load, never a literal.
- `engine` - the default engine (`auto`, `vllm`, `llama_cpp`).
- `pull` - `on_boot`, `on_demand`, or `manual`.

## Run

```bash
make run CONFIG=examples/model-manifest/sb.yml
```

## What proves it is right

`sbproxy plan -f sb.yml` accepts the config, and every `serve.models`
entry resolves to a manifest id. The air-gapped `offline-coder` entry
uses a `file:` source, so it serves without any network fetch once its
weights are on disk.
