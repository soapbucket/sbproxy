# Single binary to self-host

*Last modified: 2026-07-09*

The serve-only quickstart from [`docs/self-hosting.md`](../../docs/self-hosting.md):
one local model running on this box as provider zero, with a cloud
provider after it in the same fallback array for spill. Every plane the
gateway already runs (keys, budgets, guardrails, the usage ledger)
applies to the local model unchanged.

## Status

This config exercises the serve surface and the fallback array. The
engine-spawn lifecycle needs a GPU host to run end to end, and an
Apple Silicon Mac counts: the Metal path is certified. On a box
without a supported GPU the block validates but starts no engine. See
[`docs/model-host.md`](../../docs/model-host.md) and
[`docs/model-host-certification.md`](../../docs/model-host-certification.md).

## Run

The cloud spill provider in `sb.yml` reads `${OPENAI_API_KEY}`:

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/self-hosting/sb.yml
```

## What it shows

- Provider zero runs the weights locally; `engine: auto` and the fit
  planner choose the engine and quant for the card.
- A cloud provider sits after it in the fallback chain for spill.
- The local and cloud lanes share one routing, budget, and ledger path.
