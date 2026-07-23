# Classifier-based routing

Routes each request by what the prompt is asking for rather than by a
header or a path. A classifier guardrail labels the prompt, the CEL
policy plane turns that label into a `route_to:`, and model-based routing
picks the provider that declares the resulting model.

See [`docs/ai-classifier-routing.md`](../../docs/ai-classifier-routing.md)
for the full reference.

## What this config does

- A `type: classifier` guardrail sorts each prompt into `documentation`
  or `coding` using the local all-MiniLM-L6-v2 embedding model.
- `block_threshold: 0` puts the mesh in label-only mode. Without it the
  default threshold of 1 would treat the label as a flag and reject the
  request with a 400.
- The CEL expression rewrites the model to `qwen3-coder:30b` when the
  label is `documentation`, and tags the spend record so the local lane
  is queryable later.
- Anything else, including a prompt the classifier could not place, keeps
  the model the client asked for.

## Why a classifier and not a pattern list

A `type: regex` guardrail works and costs nothing, but it only catches
phrasings you thought of in advance. The classifier compares the prompt
against the example prompts you supply per class, so "put together a page
explaining the retry logic" lands on the documentation class without
anyone having written a pattern for it.

Both run in the same pipeline. The mesh sorts cheap detectors first, so
keeping a regex entry alongside the classifier costs nothing and catches
the obvious cases before inference runs.

## Model files

The classifier reads two files off disk and downloads nothing.

```bash
mkdir -p /var/lib/sbproxy/models/minilm
curl -fSL -o /var/lib/sbproxy/models/minilm/model.onnx \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/minilm/tokenizer.json \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json
```

The model is about 90 MB and the tokenizer well under 1 MB, so neither
comes near the 200 MB per-file ceiling and `max_model_bytes` can stay
unset. Put the files anywhere you like and edit the two paths in `sb.yml`
to match. They are absolute and `~` is not expanded.

If you already downloaded this model for the semantic cache, point at
that copy. Two guardrails on the same pair of paths share one loaded
model.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
ollama serve &
ollama pull qwen3-coder:30b
make run CONFIG=examples/ai-classifier-routing/sb.yml
```

## Try it

```bash
# A coding prompt: labeled `coding`, so the CEL else branch runs and the
# request keeps the model the client asked for.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"Refactor this function to remove the nested loop."}]}' \
  | jq -r .model
# claude-sonnet-4-5

# A documentation prompt: labeled `documentation`, rerouted to the local
# model.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":256,"messages":[{"role":"user","content":"Write the README section documenting this endpoint."}]}' \
  | jq -r .model
# qwen3-coder:30b

# A phrasing that appears in no example and no pattern list. This is the
# case the classifier exists for.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":256,"messages":[{"role":"user","content":"Put together a page explaining the retry logic."}]}' \
  | jq -r .model
# qwen3-coder:30b
```

If the last one comes back as `claude-sonnet-4-5`, lower `min_score` or add
a closer example to the `documentation` class.

## Switching to the LLM backend

The commented block at the bottom of `sb.yml` replaces the local model
with a call to any OpenAI-compatible `/chat/completions` endpoint. Swap
the `backend:` block and leave everything else alone; the same `classes:`
entries become few-shot guidance in the instruction the endpoint
receives.

That trades the model files for a network call and a per-request cost. It
also needs the `mesh:` block, which this config already has: the LLM
backend runs on the mesh's async pass, and without a mesh it stays inert
and says so once at startup.

## Tuning

`min_score` is the cosine floor the winning class must clear. `min_margin`
is how far ahead of the runner-up it has to be. Raise the margin if
prompts are getting labeled when they sit between two classes; lower the
score floor if prompts you expect to match are falling through.

A prompt that clears neither threshold gets no label and the CEL
expression falls through to its else branch. That is the safe direction:
an unclassified prompt keeps the model the client asked for.

Class examples matter more than the thresholds. Six to ten short,
representative prompts per class works well. They are averaged into one
vector per class, so examples that pull in different directions blunt the
class rather than broadening it.

## What this guardrail does not do

It never rejects a request. `block_threshold: 0` keeps the mesh from
blocking on the flag count, and no failure inside the classifier produces
a block either. A model file that will not load, an endpoint that times
out, an answer naming a class you never configured: each of those emits
no label, and the prompt keeps its original routing.

The flip side of `block_threshold: 0` is that it applies to every
guardrail on the origin, not only this one. If you want an injection or
PII guardrail to reject requests, put it on an origin whose mesh has a
non-zero threshold, or move the blocking guards to a separate origin.
