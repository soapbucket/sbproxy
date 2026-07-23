# Classifier-based routing
*Last modified: 2026-07-23*

A `type: classifier` input guardrail reads the prompt and labels it with
one of the classes you declare. The label lands in
`ai.guardrails.labels`, a CEL expression in the
[AI policy plane](ai-policy-cel.md) turns it into a `route_to:<model>`,
and model-based routing hands the request to whichever provider declares
that model.

The result is a gateway that routes on what the request is asking for.
Documentation work to the cheap local model, incident triage to the
strong hosted one, anything unrecognized to the default, without the
caller having to say so.

Reach for it when the traffic arriving on one endpoint is genuinely mixed
and the client cannot or will not tell you which lane it belongs in.
Coding agents, internal chat surfaces, and anything speaking a fixed
OpenAI-compatible URL all have that shape.

## Routing on content, not on the caller

The usual way to split traffic is to make the client declare its lane: a
separate hostname, a path prefix, an `X-Task` header, or a different API
key per workload. That works when you control every caller and every
caller is honest. It stops working the moment a single agent sends both
kinds of work down one connection, or a team ships a client you do not
own.

Content-based routing moves the decision to the gateway. Nothing about
the request has to change, so an existing client keeps working, and the
rule lives in one config file instead of in every caller.

The tradeoff is that the decision is now a prediction rather than a fact.
A header is always right about what it says. A classifier is right most
of the time, so it belongs on decisions where being wrong costs money or
latency rather than correctness. Picking a cheaper model is a good fit.
Deciding who is allowed to do what is not, and a classifier cannot do it
anyway, because this guardrail never rejects a request.

## Two backends

Both backends fill in the same `classes:` map and produce the same kind
of label. They differ in what does the work.

| | `kind: embedding` | `kind: llm` |
|---|---|---|
| Where it runs | In the proxy, on the CPU | An OpenAI-compatible endpoint you name |
| Setup | Two model files on disk | A URL, a model name, sometimes a key |
| Cost per request | None | One chat completion |
| Prompt egress | None | The prompt goes to the endpoint |
| Typical added latency | Single-digit to low-tens of milliseconds | Whatever the endpoint takes, capped by `timeout_ms` |
| Unusual phrasings | Depends on your class examples | Generally better |

Choose `embedding` when the classes are distinct and you want the
decision to be local, private, and free. It is the right default: the
model is about 90 MB, it loads once at startup, and classifying a prompt
is a single forward pass.

Choose `llm` when you do not want model files in the deployment, when the
distinctions are subtle enough that example prompts do not capture them,
or when you already run a small local model and would rather ask it. The
same block covers a hosted provider and a local runtime such as Ollama,
vLLM, or LM Studio; only `base_url`, `model`, and whether a key is needed
change.

Nothing stops you from putting a cheap `type: regex` guardrail in front
of either one. The mesh runs cheap detectors first, so an obvious case
can be caught before any inference happens.

## Getting the model files

The `embedding` backend reads two files and downloads nothing.

```bash
mkdir -p /var/lib/sbproxy/models/minilm
curl -fSL -o /var/lib/sbproxy/models/minilm/model.onnx \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/minilm/tokenizer.json \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json
```

`all-MiniLM-L6-v2` is a 384-dimension sentence-transformer under
Apache-2.0, about 90 MB, and it is the same model the semantic cache
uses. If you already downloaded it for that, point at the same copy:
two guardrails configured with the same model and tokenizer paths share
one loaded model instead of parsing the graph twice.

Air-gapped sites download on a connected host and copy the files in. See
[local inference](local-inference.md) for the rest of the local-model
story, including the sidecar option for the other ONNX features.

The released `sbproxy` binary is built with the `inprocess-classify`
feature, so the `embedding` backend works out of the box. A build without
default features reports the missing backend at startup and leaves the
guardrail inert.

## Configuration

```yaml
guardrails:
  mesh:
    block_threshold: 0      # required: see below
    cache: true
    cache_capacity: 1024
    latency_budget_ms: 250

  input:
    - type: classifier
      scope: last_user_message
      max_chars: 2000
      backend:
        kind: embedding
        model_path: /var/lib/sbproxy/models/minilm/model.onnx
        tokenizer_path: /var/lib/sbproxy/models/minilm/tokenizer.json
        min_score: 0.30
        min_margin: 0.05
      classes:
        documentation:
          - "Write the README section documenting this endpoint."
          - "Add a docstring to this function explaining its arguments."
        coding:
          - "Refactor this function to remove the nested loop."
          - "Fix the panic in this parser when the input is empty."
```

### The guardrail entry

| Field | Default | Meaning |
|---|---|---|
| `type` | required | `classifier`. |
| `backend` | required | Which backend decides the class. Tagged by `kind`. |
| `classes` | required | Class name to example prompts. At least one entry, or the config fails to load. |
| `scope` | `last_user_message` | `last_user_message` classifies the final user turn. `full_text` classifies the whole prompt. |
| `max_chars` | `2000` | Characters kept before the backend sees the text. Must be above zero. |

`scope` defaults to the last user turn because that is almost always the
operative request, and because an embedding model truncates at a few
hundred tokens anyway. Use `full_text` when the class depends on the
whole conversation rather than the latest turn.

`max_chars` is a hard cut applied before anything else, so a very long
prompt cannot build an oversized tensor or inflate an LLM classification
call. If the scoped lookup finds nothing usable, for example a multimodal
content array that is not plain text, the guardrail falls back to the
extracted prompt text.

Class names are yours. They are matched case-insensitively against a
model's answer but the label published to the policy plane always uses
the spelling you configured, so a CEL rule matches what you wrote.

### `kind: embedding`

| Field | Default | Meaning |
|---|---|---|
| `model_path` | required | Absolute path to the ONNX embedding model. `~` is not expanded. |
| `tokenizer_path` | required | Absolute path to the matching `tokenizer.json`. |
| `min_score` | `0.30` | Cosine similarity the winning class must reach. |
| `min_margin` | `0.05` | Gap the winner must open over the runner-up. |
| `max_model_bytes` | 200 MB | Override for the model file size ceiling, in bytes. |

At startup every example prompt is embedded once and each class is folded
into a single average vector. Classifying a prompt is then one forward
pass and a comparison against those vectors. There is no training step
and no state carried between requests.

A class whose examples all fail to embed is dropped with a warning rather
than failing the load, so one bad example does not cost you the other
classes. If nothing survives, the backend goes inert.

The 200 MB ceiling exists so a wrong path cannot make the proxy parse
something enormous in its own address space. `all-MiniLM-L6-v2` is well
under it, so leave `max_model_bytes` unset unless you are running a
larger model deliberately.

### `kind: llm`

| Field | Default | Meaning |
|---|---|---|
| `base_url` | required | Full URL of the chat-completions endpoint. The complete path, not a prefix: `.../v1/chat/completions`, not `.../v1`. |
| `model` | required | Model identifier sent in the request body. |
| `api_key` | unset | Bearer token. Omit entirely for an endpoint that needs none. An empty value is a config error. |
| `timeout_ms` | `2000` | Wall-clock ceiling on one classification call. |
| `cache_capacity` | `1024` | Entries in the per-backend label cache, keyed by prompt text. |
| `fail_open` | `true` | Log level for a failed call. `true` warns, `false` logs at error. Neither blocks. |

The endpoint is asked, at temperature 0 and without streaming, to answer
with exactly one of your class names or the literal `none`. Your example
prompts are quoted back as few-shot guidance, up to ten per class. An
answer that is not one of your class names is discarded and no label is
emitted, which is what keeps a model's invention from ever reaching a
routing rule. `none` is reserved for that reason, so a class cannot be
named `none`.

Successful classifications are cached by prompt text, including the
"no class fits" outcome. Failures are deliberately not cached, so one
timeout does not suppress classification for every later copy of that
prompt.

`fail_open` picks a log level and nothing else. Both settings produce the
same outcome on a failure: no label, original routing, request forwarded.

### The mesh block

```yaml
mesh:
  block_threshold: 0
```

This is the setting people get wrong.

The mesh counts every guardrail that produced a label and blocks the
request when that count reaches `block_threshold`, which
[defaults to 1](ai-guardrail-mesh.md). A successful classification is a
label, so under a default mesh block a correctly classified prompt comes
back as a 400 `guardrail_violation`. Label-only routing needs
`block_threshold: 0`.

A `mesh:` block is also what publishes labels in the first place. With no
mesh configured at all, the pipeline takes its serial path, which stops
at the first guardrail that flags and never populates
`ai.guardrails.labels`. So a classifier without a mesh block is worse
than useless: it blocks and tells the policy plane nothing.

Two consequences worth planning around:

- `block_threshold: 0` applies to every guardrail on the origin. An
  injection or PII guardrail sharing that mesh will flag and be recorded
  but will not reject. If you need blocking guards, give them an origin
  whose mesh has a non-zero threshold.
- Leave `redact_on_flag` at its default of `false`. Turning it on masks
  the prompt of anything that flagged, which for a classifier means every
  successfully labeled request.

## From label to route

The label is the class name, verbatim. A CEL expression reads it out of
`ai.guardrails.labels` and emits a `route_to:`:

```yaml
ai_policy:
  expression: |
    "documentation" in ai.guardrails.labels
      ? ["route_to:qwen3-coder:30b", "set_sink_tag:docs-local"]
      : ["allow"]
  on_error: allow
```

`route_to:<model>` rewrites the requested model, and provider selection
then picks whichever provider declares that model in its `models:` list.
Nothing else needs to change: adding a lane means adding a class, a
provider that declares the model, and a branch in the expression.

The else branch is the whole safety story. A prompt that was not
classified, for any reason at all, produces no label, falls through to
`allow`, and keeps the model the client asked for.

`set_sink_tag:` is optional but recommended while you are tuning: it
stamps the usage record so you can count how much traffic each lane
actually took. See the [policy plane reference](ai-policy-cel.md) for the
full action set.

## Tuning

`min_score` is the floor the winning class has to clear, and `min_margin`
is the distance it has to keep from the runner-up. The margin is what
stops a prompt sitting between two classes from being assigned to one of
them arbitrarily. With a single configured class there is no runner-up,
so only the floor applies.

Symptoms and fixes:

- Prompts you expected to match are falling through: lower `min_score`,
  or add an example closer to the phrasings you actually see.
- Prompts are being labeled that should not be: raise `min_margin`
  first. It is usually ambiguity rather than a weak score.
- Two classes keep trading places: they are too close to be separated by
  this method. Merge them, or move to `kind: llm`.

Class examples matter more than either threshold. Six to ten short
prompts per class, written the way your callers actually write, works
well. Every example in a class is averaged into one vector, so examples
that pull in different directions blunt the class rather than broadening
it. If a class covers two genuinely different kinds of request, make it
two classes.

Tune against real traffic. Turn the guardrail on with a policy that only
tags, read a day of usage records grouped by tag, then add the
`route_to:` once the labels look right.

## Latency

The `embedding` backend adds a forward pass over a prompt already capped
at `max_chars`. On CPU that is single-digit to low-tens of milliseconds
per request. Every classification is timed into the
`sbproxy_inference_duration_seconds` histogram under
`kind="classify", backend="inprocess"`, so you can read the real number
on your own hardware rather than trusting this paragraph.

The `llm` backend adds a full chat completion, bounded by its own
`timeout_ms` and no more.

Three things bound the cost:

- **The backend cache.** The `llm` backend caches labels by prompt text,
  so a repeated prompt costs nothing.
- **The mesh verdict cache.** With `cache: true` the mesh caches the
  whole verdict set per prompt, so a replayed prompt skips every
  detector, classifier included. Sized by `cache_capacity`.
- **`latency_budget_ms`.** The mesh runs cheap detectors first and stops
  launching further ones once the budget is spent. The classifier is
  ranked expensive, so it is among the first things a spent budget skips.
  Skipping means no label, which means the request keeps its original
  routing. Routing quietly degrades under load instead of the latency
  ceiling moving.

One caveat on `latency_budget_ms`: it gates launching, not cancellation.
An LLM classification call already in flight when the budget runs out is
not aborted, and runs to its own `timeout_ms`. If you need a hard
ceiling, set `timeout_ms` to the number you actually mean.

## Failure behavior

None of these reject a request. That is deliberate: a routing hint should
never be able to turn into an outage.

**A backend that cannot load leaves the guardrail inert.** A missing or
unreadable model file, a file over the size ceiling, or no usable class
after embedding: each of these logs a warning naming the reason, and the
guardrail then emits no label for the life of that configuration. Every
prompt keeps its original routing. The other guardrails on that origin
keep running, so a bad classifier path does not disable the PII and
injection guards configured next to it.

**A failed classification emits no label.** A timeout, a connection
error, a non-2xx status, a body that will not parse, or an answer naming
a class you never configured all produce the same result: no label, and
the request is forwarded with the model the client asked for.

**An unresolved `${VAR}` in the LLM `api_key` degrades to inert.** If the
named environment variable was unset when the config loaded, the literal
`${VAR}` is never sent as a bearer token. The classifier goes inert and
logs at error level, naming the variable, because an unset key is nearly
always a deployment mistake rather than an intentional local difference.
Everything else on the origin keeps working.

**The LLM backend needs a `mesh:` block.** It is asynchronous, and the
serial guardrail path cannot await it. Configured without a mesh, it is
silently inert forever, so the proxy logs a warning once at startup
saying exactly that. Add the mesh block, with `block_threshold: 0`.

**A classifier under `output:` is a config error.** Classification needs
the message list to honor `last_user_message` scope, and the output paths
do not have it, so an output-side entry would compile and then do nothing
forever. It is rejected at config-compile time with an error telling you
to move the entry to `input:`.

Some config mistakes are hard errors rather than a quiet degrade, because
no host could make them right: an empty `classes` map, `max_chars: 0`, a
malformed `base_url`, an empty `model`, an empty `api_key`, or a class
named `none`. Those fail the config load.

## Try it

The runnable example is in
[`examples/ai-classifier-routing/`](../examples/ai-classifier-routing/).
