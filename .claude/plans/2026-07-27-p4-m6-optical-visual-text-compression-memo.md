# P4 M6 spike: optical / visual-text compression on owned weights

Ticket: WOR-1935 (Backlog, Priority 4). Spike scope is the model-host
only. AC: a watch-and-prototype feasibility memo, no proxy work.

## What this is

Render text to an image, then feed that image to a vision-language model
instead of feeding the text as tokens. Because a vision encoder patches an
image far more coarsely than a tokenizer segments text, the same content
costs fewer "tokens" (vision patches) in the model's context window. This
only produces a real ratio when the encoder and decoder are trained
together for this exact task; feeding a screenshot of text to a generic
VLM does not reproduce these numbers.

- **DeepSeek-OCR** (2510.18234): reports roughly 10x compression at ~97%
  decoding precision, with a steeper falloff (~60% precision) around 20x.
  A second-generation release, DeepSeek-OCR-2, shipped 2026-01-27 with a
  new "Causal Visual Flow" encoder and a measured accuracy gain on
  OmniDocBench, which is a real signal that this is an actively developed
  line, not a one-off research paper. DeepSeek has also published
  production throughput numbers (200k+ pages/day on one A100-40G) for the
  document-digitization use case, which is a different workload shape than
  compressing live conversation context but is evidence the model is fast
  enough to run in a serving path, not just a research checkpoint.
- **Glyph** ("Scaling Context Windows via Visual-Text Compression",
  2510.17800): reports a more modest ~3-4x ratio. Less aggressive than
  DeepSeek-OCR but likely a gentler accuracy tradeoff at that lower ratio;
  this review did not find a production release or reference
  implementation as active as DeepSeek-OCR's.

## Why this is model-host-only, not proxy work

The epic-level note this ticket points to (L13) already ruled out doing
this at the proxy in front of closed APIs, and the finding holds: a proxy
sitting in front of OpenAI/Claude/Gemini cannot silently rewrite a
client's text prompt into a rendered image and expect the closed API's own
tokenizer and vision pipeline to reproduce a compression ratio tuned for a
specific co-trained encoder/decoder pair. Concretely: it's a net token
loss against OpenAI and Claude (their vision tokenizers are not tuned for
this), a fragile break-even against Gemini at best, it breaks prompt
caching (the rendered image is a new cache key every time upstream
content changes), and a hallucinated OCR read is a silent correctness bug
with no signal back to the caller. None of that changes here; this spike
only considers the case where sbproxy owns both the encoder and the
decoder, i.e. a managed DeepSeek-OCR-shaped deployment serving its own
requests.

## Where it could fit sbproxy's model-host

The natural shape is not "compress every request automatically." It is an
explicit, opt-in serving mode: a managed deployment declares itself as an
optical-compression front end for a long-context workload (for example,
document QA over sbproxy-served documents), the model-host launches the
paired encoder/decoder as one deployment the way LoRA adapters are one
deployment today, and the caller explicitly opts a request into it rather
than sbproxy silently rewriting arbitrary chat context. That keeps the
silent-hallucination risk bounded to workloads that asked for it.

## Recommendation: watch and prototype, do not build

This is real and moving (a second DeepSeek-OCR generation in three months
is a fast cadence for a technique this specific), but it is not yet a
build decision for three reasons: no evidence yet of a maintained,
version-pinned release artifact shaped like sbproxy's other managed
engines (a container image or a uv-installable package with a stable
CLI/server surface, the same bar `engine.vllm_container` / `engine.uv`
already hold managed engines to); no sbproxy-catalog workload today that
is context-bound enough on a self-hosted model to justify the accuracy
tradeoff; and the accuracy/ratio curve is steep enough (97% at 10x, ~60%
at 20x) that shipping this needs its own eval harness before it is
trustworthy for anything beyond a demo.

Concrete next step if this gets prioritized: a throwaway prototype running
DeepSeek-OCR-2 as a one-off (not integrated into `ManagedEngineConfig`)
against a real sbproxy document-QA-shaped workload, measuring actual
context-token reduction and answer accuracy delta on that workload
specifically, before any serving integration is attempted.

**Re-check trigger:** a DeepSeek-OCR or Glyph release that ships a
container image or pinned server binary (matching how sbproxy already
provisions vLLM/SGLang), or a third independent group reproducing these
ratios on a different base model, whichever comes first.
