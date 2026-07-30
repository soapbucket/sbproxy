# Stateless AI context optimization

This example runs query-aware sentence selection, sidecar token pruning, and a
final model-window bound on explicitly marked retrieval text. It also asks
eligible provider attempts for concise reasoning. The route keeps no summary
state and creates no compression database.

## What you need

- An OpenAI key with access to `gpt-5-mini`.
- An operator-reviewed LLMLingua-2-compatible ONNX token classifier and its
  matching Hugging Face tokenizer.
- `cargo`, `curl`, and `jq`.

The repository does not bundle a pruning model. The runtime submits batch size
1, and the ONNX graph may declare that batch axis as fixed `1`, symbolic, or
unspecified. It must emit `f32` logits whose final dimension is `2`, where
class index 1 means keep. Review the artifact license and provenance before
loading it.

Use the official mBERT WordPiece or XLM-R Unigram LLMLingua-2 tokenizer
layout. The tokenizer must add exactly two model special tokens and may not
contain non-special added tokens. The sidecar rejects other layouts at load
time so token-target correction stays bounded.

## Start the token sidecar

Stage the model files, then run:

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen 127.0.0.1:9440 \
  --token-model llmlingua-2=/var/lib/sbproxy/models/llmlingua-2/model.onnx:/var/lib/sbproxy/models/llmlingua-2/tokenizer.json:512 \
  --default-token-model llmlingua-2 \
  --token-model-max-bytes 750000000 \
  --token-max-request-bytes 1048576 \
  --token-max-request-tokens 131072 \
  --token-max-windows 256 \
  --token-max-model-window 512 \
  --token-max-concurrent 2 \
  --token-max-queued 8
```

The final `512` is the model's full token window, including two special
tokens. Use the value declared by your model. The sidecar splits longer input
at punctuation-aware boundaries. The ordinary model-file limit is 209,715,200
bytes. A typical float32 mBERT LLMLingua-2 export is about 709 MB, so this
example raises only that limit. The other resource flags show their defaults;
lower them to match your deployment. Model IDs are limited to 256 UTF-8 bytes.
The 1 MiB request limit applies to the exact encoded `Compress` protobuf,
including the model ID, text, target, and framing.

For a co-located production deployment, replace `--listen` with:

```bash
--listen-uds /run/sbproxy/classifier.sock
```

Then set the route endpoint to
`unix:///run/sbproxy/classifier.sock`. The socket path must be absolute.

## Start SBproxy

In another shell:

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-context-optimization/sb.yml
```

The sidecar connection is lazy. SBproxy can start before the sidecar, and a
sidecar outage does not reject the AI request.

## Send the marked request

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: test.sbproxy.dev' \
  -H 'Content-Type: application/json' \
  --data-binary @examples/ai-context-optimization/request.json \
  | jq
```

The request carries one exact line-delimited retrieval block. Its query asks
about the failed deployment. The `events` chunk contains the answer, while the
database and network chunks provide plausible but irrelevant detail.

The configured levers run in this order:

1. `query_select` ranks sentences within the block against the marked query.
   It keeps at most five positive-scoring sentences, restores source order
   inside each retained chunk, and puts the strongest retained chunks near the
   block edges.
2. `token_prune` sends each remaining text chunk body to the sidecar. It keeps
   at most 70 percent of that chunk according to the pruning tokenizer, then
   enforces the same per-chunk limit with the request model's estimator.
   Retrieval tags, query text, and surrounding instructions never enter the
   classifier.
3. `window_fit` applies a 4,096-token input budget after reserving 1,024 tokens
   for completion. It remains available even if either earlier lever skips or
   fails.

The complete candidate from each strict lever must reduce SBproxy's target
model estimate before it commits. A candidate that expands the request is
discarded.

After compression and provider model mapping, `reasoning: concise` sets
`reasoning_effort: low` for this OpenAI `gpt-5-mini` attempt. A request with
non-empty `tools` or `functions`, or a code-shaped prompt, bypasses that
transform.

## Use an aggregate token target

Replace the pruning target when you need a bound across all marked bodies:

```yaml
target:
  mode: target_tokens
  target_tokens: 2048
```

SBproxy allocates the target across chunks, then counts all returned bodies
again with the request model. Output above the aggregate target is rejected as
an invalid sidecar result. Set the target to at least the number of marked
chunks; a smaller target skips the lever without a sidecar call.

For sentence selection, replace `max_sentences` with one per-block token bound:

```yaml
- type: query_select
  target_tokens: 1024
```

The two query bounds are mutually exclusive.

## Check fallback behavior

Stop the classifier sidecar and repeat the request. `token_prune` records
`failed` with reason `token_prune_unavailable`; `window_fit` still runs and the
provider still receives the last valid message list.

Remove the retrieval markers from a copy of the request to exercise the other
fallback. `query_select` skips with `missing_query`, `token_prune` skips with
`no_marked_context`, and `window_fit` remains eligible.

Inspect the closed outcomes:

```bash
curl -s http://127.0.0.1:8080/metrics \
  | grep '^sbproxy_ai_compression_lever_total'
```

The reasoning transform has its own content-free counter:

```bash
curl -s http://127.0.0.1:8080/metrics \
  | grep '^sbproxy_ai_reasoning_policy_attempts_total'
```

See [AI context compression](../../docs/ai-context-compression.md) for marker
grammar, every target field, cache behavior, and failure semantics. See the
[AI gateway guide](../../docs/ai-gateway.md#reasoning-policy) for all reasoning
provider mappings and safety bypasses.
