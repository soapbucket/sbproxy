# AI gateway: per-surface rate limits

*Last modified: 2026-05-31*

Different OpenAI surfaces have different cost and capacity profiles. Chat completions are cheap and high volume; image generation is slow and expensive; audio speech bills per character; reranking bills per document. Putting one global cap on the origin does not capture this. Per-surface rate limits cap each classified surface independently so an image-generation burst does not starve chat throughput, and a runaway batch job cannot hold up interactive traffic.

Surface labels come from `AiSurface::label()`: `chat_completions`, `models`, `embeddings`, `assistants`, `threads`, `batches`, `fine_tuning`, `files`, `realtime`, `image_generation`, `image_edits`, `image_variations`, `audio_transcription`, `audio_speech`, `moderations`, `reranking`. Each cap is a sliding one-minute window; the proxy returns 429 before any upstream call when the cap fires.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-per-surface-rate-limits/sb.yml
```

## Try it

Within the chat cap (the request passes through to OpenAI):

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Quick check."}]
  }'
```

Burst past the image cap (the first 30 requests in each minute return 200, the rest 429):

```bash
for i in $(seq 1 35); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    http://127.0.0.1:8080/v1/images/generations \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "dall-e-3",
      "prompt": "a small cat",
      "size": "1024x1024",
      "n": 1
    }'
done
```
