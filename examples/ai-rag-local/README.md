# ai-rag-local

Gateway-performed retrieval, end to end, with no cloud accounts and no
credentials. SBproxy embeds the incoming question, queries a
Qdrant-compatible vector store scoped to the origin's tenant, injects
the retrieved chunk as marked system context, and only then calls the
model. Every upstream is one deterministic local fixture, so the run is
reproducible and the smoke test can assert the exact retrieved sentence
reached the model.

The interesting part is what the fixture refuses to do. Its chat
endpoint returns 500 unless the request body already contains the
retrieved sentence, so a passing run is proof that retrieval happened
inside the gateway, not a claim about it. Its vector endpoint returns an
empty result unless the query filter pins `tenant_id == "docs"`, so a
passing run also proves the tenant filter was sent.

## What is in the bundle

| File | Role |
|---|---|
| `sb.yml` | One `ai_proxy` origin with a `rag:` block, `on_failure.mode: fail_closed` |
| `fixture.py` | Stdlib-only HTTP server: embeddings, Qdrant query, chat completion |
| `docker-compose.yml` | `sbproxy` + `rag-fixture` on one bridge network |
| `smoke.json` | The CI assertion: retrieved refund policy reaches the model |
| `Makefile` | `up`, `run`, `smoke`, `down` |

## Prerequisites

Docker with the compose plugin. The gateway image is built from the
workspace source on first run; the default build includes the
`rag-full` feature set, which this example needs. No API keys and no
network egress.

## Run it

From this directory:

```bash
make run
```

This builds the gateway image, starts the fixture, waits for both, and
publishes the gateway on `127.0.0.1:8080`. Then send the question:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.localhost' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "fixture-chat",
    "messages": [{"role": "user", "content": "When do refunds arrive?"}]
  }'
```

Expected response:

```json
{
  "id": "chatcmpl-fixture-0001",
  "object": "chat.completion",
  "created": 0,
  "model": "fixture-chat",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Refunds take five business days."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 42, "completion_tokens": 8, "total_tokens": 50}
}
```

The user never typed that sentence. The gateway embedded the question,
searched the `support-docs` collection with the tenant filter, injected
the retrieved chunk, and the fixture model echoed it back because the
context was present in the request it received.

## See the fail-closed path

Stop the fixture while the gateway keeps running:

```bash
docker compose stop rag-fixture
```

Repeat the curl. Retrieval now fails and `mode: fail_closed` turns that
into a 502 with a `rag_retrieval_failed` error body instead of calling
the model without context. Bring it back with
`docker compose start rag-fixture`.

## Run the smoke assertion

```bash
make smoke
```

This runs `scripts/examples-smoke.sh` against this directory: it boots
the stack, waits for `/health`, posts the question, asserts the response
contains the retrieved sentence, and tears everything down.

## Clean up

```bash
make down
```

This removes the containers, the network, and any volumes.

## Read more

The operator guide for the `rag:` block, including every field, the
failure policies, the build features, and the metrics, is
[docs/rag.md](../../docs/rag.md).
