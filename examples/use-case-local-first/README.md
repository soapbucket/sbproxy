# Local first, spill to cloud

*Last modified: 2026-07-06*

One provider array with two lanes: a `serve:` entry that runs qwen3-14b
on this box, and a hosted provider behind it that catches overflow and
anything the card cannot take. Prompts flagged with
`x-sbproxy-disallow-prompt-training: true` route only to providers
marked `no_prompt_training` (here, only the local lane), and every
completed call from either lane lands in one hash-chained usage ledger
you can sum for the dollars the GPU displaced. The full story is in
[`docs/use-case-local-first.md`](../../docs/use-case-local-first.md).

The local lane needs a GPU host with an inference engine available;
`sbproxy doctor` names any blocker. On a box without one the config
still validates and boots, and every request spills to the cloud lane.

## Run

```bash
export OPENAI_API_KEY=sk-...

# With the installed binary:
sbproxy sb.yml

# Or with Docker:
docker compose up
```

## What to expect

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Hi"}]}' \
  | jq -r '.model'
```

Prints `qwen3-14b` when the local lane answered, `gpt-4o-mini` when the
request spilled. Then inspect the split and verify the ledger:

```bash
jq -r '.event.provider' /tmp/sb-local-first-ledger.jsonl | sort | uniq -c
sbproxy ai ledger verify /tmp/sb-local-first-ledger.jsonl
```

`verify` prints `ledger verify: OK (...)` and exits 0 when the chain is
intact.
