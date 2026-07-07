# Point your coding assistant at your own GPU

*Last modified: 2026-07-06*

The gateway hosts glm-4-flash on the local GPU and serves it under the
alias `claude-sonnet-4-5`. Because SBproxy exposes an Anthropic-format
`/v1/messages` bridge alongside the OpenAI wire, Claude Code reaches the
local model with only a base-URL change, and OpenAI-wire clients like
Cline and Continue use the same endpoint on `/v1/chat/completions`. The
full walkthrough, including the Claude Code caveat, lives in
[docs/use-case-coding-assistant.md](../../docs/use-case-coding-assistant.md).

## Run

```bash
# straight from the binary
sbproxy sb.yml

# or via compose (uncomment the GPU reservation in docker-compose.yml first)
docker compose up
```

Requires a host with an NVIDIA GPU and an inference engine on `PATH`;
`sbproxy doctor` reports whether the box qualifies. On a CPU-only host
the config validates and the gateway boots, but no engine starts and
requests to the local model fail.

## Expected output

```console
$ curl -s http://localhost:8080/v1/messages \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-sonnet-4-5","max_tokens":128,
         "messages":[{"role":"user","content":"Say hello."}]}' \
  | jq -r '.model, .content[0].text'
claude-sonnet-4-5
Hello! Running locally and ready to help.
```

The response is Anthropic-shaped even though a local GLM produced it.
The first request is slow: it pays for the weight download and the
engine boot. After that, `keep_alive: 30m` keeps the model resident.

## See also

- [docs/use-case-coding-assistant.md](../../docs/use-case-coding-assistant.md) - the story this example belongs to
- [docs/model-host.md](../../docs/model-host.md) - the `serve:` block reference and phased status
- [docs/self-hosting.md](../../docs/self-hosting.md) - the self-hosting overview
