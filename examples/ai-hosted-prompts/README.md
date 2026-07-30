# Hosted model + prompt management

This example runs one hosted provider (Anthropic) behind the gateway, manages
prompt versions through the Admin API, and compiles a shorter static prompt
against a checked-in evaluation set. Clients speak the OpenAI chat-completions
shape; the gateway translates to Anthropic and back.

The prompt store is runtime state managed over the admin API, not config,
so `sb.yml` only declares the provider and turns the admin server on.

## Run it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-hosted-prompts/sb.yml
```

The data plane listens on `127.0.0.1:8080`; the admin server on
`127.0.0.1:9090` (HTTP Basic `admin` / `change-this`, change it before
exposing anything).

## Manage a prompt

Add a version. `version` is your label, `template` is the prompt text
(with optional `{{ variables.* }}` placeholders):

```bash
curl -u admin:change-this http://127.0.0.1:9090/admin/prompts/test.sbproxy.dev/greeting/versions \
  -H 'Content-Type: application/json' \
  -d '{"version": "1", "template": "You are a terse assistant. Answer in one sentence."}'
```

Pin it as the default:

```bash
curl -u admin:change-this -X PUT http://127.0.0.1:9090/admin/prompts/test.sbproxy.dev/greeting/pin \
  -H 'Content-Type: application/json' \
  -d '{"version": "1"}'
```

List what is stored (returns each prompt with its versions and the pinned
`default_version`):

```bash
curl -u admin:change-this http://127.0.0.1:9090/admin/prompts
```

Editing is live: add a `"2"` version and pin it, and the next request
picks it up with no restart.

## Compile a shorter prompt offline

With the proxy still running, use its OpenAI-compatible endpoint to optimize
the checked-in source prompt:

```bash
cargo run -p sbproxy -- ai prompt optimize \
  --prompt examples/ai-hosted-prompts/source-prompt.txt \
  --eval-set examples/ai-hosted-prompts/eval-set.jsonl \
  --endpoint http://127.0.0.1:8080/v1 \
  --host-header test.sbproxy.dev \
  --task-model claude-haiku-4-5 \
  --optimizer-model claude-haiku-4-5 \
  --metric exact-match \
  --noise-tolerance 0 \
  --max-candidates 4 \
  --max-requests 24 \
  --timeout-secs 60 \
  --name access-decision \
  --prompt-version 2 \
  --output /tmp/access-decision-v2.json
```

`--host-header test.sbproxy.dev` routes the request to the example's configured origin
while `--endpoint` keeps the local dial address. The command evaluates the
source on all three cases at temperature zero. It
makes one candidate-generation request, evaluates every shorter usable
candidate that fits the configured candidate and request caps on the same
cases, and accepts only a candidate with no quality drop.
With three cases and four candidates, the maximum possible request count is
`3 * (4 + 1) + 1`, or 16; the configured cap of 24 leaves room while still
bounding the run.

Inspect the evidence before changing live state:

```bash
jq '{
  source_sha256,
  metric,
  baseline_score,
  optimized_score,
  original_tokens,
  optimized_tokens,
  prompt_version
}' /tmp/access-decision-v2.json
```

The optimizer writes no live prompt state. Install the selected version after
review:

```bash
jq '.prompt_version' /tmp/access-decision-v2.json \
  | curl -u admin:change-this \
      http://127.0.0.1:9090/admin/prompts/test.sbproxy.dev/access-decision/versions \
      -H 'Content-Type: application/json' \
      --data-binary @-
```

Pin version 2:

```bash
curl -u admin:change-this -X PUT \
  http://127.0.0.1:9090/admin/prompts/test.sbproxy.dev/access-decision/pin \
  -H 'Content-Type: application/json' \
  -d '{"version": "2"}'
```

Use the stored prompt by name:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: test.sbproxy.dev' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "claude-haiku-4-5",
    "prompt": "access-decision",
    "messages": [{"role": "user", "content": "Decision: access denied."}]
  }'
```

SBproxy resolves the pinned version, prepends its template as a system message,
removes the gateway-only `prompt` field, and sends the result to Anthropic.

The JSONL contract is one case per nonblank line with unique `id`, nonblank
`input`, and non-null `expected`. `exact-match` and `contains` require a string
expectation. `json-exact` accepts any non-null JSON value and requires the
complete model response to parse to that value.

The optimizer is limited to static instructions. It rejects a source prompt
with Minijinja markers. It also rejects candidate strings with few-shot
markers such as `Example:` or paired `Input:` and `Output:`, rejects Minijinja
markers and candidates that are not shorter, and writes no output if none
remains within the quality noise. These are syntax guards, so use a
task-specific process for prompts whose demonstrations have no labels. For a
direct hosted endpoint, pass `--api-key-env NAME`; the flag reads the key from
that named environment variable instead of putting the secret in shell
history.

## Send a request

An OpenAI-shaped chat completion to `test.sbproxy.dev`, served by Claude on the
upstream:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: test.sbproxy.dev' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "claude-haiku-4-5",
    "messages": [{"role": "user", "content": "Write a haiku about caching."}]
  }'
```

The response comes back in OpenAI shape (`choices[0].message.content`,
`usage.prompt_tokens`, ...) even though Claude served it.

## Or use the dashboard

Build the admin UI (`cd ui && npm run build`, then build sbproxy with
`--features embed-admin-ui`) and open `http://127.0.0.1:9090/admin/ui`:

- **Prompts** lists your versions and lets you add and pin them.
- **Playground** sends a chat completion to the `test.sbproxy.dev` endpoint and
  shows the response with token usage, cost, and latency.

See [Stored prompts and offline optimization](../../docs/ai-gateway.md#stored-prompts-and-offline-optimization)
for every optimizer bound and selection rule. See
[`admin.md`](../../docs/admin.md) for the admin surface.
