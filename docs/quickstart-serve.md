# Run a local model

*Last modified: 2026-07-28*

`sbproxy run` is the first local-model command to try. It chooses a catalogued artifact, verifies it, starts a managed local deployment, and prints an OpenAI-compatible endpoint. It is meant for one model on one machine. The completion command below uses `curl` and `jq`.

Check the host before downloading a model:

```bash
sbproxy doctor
sbproxy models list
```

`doctor` reports visible devices, available engines, cache location, and blockers. `models list` shows the catalog IDs that `run` accepts.

## Start a model

Install SBproxy if necessary, then start the small bootstrap model:

```bash
curl -fsSL https://download.sbproxy.dev | sh
sbproxy run qwen2.5-0.5b-instruct --variant q4_k_m
```

The first run downloads the selected artifact and the engine it needs. Keep this terminal open. SBproxy does not announce readiness until the model can answer requests.

The ready output names a loopback endpoint, usually `http://127.0.0.1:8080`, and prints `OPENAI_BASE_URL` plus an API-key placeholder for SDKs that require one. It also prints a generated loopback admin credential. Treat that password as a secret.

## Send a completion

In another terminal, call the endpoint:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5-0.5b-instruct","messages":[{"role":"user","content":"Say hello."}]}' \
  | jq '{model, content: .choices[0].message.content}'
```

The response contains the model name and nonempty assistant content. An OpenAI-compatible SDK can use the values printed in the ready output:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=local
```

`OPENAI_API_KEY=local` satisfies client libraries that require a nonempty value. It is separate from the generated admin credential.

## Stop or inspect it

Press `Ctrl-C` in the `sbproxy run` terminal to stop the local deployment. The verified artifact remains in the cache for a later run. To inspect catalog entries without starting a model:

```bash
sbproxy models show qwen2.5-0.5b-instruct --format json
sbproxy doctor --format json
```

Use a managed `proxy.model_host` configuration when you need fixed ports, an explicit cache location, several origins, or a deployment that survives the convenience command. [model-host.md](model-host.md) describes that shape. [self-hosting.md](self-hosting.md) covers local models with gateway policy and hosted fallback.
