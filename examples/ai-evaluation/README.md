# Live AI evaluation

*Last modified: 2026-08-25*

Register one immutable dataset version and evaluate already-recorded model
responses through SBproxy's authenticated, scoped, bounded control plane. The
run is offline by design: it makes no provider or judge network call and needs
no Redis.

## Start

```bash
export SB_ADMIN_PASSWORD='replace-me'
export SB_ADMIN_URL='http://127.0.0.1:9090'
export SB_ADMIN_USERNAME='admin'
sbproxy examples/ai-evaluation/sb.yml
```

In another shell, export the same admin variables (including
`SB_ADMIN_PASSWORD`), then register and evaluate:

```bash
sbproxy ai dataset register \
  --origin ai.local \
  --dataset examples/ai-evaluation/dataset.json

sbproxy ai evaluate \
  --origin ai.local \
  --dataset support-answers \
  --version 1 \
  --responses examples/ai-evaluation/responses.json \
  --experiment-id support-v1-run-1 \
  --experiment-name support-v1-baseline \
  --model recorded-model \
  --prompt-version support-v1 \
  --required-keyword Settings \
  --min-bytes 1 \
  --max-bytes 512
```

The result contains aggregate counts and scores, never dataset entries or
recorded responses. A duplicate `(name, version)` is refused; evaluation always
names an exact dataset version and never falls forward to latest.

Every live CLI command also accepts `--admin-url`, `--username`, and
`--password`; the environment variables keep credentials out of shell history.
See [AI evaluation harness](../../docs/ai-evaluation-harness.md) for metric and
offline-judge options.
