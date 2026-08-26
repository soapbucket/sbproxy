# Weighted prompt rollout

*Last modified: 2026-08-25*

Publish two immutable prompt versions and make stable weighted selections
through SBproxy's authenticated, scoped AI toolkit. The example needs no Redis
or model provider.

## Start

```bash
export SB_ADMIN_PASSWORD='replace-me'
export SB_ADMIN_URL='http://127.0.0.1:9090'
export SB_ADMIN_USERNAME='admin'
sbproxy examples/ai-prompt-rollout/sb.yml
```

In another shell, export the same admin variables (including
`SB_ADMIN_PASSWORD`), then select for a stable cohort:

```bash
sbproxy ai prompt select \
  --origin ai.local \
  --name support-system \
  --cohort customer-42
```

Repeat the command against the same config generation and cohort to get the
same version. Change the cohort to sample the configured distribution. The
response identifies the selected version and weight plus a lowercase SHA-256
cohort digest, but never returns prompt content, rollout salt, or the raw
cohort key.

Every live CLI command also accepts `--admin-url`, `--username`, and
`--password`; the environment variables keep credentials out of shell history.

On an `ai_proxy` origin, a bare request prompt reference such as
`"prompt":"support-system"` uses the same generation-owned selection after
the mutable runtime prompt overlay misses and before provider dispatch. An
explicit `"prompt":"support-system@2"` remains an exact stored-prompt reference
rather than a weighted selection.

See [Weighted prompt versioning](../../docs/prompt-versioning.md) for the stable
cohort algorithm, live request behavior, and observability contract.
