# Governed agent orchestration

*Last modified: 2026-08-25*

Configure scoped agents and finite-state workflows, discover capabilities,
validate a workflow, and run it through the authenticated admin plane. The
example needs no Redis; only the final run needs a compatible loopback agent.

## Start

Set secrets in the environment. `auth.shared_secret` is a secret reference;
putting the secret itself in `sb.yml` is rejected.

```bash
export SB_ADMIN_PASSWORD='replace-me'
export SB_AGENT_SECRET='replace-me-too'
export SB_ADMIN_URL='http://127.0.0.1:9090'
export SB_ADMIN_USERNAME='admin'
sbproxy examples/ai-agent-orchestration/sb.yml
```

In another shell, export the same admin variables (including
`SB_ADMIN_PASSWORD`), then inspect and validate without contacting the agent:

```bash
sbproxy ai workflow discover --origin ai.local --capability research
sbproxy ai workflow validate \
  examples/ai-agent-orchestration/workflow.yml --origin ai.local
```

After a compatible agent is listening on `127.0.0.1:18777`, run the configured
workflow:

```bash
sbproxy ai workflow run \
  --origin ai.local \
  --workflow research-flow \
  --input examples/ai-agent-orchestration/input.json
```

The agent response envelope is `{"outcome":"done","output":{"summary":"..."}}`.
The configured `output_schema` validates only the nested `output` object; the
outer `outcome` drives the workflow transition.

Every live CLI command also accepts `--admin-url`, `--username`, and
`--password`; the environment variables keep credentials out of shell history.
The egress policy is deny-by-default and authorizes only the declared loopback
endpoint.

See [Agent orchestration](../../docs/agent-orchestration.md) for the agent wire
contract, limits, and event/metric contract.
