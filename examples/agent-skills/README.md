# Agent Skills v0.2.0
*Last modified: 2026-05-09*

Demonstrates the Agent Skills v0.2.0 well-known projection. SBproxy
serves a discovery manifest at
`/.well-known/agent-skills/index.json` and re-hosts the skill bodies
the manifest pins. Every body is hashed (SHA-256) at config-load time
and re-hashed on every serve; tampered bodies return 503 with a
structured audit event.

References:

- Schema: `https://schemas.agentskills.io/discovery/0.2.0/schema.json`
- RFC: `https://github.com/cloudflare/agent-skills-discovery-rfc`

## How it composes

| Service | Role |
|---|---|
| sbproxy | Serves the manifest plus the skill bodies. No upstream needed. |

## How to run

```bash
cd examples/agent-skills
sbproxy serve -f sb.yml
```

## What to expect

### 1. Anonymous manifest

```bash
curl -s -H 'Host: test.sbproxy.dev' \
  http://127.0.0.1:8080/.well-known/agent-skills/index.json | jq
```

```json
{
  "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
  "entries": [
    {
      "name": "deploy-via-pr",
      "type": "skill-md",
      "description": "Open a pull request to deploy a config change.",
      "url": "https://test.sbproxy.dev/skills/deploy-via-pr.md",
      "digest": "sha256:..."
    }
  ]
}
```

The `internal-rotate-secret` entry is filtered out because it carries
`visibility: authenticated`.

### 2. Authenticated manifest

```bash
curl -s -H 'Host: test.sbproxy.dev' -H 'Authorization: Bearer demo' \
  http://127.0.0.1:8080/.well-known/agent-skills/index.json | jq
```

The same call with an `Authorization` header includes the
`internal-rotate-secret` entry.

### 3. Skill body

```bash
curl -s -H 'Host: test.sbproxy.dev' \
  http://127.0.0.1:8080/skills/deploy-via-pr.md
```

The body is served verbatim with `Content-Type: text/markdown;
charset=utf-8`. The proxy re-hashes the body on every serve and
ships HTTP 503 if the digest does not match the manifest entry, plus
an `agent_skill.digest_mismatch` audit event for the operator.

### 4. MCP advertising

When the origin's action is an MCP gateway and the origin has
`agent_skills:` configured, the `initialize` JSON-RPC response
includes a `capabilities.experimental.agentSkillsUrl` field pointing
at the manifest. MCP clients that have learned to fetch the manifest
discover skills without out-of-band configuration.

## Integrity and safety contract

- SHA-256 digest on every entry (mandatory in v0.2.0).
- Runtime digest verification on every artifact GET.
- Archive entries (`type: archive`) are sniffed for tar.gz or zip
  format, then validated for path traversal, external symlinks,
  decompression ratio, entry count, and expanded-size budget.
- The proxy never executes any pre-/post-hooks or scripts shipped
  inside an artifact. Artifacts are opaque bytes per spec.

## Configuration knobs

Every safety cap is configurable per entry:

| Field | Default | Purpose |
|---|---|---|
| `max_decompression_ratio` | 100 | Max compressed:expanded ratio. |
| `max_entries` | 1000 | Max entries per archive. |
| `max_expanded_bytes` | 10485760 | Max expanded archive bytes. |
| `max_clock_skew_secs` | 60 | Tolerance for time-sensitive headers. |
