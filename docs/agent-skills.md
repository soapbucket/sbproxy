# Agent Skills v0.2.0

*Last modified: 2026-05-09*

SBproxy serves an Agent Skills v0.2.0 discovery manifest at
`/.well-known/agent-skills/index.json`. Cooperative agents fetch the
manifest to discover the skills the origin advertises, then fetch each
artifact at the URL the manifest pins. Every artifact body is
hashed (SHA-256) at config-load time and re-hashed on every serve.

The schema lives at
`https://schemas.agentskills.io/discovery/0.2.0/schema.json`. The
originating RFC is at
`https://github.com/cloudflare/agent-skills-discovery-rfc`.

## What it does

The Agent Skills projection is a sibling of the four Wave 4
projections (`robots.txt`, `llms.txt`, `licenses.xml`,
`tdmrep.json`). All five are derived from the compiled config snapshot
and refreshed atomically on every config reload.

Each entry in the manifest carries:

- `name` - stable identifier.
- `type` - closed enum, `skill-md` or `archive`.
- `description` - one-line capability summary.
- `url` - relative, path-absolute, or fully-qualified.
- `digest` - `sha256:<lowercase-hex>` of the artifact body.

URLs are resolved per RFC 3986 against the request authority at serve
time, so the manifest's URLs stay portable across hostnames and
schemes.

## Configuration

```yaml
proxy:
  http_bind_port: 8080

origins:
  "test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev

    agent_skills:
      - name: "deploy-via-pr"
        type: skill-md
        description: "Open a PR to deploy a config change."
        url: "/skills/deploy-via-pr.md"
        visibility: public

      - name: "internal-rotate-secret"
        type: skill-md
        description: "Rotate a service credential via vault."
        url: "/skills/internal-rotate-secret.md"
        visibility: authenticated
```

Every field except `name`, `type`, `description`, and `url` is
optional. Skills can declare an inline `body:` literal, an explicit
filesystem `path:`, or rely on the workspace-relative resolution that
the URL implies (the example above resolves
`/skills/deploy-via-pr.md` against the directory `sbproxy serve` was
invoked from).

### Visibility

`public` (the default) returns the entry to every caller.
`authenticated` filters the entry out of the manifest served to
anonymous callers. Callers that present an `Authorization` header
receive the full set.

The serve-time filter walks the manifest fresh on every request, so
an authenticated upgrade does not require a manifest reload. SHA-256
digests are computed once at config-load and pin the artifact body
across all callers.

### Archive entries (`type: archive`)

`archive` entries point at a `.tar.gz` or `.zip` bundle. The proxy
sniffs the magic bytes, validates the bundle once at config-load time,
and serves it as opaque bytes on every request.

The archive parser refuses to load a bundle that:

- traverses outside the archive root via `..` or absolute paths,
- contains a symlink whose target escapes the archive root (or any
  symlink at all in the zip case),
- exceeds the configured decompression ratio (default 100:1),
- exceeds the configured entry count (default 1000), or
- exceeds the configured expanded byte budget (default 10 MiB).

Each cap is configurable per entry:

| Field | Default | Purpose |
|---|---|---|
| `max_decompression_ratio` | 100 | Compressed:expanded ratio cap. |
| `max_entries` | 1000 | Max entries per archive. |
| `max_expanded_bytes` | 10485760 | Max expanded archive bytes. |
| `max_clock_skew_secs` | 60 | Tolerance for time-sensitive headers. |

## Integrity contract

Every artifact `GET` re-hashes the served body and compares to the
manifest digest. On mismatch the proxy:

1. Returns HTTP 503 with a generic "service unavailable" body.
2. Emits a structured `agent_skill.digest_mismatch` audit event with
   `{ skill_name, hostname, expected_digest, observed_digest }`.
3. Increments
   `sbproxy_agent_skill_digest_mismatch_total{skill="<name>"}`.

The runtime check is the contract that lets cooperative agents trust
the digest. Operators who wire an audit sink see the mismatch land on
their existing audit pipeline.

## No script execution

Per the v0.2.0 spec, SBproxy does not execute pre-/post-hooks or any
embedded scripts shipped inside an artifact. Artifacts are served as
opaque bytes. Archives are validated for size and traversal safety at
config-load time but are never extracted to disk during a request, and
the request handler never invokes a subprocess on the artifact body.

## MCP `experimental.agentSkillsUrl` advertising

When the origin's action is an MCP gateway and `agent_skills:` is
configured, the `initialize` JSON-RPC response includes a
`capabilities.experimental.agentSkillsUrl` field pointing at the
manifest. The advertised URL is the absolute URL of the origin's
`/.well-known/agent-skills/index.json`, resolved from the request
`Host` and the proxy's TLS posture.

```json
{
  "protocol_version": "2025-06-18",
  "capabilities": {
    "tools": {},
    "experimental": {
      "agentSkillsUrl": "https://api.example.com/.well-known/agent-skills/index.json"
    }
  },
  "server_info": { "name": "sbproxy-mcp", "version": "1.0" }
}
```

The advertised path is the same regardless of caller identity; the
manifest itself filters by visibility at serve time. When
`agent_skills:` is not configured for the origin, the field is omitted
entirely (no empty advertisement).

## Inspection

```bash
curl -s -H 'Host: api.example.com' \
  http://127.0.0.1:8080/.well-known/agent-skills/index.json | jq

curl -s -H 'Host: api.example.com' -H 'Authorization: Bearer demo' \
  http://127.0.0.1:8080/.well-known/agent-skills/index.json | jq
```

The example bundle at `examples/99-agent-skills/` is runnable with
`sbproxy serve -f sb.yml` and demonstrates the manifest, the
visibility filter, and the digest contract end-to-end.

## See also

- [`mcp.md`](mcp.md) for the broader MCP gateway story.
- [`threat-model.md`](threat-model.md) for the OSS trust boundaries
  that constrain the digest verifier.
- [`features.md`](features.md) for the projection family overview.
