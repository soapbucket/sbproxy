# ADR: Agent Dynamic Client Registration

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-agent-class-taxonomy.md`, `adr-agent-registry-feed.md`, `adr-admin-action-audit.md`, and `adr-schema-versioning.md`. Reuses the RFC 7591 (Dynamic Client Registration) shape adapted to the agent-class taxonomy.

## Context

Self-service agent registration: today, an agent is recognisable to SBproxy only if it appears in the static taxonomy or the hosted feed. New vendors and small operators have no path; they either contact the hosted team for inclusion or run as `unknown`. That works for the OpenAI-class crawlers but it does not scale to the long tail of MCP clients, internal automation, or "let our partner register their bot" workflows.

OAuth's RFC 7591 already solves the same shape for client registration: `POST /register`, returns `client_id` and `client_secret`, supports owner approval via the registration access token. The IETF drafted it for OAuth clients but the registration flow is general; the agent-class case is just "an OAuth client that happens to be an automated agent with a published metadata profile."

We adapt RFC 7591, not adopt it whole. Differences:

- The metadata fields are agent-specific (vendor, purpose, expected user-agents, expected reverse-DNS suffixes), not OAuth-specific (`redirect_uris`, `grant_types`).
- Approval is mandatory. The RFC 7591 shape allows immediate registration without approval; we always queue for owner review. Self-service registration without human-in-the-loop is a spam vector and a reputation pollutant.
- Approved agents flow into the agent registry feed. The feed is the publication channel; DCR is the intake.
- Key-of-record rotation reuses the workspace's standard 30-day grace window.

This ADR pins the request / response shapes, the approval queue contract, the key-rotation surface, and the revocation surface. It does not pin the portal UI; portal flows live in the portal repo.

## Decision

Define a self-service registration endpoint at `POST /v1/agents/register`, an owner-approval queue that gates the registry feed, a key-rotation endpoint with a 30-day grace window, and a revocation endpoint. All four operations emit `AdminAuditEvent`s. Approved registrations are signed and added to the registry feed.

### Endpoint surface

| Verb | Path | Auth | Owner of state |
|---|---|---|---|
| Register | `POST /v1/agents/register` | none (open intake; rate-limited) | DCR service |
| List pending | `GET /v1/agents/pending` | portal admin | DCR service |
| Approve | `POST /v1/agents/{agent_id}/approve` | portal admin | DCR service + registry feed publisher |
| Reject | `POST /v1/agents/{agent_id}/reject` | portal admin | DCR service |
| Rotate key | `POST /v1/agents/{agent_id}/keys/rotate` | bearer registration access token | DCR service |
| Revoke | `DELETE /v1/agents/{agent_id}` | portal admin OR registration access token (self-revoke) | DCR service + registry feed publisher |
| Get | `GET /v1/agents/{agent_id}` | bearer registration access token | DCR service |

All endpoints are HTTPS-only; plain HTTP is rejected at config-load time per the `adr-http-ledger-protocol.md` § "Endpoints" precedent.

### Registration request

```http
POST /v1/agents/register HTTP/1.1
Host: agents.sbproxy.dev
Content-Type: application/json

{
  "agent_metadata": {
    "vendor":     "Acme Research Labs",
    "purpose":    "research",
    "contact_url": "https://acme.example.com/bots",
    "expected_user_agents": [
      "AcmeBot/1.0 (+https://acme.example.com/bots)"
    ],
    "expected_reverse_dns_suffixes": [
      ".bots.acme.example.com"
    ],
    "expected_keyids": [
      "ed25519:THUMBPRINT..."
    ],
    "requested_scopes": ["crawl:public", "embed:public"]
  }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `vendor` | string | yes | Display name. Capped at 128 chars. |
| `purpose` | enum | yes | Same closed enum as `adr-agent-class-taxonomy.md`: `training`, `search`, `assistant`, `research`, `archival`, `unknown`. |
| `contact_url` | string, HTTPS | yes | Operator's published abuse / docs URL. The DCR service validates the URL is reachable (HTTP HEAD with 5 s timeout) at registration time; failures are non-blocking but recorded for the approver. |
| `expected_user_agents[]` | array | yes | At least one entry. Plain strings, not regexes. The publisher converts to anchored regexes when adding to the feed. |
| `expected_reverse_dns_suffixes[]` | array | optional | Same shape as the taxonomy; `[]` means "no rDNS check applies". |
| `expected_keyids[]` | array | optional | Web Bot Auth thumbprints in `<alg>:<thumbprint>` format. Empty list means "agent does not sign yet". |
| `requested_scopes[]` | array | yes | Closed set of scopes the agent is asking for. Initial values: `crawl:public`, `crawl:gated`, `embed:public`, `mcp:tools`. New scopes require an ADR amendment. |

Validation (synchronous, before any state mutates):

- `vendor` non-empty, under cap.
- `contact_url` parses, HTTPS, host resolves, HEAD returns < 500 (not blocking; warning recorded if 4xx/5xx but registration proceeds).
- `expected_user_agents[0]` non-empty.
- All `expected_keyids` parse as `<alg>:<base64-thumbprint>`.
- `requested_scopes` are all in the closed set.

### Registration response

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "agent_id":           "acme-acmebot-01HZX...",
  "client_id":          "01HZX...",
  "client_secret":      "sk_agent_one_time_only_value...",
  "registration_access_token": "rat_...",
  "pending_approval":   true,
  "approval_status_url": "https://agents.sbproxy.dev/v1/agents/acme-acmebot-01HZX.../status",
  "created_at":         "2026-05-01T12:00:00Z"
}
```

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | Stable identifier, kebab-case `<vendor-slug>-<bot-name>-<ulid-suffix>`. Vendor slug is `vendor` lowercased and de-spaced (`Acme Research Labs` -> `acme-research-labs`). The ULID suffix prevents collision when two operators register the same vendor name. |
| `client_id` | string (ULID) | OAuth-style identifier. Used as the bearer subject when the agent calls SBproxy. Stable across key rotations. |
| `client_secret` | string | One-time value. The registration response is the ONLY time this is returned in plaintext; subsequent reads return only the metadata. The operator MUST capture and store this securely. Capped at 64 bytes, prefix `sk_agent_`. |
| `registration_access_token` | string | Bearer token for self-service follow-up calls (rotate-key, get, self-revoke). Stable until the agent is revoked. |
| `pending_approval` | bool | Always `true` at creation; flips to `false` after owner approval. |
| `approval_status_url` | string | Polling endpoint the operator can hit for status; returns `{"pending_approval": bool, "approval_state": "pending|approved|rejected"}`. |

The `client_secret` is never persisted in plaintext server-side. We store an Argon2id hash plus a versioned KDF salt; future rotations bump the KDF version. Constant-time comparison on every authentication.

The `agent_id` slug uses ULID suffixes specifically because two operators could register `Acme` simultaneously with the same vendor name; the suffix gives unconditional uniqueness without a name-collision dance.

### Approval flow

Upon successful registration the DCR service:

1. Persists the agent metadata in `dcr_agents` with `approval_state = pending`.
2. Stores `client_secret_hash` and `registration_access_token_hash`.
3. Emits `AdminAuditEvent { action: Create, target: Agent { agent_id }, subject: System { component: "dcr-service" } }`.
4. Returns 201 with the registration response above.

The portal admin sees a list at `GET /v1/agents/pending`. The list includes the metadata, contact-URL reachability result, and a heuristic flag (`auto_review_recommended: bool`) that the DCR service computes from prior approval patterns. The flag is advisory only; the human admin decides.

`POST /v1/agents/{agent_id}/approve`:

1. Updates `dcr_agents.approval_state = approved`.
2. Builds an `AgentClass` record from the metadata.
3. Submits the record to the registry feed publisher with `reputation_score = 50` (neutral starting point) and `flags = ["unverified"]`.
4. Emits `AdminAuditEvent { action: Approve, target: Agent { agent_id }, subject: User { user_id: <admin> } }`.

The next feed refresh (<= 5 minutes) propagates the new entry to subscribers.

`POST /v1/agents/{agent_id}/reject`:

1. Updates `dcr_agents.approval_state = rejected`.
2. Records the rejection reason (free-text from admin, capped at 4 KiB).
3. Emits `AdminAuditEvent { action: Revoke, target: Agent { agent_id }, ... }`. Why `Revoke` and not a `Reject` verb: the AuditAction enum is closed; rejections functionally revoke the pending state. If `Reject` becomes a frequent verb we add it via ADR amendment.

A rejected `agent_id` is not reusable. The DCR service records the rejection so a re-registration with the same `expected_user_agents` from the same source IP is rate-limited.

### Replay protection on registration

To prevent registration spam:

- Per-source-IP rate limit of 5 registrations per hour, 50 per day.
- Per-`vendor` rate limit of 3 pending registrations at a time.
- A SHA-256 hash of the canonicalised `agent_metadata` is stored for 1 hour; a second registration with the same hash within 1 hour returns 429 with `code: "dcr.duplicate_metadata"`.

The duplicate-metadata check is intentionally short-window. An honest operator who messed up their first registration retries within seconds; a spammer wants high throughput. One hour stops the high-throughput case without punishing the honest retry path.

### Key-of-record rotation

`POST /v1/agents/{agent_id}/keys/rotate`:

```http
POST /v1/agents/acme-acmebot-01HZX.../keys/rotate HTTP/1.1
Authorization: Bearer rat_...
```

Returns:

```json
{
  "agent_id":            "acme-acmebot-01HZX...",
  "client_id":           "01HZX...",
  "client_secret":       "sk_agent_new_value...",
  "previous_secret_valid_until": "2026-05-31T12:00:00Z",
  "rotated_at":          "2026-05-01T12:00:00Z"
}
```

The new `client_secret` is returned plaintext (one-time, same as registration). The previous secret stays valid for 30 days; both authenticate. After 30 days the previous secret is purged and authentication with it returns 401.

The 30-day window matches `adr-agent-registry-feed.md` § "Key rotation" and the rest of the workspace. Operators can rotate as often as they want; the window is the *minimum* overlap.

Rotation emits `AdminAuditEvent { action: RotateKey, target: Key { kind: Tenant, key_id: <agent_id> }, subject: Agent { agent_id } }`. The `subject` is the agent itself because the rotation is self-service via the registration access token; an admin-initiated rotation (rare, for compromise response) goes through a separate portal endpoint and the subject is `User`.

Forced rotation on suspected compromise: portal admins can call `POST /v1/agents/{agent_id}/keys/rotate?force=true&reason=<text>`. This skips the 30-day grace; the previous secret invalidates immediately. Subject is `User { user_id }`; the action is still `RotateKey` but the audit event's `reason` field carries the operator's justification. Forced rotation pages on `SLO-AGENT-FORCED-ROTATION` so the security team is aware.

### Revocation

`DELETE /v1/agents/{agent_id}` with `?reason=<text>`:

- Admin caller (bearer admin token): revokes any agent.
- Self caller (bearer registration access token matching the agent): self-revokes.

Effects:

1. `dcr_agents.approval_state = revoked`.
2. The registry feed publisher marks the entry `flags += ["revoked"]` and removes it on the next feed generation. A revoked entry is never re-published.
3. Both `client_secret` and `registration_access_token` invalidate immediately.
4. Emits `AdminAuditEvent { action: Revoke, target: Agent { agent_id }, reason }`.
5. Returns 204.

Subscribers pick up the revocation on their next feed refresh (<= 5 minutes). Until then, the agent's `client_id` still authenticates against the local cache. The revocation is therefore eventually-consistent; for emergency revocations the operator combines `DELETE /v1/agents/...` with a forced feed refresh via the publisher's signal channel.

A revoked `agent_id` does not free up for re-registration. The slug stays burned. Re-registration requires a new metadata submission, which produces a new `agent_id` slug.

### Storage

Postgres-backed:

```sql
CREATE TABLE dcr_agents (
    agent_id           TEXT PRIMARY KEY,
    workspace_id       TEXT NOT NULL,
    vendor             TEXT NOT NULL,
    purpose            TEXT NOT NULL,
    contact_url        TEXT NOT NULL,
    expected_user_agents JSONB NOT NULL,
    expected_reverse_dns_suffixes JSONB NOT NULL,
    expected_keyids    JSONB NOT NULL,
    requested_scopes   JSONB NOT NULL,
    approval_state     TEXT NOT NULL CHECK (approval_state IN ('pending','approved','rejected','revoked')),
    approval_reason    TEXT,
    client_id          TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    previous_client_secret_hash TEXT,
    previous_secret_valid_until TIMESTAMPTZ,
    registration_access_token_hash TEXT NOT NULL,
    metadata_hash      TEXT NOT NULL,  -- SHA-256 for duplicate detection
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at         TIMESTAMPTZ
);

CREATE INDEX dcr_agents_pending     ON dcr_agents (created_at) WHERE approval_state = 'pending';
CREATE INDEX dcr_agents_metadata    ON dcr_agents (metadata_hash, created_at);
CREATE INDEX dcr_agents_workspace   ON dcr_agents (workspace_id);
```

Secrets are stored as Argon2id hashes (memory cost 19 MiB, time cost 2, parallelism 1). The `previous_client_secret_hash` plus `previous_secret_valid_until` columns implement the 30-day grace window without proliferating rows.

Workspace scope: every DCR agent belongs to a workspace. Cross-workspace agent IDs must remain unique (they share a global slug space because they appear in the public registry feed); the workspace ID is recorded for audit and routing.

### Audit emission

Every DCR mutation emits an `AdminAuditEvent` per `adr-admin-action-audit.md`:

| DCR operation | AuditAction | AuditTarget |
|---|---|---|
| Register | Create | Agent { agent_id } |
| Approve | Approve | Agent { agent_id } |
| Reject | Revoke | Agent { agent_id } |
| Rotate key | RotateKey | Key { kind: Tenant, key_id: agent_id } |
| Forced rotate | RotateKey | Key { kind: Tenant, key_id: agent_id } |
| Self-revoke | Revoke | Agent { agent_id } |
| Admin revoke | Revoke | Agent { agent_id } |

The `before` / `after` snapshots carry the `dcr_agents` row state with secret hashes redacted (the redactor profile knows about `*_hash` columns and skips them). The `reason` field carries the human justification on approve / reject / revoke / forced-rotate.

### Schema versioning

Per `adr-schema-versioning.md`, the DCR request and response shapes carry no `schema_version` field because they are HTTP API surface (the API version sits in the `/v1/` path). Internal storage uses Postgres ALTER TABLE rules per the database-migration ADR.

The `requested_scopes` enum and the `purpose` enum are closed; new variants require an ADR amendment and the dual-emit / dual-read window applies. The wire format is forward-compatible with optional fields per Rule 1.

### What this ADR does NOT decide

- The portal UI for the approval queue.
- The reputation-score formula for newly approved agents. Approved agents start at `reputation_score = 50` with `flags = ["unverified"]`; the formula evolves in a future reputation ADR.
- The auto-approve heuristic (when, if ever, the DCR service auto-approves without human review). Initial cut always queues for human review.
- Federation across multiple regions.
- mTLS-based agent authentication (an alternative to `client_secret`); initial cut ships bearer-secret only.

## Consequences

- One self-service path for new agents to enter the registry. Long-tail vendors no longer need to email a hosted team to be visible.
- Owner approval is mandatory. We do not ship an open self-service flow that pollutes the global feed.
- The 30-day key-rotation window matches every other key in the workspace. Operators learn one rotation pattern.
- Revocation is eventually consistent on subscribers (worst case 5 minutes). Emergency revocations combine the DELETE with a forced feed refresh.
- The registration response's one-time `client_secret` is the standard OAuth pattern; operators who already integrated with OAuth recognise it.
- Self-revoke gives well-behaved operators a clean exit when they retire a bot. Admin-revoke gives the operator a hammer for abuse.
- Closed enums (`purpose`, `requested_scopes`) keep the protocol surface clean. Adding a new scope is an ADR amendment, not a silent extension.
- The slug-burn-on-rejection policy stops the spam path of "submit, get rejected, resubmit slightly modified" without explicitly banning a vendor.

## Alternatives considered

**Pure RFC 7591 with no agent-specific metadata.** Rejected. The agent fields (vendor, purpose, expected user-agents, expected reverse-DNS suffixes, expected keyids) are core to the agent registry feed; without them, the feed cannot do its job. Bolting them on as RFC 7591 extensions would put us in the same place semantically, with more ceremony.

**Auto-approve with a delay (e.g. "approved unless rejected within 24h").** Rejected. The default-allow path turns spam into a velocity game. Default-deny with explicit human review is operationally simpler and produces a higher-quality feed.

**No registration access token; require admin auth for every follow-up call.** Rejected. The whole point of the RFC 7591 access token is self-service rotation and revocation. Admin auth on every call is an operational burden.

**Allow re-registration of a rejected slug after a cooling-off period.** Considered. Rejected because the cooling-off period is a parameter we will tune forever; "burned slug" is a deterministic rule operators can reason about. Honest operators who get rejected by mistake email support and a human un-rejects; spammers eat the cost.

**Web Bot Auth-based authentication instead of `client_secret`.** Considered. Web Bot Auth (signature-based) is the long-term vision. Rejected for the initial cut because the agent has to bootstrap with *something*, and a `client_secret` is the lowest-friction starting point. The DCR endpoint accepts `expected_keyids` so an agent that already has Web Bot Auth keys advertises them at registration; the resolver prefers the signature path when present.

## References

- RFC 7591: Dynamic Client Registration. <https://datatracker.ietf.org/doc/html/rfc7591>.
- `adr-agent-class-taxonomy.md`: the schema this ADR's metadata maps to.
- `adr-agent-registry-feed.md`: the publication channel for approved agents.
- `adr-admin-action-audit.md`: the audit envelope.
- `adr-schema-versioning.md`: the dual-emit / dual-read window and breaking-change checklist.
- Argon2id parameters: OWASP Password Storage Cheat Sheet.
- ULID spec: <https://github.com/ulid/spec>.
