# Admin API guide

*Last modified: 2026-07-19*

This is the task-oriented "how do I call it" guide to the embedded admin
server: enabling it, authenticating, and a curl cookbook for the routes
operators reach for most. For the exhaustive per-route schema (every
field, every status code), see [admin-api-reference.md](admin-api-reference.md).
For the built-in dashboard that sits on top of this API, see
[admin-ui.md](admin-ui.md). For enabling, TLS, and the security posture,
see [admin.md](admin.md).

## Control plane, not data plane

sbproxy runs two separate listeners:

- The **data plane** (`proxy.http_bind_port`) serves the traffic your
  `origins:` route: proxying, the AI gateway, MCP, everything `sb.yml`
  configures as a handler.
- The **control plane** (`proxy.admin.port`, default `9090`) is a
  second HTTP(S) listener, off by default, that serves *operator*
  traffic: health, metrics, the request log, config read/write,
  reload, key and credential lifecycle, model-host and cluster
  status, and the built-in web UI.

They never share a port. A request to `/admin/keys` on the data-plane
port 404s (or hits whatever origin matches that path); the admin API
only answers on the admin port. This split means you can put the data
plane on a public load balancer and keep the admin port on loopback,
a private network, or behind a bastion, independent of how the data
plane is exposed.

## Enabling it: a complete example

Every admin route in this guide assumes an `admin` block like this
under `proxy` in `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    bind: 127.0.0.1
    username: admin
    password: ${ADMIN_PASSWORD}
    max_log_entries: 1000
    allow_ips: []
    cors_origins: []
    operators:
      - username: oncall
        password: ${ONCALL_PASSWORD}
        role: read_only
      - username: deployer
        password: ${DEPLOYER_PASSWORD}
        role: admin
    tls:
      cert: /etc/sbproxy/admin-cert.pem
      key: /etc/sbproxy/admin-key.pem

origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend:3000
```

Passwords resolve from the environment at config load
(`export ADMIN_PASSWORD=...`); a bare literal also works for local
testing. Drop `tls` to serve plaintext on loopback while developing;
add it back before setting `bind: 0.0.0.0` or listing `allow_ips` for
anything reachable off the local machine. See [admin.md](admin.md#tls)
and [admin.md](admin.md#remote-access-and-cors) for the full field
reference.

With this config running, every example below targets
`http://127.0.0.1:9090` (swap in `https://` and your `bind`/port when
you have TLS and remote access configured):

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090
export SB_ADMIN_PASSWORD='replace-me'
```

## Authenticating: Basic vs. session + CSRF

The admin server accepts two credential shapes on every protected
route:

1. **HTTP Basic**, using the top-level `username`/`password` or an
   `operators[]` entry. This is the right shape for curl, CI, and
   scripts — send it on every request, no state to manage:

   ```bash
   curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/admin/keys"
   ```

2. **A browser session**, for the UI (or any client that would rather
   not resend a password on every call). `POST /admin/login` verifies
   credentials — a Basic header, or a JSON `{"username","password"}`
   body — and responds with:

   - A `Set-Cookie: sb_admin_session=...` header: `HttpOnly`,
     `SameSite=Strict`, `Secure` when TLS is on, good for 8 hours.
   - A JSON body carrying the CSRF token and role:

     ```json
     {"role": "admin", "csrf_token": "3f9c...", "username": "admin"}
     ```

   Because the cookie is `HttpOnly`, JavaScript cannot read it back —
   that is the point, it defeats simple cookie theft via XSS. But it
   also means a state-changing request authenticated by the cookie
   must prove it is the same client that logged in, by echoing the
   CSRF token in an `X-CSRF-Token` header. That is a standard
   double-submit: an attacker who cannot read the `HttpOnly` cookie
   cannot forge the header either.

   ```bash
   # Log in, keep the cookie, capture the CSRF token.
   RESP="$(curl -fsS -c cookies.txt -X POST "${SB_ADMIN_URL}/admin/login" \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"'"${SB_ADMIN_PASSWORD}"'"}')"
   CSRF="$(echo "$RESP" | jq -r .csrf_token)"

   # A mutation via the session must carry the cookie and the header.
   curl -fsS -b cookies.txt -X POST "${SB_ADMIN_URL}/admin/reload" \
     -H "X-CSRF-Token: ${CSRF}"

   # POST /admin/logout revokes the session and clears the cookie.
   curl -fsS -b cookies.txt -X POST "${SB_ADMIN_URL}/admin/logout"
   ```

   `GET /admin/session` reports whether the current request carries a
   valid session (`{"authenticated":true,"username":...,"role":...,
   "csrf_token":...}` or `{"authenticated":false}`), which is how the
   UI recovers its identity and CSRF token after a page reload without
   forcing a fresh login.

Basic-auth requests are **CSRF-exempt** — there is no cookie to forge,
so the header requirement does not apply. `POST /admin/login`,
`POST /admin/logout`, and `GET /admin/session` all run before the
general auth gate, so they work without an existing session (you need
somewhere to call *to get* a session). The signing key for sessions is
random per process: restarting the proxy invalidates every open
session, by design, since this is an admin surface, not a customer
login.

## Roles: `admin` vs. `read_only`

Every operator identity — the top-level `username`/`password`, and
each `operators[]` entry — has a role:

- **`admin`**: every route, read and write.
- **`read_only`**: GET / read routes only. A `read_only` operator that
  attempts a mutation (`POST`, `PUT`, `PATCH`, `DELETE`) gets `403`
  before the mutation runs.

```bash
curl -i -u "oncall:${ONCALL_PASSWORD}" -X POST "${SB_ADMIN_URL}/admin/reload"
# HTTP/1.1 403 Forbidden
# {"error":"forbidden: read-only operator cannot perform this action"}
```

Give day-to-day operators `read_only` and reserve `admin` for accounts
that actually change state. Every mutation that passes the role gate
emits a structured event on the `sbproxy::admin::audit` tracing
target naming the operator, so a shared `admin` account still leaves
an attributable trail per request, but per-operator credentials with
the right role make that trail meaningful. A handful of routes carry
their own stricter or different rule instead of the general split —
compression content inspection is `admin`-only *and* requires handler
opt-in, and cluster enrollment authenticates a one-time token instead
of an operator at all. Those are called out where they apply in
[admin-api-reference.md](admin-api-reference.md).

## Error envelope

Every protected route that fails returns JSON:

```json
{"error": "<reason>"}
```

with a conventional status: `400` bad request, `401` missing/invalid
credentials, `403` insufficient role or bad/missing CSRF, `404`
unknown route or record, `405` wrong method, `409` conflict (a
revision mismatch, an in-flight reload, a terminal record), `429`
rate-limited, `5xx` server-side failure. Some families (keys,
credentials, model-host) add fields alongside `error` — e.g. a
revision conflict on a key returns `expected_revision` and
`current_revision` — see the per-route sections in
[admin-api-reference.md](admin-api-reference.md) for the exact shape.

## Rate limiting

The admin server enforces its own in-process limiter, separate from
any `rate_limits:` block on the data plane: 60 requests/minute per IP
by default, and a global cap ten times that (600/minute). Exceeding
either returns `429` and does not count against the next window. This
protects the admin port itself from a local flood; it is not
configurable via `sb.yml` today.

## Curl cookbook

All of these use the HTTP Basic convention above (`SB_ADMIN_URL`,
`SB_ADMIN_PASSWORD` exported). Swap in a session cookie + CSRF header
if you authenticated via `/admin/login` instead.

**Health.**

```bash
curl -fsS "${SB_ADMIN_URL}/healthz"
# {"status":"ok"}

curl -fsS "${SB_ADMIN_URL}/health" | jq '{status,version,checks}'
```

**Mint a key** (the plaintext token is returned once, on creation —
save it now):

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" -X POST "${SB_ADMIN_URL}/admin/keys" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "checkout-service",
    "max_requests_per_minute": 600,
    "allowed_models": ["gpt-4o-mini", "claude-haiku-4-5"],
    "max_budget_usd": 25.0,
    "tags": ["team:checkout"]
  }' | jq '{token, key: .key.key_id}'
```

**List keys** (never returns secrets):

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/admin/keys" \
  | jq '.keys[] | {key_id, status, name, policy_revision}'
```

**Run a chat completion through the playground** (the same AI client
the data plane uses, bypassing per-origin policy — see
[admin-api-reference.md](admin-api-reference.md#chat-playground)):

```bash
# See what AI origins/models are configured.
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/api/playground/endpoints" | jq

curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" -X POST \
  "${SB_ADMIN_URL}/admin/api/playground/chat" \
  -H 'Content-Type: application/json' \
  -d '{
    "origin": "ai.example.com",
    "request": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "ping"}]}
  }' | jq '{status, model, usage, cost_usd, latency_ms}'
```

**Spend and the recent-request log:**

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/api/usage/spend" | jq

# Windowed + grouped, from the durable rollups (survives restarts):
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/api/usage/spend?window=24h&group_by=model" | jq

curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/api/requests?status=500&limit=20" | jq
```

**Hot reload after editing `sb.yml` out of band:**

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" -X POST "${SB_ADMIN_URL}/admin/reload" | jq
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/admin/drift" | jq '.drift'
```

**Cluster status** (only meaningful with `proxy.cluster` configured;
returns a single-node view otherwise):

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/admin/cluster/status" \
  | jq '{summary, unhealthy_nodes}'
```

## Where to go next

- [admin-api-reference.md](admin-api-reference.md) - every route, every field, every status code.
- [admin-ui.md](admin-ui.md) - the built-in dashboard: build it, enable it, what each page does.
- [admin.md](admin.md) - enabling the server, TLS, roles, and the security checklist.
- [key-management.md](key-management.md) - the full virtual-key policy model.
- [audit-log.md](audit-log.md) - the tamper-evident audit trail for admin mutations.
