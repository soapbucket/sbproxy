# OAuth 2.0 token introspection (RFC 7662)

*Last modified: 2026-08-27*

Validate a bearer token by asking the authorization server that issued
it. The caller presents an ordinary `Authorization: Bearer <token>`;
the proxy POSTs that token to the introspection endpoint,
authenticating itself with its own client credentials, and reads back
whether the token is still active and what it is scoped for.

Two reasons to reach for this over [`jwt`](../auth-jwt/):

- **The token is opaque.** Reference tokens (what Okta, Keycloak, and
  Auth0 hand out when a client does not ask for a JWT) carry no claims
  at all. Introspection is the only way to learn anything about them.
- **Revocation has to take effect now.** A JWT stays valid until it
  expires, whatever the issuer has since decided. Introspection asks on
  every request the cache cannot answer, so a revoked token stops
  working within `cache_ttl` rather than at its `exp`.

The price is a network round trip on the request path.

## You need an introspection endpoint

The shipped config points at `http://127.0.0.1:9003/introspect`.
Without something listening there, every request answers `503`, which
is what RFC 7662 section 2.3 asks a resource server to do when it
cannot introspect.

A stub with three tokens:

```bash
cat > /tmp/introspect.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import json, time

TOKENS = {
    "live-token-with-read": {"active": True, "sub": "svc-reports",
                             "scope": "api.read api.write",
                             "exp": int(time.time()) + 300},
    "live-token-no-scope": {"active": True, "sub": "svc-metrics",
                            "scope": "api.write",
                            "exp": int(time.time()) + 300},
    "revoked-token": {"active": False},
}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        form = parse_qs(self.rfile.read(int(self.headers["content-length"])).decode())
        token = form.get("token", [""])[0]
        body = json.dumps(TOKENS.get(token, {"active": False})).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 9003), Handler).serve_forever()
EOF
python3 /tmp/introspect.py &
```

## Run

```bash
make run CONFIG=examples/auth-oauth-introspection/sb.yml
```

## Try it

Active, and it carries `api.read`. The response's `sub` becomes the
request's principal, so the access log attributes the request to
`svc-reports`:

```bash
curl -i -H 'Host: introspect.local' \
     -H 'Authorization: Bearer live-token-with-read' \
     http://127.0.0.1:8080/get
# HTTP/1.1 200 OK
```

Active, but scoped only for `api.write`. RFC 6750 section 3.1 names the
scope in the challenge, so the client can tell what it is missing:

```bash
curl -i -H 'Host: introspect.local' \
     -H 'Authorization: Bearer live-token-no-scope' \
     http://127.0.0.1:8080/get
# HTTP/1.1 403 Forbidden
# www-authenticate: Bearer error="insufficient_scope", scope="api.read"
```

The authorization server says the token is not active:

```bash
curl -i -H 'Host: introspect.local' \
     -H 'Authorization: Bearer revoked-token' \
     http://127.0.0.1:8080/get
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer error="invalid_token"
```

No token at all gets a bare challenge instead, which is the difference
between "go get a credential" and "the one you have is no good":

```bash
curl -i -H 'Host: introspect.local' http://127.0.0.1:8080/get
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer
```

## The cache, and what it will not do

Watch `sbproxy_oauth_introspection_results_total{result}` while you
replay the first request. The first call records `active`; every call
inside `cache_ttl` records `cached` and never leaves the proxy.

Three properties are worth knowing before you raise `cache_ttl`:

- **It shortens a token's life, never lengthens it.** When the
  introspection response carries `exp`, the entry expires at whichever
  of `exp` and `cache_ttl` comes first, so a token with 30 seconds left
  is not accepted for the full minute the default allows.
- **A failure is never cached.** An unreachable authorization server
  refuses the request, and refuses the next one by asking again rather
  than by replaying the refusal, so an outage does not pin anything in
  place after the server recovers.
- **It is bounded at 10,000 tokens.** A flood of invented tokens evicts
  itself rather than growing the map for the life of the process.

Set `cache_ttl: 0` when a revocation has to take effect on the very next
request. Every request then costs a round trip.

## Watching it

`sbproxy_oauth_introspection_results_total{result}` counts `active`,
`inactive`, `insufficient_scope`, `cached`, and `unavailable`. The
"Token Introspection Results" panel on the `SBProxy Security`
dashboard draws all five; the ratio of `cached` to everything else is
what `cache_ttl` is buying you, and a rising `unavailable` is an
authorization server the gateway cannot reach.

## See also

- [docs/authentication.md](../../docs/authentication.md) - which provider fits which caller.
- [docs/configuration.md](../../docs/configuration.md#oauth_introspection) - the field table.
- [examples/auth-jwt/](../auth-jwt/) - local verification, no round trip.
