# External authorization (ext_authz)

*Last modified: 2026-08-27*

Hand the admission decision to a service you run. For every request,
the proxy POSTs a check document carrying the method, the path and
query, and the request headers you allowlisted; the service answers
`{"allowed": true}` or a refusal it shapes itself. The wire shape is
Envoy's `ext_authz` HTTP service filter, so a service already written
for Envoy or for the OpenPolicyAgent Envoy plugin answers this
provider unchanged.

Reach for this rather than [`forward_auth`](../auth-forward/) when the
decision is authorization rather than authentication: an entitlement
lookup, a per-tenant quota, a policy engine the gateway does not host.
The service picks the refusal status and body, which is what lets a
quota answer `402` and a scope failure answer `403`, and this provider
composes inside an `authentication:` list and runs on HTTP/3, neither
of which `forward_auth` can do.

## You need an authorization service

The shipped config points at `http://127.0.0.1:9002/check`. Without
something listening there, every request answers `503`: the fail-closed
default refusing rather than admitting.

A stub that admits `acme` and bills `over-quota`:

```bash
cat > /tmp/authz.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        check = json.loads(self.rfile.read(int(self.headers["content-length"])))
        tenant = check.get("headers", {}).get("x-tenant", "")
        if tenant == "over-quota":
            answer = {"allowed": False, "status": 402,
                      "body": "quota exhausted",
                      "headers": {"x-quota-reset": "3600"}}
        elif tenant:
            answer = {"allowed": True, "subject": tenant}
        else:
            answer = {"allowed": False, "status": 403, "body": "no tenant"}
        body = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 9002), Handler).serve_forever()
EOF
python3 /tmp/authz.py &
```

## Run

```bash
make run CONFIG=examples/auth-ext-authz/sb.yml
```

## Try it

The service allows the request and names the caller, so `acme` becomes
the request's principal and shows up in the access log's
`principal_kind` column as `ext_authz`:

```bash
curl -i -H 'Host: authz.local' -H 'X-Tenant: acme' http://127.0.0.1:8080/get
# HTTP/1.1 200 OK
```

The service refuses, and its own status, body, and headers are what the
client sees. Nothing in the proxy's config named `402`:

```bash
curl -i -H 'Host: authz.local' -H 'X-Tenant: over-quota' http://127.0.0.1:8080/get
# HTTP/1.1 402 Payment Required
# x-quota-reset: 3600
#
# quota exhausted
```

Stop the stub service and try again. The request is refused rather than
admitted, because `failure_mode_allow` is false:

```bash
curl -i -H 'Host: authz.local' -H 'X-Tenant: acme' http://127.0.0.1:8080/get
# HTTP/1.1 503 Service Unavailable
```

## What the check document carries

Only what you allowlisted. With the shipped `headers_to_forward`, a
request carrying an `Authorization` header, a `Cookie`, and
`X-Tenant: acme` produces:

```json
{"method": "GET", "path": "/get", "headers": {"x-tenant": "acme"}}
```

The `Cookie` is absent because nothing named it. So is `Authorization`,
in this rendering, only because the request in the examples above does
not carry one; the shipped config does allowlist it. That default is
deliberate: a provider that forwarded every header would ship the
caller's credentials and session cookie to the authorization service on
the first request after an operator set the URL.

## Watching it

`sbproxy_ext_authz_decisions_total{outcome}` counts every callout by
what came back: `allow`, `deny`, `unavailable`, and `fail_open`. The
last of those is the one to alert on. It counts requests the proxy
admitted *without* the authorization service deciding anything, which
only happens when the callout failed and `failure_mode_allow: true` is
set, and folding it into the allow count would hide exactly the event
worth paging for. The "External Authorization Outcomes" panel on the
`SBProxy Security` dashboard draws all four.

Every allow and deny also publishes an `auth` decision record on the
SIEM feed and increments
`sbproxy_auth_results_total{auth_type="ext_authz"}`, which is where the
per-origin breakdown lives.

## See also

- [docs/authentication.md](../../docs/authentication.md) - which provider fits which caller.
- [docs/configuration.md](../../docs/configuration.md#ext_authz) - the field table.
- [examples/auth-forward/](../auth-forward/) - the status-code-only alternative.
