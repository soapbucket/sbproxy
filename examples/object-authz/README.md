# object_authz: BOLA + BFLA enforcement at the gateway

*Last modified: 2026-07-09*

Demonstrates the `object_authz` policy. The gateway enforces a declarative ownership rule: the path segment named by `owner_param` must equal the caller's owner identity, which `principal.owner_from: sub` resolves from the verified JWT `sub` claim. A request for one tenant's data signed with another tenant's token is blocked at the edge. A `function_rules` entry with `require_role: admin` gates `DELETE /admin/users/{user_id}`, and the `enumeration` block flags a principal that touches more than `max_distinct: 100` distinct order ids inside a `window_secs: 60` window.

## Run

```bash
make run CONFIG=examples/object-authz/sb.yml
```

## Mint test tokens

The config validates HS256 JWTs signed with `dev-secret-change-me` (issuer `https://issuer.local`, audience `sbproxy-demo`). Mint the two demo tokens with a far-future `exp`:

```bash
eval "$(python3 - <<'EOF'
import base64, hashlib, hmac, json

secret = b"dev-secret-change-me"

def mint(payload):
    def enc(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")
    head = enc({"alg": "HS256", "typ": "JWT"})
    body = enc(payload)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret, head + b"." + body, hashlib.sha256).digest()).rstrip(b"=")
    return b".".join([head, body, sig]).decode()

claims = {"iss": "https://issuer.local", "aud": "sbproxy-demo", "exp": 4102444800}
print("export JWT_A=" + mint({**claims, "sub": "tenant-A"}))
print("export JWT_ADMIN=" + mint({**claims, "sub": "u-42", "roles": ["admin"]}))
EOF
)"
```

`JWT_A` carries `sub: tenant-A`. `JWT_ADMIN` carries `sub: u-42` plus a `roles: ["admin"]` claim, the role named by the config's `require_role`.

## Try it

The upstream is the shared echo at `test.sbproxy.dev`, which has no `/tenants` or `/admin` routes. A request the gateway allows is forwarded and comes back as the upstream's 404; a request the gateway blocks is a 403 minted by the proxy.

```bash
# Allowed through the gateway: {owner} matches the token's sub.
# 404 comes from the upstream, proving the request was forwarded.
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: api.local' -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-A/orders/42
# 404

# Blocked 403 at the gateway: cross-tenant access (BOLA).
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: api.local' -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-B/orders/42
# 403
```

Function-level enforcement (BFLA):

```bash
# Blocked 403 even though the token's claims include "admin".
curl -s -o /dev/null -w '%{http_code}\n' \
  -X DELETE -H 'Host: api.local' -H "Authorization: Bearer $JWT_ADMIN" \
  http://127.0.0.1:8080/admin/users/u1
# 403
```

The policy never reads roles from JWT claims. Roles come only from the `x-roles` request header, and only when `principal.trust_role_header: true` tells the gateway a trusted upstream sets that header. This config leaves it at the default `false`, so `require_role: admin` fails closed and every `DELETE /admin/users/{user_id}` is denied. That default exists because a direct client could otherwise send `x-roles: admin` and grant itself the role.

Enumeration sweep:

```bash
# More than max_distinct (100) distinct order ids in 60s from one sub.
for i in $(seq 1 150); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.local' -H "Authorization: Bearer $JWT_A" \
    "http://127.0.0.1:8080/tenants/tenant-A/orders/$i"
done
# The first 100 are forwarded (404 from the upstream); once the
# distinct-id count passes max_distinct, the rest return 403 until
# the 60s window drains.
```

See [docs/object-authz.md](../../docs/object-authz.md) for the full schema.
