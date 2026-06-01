# object_authz: BOLA + BFLA enforcement at the gateway

*Last modified: 2026-05-31*

Demonstrates the `object_authz` policy. The gateway enforces a declarative ownership rule (`{owner}` path segment must equal the JWT `sub`) so a request for one tenant's data signed with another tenant's token is blocked at the edge. It also gates `DELETE /admin/users/{id}` on the `admin` role, and detects enumeration when a single principal scans many distinct order ids inside a 60s window.

## Run

```bash
make run CONFIG=examples/object-authz/sb.yml
```

## Try it

With `JWT_A` carrying `sub: tenant-A`:

```bash
# Allowed: own tenant.
curl -H 'Host: api.example.com' -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-A/orders/42

# Blocked 403: cross-tenant access (BOLA).
curl -H 'Host: api.example.com' -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-B/orders/42
```

With `JWT_USER` carrying `sub: u-42` and no `admin` role:

```bash
# Blocked 403: function-level (BFLA).
curl -X DELETE -H 'Host: api.example.com' -H "Authorization: Bearer $JWT_USER" \
  http://127.0.0.1:8080/admin/users/u1
```

Enumeration sweep:

```bash
# 100+ distinct order ids in 60s from JWT_A.
for i in $(seq 1 150); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.example.com' -H "Authorization: Bearer $JWT_A" \
    "http://127.0.0.1:8080/tenants/tenant-A/orders/$i"
done
# First 100 return 200; remaining return 403 until the window closes.
```

See [docs/object-authz.md](../../docs/object-authz.md) for the full schema.
