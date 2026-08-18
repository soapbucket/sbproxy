# object_authz policy
*Last modified: 2026-08-18*

The `object_authz` policy enforces object- and function-level authorization at the gateway, catching the two top OWASP API risks: BOLA (API1:2023, Broken Object Level Authorization) and BFLA (API5:2023, Broken Function Level Authorization). Alias: `bola`.

The gateway cannot know who owns an arbitrary backend object, so it enforces a declarative ownership rule: a named path segment (for example `{owner}` in `/tenants/{owner}/orders/{order_id}`) must equal the caller's verified identity. A mismatch is a cross-tenant access and is blocked. On top of that the policy detects object-id enumeration: one principal touching many distinct ids inside a short window (sequential id scanning), the signature of a BOLA fuzzing sweep.

## Config

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    authentication:
      type: jwt
      secret: dev-secret-change-me
      issuer: https://idp.example.com
      audience: api.example.com
      algorithms: [HS256]
    policies:
      - type: object_authz
        # Owner identity comes from the verified JWT subject (the
        # secure default; `owner_from: header` needs a trusted
        # upstream auth layer).
        principal:
          owner_from: sub
        # Tenant-isolation rule: the {owner} segment in the path MUST
        # equal the caller's verified identity.
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
            object_param: order_id
        # Function-isolation rule: DELETE or PUT on this path requires
        # the `admin` role.
        function_rules:
          - path: /admin/users/{user_id}
            methods: [DELETE, PUT]
            require_role: admin
        # Enumeration detection: more than 100 distinct object ids
        # from one principal inside 60s trips the anomaly.
        enumeration:
          enabled: true
          window_secs: 60
          max_distinct: 100
```

### Owner source

`principal.owner_from` picks where the policy reads the caller's identity:

* `sub` (default, recommended): the verified auth subject from `ctx.auth_result`. Safe by default.
* `header`: a request header (`principal.owner_header`, default `x-owner-id`).

> **`owner_from: header` is an authorization bypass without a header-stripping ingress.**
>
> The whole point of a BOLA rule is that the caller cannot choose the owner it is compared against. Under `owner_from: header` the caller chooses it: whatever arrives in `x-owner-id` becomes the owner identity, so any client that can open a connection to the proxy can send `x-owner-id: victim` and read every one of that tenant's objects. The rule still runs, still logs, still reports clean. It enforces nothing.
>
> This is only safe when something in front of the proxy overwrites or deletes the header on every inbound request, with no path around it: an auth proxy, an ingress controller, or a service mesh sidecar that owns the listener. "The clients we know about do not send it" is not that. If you cannot point at the component doing the stripping, use `owner_from: sub`.
>
> Config compilation warns once per origin when it sees this setting, naming the origin and the header. The warning is not a substitute for checking; nothing at config time can see whether your ingress strips anything.

Roles for `function_rules` come from the auth result. Reading them from a header (`principal.role_header`, default `x-roles`) requires the explicit `principal.trust_role_header: true` opt-in, because a direct client could otherwise send `x-roles: admin` and satisfy any role rule.

Pair either header source with `proxy.trusted_proxies` so the proxy knows which peers are the ingress.

### When the rule fires

For an `object_rule`, the policy parses the matched path against the template, extracts the `owner_param` segment, and compares it byte-for-byte to the owner identity. Mismatch returns a fixed, intentionally generic 403; the OWASP tag and detailed reason go to the security audit log, not the client. Set `test_mode: true` to report violations (metric + audit) while still allowing the request through, mirroring the WAF switch.

For a `function_rule`, the policy checks the request's `method` is in the rule's set and the caller's roles include `require_role`. A missing role is the same fixed 403 (or an allow under `test_mode`).

For `enumeration`, the policy keeps a per-principal counter of distinct object ids, reset at `window_secs` boundaries (a tumbling window: bounded, constant work per request, rather than a continuously sliding one that would grow with traffic). Its object-id source depends entirely on `object_rules`, and the two never mix on one origin:

* **Rules configured.** Only a matched rule's `object_param` capture counts. A request that matches no rule counts nothing, even if some other rule exists for a different path -- the rules define the scope.
* **No rules configured at all.** `enumeration.enabled` on its own falls back to a heuristic: a request whose *trailing* path segment is numeric or a canonical UUID has its whole path counted as one object (`/orders/1/items/1` and `/orders/2/items/1` are different objects; `/tenants/42/orders` does not count, because its last segment, `orders`, is not id-shaped). This fallback requires an identified caller -- an unattributed request is never counted, because collapsing every anonymous client into one bucket would make N innocent callers look like one attacker and let a real attacker hide in the noise -- and a trip it reports is audit-only: it is logged and counted on `sbproxy_object_authz_violations_total` (with `enforced="false"`) but never blocks, regardless of `test_mode`, because a path-shape guess is not a declared rule and both the id boundary and the caller-to-id mapping can be wrong (a paginated report path or a map-tile fetcher can look identical to a sweep). Because the request is allowed through, nothing throttles a tripped client either, so the audit feed applies its own backpressure: a tripped detect-only principal is audited once per window, and repeat hits are counted and reported on the next audited violation rather than each minting a record.

Enumeration budgets are scoped per tenant: the tracker is keyed by `(tenant, principal)`, so two tenants whose principals share an id string never share a window, and one tenant's sweep cannot trip another tenant's caller. Single-tenant traffic uses the `__default__` tenant label it reports everywhere else.

When `max_distinct` is exceeded inside `window_secs`, every subsequent request from that principal is blocked for the rest of the window (rule-scoped hits only; a heuristic hit never blocks, as above). The tracker is bounded at 50,000 live principals. When the map is full and a new principal arrives, entries whose window has already expired are swept first, so the cap counts genuinely live windows; only when every slot is live does the new principal go untracked (its requests are not counted, each refusal increments `sbproxy_object_authz_enumeration_tracker_saturated_total`, and a warning logs once per window for as long as refusals continue). An existing principal's own state is never affected by another principal's flood.

## Calling it

The runnable configuration is
[`examples/object-authz/`](../examples/object-authz/). It validates HS256 JWTs
signed with `dev-secret-change-me` (issuer `https://issuer.local`, audience
`sbproxy-demo`), resolves the owner from `sub`, gates
`DELETE /admin/users/{user_id}` behind `require_role: admin`, and sets
`enumeration` to `max_distinct: 100` over `window_secs: 60`. Start it:

```bash
make run CONFIG=examples/object-authz/sb.yml
```

Mint a token whose `sub` is `tenant-A`, using the script in that example's
README, then read the results against the upstream. The upstream is a shared
echo with no `/tenants` route, so a `404` means the gateway forwarded the
request and a `403` means the gateway stopped it. That distinction is what
makes the outcomes legible without a real backend:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' \
  -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-A/orders/42
# 404, forwarded: the path's owner segment matches the token's sub

curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' \
  -H "Authorization: Bearer $JWT_A" \
  http://127.0.0.1:8080/tenants/tenant-B/orders/42
# 403, blocked at the gateway: BOLA
```

Only the tenant segment changed. The 403 body is deliberately uninformative:

```json
{"error":"forbidden: object-level authorization check failed"}
```

It names neither the expected owner nor the rule that fired, so probing
traffic cannot map the ownership model. The OWASP tag and the detailed reason
go to the security audit log instead.

A request with no token at all is a `401` rather than a `403`, because auth
runs before this policy and there is no subject to compare against yet.

The function-level rule is the one that surprises people:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE -H 'Host: api.local' \
  -H "Authorization: Bearer $JWT_ADMIN" \
  http://127.0.0.1:8080/admin/users/u1
# 403
```

That token carries `roles: ["admin"]` and is still refused. The policy never
reads roles from JWT claims. Roles come only from the `x-roles` header, and
only when `principal.trust_role_header: true` says a trusted upstream sets it.
This config leaves the default `false`, so `require_role: admin` fails closed
and every such `DELETE` is denied. If you are wiring this up and every
role-gated route returns 403, that default is why.

Enumeration is a per-principal counter over distinct captures of
`object_param`, not a request-rate limit. Walk 150 distinct order ids inside
one window:

```bash
for i in $(seq 1 150); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' \
    -H "Authorization: Bearer $JWT_A" \
    "http://127.0.0.1:8080/tenants/tenant-A/orders/$i"
done
```

The first 100 are forwarded and answer `404`. The 101st is the first `403`,
and every request from that principal stays blocked for the rest of the
60-second window even for ids it already fetched successfully. Re-requesting
the same id repeatedly never trips it, because only distinct ids count.

## Observability

* `sbproxy_object_authz_violations_total{origin, kind, enforced}` increments on every violation, with `kind` one of `bola`, `bfla`, or `enumeration`. `enforced="true"` means the request was refused; `enforced="false"` means it was reported but allowed through (`test_mode`, or a detect-only hit from the ruleless heuristic). Alert on `enforced="true"`; watch `enforced="false"` as the audit-only signal, since it moves for requests that were served normally.
* `sbproxy_object_authz_enumeration_tracker_saturated_total` increments for every enumeration observation that went untracked because the per-principal tracker was at capacity with live windows. If this moves, enumeration detection is skipping new principals; the once-per-window warning in the log names the cap.
* `sbproxy_policy_triggers_total{origin, policy_type="object_authz", action="deny", agent_id, agent_class}` increments on the shared policy-deny path.
* Each violation also emits a structured security-audit event carrying the OWASP tag, the detailed reason, the origin, the client IP, and the request ID; the client-facing 403 stays generic so probing traffic learns nothing. The record's `status_code` carries the real disposition: `403` only when the request was refused, `200` when a `test_mode` or detect-only violation was allowed through, so a SIEM rule on `status_code: 403` matches only actual refusals. Detect-only enumeration records are additionally emitted at most once per principal per window, with suppressed repeats counted in the next record's reason.

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/object-authz/](../examples/object-authz/) - runnable BOLA + BFLA + enumeration fixture.
* [configuration.md](./configuration.md) - the full schema.
