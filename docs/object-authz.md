# object_authz policy
*Last modified: 2026-07-09*

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
* `header`: a request header (`principal.owner_header`, default `x-owner-id`). Only trustworthy when a trusted upstream auth layer sets it; the client must not be able to spoof it. Pair with `proxy.trusted_proxies` so external traffic cannot inject the header.

Roles for `function_rules` come from the auth result. Reading them from a header (`principal.role_header`, default `x-roles`) requires the explicit `principal.trust_role_header: true` opt-in, because a direct client could otherwise send `x-roles: admin` and satisfy any role rule.

### When the rule fires

For an `object_rule`, the policy parses the matched path against the template, extracts the `owner_param` segment, and compares it byte-for-byte to the owner identity. Mismatch returns a fixed, intentionally generic 403; the OWASP tag and detailed reason go to the security audit log, not the client. Set `test_mode: true` to report violations (metric + audit) while still allowing the request through, mirroring the WAF switch.

For a `function_rule`, the policy checks the request's `method` is in the rule's set and the caller's roles include `require_role`. A missing role is the same fixed 403 (or an allow under `test_mode`).

For `enumeration`, the policy keeps a per-principal sliding window of distinct object ids (the `object_param` captures). When `max_distinct` is exceeded inside `window_secs`, every subsequent request from that principal is blocked for the rest of the window. The tracker is bounded at 50,000 principals; a flood that exceeds the cap clears the map (brief detection gap, not a correctness problem).

## Observability

* `sbproxy_object_authz_violations_total{origin, kind}` increments on every violation, with `kind` one of `bola`, `bfla`, or `enumeration`. This is the metric to alert on.
* `sbproxy_policy_triggers_total{origin, policy_type="object_authz", action="deny", agent_id, agent_class}` increments on the shared policy-deny path.
* Each violation also emits a structured security-audit event carrying the OWASP tag, the detailed reason, the origin, the client IP, and the request ID; the client-facing 403 stays generic so probing traffic learns nothing.

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/object-authz/](../examples/object-authz/) - runnable BOLA + BFLA + enumeration fixture.
* [configuration.md](./configuration.md) - the full schema.
