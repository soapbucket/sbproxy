# object_authz policy
*Last modified: 2026-05-31*

The `object_authz` policy enforces object- and function-level authorization at the gateway, catching the two top OWASP API risks: BOLA (API1:2023, Broken Object Level Authorization) and BFLA (API5:2023, Broken Function Level Authorization). Alias: `bola`.

The gateway cannot know who owns an arbitrary backend object, so it enforces a declarative ownership rule: a named path segment (for example `{owner}` in `/tenants/{owner}/orders/{order_id}`) must equal the caller's verified identity. A mismatch is a cross-tenant access and is blocked. On top of that the policy detects object-id enumeration: one principal touching many distinct ids inside a short window (sequential id scanning), the signature of a BOLA fuzzing sweep.

## Config

```yaml
origins:
  "api.example.com":
    upstream: https://backend.internal
    auth:
      type: jwt
      issuer: https://idp.example.com
      audience: api.example.com
    policies:
      - type: object_authz
        # Tenant-isolation rule: the {owner} segment in the path MUST
        # equal the JWT's `sub` claim.
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_segment: owner
            owner_source: sub
        # Function-isolation rule: DELETE on this path requires the
        # `admin` role.
        function_rules:
          - path: /admin/users/{user_id}
            methods: [DELETE, PUT]
            required_role: admin
        # Enumeration detection.
        enumeration:
          enabled: true
          window_secs: 60
          # If one principal hits more than 100 distinct object ids in
          # 60s, treat it as enumeration.
          distinct_ids_threshold: 100
```

### Owner source

`owner_source` picks where the policy reads the caller's identity:

* `sub` (default, recommended): the verified auth subject from `ctx.auth_result`. Safe by default.
* `header`: a request header. Only trustworthy when a trusted upstream auth layer sets it; the client must not be able to spoof it. Pair with `proxy.trusted_proxies` so external traffic cannot inject the header.

### When the rule fires

For an `object_rule`, the policy parses the matched path against the template, extracts the named segment, and compares it byte-for-byte to the owner identity. Mismatch returns the configured deny status (default 403) with an `error_class: bola_blocked` access-log tag.

For a `function_rule`, the policy checks the request's `method` is in the rule's set and the caller's roles include `required_role`. Missing role returns 403 with `error_class: bfla_blocked`.

For `enumeration`, the policy keeps a per-principal sliding window of distinct object ids. When `distinct_ids_threshold` is exceeded inside `window_secs`, every subsequent request from that principal is blocked for the rest of the window. The tracker is bounded at 50,000 principals; a flood that exceeds the cap clears the map (brief detection gap, not a correctness problem).

## Observability

* `sbproxy_policy_triggers_total{origin, policy_type="object_authz", action="block"}` increments on every block.
* Access log: `error_class` set to `bola_blocked`, `bfla_blocked`, or `enumeration_blocked` per the trigger.
* When the rule fires, the access log includes `policy_action` so dashboards can split by which rule type triggered.

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/object-authz/](../examples/object-authz/) - runnable BOLA + BFLA + enumeration fixture.
* [configuration.md](./configuration.md) - the full schema.
