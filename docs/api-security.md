# API security

*Last modified: 2026-08-17*

Most API breaches are not clever. They are an endpoint that forgot to check who
was asking, a limit nobody set, or a field that was never supposed to be
writable. A gateway is a good place to fix that class of problem, because it
sits in front of every route whether or not the service behind it remembered.

This page covers the API threat classes SBproxy can act on, the configuration
for each, and the parts that stay with the service. For MCP and agent traffic,
see [mcp-security.md](mcp-security.md). For the whole picture, start at
[security.md](security.md).

The public reference here is the OWASP API Security Top 10:
[owasp.org/API-Security](https://owasp.org/API-Security/). The sections below
solve the same problems in configuration terms.

## Object access that trusts the caller's ID

The oldest and most common API flaw: `GET /orders/1042` returns order 1042 to
whoever asks, because the handler checked that you are logged in and not that
the order is yours.

SBproxy enforces object-level authorization at the edge, so the check exists
even when the handler forgot.

<!-- sbproxy-config-excerpt -->
```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: "https://backend.internal"
    policies:
      - type: bola
        principal:
          owner_from: sub
        object_rules:
          - path: /tenants/{owner}/orders/{order_id}
            owner_param: owner
            object_param: order_id
        function_rules:
          - path: /admin/users/{user_id}
            methods: [DELETE, PUT]
            require_role: admin
        enumeration:
          enabled: true
          window_secs: 60
          max_distinct: 100
```

`owner_from: sub` reads the caller's identity from the verified auth subject
rather than from anything the request supplied, which is the safe default. The
enumeration block is the other half: it trips when one principal touches more
distinct object ids than a real user would, which is what scraping looks like
when every individual request is authorized. It does not need `object_rules`
to work: without a rule to capture the object id explicitly, the detector
falls back to the last numeric- or UUID-shaped path segment, so `enumeration:
{ enabled: true }` on its own catches a BOLA sweep against a bare
`/orders/{id}`-shaped API with no ownership rule declared.

See [object-authz.md](object-authz.md) for the full matcher surface, including
tenant claims and collection endpoints, and
[`examples/object-authz/`](../examples/object-authz/) for a complete working
config.

**Still yours.** The gateway compares an identifier in the request against a
claim in the token. It cannot know that order 1042 belongs to user 7 unless
that relationship is expressed somewhere it can see. For deep object graphs the
service remains the authority.

## Authentication that is weaker than it looks

Bearer tokens with no audience check, JWTs validated against the wrong issuer,
a session cookie that survives logout. Each is ordinary and each is enough.

SBproxy ships auth providers rather than an auth framework, so the choice is
which one to attach:

<!-- sbproxy-config-excerpt -->
```yaml
    auth:
      type: jwt
      jwks_url: "https://issuer.example/.well-known/jwks.json"
      issuer: "https://issuer.example"
      audience: "api.example.com"
```

`oidc` runs a full relying-party login with authorization code and PKCE and a
sealed session cookie ([auth-oidc.md](auth-oidc.md)). `api_key` and
`bearer_token` cover machine callers.

Two options on `jwt` are worth turning on if your issuer supports them.
`require_dpop: true` demands an RFC 9449 proof whose `jkt` matches the token's
`cnf.jkt`, so a stolen bearer is not enough on its own. `require_mtls_bound:
true` requires the token's `cnf.x5t#S256` to match the inbound client
certificate (RFC 8705). Both fail closed when the binding metadata is absent,
which is the behavior you want.

Every auth failure is recorded as a structured `auth_denied` audit event with
the scheme that rejected it, and never with the credential.

See [`examples/auth-jwt/`](../examples/auth-jwt/) for a complete working
config.

**Still yours.** Choosing an audience and issuer that actually narrow anything.
A JWT validated against a wildcard audience is a validated JWT that proves
little.

## No limit on what one caller can consume

An endpoint with no rate limit is a denial-of-service primitive and a
credential-stuffing oracle at the same time. It is also how a single retry loop
takes down a backend at 3am.

<!-- sbproxy-config-excerpt -->
```yaml
    policies:
      - type: rate_limiting
        requests_per_minute: 600
      - type: concurrent_limiting
        max: 50
      - type: request_limiting
        max_body_size: 1048576
        max_header_count: 64
        max_header_size: 16384
        max_url_length: 2048
      - type: ddos_protection
        requests_per_second: 100
        block_duration_secs: 300
```

`request_limiting` is the one people skip and then regret, because it bounds the
shapes that never reach a rate limiter: a 4 GB body, a header the parser chokes
on, a URL long enough to be its own attack. `agent_budget` caps spend rather
than requests, which is the limit that matters for AI-backed endpoints, and
`rate_limit_budget` ties a limit to a budget rather than a fixed count.

Body size for a specific route is a `payload_limit` transform rather than a
policy, which is worth knowing when you go looking for it.

Rate limit counters are shared across nodes when clustering is configured, so a
limit means the same thing behind a load balancer instead of becoming
per-instance. See [configuration.md](configuration.md) for the cluster fields.

See [`examples/rate-limiting/`](../examples/rate-limiting/) for a complete
working config.

**Still yours.** Picking numbers. A limit set above your actual capacity is
documentation, not protection.

## Input the service will trust

Injection, mass assignment, and schema drift are one problem wearing three
names: the request contained something the service did not expect and handled
anyway.

Validate against the contract you publish:

<!-- sbproxy-config-excerpt -->
```yaml
    policies:
      - type: openapi_validation
        spec_file: "./openapi.yaml"
        mode: enforce
        status: 400
      - type: request_validator
        schema:
          type: object
          required: [order_id]
          properties:
            order_id: { type: string }
      - type: waf
```

`openapi_validation` is the strongest of these, because it rejects anything your
own specification does not describe, including fields an attacker hoped were
silently bound. `mode: log` runs it in observation first, which is how you find
out what your clients actually send before you start refusing. The spec goes
inline or on disk; see [openapi-validation.md](openapi-validation.md) and
[`examples/openapi-validation/`](../examples/openapi-validation/) for the
full field set.

`request_validator` is the narrower tool when you want to check one field
without publishing a whole spec; see
[`examples/request-validator/`](../examples/request-validator/) for a
complete working config.

`http_framing` covers request smuggling and the framing tricks that let one
request look like two, refusing conflicting `Content-Length` and
`Transfer-Encoding` combinations rather than guessing which one the backend will
believe.

**Still yours.** Keeping the specification honest. Validation against a stale
spec enforces last quarter's contract.

## Requests the service makes on the caller's behalf

Server-side request forgery turns your API into a proxy for the attacker, and
cloud metadata endpoints make it worth their while.

The SSRF guard refuses upstreams resolving to private address space by default:

<!-- sbproxy-config-excerpt -->
```yaml
proxy:
  extensions:
    upstream:
      allow_private_cidrs:
        - 10.0.0.0/8
```

That allowlist is the escape hatch, and it should stay short. Everything not
listed is refused after DNS resolution, so a hostname that resolves to
`169.254.169.254` does not become a credential leak.

**Still yours.** SSRF that happens entirely inside your service, without
traversing the gateway, is invisible here.

## Data leaving that should not

Two directions worth separating. Secrets leaking outward in responses, and
regulated data leaving in ways you cannot account for.

<!-- sbproxy-config-excerpt -->
```yaml
    policies:
      - type: leaked_credentials
        action: block
        sha1_file: "./pwned-sha1.txt"
      - type: dlp
        detectors: [email, phone_us, credit_card, us_ssn]
        action: block
```

`leaked_credentials` catches the accidental case where a stack trace or debug
field carries a key, matching against a list you supply as `passwords`,
`sha1_hashes`, or a `sha1_file`.

`dlp` handles the regulated-data case, and it has two limits worth knowing
before you plan around it.

It scans **requests only**. Setting `direction: response` or `both` is accepted
and then warned about at load, and the scan still runs on the request side.
So `dlp` catches regulated data on the way in, not on the way out.

Its actions are `tag` and `block`, not redact. `tag` marks the request for
downstream handling and lets it through; `block` refuses it. Redact-and-continue
exists on the AI path instead, in the guardrail mesh, where a `pii` guardrail
can strip matches rather than refuse the request. See
[ai-gateway.md](ai-gateway.md).

For data on the way out, the controls that actually run are
`leaked_credentials` above and the response transforms. Where redaction does
run, it runs before observability fan-out, so a redacted value does not
reappear in a log or a trace.

**Still yours.** Classifying your own data. The detectors find shapes, not
meaning.

## Browser-facing misconfiguration

If your API is called from a browser, the boring headers are most of the work:

<!-- sbproxy-config-excerpt -->
```yaml
    policies:
      - type: security_headers
      - type: csrf
        secret_key: "${CSRF_SIGNING_KEY}"
        cookie_name: csrf_token
        safe_methods: [GET, HEAD, OPTIONS]
      - type: sri
        enforce: true
        algorithms: [sha384]
```

`page_shield` watches for third-party script drift on pages you serve.
`content_digest` binds a body to its `Content-Digest` header so a proxy in
between cannot alter it unnoticed.

See [`examples/csrf/`](../examples/csrf/) for a complete working config.

**Still yours.** CORS policy is a decision about who should be able to call you,
and no default is right for everyone.

## Automated traffic you cannot distinguish

Scrapers, credential stuffers, and AI crawlers all look like clients. Some you
want, some you do not, and telling them apart by user agent stopped working
years ago.

<!-- sbproxy-config-excerpt -->
```yaml
    policies:
      - type: ip_filtering
        blacklist: ["203.0.113.0/24"]
    auth:
      type: web_bot_auth
```

`web_bot_auth` verifies an RFC 9421 signature against a published key directory,
which is the difference between a crawler claiming to be someone and one proving
it. Its directory and key settings are in [web-bot-auth.md](web-bot-auth.md).
`pay_per_crawl` turns unwanted automation into a priced transaction rather than
a block.

See [`examples/ip-filter/`](../examples/ip-filter/) for a complete working
config of the `ip_filtering` policy above.

**Still yours.** Deciding which bots you want. The gateway will enforce either
answer.

## Not knowing an incident happened

Every denial above emits a structured security audit record with a stable event
type and a closed reason label, so a SIEM rule can route on the failure mode
without parsing prose. Records carry hostname, client IP, request id, method,
status, and tenant when known, and never the offending header value, because
attacker-controlled bytes in a SIEM log are their own problem.

Policy decisions are also counted:

```
sbproxy_policy_triggers_total{origin,policy_type,action}
sbproxy_auth_results_total
```

See [audit-log.md](audit-log.md) for the record shapes and
[observability.md](observability.md) for the metric surface.

**Still yours.** Alerting. An audit stream nobody queries is storage.

## A note on what a gateway cannot do

Everything above is enforcement at the edge. It composes badly with two things,
and it is worth being direct about them.

Business-logic flaws are invisible here. A gateway can confirm you are allowed
to call `POST /transfer`, not that transferring this amount to this account
makes sense.

And a control at the edge is only as good as the edge being unavoidable. If a
service is reachable directly, every policy on this page is optional from the
attacker's point of view. Network placement is the precondition for all of it.

## Where to go next

- [security.md](security.md) for the whole picture across traffic types.
- [object-authz.md](object-authz.md) for object-level authorization in depth.
- [audit-log.md](audit-log.md) for the audit record shapes.
- [configuration.md](configuration.md) for every field these examples use.
