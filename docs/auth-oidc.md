# OIDC Relying-Party login

*Last modified: 2026-08-16*

The `oidc` auth provider turns SBproxy into an OpenID Connect
Relying Party. Unlike the `jwt` provider, which only validates a
bearer JWT that the caller already holds, this provider drives
the full authorization-code + PKCE login dance: it redirects an
unauthenticated caller to the IdP, exchanges the returned code
for an ID token, validates the token, and mints a sealed session
cookie. Subsequent requests authenticate from the cookie until
the session expires.

This is the "put SSO in front of an app that has none" use case
that operators reach for with oauth2-proxy, Pomerium, or
Cloudflare Access. SBproxy ships it as a configuration auth
provider; no separate sidecar needed.

## Quick start

```yaml
origins:
  "app.example.com":
    action:
      type: proxy
      url: http://upstream-app:3000
    auth:
      type: oidc
      authorization_endpoint: https://idp.example.com/authorize
      token_endpoint:         https://idp.example.com/oauth/token
      jwks_uri:               https://idp.example.com/.well-known/jwks.json
      issuer:                 https://idp.example.com/
      client_id:              sbproxy-app-example-com
      client_secret:          vault://primary/secret/data/oidc/client?key=client_secret
      cookie_secret:          vault://primary/secret/data/oidc/cookie?key=cookie_secret
      scope:                  "openid email profile"
```

The minimum fields are the four IdP endpoints (`authorization_endpoint`,
`token_endpoint`, `jwks_uri`, `issuer`), the OAuth `client_id`
and `client_secret`, and a `cookie_secret` used to seal the
session cookie. Everything else has a sensible default.

A runnable example lives at
[`examples/oidc/`](../examples/oidc/) with a mock IdP shape and
the curl invocations to walk through.

## Flow

1. The browser requests a protected origin without a session cookie.
2. SBproxy mints a transaction cookie (sealed PKCE verifier + state
   + nonce, TTL `tx_ttl_secs`) and 302's the browser to
   `authorization_endpoint?response_type=code&client_id=...&redirect_uri=https%3A%2F%2Fapp.example.com%2Foidc%2Fcallback&scope=...&state=...&nonce=...&code_challenge=...&code_challenge_method=S256`.
3. The IdP authenticates the user and 302's back to
   `https://app.example.com/oidc/callback?code=...&state=...`.
4. The `/oidc/callback` handler (a synthetic endpoint mounted by
   the OIDC provider, the same shape as MCP's well-known
   endpoints) unseals the transaction cookie, verifies the
   `state` matches, POSTs to `token_endpoint` with the `code` and
   the PKCE `code_verifier`, validates the returned ID token
   against `issuer` + `client_id` + `nonce`, mints a sealed
   session cookie (TTL `session_ttl_secs`), and 302's the browser
   back to the originally-requested URL.
5. Subsequent requests carry the session cookie; the proxy
   decrypts and the caller is treated as authenticated.

All cookies use the `__Host-` prefix per RFC 6265bis (forces
`Secure` + `Path=/` + no `Domain`), so the cookie-tossing attack
against the session secret is closed.

## Calling it

The runnable configuration is [`examples/oidc/`](../examples/oidc/). Its IdP
endpoints point at `idp.example.com`, which does not exist, so the login
cannot complete. Everything SBproxy itself does before and after the IdP is
still reachable, and that is the half worth checking. Start it:

```bash
make run CONFIG=examples/oidc/sb.yml
```

Request a protected path with no session cookie:

```bash
curl -sS -i -H 'Host: app.example.com' http://127.0.0.1:8080/dashboard
```

```http
HTTP/1.1 302 Found
Location: https://idp.example.com/authorize?response_type=code&client_id=sbproxy-app-example-com&redirect_uri=https%3A%2F%2Fapp.example.com%2Foidc%2Fcallback&scope=openid%20email%20profile&state=ye50VIeL_wUmrTKZjLjLPXQkx8mZRav89uRrUbW6J48&nonce=SLuBu1Wo9kW2Q1hiLsGNNmeVX7ZYjvj5YDJIv4cuyTI&code_challenge=XfOcq25BKC28bKxO9RzKist0YkW4tPvA0ysn7SZ-1hI&code_challenge_method=S256
Set-Cookie: __Host-sbproxy_oidc_tx=uXKf80cZ7IJpktd3cFHBD_plDohWO5iCvoIWG_uNgLD...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300
```

`state`, `nonce`, and `code_challenge` are freshly generated per login and
differ on every request. `code_challenge_method=S256` confirms PKCE is on;
there is no configuration knob that turns it off. `redirect_uri` is the
`/oidc/callback` path the provider mounts, percent-encoded, and it is the
value that has to be registered with the IdP.

The `Set-Cookie` is the transaction cookie, not the session. It seals the PKCE
verifier, the `state`, and the `nonce` so the callback can verify the response
without server-side state. `Max-Age=300` is `tx_ttl_secs`, so a login left
open for longer than five minutes has to restart. The `__Host-` prefix forces
`Secure` and `Path=/` with no `Domain`, which is what closes cookie-tossing
against the session secret.

The response also carries a small JSON body with an empty `error` field. A
browser follows the `Location` and never renders it; it is visible only
because `curl` prints the body.

Now call the callback the way a forged request would, without the transaction
cookie:

```bash
curl -sS -i -H 'Host: app.example.com' \
  'http://127.0.0.1:8080/oidc/callback?code=abc&state=xyz'
```

```json
{"error":"invalid_request","error_description":"oidc tx cookie missing; restart the login"}
```

That is `400`, and it is the state-fixation guard doing its job: a `code` and
`state` alone are not enough, because the `state` has to match the one sealed
in the cookie this browser was given.

Logout is worth exercising in both directions, because the interesting case is
the one that is refused. The example allowlists
`https://app.example.com/goodbye` and sets `post_logout_redirect_default` to
`https://app.example.com/`. An allowlisted target is honored verbatim:

```bash
curl -sS -i -H 'Host: app.example.com' \
  'http://127.0.0.1:8080/oidc/logout?post_logout_redirect_uri=https://app.example.com/goodbye'
```

```http
HTTP/1.1 302 Found
location: https://idp.example.com/oauth/logout?id_token_hint=&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fgoodbye
set-cookie: __Host-sbproxy_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0
```

A target that is not on the allowlist is **replaced, not rejected**:

```bash
curl -sS -i -H 'Host: app.example.com' \
  'http://127.0.0.1:8080/oidc/logout?post_logout_redirect_uri=https://evil.example.com/'
```

```http
HTTP/1.1 302 Found
location: https://idp.example.com/oauth/logout?id_token_hint=&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F
```

The attacker-supplied host is gone and `post_logout_redirect_default` took its
place. Expect a `302`, not a `400`, when testing this: the gate is a
substitution rather than an error, so a test that asserts on a failure status
will pass for the wrong reason. Matching is an exact string comparison, so
`https://app.example.com/goodbye` and
`https://app.example.com/goodbye/` are different entries.

In both cases `set-cookie` clears the session with `Max-Age=0` before the
redirect, so the cookie is dropped whether or not the IdP honors the
end-session call. `id_token_hint` is sent empty because the session cookie
does not carry the original ID token; an OP that requires the hint rejects the
redirect, which is why most deployments do not depend on it.

## Configuration reference

| Field | Type | Default | Description |
|---|---|---|---|
| `authorization_endpoint` | URL | (required) | IdP's authorization endpoint. |
| `token_endpoint` | URL | (required) | IdP's token endpoint. The callback POSTs `code` + `code_verifier` here. |
| `jwks_uri` | URL | (required) | IdP's JWKS endpoint. Fetched through the same `JwksCache` the `jwt` provider uses, so the keys are cached across origins. |
| `issuer` | URL | (required) | Expected `iss` on the ID token. Pinned by config so a rogue token from a different IdP (even one signed by a key pulled from `jwks_uri`) is rejected. |
| `client_id` | string | (required) | OAuth client ID. Sent on the auth redirect and matched against the ID token `aud`. |
| `client_secret` | string | (required) | OAuth client secret. Sent over Basic on the token-endpoint POST. Supports secret references. |
| `cookie_secret` | string | (required) | 32+ byte secret used as the HKDF IKM for the session + transaction cookie keys. Supports secret references. Rotating this invalidates every outstanding session and tx cookie. |
| `redirect_path` | path | `/oidc/callback` | Path the IdP redirects back to. Must be one of the URIs you registered with the IdP under `redirect_uris`. |
| `logout_path` | path | `/oidc/logout` | Path that triggers RP-initiated logout. |
| `end_session_endpoint` | URL | unset | IdP's `end_session_endpoint`. When set, `/oidc/logout` deletes the session cookie and 302's to the OP so the IdP terminates its own session too. When unset, `/oidc/logout` only deletes the cookie and 302's to `post_logout_redirect_default`. |
| `userinfo_endpoint` | URL | unset | IdP's userinfo endpoint. When set, the callback handler calls userinfo after the token exchange and projects the resulting claims as trust headers on the request to the upstream. |
| `post_logout_redirect_default` | path or URL | `/` | Where to send the browser after a logout completes if the caller did not supply (or did not allowlist) a `post_logout_redirect_uri`. |
| `post_logout_redirect_allowlist` | list of URLs | `[]` | Permitted values for the `post_logout_redirect_uri` query parameter on `/oidc/logout`. Without this gate the endpoint becomes an open-redirect. Match is verbatim. |
| `scope` | string | `openid` | Space-separated OIDC scope list. Minimum is `openid` (the scope that produces an ID token); add `email profile groups` etc. as needed. |
| `session_ttl_secs` | integer | `3600` | Session cookie TTL in seconds. |
| `tx_ttl_secs` | integer | `300` | Transaction cookie TTL in seconds. Should comfortably exceed the operator's expected time between auth redirect and callback redirect; a stale tx cookie aborts the login. |
| `session_cookie_name` | string | `__Host-sbproxy_session` | Name of the session cookie. The `__Host-` prefix forces `Secure` + `Path=/` + no `Domain`. |
| `tx_cookie_name` | string | `__Host-sbproxy_oidc_tx` | Name of the transaction cookie. |
| `attrs` | block | `{}` | Provider-level attribution metadata stamped onto the resolved `Principal` on a successful OIDC session validation. Same shape as the other auth providers. |

## Trust-header injection (optional)

When `userinfo_endpoint` is set, the callback handler:

1. Calls the userinfo endpoint with the access token from the
   token exchange.
2. Projects the returned claims through
   `userinfo::trust_headers_from_claims`.
3. Stashes the projection in the sealed session cookie.

On every subsequent request, the request-time auth check replays
the trust headers onto the upstream request. Downstream policies
(for example the `object_authz` BOLA + BFLA policy) see the
verified subject and groups without an additional round trip.

The headers stamped are:

| Header | Source claim |
|---|---|
| `X-Auth-Subject` | `sub` |
| `X-Auth-Email` | `email` (when present and `email_verified` is `true`) |
| `X-Auth-User` | `preferred_username`, falling back to `name` (first present) |
| `X-Auth-Groups` | `groups` (comma-joined when array-shaped) |

Upstreams MUST be configured to trust these headers only from
the proxy (e.g. via mTLS or a tight network boundary); the proxy
strips inbound copies of these headers from the client before
adding its own so a malicious client cannot inject identity.

## Logout

Send the browser to `logout_path` (default `/oidc/logout`). The
handler:

1. Deletes the session cookie.
2. If `end_session_endpoint` is set, 302's the browser to the IdP
   so the OP terminates its own session.
3. Otherwise, 302's the browser to `post_logout_redirect_default`
   (or, if the caller supplied a `post_logout_redirect_uri` query
   parameter that appears in `post_logout_redirect_allowlist`,
   honors that value verbatim).

The allowlist is the open-redirect gate. Without it, leaving the
endpoint to honor arbitrary query parameters is unsafe.

## Discovery

Today the IdP endpoints are explicit config fields. The runtime contains the
validated discovery-document parser and TTL cache, but configuration does not
yet wire them into the auth provider. Read
`<issuer>/.well-known/openid-configuration` and populate
`authorization_endpoint`, `token_endpoint`, `jwks_uri`, and the optional
`end_session_endpoint` explicitly.

## Session storage

Default is **stateless encrypted cookie**: the session claims
travel in the cookie body, sealed with the per-origin cookie
key. No proxy-side state, no Redis. The cookie size grows with
the projected trust headers, so keep the trust-header projection
narrow.

For long-lived sessions or for sessions that need server-side
revocation, the `oidc::store` module ships a `SessionStore` trait and
a `KvSessionStore` implementation backed by the existing `kv` storage
abstraction. There is no `sb.yml` field that enables it today: wiring
it into the request path is a code change (a custom build that
constructs a `KvSessionStore` and threads it through), not a
configuration option. The default is stateless because the cookie
shape covers the common case and avoids the operational cost of a
session store.

## Relationship to the other auth providers

| Provider | Validates | Issues | Drives a login flow |
|---|---|---|---|
| `noop` | nothing | nothing | no |
| `api_key`, `basic_auth`, `bearer`, `digest` | per-credential lookup | no | no |
| `jwt` | bearer JWT (issuer / audience / signature) | no | no |
| `forward_auth` | delegates to an external authorizer | no | no |
| `oidc` (this provider) | session cookie + ID token | session cookie | **yes** |

The `oidc` provider shares the JWKS cache with `jwt` so two
origins backed by the same IdP do not duplicate key fetches.
Operators that want to layer "validate a bearer JWT issued by a
different system" on top of "log in via OIDC" can combine
`oidc` here with `jwt` on a different origin in the same
config; the providers are independent.

## What's not in this provider

* **Discovery-document auto-population** of the four endpoint
  fields. Tracked as a follow-up; today the operator pastes the
  values from the IdP's published `.well-known/openid-configuration`.
* **Refresh-token rotation.** The session TTL bounds the time
  between IdP round-trips. A follow-up adds rotating refresh
  tokens behind a server-side session store.
* **DPoP-bound sessions.** The session cookie today is a sealed
  bearer; DPoP binding to a client-held key is a follow-up.
* **MFA enforcement / step-up.** The provider honors whatever
  the IdP does on the auth side; in-proxy step-up is not in
  scope.

## See also

- [Example: `examples/oidc/`](../examples/oidc/)
- [`configuration.md`](configuration.md) for the auth-provider
  registry surface.
