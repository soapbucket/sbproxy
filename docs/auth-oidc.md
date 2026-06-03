# OIDC Relying-Party login

*Last modified: 2026-06-03*

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
      client_secret:          vault://idp/client_secret
      cookie_secret:          vault://oidc/cookie_secret
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
   `authorization_endpoint?response_type=code&client_id=...&code_challenge=...&state=...&nonce=...&scope=...&redirect_uri=https://app.example.com/oidc/callback`.
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

## Configuration reference

| Field | Type | Default | Description |
|---|---|---|---|
| `authorization_endpoint` | URL | (required) | IdP's authorization endpoint. |
| `token_endpoint` | URL | (required) | IdP's token endpoint. The callback POSTs `code` + `code_verifier` here. |
| `jwks_uri` | URL | (required) | IdP's JWKS endpoint. Fetched through the same `JwksCache` the `jwt` provider uses, so the keys are cached across origins. |
| `issuer` | URL | (required) | Expected `iss` on the ID token. Pinned by config so a rogue token from a different IdP (even one signed by a key pulled from `jwks_uri`) is rejected. |
| `client_id` | string | (required) | OAuth client ID. Sent on the auth redirect and matched against the ID token `aud`. |
| `client_secret` | string | (required) | OAuth client secret. Sent over Basic on the token-endpoint POST. Supports `vault://` references. |
| `cookie_secret` | string | (required) | 32+ byte secret used as the HKDF IKM for the session + transaction cookie keys. Supports `vault://`. Rotating this invalidates every outstanding session and tx cookie. |
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
| `X-Auth-Name` | `name` (when present) |
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
   honours that value verbatim).

The allowlist is the open-redirect gate. Without it, leaving the
endpoint to honour arbitrary query parameters is unsafe.

## Discovery

Today the IdP endpoints are explicit config fields. The OIDC
discovery document at `<issuer>/.well-known/openid-configuration`
is supported as an optional discovery-time fetch: when an
operator points the provider at a discovery URL (a follow-up
PR2), the proxy can populate `authorization_endpoint`,
`token_endpoint`, `jwks_uri`, and `end_session_endpoint` from the
fetched document instead of from explicit config. Until that
lands, populate the endpoints by hand from the IdP's discovery
document.

## Session storage

Default is **stateless encrypted cookie**: the session claims
travel in the cookie body, sealed with the per-origin cookie
key. No proxy-side state, no Redis. The cookie size grows with
the projected trust headers, so keep the trust-header projection
narrow.

For long-lived sessions or for sessions that need server-side
revocation, the `oidc::store` helpers offer a server-side
session-store hook (KV-backed) that operators can wire under the
existing `kv` storage. The default is stateless because the
cookie shape covers the common case and avoids the operational
cost of a session store.

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
* **MFA enforcement / step-up.** The provider honours whatever
  the IdP does on the auth side; in-proxy step-up is not in
  scope.

## See also

- [Example: `examples/oidc/`](../examples/oidc/)
- [`configuration.md`](configuration.md) for the auth-provider
  registry surface.
