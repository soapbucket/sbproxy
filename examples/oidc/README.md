# oidc

*Last modified: 2026-06-04*

OpenID Connect Relying-Party login flow. Puts SSO in front of an
upstream that has no auth of its own: an unauthenticated browser is
redirected to the IdP, completes the auth-code + PKCE flow, and is
served with a sealed session cookie. Subsequent requests authenticate
from the cookie.

This is the "put SSO in front of an app that has none" pattern that
oauth2-proxy, Pomerium, and Cloudflare Access ship. SBproxy provides
it as a configuration auth provider; no separate sidecar needed.

See [`docs/auth-oidc.md`](../../docs/auth-oidc.md) for the full
field reference (every `oidc:` config knob with defaults), the
trust-header-projection contract, the logout open-redirect gate,
and the session-storage model.

## Setup

```bash
# The four IdP endpoints below are placeholders; copy the real values
# from your IdP's published <issuer>/.well-known/openid-configuration
# document (Keycloak, Auth0, Google, Okta, ...).
export ANTHROPIC_API_KEY=unused-for-this-example
```

## Run

```bash
make run CONFIG=examples/oidc/sb.yml
```

## Walk through the flow (interactive)

The auth-redirect dance is browser-driven:

```bash
open http://127.0.0.1:8080/        # 302 to IdP authorize endpoint
# ... complete login at the IdP ...
# IdP 302s back to /oidc/callback?code=...&state=...
# the proxy validates the ID token, mints a session cookie, 302s to "/"
```

Subsequent requests carry the `__Host-sbproxy_session` cookie and
authenticate from it.

## What the example wires

| Field | Demo value | Production source |
|---|---|---|
| `authorization_endpoint` / `token_endpoint` / `jwks_uri` / `issuer` | placeholder URLs | IdP's `.well-known/openid-configuration` |
| `client_id` / `client_secret` | demo strings | OAuth client registered with the IdP |
| `cookie_secret` | 32-byte literal (demo only) | `vault://primary/secret/data/oidc/cookie?key=cookie_secret` |
| `scope` | `openid email profile` | adjust to what your IdP exposes |
| `userinfo_endpoint` | enabled | optional; enables the X-Auth-Subject / Email / Name / Groups trust-header projection |
| `end_session_endpoint` | enabled | optional; lets `/oidc/logout` terminate the IdP session too |
| `post_logout_redirect_allowlist` | two-entry list | open-redirect gate; required to use the `post_logout_redirect_uri` query parameter |

## See also

- [`docs/auth-oidc.md`](../../docs/auth-oidc.md) - full operator guide.
