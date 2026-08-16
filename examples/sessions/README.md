# Sessions

*Last modified: 2026-08-16*

![Sessions](../../docs/assets/sessions.gif)

> **Known issue: no cookie on a `static` action.** As shipped, the request
> below does not actually receive a `set-cookie` header. Session-cookie
> issuance is written on the proxy response path that only runs when the
> origin's `action` is `proxy`; a `static` action's response is built on a
> different path that never reaches it. Confirmed by pointing this same
> `session:` block at an `action: proxy` origin instead, where the cookie is
> issued correctly. This is a proxy bug, not a config error; tracked for a
> fix. Until then this example cannot demonstrate cookie issuance as
> written; swap the action to `proxy` against any upstream to see it work.

The `session` block on `app.local` configures the encrypted cookie used to carry session state across requests. Cookie name is `sb_session`, max age is 3600 seconds, `http_only` is on, `same_site` is `Lax`, and `allow_non_ssl: true` lets the example run on plain HTTP for local testing. The action is a static JSON response so you can observe cookie issuance directly without a real backend.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# First request: server issues the session cookie. Persist it to a jar.
curl -sv -c /tmp/sb-session.jar -H 'Host: app.local' http://127.0.0.1:8080/ 2>&1 | grep -iE '^< set-cookie|sb_session'
# < set-cookie: sb_session=<encrypted>; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax

# Inspect the cookie jar.
cat /tmp/sb-session.jar | grep sb_session
# 127.0.0.1  FALSE  /  FALSE  <expires>  sb_session  <encrypted>

# Subsequent request: client sends the cookie back; the proxy validates it.
curl -sv -b /tmp/sb-session.jar -H 'Host: app.local' http://127.0.0.1:8080/ 2>&1 | grep -iE '^< HTTP|cookie'
# > Cookie: sb_session=<encrypted>
# < HTTP/1.1 200 OK

# Body is the static action's payload.
curl -s -b /tmp/sb-session.jar -H 'Host: app.local' http://127.0.0.1:8080/
# {"message":"session cookie issued, see Set-Cookie response header","cookie_name":"sb_session","max_age_secs":3600}
```

## What this exercises

- `session.cookie_name` and `session.max_age`
- `http_only`, `secure`, `same_site` cookie attributes
- `allow_non_ssl: true` for local HTTP testing
- Composition with the `static` action

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
