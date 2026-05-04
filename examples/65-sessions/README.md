# Sessions

*Last modified: 2026-04-27*

The `session` block on `app.local` configures the encrypted cookie used to carry session state across requests. Cookie name is `sb_session`, max age is 3600 seconds, `http_only` is on, `same_site` is `Lax`, and `allow_non_ssl: true` lets the example run on plain HTTP for local testing. The action is a static JSON response so you can observe cookie issuance directly without a real backend.

## Run

```bash
sb run -c sb.yml
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
