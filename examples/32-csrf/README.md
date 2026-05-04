# CSRF protection

*Last modified: 2026-04-27*

Demonstrates the `csrf` policy. Safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt and serve as the channel through which the proxy issues the `csrf_token` cookie. State-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`) must echo the token back in the `X-CSRF-Token` request header; mismatches and missing tokens are rejected with `403`. The action is `static` so the example is self-contained and shows the policy in isolation. Listener is `127.0.0.1:8080`, Host header is `csrf.local`.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# 1. Safe method seeds the cookie. Save it to cookies.txt.
$ curl -i -c cookies.txt -H 'Host: csrf.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
set-cookie: csrf_token=eyJ...; Path=/; SameSite=Lax
content-type: application/json

{"ok":true}
```

```bash
# 2. POST without a token - rejected
$ curl -i -X POST -H 'Host: csrf.local' http://127.0.0.1:8080/submit
HTTP/1.1 403 Forbidden
content-type: text/plain

csrf token missing or invalid
```

```bash
# 3. POST with the cookie and matching header - accepted
$ TOKEN=$(awk '/csrf_token/ {print $7}' cookies.txt)
$ curl -i -X POST -b cookies.txt -H 'Host: csrf.local' \
       -H "X-CSRF-Token: $TOKEN" http://127.0.0.1:8080/submit
HTTP/1.1 200 OK
content-type: application/json

{"ok":true}
```

```bash
# 4. POST with a forged token - rejected
$ curl -i -X POST -b cookies.txt -H 'Host: csrf.local' \
       -H 'X-CSRF-Token: not-the-real-token' http://127.0.0.1:8080/submit
HTTP/1.1 403 Forbidden
```

## What this exercises

- `csrf` policy - HMAC-signed token issued via cookie, validated from `X-CSRF-Token`
- `safe_methods` - exemption list that triggers token issuance instead of validation
- `cookie_path` and `cookie_same_site: Lax` - cookie scope tuned for typical browser flows
- `static` action - returns a canned JSON body so the example needs no upstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
