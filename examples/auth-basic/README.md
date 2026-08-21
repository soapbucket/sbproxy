# HTTP Basic authentication

*Last modified: 2026-08-16*

![HTTP Basic authentication](../../docs/assets/auth-basic.gif)

Two-user HTTP Basic auth with a custom realm (`"sbproxy demo"`). Useful for quick admin panels and small internal tools. Requests without credentials, or with the wrong password, get a `401` carrying `WWW-Authenticate: Basic realm="sbproxy demo"`, which is what makes a browser pop its credentials dialog. Credentials are matched against the static `users` list before `test.sbproxy.dev` is contacted. Passwords are stored in plain in this example so it stays reproducible; in production you would interpolate them from the environment or the vault.

## Run

```bash
make run CONFIG=examples/auth-basic/sb.yml
```

No env vars required.

## Try it

No credentials:

```bash
$ curl -i -H 'Host: basic.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Basic realm="sbproxy demo"

{"error":"unauthorized"}
```

The realm on that header is the `realm` field from `sb.yml`. RFC 9110 section
11.6.1 requires the parameter, so an origin that configures none is challenged
as `Basic realm="restricted"` rather than getting a bare 401.

Valid credentials, request forwarded:

```bash
$ curl -i -u admin:s3cret -H 'Host: basic.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","url":"/get","headers":{"authorization":"Basic YWRtaW46czNjcmV0","host":"test.sbproxy.dev",...},"query":{},"timestamp":"2026-07-09T19:29:58.060Z"}
```

Second user also works:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -u readonly:viewonly -H 'Host: basic.local' http://127.0.0.1:8080/get
200
```

Wrong password, rejected:

```bash
$ curl -is -u admin:wrong -H 'Host: basic.local' http://127.0.0.1:8080/get | head -n 3
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Basic realm="sbproxy demo"
```

A rejected password is challenged too, not only a missing one.

## What this exercises

- `authentication.type: basic_auth` - HTTP Basic with allowlisted users
- `realm` - the realm sent on the 401 `WWW-Authenticate` challenge
- `users` list - `username` / `password` pairs validated locally

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
