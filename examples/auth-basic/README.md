# HTTP Basic authentication

*Last modified: 2026-08-16*

![HTTP Basic authentication](../../docs/assets/auth-basic.gif)

Two-user HTTP Basic auth with a custom realm (`"sbproxy demo"`). Useful for quick admin panels and small internal tools. Requests without credentials, or with the wrong password, get a plain `401` with a JSON body; the configured `realm` is not currently emitted as a `WWW-Authenticate` challenge, so browsers will not auto-prompt for credentials on this origin (see the note under "Try it"). Credentials are matched against the static `users` list before `test.sbproxy.dev` is contacted. Passwords are stored in plain in this example so it stays reproducible; in production you would interpolate them from the environment or the vault.

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

{"error":"unauthorized"}
```

Note: no `WWW-Authenticate` header is sent, so a browser will not pop its native
credentials dialog against this origin; the request just gets a 401. The `realm`
field in `sb.yml` is accepted by config validation but is not currently wired
into the response.

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
$ curl -is -u admin:wrong -H 'Host: basic.local' http://127.0.0.1:8080/get | head -n 1
HTTP/1.1 401 Unauthorized
```

## What this exercises

- `authentication.type: basic_auth` - HTTP Basic with allowlisted users
- `realm` - accepted in config; not currently surfaced on the wire (see note above)
- `users` list - `username` / `password` pairs validated locally

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
