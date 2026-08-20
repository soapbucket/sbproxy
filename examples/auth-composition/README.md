# Auth composition

*Last modified: 2026-08-19*

Accepts either of two credentials on the same origin. The `authentication:` block here is a list, not a single provider: the `api_key` entry is tried first, the `bearer` entry second, and the first provider that accepts the request wins. Requests that satisfy neither are rejected with 401 inside the proxy; a winning request is forwarded to `test.sbproxy.dev` with the winning provider's identity bound to it. This is the standard shape of a credential migration: callers on the legacy API key keep working while new callers move to bearer tokens, with no cutover day.

Audit events, decision records, and the auth metric name the provider that actually authenticated each request (`api_key` or `bearer` here), so the migration's progress is visible in the numbers.

## Run

```bash
make run CONFIG=examples/auth-composition/sb.yml
```

No env vars required.

## Try it

No credential, request is rejected before the upstream is contacted:

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: application/json

{"error":"unauthorized"}
```

The legacy API key is accepted by the first provider in the list:

```bash
$ curl -i -H 'Host: api.local' -H 'X-Api-Key: legacy-key-1' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","url":"/get","headers":{"host":"test.sbproxy.dev","x-api-key":"legacy-key-1",...},"query":{},"timestamp":"2026-08-19T18:04:12.331Z"}
```

The new bearer token is accepted by the second provider, on the same origin:

```bash
$ curl -i -H 'Host: api.local' -H 'Authorization: Bearer new-token-1' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","url":"/get","headers":{"host":"test.sbproxy.dev","authorization":"Bearer new-token-1",...},"query":{},"timestamp":"2026-08-19T18:04:31.887Z"}
```

Wrong values for both are rejected the same way as no credential:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -H 'Host: api.local' -H 'X-Api-Key: not-a-key' \
       -H 'Authorization: Bearer not-a-token' \
       http://127.0.0.1:8080/get
401
```

When every provider rejects, the response reuses the first provider's status and message, and any `WWW-Authenticate` challenges the providers produce are merged onto it. Neither `api_key` nor `bearer` issues a challenge header, so the 401 above is bare; compose a `digest` or `cap` provider and its challenge appears on the shared 401.

## What this exercises

- `authentication:` as a list - two or more providers on one origin
- OR semantics - providers tried in declared order, first success wins
- Per-provider attribution - records name the winning provider, not the composite
- Pre-upstream rejection - 401s never reach the upstream

## See also

- [docs/configuration.md](../../docs/configuration.md) - the full rules, including the types a list refuses (`noop`, `forward_auth`, `oidc`)
- [examples/auth-api-key/](../auth-api-key/) - the single-provider form
- [examples/auth-bearer/](../auth-bearer/) - bearer tokens on their own
