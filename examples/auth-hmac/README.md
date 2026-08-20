# HMAC signed-request authentication

HMAC auth keeps the secret off the wire entirely: the client signs each request with a shared secret and the proxy recomputes the signature, so what travels is a proof bound to that one request. A bearer token or API key leaks the same reusable value on every call; a captured HMAC-signed request replays nowhere else and goes stale once its timestamp leaves the clock-skew window. This example serves a static page behind one signing key.

The wire format is RFC 9421 HTTP Message Signatures with the `hmac-sha256` algorithm, the standardized form of the scheme API gateways ship as "HMAC auth" and the same signature machinery SBproxy already uses for Web Bot Auth.

## The credential

The config names a `key_id` and points the secret at the environment, so the file never carries it:

```yaml
authentication:
  type: hmac_auth
  clock_skew_seconds: 300
  keys:
    - key_id: svc-billing
      secret: env:SBPROXY_HMAC_SECRET
      project: billing
```

`secret` accepts the same reference forms as every other signing-key field: `env:NAME`, `file:PATH`, `${VAR}`, an inline literal, or a vault backend URI. A reference nothing can resolve refuses to boot rather than becoming the key.

## Run

```bash
export SBPROXY_HMAC_SECRET=worked-example-secret
sbproxy serve -f sb.yml
```

## Try it

An unsigned request gets the challenge:

```bash
$ curl -i -H 'Host: hmac.local' http://127.0.0.1:8080/
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 41
WWW-Authenticate: Signature

{"error":"hmac_auth: signature required"}
```

To sign, build the RFC 9421 signature base (one line per covered component, then the `@signature-params` line), HMAC it, and send the `Signature-Input` / `Signature` pair:

```bash
created=$(date +%s)
base=$(printf '"@method": GET\n"@target-uri": /\n"@signature-params": ("@method" "@target-uri");created=%s;keyid="svc-billing";alg="hmac-sha256"' "$created")
sig=$(printf '%s' "$base" | openssl dgst -sha256 -hmac "$SBPROXY_HMAC_SECRET" -binary | base64)
curl -i -H 'Host: hmac.local' \
  -H "Signature-Input: sig1=(\"@method\" \"@target-uri\");created=$created;keyid=\"svc-billing\";alg=\"hmac-sha256\"" \
  -H "Signature: sig1=:$sig:" \
  http://127.0.0.1:8080/
```

```text
HTTP/1.1 200 OK
content-type: application/json
content-length: 87

{"authenticated": true, "note": "served after a valid RFC 9421 hmac-sha256 signature"}
```

The signature is bound to what it covers. Reuse the same two headers against a different path and the reconstructed `@target-uri` no longer matches what was signed:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: hmac.local' \
    -H "Signature-Input: sig1=(\"@method\" \"@target-uri\");created=$created;keyid=\"svc-billing\";alg=\"hmac-sha256\"" \
    -H "Signature: sig1=:$sig:" \
    http://127.0.0.1:8080/admin
401
```

Replay the untouched request after the window and the `created` timestamp is stale, so the same 401 comes back. That window is the replay defense: `created` is mandatory, at most `clock_skew_seconds` old, and at most `clock_skew_seconds` in the future.

## What this shows

- A signing key resolved from the environment, never inlined or logged
- The `WWW-Authenticate: Signature` challenge on unsigned and failed requests, with no key material in the response
- Method and path bound into the signature, so a captured request cannot be redirected
- A mandatory `created` timestamp window (default 300 seconds) as the replay defense
- `hmac-sha256` pinned: the only symmetric algorithm in the RFC 9421 registry, so there is no SHA-1 to negotiate down to

On a match the request's principal gets `sub: svc-billing`, `principal_kind: hmac_auth`, and the entry's metadata (`project: billing` here) for per-credential reporting in the access log.

## See also

- [docs/configuration.md](../../docs/configuration.md) documents the `hmac_auth` type, its `keys` and `required_components` fields, and the freshness rules.
- [examples/auth-api-key](../auth-api-key/) is the simpler static-credential form when per-request signing is more than the caller can do.
- [examples/web-bot-auth](../web-bot-auth/) uses the same RFC 9421 signatures with public-key crypto and a published agent directory.
