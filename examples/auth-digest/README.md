# HTTP Digest authentication

*Last modified: 2026-08-28*

Digest auth (RFC 7616) keeps the password off the wire: the client proves it knows the secret by hashing it into a response, and the server checks that hash against a stored HA1 without ever seeing the plaintext. This example serves a static page behind one digest user and answers the SHA-256 challenge.

## The credential

The config stores an HA1 hash, not a password. HA1 is `H(username:realm:password)`, so for user `alice`, realm `sbproxy`, password `secret`:

```bash
printf 'alice:sbproxy:secret' | shasum -a 256
# 666cbbd429e28a3f29a4276b9a3e9c62ddd997fa47a251dcff1a4c63b435cd3f
```

That hash is what goes in `sb.yml`. The plaintext `secret` never appears in the file. SHA-256 is the default algorithm; RFC 7616 deprecates MD5, and the compile step refuses an HA1 whose length does not match the selected algorithm, so a stale MD5 table cannot slip through as SHA-256.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

No credentials gets a challenge:

```bash
$ curl -i -H 'Host: digest.local' http://127.0.0.1:8080/
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Digest realm="sbproxy", nonce="cf95453940cff8c1be7115cd9faf85c6", qop="auth", algorithm=SHA-256
content-length: 24

{"error":"unauthorized"}
```

Curl's `--digest` answers that challenge and retries, so the correct password gets through (two requests cross the wire, one to collect the nonce and one to respond to it):

```bash
$ curl -i --digest -u alice:secret -H 'Host: digest.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json
content-length: 81

{"authenticated": true, "note": "served after a valid RFC 7616 digest response"}
```

The wrong password never produces a matching hash, so it stays at 401:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' --digest -u alice:wrong -H 'Host: digest.local' http://127.0.0.1:8080/
401
```

## What this shows

- Digest auth with a SHA-256 HA1 stored in place of the password
- The `WWW-Authenticate` challenge with `qop="auth"` and the advertised algorithm
- A wrong password failing without the plaintext ever reaching the config

The provider also tracks nonce counts: a captured `Authorization` header replayed with the same nonce and nonce-count is refused even though its digest is valid, which is the RFC 7616 protection against a sniffed header being reused.

## See also

- [docs/configuration.md](../../docs/configuration.md) documents the `digest` auth type and its `algorithm` and `users` fields.
- [examples/auth-basic](../auth-basic/) is the simpler password-on-the-wire form when the transport is already TLS.
