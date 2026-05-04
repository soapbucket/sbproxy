# mTLS client certificate authentication

*Last modified: 2026-04-27*

Demonstrates mutual TLS at the listener. Incoming HTTPS clients must present a certificate signed by the configured CA bundle. Failed handshakes never reach `request_filter`; the connection is dropped at the TLS layer. After a successful handshake the proxy strips any inbound `X-Client-Cert-*` headers (so a non-TLS client cannot forge them) and forwards the verified identity as `X-Client-Cert-Verified`, `X-Client-Cert-CN`, `X-Client-Cert-SAN`, `X-Client-Cert-Organization`, `X-Client-Cert-Serial`, and `X-Client-Cert-Fingerprint`. `require: true` (default) rejects anonymous clients at the handshake; `require: false` admits them and the upstream sees no cert headers.

## Run

```bash
bash examples/85-mtls-client-auth/generate-certs.sh
sbproxy serve -f sb.yml
```

The bootstrap script writes a self-signed CA, a server cert (CN=localhost, SAN includes 127.0.0.1), and a client cert (CN=alice@example.com, SAN includes alice.local) into `examples/85-mtls-client-auth/certs/`. Re-run it whenever the certs expire (one year by default).

## Try it

```bash
# Verified client: the upstream sees X-Client-Cert-CN: alice@example.com.
curl --cacert examples/85-mtls-client-auth/certs/ca.pem \
     --cert  examples/85-mtls-client-auth/certs/client.pem \
     --key   examples/85-mtls-client-auth/certs/client.key \
     -H 'Host: localhost' \
     https://127.0.0.1:8443/headers | jq '.headers'
```

```bash
# Anonymous client: TLS handshake fails before request_filter runs.
curl -k https://127.0.0.1:8443/headers
# curl: (35) ... peer did not return a certificate
```

```bash
# Plaintext HTTP on 8080 still works for local debugging when the
# origin allows it; mTLS only applies to the HTTPS listener.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq .url
```

## What this exercises

- `proxy.mtls.client_ca_file` - CA bundle that must sign every accepted client cert
- `proxy.mtls.require` - hard reject anonymous clients at the TLS handshake
- Forwarded identity headers (`X-Client-Cert-*`) carrying CN, SAN, organisation, serial, and SHA-256 fingerprint to the upstream
- Stripping of inbound `X-Client-Cert-*` headers to prevent header forgery

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
