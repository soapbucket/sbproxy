# MCP OAuth auth discovery (RFC 9728)

Turns on the MCP auth discovery flow so a compliant client can find the
authorization server before opening a session.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

- `GET /.well-known/oauth-protected-resource` returns the RFC 9728
  metadata naming `https://issuer.example.com`.
- A `tools/call` with no `Authorization` header returns `401` with
  `WWW-Authenticate: Bearer resource_metadata="<that URL>"`.
- The discovery manifest at the well-known MCP path carries an
  `authorization` pointer to the same metadata.
