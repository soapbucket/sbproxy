# MCP OAuth auth discovery (RFC 9728)

> **Partially runnable.** `federated_servers[].origin` here is
> `github.example.com`, an RFC 2606 reserved placeholder, not a running MCP
> server, so `tools/call` against a federated tool cannot complete
> end-to-end. The discovery endpoints below (`/.well-known/...`, the `401` +
> `WWW-Authenticate` challenge) are served by the gateway itself and do not
> touch the upstream, so those work as shipped. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics and its own end-to-end caveat.

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
