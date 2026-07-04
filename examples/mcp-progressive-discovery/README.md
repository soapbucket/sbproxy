# MCP progressive tool discovery

Keeps a large federated catalogue out of the model's context window by
advertising only `search` and `execute` meta-tools.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

- `tools/list` returns exactly two tools, `search` and `execute`, not
  the full federated catalogue.
- `tools/call` `search` with a `query` returns matching catalogue
  entries; `tools/call` `execute` with a tool `name` invokes it.
