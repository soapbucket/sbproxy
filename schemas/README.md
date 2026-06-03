# `sb.yml` JSON Schema

`sb-config.schema.json` is **generated** from the Rust types in
[`crates/sbproxy-config/src/types.rs`](../crates/sbproxy-config/src/types.rs).
Do not edit it by hand: any local change is overwritten on the
next regeneration.

## Regenerate

```bash
cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
```

The CI gate (`scripts/check-config-schema.sh`) runs the same
command and `diff`s against this file; a Rust type change that
does not regenerate is rejected at PR time.

## Use in your `sb.yml`

Add the schema directive at the top of your config so editor
tooling (VS Code, IntelliJ, Helix) validates as you type:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action: { type: proxy, url: http://127.0.0.1:9000 }
```

See [`docs/json-schema.md`](../docs/json-schema.md) for the
full editor-setup walkthrough, the caveats, and the source-of-
truth pointer.
