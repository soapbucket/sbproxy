# JSON Schema editor integration

*Last modified: 2026-07-09*

Shows the one-line `# yaml-language-server: $schema=...` directive that wires `schemas/sb-config.schema.json` into your editor. VS Code (with the YAML extension), the IntelliJ / JetBrains family, and Helix all honour it and validate `sb.yml` as you type: field-name autocomplete, typed values (`http_bind_port: "hello"` underlines red), closed-enum dropdowns, and rustdoc tooltips. The schema is generated from the Rust config types, so it cannot drift from the binary. The config itself is a minimal single-origin proxy; the interesting part is line 1.

## Run

Open `sb.yml` in a schema-aware editor and type `proxy.` on a fresh line under `proxy:`; the autocomplete dropdown lists every field. To check the same config against the real parser:

```bash
sbproxy validate examples/json-schema/sb.yml
```

To serve it, from the repository root:

```bash
make run CONFIG=examples/json-schema/sb.yml
```

## Try it

The config proxies `api.example.com` to `http://127.0.0.1:9000`, so start any local server on port 9000 first (for example `python3 -m http.server 9000`), then:

```bash
$ curl -i -H 'Host: api.example.com' http://127.0.0.1:8080/
HTTP/1.1 200 OK
```

Without a server on port 9000 the proxy answers 502, which is expected; this example exists for the editor integration, not the upstream.

## See also

- [docs/json-schema.md](../../docs/json-schema.md) - full editor-setup walkthrough
- [schemas/sb-config.schema.json](../../schemas/sb-config.schema.json) - the generated schema
