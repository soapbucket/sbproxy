# JSON Schema for `sb.yml`
*Last modified: 2026-07-09*

SBproxy publishes a JSON Schema describing every field its
configuration accepts. Editors that understand the schema
(VS Code with the YAML extension, IntelliJ / JetBrains family,
Helix) validate the file as you type and surface a typo or a
wrong-typed value before you ever start the binary.

## Where it lives

The schema is committed at
[`schemas/sb-config.schema.json`](../schemas/sb-config.schema.json).

It is **generated from the Rust types** that the runtime parses,
not hand-rolled, so it cannot drift from the binary. The
[`crates/sbproxy-config/src/types.rs`](../crates/sbproxy-config/src/types.rs)
file is the source of truth; every `pub struct` and `pub enum`
reachable from `ConfigFile` derives `schemars::JsonSchema`, and
[`generate-schema.rs`](../crates/sbproxy-config/src/bin/generate-schema.rs)
emits the JSON via `schemars::schema_for!(ConfigFile)`.

## Editor opt-in

Add one comment header at the top of your `sb.yml`:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action: { type: proxy, url: http://127.0.0.1:9000 }
```

Every `examples/*/sb.yml` in this repo carries the same header
(with a relative `../../schemas/...` path) so the in-repo
examples self-validate against the schema operators consume.

The directive is a YAML comment, so a runtime that does not
understand it ignores the line. The schema does not change the
config format; it just teaches the editor what to flag.

## What you get

* **Field-name autocomplete**. Tab-complete on `proxy.` shows
  every top-level field the runtime accepts.
* **Type validation**. Typing a string where the field expects
  an integer underlines red.
* **Enum hints**. Closed enums (`admin.operators[].role:
  read_only | admin`) drop down the allowed values.
* **Inline docs**. The doc comment on every `pub struct` field
  in `types.rs` lands in the schema's `description`, so an
  editor that surfaces tooltips shows the same description the
  rustdoc surfaces.

## Regenerating the schema

After editing a Rust type in `crates/sbproxy-config/src/types.rs`,
regenerate the committed schema:

```bash
cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
```

The CI gate runs the same command and diffs the result against
the committed file; a Rust type change that does not regenerate
the schema fails the `config schema is current` step
on the `build / test` job. The generator is deterministic (the
`preserve_order` feature on `schemars` pins object property
order across runs), so the diff is byte-for-byte.

## Caveats

* **Free-form extension fields**. The `extensions:` map under
  `proxy:` and `origins[]:` accepts arbitrary user-defined keys
  (the runtime forwards them to extension consumers without
  parsing). The schema models these as
  `Map<String, Object>`; an editor will not warn on unknown
  keys inside an `extensions:` block. This is intentional.
* **Schema dialect**. The output is JSON Schema draft-07. Every
  editor in our compatibility list supports draft-07; the
  upgrade to draft-2020-12 is gated on the
  [yaml-language-server's draft-2020-12 PR](https://github.com/redhat-developer/yaml-language-server/pulls)
  shipping a stable release.
* **`$ref` indirection**. Reusable types (e.g. `PathMatcher`,
  `HeaderMatcher`) appear as `$ref: #/definitions/X` references
  rather than inlined. Editors resolve these transparently;
  tools that diff the schema across versions can use
  [json-schema-diff](https://github.com/Stranger6667/jsonschema)
  to flag breaking changes.

## See also

* [`configuration.md`](configuration.md) - the prose reference
  for every `sb.yml` field; the schema is the machine-readable
  companion.
* [`schemas/README.md`](../schemas/README.md) - one-line pointer
  back to the generator + the editor opt-in line.
