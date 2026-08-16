# JSON Schema for `sb.yml`
*Last modified: 2026-08-16*

SBproxy publishes a generated JSON Schema for the typed `sb.yml` envelope.
Editors that understand the schema (VS Code with the YAML extension, the
IntelliJ / JetBrains family, Helix) can autocomplete known envelope fields,
check their types, and offer closed-enum values.

## Where it lives

The schema is committed at
[`schemas/sb-config.schema.json`](../schemas/sb-config.schema.json).

It is generated from the Rust types that parse the configuration envelope. The
[`crates/sbproxy-config/src/types.rs`](../crates/sbproxy-config/src/types.rs)
file is the source of truth; every `pub struct` and `pub enum`
reachable from `ConfigFile` derives `schemars::JsonSchema`, and
[`generate-schema.rs`](../crates/sbproxy-config/src/bin/generate-schema.rs)
emits the JSON via `schemars::schema_for!(ConfigFile)`.

The schema and runtime stay aligned for those typed fields. Runtime module
constructors own a second layer that the generated schema cannot describe.

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
config format; it teaches the editor what to flag.

## What you get

* **Field-name autocomplete**. Tab-complete on `proxy.` shows its typed
  envelope fields.
* **Type validation**. Typing a string where the field expects
  an integer underlines red.
* **Enum hints**. Closed enums (`admin.operators[].role:
  read_only | admin`) drop down the allowed values.
* **Inline docs**. Rust field comments land in the schema's `description`.

## Calling it

The runnable configuration is
[`examples/json-schema/`](../examples/json-schema/). The interesting part is
line 1, the `# yaml-language-server: $schema=` directive; the rest is a
minimal single-origin proxy.

Editor autocomplete cannot be shown here, but the schema that drives it can be
checked outside an editor, which is also how you would wire it into CI. Point
any JSON Schema validator at it:

```bash
python3 -c '
import json, yaml, jsonschema
schema = json.load(open("schemas/sb-config.schema.json"))
doc = yaml.safe_load(open("examples/json-schema/sb.yml"))
for e in jsonschema.Draft7Validator(schema).iter_errors(doc):
    print("/".join(map(str, e.path)), e.message)
'
```

That prints nothing for the shipped config. Change `http_bind_port: 8080` to
`http_bind_port: "hello"`, the exact case the section above says underlines
red, and it prints:

```
proxy/http_bind_port 'hello' is not of type 'integer'
```

The path is the same one your editor highlights, because it is the same
schema.

The binary is the second opinion, and it does not read the schema at all. It
compiles the config through the real Rust types:

```bash
sbproxy validate examples/json-schema/sb.yml
# ok: examples/json-schema/sb.yml is a valid sbproxy config
```

The same broken file fails with a message carrying the line and column:

```
validate: config '/tmp/bad.yml' did not compile:
failed to parse config YAML: proxy.http_bind_port: invalid type: string "hello", expected u16 at line 23 column 19
```

Both agree because the schema is generated from those same Rust types, which
is the property that keeps the editor from drifting from the binary. They are
not interchangeable, though: the schema catches shape errors as you type, and
`sbproxy validate` catches everything the schema deliberately leaves opaque,
including the module payloads described next. Use the schema in your editor
and `sbproxy validate` in CI.

## Opaque module payloads

Four module boundaries are deliberately opaque in the generated schema:

* `origins.<host>.action`
* `origins.<host>.authentication` (also accepted at runtime as `auth`)
* each item under `origins.<host>.policies`
* each item under `origins.<host>.transforms`

These values are stored as generic JSON and passed to the constructor selected
by their `type` field. The schema can confirm the surrounding origin shape,
but it cannot autocomplete a module's fields or reject a typo inside one of
these payloads.

Run the runtime-authoritative check before deployment:

```bash
sbproxy validate /etc/sbproxy/sb.yml
```

`validate` compiles the typed envelope and constructs the selected action,
authentication, policies, and transforms without starting listeners.

## Regenerating the schema

After editing a Rust type in `crates/sbproxy-config/src/types.rs`,
regenerate the committed schema:

```bash
cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
```

The CI gate runs `scripts/check-config-schema.sh`, which regenerates the
schema and diffs it against the committed file; a Rust type change that does
not regenerate the schema fails the `generated artifacts are current` step
on the `build / test` job (that step also runs the config-readers,
model-host-capabilities, and metrics-stability drift checks). The generator
is deterministic (the `preserve_order` feature on `schemars` pins object
property order across runs), so the diff is byte-for-byte.

## Caveats

* **Open objects**. Most typed envelope structs do not set
  `additionalProperties: false`. An editor therefore accepts an extra key in
  those objects even when the runtime later ignores it for compatibility or
  rejects it during compilation.
* **Serde aliases**. Runtime aliases such as `auth`, `session_config`,
  `l2_cache`, and several legacy field names are accepted by serde but do not
  appear as separate properties in the generated schema. An editor may flag a
  valid alias, and autocomplete favors the canonical spelling.
* **Free-form extension fields**. The `extensions:` map under
  `proxy:` and `origins.<host>:` accepts arbitrary user-defined keys
  (the runtime forwards them to extension consumers without
  parsing). The schema models these as
  an open map; an editor will not warn on unknown
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
