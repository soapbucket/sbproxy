# Extension Bundles
*Last modified: 2026-08-13*

Dynamic bundles add policies, transforms, actions, HTTP filters, and provider-neutral event hooks without linking a new proxy binary. A local installation is a directory of bundle directories:

```text
examples/extension-bundles/
├── sb.yml
└── bundles/
    ├── hello-javascript/
    │   ├── bundle.yaml
    │   └── entry.js
    └── queued-envelope-wasm/
        ├── bundle.yaml
        └── action.wasm
```

Point the config at the parent directory:

```yaml
extensions:
  bundles_dir: bundles
```

A relative `bundles_dir` uses the directory containing `sb.yml` as its base. The loader visits each child directory, reads its `bundle.yaml`, then reads the declared entry artifact without following a path outside that bundle. The runnable layout is in [examples/extension-bundles](../examples/extension-bundles/).

Git sources use the same bundle layout from a verified checkout:

```yaml
extensions:
  sources:
    - type: git
      repo: https://github.com/acme/sbproxy-extensions.git
      revision: production
      path: bundles
      credential: secret://primary/extension-git-token
      verify_signature: true
      timeout_secs: 60
      refresh_interval_secs: 60
```

`revision` must be a full 40- or 64-character commit SHA, or a reference whose tag or commit Git can verify when `verify_signature: true`. Every Git bundle must also declare a `sha256`; see [What the digest covers](#what-the-digest-covers) for how much of the bundle that digest is a digest of. A relative `path` stays inside the verified checkout.

`credential` is a secret reference, not a token literal. It accepts the same `env:NAME`, `${NAME}`, `file:/path`, `secret://`, and provider-backed references as the rest of the config. SBproxy resolves it through the process secret resolver and gives Git command-scoped HTTP authorization. The resolved value is not added to the repository URL, Git arguments, checkout metadata, logs, errors, or extension inventory. SSH repositories continue to use the host's SSH credentials.

`refresh_interval_secs` accepts `0` or 1 through 86400. Zero fetches at startup and on ordinary reload only. Positive values start one jittered refresh loop at the shortest enabled interval across all Git bundle sources. An unchanged set of verified commits skips publication. A changed source builds and validates the complete registry, then uses the normal atomic reload transaction. Fetch, digest, export, runtime, or lifecycle failure leaves the last verified generation serving.

`GET /api/extensions` keeps the redacted repository, requested reference, verified commit, and latest refresh health in each Git bundle's bounded `load.detail`. It never includes the credential reference or resolved value.

## Bundle manifest

This JavaScript bundle exports one action and one transform:

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: hello-javascript
version: 1.0.0
runtime: javascript
entry: entry.js
sha256: 42c3e04fdb8ad0d2539fb743311d49bf498394c46c73df0999ff0b2e07061fb4
hooks:
  - kind: action
    type: hello_javascript
    export: respond
    config_schema:
      type: object
      additionalProperties: false
      properties:
        response_header:
          type: string
          default: x-extension-runtime
      required: [response_header]
  - kind: transform
    type: example_javascript_transform
    export: transformResponse
failure_posture: closed
sandbox:
  budget_ms: 50
  memory_mb: 16
  stack_kb: 512
  max_buffer_bytes: 1048576
  max_output_bytes: 1048576
  max_fuel: 100000000
permissions: []
```

- `apiVersion` is `sbproxy.dev/v1alpha1` and `kind` is `Bundle`.
- `name` is a stable lowercase bundle ID. Each hook `type` is the name used in `sb.yml`.
- `runtime` is `javascript`, `wasm`, or `proxy_wasm`.
- `entry` is a file inside the bundle directory. JavaScript accepts `.js` or `.ts`; both WASM runtimes accept `.wasm`.
- `sha256` pins a digest and `digest_scope` says what that digest is a digest of. The example above omits `digest_scope`, so it means `entry`, the narrower of the two scopes. See [What the digest covers](#what-the-digest-covers).
- `hooks` declares at least one typed hook. A JavaScript hook names its ES module export. WASM hooks omit `export`.
- `config_schema` is an optional Draft 7 JSON Schema for one attachment. Defaults are applied before the hook starts, and invalid attachment config refuses the candidate.
- `secret_vars` names `config_schema` properties that hold a secret. Each is resolved through the same [reference forms](secrets.md) any other secret-bearing field accepts (`${VAR}`, `env:NAME`, `file:`, or a provider URI) before the hook ever runs; an unresolvable reference refuses the candidate. A property not listed here is never inspected for a reference, so resolution is always something a bundle author declared, not something the config compiler guessed at.
- `masked_vars` names `config_schema` properties to keep out of logs, errors, and diagnostics without resolving them, for a sensitive literal that is not a secret reference (a tenant ID, an internal hostname). Both lists require the named property to exist in `config_schema`, and a property cannot appear in both.
- `failure_posture` defaults to `closed`. `open`, `degraded`, and `observe` are only valid where that hook contract defines them. An `action` hook is terminal and accepts only `closed`, because there is nothing to fall through to when it fails.
- `sandbox` bounds wall time, memory, stack, buffered input, output, and WASM fuel. The values shown are the defaults.
- `permissions` must remain empty in this release. Bundle code receives no filesystem or network capability. That empty list is what makes the guarantee true, so under `digest_scope: bundle_v1` it is inside the signed content along with the rest of the manifest.

Hook types cannot replace a built-in or linked registration of the same kind. Duplicate claims fail candidate construction instead of choosing a winner by load order.

Where a hook's `failure_posture` applies, an attachment in `sb.yml` can override it. The precedence has three steps, and it matters that the middle one exists:

1. An explicit `failure_posture` (or the legacy `fail_on_error`) written on the attachment. The operator wiring the bundle into an origin outranks whoever wrote the bundle.
2. The bundle manifest's own `failure_posture`.
3. The attachment's default, which for a `transforms:` entry is `open`.

Writing nothing on the attachment is not the same as writing `open` there. A bundle that ships `failure_posture: closed` keeps it unless you say otherwise, which is what makes step two worth having: the bundle author's judgment about their own hook is the fallback, not the wrapper's default.

## What the digest covers

`sha256` is 64 lowercase hexadecimal characters with no `sha256:` prefix. `digest_scope` says how much of the bundle those characters are a digest of, and there are two answers.

`digest_scope: entry` is the default and covers the exact bytes of the single file named by `entry`. Nothing else: not `bundle.yaml`, not the WAT or TypeScript source used to build the entry, not any other file in the directory. Every manifest written before `digest_scope` existed means this, which is why it stays the default.

Read that scope carefully before relying on it, because the manifest sits outside it. `bundle.yaml` is where a bundle's hook kinds, sandbox limits, failure posture, and `permissions` live, and an empty `permissions: []` is the line that guarantees guest code gets no filesystem or network capability. Pinning the code while leaving the file that grants its capabilities unpinned is the verification the wrong way round.

`digest_scope: bundle_v1` covers `bundle.yaml` and every other file the bundle ships:

```yaml
sha256: 1f0a4c7e6b25d3908c11a4f52e7b0d63c9a8f4e21b5d7c6083ae95f2d41b7c60
digest_scope: bundle_v1
```

### How a bundle_v1 digest is built

The digest is a SHA-256 over a text index, one line per file:

```text
sbproxy-bundle-digest/v1
<64 lowercase hex of the file's content>  <bundle-relative path>
...
```

The rules that make the same directory produce the same value on any machine:

- **Ordering.** Lines sort by bundle-relative path, comparing UTF-8 bytes ascending, which is what `LC_ALL=C sort` gives you. `bundle.yaml` takes its natural place in that order rather than a reserved slot.
- **Separator.** Path components join with `/` on every platform.
- **The path is hashed, not only the bytes.** Each line carries the file's path, so giving two files each other's names changes the index even though the set of content hashes did not move.
- **Coverage.** Every regular file in the directory, recursively. Empty directories carry no content and do not appear.
- **Self-exclusion.** A digest cannot be inside its own input, so `bundle.yaml` contributes the hash of its own bytes with the single top-level `sha256:` line deleted, terminating newline included. That is exactly `grep -v '^sha256:' bundle.yaml`, and nothing else in the file is rewritten, reordered, or normalized. The manifest has to be UTF-8, has to end with a newline, and has to write `sha256` as one unquoted top-level key with its value on the same line. Anything else refuses the bundle instead of guessing which bytes to drop.
- **File modes are not covered.** Mode bits do not survive the transports a bundle travels through, and sbproxy reads guest files into a sandbox rather than executing them from disk, so the executable bit grants a bundle nothing the digest would be protecting.
- **Symlinks are refused, never followed.** The bytes a symlink names live outside the hashed content, and one pointing out of the bundle directory reads a file you never shipped. Any symlink anywhere in the directory refuses the bundle.
- **File names have to be portable.** A name that is not valid UTF-8, or that carries a control character, `/`, or `\`, refuses the bundle. A name holding a newline could otherwise forge an index line.

Content is hashed byte for byte, so a checkout that rewrites line endings produces a different digest. Add `* -text` to a `.gitattributes` beside the bundle if anyone on your team runs `core.autocrlf`.

One bundle may ship at most 512 files, nested at most 8 directories deep, at most 16 MiB per file and 64 MiB in total.

### Computing a digest

Under `digest_scope: entry`, one command over the final entry artifact:

```bash
# macOS
shasum -a 256 bundles/hello-javascript/entry.js

# Linux
sha256sum bundles/hello-javascript/entry.js
```

Under `digest_scope: bundle_v1` no single command produces it, so the repository ships the recipe:

```bash
scripts/bundle-digest.sh bundles/hello-javascript
```

The script is a convenience for bundle authors and is not part of the trusted path. sbproxy recomputes the digest itself on every candidate load and compares against the manifest.

Copy the value into `bundle.yaml` only once every file in the bundle is final, and recompute it after any later edit to any of them.

### What a mismatch does

A mismatch refuses startup, `sbproxy validate`, doctor candidate inspection, or reload before the candidate can become active. So does an unreadable file, a symlink under `bundle_v1`, a manifest that cannot be canonicalized, and a bundle over any of the limits above. None of these warn and continue. The previous generation keeps serving, and no hook from the refused candidate reaches the running registry.

Local directory bundles may omit `sha256` entirely, which pins nothing at all. Production bundles should pin it, and Git-sourced bundles must.

### Moving a bundle to bundle_v1

Bundles already in production keep loading untouched, and the two scopes coexist across bundles in the same installation. To upgrade one:

1. Run `scripts/bundle-digest.sh <bundle-directory>`.
2. Replace that manifest's `sha256` value with what the script printed.
3. Add `digest_scope: bundle_v1` beside it.

A manifest that declares `digest_scope: bundle_v1` without a `sha256` fails validation rather than loading with nothing pinned.

## JavaScript and load-time TypeScript

JavaScript and TypeScript entries are ES modules with named exports. The host passes one JSON value to the selected export and accepts one strict JSON result. For the configurable HTTP hooks:

| Hook | Input field | Valid result |
|---|---|---|
| `policy` | `request` plus `config` | `allow` or `deny`, with bounded status, message, and headers |
| `transform` | `body.body_base64`, `body.content_type`, `body.origin`, plus `config` | A replacement `body_base64` |
| `action` | `request` plus `config` | A bounded local `response` with status, headers, and `body_base64` |

Every input and result carries `"version": "sbproxy-envelope/v1"`. Unknown result fields, invalid headers, invalid base64, or an out-of-range status fail the invocation.

A hook that ends the request has to return a status the client can act on, so two further rules apply to any response a bundle produces, including a Proxy-Wasm local response:

- The status must be final, in the range 200 to 599. An informational 1xx says "keep going", but the host has already stopped dispatch by the time it sees the result, so the caller would wait for a final status that never arrives. A 1xx is refused before any byte is written.
- A 204 or a 304 must carry an empty body. Those statuses carry no content by definition, and framing a body under one desynchronizes an HTTP/1 connection. A guest body there is refused rather than dropped, because dropping it would leave a bundle that believes it is returning content looking like it works.

Both refusals name the status and nothing else. No guest-supplied bytes reach the error, so a bundle cannot use a rejection to place content in the operator's logs.

An action bundle finishes the request locally. Its attachment has no upstream configuration, so returning `outcome: "proxy"` fails with `unsupported_action_outcome`. Configure a concrete `type: proxy` or `type: load_balancer` action when the origin should forward traffic. For extension logic around a forwarded stream, attach a Proxy-Wasm filter to that concrete action.

A `.ts` entry is parsed and stripped to ES2020 JavaScript exactly once while a candidate loads. Every declared export is preflighted then. TypeScript is a source convenience; the runtime is still JavaScript.

sbproxy adds no TypeScript CLI, package manager, install command, module loader, or runtime dependency resolution. Imports, re-exports, and dynamic `import()` are rejected. If the extension uses dependencies, resolve them in your own build and ship one prebuilt flat `.js` artifact. Point `entry` at that final artifact and calculate its digest from those final bytes.

## Envelope WASM

An envelope WASM manifest uses:

```yaml
runtime: wasm
abi: sbproxy-envelope/v1
entry: action.wasm
```

The artifact is a WASI preview 1 command module with an exported `_start`. On each invocation, sbproxy creates a fresh Wasmtime store, writes the same versioned JSON hook envelope to stdin, runs `_start`, and parses one strict JSON result from stdout. The module receives no filesystem, network, environment, or host-clock access. The compiled module is shared, but guest state is not.

The worked example keeps `action.wat` beside the committed `action.wasm` and rebuilds it with `wat2wasm`. A production build can use any language that emits a compatible WASI preview 1 command module.

## Proxy-Wasm HTTP and AI stream hooks

A Proxy-Wasm manifest uses ABI 0.2.1 and may declare only `proxy_wasm` or `ai_stream_event` hooks:

```yaml
runtime: proxy_wasm
abi: 0.2.1
entry: filter.wasm
hooks:
  - kind: proxy_wasm
    type: example_http_filter
    execution:
      body_mode: streamed
```

Attach HTTP filters to an origin in request order:

```yaml
origins:
  "filtered.extension.local":
    action:
      type: proxy
      url: https://api.example.com
    filters:
      - type: example_http_filter
        config:
          label: worked-example
        failure_posture: closed
```

`filters` is an ordered list of `type`, `config`, and an optional `failure_posture` override. Body access comes from each manifest hook, not from the attachment. The chain buffers only when at least one attached filter declares `buffered`, using the smallest configured input limit among filters that consume a body. `none` plus `streamed` still streams, while a `none`-only chain passes bodies through untouched.

An origin with filters must use a proxy action. If it has forward rules, every action those rules can select must also be a proxy action. A filtered origin cannot configure `fallback_origin`. Candidate validation rejects any other combination before publication.

The host implements a bounded HTTP subset of Proxy-Wasm. Unsupported imports fail candidate load. A callback that returns `Pause` without resolving it is treated as a filter failure, so a guest cannot leave a request stalled. The attachment or bundle failure posture decides whether traffic is admitted or refused after that failure.

For `ai_stream_event`, sbproxy maps normalized AI chunks onto Proxy-Wasm request-body callbacks and keeps one filter session for the model stream. The manifest must declare `body_mode: streamed`. JavaScript and envelope WASM do not accept this hook kind.

## AI events

AI hooks receive a provider-neutral event with `schema_version: 1`, a monotonically increasing request-local `sequence`, optional `request_id` and `model`, and one payload:

| Manifest kind | Event payload |
|---|---|
| `ai_guardrail_input` | Canonical messages and an evaluation stage such as `original` |
| `ai_tool_call` | One complete tool call with assembled JSON arguments |
| `ai_guardrail_output` | Canonical buffered assistant text |
| `ai_stream_event` | Normalized message-start, text-delta, usage, or message-stop chunk |
| `ai_close` | One terminal summary with finish reason, byte and delta counts, tool-call count, and token usage when known |

JavaScript and envelope WASM AI hooks return `release`, `flag`, `block`, or `mutate`. A `block` carries an HTTP status from 400 through 599 plus a bounded code and client-safe message. A `flag` carries the code and message but does not stop traffic. `enforcement_mode: observe` moves a hook onto a bounded observation lane; the default `block` mode waits for the decision before releasing the corresponding operation or bytes.

A `mutate` rewrites the event's content in place and releases it. The decision carries a bounded `code` and a `body_base64` payload holding the replacement content: plain UTF-8 text for `ai_guardrail_output`, the JSON of the canonical message list for `ai_guardrail_input`, and the JSON of the complete call object for `ai_tool_call`. The host applies the rewrite before the next hook runs, so hooks compose: a redactor followed by a classifier classifies the redacted content. What ships is the rewritten content, spliced back into the provider-shaped body; a rewrite the body shape cannot faithfully carry (for example, one replacement text against a multi-choice completion) refuses the response rather than shipping the original.

A rewritten tool call replaces the held argument fragments with one canonical frame carrying the whole call. Three rewrites refuse as unrepresentable: a changed `index` (the call's identity is host-owned), `arguments_json` that does not parse as JSON (the frame carries it into a field clients parse), and any rewrite of a call whose assembled arguments were truncated at the stream buffer cap, because an edit of a prefix must not ship as if it were the whole value.

The input splice is content-only. The canonical message list is a lossy view (it carries no tool calls, drops non-text content parts, and folds provider role spellings), so the host never rebuilds the body from it: the original request stays authoritative, and only the text of messages the rewrite actually changed lands back in its original slot. Tool calls, images, and role spellings on untouched messages survive byte for byte. A rewrite that adds, removes, reorders, or relabels messages, or changes a message whose content has more than one text part, refuses as unrepresentable.

Mutation is declared, not inferred. A hook may return `mutate` only when its manifest entry sets `execution.mutates: true`, which is accepted on `ai_guardrail_input`, `ai_guardrail_output`, and `ai_tool_call` hooks; declaring it elsewhere, or combining it with `enforcement_mode: observe` (whose decisions are discarded), refuses at config load. An undeclared or oversized rewrite (the payload is capped by `sandbox.max_buffer_bytes`) is an engine fault handled under the bundle's failure posture: refused under `closed`, released unmodified under an admitting posture. Identity fields such as `sequence` and `request_id` are host-owned and cannot be rewritten.

## Payment and x402 events

A payment hook declares `execution.body_mode: none`. It receives a credential-free lifecycle event with `schema_version: 1`, a phase (`challenge`, `verify`, `settle`, or `reconcile`), an outcome, rail, monetary amount, and bounded identifiers. Optional fields include method, network, asset, intent ID, request ID, and a sanitized provider reference after success.

x402 uses the shared payment extension ABI as a rail. An x402 verification can report `rail: x402`, `method: exact`, a CAIP-2 network such as `eip155:84532`, and an asset such as `USDC`. Raw payment credentials and raw provider responses never enter the event.

For a `started` outcome, a blocking hook returns `continue` or `reject` before the provider write or access release. Terminal outcomes (`succeeded`, `rejected`, `failed`, `ambiguous`, or `unsupported`) are observation-only. A terminal return value cannot reverse a payment or retroactively deny access.

## Candidate load and reload

Startup, `sbproxy validate`, `sbproxy doctor <config>`, the file watcher, `SIGHUP`, and `POST /admin/reload` all build a candidate before publication. Candidate construction checks the source path, manifest, declared digest at its declared scope, hook collisions, config schemas, JavaScript or TypeScript exports, and WASM module contract. The running registry and pipeline generation swap together only after every required check succeeds.

If a bundle edit has a bad digest, syntax error, missing export, unsupported import, invalid WASM module, or conflicting hook name, reload rejects that candidate and the prior generation keeps serving. No hook from a rejected candidate leaks into the running registry.

Use the two inventory views for different questions:

- `sbproxy doctor sb.yml --format json` reports a stopped `doctor` snapshot. `active` means the candidate selected and wired the hook after preparing its chain. It does not mean traffic ran or that a runtime health check passed. A hook that loaded but has no attachment is `unconsumed`. `not_evaluated` is reserved for the loader-level fallback when doctor cannot finish candidate construction.
- Authenticated `GET /api/extensions` reports the `running` generation, including active, available, unconsumed, failed, or shadowed state, chain position, execution limits, and collisions. AI hooks become active with their compiled lifecycle chain. Payment hooks become active after the payment dispatcher installs successfully.

## Context from other extension systems

The design comparison points are:

- Envoy recommends Proxy-Wasm ABI 0.2.1 and loads Wasm configuration before request callbacks. See [Envoy's Wasm architecture overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/wasm) (accessed 2026-08-02).
- Kong's JavaScript plugin server can load TypeScript directly and resolve packages from `node_modules`. sbproxy intentionally does neither at runtime. See [Kong JavaScript plugins](https://developer.konghq.com/custom-plugins/javascript/) (accessed 2026-08-02).
- Apache APISIX runs external plugins in sidecar processes over a Unix-socket RPC RPC path and restarts the runner on reload. sbproxy bundle guests run inside the proxy sandbox and swap with the pipeline candidate. See [APISIX external plugins](https://apisix.apache.org/docs/apisix/external-plugin/) (accessed 2026-08-02).
- OPA activates a downloaded bundle only after verification and keeps the existing bundle when activation fails. sbproxy uses the same last-good operational model for the full pipeline candidate. See [OPA bundle management](https://www.openpolicyagent.org/docs/management-bundles) (accessed 2026-08-02).
