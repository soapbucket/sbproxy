# Local extension bundles

*Last modified: 2026-08-02*

This example loads six extension bundles from a directory next to `sb.yml`. Three routes exercise five HTTP hooks. Four more JavaScript hooks receive normalized AI events, one JavaScript hook receives credential-free payment events such as x402 verification, and the Proxy-Wasm module also handles live AI stream events.

## Run the HTTP hooks

From the repository root:

```bash
sbproxy validate examples/extension-bundles/sb.yml
sbproxy doctor examples/extension-bundles/sb.yml
sbproxy serve -f examples/extension-bundles/sb.yml
```

The TypeScript policy requires one header. Its source is transpiled once when the candidate loads. After the policy admits the request, the JavaScript action creates a response and the JavaScript transform replaces its body:

```bash
curl -i -H 'Host: javascript.extension.local' \
  http://127.0.0.1:8080/
# HTTP/1.1 403
# missing x-extension-example

curl -i -H 'Host: javascript.extension.local' \
  -H 'X-Extension-Example: present' \
  http://127.0.0.1:8080/
# HTTP/1.1 200
# hello from a JavaScript transform
```

The second route invokes the native sbproxy envelope ABI from a WASI preview 1 module:

```bash
curl -i -H 'Host: wasm.extension.local' \
  http://127.0.0.1:8080/
# HTTP/1.1 202
# queued
```

The third route proxies to the project's public echo service. Its Proxy-Wasm HTTP filter stamps the upstream response before sbproxy sends it downstream:

```bash
curl -i -H 'Host: filtered.extension.local' \
  http://127.0.0.1:8080/echo
# HTTP/1.1 200
# x-extension-filter: proxy-wasm
```

## Inspect what loaded

`doctor` evaluates the stopped candidate. The admin endpoint reports the running generation:

```bash
sbproxy doctor examples/extension-bundles/sb.yml --format json \
  | jq '.extensions.summary, .extensions.bundles, .extensions.hooks'

curl -fsS -u admin:worked-example \
  http://127.0.0.1:9090/api/extensions \
  | jq '{scope, summary, bundles, hooks}'
```

The doctor scope is `doctor`, and its hooks report `not_evaluated`. The admin scope is `running`, so an attached action, policy, transform, or filter can be `active` while an event hook that has not been selected by the config remains available or unconsumed.

## Prove reload safety

The real-process reload test publishes generation one, reloads to generation two, then rejects a candidate whose JavaScript module no longer exports its declared hook. Requests continue through generation two after that rejection:

```bash
cargo test -p sbproxy-e2e --test extension_bundles
```

## Build the WASM artifacts

The committed `.wasm` files let the example run without a compiler. Their WAT sources sit beside them. Rebuild both after changing either source:

```bash
examples/extension-bundles/build-wasm.sh
```

Then calculate SHA-256 over the final entry bytes and replace the matching `sha256:` value in `bundle.yaml`:

```bash
# macOS
shasum -a 256 examples/extension-bundles/bundles/queued-envelope-wasm/action.wasm
shasum -a 256 examples/extension-bundles/bundles/ai-stream-proxy-wasm/filter.wasm

# Linux
sha256sum examples/extension-bundles/bundles/queued-envelope-wasm/action.wasm
sha256sum examples/extension-bundles/bundles/ai-stream-proxy-wasm/filter.wasm
```

The digest is exact and case-sensitive. It is the 64 lowercase hexadecimal characters only, without a `sha256:` prefix.

## AI and payment events

The `ai-events` bundle exports hooks for `guardrail_input`, `tool_call`, `guardrail_output`, and `close`. Each function receives the same provider-neutral envelope and returns a strict `release`, `flag`, or `block` decision.

The `ai-stream-proxy-wasm` bundle receives normalized AI stream events through Proxy-Wasm ABI 0.2.1 request-body callbacks. Its `example_http_filter` registration powers the third live route above.

The `payment-events` bundle receives bounded lifecycle facts. For x402, `event.rail` is `x402`, `event.method` is `exact`, and fields can include the CAIP-2 network, asset, amount, request ID, and intent ID. Payment credentials and raw provider responses are not present. A `started` event can return `continue` or `reject`; terminal outcomes are observation-only.

The focused test drives all of these adapters with representative events:

```bash
cargo test -p sbproxy-extension --test published_bundle_examples
```

## TypeScript is a load-time convenience

sbproxy adds no TypeScript CLI, package manager, install command, module loader, or runtime dependency resolution. A dependency-free `.ts` entry can be transpiled while a candidate loads. Imports, re-exports, and dynamic `import()` calls are rejected.

If your code uses dependencies, resolve them in your own build and ship one prebuilt flat `.js` artifact. Point `entry:` at that file and calculate the digest from those final bytes.
