# WASM transform

*Last modified: 2026-04-27*

Demonstrates the `wasm` response-body transform. The upstream response body is piped through a sandboxed wasm32-wasi module: the body goes in on stdin, whatever the module writes to stdout becomes the new response body. Any wasm32-wasi binary works without custom glue. This example uses the pre-built `examples/wasm/echo-rust/echo.wasm` module which copies stdin to stdout, so the static `hello from sbproxy` body round-trips unchanged. Sandbox limits are conservative: `timeout_ms: 500` aborts modules that exceed wall-clock time via an epoch-interruption trap, and `max_memory_pages: 256` caps memory at 16 MiB (64 KiB per page). The origin is at `127.0.0.1:8080` behind the `wasm.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

The pre-built `echo.wasm` module is checked in at `examples/wasm/echo-rust/echo.wasm`. The path in `module_path` is resolved relative to the working directory the proxy is started from; use an absolute path in production.

## Try it

```bash
# Static body is read by the proxy, fed to echo.wasm on stdin, then
# emitted from the module on stdout unchanged.
$ curl -i -H 'Host: wasm.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: text/plain
content-length: 18

hello from sbproxy
```

```bash
# Replace module_path with a different wasm32-wasi binary to do real work.
# A module that uppercased its input would yield: HELLO FROM SBPROXY
```

```bash
# A runaway module is aborted at 500ms by the epoch-interruption trap.
# When fail_on_error is in effect, the response falls back to the unmodified
# upstream body via the standard transform error path.
```

## What this exercises

- `wasm` transform - pipes the response body through a wasm32-wasi module
- `module_path` - filesystem path to the compiled `.wasm` binary
- `timeout_ms` - hard wall-clock ceiling enforced via Wasmtime epoch interruption
- `max_memory_pages` - linear-memory cap, 64 KiB per page
- `static` action - canned plaintext body so no upstream is needed

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/wasm-development.md](../../docs/wasm-development.md) - authoring contract for WASI transform modules
