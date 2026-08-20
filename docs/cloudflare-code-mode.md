# Cloudflare Code Mode
*Last modified: 2026-08-19*

SBproxy can emit a typed TypeScript module covering every tool in the
MCP federation registry. Agents written against the [Cloudflare Code
Mode](https://blog.cloudflare.com/code-mode/) runtime can import the
module and invoke each tool as an ordinary async function. Code Mode
compresses a large tool catalog from many tool-call JSONs down to a
single typed module, cutting the agent's token spend by roughly an
order of magnitude on large surfaces.

See [`examples/mcp-code-mode/`](../examples/mcp-code-mode/) for a complete
working config.

## What it emits

The emitted module pairs each tool with an `Input` interface, an
`Output` interface, and a member of a `codemode` namespace whose
shape matches the `@cloudflare/codemode` runtime contract:

```ts
export interface SearchDocsInput {
  query: string;
  limit?: number;
}

export interface SearchDocsOutput {
  content?: Array<{ type: string; text?: string; mimeType?: string; [key: string]: unknown }>;
  isError?: boolean;
  [key: string]: unknown;
}

export const codemode = {
  /** Search the documentation. */
  ['search_docs']: (input: SearchDocsInput): Promise<SearchDocsOutput> =>
    __codemode_call('search_docs', input as unknown),
} as const;

export default codemode;
```

A self-contained runtime stub is appended to the module so it is
importable from any TypeScript environment that has `fetch`. The
stub posts the typed input to the gateway and parses the JSON
response. An `AGENT_GATEWAY_TOKEN` env var, when set, is forwarded
as a bearer token; callers that need a custom auth scheme can
install their own fetch via `setCodemodeFetch(...)`.

## Calling the emitter from Rust

The federation registry exposes a single method:

```rust,ignore
let federation: McpFederation = /* built at startup */;
let module_text: String = federation.codemode_ts("https://gw.example/.well-known/mcp");
```

The returned string is reproducible: tools are sorted
lexicographically before emission so an Etag derived from the body
is stable as long as the registry does not change.

## JSON Schema support

The codegen covers the subset MCP tool schemas typically use:

- `type: object` with `properties` and `required` becomes a typed
  `interface`. `additionalProperties: false` removes the index
  signature; otherwise the interface allows extension fields.
- `type: string|number|integer|boolean|null` maps to the obvious TS
  primitive.
- `type: array` with `items` becomes `Array<T>`.
- `enum` over strings becomes a TS string-literal union.
- `oneOf` / `anyOf` becomes a union.
- Nested objects inline as structural types so the parent interface
  stays compact.
- Unrecognised shapes fall back to `unknown` rather than failing
  to emit. Operators who want a tighter type can post-process or
  ask the upstream MCP server to publish a tighter schema.

Every tool name is emitted as a computed string key (`['class']`,
`['with-dash']`, and even `['__proto__']`) so upstream names always remain data
and cannot change the generated namespace object's prototype.

## Streaming tools

A tool the federation registry marks as streaming is emitted with an
`AsyncIterable<Output>` signature instead of a `Promise`, backed by a
`__codemode_call_stream` helper in the runtime stub, so the agent can
write `for await (const chunk of codemode.tool(input))`. The helper
consumes the upstream as server-sent events (one JSON object per
`data:` line) or newline-delimited JSON (`application/x-ndjson`),
yields each parsed chunk, and rejects on transport error. The
streaming helper is only appended when the catalog actually contains
a streaming tool, so a module with none stays as small as before.

## HTTP endpoint

The proxy serves the module itself: `GET
/.well-known/mcp/codemode.ts` on an MCP gateway origin returns the
emitted TypeScript with `content-type: text/typescript; charset=utf-8`.
The response
carries a strong `ETag` (the SHA-256 of the emitted bytes) and
`Cache-Control: max-age=60, must-revalidate`; a request whose
`If-None-Match` matches gets a `304 Not Modified` with no body.
Emission and hashing are cached against the registry generation, so
the ETag stays stable until the tool catalog changes.

A `draft` federated server's tools are excluded from the emitted
module, the same treatment `tools/list` gives them (see
[mcp-security-coverage.md](mcp-security-coverage.md)'s MCP09 row).
This endpoint runs ahead of per-caller authentication and its module
is cached per catalog, not per principal, so `rbac_policies`
scoping is not applied here: every caller receives the same module,
listing every non-`draft` tool regardless of which tools an RBAC rule
would let that caller actually call.

## References

- Code Mode: the better way to use MCP (Cloudflare blog): https://blog.cloudflare.com/code-mode/
- Code Mode SDK changelog v0.2.1: https://developers.cloudflare.com/changelog/post/2026-03-17-codemode-sdk-v021/
- Code Mode for MCP server portals (Cloudflare changelog): https://developers.cloudflare.com/changelog/post/2026-03-26-mcp-portal-code-mode/
- Cloudflare Agents docs: https://developers.cloudflare.com/agents/api-reference/codemode/
