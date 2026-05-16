# Cloudflare Code Mode
*Last modified: 2026-05-15*

SBproxy can emit a typed TypeScript module covering every tool in the
MCP federation registry. Agents written against the [Cloudflare Code
Mode](https://blog.cloudflare.com/code-mode/) runtime can import the
module and invoke each tool as an ordinary async function. Code Mode
compresses a large tool catalog from many tool-call JSONs down to a
single typed module, cutting the agent's token spend by roughly an
order of magnitude on large surfaces.

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
  search_docs: (input: SearchDocsInput): Promise<SearchDocsOutput> =>
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

```rust
let federation: McpFederation = // ... built at startup
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

Property names that collide with TypeScript reserved words or
contain non-identifier characters are emitted as string-quoted keys
(`'class':`, `'with-dash':`).

## Streaming tools

Streaming MCP tools are out of scope for the initial emission. The
runtime stub posts and waits for a JSON response. A follow-up will
emit `AsyncIterable<T>`-typed signatures and add server-sent-event
plumbing to the stub.

## HTTP endpoint

Serving the module over HTTP at a well-known URL is the natural next
step. The current PR ships the emitter as a library function on the
federation registry so any HTTP wiring layer can hand the bytes
through to the client. A future ticket will land the
`/.well-known/mcp/codemode.ts` route on the proxy itself, with
caching, Etag, and workspace + RBAC filtering wired against the
same predicates the existing agent-skills endpoint uses.

## References

- Code Mode: the better way to use MCP (Cloudflare blog): https://blog.cloudflare.com/code-mode/
- Code Mode SDK changelog v0.2.1: https://developers.cloudflare.com/changelog/post/2026-03-17-codemode-sdk-v021/
- Code Mode for MCP server portals (Cloudflare changelog): https://developers.cloudflare.com/changelog/post/2026-03-26-mcp-portal-code-mode/
- Cloudflare Agents docs: https://developers.cloudflare.com/agents/api-reference/codemode/
