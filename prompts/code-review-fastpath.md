# SBproxy code review: fast path, simplification, duplication

You are reviewing the SBproxy codebase, a Rust reverse proxy built on Pingora (~28 crates under `crates/`, ~280k lines). Your job is to find concrete, verifiable improvements in three areas, ranked by impact:

1. **Fast-path performance**: code executed once per proxied request must be lean.
2. **Simplification**: less code doing the same job.
3. **Duplication and anti-patterns**: repeated logic and non-idiomatic Rust.

This is a review, not a refactor. Report findings; do not edit code. Every finding must cite `file:line` and be verified by reading the actual code, not inferred from names.

## Scope

Review `crates/` in the `sbproxy/` repo. Weight your time toward the per-request path:

- `crates/sbproxy-core/src/server/proxy_http.rs` and `server/request_phase.rs`: the Pingora `ProxyHttp` phase callbacks (request_filter, upstream_peer, request/response filters, body filters, logging). Everything here runs for every request.
- `crates/sbproxy-core/src/pipeline.rs`: route matching (path templates, header and query matchers, `match_request`).
- `crates/sbproxy-core/src/dispatch.rs`, `context.rs`, `hooks.rs`: per-request dispatch, request context construction, hook invocation.
- `crates/sbproxy-middleware`, `crates/sbproxy-httpkit` (buffer pool), `crates/sbproxy-transport`: per-request plumbing.
- `crates/sbproxy-ai`, `crates/sbproxy-classifiers`, `crates/sbproxy-security`: run inline on AI-gateway requests; treat as hot when invoked per request.

Cold path (startup, config parsing, `admin*.rs`, `reload.rs`, k8s operator, CLI): review only for simplification and duplication. Do not flag micro-optimizations there; clarity wins on the cold path.

Out of scope: `target/`, `e2e/` test fixtures, the archived Go `proxy/` tree, generated schemas.

## Pass 1: fast path

For each hot file, hunt for:

- **Per-request allocation**: `format!`, `to_string()`, `to_owned()`, `String::from`, `Vec::new` + push, and `collect()` inside request handling where a borrow, `&str`, `Cow`, `SmallVec`, or a pooled buffer would do. Header values compared via allocation instead of `eq_ignore_ascii_case` on bytes.
- **Clone pressure**: `.clone()` on request/response data, config snapshots, or large structs where an `Arc` clone or a borrow suffices. (`server.rs` has ~44 `.clone()` calls and `pipeline.rs` ~20; classify each on the hot path as cheap-Arc, necessary, or avoidable.)
- **Work that belongs at config-load time**: regexes, path templates, CIDR lists, or matchers compiled or sorted per request instead of once at reload. `pipeline.rs::compile` exists; verify every matcher actually goes through a compiled form and nothing re-parses per call. `trustworthy_cidrs()` / `untrusted_cidrs()` return fresh `Vec`s; check whether they are called per request.
- **Locking**: `Mutex`/`RwLock` acquired per request, especially held across `.await`. Read-mostly shared state should be `ArcSwap`, atomics, or a snapshot cloned at request start. Flag any global counter that serializes requests.
- **Linear scans**: routes, keys, or policies matched by iterating a `Vec` when the set is large enough to warrant a prefix trie, `matchit`-style router, or `HashMap` keyed lookup. Note the expected cardinality when judging.
- **Body handling**: buffering a full body where streaming works, copying between buffers instead of reusing `bytes::Bytes` slices, bypassing the httpkit buffer pool.
- **Async overhead**: `async` fns that never await, `Box<dyn Future>` or `#[async_trait]` indirection on the per-request path where a plain call or enum dispatch would do, per-request `tokio::spawn` for work that could run inline.

For each finding, state the per-request cost (allocation, lock, syscall, O(n) scan) and the concrete cheaper alternative. No speculative "might be faster" items; if you cannot articulate the cost, drop the finding.

## Pass 2: simplification and duplication

- **Duplicate functions**: the same logic implemented in more than one place. Likely suspects across 28 crates: header parsing/normalization helpers, CIDR/IP trust checks, retry/backoff loops, error-to-HTTP-response mapping, JSON body inspection, token counting. Search by signature shape and by distinctive string constants, not just function names. Report each cluster with all locations and which copy should become canonical (usually `sbproxy-httpkit` or `sbproxy-core`).
- **Copy-paste variants**: near-identical blocks differing in one type or literal; propose the single generic or parameterized version only if it is genuinely simpler than the copies.
- **Over-abstraction**: traits with exactly one implementation, builder patterns for structs constructed in one place, generics with a single instantiation, layers that only forward. `wave8.rs` and similarly wave-named modules deserve a look for scaffolding that outlived its feature.
- **Dead code**: pub items with no non-test callers (workspace-wide grep before claiming dead), feature-gated paths whose feature is never enabled, config options parsed but never read.
- **Structural simplification**: deep nesting that early returns would flatten, `match` arms that collapse, hand-rolled logic where a std or already-imported-dependency method exists. Large files are a signal, not a finding: `server.rs` (3.2k lines), `admin.rs` (3k), `pipeline.rs` (2.8k) likely contain separable concerns; only propose splits along real seams.

## Pass 3: anti-patterns

Rust-specific, on any path:

- `unwrap()`/`expect()`/`panic!` reachable from request handling (a poisoned request must not take down the worker; Pingora phases should return errors).
- Blocking calls in async context: `std::fs`, `std::net`, blocking channel recv, or a `std::sync::Mutex` held across an await.
- Unbounded growth: channels without capacity, per-request inserts into maps with no eviction, retry loops without a ceiling.
- Clone-to-appease-the-borrow-checker where restructuring removes the clone.
- Stringly-typed enums (matching on `&str` constants that should be an enum), booleans-as-flags trios that should be one enum.
- `anyhow` in library crates' public APIs where callers need to match on error kinds (`thiserror` territory); `anyhow` is fine in the binary.
- Collect-then-iterate chains, `return`ed `impl Iterator` re-collected at every call site.

## Style (per google/comprehensive-rust STYLE.md)

Apply its durable code rules: code formats clean under `rustfmt` with standard spacing; names are meaningful and domain-derived, never `Foo`/`Bar`/`data`/`tmp`/`handle_stuff`; examples and helpers stay short and functional. Flag names that describe the mechanism instead of the meaning, and modules whose names no longer match their contents (e.g. wave-numbered modules). Style findings are the lowest severity tier; do not let them crowd out the passes above.

## Verification and output

Before reporting, verify each finding: read the surrounding code, confirm the code path is actually reachable per request (for fast-path items), and workspace-grep before calling anything duplicate or dead. Discard anything you cannot confirm.

Report findings ranked by impact, most severe first:

```
### N. <one-line summary>
- Category: fast-path | duplication | simplification | anti-pattern | style
- Location: <file:line> (all locations for duplication clusters)
- Evidence: what the code does today, quoted or paraphrased tightly
- Cost: the per-request or maintenance cost, stated concretely
- Suggested change: the specific cheaper or simpler form
- Risk: low | medium | high, with the behavior that must be preserved
```

Finish with a short summary: finding counts per category, the three changes with the best cost/risk ratio, and anything you flagged as suspicious but could not confirm (listed separately, clearly marked unverified).

Constraints if fixes are later applied from this review: behavior must be preserved exactly; the archived `proxy/` Go tree is never touched; changes gate via `./scripts/check.sh`; any crate constructing a struct whose definition changes must be checked workspace-wide.
