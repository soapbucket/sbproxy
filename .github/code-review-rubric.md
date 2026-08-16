# Code review rubric

*Last modified: 2026-08-16*

The checklist an automated reviewer runs against a branch before it
becomes a PR, and the shape its output takes so the result can be pasted
into the PR body as a note.

Nine categories: security, concurrency, logging, metrics, correctness,
code smell, Rust practices, tests, and docs.

This exists because the mechanical gates in `CLAUDE.md` answer "does it
compile, lint, and pass" and cannot answer "is this going to be a
problem in six months". Clippy does not know that a `Mutex` guard held
across a `tracing` call is fine but held across an `.await` is a
deadlock, that a label built by hand bypasses the cardinality limiter,
or that a config key deleted rather than refused goes from inert to
silently ignored. Those are the failures this catches.

## How to run it

The reviewer needs the diff. Give it the diff, do not make it guess:

```bash
git diff origin/main > /tmp/review-diff.patch
```

Then point the reviewer at both the patch and the worktree, and require
an agent type that actually has shell access. A reviewer without `Bash`
cannot run `git diff` and will silently fall back to inferring scope
from file modification times, which reads whole files it should not and
misses files it should.

Ask for findings ranked most severe first, and ask it to say what it
checked and found sound rather than padding the list.

## Severity

| Level | Meaning | What happens |
|---|---|---|
| **Blocker** | Data loss, a crash reachable from input, a cross-tenant leak, a security control that does not hold, or a silent behavior change operators cannot see | Fix before merge |
| **Major** | Correct today but fragile: an invariant held only by convention, a footgun the next caller will hit, an observability gap that makes an incident unreadable | Fix before merge, or file it and say so in the PR |
| **Minor** | Real but bounded: a needless allocation off the hot path, a missing `#[must_use]`, a doc comment that has drifted from the code | Fix if cheap, otherwise note it |
| **Sound** | Checked and correct | Say so in one line; do not pad |

A finding with no concrete failure scenario is not a finding. "This
could be cleaner" is not reviewable. "A guest writing 1 MiB to stderr
traps the call because `MemoryOutputPipe` returns `StreamError::Trap`
past capacity" is.

## 1. Security

- **Input reaching a panic.** Indexing, slicing, `unwrap`, `expect`,
  division, or arithmetic on anything derived from a request, a config
  file, or a sandboxed guest's output. This workspace runs a
  `unwrap/expect/panic` ratchet, so a new site is deliberate; the
  question is whether the invariant is enforced by construction or only
  asserted in prose.
- **Untrusted output treated as trusted.** A sandboxed guest (WASM, JS,
  Lua) returning a payload that is then used without revalidating it
  against the same limits the original passed. A hook must not be able
  to enlarge a body past `max_buffer_bytes` by returning a bigger one.
- **Cross-tenant isolation.** Anything keyed, cached, pooled, or memoized
  without tenant identity mixed in **by the host**, not by the caller and
  never by operator-supplied logic. A policy may narrow a key; it must
  never be able to widen one past its own tenant.
- **Egress and SSRF.** Any new outbound request path, and whether it
  routes through the existing SSRF guard rather than around it. An
  unrestricted fetch reachable from config is an SSRF primitive handed
  to whoever writes the config.
- **Secrets.** Any path where a resolved secret, credential, token, or
  key could reach a log line, an error string, a `Debug` impl, a metric
  label, or a panic message. Interpolated config values in error strings
  are the recurring version of this.
- **Redaction before emission.** Prompts, tool arguments, and response
  bodies reaching a log, an audit record, or an event sink without going
  through the redactor.
- **Denial of service.** Unbounded allocation, unbounded loop counts,
  unbounded retained buffers, or a cap that is checked after the
  allocation rather than before.

## 2. Concurrency and async

- **Lock held across an `.await`.** The classic deadlock, and the one
  clippy's default lints will not catch across a function boundary.
- **Lock held across a call that can panic or reenter**, including
  `tracing` macros with a custom subscriber.
- **Poisoning.** A `Mutex` whose `lock()` is `unwrap()`ed turns one panic
  into every subsequent caller panicking. Recover with
  `unwrap_or_else(|e| e.into_inner())` unless the poisoning genuinely
  should be fatal.
- **Cancellation safety.** A future that leaves shared state
  half-updated when dropped at a timeout. Accounting and billing paths
  are where this actually costs money.
- **Ordering assumptions.** Anything relying on two independent tasks
  completing in a particular order without a barrier that enforces it.

## 3. Logging and diagnosability

- **`debug!` and `trace!` are compiled out of release builds** by
  `release_max_level_info`. Anything an operator needs during a
  production incident must not live only in a debug line. The reason a
  decision was made belongs in the audit record or the access log.
- **Nothing on the hot path at `info`.** Per-request logging at `info`
  is how a proxy becomes its own load generator.
- **Failures are attributable.** A warning that says something failed
  without naming which origin, hook, tenant, or rule is not actionable.
- **Levels mean what they say.** `warn` for a fail-open or a
  declined-and-fell-back, `error` for a fault, and neither for an
  expected outcome. An `error` line that fires on a normal path trains
  operators to ignore the channel.
- **No log line is the only record of a decision.** Logs are lossy and
  rotate; a decision that matters needs a structured record too.

## 4. Metrics and observability

- **Every new metric is declared in the capability registry** with a
  live production writer. A recorder that only tests call scrapes fine
  and reads flat zero forever, which is the failure the registry exists
  to catch.
- **Label values go through the cardinality limiter.** A hand-built
  label is how a tenant id, request id, or path turns into an unbounded
  series set. Run ids, task ids, and trace ids are never labels.
- **Label arity matches the declaration.** Prometheus panics at runtime
  on a mismatch, and the panic is in whichever request happened to hit
  the new code path first.
- **Histograms do not carry high-cardinality labels.** A histogram
  multiplies its label set by its bucket count.
- **Tenant attribution is present** on anything an operator would need
  to break down per customer, and the single-tenant default still
  produces the series it produced before.
- **A fail-open is counted as a fail-open**, not folded into a success
  or an error. It is a request that proceeded without the decision being
  made, and it needs its own alert.
- **Drops are counted.** A silently lossy audit or event feed is worse
  than none: it reads as evidence of absence.

## 5. Correctness and behavior change

- **Silent no-ops.** A call site that became a no-op where a caller still
  reasonably expects work to happen.
- **An early return inside a long function.** The highest-yield check in
  this section, on the evidence. `request_filter`,
  `response_body_filter`, and `handle_ai_proxy` each run many independent
  stages in sequence, so a `return` added inside one stage silently skips
  every stage below it: mirroring, `on_request` callbacks, forward rules,
  `handle_action`, the idempotency capture. Nothing fails. A feature just
  stops happening for the subset of requests that take the new branch.
  Ask what runs *after* the block being edited, and prefer a flag that
  gates one thing to a return that gates everything. Three instances
  landed in a single change: one caught by review, two by asking that
  question before committing.
- **Removed config keys are refused, not deleted.** Config structs
  without `deny_unknown_fields` turn a deleted key from inert-and-
  documented into inert-and-ignored, which is strictly worse. Refuse at
  compile with a message naming the replacement.
- **Defaults that change behavior on upgrade.** A new field whose
  default differs from prior behavior is a breaking change wearing a
  default's clothes.
- **Error paths are as considered as happy paths.** What the request
  does when the new code fails, and whether that is stated rather than
  incidental.
- **Fallbacks are reachable and correct.** A decline path that is the
  common case must be the cheapest to express and must not be
  implemented as an error.
- **A feature that only fires from `response_filter` does nothing for
  actions that never reach that hook, and the config gives the
  operator no way to tell.** Anything that injects behavior from
  Pingora's `response_filter` (a header, a cookie, a rewrite) silently
  does nothing for `type: static` and `type: mock` origins,
  which write their response during the request phase and never reach
  `response_filter`. A 2026-08-16 pass hit this same root cause four
  independent times in one sweep of shipped examples: SRI header
  injection, session cookies, CSRF tokens, and `security_headers`'s
  richer CSP path all no-op on a `static` action while working
  correctly on `type: proxy`. Each was found separately, by unrelated
  examples, because nothing short of a live request against the
  specific action type surfaces it. When a hook lands, ask which
  action types it actually runs under, not just whether the policy or
  transform layer accepts the config.

## 6. Code smell

- **Invariants held by convention.** `[0]` after a comment saying the
  vector is never empty, when the type could have made it non-empty.
- **Duplicated vocabulary.** A second enum, label set, or error type
  describing something the codebase already names.
- **Boolean parameters** at call sites, especially several in a row.
- **Functions that grew a phase.** A function doing setup, decision, and
  emission, where the decision cannot be tested without the other two.
- **Comments explaining what rather than why.** The code says what.
- **Copy-paste with one thing changed**, particularly across match arms,
  where the changed thing is easy to get wrong and impossible to spot.
- **Dead scaffolding.** Types, variants, or fields with no production
  consumer and no ticket, which read as capability that does not exist.

## 7. Rust practices

- **`as` casts that can truncate, wrap, or lose precision.** Prefer
  `try_from` with a real error, or saturate explicitly and say so.
- **Needless allocation on a hot path**, especially `to_string()` or
  `clone()` where a borrow would do.
- **`#[must_use]`** on builders and on anything returning a value that
  is meaningless to discard.
- **`#[non_exhaustive]`** on public enums and structs that will grow.
- **Trait contracts honored.** A deliberate deviation (a `Write` impl
  that reports a full write while dropping bytes) needs a comment saying
  why, and a test pinning it.
- **Error types that carry what the caller needs to act**, rather than a
  formatted string the caller has to parse.
- **`impl Trait` and generics that leak into a public signature** and
  cannot later be changed without a break.

## 8. Tests

- **Would the test fail without the fix?** A test that passes on both
  sides of the change is documentation, not a test.
- **The seam is tested by name.** Coverage of a function is not proof it
  is wired; the call site is the thing that regresses.
- **Failure modes are tested**, not only the happy path, and especially
  the refusals a change introduces.
- **No shared-global assumptions.** A test asserting an exact value of a
  process-wide counter passes alone and fails under a parallel runner.
- **Fixtures match the shipped surface.** A test config that no operator
  could write proves nothing about the config operators do write.

## 9. Docs and examples

The category that gets skipped because it looks cosmetic. It is not: a
doc is the interface most operators actually use, and a wrong one costs
more than missing code because it is trusted.

- **Does the doc match the code, or the intent?** A number, default,
  limit, or budget stated in prose and separately defined in code will
  drift, and the prose is what an operator plans against. Check the
  constant, do not take the sentence's word for it. This review found
  `observability.md` and a rustdoc both claiming a 1000-value
  cardinality budget for a label the limiter caps at 200.
- **Does a config example actually compile?** Examples in `docs/` are
  not swept by the `validate_examples` test, which only covers
  `examples/`. A doc example using a key that has never existed will sit
  there indefinitely. This review found a `type: cel` block in
  `headless-detection.md` using a `response_headers:` key with no
  implementation, anywhere, ever.
  The way to check is cheap and worth doing every time: assemble the
  excerpts into one complete config and run `sbproxy validate` against
  it. Read the output rather than the exit status, because a config that
  parses but cannot construct its modules reports
  `compiled, but a module failed to construct` and still exits 0.
  Writing the three security pages, that command found six errors a
  careful manual pass had already missed, including two required fields
  and a detector name that does not exist.
- **Does a config example that constructs actually behave as documented
  at runtime?** Passing `sbproxy validate` or the `construct_examples`
  sweep proves a config compiles and its pipeline builds; it proves
  nothing about what a live request through it returns. A 2026-08-16
  pass that booted all 203 shipped examples with the real binary and
  replayed every documented curl found more than a dozen genuine
  runtime bugs that every static check had missed clean: response
  bodies documented as `text/plain` that are actually
  `application/json` (auth-api-key, cel-policy, ddos-protection, csrf,
  auth-bearer, ip-filter, request-validator, and others, independently,
  each time), and examples pointing a backend at `127.0.0.1` with no
  `proxy.extensions.upstream.allow_private_cidrs`, so the SSRF guard
  502s the walkthrough before the documented feature ever runs
  (upstream-retries, grpc-h2c, retry-on-status, keys-inbound-headers,
  json-schema). Neither class is visible from the config alone; both
  need a live request.
- **Does a documented field parse but do something else?** The failure
  above the one people look for. A key can be accepted, warned about at
  load, and then quietly do less than the doc says. `dlp` takes
  `direction: response` and logs that response-side scanning is not
  implemented before scanning the request anyway, so a page describing
  it as an outbound control is wrong in the way that matters, and no
  key-existence check catches it. Grep the module for `not implemented`
  and for load-time warnings before describing what a field does.
- **Do metric names in prose match the registry exactly?** PromQL is
  literal, so a counter written without its `_total` suffix hands the
  reader a query that matches nothing. This review found
  `sbproxy_ai_wasted_tokens` in `key-management.md` where the family is
  `sbproxy_ai_wasted_tokens_total`.
- **Did a change turn a known gap into a promise?** The most expensive
  doc bug in this class. Extending a doc to say a feature "works on both
  paths" when one path is a no-op in release builds converts an
  acknowledged limitation into a support ticket. If the code has a
  caveat, the doc states the caveat.
- **Is the doc's claim reachable by the reader?** A capability described
  without the config that enables it, or described at a scope the config
  does not offer, reads as shipped.
- **Removed and refused keys are documented as such**, in
  `config-stability.md`, with what to use instead. A key that stops
  working with no entry is indistinguishable from a bug.
- **Generated docs are regenerated, not hand-edited.** For anything with
  a generator (`metrics-stability.md`, `llms-full.txt`), a hand edit
  passes review and fails the drift guard, or worse, passes both and
  goes stale silently.
- **The dated header is updated** when the content changes, since it is
  the only signal a reader has about staleness.
- **US English, no em-dashes**, per the workspace convention. Fix the
  source string for anything generated rather than the generated page.

Two traps worth knowing before you automate any of this.

The generated JSON schema does not validate module config. Policy and
action bodies are free-form there, so a schema check passes on field
names that do not exist and gives false confidence in exactly the
category where the mistakes are. Check module fields against the struct
or against a swept example instead.

And a doc that names something which does not exist is sometimes correct
on purpose. `observability.md` and `ai-crawl-control.md` each name a
metric that was never emitted, because each sentence is telling the
reader it is not there. A checker will flag both. Read the sentence
before you fix it.

Worth stating plainly: a doc correction found while reviewing unrelated
code is worth making and worth calling out in the PR, not silently
folding in. The next person to read that page should be able to see when
it was last true.

## Output format

Findings first, ranked. Then a short "checked and sound" list so the
absence of a finding is visible rather than ambiguous.

```markdown
### Review notes

**Blocker / Major / Minor** - `path/to/file.rs:LINE` - one-line claim.
Failure scenario: concrete inputs or state, and what goes wrong.

### Checked and sound
- Category: what was verified, in one line.
```

Paste that into the PR body under a `## Review notes` heading. If a
finding was accepted rather than fixed, say which and why, so the next
reader does not rediscover it as new.
