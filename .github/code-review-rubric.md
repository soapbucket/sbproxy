# Code review rubric

*Last modified: 2026-08-12*

The checklist an automated reviewer runs against a branch before it
becomes a PR, and the shape its output takes so the result can be pasted
into the PR body as a note.

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

## Output format

Findings first, ranked. Then a short "checked and sound" list so the
absence of a finding is visible rather than ambiguous.

```markdown
### Review notes

**Blocker / Major / Minor** — `path/to/file.rs:LINE` — one-line claim.
Failure scenario: concrete inputs or state, and what goes wrong.

### Checked and sound
- Category: what was verified, in one line.
```

Paste that into the PR body under a `## Review notes` heading. If a
finding was accepted rather than fixed, say which and why, so the next
reader does not rediscover it as new.
