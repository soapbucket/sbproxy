# AI Group C0 process RED report

Date: 2026-08-24

Status: RED authored, controller execution required. This author did not run Cargo, Rust, rustfmt, staging, commit, fetch, or push commands.

## Ownership

The only product-tree file added is:

- `crates/sbproxy/tests/classifier_hook_egress.rs`

No existing test, production, manifest, lock, metric, dashboard, schema, documentation, or Group B file was edited. No separate fixture file was needed. This report is the only other file added.

## Boundary and production break

The integration test starts `env!("CARGO_BIN_EXE_sbproxy")`, not a private handler or a directly constructed hook. It owns three real loopback boundaries:

1. The shipped proxy child, with a token-authenticated Echo readiness origin.
2. A minimal OpenAI-compatible upstream that accepts the forwarded AI POST and records only request count plus a prompt-present boolean.
3. A classifier TCP wire tap that records connection count, byte count, and a prompt-present boolean without retaining or printing payloads.

`denied_classifier_hook_destination_gets_no_connection_or_prompt_bytes` configures the future closed `egress.classifier_hooks` purpose with an empty host allowlist. It drives one real `/v1/chat/completions` request and requires all of the following:

- The AI upstream returns through the proxy with HTTP 200.
- The AI upstream receives exactly one request and the request contains the marker, proving the real request path ran.
- The classifier destination accepts zero connections.
- The classifier destination receives zero wire bytes.
- The classifier destination never observes the prompt marker.

The named production mutation is replacing the governed stock-hook connector with the current `ClassifierClient::connect_lazy` call inside `LazyClassifierClient::classify`. This process test must fail under that mutation.

`explicitly_authorized_loopback_classifier_hook_can_dial` is the positive control. It differs by allowlisting `127.0.0.1`, opting into private destinations, and permitting the fixture port. The same real AI request must reach the provider and cause at least one classifier connection. The classifier fixture intentionally closes rather than implementing gRPC, so the existing fail-open hook posture is exercised without adding tonic or proto dependencies to the binary crate.

## Expected controller RED

Proposed exact focused command from the AI worktree:

```bash
CARGO_BUILD_JOBS=2 cargo nextest run -p sbproxy --test classifier_hook_egress --locked --no-fail-fast
```

Expected current-tree result: two tests selected, both fail at child startup with the sanitized assertion chain ending in:

```text
stock `egress.classifier_hooks` is rejected before the process can reach readiness
```

Static reason: `EgressTopLevelConfig` has `#[serde(deny_unknown_fields)]` and currently exposes `ai_providers`, `usage_sinks`, `model_artifacts`, `token_exchange`, and `telemetry`, but no `classifier_hooks` member. The test config therefore cannot reach readiness yet. A compiler or harness error would not be an accepted RED; the controller must confirm the failure is this missing product surface.

After the config field and lifecycle gate exist, the positive control should pass. With the current live callsite still using `ClassifierClient::connect_lazy`, the denied test should then advance past startup and the HTTP 200/provider assertions, but fail because `classifier.connections()` is nonzero. That is the required second RED at the actual dial bypass.

## Controller execution

The controller ran the proposed command on 2026-08-24 with the protected AI target directory, `CARGO_BUILD_JOBS=2`, and `--no-fail-fast`.

```text
2 tests run: 0 passed, 2 failed, 0 skipped
explicitly_authorized_loopback_classifier_hook_can_dial  FAIL
denied_classifier_hook_destination_gets_no_connection_or_prompt_bytes  FAIL
```

Both failures reached the shipped child process and ended at the intended sanitized assertion chain:

```text
stock `egress.classifier_hooks` is rejected before the process can reach readiness
```

There was no compilation failure, selector miss, harness timeout, or unrelated panic. The initial process-boundary RED is accepted.

## Bounded cleanup and privacy

- The proxy child has a 30 second startup ceiling, a 5 second request ceiling, bounded port retries, and `Drop` performs kill plus wait.
- Both listener threads poll bounded nonblocking accept loops. Accepted classifier reads time out after 100 ms; upstream reads time out after 500 ms and cap the request at exactly 64 KiB. Their `Drop` implementations signal and join.
- The readiness probe requires the child-specific `x-sbproxy-e2e-harness-token`, so a stolen port cannot make a different proxy look ready.
- Child output goes to an isolated file and is never copied into an assertion. Startup classification reads it only to recognize an address collision or the missing config key.
- Fixtures publish only booleans and counters. No request, response, prompt, token, API key, config body, or classifier bytes are formatted into assertion output.
- The blocking client disables ambient proxies, so every test request remains on loopback.

## Next REDs that need production seams

Deterministic DNS rebinding cannot be represented honestly from this isolated process test without changing production or globally mutating the host resolver. Do not simulate it with two helper calls or `/etc/hosts` mutation. Once the governed tonic connector owns an injectable resolver, add this exact connector RED:

1. A `SequenceResolver` returns one policy-authorized public address for `classifier.test` on the first connector invocation and `127.0.0.1` on the second.
2. The first classifier fixture accepts one authenticated request, then closes its channel to force a real reconnect.
3. The second request carries a distinct private prompt marker.
4. The connector must re-resolve and reauthorize before dialing. The private listener must observe zero accepts and zero bytes, and the second marker must not appear at either destination.
5. Mutating reconnect to reuse the first authorization or to call tonic's default resolver must fail the test.

The nonlocal authenticated-TLS RED also needs the final config vocabulary and connector injection. Add a TLS fixture for `classifier.test` whose certificate names that host, provide its bearer token through the repository secret-reference path, and drive the same stock process request. The fixture must observe the original TLS server name and required authorization metadata, but assertion state must expose only booleans. Companion cases for plaintext nonlocal HTTP, a missing secret, and invalid peer identity must fail before any prompt bytes leave the process. gRPC has no redirect behavior in this hook, so an HTTP redirect RED is not applicable.

## Static checks completed

These non-Rust commands were run after authorship:

```text
git diff --no-index --check /dev/null <each new file>   PASS
ownership/status inspection                            PASS
em dash and payload-print scan                         PASS
```

The ownership inspection found only the new C0 test in this task's product scope. All pre-existing Group B tracked and untracked work was left untouched.

AI_C0_RED_READY

## 2026-08-25 scoped-review correction

Status: REVISED RED AUTHORED, AWAITING A FRESH CONTROLLER RUN AND SCOPED RE-REVIEW. The earlier `AI_C0_RED_READY` status and 2026-08-24 controller run apply only to the superseded TCP-only fixture. They remain useful evidence for the initial missing-config phase, but they are not execution evidence for the revised gRPC test tree and do not mean C0 is approved.

The independent C0 review was NOT APPROVED with 1 Blocker, 2 Major, and 1 Minor. This append records the test-only dispositions:

- Blocker: the authorized TCP accept control could pass without a real classifier RPC. Replaced with a real Tonic server carrying the generated `InferenceService` and `ClassifierService` contracts. The positive test now requires exact completed RPC observations and successful provider dispatch.
- Major: only intent was configured, so the test could not catch a quality-hook bypass or split clients. Both stock intent and prompt-aware provider quality are now configured in the same child. The fixture requires exactly two ordered `InferenceService/Classify` calls, for `intent-v1` and `quality-local-openai-v1`, both with `top_k: 0` and exact prompt equality, over exactly one accepted HTTP/2 connection.
- Major: the denied assertion used one fixed 100 ms sleep. Replaced with a condition-polling 500 ms quiet window. It fails on the first accepted connection, any generated classifier RPC, or exact-prompt RPC observation and otherwise spans two complete configured 250 ms hook deadlines. The current client has no additional retry loop.
- Minor: the report overstated readiness after the first controller run. Corrected by this append and the explicit phased status below.

### Actual stock RPC characterization

The source contract matters here. Both stock hooks call `LazyClassifierClient::classify` before provider dispatch:

- intent sends model `intent-v1` to `InferenceService/Classify`;
- provider-quality sends model `quality-local-openai-v1` to the same method and matches the `preferred` label.

`ClassifierService/Quality` scores generated response text and is not the prompt-aware provider-routing method. The fixture implements it because the shared rich-sidecar client carries both generated services, but the authorized test requires its call count to remain zero. This prevents a test-only semantic rewrite from hiding the real production boundary.

Before the AI POST, both tests require zero classifier accepts, zero RPCs, and zero prompt observations. This prevents a startup probe from satisfying the positive control. After the authorized POST, the exact two Classify calls, one connection, two prompt-equality observations, one successful AI upstream request, zero Quality calls, and zero other generated RPCs are mandatory. These assertions kill all of the following mutations:

1. Remove live intent classification.
2. Remove live provider-quality classification.
3. Govern intent but restore raw `connect_lazy` for quality.
4. Construct independent clients or connectors per hook.
5. Replace live calls with a startup-only readiness probe.

The denied policy configures the same two hooks and requires the real gRPC destination to remain completely quiet while the AI provider still serves once. An accepted socket is already a failure, so malformed or partial HTTP/2 traffic cannot evade the test merely by avoiding a decoded RPC.

### Dependency disposition

The binary crate did not expose the generated server traits through an existing direct dependency or re-export. `sbproxy-classifier-client` re-exports response value types only, not `InferenceServiceServer`, `ClassifierServiceServer`, or Tonic server machinery. Three narrow test-only dependencies were therefore added to `crates/sbproxy/Cargo.toml`:

- `sbproxy-classifier-proto` for the exact generated services, messages, and server traits;
- `tonic` for the real bounded gRPC server and request/response contracts;
- `tokio-stream` with `net` for a retained ephemeral listener whose accepted connections are counted.

Tokio was already a direct binary dependency with the required runtime and network features. No new crate version was introduced, and all three added test dependencies already exist in the workspace lock graph. Cargo still needs to refresh the `sbproxy` package dependency list in `Cargo.lock`; this author did not run Cargo or hand-edit the lockfile.

### Phased RED and closure claims

Phase 0, current tree: `EgressTopLevelConfig` still rejects `egress.classifier_hooks`. After Cargo has refreshed the lockfile through its normal resolver, the focused run must select the two new unique tests and fail both only at the sanitized unknown-config startup boundary. A compiler error, stale-lock refusal, zero-selector run, fixture timeout, or unrelated panic is not an accepted RED.

Phase 1, config surface present but live dial still raw: the authorized test must pass its exact two-RPC, one-connection positive control. The denied test must advance through HTTP 200 and provider dispatch, then fail immediately when the raw connector reaches the classifier fixture. This is the semantic `connect_lazy` bypass RED.

Phase 2, local last-callsite governance present: both C0 tests may turn GREEN only when intent and provider-quality share the governed client and the denied destination sees no side effect. That is not full I6-R1 closure. Deterministic reconnect DNS reauthorization and nonlocal authenticated TLS remain mandatory later C phases exactly as specified above; neither is claimed by C0.

Because the manifest gained test-only dependencies, the controller should first let Cargo refresh the lockfile, inspect that resolver-produced diff, and then capture the locked focused result. The locked proof command remains:

```bash
CARGO_BUILD_JOBS=2 cargo nextest run -p sbproxy --test classifier_hook_egress --locked --no-fail-fast
```

### Revised static audit

No Cargo, Rust, rustfmt, staging, commit, fetch, push, or production implementation command was run in this correction. Static inspection found:

- every accept, RPC, request, and shutdown wait has a finite deadline or a deterministic owner drop path;
- the proxy child is initialized after the fixtures and therefore drops, kills, and waits before the gRPC fixture receives its shutdown signal and joins;
- classifier observations cap retained calls at eight and retain only model id, `top_k`, counts, and prompt-equality booleans;
- assertion output contains no prompt, request body, response body, API key, bearer token, classifier payload, or child log;
- both test selectors are unique and exercise the real `CARGO_BIN_EXE_sbproxy` boundary;
- the three dev-dependencies are necessary because no direct re-export supplies their server-side APIs;
- `git diff --check` for the manifest and no-index whitespace checks for the untracked test/report pass;
- em dash and debug/payload-print scans pass.

AI_C0_REVISED_RED_READY

## 2026-08-25 controller compile rejection and fixture correction

Status: REVISED RED HARNESS CORRECTED, AWAITING A FRESH CONTROLLER RUN. No semantic RED is credited from the rejected attempt described below. This correction did not run Cargo, Rust, rustfmt, staging, commit, fetch, or push commands.

After Cargo refreshed the lockfile, the controller reran the locked focused command. The attempt stopped during test-target compilation, before either selector executed: `tokio_stream::wrappers::TcpListenerStream` had no `.inspect(...)` method because `tokio-stream` 0.1.18's `StreamExt` supplies `map` but not `inspect`. This was a fixture API error, not the expected missing `egress.classifier_hooks` product-surface RED, so the attempt was rejected.

The harness now wraps the listener with an identity `StreamExt::map`. For every emitted accept result, the closure increments `ClassifierObservation::accepts` only when the result is `Ok`, then returns that same `Result` unchanged to Tonic. This retains the accepted causal assertion: a real successful socket acceptance is published before Tonic consumes that incoming item, while accept errors and stream item types remain unmodified. No dependency or production change was added.

The controller must rerun the same locked focused command and confirm that exactly two tests execute and fail only at the sanitized unknown-configuration startup boundary before Phase 0 can be accepted.

AI_C0_REVISED_RED_PENDING_CONTROLLER_RERUN

## 2026-08-25 controller Phase-0 acceptance and Phase-1 config shell

Status: PHASE 0 ACCEPTED; PHASE 1 CONFIGURATION PLUMBING AUTHORED,
AWAITING THE CONTROLLER SEMANTIC RUN. This append supersedes the pending
rerun status immediately above. The production author did not run Cargo,
Rust, rustfmt, staging, commit, fetch, or push commands.

The controller reran the locked focused command after the fixture correction.
Exactly two tests were selected, both reached the shipped child process, and
both failed only at the sanitized unknown-configuration boundary:

```text
2 tests run: 0 passed, 2 failed, 0 skipped
authorized_stock_intent_and_quality_share_one_live_classifier_connection  FAIL
denied_stock_intent_and_quality_get_no_connection_rpc_or_prompt_bytes  FAIL
stock `egress.classifier_hooks` is rejected before the process can reach readiness
```

There was no compilation failure, selector miss, harness timeout, or unrelated
panic. This is the accepted Phase-0 RED.

The Phase-1 production shell now adds only the first-class configuration and
lifecycle contract:

- `EgressPurpose::ClassifierHook` has the closed label `classifier_hook`.
- Top-level `egress.classifier_hooks` accepts the existing
  `EgressPurposeConfig` shape.
- Config compilation produces an exact-purpose classifier-hook authorizer and
  leaves an absent or `allow_by_default` block as `None`.
- The shared boot/reload lifecycle seam installs that authorizer and explicitly
  clears the `ClassifierHook` registry slot when a later generation omits or
  disables the block.
- Default, allow-by-default, exact-purpose, closed-label, and dynamic
  install/drop-reload tests were extended, and the operator docs plus the Rust
  schema-source comments describe the new sub-block. The committed JSON schema
  is generator-owned and was deliberately not hand-edited; the controller must
  regenerate `schemas/sb-config.schema.json` with its normal Cargo command.

Deliberately unchanged: `LazyClassifierClient`, its raw Tonic connector, every
classifier network callsite, and `classifier_hook_egress.rs`. Therefore the
required next controller outcome remains two-phase: the authorized process test
must turn GREEN, while the denied test must reach the provider and then fail on
the classifier fixture's first accepted connection. A startup/config failure or
a denied test that does not prove provider dispatch is not the semantic RED.

Static-only validation completed for this shell: production/reference
searches, touched-path ownership inspection, and `git diff --check`. The
controller still owns schema regeneration, formatting, and all Rust execution.

AI_C0_PHASE1_CONFIG_READY

## 2026-08-25 Phase-1 review harness correction

Status: CONFIGURATION WIRING SOUND; REVIEW FINDINGS FIXED IN THE HARNESS,
AWAITING CONTROLLER EXECUTION. The scoped Phase-1 review was NOT APPROVED
with 0 Blockers, 1 Major, and 1 Minor. This author ran no Cargo, Rust,
rustfmt, staging, commit, fetch, or push commands.

The Major finding was valid. The process test redirected both child streams
to an unrestricted append-only file for the child's full lifetime, then used
`BufRead::read_line` for readiness. A noisy child could consume disk, and a
newline-free readiness response could grow one `String` without limit while
also stretching the intended startup deadline.

The harness now owns both child pipes from immediately after spawn:

- dedicated threads continuously drain stdout and stderr in 4 KiB chunks;
- retained diagnostics stop at 32 KiB total while a saturating full-stream
  byte count and overflow bit continue to update;
- independent per-stream overlap windows scan every byte, including markers
  split across reads and markers emitted after retained diagnostics fill;
- the full scan recognizes address collisions and the two-part
  `classifier_hooks` plus `unknown field` startup signature without retaining
  either as a printable diagnostic;
- prompt, provider-key, and dynamic harness-token markers produce only one
  sanitized failure and are never formatted or returned;
- early exit, timeout, successful explicit shutdown, assertion unwinding, and
  `Drop` all stop and reap the child before joining both drain owners.

Readiness no longer uses line allocation. It reads fixed 1 KiB chunks into a
buffer capped at 16 KiB, accepts only a complete header frame carrying the
child-specific token, and rejects EOF, invalid UTF-8, a complete wrong frame,
or a frame that reaches the cap. Connect, write, every read, and the retry
sleep use the same absolute startup deadline; per-operation socket timeouts are
the lesser of 500 ms and the remaining total budget.

The requested adjacent body audit found one more unbounded collection:
`ProxyChild::post_ai` called `response.bytes()`. It now drains the response
through a fixed 4 KiB buffer, retains no body, and refuses after 256 KiB under
the client's existing five-second total request timeout. The existing upstream
fixture request reader was already capped at 64 KiB.

One local harness regression now proves 32 KiB retention, complete two-stream
accounting, overflow, cross-chunk address/unknown-config/private-marker scans,
sanitized failure text, bounded readiness-header matching, and a real
newline-free readiness peer that cannot stretch a 200 ms absolute deadline.
Therefore the focused target now selects three tests. The harness regression
should pass, the authorized process control should pass after Phase 1, and the
denied test must still reach its live connection-side-effect RED until the
governed classifier connector lands.

The Minor finding was also fixed: both remaining stale `ten` claims in
`docs/ai-gateway-security-coverage.md` now say `eleven`, consistent with the
new classifier-hook purpose. Static whitespace, forbidden unbounded-read,
private-marker-format, and touched-path scans pass. Controller execution is
still required.

AI_C0_PHASE1_HARNESS_FIX_READY

## 2026-08-25 Phase-1 byte-cap regression correction

Status: CONFIGURATION WIRING REMAINS SOUND; THE NEW HARNESS REGRESSION GAP IS
CORRECTED, AWAITING CONTROLLER EXECUTION AND SCOPED RE-REVIEW. The latest C0
re-review was NOT APPROVED with 0 Blockers, 1 Major, and 0 Minors. This author
ran no Cargo, Rust, rustfmt, staging, commit, fetch, or push commands.

The earlier newline-free readiness case observed only `false` before 400 ms.
Deleting the explicit capacity return while leaving the absolute socket
deadline intact could still produce that same observation, so the test did not
prove which boundary ended the read. The adjacent 256 KiB AI response limit
also had no over-limit input and therefore did not protect its bounded reader.

Both paths now use one generic bounded-read seam. It reads fixed 4 KiB chunks,
caps retention independently from observation, handles interrupted reads, and
stops after the first byte beyond the configured maximum. Readiness retains at
most its 16 KiB header frame; AI response bodies retain zero bytes. The seam
returns a typed end reason plus retained and observed byte counts rather than
collapsing limit exhaustion into an ordinary rejection.

The production-like readiness path wraps the real `TcpStream` in a reader that
recomputes the lesser of the remaining absolute startup budget and the 500 ms
socket timeout before every read. Its live newline-free peer sends exactly 16
KiB plus one byte and then stays open. The regression now requires
`LimitExceeded { retained_bytes: 16384, observed_bytes: 16385 }` before the 200
ms deadline. Removing the cap branch while retaining deadline handling yields
an ordinary deadline rejection instead, so the exact typed assertion fails.

`ProxyChild::post_ai` has no alternate response-body collector: it invokes the
same generic seam with a 256 KiB maximum and zero retention, then rejects the
typed over-limit result. The harness drives that production-used seam with
three deliberately fragmented chunks totaling 256 KiB plus one byte and
requires exact first-over-limit observation with no retained body. The static
audit also forbids whole-body and unbounded read helpers in this test target.

The focused target still contains exactly three tests; the existing harness
regression was extended rather than adding another process test. The controller
must run it to establish execution evidence. Static-only checks completed here:

```text
git diff --check                                      PASS
git diff --no-index --check /dev/null <C0 test>      PASS (exit 1: new file)
forbidden whole-body/line/unbounded-read scan         PASS (zero matches)
unique #[test] and selector count                     PASS (3)
stale ten-purpose wording scan                        PASS (zero matches)
```

Stable SHA-256 inputs for the controller gate:

```text
164b0e567e557fa0b208ddae4d9fdd69026effa34c2dad76fedc9caed53928f3  crates/sbproxy/tests/classifier_hook_egress.rs
0e0ab18394b67b1d9939600de10f2b7f33794227d6e754dbd14173d9229d0663  docs/ai-gateway-security-coverage.md
```

AI_C0_PHASE1_CAP_REGRESSIONS_READY

## 2026-08-25 Phase-1 real AI-POST callsite correction

Status: CONFIGURATION WIRING REMAINS SOUND; THE REAL-CALLSITE REGRESSION IS
AUTHORED, AWAITING CONTROLLER EXECUTION AND SCOPED RE-REVIEW. The follow-up C0
review remained NOT APPROVED with 0 Blockers, 1 Major, and 0 Minors. This
author ran no Cargo, Rust, rustfmt, staging, commit, fetch, or push commands.

The previous fragmented 256 KiB-plus-one case proved the generic bounded-read
primitive, but it did not invoke the AI POST callsite. Replacing
`ProxyChild::post_ai` with a whole-body collection could bypass that primitive
while leaving the direct helper regression green. The previous readiness
cap-exhaustion proof remains unchanged and still requires the typed 16
KiB-plus-one outcome before its absolute deadline.

The AI request path now has one unambiguous owner, `ProxyEndpoint::post_ai`.
`ProxyChild` stores that endpoint and has no forwarding `post_ai` wrapper or
separate port field. Both real shipped-child process cases call
`proxy.endpoint.post_ai`, and the oversized-response case constructs the same
endpoint type against its loopback fixture. Static ownership inspection finds
exactly one `fn post_ai` and exactly three invocations: oversized, denied, and
authorized.

The loopback fixture accepts for at most one second, bounds request reads, and
uses one absolute two-second deadline for all response writes. The endpoint's
blocking client retains its existing five-second total timeout, and the server
is joined after those bounded operations. It returns a valid fragmented JSON
string whose declared body contains an opening quote, exactly 256 KiB of
filler, a private trailing body marker, and a closing quote. The last network
fragment contains the final filler bytes and then the private marker, so data
exists beyond the first over-limit byte.

The exact production-used method must return the typed value
`ResponseLimitExceeded { limit_bytes: 262144, observed_bytes: 262145,
retained_bytes: 0 }`. Its rendered error must equal the fixed count-only
diagnostic and contain neither the private request prompt nor the trailing
response marker. Restoring whole-body collection or otherwise bypassing the
bounded response seam consumes the valid body and returns HTTP 200, causing
the real-callsite `expect_err` assertion to fail. Reading farther than the
first over-limit byte or retaining body diagnostics also fails the typed
count/no-retention and no-leak assertions.

The focused target still contains exactly three tests. Fresh static-only
checks completed for this correction:

```text
git diff --check                                      PASS
git diff --no-index --check /dev/null <C0 test>      PASS (exit 1: new file)
forbidden whole-body/line/unbounded-read scan         PASS (zero matches)
post_ai owner/invocation inspection                   PASS (1 owner, 3 calls)
unique #[test] count                                  PASS (3)
```

Stable SHA-256 inputs for the controller gate:

```text
1c21f93595a30d48e94148c6d0fbf1d977a4e5d98296a88fa3013b7912811b65  crates/sbproxy/tests/classifier_hook_egress.rs
0e0ab18394b67b1d9939600de10f2b7f33794227d6e754dbd14173d9229d0663  docs/ai-gateway-security-coverage.md
```

AI_C0_PHASE1_REAL_CALLSITE_CAP_READY

## 2026-08-25 Phase-1 deterministic overflow-probe correction

Status: CONFIGURATION WIRING REMAINS SOUND; BOTH THE REAL-CALLSITE AND
DETERMINISTIC PROBE-WIDTH REGRESSIONS ARE AUTHORED, AWAITING CONTROLLER
EXECUTION AND FINAL SCOPED APPROVAL. The final reviewer wording retained the
same 0 Blocker, 1 Major, 0 Minor finding. This author ran no Cargo, Rust,
rustfmt, staging, commit, fetch, or push commands.

The real loopback response remains necessary to kill a whole-body bypass in
the sole `ProxyEndpoint::post_ai` method. It cannot by itself deterministically
distinguish a one-byte overflow probe from a wider probe: a real Reqwest
`Response::read` may legally satisfy a 4 KiB buffer with only one byte. The
typed 262145-byte observation could therefore remain unchanged under that
mutation.

The same `read_bounded_frame` function now also consumes a deterministic
custom `Read` source. That source always fills the complete buffer requested
by the helper and records requested, consumed, and remaining byte counts. It
offers exactly the 256 KiB cap, one over-limit byte, and a further 8 KiB of
trailing data. The regression requires all of these independent effects:

- the typed end is `LimitExceeded` with exactly 262145 observed bytes;
- the source reports exactly 262145 consumed bytes;
- all 8192 trailing bytes remain untouched; and
- the final source read request is exactly one byte.

Changing the overflow probe to 4 KiB therefore consumes and observes 4096
bytes at that step, reduces the protected trailing remainder, and records a
4096-byte final request. It fails deterministically even if the separate real
HTTP reader would have returned a short read. The real endpoint regression,
private trailing marker, exact typed ceiling error, and prompt/body no-leak
assertions were deliberately retained, so the helper seam does not reopen the
earlier callsite-bypass gap.

The focused target still contains exactly three tests; both cap mutations are
covered inside the existing bounded-harness regression. Fresh static-only
checks completed for this correction:

```text
git diff --check                                      PASS
git diff --no-index --check /dev/null <C0 test>      PASS (exit 1: new file)
forbidden whole-body/line/unbounded-read scan         PASS (zero matches)
post_ai owner/invocation inspection                   PASS (1 owner, 3 calls)
recording-reader cap/trailing/request inspection      PASS
unique #[test] count                                  PASS (3)
stale ten-purpose wording scan                        PASS (zero matches)
```

Stable SHA-256 inputs for the controller gate:

```text
d7a4a68d01deec3bb8b739888427cb7d3e142ece53fc49fe9820754c64798931  crates/sbproxy/tests/classifier_hook_egress.rs
0e0ab18394b67b1d9939600de10f2b7f33794227d6e754dbd14173d9229d0663  docs/ai-gateway-security-coverage.md
```

AI_C0_PHASE1_DETERMINISTIC_CAP_READY

## 2026-08-25 rejected Phase-1 run and readiness-action correction

Status: CONTROLLER RUN REJECTED AS A HARNESS FAILURE; READINESS CONFIGURATION
CORRECTED, AWAITING SCOPED RE-REVIEW AND A FRESH CONTROLLER RUN. No semantic
Phase-1 result is credited from the rejected run. This author ran no Cargo,
Rust, rustfmt, staging, commit, fetch, or push commands.

The controller selected all three focused tests. The bounded harness regression
passed, while both child-process tests exhausted the full 30-second readiness
deadline with zero captured child output. An isolated authorized rerun showed
that the shipped child remained healthy and listened on the configured port.
A direct request with `Host: ready.localhost` returned the configured HTTP/1.1
200 static response but did not carry `x-sbproxy-e2e-harness-token`. The two
timeouts therefore did not test classifier egress and were rejected.

Source tracing confirmed the fixture-contract mismatch. The generated Static
action writes its response directly and does not stamp the test-only child
identity header. The Echo action is a schema-valid, fieldless action that
always returns 200 and explicitly stamps the same environment-derived harness
token. The C0 probe correctly insists on both status 200 and exact token
equality so that a different process winning the ephemeral-port handoff cannot
be mistaken for the spawned child.

The test configuration now changes only `ready.localhost` from a Static action
with status/content/body fields to:

```yaml
action:
  type: echo
```

No production token behavior, readiness parser, process lifecycle, classifier
connector, or policy behavior changed. A mutation note beside the generated
YAML records why Echo is intentional and why replacing it with Static breaks
the correct-child proof. The C target has one configured readiness origin, one
probe host, one exact token matcher, and no remaining `type: static` readiness
assumption.

The next controller run must again select three tests. The bounded harness
regression must pass, the authorized process case must advance beyond
readiness, and the denied case must reach the intended live classifier
connection-side-effect RED. A readiness timeout remains a rejected harness
outcome.

Fresh static-only checks completed for this correction:

```text
git diff --check                                      PASS
git diff --no-index --check /dev/null <C0 test>      PASS (exit 1: new file)
readiness origin/host/token ownership scan            PASS (one path)
remaining type: static scan in C target               PASS (zero matches)
forbidden whole-body/line/unbounded-read scan         PASS (zero matches)
post_ai owner/invocation inspection                   PASS (1 owner, 3 calls)
unique #[test] count                                  PASS (3)
```

Stable SHA-256 inputs for the controller gate:

```text
6be1cc427daff4d8cdd73a1dc5a8ecae50dc1b21a50799f3c47db7d3bbd7d3cb  crates/sbproxy/tests/classifier_hook_egress.rs
0e0ab18394b67b1d9939600de10f2b7f33794227d6e754dbd14173d9229d0663  docs/ai-gateway-security-coverage.md
```

AI_C0_PHASE1_ECHO_READINESS_READY

## 2026-08-25 controller Phase-1 semantic RED acceptance

Status: PHASE 1 ACCEPTED. The controller reran the exact locked target after
the Echo readiness correction:

```text
3 tests run: 2 passed, 1 failed, 0 skipped
PASS c0_harness_bounds_child_output_readiness_and_real_ai_post_response
PASS authorized_stock_intent_and_quality_share_one_live_classifier_connection
FAIL denied_stock_intent_and_quality_get_no_connection_rpc_or_prompt_bytes
```

The denied test failed at the intended last-callsite side effect, not startup,
compilation, selection, fixture, or provider dispatch. Its bounded observation
was exactly one accepted classifier connection and two prompt-bearing
`InferenceService/Classify` RPCs, ordered as `intent-v1` then
`quality-local-openai-v1`, with zero `ClassifierService/Quality` or unrelated
RPCs. The authorized control proved that the same two stock hooks work over
one shared live connection. This is the accepted semantic RED for the current
raw `ClassifierClient::connect_lazy` bypass.

Phase 2 may turn these three tests green only through the real shared
`LazyClassifierClient` connector. Group B still owns
`crates/sbproxy-core/src/classifier_hooks.rs`; no C production edit may overlap
that ownership before its handoff. Reconnect-time DNS reauthorization and
nonlocal authenticated TLS remain later C requirements and are not claimed by
this C0 checkpoint.

AI_C0_PHASE1_SEMANTIC_RED_ACCEPTED

## 2026-08-25 read-only governed-connector audit

The accepted C0 semantic RED identifies the raw `ClassifierClient::connect_lazy`
callsite, but the production boundary must live inside Tonic's connector service,
where it is invoked for every physical connect and reconnect. Wrapping only
channel construction would leave Tonic's later reconnects ungoverned.

Reload adds a generation-consistency requirement. The candidate pipeline is
constructed before its gates become global, and an older channel can reconnect
after a newer generation is published. The pipeline must therefore pass its own
compiled `ClassifierHook` authorizer directly into one shared lazy channel. Each
connector invocation must authorize and resolve, immediately verify the returned
addresses, record a closed allowed/denied outcome, and dial only the verified
`SocketAddr`; it must never fall back to hostname dialing or read a dynamic global
gate. HTTPS must keep the original host as the TLS/SNI identity even while dialing
the pinned address.

C0 local GREEN is deliberately narrower than Group C completion. It proves the
loopback allow/deny boundary, zero denied socket side effects, and one shared
intent/quality channel. Separate RED/GREEN phases are still required for DNS
change on reconnect, public-to-private rebinding refusal, original-host TLS and
CA verification, bounded secret-backed bearer authentication, nonlocal config
preflight, both shipped classifier servers' TLS/auth enforcement, and remote
error/label privacy. None of those may be inferred from C0.

AI_C0_GOVERNED_CONNECTOR_BOUNDARY_AUDITED
