# Config authority certification drills

*Last modified: 2026-07-26*

Eight drills that run an authority and a subscriber as separate processes
and check what happens when configuration is published, rotated,
replayed, tampered with, or unavailable.

They are not in CI. That is deliberate and it has a cost: a suite nobody
runs rots. This page exists so the drills can be run by hand in a couple
of minutes, and so the reason each one exists survives longer than the
person who wrote it.

## Why they exist at all

Every layer of config distribution is covered by unit and integration
tests, and those tests run one side against a stub inside one process.
They cannot see a boot-time refusal, a listener that never binds, a
credential that resolves differently in a child process, or a
configuration that verifies and then fails to serve traffic.

Twice before in this project, a feature certified by unit tests alone
turned out not to work when a real process tried it, and validation on
real hardware found the bugs both times. Those two rounds cost a GPU
instance and a day each. This one costs two processes on a laptop.

## Running them

The drills execute the **release** binary, so build it first. This is not
optional: without it the harness runs whatever stale binary is on disk,
or none.

```bash
cargo build --release -p sbproxy
cargo test -p sbproxy-e2e --release --test config_authority_drills -- --ignored
```

They are marked `#[ignore]`, so an ordinary e2e run skips them and a
deliberate run needs `--ignored`. Expect three to four minutes: most of
the wall time is process starts and poll intervals, not computation.
`poll_interval` is validated to be at least 5 seconds, so the drills
cannot go faster than that no matter how much they would like to.

**If you use a custom `CARGO_TARGET_DIR`, set `SBPROXY_E2E_BIN` too.**
The harness resolves the binary from the worktree root
(`<worktree>/target/release/sbproxy`) rather than from
`CARGO_TARGET_DIR`, so with a custom target directory every drill fails
at setup with "sbproxy binary missing":

```bash
export SBPROXY_E2E_BIN="$CARGO_TARGET_DIR/release/sbproxy"
```

**Kill strays before you start.** A subscriber or authority left behind
by an interrupted run holds its port and answers the next run with the
previous run's credentials, which surfaces as a baffling
`{"error":"Unauthorized"}`. `pkill -f 'sbproxy --config'` first.

One drill at a time, if you are diagnosing a failure:

```bash
cargo test -p sbproxy-e2e --release --test config_authority_drills -- \
  --ignored --exact drill_3_an_older_revision_is_refused_and_stays_refused_after_restart
```

Every drill prints the subscriber's stderr on failure. That is usually
the whole answer, because a subscriber that refuses a bundle says why.

## Two kinds of authority, and why

Drills 1, 6, 7, and 8 run the **shipped authority binary**. What they
test is the real publish path, the real store, and the real boot, so a
stub would be testing the stub.

Drills 2, 3, 4, and 5 run a **stub authority** built from the shipped
bundle types (`ConfigBundle`, `ConfigBundleSigner`) and serving the real
wire format. What they test is a subscriber's reaction to a bundle no
real authority would ever send: an older revision, a payload mutated
after signing, a signature from a retired key, or no answer at all.
Getting the real authority to do those things would mean adding a
misbehave switch to production code, which is a worse idea than a
sixty-line stub. The interesting half is the subscriber's refusal, and
that half is the shipped code either way.

## The drills

### 1. Happy path

Publishes a configuration, waits for the subscriber to serve it, and
checks that both sides report the same revision and digest. Also checks
that an overlay kept the subscriber's own origins, and that
`GET /admin/config/effective` on the subscriber names the authority as
the owner of what it took.

Fails if: the bundle listener does not bind, the credential does not
resolve in the child process, the merge produces something that does not
compile, or the reload does not swap the pipeline.

### 2. Key rotation

Applies a bundle under one key id. Adds a second id to the trust map,
publishes under it, and checks it applies. Then removes the first id and
serves a bundle signed by it, checking that it is refused and that the
previously applied configuration keeps serving.

**This drill found a real bug, twice over, and is the reason the ticket
insisted on real processes.** The verifying-key file was read once at
startup and re-read only if it had failed to load entirely. So adding a
key id never took effect, and every bundle signed by it was refused
indefinitely with `key ID ... is not in the verifying key set`. Worse,
removing one never took effect either: a key revoked because it leaked
kept verifying bundles until every node had been restarted, which made
revocation a rolling restart rather than an edit.

The docs had promised rotation with "no synchronized fleet restart" the
whole time. No unit test could see the gap, because they all construct
the key set directly and never go through the file. The subscriber now
re-reads the file on every poll that returns a bundle, and keeps the
loaded set when a read fails so a file mid-rewrite is not a window where
everything is refused.

If this drill starts failing again, that regression is what it is
telling you.

### 3. Replay

Applies revision 5, then serves a correctly signed, entirely valid
revision 4. Everything about it verifies; only the anti-replay cursor
refuses it.

Then restarts the subscriber and serves revision 4 again. **This is the
half that matters**: a cursor held only in memory would make a restart
all an attacker needs, and a restart is not a hard thing to cause.

### 4. Tamper

Two mutations, each isolated so the failure mode is unambiguous. A
payload swapped after signing fails on the digest. A signature byte
flipped in place fails on the signature. In both cases the previously
applied configuration keeps serving, because a refused bundle must not
leave a node with no configuration.

The signature mutation flips a byte rather than truncating the field, so
this tests a wrong signature rather than a malformed one. Those take
different code paths and the wrong-signature path is the one an attacker
would exercise.

### 5. Authority outage

Kills the authority mid-poll. Checks that the subscriber keeps serving
its cached bundle for the whole window, that
`sbproxy_config_bundle_age_seconds` is published so an operator can
alert on it, and that the node converges when the authority returns
**without a restart**.

A control-plane outage must not take down a data plane that does not
depend on it. `max_staleness` is a boot-time gate, not a kill switch,
and this drill is what keeps that true.

### 6. Denied path, at both gates

Attempts to publish a payload naming `proxy.admin`. The authority
refuses it and reports `revision_consumed: false`, and the next good
publish is revision 1, proving the counter did not move.

Then, separately, serves a hand-signed bundle carrying the same denied
path from the stub, bypassing the publish path entirely. The subscriber
refuses it too, and its own admin listener is still answering
afterwards.

**Two gates rather than one gate twice** is the property. If only the
publish path checked, anyone who could sign would own every subscriber's
admin port.

### 7. Editor lock

Applies a bundle that overrides a setting the subscriber's own file also
sets. Then `PUT /admin/config` with an edit to that setting, and checks
for `409`, `code: config_not_locally_owned`, the conflicting path named,
and the authority named in the remedy. Confirms neither the running
configuration nor the file on disk changed.

Then writes a setting the authority does **not** set and checks that it
succeeds and takes effect. The guard is per-setting, not a blanket lock,
and a drill that only proved the refusal would not notice if it had
become one.

### 8. Cold boot

`overlay` with no cached bundle and an unreachable authority boots on
the local file. `replace` with no cached bundle refuses to start,
because under replace the local file is not a servable configuration on
its own and booting anyway would serve a configuration nobody wrote.

## When a drill fails

Read the subscriber stderr in the failure output first. A refusal names
its reason, and the reason is nearly always the answer.

Timeouts are the exception. The drills poll with a deadline rather than
sleeping a fixed amount, so a timeout means "never converged" rather
than "was slow". On a machine that is also compiling, `CONVERGE` in the
test file is the knob; raise it before concluding the feature is broken.

If a drill fails on a machine where the previous run passed and nothing
changed, check that the release binary is current. A stale
`target/release/sbproxy` is the most common cause of a confusing
failure here, because the drills will happily certify last week's code.

## What these drills do not cover

Stated plainly so nobody reads a green run as more than it is.

- **TLS on the bundle listener.** The drills bind loopback and set
  `allow_insecure_http: true` on the subscriber, because without it the
  subscriber refuses a plaintext authority URL outright, which is the
  right default: the credential and the whole configuration would
  otherwise cross the wire in the clear. A production subscriber uses
  `https` and never sets that flag, and the TLS path is covered by the
  TLS startup tests. Nothing in a green drill run says anything about
  the TLS listener.
- **A real network.** Everything is loopback, so nothing here says
  anything about behaviour across a partition, under packet loss, or
  against a slow DNS resolver.
- **Scale.** One subscriber. The per-subscriber and fleet-wide rate
  limits are unit-tested; how an authority behaves with a thousand
  nodes restarting at once is not tested here.
- **Clock skew.** Bundle expiry and the permitted skew window are
  unit-tested against injected clocks, which is the only way to test
  them deterministically.
