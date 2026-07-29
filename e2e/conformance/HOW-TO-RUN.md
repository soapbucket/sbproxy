# HTTP compatibility catalog (curl + bash)

*Last modified: 2026-07-28*

This directory contains 93 black-box HTTP cases driven by raw curl
through `run-tests.sh`. The catalog was originally written for the Go
implementation. The proxy implementation now lives entirely in this
Rust repository; the retired implementation is preserved at
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go).

The default command runs a maintained smoke set. It covers basic
proxying, API and AI paths, callbacks, failure modes, threat protection,
metrics, secrets, error responses, load balancing, and gRPC-Web. Use
`--all` when migrating or auditing the complete historical catalog.
The full-catalog command is diagnostic: a failure may mean an old
fixture needs to be translated to the current schema, so review its
configuration before treating it as a product regression.

## Why both suites exist

| | `e2e/tests/*.rs` (Rust-native) | `e2e/conformance/` (this dir) |
|---|---|---|
| Runner | `cargo test` | `bash run-tests.sh` |
| Author style | Rust assertions, typed harness | curl + grep + bash |
| Deps | cargo only | node + jq + python3 + curl + lsof + openssl |
| What it covers | Current targeted feature contracts | HTTP smoke tests and historical compatibility cases |
| Default scope | Test selected by the cargo command | 16 maintained smoke cases |
| Full scope | Workspace or package suite | 93-case migration audit |
| Catches | Logic bugs in feature code | HTTP framing, routing, and wire-level regressions |

The suites are complementary. For example, curl exposes response
framing problems that an in-process HTTP client may tolerate, while
the Rust suite can assert internal state and typed errors directly.

## Running it

From the workspace root:

```bash
# Maintained smoke set against a release binary
./scripts/run-e2e.sh

# Selected cases
./scripts/run-e2e.sh 01 03 18

# Full historical catalog audit
./scripts/run-e2e.sh --all
# Equivalent explicit entry point:
./scripts/run-all-e2e.sh
```

The script builds the release binary and invokes the in-tree
`run-tests.sh`. To use a different already-built Rust binary directly,
set `SBPROXY_BIN` when running the conformance script:

```bash
SBPROXY_BIN="$PWD/target/debug/sbproxy" \
  ./e2e/conformance/run-tests.sh 83
```

## Prerequisites

- `node` (test backends are JS)
- `jq` (assertion helpers)
- `python3` (JWT helper for case 20)
- `curl`
- `lsof` (verifies that the runner owns each test listener)
- `openssl` (generates local test certificates on the first run)

## What is in here

- `cases/` - 93 numbered test directories, each with an `sb.yml` and
  any fixtures the case needs.
- `servers/` - the test backend harness:
  - `test-server.js` - generic echo + callback recorder.
  - `mock-ai.js` - OpenAI-shape mock provider.
  - `echo-server.go` - intentional pure-Go echo-server fixture. Its compiled
    binary is gitignored; rebuild it with `go build -o echo-server echo-server.go`
    only when working on that fixture. It is not a proxy implementation.
- `run-tests.sh` - the bash runner with per-case assertions.
- `generate-certs.sh` - produces self-signed mTLS material for cases
  that need it. Output is gitignored.
- `load-test.sh` - convenience wrapper for stress-running individual
  cases.

## Why these cases are not merged into `e2e/cases/`

The Rust-native suite at `e2e/tests/` has its own small `cases/`
directory for fixture configs that some Rust tests reference. Keeping
the conformance cases here avoids name collisions and makes the code-
review boundary obvious: PRs that touch `e2e/conformance/` are
touching the wire-protocol conformance spec; PRs that touch
`e2e/tests/` are touching Rust-native feature tests. Different stakes,
different reviewers.
