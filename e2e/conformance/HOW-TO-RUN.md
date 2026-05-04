# Conformance e2e suite (curl + bash)

*Last modified: 2026-04-27*

The blackbox conformance suite for sbproxy. 93 cases driven by raw
curl through `run-tests.sh`. Originally authored against the Go
implementation; vendored here so it survives the archival of
`soapbucket/sbproxy-go`.

This is **not** a deprecated suite. It is the strictest HTTP
conformance harness we ship, and it catches things the Rust-native
suite at `e2e/tests/*.rs` does not.

## Why both suites exist

| | `e2e/tests/*.rs` (Rust-native) | `e2e/conformance/` (this dir) |
|---|---|---|
| Runner | `cargo test` | `bash run-tests.sh` |
| Author style | Rust assertions, typed harness | curl + grep + bash |
| Deps | cargo only | node + jq + python3 + curl |
| What it covers | Targeted feature tests | Full HTTP-stack conformance |
| Speed | Fast (~50 tests in seconds) | Slower (93 cases, real curl) |
| Catches | Logic bugs in feature code | Wire-protocol bugs |

The proof point: the v2 Content-Length bug on 429 responses passed
the Rust suite (its HTTP client tolerated the missing header) but
hung the curl suite. Both suites catch different things; we run
both.

## Running it

From the workspace root:

```bash
# All cases against the release binary
./scripts/run-e2e.sh

# A subset
./scripts/run-e2e.sh 01 03 18

# Against an externally-cloned suite (e.g. soapbucket/sbproxy-go)
GO_E2E_DIR=/path/to/sbproxy-go/e2e ./scripts/run-e2e.sh
```

The script builds the release binary, symlinks it where the runner
expects, and invokes `run-tests.sh`.

## Prerequisites

- `node` (test backends are JS)
- `jq` (assertion helpers)
- `python3` (JWT helper for case 20)
- `curl`

## What is in here

- `cases/` - 93 numbered test directories, each with an `sb.yml` and
  any fixtures the case needs.
- `servers/` - the test backend harness:
  - `test-server.js` - generic echo + callback recorder.
  - `mock-ai.js` - OpenAI-shape mock provider.
  - `echo-server.go` - pure-Go echo server (the compiled binary is
    gitignored; rebuild with `go build -o echo-server echo-server.go`).
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
