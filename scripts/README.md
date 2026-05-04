# scripts/

*Last modified: 2026-04-30*


Helper scripts that wrap the day-to-day dev loop and the CI runners
the GitHub workflows invoke. Run from the repository root unless a
script's header says otherwise.

## Inventory

| Script | What it does | CI workflow |
|---|---|---|
| `run-e2e.sh` | Build the Rust proxy and drive the vendored Go conformance suite. | local + CI |
| `run-all-e2e.sh` | Build the proxy and run every Rust e2e test. | local + CI |
| `build-e2e.sh` | Just the proxy build step (release profile). | shared by other runners |
| `perf-compare.sh` | Two-bench delta comparison between branches. | nightly bench |
| `generate-certs.sh` | Mint a local CA + leaf cert for TLS tests. | local only |
| `install.sh` | One-command install of `sbproxy` from a release archive. | end-user |
| `docs-ci.sh` | Wave 1 / Q1.10 doc CI runner: lychee + code-block check. | `.github/workflows/docs-ci.yml` (B1.10) |
| `examples-smoke.sh` | Wave 1 / Q1.11 examples-in-CI smoke runner. | `.github/workflows/examples-smoke.yml` (B1.8) |

Per-script usage and env knobs live in each script's leading comment
header. Run `<script> --help` to dump the header.

## Wave 1 cross-cutting runners

`docs-ci.sh` and `examples-smoke.sh` are the runners the Wave 1
builder workflows wrap. They are kept as plain shell so operators can
reproduce CI locally without building anything Rust. Both exit
non-zero on failure and print one line per checked artifact.

`docs-ci.sh` covers two trees: `sbproxy-rust/docs/` and
`sbproxy-enterprise/docs/`. The enterprise tree is optional; if
`ENTERPRISE_ROOT` is unset and the sibling repo is missing the script
just runs against the rust tree.

`examples-smoke.sh` discovers every directory under `examples/` (this
repo and the enterprise repo) that ships a `docker-compose.yml`. Each
example may add an optional `smoke.json` declaring how to probe the
example's running stack.

### smoke.json schema

```json
{
  "admin_port":        9090,
  "data_plane_port":   8080,
  "health_path":       "/healthz",
  "feature_endpoints": ["/preview/x", "/api/v1/foo"],
  "audit_check":       false
}
```

Field-by-field:

| Field | Default | Notes |
|---|---|---|
| `admin_port` | same as `data_plane_port` | The port the runner polls for liveness. The proxy serves `/healthz` on its admin listener (default 9090) only when `proxy.admin.enabled: true`; examples that do not enable the admin listener can point this at the data-plane port and set `health_path: "/health"`. |
| `data_plane_port` | discovered from the first `published:` port in `docker-compose.yml` | The port the runner hits for `feature_endpoints[]`. |
| `health_path` | `/healthz` | The path used for the liveness probe. Use `/health` for examples that do not enable the admin listener. |
| `feature_endpoints` | `[]` | Each entry is a path on the data-plane port that the runner GETs and asserts returns 2xx. |
| `audit_check` | `false` | When `true`, the runner additionally hits `/api/audit/recent` on the admin port and asserts at least one entry. The OSS in-memory adapter does not ship this endpoint until Wave 2 (R1.2); leave `false` for Wave 1 examples. |

Legacy fields `port` and `endpoints` are still accepted as aliases
for `data_plane_port` and `feature_endpoints` respectively.

Examples without `smoke.json` get the safe defaults: liveness only,
no feature probes, no audit check.
