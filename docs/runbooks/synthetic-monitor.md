# Synthetic monitor runbook
*Last modified: 2026-04-30*

This is a scribe-handoff snippet for `docs/operator-runbook.md`. The
synthetic-monitor workflow at `.github/workflows/synthetic-nightly.yml`
runs the `bench-synthetic` probe against the bundled observability +
crawl-tiered example stack on a nightly cron and opens a GitHub issue
on failure. This page documents how operators page on those issues
and what to check first.

## Permissions and tokens

The workflow declares an explicit minimal `permissions:` block:

```yaml
permissions:
  contents: read
  issues: write
```

Issue creation runs against the workflow's `GITHUB_TOKEN`. The token
is auto-provisioned per run, scoped to the repository the workflow
fires in, and expires when the run ends. No manual rotation is
required.

If a future deployment needs cross-repo issue routing (e.g. opening
a ticket in a separate ops tracker on probe failure), swap
`GITHUB_TOKEN` for a dedicated personal-access token mounted as a
repository secret. The workflow's `failure-notification` step is
the one that calls `github.rest.issues.create`; replace the
`github`-scripted call's auth and update `permissions.issues` to
`read` if the PAT carries the write scope itself.

## What gets paged

The workflow opens an issue tagged `synthetic`, `wave1`, `incident`
on any of:

- The probe binary exits non-zero. Most often a connection refused
  to the bundled example stack, an HTTP 5xx from the proxy, or a
  `timeout` result line from the probe itself.
- The post-run JSONL grep finds a `"result":"error"` or
  `"result":"timeout"` line, even when the binary exited zero. This
  catches the case where a future probe-binary change loosens its
  exit policy.

The issue body carries the probe's full stdout (one JSONL line per
iteration). Treat the body as the primary diagnostic; the workflow
also uploads the same file as the `synthetic-probe-output` artifact
for 14 days.

## First-line triage

1. Open the linked workflow run. Confirm the failure was at the
   `run synthetic probe` step and not at the docker-compose `up`
   step. A compose failure usually means an upstream image tag
   (nginx, mock-ledger) was retagged; rerun the workflow.
2. Read the JSONL. If `result` is `error` and the message mentions
   `connection refused`, the proxy did not finish booting before
   the probe fired. The compose stack waits for the
   `service_healthy` condition, so a real refused likely means the
   data-plane listener crashed; pull the proxy logs from the
   uploaded artifact.
3. If `result` is `timeout` on the first iteration, suspect
   upstream DNS or network. The probe target is `127.0.0.1:8080`,
   so timeouts with no other failures usually mean the proxy is up
   but not responding within the probe's per-iteration budget.

## Re-running

`workflow_dispatch:` is enabled, so on-call can rerun without
waiting for the next 04:13 UTC tick. Visit the workflow page and
click `Run workflow` against `main`.
