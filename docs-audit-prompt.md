# SBproxy documentation audit

You are auditing the **public OSS SBproxy documentation** for completeness, accuracy against
the codebase, and the presence of clear, runnable examples for every feature and every CLI
command. This is a **read-only audit of the docs**: you do not edit `docs/` or `examples/`.
Your deliverables are (1) a findings report and (2) a Linear documentation epic with one
sub-issue per finding.

## Scope

- **In scope:** the OSS Rust tree only.
  - Docs: `/Users/rick/projects/soapbucket/sbproxy/docs/` (flat directory, ~50 `.md` files)
  - Examples: `/Users/rick/projects/soapbucket/sbproxy/examples/` (~120 dirs, each `README.md` + `sb.yml`)
  - Top-level docs: `README.md`, `CHANGELOG.md`, `llms.txt`, `MIGRATION.md`, `examples/README.md`
  - Code of record: `crates/` (the workspace crates listed below)
- **Out of scope:** `sbproxy-enterprise/`, the archived Go `proxy/` folder (never touch it),
  `mcptest*`, and anything outside `sbproxy/`. Do not audit enterprise-only behavior except to
  confirm the OSS docs correctly mark where the OSS/enterprise boundary is.

## Ground truth: what the binary actually exposes

Verify docs against the code, not against other docs. Key facts to confirm and use:

- **CLI surface** (`crates/sbproxy/src/main.rs`): the subcommands are
  `serve` (default when given `-f <path>`), `validate <path>` (alias `--check`),
  `projections`, `plan`, `apply`, and `--version` / `-V` / `version`.
  Global flags include `--config` / `-f`, `--log-level <level>`, `--grace-time` / `SB_GRACE_TIME`,
  `--shutdown-grace`, and `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS`. Enumerate the real,
  current set from the source before judging the docs; do not trust this list if the code disagrees.
- **Workspace crates** (feature surface lives here): `sbproxy`, `sbproxy-ai`, `sbproxy-cache`,
  `sbproxy-config`, `sbproxy-core`, `sbproxy-extension`, `sbproxy-httpkit`, `sbproxy-middleware`,
  `sbproxy-modules`, `sbproxy-observe`, `sbproxy-openapi`, `sbproxy-platform`, `sbproxy-plugin`,
  `sbproxy-security`, `sbproxy-tls`, `sbproxy-transport`, `sbproxy-vault`, `sbproxy-k8s-operator`,
  `sbproxy-agent-detect`, `sbproxy-classifiers`, and the classifier crates.
- **Config schema** is the authoritative feature contract. Derive the real set of `sb.yml`
  fields/actions/policies from `sbproxy-config` (and wherever the schema/serde structs live), and
  check `docs/configuration.md` and `docs/config-stability.md` against it.
- **Build/run/validate**:
  - `make build` (debug) / `make build-release` (release) builds the binary.
  - `make run CONFIG=<path>` runs the proxy; `sbproxy validate <path>` validates a config.
  - Examples bind `127.0.0.1:8080` and use `*.local` Host headers; a public echo upstream is
    hosted at `test.sbproxy.dev` (httpbin-style).

## What "good docs" means here (the audit checklist)

For each item below, produce findings with severity (blocker / major / minor) and a
`file:line` reference.

1. **Feature coverage.** Build a feature inventory from three sources and reconcile them:
   (a) the crates + config schema, (b) `CHANGELOG.md` + `llms.txt` + `docs/features.md`,
   (c) the `examples/` directory names. Every shipped OSS feature must have: a docs section,
   an entry in `docs/features.md`, and at least one runnable example. Flag any feature that is
   in the code but missing from docs, in the docs but not in the code (stale/aspirational), or
   missing an example.

2. **Accuracy vs codebase.** Spot-check every doc's concrete claims against the source: field
   names, default values, action/policy names, env vars, flag names, exit codes, header names,
   admin API routes (`docs/admin-api-reference.md` vs the embedded admin server), metric names
   (`docs/observability.md`), and event types (`docs/events.md`). Any mismatch is a finding.

3. **Getting started.** Confirm there is a clear, single getting-started path (README quick start
   → `docs/manual.md` → `docs/configuration.md`) that a new user can follow end to end without
   prior context. It must cover install, a minimal working `sb.yml`, running it, and a first
   successful request. Flag gaps, dead ends, or steps that assume unstated knowledge.

4. **FAQ.** Confirm a discoverable FAQ exists. If none exists, that is a blocker finding with a
   proposed outline (the questions it should answer, drawn from `docs/troubleshooting.md`, common
   config errors, and the OSS/enterprise boundary).

5. **Troubleshooting.** `docs/troubleshooting.md` must map real, current failure modes to fixes.
   Verify each symptom/fix against actual error strings and behavior in the code. Flag stale or
   missing entries.

6. **Per-command examples.** Every CLI subcommand and major flag must have at least one clear,
   copy-pasteable, actionable example in the docs (`docs/manual.md` and/or the relevant page),
   with expected output. Flag any command that is undocumented or documented without a runnable
   example.

7. **Per-feature end-to-end examples.** Every feature's example must be a true end-to-end recipe:
   a valid `sb.yml`, the exact run command, and the exact `curl` (or equivalent) that exercises it,
   plus the expected response. The `examples/<name>/README.md` must match its `sb.yml`.

## Verification: full end-to-end (required)

Do not rely on reading alone. Actually build and exercise the binary.

1. Build once: `make build-release` (or `make build`). Capture the binary path.
2. **Validate every example config:** run `sbproxy validate examples/<name>/sb.yml` for all
   examples. Record every non-zero exit / validation error as a finding.
3. **Run and curl a representative sample of every feature category end to end:** start the proxy
   with `make run CONFIG=examples/<name>/sb.yml`, send the `curl` from that example's README
   (using the documented `*.local` Host header and `test.sbproxy.dev` upstream where relevant),
   and confirm the actual response matches what the docs claim. Cover at least one example from
   each feature family (auth, rate limiting, WAF/DDoS, CEL/Lua/JS/WASM scripting, routing/load
   balancing, caching, redirects, AI gateway routing/fallback/guardrails/budgets/streaming, MCP,
   agent-skills, observability, admin API). For AI examples that need real provider keys, note the
   prerequisite rather than calling live providers; still validate the config and the non-AI path.
4. Tear down each run cleanly before starting the next (examples share `127.0.0.1:8080`).
5. Record, for every example you ran: validated (y/n), ran (y/n), curl matched docs (y/n), notes.

## House rules (must follow)

- **Brand:** the public name is **SBproxy** (mixed case in prose); lowercase `sbproxy` is only for
  the binary/crate/hostname. Flag brand-casing errors in docs as minor findings.
- **No em-dashes** anywhere. If you find em-dashes in docs, note them as a minor finding (do not edit).
- **No Linear references in public docs.** `docs/`, `CHANGELOG.md`, `README.md`, `examples/README.md`
  must not contain `WOR-NNN` or `linear.app` URLs. Any such reference is a finding. (Linear refs are
  fine **inside the issues you file** - just not in the docs themselves.)
- **Docs convention:** flat `docs/` directory, lowercase-hyphenated filenames, no subdirectories,
  no per-crate READMEs. Flag violations.
- Cross-check the prior audit artifacts `docs-audit.md` and `docs-manifest.md` for context, but
  re-verify their claims against current code; treat them as possibly stale.

## Deliverable 1: findings report

Write a report to `sbproxy/docs-audit-report.md` with:
- An executive summary: counts by severity, overall doc health, the top 5 most important gaps.
- A **feature coverage matrix**: feature → has doc? → in features.md? → has example? → example
  validates? → example ran end-to-end? → notes.
- A **CLI command matrix**: command/flag → documented? → has runnable example? → notes.
- A findings list grouped by category (coverage, accuracy, getting-started, FAQ, troubleshooting,
  per-command examples, per-feature examples), each with severity and `file:line`.
- An appendix with the raw build/validate/run logs (or a summary table of the end-to-end runs).

## Deliverable 2: Linear documentation epic + issues

After the report is written:
1. Identify the correct Linear team (the one using the `WOR-` prefix that owns SBproxy OSS work).
   Confirm it before creating anything.
2. Create a **documentation epic** for this audit - a Linear project named something like
   "SBproxy documentation audit (<date>)" **or** a single parent issue if that matches the team's
   convention for epics. Put the executive summary and a link/path to `docs-audit-report.md` in
   its description.
3. Create **one sub-issue per finding** (group trivially related minor findings into a single
   issue where it reduces noise). Each issue must have: a clear title, the affected file(s) with
   `file:line`, the specific inaccuracy/gap, the evidence (what the code/binary actually does), and
   a concrete suggested fix. Set priority from severity: blocker → Urgent/High, major → Medium,
   minor → Low. Label them as documentation work and link them to the epic.
4. Do **not** start fixing the docs. Stop after the report and the filed issues, and print a
   summary: report path, epic URL/ID, and the list of created issue IDs by severity.

## Order of work

1. Inventory features from code + schema + changelog + examples; build the coverage matrix skeleton.
2. Audit each doc page for accuracy against the code; fill in findings.
3. Build the binary; validate all example configs; run the end-to-end sample.
4. Assess getting-started, FAQ, troubleshooting, and per-command coverage.
5. Write `docs-audit-report.md`.
6. Create the Linear epic and file the issues.
7. Print the final summary.
