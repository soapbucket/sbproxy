# Lane B task 2 brief: WOR-1982 classifier-backed safety guardrails

## Binding sources

- Plan: `/Users/rick/projects/soapbucket/docs/sbproxy/2026-07-22-wor-1963-through-1968-implementation-plan.md`
- Linear: `WOR-1982`
- Initial implementation: `b1f2d030`
- Worktree: `/Users/rick/projects/soapbucket/sbproxy/.worktrees/wor1982-classifier-safety`
- Branch: `codex/wor1982-classifier-safety`

## Product contract

- Add backward-compatible classifier modes for `toxicity`, `jailbreak`, and
  `content_safety` through the existing `TextClassifier` seam.
- Keyword mode remains the zero-dependency default and is behavior-compatible.
- Class taxonomies are closed and documented.
- Threshold and margin behavior matches the classifier guardrail.
- Input classification respects `ClassifierScope`, whose default is the last
  user message.
- Output classification evaluates the full assistant response in both
  buffered and streaming paths.
- Metrics distinguish guardrail, closed class, verdict, and
  `keyword`/`classifier` backend, with live production writers.
- Streaming output honors hold-back semantics: no unclassified bytes escape.
- Documentation states the default mode and the limits of keyword matching.
- No GPU work is required.

## Review findings that must be repaired

1. Incomplete or malformed configured taxonomy construction can leave the
   classifier guardrail inactive and fail open.
2. Per-request classifier/backend failures can be cached as a clean verdict,
   allowing later requests to bypass classification.
3. Streaming output can emit bytes before the classifier has produced the
   required verdict.
4. Buffered and streaming output paths classify different subjects instead of
   the same full assistant response.

## Repair constraints

- Preserve the existing uncommitted strict-TDD work. Inspect it before editing.
- First inventory the current diff and existing RED/GREEN evidence. Do not
  discard or wholesale rewrite work that already addresses a finding.
- Use one minimal behavior change at a time. Every change needs a regression
  that was observed failing for the intended reason before production code.
- Fail closed for configured classifier construction and per-request
  classification failures. Do not cache errors as clean results.
- Streaming may buffer, delay, or terminally block according to
  `StreamPolicy`, but must never release bytes before the relevant verdict.
- Buffered and streaming paths must classify the same complete output subject.
- Preserve keyword-mode defaults and byte-compatible behavior.
- Keep metric labels bounded and documented.
- Do not add dependencies, schemas, GPU work, remote LLM classification, or
  unrelated refactors.
- Do not integrate, update Linear, push, or edit the external epic ledger.

## Required handoff

- Commit the completed repair on `codex/wor1982-classifier-safety`.
- Append a report in this SDD directory covering each finding, strict-TDD
  evidence, exact verification commands/results, self-review, and remaining
  concerns.
- Return status, commit hash, tests, and concerns. A dirty worktree is not a
  completed handoff.
