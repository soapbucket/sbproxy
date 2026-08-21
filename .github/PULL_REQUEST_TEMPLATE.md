<!-- Last modified: 2026-08-20 -->

## What this PR does

<!-- One or two sentences. What changed and why. -->

## Linked issue

<!-- Closes #NNN, refs #NNN, or "no issue" if this is a small fix. -->

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation only
- [ ] Tooling / CI / release pipeline

## Testing

<!-- How did you verify this? cargo test, e2e, manual repro, benchmark? Include exact commands so a reviewer can re-run. -->

```
cargo test --workspace --locked
```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes
- [ ] Relevant docs under `docs/` updated (or no docs change needed)
- [ ] Change fragment added if user-visible (`python3 scripts/changelog-fragments.py --new <type> '<message>'`; do not edit CHANGELOG.md)
- [ ] No new unsafe blocks (or justified inline)
- [ ] No new dependencies (or noted in PR description with rationale)
- [ ] Adversarial review run against `.github/code-review-rubric.md`, findings and dispositions recorded below

## Notes for reviewers

<!-- Anything specific you want a reviewer to look hard at, or any context that doesn't fit above. -->

## Adversarial review

<!--
Required by the "Code review" section of CLAUDE.md, and read by the
`review-evidence` workflow. Fill this in OUTSIDE the comment markers;
a commented-out block does not count, and neither does an empty one.

Reviewer: <the agent, tool, or person that ran the rubric>
Findings: <n> Blocker, <n> Major, <n> Minor
Verification: <how the fixes were re-checked>

- <Blocker|Major|Minor> - `path/to/file.rs:LINE` - one-line claim.
  Then what happened to it: Fixed, Landed in #NNNN, Partly addressed,
  Deferred, Accepted, Declined, Filed, Not fixed here, Not replicated.
  Write the honest one and give the reason whenever it was not simply
  fixed; the whole vocabulary is in CLAUDE.md under "Code review".

One list item per finding, and the item count per severity has to match
the Findings line. When the review turned nothing up the whole block is
two lines: a Reviewer line and `Findings: none`, with no Verification.

Check a draft first:
  python3 scripts/check-review-evidence.py --body-file /tmp/body.md
-->
