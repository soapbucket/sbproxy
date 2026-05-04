<!-- Last modified: 2026-04-27 -->

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
- [ ] CHANGELOG.md `## Unreleased` entry added if user-visible
- [ ] No new unsafe blocks (or justified inline)
- [ ] No new dependencies (or noted in PR description with rationale)

## Notes for reviewers

<!-- Anything specific you want a reviewer to look hard at, or any context that doesn't fit above. -->
