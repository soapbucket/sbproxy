---
name: Bug report
about: Something doesn't work as documented or expected
title: ""
labels: bug
---

<!-- Last modified: 2026-04-27 -->

## What happened

<!-- One or two sentences describing the bug. -->

## Reproduction

<!-- The smallest possible config + command that reproduces the issue. Pretend the maintainer has never seen your setup. -->

`sb.yml`:

```yaml
# minimal config that triggers the bug
```

Command and request:

```bash
sbproxy run sb.yml &
curl -v http://localhost:8080/...
```

Output:

```
# observed output, status codes, error messages
```

## Expected behavior

<!-- What should have happened? -->

## Environment

- SBproxy version: <!-- output of `sbproxy --version` -->
- OS / arch: <!-- e.g. linux/amd64, darwin/arm64 -->
- Install method: <!-- brew, docker, source, binary download -->
- Rust toolchain (if built from source): <!-- output of `rustc --version` -->

## Logs

<!-- Relevant log output. Run with RUST_LOG=sbproxy=debug if behavior is non-obvious. Trim aggressively, ~50 lines max. -->

```
```

## Anything else

<!-- Workarounds you tried, related issues, suspected cause, etc. -->
