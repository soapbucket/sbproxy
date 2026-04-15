# Upgrade Guide

*Last modified: 2026-04-14*

## How to upgrade

```shell
# Homebrew
brew upgrade sbproxy

# Go
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest

# Docker
docker pull ghcr.io/soapbucket/sbproxy:latest
```

Before upgrading any production instance:
1. Run `sbproxy validate -c sb.yml` with the new binary against your existing config.
2. Check [CHANGELOG.md](../CHANGELOG.md) for any breaking changes in the target version.
3. Deploy to a staging environment first.

## Breaking changes by version

### v0.1.x
- No breaking changes.

This section grows as the project evolves. An entry is added here whenever a change
requires you to update your `sb.yml`.
