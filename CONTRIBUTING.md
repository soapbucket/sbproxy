# Contributing to sbproxy

Thank you for your interest in contributing. This document covers the setup, standards, and process for submitting changes.

## Development Setup

```bash
git clone https://github.com/soapbucket/sbproxy.git
cd sbproxy
make build
make test
```

Requirements:

- Go 1.25+
- golangci-lint (for `make lint`)
- Docker (optional, for container builds)

## Code Standards

- Format with `gofmt` (enforced by CI). Run `make fmt` to auto-format.
- All exported types and functions must have godoc comments.
- Tests are required for new functionality.
- Run `make lint` before submitting.
- Error handling must be explicit (`if err != nil`). No panics in production code.
- Context (`ctx`) must be the first argument in functions that accept it.

## Pull Request Process

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make your changes. Keep each commit to one logical change.
4. Run `make test` and `make lint`.
5. Submit a PR against `main`.
6. Wait for CI to pass and a maintainer review.

Tips for a smooth review:

- Keep PRs focused. One feature or fix per PR.
- Include tests that cover the new or changed behavior.
- If the PR changes public API in `pkg/`, call that out in the description.
- Reference any related issues with `Fixes #123` or `Related #456`.

## Package Structure

- `pkg/` - Public API. Changes here require careful review since external consumers depend on these interfaces.
- `internal/` - Private implementation. Not importable by external projects.
- `cmd/` - Binary entry points (`cmd/sbproxy/`).
- `examples/` - Configuration examples (YAML files).
- `docs/` - Documentation.

## Naming Conventions

- **Packages**: lowercase, single word when possible (`cache`, `config`, `engine`, `policy`).
- **Files**: lowercase with underscores (`rate_limiter.go`, `action_ai_proxy.go`).
- **Interfaces**: named by what they do (`ActionHandler`, `AuthProvider`, `EventBus`).
- **Test files**: `*_test.go` in the same package.

## Running Tests

```bash
make test          # All tests
make test-race     # With race detector
make bench         # Benchmarks
make lint          # Linter
make fmt           # Auto-format
make validate CONFIG=path/to/sb.yml  # Validate a config file
```

## Reporting Issues

- Use GitHub Issues for bugs and feature requests.
- Include your Go version, OS, and a minimal config that reproduces the problem.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
