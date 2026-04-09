# sbproxy

## Build & Test
- **Build:** `go build ./cmd/sbproxy/`
- **Test:** `go test ./...`
- **Lint:** `golangci-lint run ./...`
- **Validate config:** `go run ./cmd/sbproxy/ validate -c sb.yml`

## Package Structure
- `pkg/` - Public API (config types, plugin interfaces, event bus, proxy lifecycle)
- `internal/` - Private implementation
- `cmd/sbproxy/` - Binary entry point
- `examples/` - Config examples
- `docs/` - Documentation

## Key Packages
- `pkg/plugin/` - Plugin registry for actions, auth, policies, transforms
- `pkg/config/` - Pure config types (zero internal imports)
- `internal/ai/` - AI gateway handler with sub-packages (hooks, limits, routing, response)
- `internal/config/` - Config loading and validation
- `internal/engine/` - HTTP request pipeline

## Rules
- `pkg/` packages must NEVER import from `internal/`
- Run `go build ./...` after every change
- Run `./scripts/import-guard.sh` before committing
