# Contributing to sbproxy
*Last modified: 2026-04-27*

## Prerequisites

- Rust 1.75+ (for RPITIT support)
- Cargo (comes with Rust)
- Node.js 18+ (for e2e test backends)
- cmake (for Pingora's BoringSSL dependency)

## Building

```bash
# Debug build (fast compilation)
cargo build --workspace

# Release build (optimized)
cargo build --release -p sbproxy
```

## Testing

```bash
# Run all unit tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p sbproxy-modules
cargo test -p sbproxy-ai
cargo test -p sbproxy-extension

# Run with output
cargo test -p sbproxy-modules -- --nocapture

# Run a specific test
cargo test -p sbproxy-modules json_transform_set_fields
```

## Running

```bash
# Start with a config file
./target/release/sbproxy --config sb.yml

# The config format is YAML:
# proxy:
#   http_bind_port: 8080
# origins:
#   "example.com":
#     action:
#       type: proxy
#       url: http://backend:3000
```

## Project structure

See [docs/architecture.md](docs/architecture.md) for the full architecture guide.

The project is a Cargo workspace with 19 crates under `crates/`. Each crate has a single responsibility.

## Adding a new module

### Built-in module (enum variant)

1. Choose the module type: action, auth, policy, or transform
2. Add your config struct to the appropriate file in `sbproxy-modules/src/{type}/`
3. Add a new variant to the enum in `sbproxy-modules/src/{type}/mod.rs`
4. Update the match arms in `*_type()`, `Debug`, and `apply()`/`check()` methods
5. Add a match arm in `sbproxy-modules/src/compile.rs` for your type name
6. Write unit tests
7. Run `cargo test --workspace`

Example, adding a new policy:

```rust
// In sbproxy-modules/src/policy/mod.rs
pub enum Policy {
    // ... existing variants ...
    MyNewPolicy(MyNewPolicy),
    Plugin(Box<dyn PolicyEnforcer>),
}

// In a new file or same file:
#[derive(Debug, Deserialize)]
pub struct MyNewPolicy {
    pub some_field: String,
}

impl MyNewPolicy {
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
    pub fn check(&self) -> bool { true }
}

// In compile.rs:
"my_new_policy" => Ok(Policy::MyNewPolicy(MyNewPolicy::from_config(config.clone())?)),
```

### Third-party plugin (dynamic dispatch)

Out-of-tree crates can register their own actions, auth providers, policies, or transforms via `inventory`. The proxy discovers them at link time, so no central wiring change is needed.

```rust
// In your-crate/src/policy.rs
use sbproxy_plugin::*;

pub struct MyPolicy { /* ... */ }

impl PolicyEnforcer for MyPolicy {
    fn policy_type(&self) -> &'static str { "my_policy" }
    fn enforce(&self, req: &http::Request<bytes::Bytes>, ctx: &mut dyn std::any::Any)
        -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>
    {
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

inventory::submit! {
    PluginRegistration {
        kind: PluginKind::Policy,
        name: "my_policy",
        factory: |config| { /* ... */ },
    }
}
```

## Code style

- Follow `rustfmt` defaults
- Use `cargo clippy -- -D warnings` before committing
- Prefer `anyhow::Result` for fallible functions
- Use `CompactString` for short strings (hostnames, IDs)
- Use `SmallVec` for small collections (policies, transforms)
- Write doc comments on all public types and functions

## E2E tests

```bash
# Run smoke tests
./scripts/run-e2e.sh

# Run specific cases
./scripts/run-e2e.sh 01 14 11
```

E2E tests reuse the Go test suite configs with a compatibility layer for field name differences.

## Benchmarks

```bash
# Run all benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench -p sbproxy-modules -- json_transform
```
