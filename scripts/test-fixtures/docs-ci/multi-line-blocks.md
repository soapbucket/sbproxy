# Multi-line code-block regression fixture

This fixture intentionally ships three rust blocks that each contain
blank lines inside the fence. The previous awk-based extractor
treated those blank lines as block separators and surfaced false
positives. The state-machine extractor in `docs-ci.sh` should round
trip each block as a single body.

## Block 1: function with internal blank line

```rust
fn add(a: i32, b: i32) -> i32 {
    let total = a + b;

    total
}
```

## Block 2: top-level imports separated by a blank line

```rust,no_run
use std::collections::HashMap;
use std::sync::Arc;

fn build_map() -> HashMap<String, Arc<String>> {
    let mut m = HashMap::new();

    m.insert("key".to_string(), Arc::new("value".to_string()));
    m
}
```

## Block 3: structs and impls separated by blank lines

```rust
struct Config {
    name: String,
    port: u16,
}

impl Config {
    fn new(name: &str, port: u16) -> Self {
        Config {
            name: name.to_string(),
            port,
        }
    }
}

fn _exercise() {
    let c = Config::new("test", 8080);
    let _ = (c.name, c.port);
}
```

## A bash block with blank lines

```bash
echo "first"

echo "second"

echo "third"
```

## A bash block tagged skip (the runner must NOT execute it)

```bash,skip
this is not valid bash and should be skipped
```
