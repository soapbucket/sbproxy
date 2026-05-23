//! WOR-650 - fuzz harness for the CEL expression engine.
//!
//! Feeds arbitrary bytes through `CelEngine::compile` and, when
//! compilation succeeds, through `eval` and `eval_bool` against a
//! small fixed context. CEL is the largest happy-path-only-tested
//! surface in the scripting crate; this target drives the parser and
//! the evaluator with adversarial input so sandbox-escape or
//! denial-of-service panics surface as fuzzer crashes.
//!
//! Goal: no panic in the host process. Every input must drive the
//! engine to a typed `Ok`/`Err`, never an abort. Malformed
//! expressions (the overwhelming majority of random inputs) take the
//! `Err` path, which is the engine's normal rejection behaviour.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use sbproxy_extension::cel::{CelContext, CelEngine, CelValue};

/// Cap on the source length handed to the CEL compiler. Production
/// CEL expressions in `sb.yml` are short (well under 1 KiB); the
/// ticket calls for a bounded source so a fuzzer cannot wedge on a
/// multi-megabyte expression. 8 KiB is a generous ceiling that still
/// exercises deeply nested expressions.
const MAX_SOURCE_LEN: usize = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    drive(data);
});

fn drive(input: &[u8]) {
    if input.len() > MAX_SOURCE_LEN {
        return;
    }

    // CEL source is text. Lossy decoding keeps the harness fed even
    // when the fuzzer hands us non-UTF-8 bytes; the compiler treats
    // the replacement characters as ordinary (invalid) tokens.
    let source = String::from_utf8_lossy(input);

    let engine = CelEngine::new();

    // Path A: compile only. Most random inputs fail to parse, which
    // is the engine's normal rejection path.
    let compiled = match engine.compile(&source) {
        Ok(expr) => expr,
        Err(_) => return,
    };

    // Path B: evaluate the (rare) input that compiled, against a
    // context that exposes the variable names production policies
    // reach for so the evaluator does real work (map access, string
    // ops, list size, custom functions). The result type does not
    // matter; either `Ok` or `Err` is acceptable.
    let ctx = sample_context();
    let _ = engine.eval(&compiled, &ctx);
    let _ = engine.eval_bool(&compiled, &ctx);
}

/// A fixed context mirroring the shape policies see at runtime:
/// `request.method`, `request.path`, `request.headers.host`, plus a
/// couple of scalars and a list so `size()` and member access have
/// something to operate on.
fn sample_context() -> CelContext {
    let mut headers = HashMap::new();
    headers.insert(
        "host".to_string(),
        CelValue::String("test.sbproxy.dev".to_string()),
    );

    let mut request = HashMap::new();
    request.insert("method".to_string(), CelValue::String("GET".to_string()));
    request.insert(
        "path".to_string(),
        CelValue::String("/api/v1/users".to_string()),
    );
    request.insert("headers".to_string(), CelValue::Map(headers));

    let mut ctx = CelContext::new();
    ctx.set("request", CelValue::Map(request));
    ctx.set("path", CelValue::String("/api/v1/users".to_string()));
    ctx.set("name", CelValue::String("alice".to_string()));
    ctx.set("x", CelValue::Int(3));
    ctx.set("y", CelValue::Int(7));
    ctx.set(
        "items",
        CelValue::List(vec![CelValue::Int(1), CelValue::Int(2), CelValue::Int(3)]),
    );
    ctx
}
