//! WOR-168 - fuzz harness for the CEL response-body transform.
//!
//! Feeds arbitrary bytes through `CelScriptTransform::from_config`
//! and (when compilation succeeds) through `evaluate_headers`,
//! including a corpus of header rules that exercises the
//! `CelHeaderOp::Remove` branch the WOR-168 fix replaced from
//! `unreachable!()` to a typed `TransformError::InvariantViolated`.
//!
//! Goal: no panics, no aborts. The production code paths must
//! either return Ok (with a possibly-empty mutation set) or a typed
//! error; either is acceptable to the fuzzer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbproxy_modules::transform::{CelHeaderOp, CelHeaderRule, CelScriptTransform};

fuzz_target!(|data: &[u8]| {
    drive(data);
});

fn drive(input: &[u8]) {
    // Path A: feed the bytes as a raw YAML / JSON config into
    // `from_config`. Most inputs will be rejected (deny_unknown_fields,
    // missing required field, type mismatch); the harness only cares
    // that no path panics.
    if let Ok(s) = std::str::from_utf8(input) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = CelScriptTransform::from_config(v);
        }
    }

    // Path B: synthesize a transform that exercises the Remove branch
    // alongside Set and Append. The header name and the value
    // expression are both derived from the fuzzer input so the
    // expression evaluator sees adversarial bytes too. The point of
    // this branch is to lock down the WOR-168 fix: a Remove rule must
    // never panic, even if the value-expression branch is reached
    // through a future regression.
    let name = pick_header_name(input);
    let expr = pick_value_expr(input);
    let rules = vec![
        CelHeaderRule {
            op: CelHeaderOp::Remove,
            name: name.clone(),
            // Carry a value_expr on a Remove rule so future regressions
            // that route into the inner Set | Append match can be
            // exercised; today this is ignored by `from_config` but
            // tolerated by the field-direct constructor.
            value_expr: Some(expr.clone()),
        },
        CelHeaderRule {
            op: CelHeaderOp::Set,
            name: format!("{name}-set"),
            value_expr: Some(expr.clone()),
        },
        CelHeaderRule {
            op: CelHeaderOp::Append,
            name: format!("{name}-append"),
            value_expr: Some(expr),
        },
    ];
    let transform = CelScriptTransform {
        on_request: None,
        on_response: None,
        headers: rules,
    };
    // `evaluate_headers` returns Result; either branch is acceptable.
    let _ = transform.evaluate_headers(input, 200, &http::HeaderMap::new());
    // The lossy shim must absorb any invariant errors and return a
    // Vec.
    let _ = transform.evaluate_headers_lossy(input, 200, &http::HeaderMap::new());
}

/// Derive a non-empty, ASCII-printable header name from the fuzzer
/// input. Header names in production are case-insensitive and cannot
/// contain whitespace; we approximate that here so the CEL evaluator
/// is asked to do real work.
fn pick_header_name(input: &[u8]) -> String {
    let chunk = if input.len() >= 4 { &input[..4] } else { input };
    let mut name = String::from("x-");
    for &b in chunk {
        if b.is_ascii_alphanumeric() {
            name.push(b as char);
        } else {
            name.push('a');
        }
    }
    if name == "x-" {
        name.push('z');
    }
    name
}

/// Derive a CEL value expression from the fuzzer input. Most random
/// inputs will fail to parse, which is the engine's normal failure
/// path (logged + skipped). The point is to drive the parser and
/// the evaluator with adversarial input so panics can surface.
fn pick_value_expr(input: &[u8]) -> String {
    if input.len() <= 4 {
        return r#""x""#.to_string();
    }
    let tail = &input[4..];
    // Prefer UTF-8 input; fall back to a literal so the parser
    // still has something to chew on.
    match std::str::from_utf8(tail) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => r#""x""#.to_string(),
    }
}
