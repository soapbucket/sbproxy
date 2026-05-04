//! Wave 4 / Q4.8: `aipref` request signal parsing.
//!
//! The W3C AI Preferences Working Group's `aipref` header carries a
//! comma-separated list of `key=value` pairs that lets a crawler
//! declare which categories of AI processing the requester opts into:
//!
//! ```http
//! aipref: train=no, search=yes, ai-input=yes
//! ```
//!
//! Wave 4 surfaces these as `request.aipref.<key>` fields readable by
//! every scripting surface (CEL, Lua, JavaScript). Default-permissive
//! semantics: missing or malformed inputs leave every category at
//! `true` (the proxy never silently downgrades a request because the
//! caller emitted a malformed header).
//!
//! All tests in this file are `#[ignore]`'d with `TODO(wave4-G4.X)`
//! markers until the parser in
//! `crates/sbproxy-extension/src/scripting/context.rs` lands.

use sbproxy_e2e::ProxyHarness;

// --- Test 1: valid aipref header parsed into CEL context ---

#[test]
fn aipref_header_parsed_into_request_context() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.aipref.train == false'
        deny_status: 403
        deny_message: "train opt-out required"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // train=no should make `request.aipref.train == false` true ->
    // policy passes -> 200.
    let resp = harness
        .get_with_headers(
            "/",
            "aipref.localhost",
            &[("aipref", "train=no, search=yes, ai-input=yes")],
        )
        .expect("GET");
    assert_eq!(
        resp.status, 200,
        "train=no must surface as request.aipref.train == false; got {}",
        resp.status
    );
}

// --- Test 2: unknown keys silently ignored ---

#[test]
fn aipref_unknown_keys_silently_ignored() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.aipref.train == true'
        deny_status: 403
        deny_message: "train must remain default-permissive"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // foo=bar is unknown; train=yes is canonical. The unknown key
    // must not poison the parse and must not affect train.
    let resp = harness
        .get_with_headers("/", "aipref.localhost", &[("aipref", "foo=bar, train=yes")])
        .expect("GET");
    assert_eq!(
        resp.status, 200,
        "unknown keys must be ignored; train=yes -> request.aipref.train == true"
    );
}

// --- Test 3: malformed input falls through to default-permissive ---

#[test]
fn aipref_malformed_logged_at_warn_falls_through_to_default() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.aipref.train == true'
        deny_status: 403
        deny_message: "default-permissive expected"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // `train` (no `=`) is malformed. Default-permissive means train
    // stays at true even though the parse errored.
    let resp = harness
        .get_with_headers("/", "aipref.localhost", &[("aipref", "train")])
        .expect("GET");
    assert_eq!(
        resp.status, 200,
        "malformed header must leave aipref at default-permissive; got {}",
        resp.status
    );
}

// --- Test 4: absent header = default-permissive ---

#[test]
fn aipref_absent_header_means_default_permissive() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.aipref.train == true'
        deny_status: 403
        deny_message: "default-permissive expected"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let resp = harness.get("/", "aipref.localhost").expect("GET");
    assert_eq!(
        resp.status, 200,
        "absent aipref header -> request.aipref.train == true (default-permissive)"
    );
}

// --- Test 5: same surface from Lua and JavaScript transforms ---

#[test]
#[ignore = "TODO(wave5): Lua and JavaScript transform surfaces don't yet receive a `ctx.request` payload (the existing transforms see only the body). The CEL surface for aipref is wired (`request.aipref.{train,search,ai_input}` per `sbproxy_extension::cel::context::populate_aipref_namespace`); plumbing the same fields into the Lua and JS bindings is a small wave-5 follow-up that requires extending `LuaJsonTransform` / `JavaScriptTransform` to take an enriched ctx."]
fn aipref_lua_and_js_surfaces() {
    // Lua surface: a transform reads request.aipref.train and stamps a
    // response header so the test can observe it. The transform path
    // is per-response so the static-action body is enough.
    let lua_yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref-lua.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: lua
        script: |
          function modify_response(resp, ctx)
            local v = (ctx and ctx.request and ctx.request.aipref and ctx.request.aipref.train)
            if v == true then
              resp.headers["x-aipref-train"] = "true"
            else
              resp.headers["x-aipref-train"] = "false"
            end
            return resp
          end
"#;
    let harness = ProxyHarness::start_with_yaml(lua_yaml).expect("start lua proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "aipref-lua.localhost",
            &[("aipref", "train=no, search=yes")],
        )
        .expect("GET lua");
    assert_eq!(
        resp.headers.get("x-aipref-train").map(String::as_str),
        Some("false"),
        "Lua transform must observe request.aipref.train == false for train=no"
    );

    // JS surface: same shape, JavaScript transform.
    let js_yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "aipref-js.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: javascript
        script: |
          function modify_response(resp, ctx) {
            const v = ctx?.request?.aipref?.train;
            resp.headers["x-aipref-train"] = v === true ? "true" : "false";
            return resp;
          }
"#;
    let harness = ProxyHarness::start_with_yaml(js_yaml).expect("start js proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "aipref-js.localhost",
            &[("aipref", "train=no, search=yes")],
        )
        .expect("GET js");
    assert_eq!(
        resp.headers.get("x-aipref-train").map(String::as_str),
        Some("false"),
        "JS transform must observe request.aipref.train == false for train=no"
    );
}
