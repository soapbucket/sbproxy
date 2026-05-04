//! End-to-end coverage for scripting-based response transforms.
//!
//! Covers:
//! * `lua_json`   - Lua script with a `modify_json(data, ctx)` entry.
//! * `javascript` - QuickJS script that gets the raw body string.
//! * `js_json`    - QuickJS script with a parsed JSON value.
//!
//! Each transform's failure mode is also covered. The body
//! buffering pipeline that honours `fail_on_error: true` only runs
//! on proxy-action origins, so failure-path tests use a
//! `MockUpstream`. Static-action origins log-and-continue on error.

use sbproxy_e2e::{MockUpstream, ProxyHarness};

// --- lua_json: modify_json(data, ctx) ---

#[test]
fn lua_json_transform_modifies_json_via_modify_json_function() {
    // Mirrors examples/49-transform-lua/sb.yml.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "lua.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        id: 1
        title: "lua transforms keep their cool"
        body: "the lua script will count these eight words"
        userId: 7
    transforms:
      - type: lua_json
        script: |
          function modify_json(data, ctx)
            if type(data) == "table" then
              if data.title then
                data.title = string.upper(data.title)
              end
              if data.body then
                local count = 0
                for _ in string.gmatch(data.body, "%S+") do
                  count = count + 1
                end
                data.word_count = count
                data.body = nil
              end
              data.transformed_by = "lua"
            end
            return data
          end
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "lua.local").expect("GET");
    assert_eq!(resp.status, 200);
    let json = resp.json().expect("body must be JSON");

    assert_eq!(
        json["title"], "LUA TRANSFORMS KEEP THEIR COOL",
        "title should be uppercased by the lua script"
    );
    assert_eq!(
        json["word_count"], 8,
        "lua script should count the body words: {}",
        json
    );
    assert!(
        json.get("body").is_none(),
        "lua script should drop the body field"
    );
    assert_eq!(json["transformed_by"], "lua");
    assert_eq!(json["id"], 1, "untouched fields pass through");
}

#[test]
fn lua_json_invalid_script_replaces_body_with_error_on_proxy_action() {
    // proxy-action origins honour `fail_on_error: true` by replacing
    // the buffered body with a generic error envelope. The mock
    // upstream returns a benign JSON body that the malformed lua
    // script tries (and fails) to process.
    let upstream = MockUpstream::start(serde_json::json!({"id": 1})).expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lua-bad.local":
    action:
      type: proxy
      url: "{}"
    transforms:
      - type: lua_json
        fail_on_error: true
        script: |
          this is not valid lua syntax !!!
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/", "lua-bad.local").expect("GET");
    let body = resp.text().unwrap_or_default();
    assert!(
        body.contains("\"error\""),
        "expected generic error envelope when lua script fails, got: {}",
        body
    );
}

// --- javascript: function transform(body) returns string ---

#[test]
fn javascript_transform_runs_default_transform_function() {
    // Mirrors examples/50-transform-javascript/sb.yml.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "js.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        id: 1
        title: "javascript runs on the request path"
        body: "this body is longer than forty characters so it will be trimmed by the script"
        userId: 7
    transforms:
      - type: javascript
        script: |
          function transform(body) {
            var data = JSON.parse(body);
            if (typeof data.title === "string") {
              data.title_length = data.title.length;
              data.title_reversed = data.title.split("").reverse().join("");
            }
            if (typeof data.body === "string" && data.body.length > 40) {
              data.body = data.body.slice(0, 40) + "...";
            }
            data.transformed_by = "javascript";
            return JSON.stringify(data);
          }
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "js.local").expect("GET");
    assert_eq!(resp.status, 200);
    let json = resp.json().expect("body must be JSON");

    assert_eq!(
        json["title_length"], 35,
        "javascript should report title length: {}",
        json
    );
    assert_eq!(
        json["title_reversed"], "htap tseuqer eht no snur tpircsavaj",
        "javascript should reverse the title"
    );
    assert!(
        json["body"]
            .as_str()
            .map(|s| s.ends_with("..."))
            .unwrap_or(false),
        "body should be trimmed and end with ...: {}",
        json
    );
    assert_eq!(json["transformed_by"], "javascript");
}

#[test]
fn javascript_transform_with_custom_function_name() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "js-custom.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "hello"
    transforms:
      - type: javascript
        function_name: my_func
        script: |
          function my_func(body) {
            return body.toUpperCase() + "!";
          }
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "js-custom.local").expect("GET");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "HELLO!");
}

#[test]
fn javascript_transform_broken_script_replaces_body_on_proxy_action() {
    let upstream =
        MockUpstream::start(serde_json::json!({"x": "anything"})).expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "js-bad.local":
    action:
      type: proxy
      url: "{}"
    transforms:
      - type: javascript
        fail_on_error: true
        script: |
          function transform(body) {{
            // referencing an undefined symbol should throw
            return totallyUndefinedSymbol();
          }}
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/", "js-bad.local").expect("GET");
    let body = resp.text().unwrap_or_default();
    assert!(
        body.contains("\"error\""),
        "expected generic error envelope when js throws, got: {}",
        body
    );
}

// --- js_json: function modify_json(data) returns object ---

#[test]
fn js_json_transform_doubles_count_and_adds_field() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "jsjson.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        count: 5
        label: "items"
    transforms:
      - type: js_json
        script: |
          function modify_json(data) {
            data.count = data.count * 2;
            data.processed = true;
            return data;
          }
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "jsjson.local").expect("GET");
    assert_eq!(resp.status, 200);
    let json = resp.json().expect("body must be JSON");
    assert_eq!(json["count"], 10);
    assert_eq!(json["processed"], true);
    assert_eq!(json["label"], "items");
}
