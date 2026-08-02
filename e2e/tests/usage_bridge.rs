//! Billable usage reaches the durable queue from real traffic (WOR-2169).
//!
//! `proxy.payments.usage_reporters.stripe_meter` shipped with a reporter, a
//! durable queue, and a worker that drains it, and with no producer. An
//! operator could configure the block, pass validation, pass startup, serve
//! traffic, and enqueue nothing. The existing coverage did not catch it
//! because `crates/sbproxy-billing/tests/stripe_meter_contract.rs` hands the
//! reporter an event it built itself, which is one step past the step that
//! was missing.
//!
//! So every test here starts at an HTTP request through the harness and
//! finishes by reading the SQLite file the recovery worker drains. Nothing
//! below constructs a `UsageEvent`, calls a reporter, or touches an internal
//! type. If the producer is removed again, these fail.
//!
//! # What is deliberately not tested here
//!
//! The Stripe leg. `StripeMeterEndpoints::from_api_root` refuses anything
//! that is not an HTTPS root and the API root is a constant, so there is no
//! configuration that points the reporter at a loopback stub the way the
//! Core Lightning tests point the settler at a Unix socket. The reporter's
//! wire contract is covered against a stub transport in
//! `crates/sbproxy-billing/tests/stripe_meter_contract.rs`; what was missing
//! and what is covered here is everything up to the queue.
//!
//! That split is also the property the last test asserts directly: a served
//! request must reach the queue and stop, because a provider call on the
//! request path would put Stripe's availability in front of the origin.
//!
//! Requires a payments-featured binary. Build it once with:
//!
//! ```text
//! CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy \
//!   --features payment-x402,payment-mpp,payment-stripe,payment-lightning-cln
//! ```
//!
//! or point `SBPROXY_E2E_PAYMENTS_BIN` at one. Then:
//!
//! ```text
//! cargo test -p sbproxy-e2e --release --test usage_bridge
//! ```

#![cfg(unix)]

use std::io::Read as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};

/// The host every AI request in this file targets.
const AI_HOST: &str = "billing.localhost";

/// The Stripe customer the minted key carries, and therefore the account
/// every queued row bills.
const CUSTOMER: &str = "cus_wor2169e2e";

/// The Stripe meter event name the reporter is configured with.
const EVENT_NAME: &str = "sbproxy_ai_tokens";

/// `examples/usage-bridge-queue/`, resolved from the crate that is running.
fn example_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate lives under workspace root")
        .join("examples/usage-bridge-queue")
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("HTTP client")
}

fn pick_admin_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// One completion, with token counts the meter event turns into a quantity.
fn chat_reply() -> Value {
    json!({
        "id": "chatcmpl-usage-bridge",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-client",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 900,
            "completion_tokens": 120,
            "total_tokens": 1020
        }
    })
}

/// Writes one test-only secret into the per-test temp dir, owner read/write
/// only, and returns its absolute path.
///
/// The proxy resolves `file:` references itself at boot with no
/// `proxy.secrets` backend configured, which a `secret://env/NAME`
/// reference would require.
fn write_secret_file(dir: &Path, name: &str, value: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, value).expect("write secret file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict secret file");
    path
}

/// A fresh, clearly test-only key: 32 bytes from the OS entropy pool, hex
/// encoded. Generated, never vendored, never reused.
fn fresh_test_key() -> String {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .expect("open urandom")
        .read_exact(&mut bytes)
        .expect("read urandom");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The `proxy.payments` half of the document, parameterised on the two
/// things each test varies.
///
/// `reporter` is a whole YAML block rather than a field, so the last test
/// can leave it out entirely and prove the no-reporter case rather than
/// assert it in a comment.
fn payments_block(
    state_path: &Path,
    binding_key: &Path,
    stripe_key: &Path,
    reporter: &str,
) -> String {
    format!(
        r#"  payments:
    state_path: '{state_path}'
    challenge_binding_key: 'file:{binding_key}'
    recovery_encryption:
      key_id: usage-bridge-e2e
      key: 'file:{recovery_key}'
      max_age_hours: 23
    worker:
      reconcile_interval_ms: 1000
      max_reconcile_batch: 4
      shutdown_timeout_ms: 2000
    rails:
      stripe:
        api_key: 'file:{stripe_key}'
        business_network_id: profile_test_example
        quote_currency: USD
        currency_decimals: 2
        payment_method_types: [card]
{reporter}"#,
        state_path = state_path.display(),
        binding_key = binding_key.display(),
        // One file serves as both secrets. Both are 32 bytes of hex, both
        // are test-only, and the recovery cipher checks the resolved length
        // rather than the path it came from.
        recovery_key = binding_key.display(),
        stripe_key = stripe_key.display(),
    )
}

/// The reporter block, bound to one source and one unit.
fn reporter_block(source: &str, unit: &str, failure_posture: &str) -> String {
    format!(
        "    usage_reporters:\n      \
         stripe_meter:\n        \
         event_name: {EVENT_NAME}\n        \
         customer_field: stripe_customer_id\n        \
         source: {source}\n        \
         unit: {unit}\n        \
         failure_posture: {failure_posture}\n"
    )
}

/// A running stack: proxy, mock model provider, and the paths the test reads.
struct Stack {
    proxy: ProxyHarness,
    admin_port: u16,
    state_path: PathBuf,
    _upstream: MockUpstream,
    _dir: tempfile::TempDir,
}

/// Boot a proxy with governed keys, an AI origin, and the given reporter
/// block (which may be empty).
fn start(reporter: &str) -> Stack {
    let dir = tempfile::tempdir().expect("temp dir");
    let admin_port = pick_admin_port();
    let state_path = dir.path().join("payments.sqlite3");
    let key_store = dir.path().join("keys.redb");
    let binding_key = write_secret_file(dir.path(), "binding.key", &fresh_test_key());
    let stripe_key = write_secret_file(dir.path(), "stripe.key", "sk_test_usage_bridge_e2e");
    let upstream = MockUpstream::start(chat_reply()).expect("mock model provider");

    let payments = payments_block(&state_path, &binding_key, &stripe_key, reporter);
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
  tenants:
    - id: tenant-a
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: '{key_store}'
    cache:
      ttl_secs: 60
    crypto:
      pepper: usage-bridge-e2e-pepper
      master_key: usage-bridge-e2e-master
    failure_mode_allow: false
{payments}
origins:
  "{AI_HOST}":
    tenant_id: tenant-a
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: sk-openai
          base_url: "{upstream}"
          allow_private_base_url: true
          default_model: gpt-client
          models: [gpt-client]
"#,
        key_store = key_store.display(),
        upstream = upstream.base_url(),
    );

    let proxy =
        ProxyHarness::start_payments_with_yaml_and_env(&yaml, &[]).expect("start payments proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10)).expect("admin port to bind");

    Stack {
        proxy,
        admin_port,
        state_path,
        _upstream: upstream,
        _dir: dir,
    }
}

fn admin_post(port: u16, path: &str, body: Option<&Value>) -> (u16, String) {
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut builder = http_client().post(url).basic_auth("admin", Some("secret"));
    if let Some(body) = body {
        builder = builder.json(body);
    }
    let response = builder.send().expect("admin request");
    let status = response.status().as_u16();
    (status, response.text().unwrap_or_default())
}

/// Mint a governed key whose credential metadata carries the Stripe
/// customer, which is where the reporter's `customer_field` resolves from.
///
/// Deliberately not a request header. A caller that could nominate the
/// account their usage bills to by setting a header could bill it to
/// somebody else.
fn mint_key(stack: &Stack) -> String {
    let (status, text) = admin_post(
        stack.admin_port,
        "/admin/keys",
        Some(&json!({
            "name": "usage-bridge-e2e",
            "tenant": "tenant-a",
            "metadata": {"stripe_customer_id": CUSTOMER}
        })),
    );
    assert_eq!(status, 201, "mint governed key: {text}");
    let body: Value = serde_json::from_str(&text).expect("mint response JSON");
    body["token"].as_str().expect("one-time token").to_string()
}

/// Drive one chat completion through the proxy as the minted key.
fn chat(stack: &Stack, token: &str) -> u16 {
    let authorization = format!("Bearer {token}");
    let response = stack
        .proxy
        .post_json(
            "/v1/chat/completions",
            AI_HOST,
            &json!({
                "model": "gpt-client",
                "messages": [{"role": "user", "content": "bill this"}]
            }),
            &[("authorization", authorization.as_str())],
        )
        .expect("AI request");
    response.status
}

/// One row of the durable usage queue, read back the way the recovery
/// worker reads it.
#[derive(Debug, Clone)]
struct QueuedUsage {
    reporter: String,
    usage_identifier: String,
    tenant_id: String,
    origin_id: String,
    status: String,
    event: Value,
}

/// Every queued usage row, oldest first.
///
/// Opened read-only so the assertion cannot perturb the file the running
/// proxy still owns.
fn queued_rows(state_path: &Path) -> Vec<QueuedUsage> {
    if !state_path.exists() {
        return Vec::new();
    }
    let connection = rusqlite::Connection::open_with_flags(
        state_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open the settlement store read only");
    let mut statement = connection
        .prepare(
            "SELECT reporter, usage_identifier, tenant_id, origin_id, status, event_jcs
               FROM usage_reports ORDER BY created_at_ms, usage_identifier",
        )
        .expect("the usage queue table exists");
    let rows = statement
        .query_map([], |row| {
            Ok(QueuedUsage {
                reporter: row.get(0)?,
                usage_identifier: row.get(1)?,
                tenant_id: row.get(2)?,
                origin_id: row.get(3)?,
                status: row.get(4)?,
                event: serde_json::from_str(&row.get::<_, String>(5)?)
                    .expect("a queued event is JSON"),
            })
        })
        .expect("scan the usage queue");
    rows.map(|row| row.expect("read a usage row")).collect()
}

/// Poll until the queue holds at least `want` rows, or fail.
///
/// The row is written in the proxy's `logging` phase, which runs after the
/// response has reached the client, so a test that read the file the instant
/// its HTTP call returned would be racing the writer.
fn wait_for_rows(state_path: &Path, want: usize) -> Vec<QueuedUsage> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = queued_rows(state_path);
        if rows.len() >= want {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "the usage queue at {} never reached {want} rows; it held {:?}",
            state_path.display(),
            rows,
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_served_ai_request_queues_one_billable_unit() {
    let stack = start(&reporter_block("ai", "total_tokens", "degraded"));
    let token = mint_key(&stack);

    assert_eq!(chat(&stack, &token), 200, "the request must be served");

    let rows = wait_for_rows(&stack.state_path, 1);
    assert_eq!(rows.len(), 1, "one request, one billable unit: {rows:?}");
    let row = &rows[0];

    assert_eq!(row.reporter, "stripe_meter");
    assert_eq!(
        row.tenant_id, "tenant-a",
        "the row is attributed to a tenant"
    );
    assert_eq!(row.origin_id, AI_HOST);
    assert_eq!(
        row.status, "queued",
        "the request path enqueues and stops; draining is the worker's job"
    );

    // The event the worker will hand the reporter, verbatim.
    assert_eq!(row.event["event_name"], EVENT_NAME);
    assert_eq!(
        row.event["quantity"], 1020,
        "900 prompt plus 120 completion, which is what the upstream reported"
    );
    assert_eq!(
        row.event["attributes"]["stripe_customer_id"], CUSTOMER,
        "the customer comes from the credential, so the bill has an account"
    );

    // Resource type and name are explicit. An AI call is a model, and it
    // says so rather than arriving as an unlabelled quantity.
    assert_eq!(row.event["attributes"]["resource_type"], "ai_model");
    assert_eq!(
        row.event["attributes"]["resource_name"],
        "openai/gpt-client"
    );
    assert_eq!(row.event["attributes"]["unit"], "total_tokens");
    assert!(
        row.event["attributes"]["claim_id"]
            .as_str()
            .is_some_and(|claim| !claim.is_empty()),
        "a queued row has to name the work it bills for: {row:?}"
    );

    assert!(
        row.usage_identifier.starts_with("sbu-"),
        "the identifier is namespaced to this proxy: {}",
        row.usage_identifier
    );
    assert!(
        row.usage_identifier.len() <= 200,
        "Stripe bounds an identifier at 200 characters: {}",
        row.usage_identifier
    );
}

#[test]
fn the_examples_own_walkthrough_still_runs() {
    // Everything above drives the proxy directly, which is why all of it
    // stayed green while the example next to it rotted (WOR-2220). The
    // example's entry point fed a non-2xx admin body to a JSON parser and
    // reported a missing `token` field instead of the HTTP status that
    // explained it, and the README's documented query selected a `quantity`
    // column that `usage_reports` does not have. Nothing ran either one:
    // `scripts/examples-smoke.sh` gates on a `docker-compose.yml`, and this
    // example ships none because the shared image compiles the default
    // feature set while the meter needs `payment-stripe`.
    //
    // So this test runs the shipped script and the README's own sqlite3
    // commands rather than reimplementing them. A walkthrough that stops
    // working is a failure here.
    let stack = start(&reporter_block("ai", "total_tokens", "degraded"));
    let example = example_dir();
    let state = stack.state_path.display().to_string();

    let output = Command::new("bash")
        .arg(example.join("bin/bill-one-call.sh"))
        .env("ADMIN", format!("http://127.0.0.1:{}", stack.admin_port))
        .env("ADMIN_AUTH", "admin:secret")
        .env("PROXY", stack.proxy.base_url())
        .env("HOST", AI_HOST)
        .env("MODEL", "gpt-client")
        .env("CUSTOMER", CUSTOMER)
        .env("STATE", &state)
        .output()
        .expect("run examples/usage-bridge-queue/bin/bill-one-call.sh");

    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.success(),
        "bin/bill-one-call.sh is the example's own entry point and has to run \
         clean: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Reported by the walkthrough itself, so a script that stops billing
    // fails here rather than printing a reassuring zero.
    let reported = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("rows on the usage queue"))
        .map(str::trim)
        .next();
    assert_eq!(
        reported,
        Some("1"),
        "one call, one billable unit:\nstdout:\n{stdout}"
    );

    // Every sqlite3 command the README promises output for, run against the
    // file this stack actually wrote. Parsed out of the CAPTURE markers so
    // the assertion cannot drift from the text the reader is given.
    let readme = std::fs::read_to_string(example.join("README.md"))
        .expect("read examples/usage-bridge-queue/README.md");
    let mut ran = 0_usize;
    for line in readme.lines() {
        let documented = match line
            .strip_prefix("<!-- CAPTURE: ")
            .and_then(|rest| rest.strip_suffix(" -->"))
        {
            Some(command) if command.starts_with("sqlite3 ") => command,
            _ => continue,
        };
        let command = documented.replace("/tmp/sbproxy-usage-bridge/payments.sqlite3", &state);
        let output = Command::new("bash")
            .arg("-c")
            .arg(&command)
            .output()
            .expect("run a documented sqlite3 command");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "the README documents this command and promises its output:\n  \
             {documented}\n{stderr}"
        );
        assert!(
            !output.stdout.is_empty(),
            "this documented command returned nothing, so the block under it \
             in the README would be empty:\n  {documented}"
        );
        ran += 1;
    }
    assert!(
        ran >= 2,
        "the README's sqlite3 walkthrough commands went missing; ran {ran}"
    );
}

#[test]
fn two_requests_queue_two_rows_with_two_identifiers() {
    // The failure this guards against is an identifier keyed on something
    // that does not vary per sale. Every row would then collide, the
    // provider would deduplicate them back down to one, and the operator
    // would bill for one request out of every N with nothing anywhere
    // recording the difference.
    let stack = start(&reporter_block("ai", "total_tokens", "degraded"));
    let token = mint_key(&stack);

    assert_eq!(chat(&stack, &token), 200);
    assert_eq!(chat(&stack, &token), 200);

    let rows = wait_for_rows(&stack.state_path, 2);
    assert_eq!(rows.len(), 2, "two sales, two rows: {rows:?}");
    assert_ne!(
        rows[0].usage_identifier, rows[1].usage_identifier,
        "two requests that both consumed tokens are two charges"
    );

    // Same account, same meter event, same unit. Only the claim moved.
    assert_eq!(
        rows[0].event["attributes"]["stripe_customer_id"],
        rows[1].event["attributes"]["stripe_customer_id"]
    );
    assert_eq!(rows[0].event["event_name"], rows[1].event["event_name"]);
    assert_ne!(
        rows[0].event["attributes"]["claim_id"],
        rows[1].event["attributes"]["claim_id"]
    );
}

#[test]
fn the_configured_source_decides_what_is_billed_and_nothing_else_is() {
    // The double-charge guard. This origin serves AI traffic, and the
    // meter event is bound to `mcp`, so it bills nothing: the same request
    // is not allowed to be both an AI sale and a tool sale just because it
    // could plausibly be described as either.
    let stack = start(&reporter_block("mcp", "tool_call", "degraded"));
    let token = mint_key(&stack);

    assert_eq!(chat(&stack, &token), 200, "the request is still served");

    // Give the writer the same window the positive tests get, so this is
    // "nothing was queued" rather than "the assertion ran first".
    std::thread::sleep(Duration::from_secs(2));
    let rows = queued_rows(&stack.state_path);
    assert!(
        rows.is_empty(),
        "a meter event bound to mcp must not bill an AI request: {rows:?}"
    );
}

#[test]
fn an_ai_request_with_no_reporter_configured_queues_nothing() {
    // Requirement stated as a test rather than as a comment: with no
    // reporter block the request path does no billing work at all. The
    // settlement store is still open and still has the table, so an empty
    // table is a real observation rather than a missing file.
    let stack = start("");
    let token = mint_key(&stack);

    assert_eq!(chat(&stack, &token), 200);

    std::thread::sleep(Duration::from_secs(2));
    let rows = queued_rows(&stack.state_path);
    assert!(
        rows.is_empty(),
        "no reporter configured means no billing work: {rows:?}"
    );

    // And the counter agrees. A row that was written and then deleted would
    // satisfy the assertion above; a counter that never moved would not.
    let metrics = stack
        .proxy
        .get("/metrics", AI_HOST)
        .expect("GET /metrics")
        .text()
        .unwrap_or_default();
    assert!(
        !metrics.contains("sbproxy_usage_bridge_enqueued_total"),
        "an unconfigured bridge must not even create the series"
    );
}

#[test]
fn a_queued_row_carries_no_provider_call_with_it() {
    // The hot path enqueues and stops. The row's `status` is the visible
    // half of that: `queued` means nothing has been dispatched, and only
    // the recovery worker's own lease moves it on. A request path that
    // called Stripe inline would have to reach a terminal status here, and
    // would have put a third party's availability in front of the origin.
    let stack = start(&reporter_block("ai", "prompt_tokens", "degraded"));
    let token = mint_key(&stack);

    assert_eq!(chat(&stack, &token), 200);

    let rows = wait_for_rows(&stack.state_path, 1);
    assert_eq!(rows[0].status, "queued");
    assert_eq!(
        rows[0].event["quantity"], 900,
        "the configured unit is prompt tokens, so the quantity is the prompt"
    );

    // The bridge counted it, against the tenant it belongs to. A billing
    // counter that merged every tenant would answer a question nobody asks.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = stack
            .proxy
            .get("/metrics", AI_HOST)
            .expect("GET /metrics")
            .text()
            .unwrap_or_default();
        let counted = metrics.lines().any(|line| {
            line.starts_with("sbproxy_usage_bridge_enqueued_total")
                && line.contains("tenant_id=\"tenant-a\"")
                && line.contains("resource_type=\"ai_model\"")
                && !line.ends_with(" 0")
        });
        if counted {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "sbproxy_usage_bridge_enqueued_total never moved for tenant-a; \
             a queued charge left no operational trace"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
