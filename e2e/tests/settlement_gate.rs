//! WOR-2143: the settlement origin gate, end to end.
//!
//! Challenge -> settle -> allow against a stub upstream, on the Core
//! Lightning rail: CLN speaks newline-delimited JSON-RPC over a Unix
//! socket, so a stub node needs no TLS and the proxy runs the real
//! adapter, the real SQLite settlement store, and the real gate.
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
//! cargo test -p sbproxy-e2e --release --test settlement_gate
//! ```

#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

/// A payment hash the stub node reports, as 64 lowercase hex chars.
const PAYMENT_HASH: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";

/// A syntactically valid regtest BOLT 11 string (prefix + bech32 chars).
const BOLT11: &str = "lnbcrt100u1stubinvoicestubinvoicestubinvoice";

/// What the stub Core Lightning node knows about its one invoice.
#[derive(Default)]
struct NodeState {
    /// The label the proxy created the invoice under.
    label: Option<String>,
    /// The invoiced amount, in millisatoshi.
    amount_msat: Option<u64>,
    /// Whether the payer settled it.
    paid: bool,
}

/// A stub Core Lightning node on a Unix socket.
///
/// One newline-delimited JSON-RPC exchange per connection, exactly the
/// framing `UnixClnTransport` speaks. Supports `getinfo`, `invoice`,
/// and `listinvoices`, which is the complete surface the settlement
/// path uses.
struct ClnStub {
    state: Arc<Mutex<NodeState>>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ClnStub {
    fn start(socket_path: &std::path::Path) -> anyhow::Result<Self> {
        let listener = UnixListener::bind(socket_path)?;
        listener.set_nonblocking(true)?;
        let state = Arc::new(Mutex::new(NodeState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let stop_flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut raw = Vec::new();
                        let mut byte = [0_u8; 1];
                        while let Ok(read) = stream.read(&mut byte) {
                            if read == 0 || byte[0] == b'\n' {
                                break;
                            }
                            raw.push(byte[0]);
                        }
                        let Ok(request) = serde_json::from_slice::<serde_json::Value>(&raw) else {
                            continue;
                        };
                        let id = request
                            .get("id")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let method = request
                            .get("method")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default();
                        let params = request.get("params").cloned().unwrap_or_default();
                        let result = respond(&thread_state, method, &params);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": result,
                        });
                        let mut bytes = response.to_string().into_bytes();
                        bytes.push(b'\n');
                        let _ = stream.write_all(&bytes);
                        let _ = stream.flush();
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            state,
            stop,
            join: Some(join),
        })
    }

    /// Marks the outstanding invoice as paid, out of band, exactly as a
    /// Lightning payer would.
    fn pay_invoice(&self) {
        self.state.lock().expect("node state").paid = true;
    }
}

impl Drop for ClnStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Answers one JSON-RPC method from the stub node's state.
fn respond(
    state: &Arc<Mutex<NodeState>>,
    method: &str,
    params: &serde_json::Value,
) -> serde_json::Value {
    match method {
        "getinfo" => serde_json::json!({"version": "v26.06"}),
        "invoice" => {
            let mut node = state.lock().expect("node state");
            node.label = params
                .get("label")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            node.amount_msat = params
                .get("amount_msat")
                .and_then(serde_json::Value::as_u64);
            serde_json::json!({
                "payment_hash": PAYMENT_HASH,
                "bolt11": BOLT11,
            })
        }
        "listinvoices" => {
            let node = state.lock().expect("node state");
            let requested = params
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if node.label.as_deref() != Some(requested) {
                return serde_json::json!({"invoices": []});
            }
            let amount = node.amount_msat.unwrap_or_default();
            serde_json::json!({"invoices": [{
                "label": requested,
                "status": if node.paid { "paid" } else { "unpaid" },
                "payment_hash": PAYMENT_HASH,
                "amount_msat": amount,
                "amount_received_msat": if node.paid { amount } else { 0 },
                "bolt11": BOLT11,
            }]})
        }
        _ => serde_json::json!({}),
    }
}

/// A stub origin that counts every request it serves.
struct CountingOrigin {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl CountingOrigin {
    fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let stop_flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let body = "<h1>paid article</h1>";
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0_u8; 8192];
                        let _ = stream.read(&mut buf);
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            hits,
            stop,
            join: Some(join),
        })
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for CountingOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// One running settlement stack: stub node, counting origin, proxy.
struct Stack {
    harness: ProxyHarness,
    node: ClnStub,
    origin: CountingOrigin,
    _dir: tempfile::TempDir,
}

/// Writes one test-only secret into the per-test temp dir, owner
/// read/write only, and returns its absolute path.
///
/// The proxy resolves `file:` references itself at boot, with no
/// `proxy.secrets` backend needed. A provider URI such as
/// `secret://env/NAME` would require one and fail boot without it,
/// which is exactly how the first version of this harness died.
fn write_secret_file(
    dir: &std::path::Path,
    name: &str,
    value: &str,
) -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, value)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// A fresh, clearly test-only binding key per run: 32 bytes from the OS
/// entropy pool, hex encoded. Generated, never vendored, never reused.
fn fresh_test_key() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn start_stack() -> anyhow::Result<Stack> {
    let dir = tempfile::tempdir()?;
    let socket_path = dir.path().join("lightning-rpc");
    let state_path = dir.path().join("settlement.sqlite3");
    // The stub node never checks the rune, so its value only has to
    // exist; the binding key derives real signing material and gets a
    // fresh random value each run.
    let binding_key_path = write_secret_file(dir.path(), "binding.key", &fresh_test_key()?)?;
    let rune_path = write_secret_file(dir.path(), "cln.rune", "sbproxy-e2e-test-only-rune")?;
    let node = ClnStub::start(&socket_path)?;
    let origin = CountingOrigin::start()?;

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
  payments:
    state_path: {state_path}
    challenge_binding_key: file:{binding_key}
    rails:
      lightning_cln:
        socket_path: {socket_path}
        rune: file:{rune}
        quote_currency: BTC
        settlement_decimals: 11
origins:
  "blog.localhost":
    action:
      type: proxy
      url: http://127.0.0.1:{origin_port}
    policies:
      - type: ai_crawl_control
        price: 0.0001
        currency: BTC
        header: crawler-payment
        crawler_user_agents:
          - GPTBot
"#,
        state_path = state_path.display(),
        binding_key = binding_key_path.display(),
        socket_path = socket_path.display(),
        rune = rune_path.display(),
        origin_port = origin.port,
    );

    let harness = ProxyHarness::start_payments_with_yaml_and_env(&yaml, &[])?;
    Ok(Stack {
        harness,
        node,
        origin,
        _dir: dir,
    })
}

const CRAWLER_UA: (&str, &str) = ("user-agent", "GPTBot/1.0");

#[test]
fn challenge_settle_allow_and_replay_refusal() {
    let stack = start_stack().expect("start settlement stack");

    // 1. Challenge: an unpaid crawler gets a 402 with the Lightning
    //    invoice and the signed quote token; the origin sees nothing.
    let challenge = stack
        .harness
        .get_with_headers("/article", "blog.localhost", &[CRAWLER_UA])
        .expect("challenge request");
    assert_eq!(challenge.status, 402, "unpaid crawl is challenged");
    let token = challenge
        .headers
        .get("crawler-payment")
        .expect("the 402 carries the quote token")
        .clone();
    let body = String::from_utf8(challenge.body.clone()).expect("402 body is UTF-8");
    assert!(body.contains(BOLT11), "the 402 carries the invoice: {body}");
    assert!(
        body.contains("\"rail\":\"lightning\""),
        "the 402 names the rail: {body}"
    );
    assert_eq!(
        stack.origin.hits(),
        0,
        "a challenge never touches the origin"
    );

    // 2. Settle out of band, then retry with the quote token: the gate
    //    proves the invoice paid through the real adapter and the real
    //    store, and the request reaches the origin exactly once.
    stack.node.pay_invoice();
    let paid = stack
        .harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[CRAWLER_UA, ("crawler-payment", token.as_str())],
        )
        .expect("paid retry");
    assert_eq!(paid.status, 200, "a settled payment reaches the origin");
    assert_eq!(stack.origin.hits(), 1, "the origin served exactly once");

    // 3. Replay: the same settled quote presented again authorizes
    //    nothing further. The payment settled once, the content served
    //    once.
    let replay = stack
        .harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[CRAWLER_UA, ("crawler-payment", token.as_str())],
        )
        .expect("replay retry");
    assert_eq!(replay.status, 402, "a replay is refused");
    let replay_body = String::from_utf8(replay.body).expect("replay body is UTF-8");
    assert!(
        replay_body.contains("proof_replayed"),
        "the refusal names the replay: {replay_body}"
    );
    assert_eq!(stack.origin.hits(), 1, "a replay never touches the origin");

    // 4. WOR-2219: the whole money path leaves an operational trace.
    //
    // The three assertions above are exactly the shape of test that let
    // `sbproxy_payment_settlement_total` sit at zero through a complete
    // settled payment: the durable rows were right, the status codes were
    // right, and nothing looked at the metric an operator alerts on.
    let metrics = stack
        .harness
        .get("/metrics", "blog.localhost")
        .expect("GET /metrics")
        .text()
        .expect("metrics body is UTF-8");
    let counted = |operation: &str, outcome: &str| {
        metrics.lines().any(|line| {
            line.starts_with("sbproxy_payment_settlement_total{")
                // The rail is the one that settles, not the one advertised:
                // the 402 above says `lightning` and this says
                // `lightning_cln`, which is what keeps this family in one
                // vocabulary with the reconciliation sweep.
                && line.contains("rail=\"lightning_cln\"")
                && line.contains(&format!("operation=\"{operation}\""))
                && line.contains(&format!("outcome=\"{outcome}\""))
                && !line.ends_with(" 0")
        })
    };
    assert!(
        counted("challenge", "prepared"),
        "the 402 prepared a durable challenge and nothing counted it:\n{metrics}"
    );
    assert!(
        counted("redeem", "succeeded"),
        "a settled payment reached the origin and nothing counted it:\n{metrics}"
    );
    assert!(
        counted("redeem", "proof_replayed"),
        "the replay refusal left no trace on the settlement counter:\n{metrics}"
    );
}

#[test]
fn an_unpaid_retry_never_reaches_the_origin() {
    let stack = start_stack().expect("start settlement stack");

    let challenge = stack
        .harness
        .get_with_headers("/article", "blog.localhost", &[CRAWLER_UA])
        .expect("challenge request");
    assert_eq!(challenge.status, 402);
    let token = challenge
        .headers
        .get("crawler-payment")
        .expect("the 402 carries the quote token")
        .clone();

    // The invoice is still unpaid: verified-but-not-settled is a 503,
    // never origin access and never a receipt.
    let unpaid = stack
        .harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[CRAWLER_UA, ("crawler-payment", token.as_str())],
        )
        .expect("unpaid retry");
    assert_eq!(unpaid.status, 503, "an unpaid payment is unavailable");
    assert!(
        unpaid.headers.contains_key("retry-after"),
        "the client is told when to retry"
    );
    assert_eq!(
        stack.origin.hits(),
        0,
        "no unpaid request reaches the origin"
    );
}

/// The value of one `sbproxy_payment_settlement_total` series in a scrape,
/// or zero when nothing has created it.
fn settlement_total(metrics: &str, operation: &str, outcome: &str) -> f64 {
    metrics
        .lines()
        .find(|line| {
            line.starts_with("sbproxy_payment_settlement_total{")
                && line.contains("rail=\"lightning_cln\"")
                && line.contains(&format!("operation=\"{operation}\""))
                && line.contains(&format!("outcome=\"{outcome}\""))
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

#[test]
fn an_early_retry_then_payment_is_never_billed_twice() {
    // WOR-2230, and the sequence this suite never ran: retry, then pay, then
    // retry. `challenge_settle_allow_and_replay_refusal` pays before its
    // first retry, so its intent is never stranded, and
    // `an_unpaid_retry_never_reaches_the_origin` stops at the 503. Between
    // them they left the whole reconciliation path uncovered, which is how a
    // double charge survived in it.
    let stack = start_stack().expect("start settlement stack");

    let challenge = stack
        .harness
        .get_with_headers("/article", "blog.localhost", &[CRAWLER_UA])
        .expect("challenge request");
    assert_eq!(challenge.status, 402, "unpaid crawl is challenged");
    let token = challenge
        .headers
        .get("crawler-payment")
        .expect("the 402 carries the quote token")
        .clone();

    // 1. Retry a little early, before paying. Ordinary crawler behaviour.
    //    The rail verifies the invoice, finds it unpaid, and the intent
    //    strands in `NeedsReconciliation` with a dispatch outstanding.
    let early = stack
        .harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[CRAWLER_UA, ("crawler-payment", token.as_str())],
        )
        .expect("early retry");
    assert_eq!(early.status, 503, "an unpaid retry strands the intent");
    assert_eq!(stack.origin.hits(), 0);

    // 2. The crawler pays. The money is really gone.
    stack.node.pay_invoice();

    // 3. Retry until the strand resolves. The request path never retries a
    //    stranded intent, so what unblocks this is the recovery worker
    //    proving the invoice paid, not a second settle from here.
    let mut last = 0_u16;
    for _ in 0..80 {
        let retry = stack
            .harness
            .get_with_headers(
                "/article",
                "blog.localhost",
                &[CRAWLER_UA, ("crawler-payment", token.as_str())],
            )
            .expect("retry after paying");
        last = retry.status;
        if last != 503 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(
        last, 200,
        "a payment the worker proved settled has to serve the content it bought",
    );
    assert_eq!(stack.origin.hits(), 1, "the origin served exactly once");

    // 4. One payment, one invoice. This is the assertion the bug was about:
    //    a second prepared challenge here is a second bill for an article
    //    the crawler already paid for.
    let metrics = stack
        .harness
        .get("/metrics", "blog.localhost")
        .expect("GET /metrics")
        .text()
        .expect("metrics body is UTF-8");
    assert!(
        (settlement_total(&metrics, "challenge", "prepared") - 1.0).abs() < f64::EPSILON,
        "exactly one challenge may ever be prepared for one paid article:\n{metrics}"
    );
}

#[test]
fn a_configured_rail_seeds_its_settlement_series() {
    // Boot, scrape, no traffic. An operator who cannot find the family at
    // all has no way to tell a quiet deployment from one whose settlement
    // path reports nothing, and the second reads as the first for as long
    // as nobody pays. The seed is what makes the absence mean
    // misconfiguration.
    let stack = start_stack().expect("start settlement stack");

    let metrics = stack
        .harness
        .get("/metrics", "blog.localhost")
        .expect("GET /metrics")
        .text()
        .expect("metrics body is UTF-8");
    let seeded = |operation: &str, outcome: &str| {
        metrics.lines().any(|line| {
            line.starts_with("sbproxy_payment_settlement_total{")
                && line.contains("rail=\"lightning_cln\"")
                && line.contains(&format!("operation=\"{operation}\""))
                && line.contains(&format!("outcome=\"{outcome}\""))
        })
    };
    assert!(
        seeded("challenge", "prepared"),
        "a configured rail must draw a flat line before its first challenge:\n{metrics}"
    );
    assert!(
        seeded("redeem", "succeeded"),
        "a configured rail must draw a flat line before its first settlement:\n{metrics}"
    );
    assert_eq!(
        stack.origin.hits(),
        0,
        "the seed comes from startup, not from a request"
    );
}

#[test]
fn a_reader_is_never_challenged() {
    let stack = start_stack().expect("start settlement stack");
    let reader = stack
        .harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (Macintosh)")],
        )
        .expect("reader request");
    assert_eq!(reader.status, 200, "a reader passes without payment");
    assert_eq!(stack.origin.hits(), 1);
}
