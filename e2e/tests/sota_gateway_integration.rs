//! WOR-2658: the SOTA gateway epic (WOR-2646), assembled.
//!
//! The nine feature siblings of this epic each merged with their own
//! unit coverage, and every one of them touches the same dispatch path:
//! a model group picks a member, cache affinity re-orders the pick,
//! service tier rewrites the outbound body, SigV4 signs whatever that
//! rewriting produced, the pre-header budget decides when a stream may
//! still be moved, and the tenant-key fallback decides which credential
//! pays. Green unit tests on nine features that share one code path are
//! not evidence that the nine compose. This file is that evidence.
//!
//! Everything here runs through the real `ProxyHarness` against the
//! binary `sbproxy_e2e::proxy_binary_path` resolves, which is
//! `SBPROXY_E2E_BIN` when set, then `target/release/sbproxy`, then
//! `target/debug/sbproxy`. Nothing here enforces the release build, so
//! every wall-clock assertion in this file is sized to hold under a
//! debug one: the pre-header tests allow two seconds for a 400 ms
//! budget, and the shadow-dispatch test allows 700 ms against copies
//! that take 1.5 seconds. Every claim is a named test.
//!
//! # Where a stub cannot be the real vendor, the wire is
//!
//! Two of the epic's claims are about a vendor this suite cannot dial,
//! so both are emulated at the wire level and the emulation is stated
//! rather than implied:
//!
//! - **SigV4 to Bedrock.** No AWS account is involved. The Bedrock stub
//!   captures the request the proxy actually sent and
//!   [`recompute_sigv4_signature`] rebuilds the canonical request,
//!   string-to-sign, and signature from the same static credentials the
//!   config names, then compares them against the `Authorization`
//!   header byte for byte. Because the payload hash is folded into the
//!   canonical request, a signature that verifies against the *arrived*
//!   body is proof that nothing rewrote the body after signing, which
//!   is the property the epic is worried about. What this does not
//!   prove is that AWS would accept the signature; that is the
//!   `aws-sigv4` crate's own contract, exercised by
//!   `crates/sbproxy-ai/src/aws_sigv4.rs` against AWS's published test
//!   vectors.
//! - **An OpenAI SDK client reading `GET /v1/models`.** No SDK is
//!   linked here. [`assert_openai_sdk_model_shape`] applies a strict
//!   schema of exactly what the OpenAI `Model` object declares required
//!   (`id`, `object == "model"`, an integer `created`, a string
//!   `owned_by`), which is the set an SDK-shaped deserializer refuses
//!   the response without. A field the SDK ignores is allowed through;
//!   a missing required field or a wrong JSON type fails.
//!
//! # What this file deliberately does not assert
//!
//! One of WOR-2658's verification lines describes a surface the merged
//! code does not have, and inventing an assertion that passes anyway
//! would be worse than saying so: the value ledger answers what *local
//! versus cloud serving* and what *compression* saved (`record_local`,
//! `record_cloud`, `record_compression`). It has no tier lane and no
//! cache-affinity lane, so it cannot answer what the tier choice or the
//! affinity saved. Pricing the tier that was not chosen, and pricing
//! the cache miss that did not happen, are both counterfactuals nobody
//! has defined yet, which makes a fourth lane a design decision rather
//! than an integration fix. No test here pretends otherwise.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::KeyInit as _;
use hmac::{Hmac, Mac};
use sbproxy_e2e::{proxy_binary_path, ProxyHarness};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The tenant's own provider key, refused by the flex stub in the
/// fallback tests.
const TENANT_KEY: &str = "sk-tenant-acme-e2e";
/// The operator-held credential the fallback retries on.
const HOUSE_KEY: &str = "sk-house-operator-e2e";
/// Static AWS credentials for the signed member. Not real, and never
/// leave loopback.
const AWS_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const AWS_REGION: &str = "us-east-1";

/// Model ids, one per group member. Distinct on purpose: a member that
/// can be addressed by its own id makes every non-group test
/// deterministic without leaning on a weighted draw.
const MODEL_SIGNED: &str = "claude-e2e";
const MODEL_FLEX: &str = "gpt-e2e-flex";
const MODEL_STANDARD: &str = "gpt-e2e-standard";
/// The one public name the group publishes.
const GROUP: &str = "sota-chat";
/// Served by `openai-flex` **and** `openai-flex-backup`, so a stalled
/// candidate has somewhere to go. Kept off `MODEL_FLEX` on purpose: the
/// single-candidate ids above are what make every non-failover test
/// deterministic.
const MODEL_STALL: &str = "gpt-e2e-stall";
/// Served by `openai-standard` **and** `openai-standard-backup`, so
/// "nothing moved after the commit point" is a claim with something to
/// move to.
const MODEL_STREAM: &str = "gpt-e2e-stream";

// ---------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------

/// A raw HTTP/1.1 stub that answers every request from a closure and
/// records what it was sent.
///
/// `MockUpstream` covers fixed and sequenced replies; this one exists
/// because several tests here need the *request* to decide the reply
/// (a Bedrock path, a refused credential, a stalled stream) and need
/// the captured bytes afterward for signature verification.
struct ScriptedUpstream {
    port: u16,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// One request as the stub received it, before anything normalized it.
#[derive(Debug, Clone)]
struct SeenRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl SeenRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// What a stub does with one request.
enum Reply {
    /// A complete response: status, content type, body.
    Body(u16, &'static str, Vec<u8>),
    /// Accept the connection, send nothing at all, and hold it open.
    /// This is the pre-header stall: the proxy has a live socket and no
    /// response line.
    StallForever,
    /// Send response headers and one SSE frame, then drop the
    /// connection mid-stream. Past the headers the request is committed
    /// to this provider.
    DieMidStream(String),
    /// A complete SSE stream, terminated properly.
    Sse(Vec<String>),
    /// Read the request and close the connection without answering.
    /// The proxy sees a transport failure, which is the failure class
    /// a candidate order exists to route around.
    Hangup,
}

impl ScriptedUpstream {
    fn start<F>(reply: F) -> ScriptedUpstream
    where
        F: Fn(&SeenRequest, usize) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("stub listener");
        let port = listener.local_addr().expect("stub addr").port();
        listener
            .set_nonblocking(true)
            .expect("stub nonblocking listener");
        let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));

        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            // Held open until shutdown so a `StallForever` connection is
            // not closed by dropping its stream.
            let mut stalled: Vec<TcpStream> = Vec::new();
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = match read_request(&mut stream) {
                            Ok(request) => request,
                            Err(_) => continue,
                        };
                        if let Ok(mut log) = seen_thread.lock() {
                            log.push(request.clone());
                        }
                        let index = count.fetch_add(1, Ordering::SeqCst);
                        match reply(&request, index) {
                            Reply::Body(status, content_type, body) => {
                                let head = format!(
                                    "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n\
                                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(head.as_bytes());
                                let _ = stream.write_all(&body);
                                let _ = stream.flush();
                            }
                            Reply::StallForever => {
                                stalled.push(stream);
                            }
                            Reply::Hangup => {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                drop(stream);
                            }
                            Reply::Sse(frames) => {
                                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                                     Cache-Control: no-cache\r\nConnection: close\r\n\r\n";
                                let _ = stream.write_all(head.as_bytes());
                                for frame in frames {
                                    let _ = stream.write_all(frame.as_bytes());
                                }
                                let _ = stream.flush();
                            }
                            Reply::DieMidStream(frame) => {
                                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                                            Cache-Control: no-cache\r\n\
                                            Transfer-Encoding: chunked\r\n\r\n";
                                let _ = stream.write_all(head.as_bytes());
                                let chunk = format!("{:x}\r\n{}\r\n", frame.len(), frame);
                                let _ = stream.write_all(chunk.as_bytes());
                                let _ = stream.flush();
                                // No terminating chunk: the peer sees a
                                // truncated body, which is what a
                                // provider dying mid-stream looks like.
                                drop(stream);
                            }
                        }
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        ScriptedUpstream {
            port,
            seen,
            stop,
            join: Some(join),
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().map(|log| log.clone()).unwrap_or_default()
    }
}

impl Drop for ScriptedUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Read one HTTP/1.1 request: request line, headers, `Content-Length`
/// body. Enough for a stub, and deliberately no more.
fn read_request(stream: &mut TcpStream) -> std::io::Result<SeenRequest> {
    // The listener is non-blocking so the accept loop can poll its stop
    // flag; the accepted stream must not be, or every read here returns
    // `WouldBlock` before the request arrives. A read timeout also has
    // no meaning on a non-blocking socket.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(SeenRequest {
        method,
        path,
        headers,
        body,
    })
}

fn openai_reply(model: &str, content: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "chatcmpl-sota",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 11,
            "completion_tokens": 5,
            "total_tokens": 16,
            "prompt_tokens_details": {"cached_tokens": 7},
            // The gateway's usage extractor reads this key in either
            // vendor shape, and this branch's own admin row column
            // `tokens_cache_write` has no other source. A stub that
            // reported only cache reads would leave that column
            // untested on every request the suite makes.
            "cache_creation_input_tokens": 3
        }
    }))
    .expect("openai reply")
}

/// A guardrail intervention shaped the way Bedrock shapes one: the
/// `stopReason`, and a `trace` whose input assessment carries the
/// matched text verbatim.
///
/// The echo is the point. Without it the proxy has nothing of the
/// caller's to leak and "the refusal quotes nothing" passes whatever
/// the proxy does with the upstream payload.
fn intervened_converse_reply(caller_text: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "output": {"message": {"role": "assistant", "content": [{"text": ""}]}},
        "stopReason": "guardrail_intervened",
        "usage": {"inputTokens": 12, "outputTokens": 4, "totalTokens": 16},
        "trace": {
            "guardrail": {
                "inputAssessment": {
                    "e2e-guardrail": {
                        "sensitiveInformationPolicy": {
                            "piiEntities": [{
                                "type": "US_SOCIAL_SECURITY_NUMBER",
                                "match": caller_text,
                                "action": "BLOCKED"
                            }]
                        },
                        "invocationMetrics": {"guardrailProcessingLatency": 12}
                    }
                }
            }
        }
    }))
    .expect("intervened converse reply")
}

fn converse_reply(text: &str, stop_reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "output": {"message": {"role": "assistant", "content": [{"text": text}]}},
        "stopReason": stop_reason,
        "usage": {"inputTokens": 12, "outputTokens": 4, "totalTokens": 16}
    }))
    .expect("converse reply")
}

/// A complete OpenAI-shaped SSE stream: one content delta, one finish
/// frame, `[DONE]`.
fn sse_frames(content: &str) -> Vec<String> {
    vec![
        format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-sota",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000,
                "model": MODEL_STALL,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}}]
            })
        ),
        format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-sota",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000,
                "model": MODEL_STALL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            })
        ),
        "data: [DONE]\n\n".to_string(),
    ]
}

fn wants_stream(request: &SeenRequest) -> bool {
    request.json().get("stream").and_then(Value::as_bool) == Some(true)
}

fn refused_credential() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "error": {
            "message": "Incorrect API key provided.",
            "type": "invalid_request_error",
            "code": "invalid_api_key"
        }
    }))
    .expect("refusal body")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

// ---------------------------------------------------------------------
// The composite config
// ---------------------------------------------------------------------

/// Ports and paths one composite gateway needs.
struct Wiring<'a> {
    admin_port: u16,
    key_store: &'a Path,
    usage_path: &'a Path,
    events_path: &'a Path,
    signed_url: &'a str,
    flex_url: &'a str,
    standard_url: &'a str,
    shadow_a_url: &'a str,
    shadow_b_url: &'a str,
    flex_backup_url: &'a str,
    standard_backup_url: &'a str,
    rate_card_path: &'a Path,
}

/// The whole epic in one `ai_proxy` action.
///
/// Every sibling of WOR-2646 is present here at once, which is the
/// point: these keys were reviewed one at a time and they all lower
/// onto one candidate-selection path.
fn composite_config(wiring: &Wiring<'_>) -> String {
    let Wiring {
        admin_port,
        key_store,
        usage_path,
        events_path,
        signed_url,
        flex_url,
        standard_url,
        shadow_a_url,
        shadow_b_url,
        flex_backup_url,
        standard_backup_url,
        rate_card_path,
    } = wiring;
    let key_store = key_store.display();
    let usage_path = usage_path.display();
    let events_path = events_path.display();
    let rate_card_path = rate_card_path.display();
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  tenants:
    - id: acme
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{key_store}"
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    inbound:
      headers:
        - name: x-sb-api
          scheme: ""
      require: false
    seed:
      credentials:
        - id: house-openai
          name: house openai account
          provider: openai
          secret: {HOUSE_KEY}
events:
  sink: file
  path: "{events_path}"
  types:
    - credential_fallback
origins:
  "sota.local":
    tenant_id: acme
    action:
      type: ai_proxy
      capture_content: true
      # WOR-2647: the published limits come from the operator's rate
      # card, which is where `max_output_tokens` lives. Without one the
      # listing can only report a context window for models the static
      # table happens to name, so the verify line "the group, its
      # members, and their limits" would be unreachable by fixture
      # construction rather than by product behavior.
      rate_card: "{rate_card_path}"
      usage_sinks:
        - type: jsonl_file
          path: "{usage_path}"
      routing:
        strategy: round_robin
      cache_affinity:
        ttl_secs: 300
        max_keys_per_provider: 64
      resilience:
        pre_header_timeout_ms: 400
        # `round_robin` spreads rather than orders, so on its own it
        # gives the attempt loop a budget of one and a dead candidate
        # is a 502. The attempt budget, not the strategy, is what
        # decides whether a failure is handed on, and this key opens
        # it. That is what lets a keyed conversation on this origin
        # cross a real failover, which is WOR-2658's third scope item.
        content_policy_fallback: true
      providers:
        - name: bedrock-guarded
          provider_type: bedrock
          base_url: "{signed_url}"
          allow_private_base_url: true
          models: [{MODEL_SIGNED}]
          aws_sigv4:
            region: {AWS_REGION}
            credentials:
              source: static
              access_key_id: {AWS_ACCESS_KEY_ID}
              secret_access_key: {AWS_SECRET_ACCESS_KEY}
          bedrock_guardrail:
            identifier: e2e-guardrail
            version: DRAFT
            trace: true
        - name: openai-flex
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{flex_url}"
          allow_private_base_url: true
          models: [{MODEL_FLEX}, {MODEL_STALL}]
          service_tier: flex
          fallback_credential_id: house-openai
        - name: openai-standard
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{standard_url}"
          allow_private_base_url: true
          models: [{MODEL_STANDARD}, {MODEL_STREAM}]
          service_tier: standard
          on_key_failure: fail_closed
        # Two providers exist only to give a failover somewhere to go.
        # They serve the pooled ids and nothing else, so the
        # single-candidate ids above stay deterministic for every test
        # that is not about failover.
        - name: openai-flex-backup
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{flex_backup_url}"
          allow_private_base_url: true
          models: [{MODEL_STALL}]
        - name: openai-standard-backup
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{standard_backup_url}"
          allow_private_base_url: true
          models: [{MODEL_STREAM}]
        - name: shadow-a
          provider_type: openai
          api_key: shadow-a-key
          base_url: "{shadow_a_url}"
          allow_private_base_url: true
          enabled: false
          models: [{MODEL_STANDARD}]
        - name: shadow-b
          provider_type: openai
          api_key: shadow-b-key
          base_url: "{shadow_b_url}"
          allow_private_base_url: true
          enabled: false
          models: [{MODEL_STANDARD}]
      model_groups:
        - name: {GROUP}
          routing: weighted
          members:
            - provider: bedrock-guarded
              model: {MODEL_SIGNED}
              weight: 1
            - provider: openai-flex
              model: {MODEL_FLEX}
              weight: 8
            - provider: openai-standard
              model: {MODEL_STANDARD}
              weight: 1
      shadow:
        targets:
          - provider: shadow-a
            sample_rate: 1.0
            timeout_ms: 5000
            task_timeout_ms: 5000
            model: {MODEL_STANDARD}
          - provider: shadow-b
            sample_rate: 1.0
            timeout_ms: 5000
            task_timeout_ms: 5000
            model: {MODEL_STANDARD}
  # The two streaming claims need a strategy that defines a *next*
  # candidate, and `fallback_chain`'s declared priority order is also
  # what makes "the first one" deterministic in a test. Measured against
  # this same binary: with `round_robin` a pre-header elapse refuses the
  # request with 502 naming the budget rather than handing it on, and
  # with `fallback_chain` it is handed to the declared successor. Same
  # `pre_header_timeout_ms`, same stubs, different strategy.
  "stream.local":
    tenant_id: acme
    action:
      type: ai_proxy
      # The price table is process-global and the last compiled origin
      # installs it, so both origins name the same card. Without that
      # the published limits would depend on origin compile order.
      rate_card: "{rate_card_path}"
      # WOR-2651: `fallback_chain` owns its candidate order, so on this
      # origin a lease must be neither read nor recorded. The block is
      # configured here precisely so the standing-aside is under test
      # rather than merely unreachable.
      cache_affinity:
        ttl_secs: 300
        max_keys_per_provider: 64
      routing:
        strategy: fallback_chain
      resilience:
        pre_header_timeout_ms: 400
      providers:
        - name: stall-primary
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{flex_url}"
          allow_private_base_url: true
          models: [{MODEL_STALL}]
        - name: stall-backup
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{flex_backup_url}"
          allow_private_base_url: true
          models: [{MODEL_STALL}]
        - name: stream-primary
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{standard_url}"
          allow_private_base_url: true
          models: [{MODEL_STREAM}]
        - name: stream-backup
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{standard_backup_url}"
          allow_private_base_url: true
          models: [{MODEL_STREAM}]
"#
    )
}

/// One composite gateway plus everything it points at, so a test can
/// hold the whole fixture alive with a single binding.
struct Gateway {
    proxy: ProxyHarness,
    admin_port: u16,
    signed: ScriptedUpstream,
    flex: ScriptedUpstream,
    standard: ScriptedUpstream,
    shadow_a: ScriptedUpstream,
    shadow_b: ScriptedUpstream,
    flex_backup: ScriptedUpstream,
    standard_backup: ScriptedUpstream,
    /// Arm to make the next request the `flex` stub receives fail at
    /// the transport layer. Cleared by the stub as it fires.
    flex_hangup: Arc<AtomicBool>,
    usage_path: std::path::PathBuf,
    events_path: std::path::PathBuf,
    _workdir: tempfile::TempDir,
}

/// What `GET /api/requests/{id}/content` had to say.
#[derive(Debug)]
enum RetainedPair {
    /// A sample exists, with whatever shadow answers were attached by
    /// the time the poll window closed.
    Sample(Value),
    /// The endpoint refused by status. `404` is the consent refusal:
    /// no sample was ever stored for that request.
    Refused(u16),
    /// No request row appeared under that key at all, which means the
    /// request never reached the admin ring rather than that its
    /// content was refused.
    NoRequestRow,
}

impl RetainedPair {
    fn sample(self) -> Value {
        match self {
            Self::Sample(body) => body,
            other => panic!("expected a retained sample, got {other:?}"),
        }
    }
}

/// Behaviors the individual tests vary. Everything else is the
/// composite config above, unchanged, so a test that only cares about
/// one sibling still boots all nine.
#[derive(Default, Clone, Copy)]
struct Behavior {
    /// The Bedrock stub answers `stopReason: guardrail_intervened`.
    guardrail_intervenes: bool,
    /// The flex stub refuses the first credential it sees with a 401.
    flex_refuses_first_key: bool,
    /// The standard stub refuses the first credential it sees with 401.
    standard_refuses_first_key: bool,
    /// The flex stub accepts the connection and never answers, so a
    /// streaming request on the pooled `MODEL_STALL` id has to be moved
    /// to `openai-flex-backup` on the pre-header budget.
    flex_stalls: bool,
    /// The first member of the `MODEL_STREAM` chain answers headers plus
    /// one frame and then dies. Only the first: the successor behind it
    /// stays healthy on purpose, so "nothing moved after the commit
    /// point" is a claim about a gateway that had a good option and did
    /// not take it.
    standard_dies_mid_stream: bool,
    /// Both shadow stubs hold their answer for [`SHADOW_STUB_DELAY`]
    /// before replying, so "neither delays the primary" is a measured
    /// claim rather than a claim about two stubs that answer instantly.
    shadows_are_slow: bool,
}

/// How long a slow shadow stub holds its answer.
///
/// Long enough that a primary waiting on either copy could not finish
/// inside [`PRIMARY_WITHOUT_SHADOWS`], and short enough that a test
/// which does wait for the copies still finishes.
const SHADOW_STUB_DELAY: Duration = Duration::from_millis(1500);

/// The ceiling a primary request has to come in under while both
/// shadow copies are still in flight.
const PRIMARY_WITHOUT_SHADOWS: Duration = Duration::from_millis(700);

/// One SSE frame, truncated: response headers and a partial body, then
/// the connection drops.
fn truncated_stream_frame() -> String {
    format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-sota",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": MODEL_STREAM,
            "choices": [{"index": 0, "delta": {"content": "partial"}}]
        })
    )
}

fn start_gateway(behavior: Behavior) -> Gateway {
    let workdir = tempfile::tempdir().expect("workdir");
    let key_store = workdir.path().join("keys.redb");
    let usage_path = workdir.path().join("usage.jsonl");
    let events_path = workdir.path().join("events.ndjson");
    let rate_card_path = workdir.path().join("rate-card.json");
    std::fs::write(&rate_card_path, rate_card()).expect("rate card");
    let admin_port = free_port();

    let signed = ScriptedUpstream::start(move |request, _index| {
        Reply::Body(
            200,
            "application/json",
            if behavior.guardrail_intervenes {
                // Real Bedrock returns the matched input inside
                // `trace.guardrail.inputAssessment`, so a stub that
                // returns a bare `stopReason` gives the proxy nothing
                // to leak and makes "the refusal quotes nothing"
                // vacuous. This one hands back the caller's own prompt
                // exactly where AWS does.
                intervened_converse_reply(&caller_prompt(request))
            } else {
                converse_reply("signed member answered", "end_turn")
            },
        )
    });
    let flex_hangup = Arc::new(AtomicBool::new(false));
    let flex_hangup_stub = Arc::clone(&flex_hangup);
    let flex = ScriptedUpstream::start(move |request, index| {
        // Armed by a test that needs this provider to fail exactly
        // once, so a failover can be provoked at a chosen turn rather
        // than at a request index the test has to guess.
        if flex_hangup_stub.swap(false, Ordering::SeqCst) {
            return Reply::Hangup;
        }
        if behavior.flex_stalls {
            return Reply::StallForever;
        }
        if behavior.flex_refuses_first_key && index == 0 {
            return Reply::Body(401, "application/json", refused_credential());
        }
        let model = request
            .json()
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(MODEL_FLEX)
            .to_string();
        Reply::Body(200, "application/json", openai_reply(&model, "flex"))
    });
    let flex_backup = ScriptedUpstream::start(|request, _index| {
        if wants_stream(request) {
            return Reply::Sse(sse_frames("flex backup"));
        }
        Reply::Body(
            200,
            "application/json",
            openai_reply(MODEL_STALL, "flex backup"),
        )
    });
    let standard_backup = ScriptedUpstream::start(|request, _index| {
        if wants_stream(request) {
            return Reply::Sse(sse_frames("standard backup"));
        }
        Reply::Body(
            200,
            "application/json",
            openai_reply(MODEL_STREAM, "standard backup"),
        )
    });
    let standard = ScriptedUpstream::start(move |request, index| {
        if behavior.standard_dies_mid_stream {
            return Reply::DieMidStream(truncated_stream_frame());
        }
        if behavior.standard_refuses_first_key && index == 0 {
            return Reply::Body(401, "application/json", refused_credential());
        }
        let model = request
            .json()
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(MODEL_STANDARD)
            .to_string();
        Reply::Body(200, "application/json", openai_reply(&model, "standard"))
    });
    let shadow_a = ScriptedUpstream::start(move |_, _| {
        if behavior.shadows_are_slow {
            std::thread::sleep(SHADOW_STUB_DELAY);
        }
        Reply::Body(
            200,
            "application/json",
            openai_reply(MODEL_STANDARD, "shadow a said something else"),
        )
    });
    let shadow_b = ScriptedUpstream::start(move |_, _| {
        if behavior.shadows_are_slow {
            std::thread::sleep(SHADOW_STUB_DELAY);
        }
        Reply::Body(
            200,
            "application/json",
            openai_reply(MODEL_STANDARD, "shadow b said something else"),
        )
    });

    let yaml = composite_config(&Wiring {
        admin_port,
        key_store: &key_store,
        usage_path: &usage_path,
        events_path: &events_path,
        signed_url: &signed.base_url(),
        flex_url: &flex.base_url(),
        standard_url: &standard.base_url(),
        shadow_a_url: &shadow_a.base_url(),
        shadow_b_url: &shadow_b.base_url(),
        flex_backup_url: &flex_backup.base_url(),
        standard_backup_url: &standard_backup.base_url(),
        rate_card_path: &rate_card_path,
    });
    let proxy = ProxyHarness::start_with_workspace(&yaml, &[]).expect("composite gateway boots");

    Gateway {
        proxy,
        admin_port,
        signed,
        flex,
        standard,
        shadow_a,
        shadow_b,
        flex_backup,
        standard_backup,
        flex_hangup,
        usage_path,
        events_path,
        _workdir: workdir,
    }
}

/// A LiteLLM-shaped rate card naming this fixture's models.
///
/// `max_output_tokens` has exactly one source in the product, the
/// operator's rate card, so a fixture that ships none can never publish
/// it. The windows differ per member on purpose: a group's published
/// window is the floor across its members, and identical numbers would
/// not tell a floor from a copy.
fn rate_card() -> String {
    serde_json::to_string_pretty(&json!({
        MODEL_SIGNED: {
            "max_input_tokens": 200_000,
            "max_output_tokens": 8_192,
            "input_cost_per_token": 0.000_003,
            "output_cost_per_token": 0.000_015,
        },
        MODEL_FLEX: {
            "max_input_tokens": 128_000,
            "max_output_tokens": 16_384,
            "input_cost_per_token": 0.000_000_15,
            "output_cost_per_token": 0.000_000_6,
        },
        MODEL_STANDARD: {
            "max_input_tokens": 400_000,
            "max_output_tokens": 32_768,
            "input_cost_per_token": 0.000_002_5,
            "output_cost_per_token": 0.000_01,
        },
    }))
    .expect("rate card json")
}

/// The caller's own prompt text, as the Bedrock stub received it.
fn caller_prompt(request: &SeenRequest) -> String {
    request.json()["messages"][0]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

impl Gateway {
    fn chat(&self, model: &str, prompt: &str, headers: &[(&str, &str)]) -> sbproxy_e2e::Response {
        self.proxy
            .post_json(
                "/v1/chat/completions",
                "sota.local",
                &json!({"model": model, "messages": [{"role": "user", "content": prompt}]}),
                headers,
            )
            .expect("chat request")
    }

    fn admin_json(&self, path: &str) -> Value {
        reqwest::blocking::Client::new()
            .get(format!("http://127.0.0.1:{}{path}", self.admin_port))
            .basic_auth("admin", Some("secret"))
            .send()
            .expect("admin request")
            .json()
            .expect("admin json")
    }

    /// Mint a governed key, optionally consenting to content recording.
    fn mint_key(&self, name: &str, allow_content_capture: bool) -> (String, String) {
        let response: Value = reqwest::blocking::Client::new()
            .post(format!("http://127.0.0.1:{}/admin/keys", self.admin_port))
            .basic_auth("admin", Some("secret"))
            .json(&json!({"name": name, "allow_content_capture": allow_content_capture}))
            .send()
            .expect("mint request")
            .json()
            .expect("mint json");
        (
            response["token"].as_str().expect("token").to_string(),
            response["key"]["key_id"]
                .as_str()
                .expect("key id")
                .to_string(),
        )
    }

    fn usage_rows(&self, want: usize) -> Vec<Value> {
        for _ in 0..80 {
            let rows: Vec<Value> = std::fs::read_to_string(&self.usage_path)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            if rows.len() >= want {
                return rows;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        std::fs::read_to_string(&self.usage_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn events(&self) -> String {
        std::fs::read_to_string(&self.events_path).unwrap_or_default()
    }

    fn logs(&self) -> String {
        format!(
            "{}\n{}",
            self.proxy.stdout_contents(),
            self.proxy.stderr_contents()
        )
    }

    /// What the content endpoint says about the most recent request
    /// made under `key_id`.
    ///
    /// Three outcomes rather than an `Option`, because "no pair" has
    /// two very different causes and a consent assertion that cannot
    /// tell them apart would pass on a slow write as readily as on a
    /// refusal.
    fn retained_pair(&self, key_id: &str) -> RetainedPair {
        let mut request_id = None;
        for _ in 0..60 {
            let rows: Vec<Value> = self
                .admin_json(&format!("/api/requests?api_key_id={key_id}"))
                .as_array()
                .cloned()
                .unwrap_or_default();
            if let Some(id) = rows.first().and_then(|row| row["request_id"].as_str()) {
                request_id = Some(id.to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let Some(request_id) = request_id else {
            return RetainedPair::NoRequestRow;
        };
        // The shadow halves land from their own tasks, so poll until
        // both are attached or the window closes.
        let mut last = None;
        for _ in 0..60 {
            let response = reqwest::blocking::Client::new()
                .get(format!(
                    "http://127.0.0.1:{}/api/requests/{request_id}/content",
                    self.admin_port
                ))
                .basic_auth("admin", Some("secret"))
                .send()
                .expect("content fetch");
            let status = response.status().as_u16();
            if status != 200 {
                return RetainedPair::Refused(status);
            }
            let body: Value = response.json().unwrap_or(Value::Null);
            let shadows = body["shadow_responses"].as_array().map_or(0, Vec::len);
            last = Some(body);
            if shadows >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        match last {
            Some(body) => RetainedPair::Sample(body),
            None => RetainedPair::NoRequestRow,
        }
    }

    /// A GET served by the proxy itself rather than the admin server,
    /// for the LiteLLM-parity read-only endpoints.
    fn admin_json_via_proxy(&self, path: &str) -> Value {
        self.proxy
            .get(path, "sota.local")
            .expect("proxy-served management endpoint")
            .json()
            .expect("management json")
    }
}

// ---------------------------------------------------------------------
// Wire-level emulation helpers
// ---------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Rebuild the SigV4 signature for `request` from the static
/// credentials the config names, and return it beside the one the proxy
/// sent.
///
/// This is the wire-level stand-in for a real Bedrock endpoint. The
/// payload hash is part of the canonical request, so a match proves the
/// bytes that arrived are the bytes that were signed: if the guardrail
/// rewrite (or anything else) had touched the body after signing, the
/// two signatures would differ.
fn recompute_sigv4_signature(request: &SeenRequest) -> (String, String) {
    let authorization = request
        .header("authorization")
        .expect("a signed provider sends an Authorization header");
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 "),
        "the signed member must use SigV4, got {authorization}"
    );
    let mut credential = String::new();
    let mut signed_headers = String::new();
    let mut sent_signature = String::new();
    for part in authorization
        .trim_start_matches("AWS4-HMAC-SHA256 ")
        .split(',')
    {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("Credential=") {
            credential = value.to_string();
        } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
            signed_headers = value.to_string();
        } else if let Some(value) = part.strip_prefix("Signature=") {
            sent_signature = value.to_string();
        }
    }
    // Credential=<access key>/<date>/<region>/<service>/aws4_request
    let scope_parts: Vec<&str> = credential.splitn(2, '/').collect();
    assert_eq!(
        scope_parts.first().copied(),
        Some(AWS_ACCESS_KEY_ID),
        "the signature is scoped to the configured access key, not another one"
    );
    let scope = scope_parts.get(1).copied().unwrap_or_default().to_string();
    let scope_fields: Vec<&str> = scope.split('/').collect();
    let date = scope_fields.first().copied().unwrap_or_default();
    let region = scope_fields.get(1).copied().unwrap_or_default();
    let service = scope_fields.get(2).copied().unwrap_or_default();
    assert_eq!(
        region, AWS_REGION,
        "credential scope names the config region"
    );
    assert_eq!(
        service, "bedrock",
        "a bedrock provider signs for the bedrock service by default"
    );

    let canonical_headers: String = signed_headers
        .split(';')
        .map(|name| {
            let value = request
                .header(name)
                .unwrap_or_else(|| panic!("SignedHeaders names {name}, which never arrived"));
            format!("{name}:{}\n", value.trim())
        })
        .collect();
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        request.path.split('?').next().unwrap_or(&request.path),
        "",
        canonical_headers,
        signed_headers,
        sha256_hex(&request.body),
    );
    let amz_date = request
        .header("x-amz-date")
        .expect("a signed request carries x-amz-date");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac(format!("AWS4{AWS_SECRET_ACCESS_KEY}").as_bytes(), date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    let k_signing = hmac(&k_service, "aws4_request");
    (
        hex::encode(hmac(&k_signing, &string_to_sign)),
        sent_signature,
    )
}

/// Every field the OpenAI `Model` object declares required, and the
/// JSON type an SDK-shaped deserializer demands for each.
///
/// A field the SDK ignores may be present; a required field that is
/// missing or wrongly typed is what makes an SDK refuse the whole
/// listing, which is the failure WOR-2647 was about.
fn assert_openai_sdk_model_shape(entry: &Value) {
    assert!(
        entry["id"].is_string() && !entry["id"].as_str().unwrap_or_default().is_empty(),
        "`id` must be a non-empty string: {entry}"
    );
    assert_eq!(
        entry["object"].as_str(),
        Some("model"),
        "`object` must be the literal \"model\": {entry}"
    );
    assert!(
        entry["created"].is_i64() || entry["created"].is_u64(),
        "`created` must be an integer; the SDK's Model refuses a listing without it: {entry}"
    );
    assert!(
        entry["owned_by"].is_string(),
        "`owned_by` must be a string: {entry}"
    );
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// The integration claim itself, before any individual sibling's: nine
/// features that were each reviewed alone compile together into one
/// action, boot, and serve a request. A key refused at config load or a
/// pipeline that fails to construct fails here first, and every other
/// test in this file inherits that.
#[test]
fn the_whole_epic_composes_into_one_action_that_boots_and_serves() {
    let gateway = start_gateway(Behavior::default());
    let response = gateway.chat(MODEL_STANDARD, "hello", &[]);
    assert_eq!(
        response.status,
        200,
        "composite gateway refused a plain request: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = response.json().expect("chat response json");
    assert_eq!(
        body["choices"][0]["message"]["content"], "standard",
        "the standard member answered: {body}"
    );
}

/// WOR-2657 plus WOR-2647: the group is discoverable under its one
/// public name, its members are enumerable with their own upstream
/// model ids and weights, and the listing still deserializes into an
/// OpenAI SDK's `Model` list.
#[test]
fn the_model_group_and_its_members_are_listed_and_parse_as_an_openai_model_list() {
    let gateway = start_gateway(Behavior::default());

    let listing = gateway
        .proxy
        .get("/v1/models", "sota.local")
        .expect("models listing")
        .json()
        .expect("models json");
    assert_eq!(listing["object"], "list", "{listing}");
    let data = listing["data"].as_array().expect("data array");
    for entry in data {
        assert_openai_sdk_model_shape(entry);
    }
    let ids: Vec<&str> = data
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert!(
        ids.contains(&GROUP),
        "the one public name an operator published has to be listed: {ids:?}"
    );
    for member in [MODEL_SIGNED, MODEL_FLEX, MODEL_STANDARD] {
        assert!(
            ids.contains(&member),
            "member {member} missing from the listing: {ids:?}"
        );
    }

    // WOR-2647's third verify line: the limits, not only the names. A
    // client sizing a prompt reads these, and a listing that omits them
    // sends it to the vendor to find out.
    let entry_for = |wanted: &str| {
        data.iter()
            .find(|entry| entry["id"] == wanted)
            .unwrap_or_else(|| panic!("{wanted} missing from the listing: {data:?}"))
            .clone()
    };
    for (member, window, max_output) in [
        (MODEL_SIGNED, 200_000_u64, 8_192_u64),
        (MODEL_FLEX, 128_000, 16_384),
        (MODEL_STANDARD, 400_000, 32_768),
    ] {
        let entry = entry_for(member);
        assert_eq!(
            entry["context_window"].as_u64(),
            Some(window),
            "{member} published no context window: {entry}"
        );
        assert_eq!(
            entry["max_output_tokens"].as_u64(),
            Some(max_output),
            "{member} published no output limit: {entry}"
        );
    }

    let group_entry = entry_for(GROUP);
    assert!(
        group_entry["capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|c| c == "chat_completions")),
        "a group's capabilities are the union across its members: {group_entry}"
    );
    // A group is several models behind one id, so the only limit it can
    // honestly publish is the one every member can honor: the floor.
    assert_eq!(
        group_entry["context_window"].as_u64(),
        Some(128_000),
        "a group's window is the floor across its members, not any one member's: \
         {group_entry}"
    );
    assert_eq!(
        group_entry["max_output_tokens"].as_u64(),
        Some(8_192),
        "and so is its output limit: {group_entry}"
    );

    // The LiteLLM-parity surface, which is the only one that can carry
    // per-member facts: a derived group is several providers behind one
    // model id and has nothing per-deployment to say.
    let info = gateway.admin_json_via_proxy("/model_group/info");
    let group = info["data"]
        .as_array()
        .expect("model_group/info data")
        .iter()
        .find(|entry| entry["model_group"] == GROUP)
        .unwrap_or_else(|| panic!("named group missing from /model_group/info: {info}"));
    let members = group["members"].as_array().expect("members array");
    assert_eq!(members.len(), 3, "three members: {group}");
    let weights: Vec<(&str, &str, u64)> = members
        .iter()
        .map(|member| {
            (
                member["provider"].as_str().unwrap_or_default(),
                member["model"].as_str().unwrap_or_default(),
                member["weight"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    assert!(
        weights.contains(&("bedrock-guarded", MODEL_SIGNED, 1)),
        "the signed member and its own upstream model id: {weights:?}"
    );
    assert!(
        weights.contains(&("openai-flex", MODEL_FLEX, 8)),
        "the cheap-tier member and its weight: {weights:?}"
    );
    assert!(
        weights.contains(&("openai-standard", MODEL_STANDARD, 1)),
        "the standard member: {weights:?}"
    );
}

/// WOR-2648 with WOR-2649 on top, which is the pairing the epic called
/// out: the guardrail attaches `guardrailConfig` to the Converse body,
/// and the signature has to cover the body that rewriting produced.
///
/// Wire-level emulation: the signature is recomputed here from the
/// arrived bytes. See this file's header for what that does and does
/// not prove.
#[test]
fn the_signed_member_signs_the_body_the_guardrail_rewrite_produced() {
    let gateway = start_gateway(Behavior::default());
    let response = gateway.chat(MODEL_SIGNED, "sign this", &[]);
    assert_eq!(
        response.status,
        200,
        "signed member refused: {}",
        String::from_utf8_lossy(&response.body)
    );

    let seen = gateway.signed.seen();
    let request = seen.first().expect("the signed member was dialed");
    assert!(
        request.path.contains("/converse"),
        "a bedrock provider translates to the Converse path: {}",
        request.path
    );
    let authorization = request
        .header("authorization")
        .expect("a signed request carries an Authorization header");
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256"),
        "a signed provider presents a SigV4 credential and never an api_key bearer \
         token: {authorization}"
    );
    let body = request.json();
    assert_eq!(
        body["guardrailConfig"]["guardrailIdentifier"], "e2e-guardrail",
        "the inline guardrail rode on the Converse call: {body}"
    );
    assert_eq!(
        body["guardrailConfig"]["guardrailVersion"], "DRAFT",
        "{body}"
    );

    let (recomputed, sent) = recompute_sigv4_signature(request);
    assert_eq!(
        recomputed, sent,
        "the signature does not cover the body that arrived, which means something \
         rewrote the request after signing"
    );
}

/// WOR-2649's headline, and the one behavior change on upgrade: an
/// intervention is a 200 with `stopReason: guardrail_intervened` on the
/// wire, and it must not reach the caller as a successful empty
/// completion. The refusal names the guardrail and not the caller's own
/// text, because a Bedrock assessment quotes the prompt back.
#[test]
fn a_guardrail_intervention_becomes_a_403_that_quotes_nothing() {
    let gateway = start_gateway(Behavior {
        guardrail_intervenes: true,
        ..Behavior::default()
    });
    let secret_prompt = "my social security number is 000-00-0000";
    let response = gateway.chat(MODEL_SIGNED, secret_prompt, &[]);
    assert_eq!(
        response.status,
        403,
        "an intervention relayed as a 200 is the bug: {}",
        String::from_utf8_lossy(&response.body)
    );
    let text = response.text().unwrap_or_default();
    assert!(
        text.contains("guardrail"),
        "the refusal has to say what refused: {text}"
    );
    // The premise, asserted rather than assumed: the upstream payload
    // this refusal was derived from *did* carry the caller's own text,
    // the way a real Bedrock assessment does. Without this the next
    // assertion is a claim about a stub that had nothing to leak.
    let upstream = gateway
        .signed
        .seen()
        .first()
        .map(SeenRequest::json)
        .expect("the signed member was dialed");
    assert_eq!(
        upstream["messages"][0]["content"][0]["text"], secret_prompt,
        "the stub was sent the secret, so its assessment echoes one: {upstream}"
    );
    assert!(
        !text.contains("000-00-0000"),
        "the block reason must never quote the caller's own text back: {text}"
    );
    assert!(
        !text.contains("piiEntities") && !text.contains("inputAssessment"),
        "the vendor's assessment payload must not be relayed either: {text}"
    );
}

/// WOR-2652: the tier is the operator's, and a caller asking for a
/// dearer one loses the argument. Both halves in one request, because
/// on its own "the operator's tier arrives" is green even if the
/// caller's was never stripped.
#[test]
fn the_operator_tier_reaches_the_provider_and_the_callers_is_stripped() {
    let gateway = start_gateway(Behavior::default());
    let response = gateway
        .proxy
        .post_json(
            "/v1/chat/completions",
            "sota.local",
            &json!({
                "model": MODEL_FLEX,
                "messages": [{"role": "user", "content": "hi"}],
                "service_tier": "priority"
            }),
            &[],
        )
        .expect("chat request");
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    let seen = gateway.flex.seen();
    let body = seen.first().expect("the flex member was dialed").json();
    assert_eq!(
        body["service_tier"], "flex",
        "the destination's own tier is what reaches the vendor: {body}"
    );
    assert_ne!(
        body["service_tier"], "priority",
        "raising the tier raises the bill and the operator pays it: {body}"
    );

    // The half `flex` cannot show, because `flex` spells the same in
    // the config and on the wire. `openai-standard` declares
    // `service_tier: standard` and OpenAI's catalog vocabulary spells
    // that tier `default`, so a gateway that passed the configured
    // string through unchanged would send `standard` and the vendor
    // would reject or ignore it.
    assert_eq!(
        gateway.chat(MODEL_STANDARD, "hi", &[]).status,
        200,
        "the standard member refused"
    );
    let standard = gateway.standard.seen();
    let standard_body = standard
        .first()
        .expect("the standard member was dialed")
        .json();
    assert_eq!(
        standard_body["service_tier"], "default",
        "the vendor's own spelling of `standard` is what goes on the wire, not the \
         gateway's canonical name for the tier: {standard_body}"
    );
}

/// WOR-2655: a credential refusal is a statement about the key, so the
/// operator's credential answers where the tenant's was refused, and
/// the loud record of the swap names no secret material anywhere.
#[test]
fn a_refused_tenant_key_is_served_on_the_operator_credential_and_names_no_secret() {
    let gateway = start_gateway(Behavior {
        flex_refuses_first_key: true,
        ..Behavior::default()
    });
    let response = gateway.chat(MODEL_FLEX, "hi", &[]);
    assert_eq!(
        response.status,
        200,
        "the operator's credential should have answered: {}",
        String::from_utf8_lossy(&response.body)
    );

    let presented: Vec<String> = gateway
        .flex
        .seen()
        .iter()
        .map(|request| {
            request
                .header("authorization")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        presented,
        vec![
            format!("Bearer {TENANT_KEY}"),
            format!("Bearer {HOUSE_KEY}")
        ],
        "the entry's own key first, then the operator's, both under the vendor's header"
    );

    // Loud: the typed feed carries the swap.
    let mut events = String::new();
    for _ in 0..60 {
        events = gateway.events();
        if events.contains("credential_fallback") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let line = events
        .lines()
        .find(|line| line.contains("credential_fallback"))
        .unwrap_or_else(|| panic!("no credential_fallback event: {events}"));
    let event: Value = serde_json::from_str(line).expect("event json");
    assert_eq!(event["data"]["id"], "house-openai", "{event}");
    assert_eq!(event["data"]["outcome"], "engaged", "{event}");

    // And silent about the material, on every surface that leaves the
    // process.
    let logs = gateway.logs();
    for secret in [TENANT_KEY, HOUSE_KEY, AWS_SECRET_ACCESS_KEY] {
        assert!(
            !events.contains(secret),
            "credential material reached the event feed"
        );
        assert!(
            !logs.contains(secret),
            "credential material reached the log"
        );
    }
}

/// The opt-out, written as a differential against the test above:
/// `fail_closed` is *defined* as the behavior the fallback changed away
/// from, so on its own it passes with or without the feature.
#[test]
fn the_second_credential_opts_out_and_gets_the_providers_own_refusal() {
    let gateway = start_gateway(Behavior {
        flex_refuses_first_key: true,
        standard_refuses_first_key: true,
        ..Behavior::default()
    });
    assert_eq!(
        gateway.chat(MODEL_FLEX, "hi", &[]).status,
        200,
        "the fallback entry is served on the house credential"
    );
    assert_eq!(
        gateway.chat(MODEL_STANDARD, "hi", &[]).status,
        401,
        "the fail_closed entry returns the provider's rejection: a revoked tenant \
         must not keep working on the house account"
    );
    let presented: Vec<String> = gateway
        .standard
        .seen()
        .iter()
        .map(|request| {
            request
                .header("authorization")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        presented,
        vec![format!("Bearer {TENANT_KEY}")],
        "the house credential is never presented to the opted-out entry"
    );
}

/// WOR-2651, running under everything else the epic added: affinity
/// layers over the strategy that is already configured rather than
/// replacing it, so a caller who sent a `prompt_cache_key` goes back to
/// the provider that already holds their warm prefix on every later
/// turn.
///
/// `MODEL_STALL` is a two-member pool under `round_robin`, which alone
/// alternates every turn. Twelve turns all landing on one member is the
/// signal, and it is deterministic in both directions: without the
/// lease this test reads six of each. Both members serve the same model
/// id on purpose, because a lease recorded against a different resolved
/// model is dropped by design and a pool is where the feature is meant
/// to bite.
#[test]
fn cache_affinity_returns_a_caller_to_the_provider_that_holds_its_warm_prefix() {
    let gateway = start_gateway(Behavior::default());
    let cache_key = "sota-e2e-conversation-1";

    let mut served = Vec::new();
    for turn in 0..12 {
        let response = gateway
            .proxy
            .post_json(
                "/v1/chat/completions",
                "sota.local",
                &json!({
                    "model": MODEL_STALL,
                    "prompt_cache_key": cache_key,
                    "messages": [{"role": "user", "content": format!("turn {turn}")}]
                }),
                &[],
            )
            .expect("chat request");
        assert_eq!(
            response.status,
            200,
            "turn {turn} failed: {}",
            String::from_utf8_lossy(&response.body)
        );
        served.push(
            response.json().expect("json")["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
    }

    let first = served.first().cloned().unwrap_or_default();
    assert!(
        served.iter().all(|answer| *answer == first),
        "a warm-cache caller was scattered across the pool, which is what round robin \
         alone does: {served:?}"
    );
    assert_eq!(
        first, "flex",
        "the premise of the failover below: round robin's first pick on a fresh \
         process is the first declared member, so the lease is held by `openai-flex`"
    );

    // WOR-2658 scope item 3: the conversation has to cross a *failover*,
    // not merely sit still on a healthy pool. The lease holder fails at
    // the transport layer for exactly one turn.
    gateway.flex_hangup.store(true, Ordering::SeqCst);
    let dialed_before = gateway.flex.seen().len();
    let response = gateway
        .proxy
        .post_json(
            "/v1/chat/completions",
            "sota.local",
            &json!({
                "model": MODEL_STALL,
                "prompt_cache_key": cache_key,
                "messages": [{"role": "user", "content": "the leased provider just died"}]
            }),
            &[],
        )
        .expect("chat request");
    assert_eq!(
        response.status,
        200,
        "a keyed conversation whose leased provider died must still be served: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        gateway.flex.seen().len() > dialed_before,
        "the leased provider was never dialed, so nothing here was a failover"
    );
    let after_failover = response.json().expect("json")["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        after_failover, "flex backup",
        "the sibling had to answer the turn the lease holder could not: {after_failover}"
    );

    // And the conversation continues to be pinned afterward, now to
    // whichever member holds the warm prefix. Either destination is
    // correct; being scattered again is not.
    let mut resumed = Vec::new();
    for turn in 0..8 {
        let response = gateway
            .proxy
            .post_json(
                "/v1/chat/completions",
                "sota.local",
                &json!({
                    "model": MODEL_STALL,
                    "prompt_cache_key": cache_key,
                    "messages": [{"role": "user", "content": format!("resumed {turn}")}]
                }),
                &[],
            )
            .expect("chat request");
        assert_eq!(response.status, 200, "resumed turn {turn} failed");
        resumed.push(
            response.json().expect("json")["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
    }
    let resumed_first = resumed.first().cloned().unwrap_or_default();
    assert!(
        resumed.iter().all(|answer| *answer == resumed_first),
        "the conversation was scattered across the pool after the failover: {resumed:?}"
    );

    // The control, so the assertion above is a claim about this feature
    // rather than about a rotation that happened to sit still. Twelve
    // more turns on the same route with no cache key: a caller who
    // sends nothing to lease on is routed by the strategy alone, and
    // round robin over two members splits them.
    let mut unkeyed = Vec::new();
    for turn in 0..12 {
        let response = gateway.chat(MODEL_STALL, &format!("no key {turn}"), &[]);
        assert_eq!(response.status, 200, "unkeyed turn {turn} failed");
        unkeyed.push(
            response.json().expect("json")["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
    }
    assert!(
        unkeyed.iter().any(|answer| *answer != first),
        "without a cache key these should have been split across the pool; if they all \
         landed on one member the keyed run above proves nothing: {unkeyed:?}"
    );
}

/// WOR-2651, the other half of the same feature and the one this branch
/// fixed: four routing strategies own their candidate order outright,
/// and on those origins a prompt-cache lease is neither read nor
/// recorded.
///
/// `stream.local` is `fallback_chain` **with** a `cache_affinity:`
/// block, which is the only shape where the standing-aside can be
/// observed. The first turn fails the declared first candidate at the
/// transport layer, so the successor serves it; if a lease were
/// recorded on that success and read on the next turn, the successor
/// would keep the conversation and the operator's declared priority
/// order would drift further from itself the longer the route ran.
#[test]
fn cache_affinity_stands_aside_for_the_chains_declared_order() {
    let gateway = start_gateway(Behavior::default());
    let cache_key = "sota-e2e-chain-conversation";

    let turn = |content: &str| {
        gateway
            .proxy
            .post_json(
                "/v1/chat/completions",
                "stream.local",
                &json!({
                    "model": MODEL_STALL,
                    "prompt_cache_key": cache_key,
                    "messages": [{"role": "user", "content": content}]
                }),
                &[],
            )
            .expect("chat request")
    };

    // Turn one: the declared first candidate dies, the successor
    // answers, and a lease-recording origin would now hold a lease on
    // the successor.
    gateway.flex_hangup.store(true, Ordering::SeqCst);
    let first = turn("the chain's first candidate just died");
    assert_eq!(
        first.status,
        200,
        "the chain's successor should have answered: {}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(
        first.json().expect("json")["choices"][0]["message"]["content"],
        "flex backup",
        "the premise: the successor served this turn, so any lease is on the successor"
    );

    // Every turn after it goes back to the declared first candidate.
    for index in 0..6 {
        let response = turn(&format!("chain turn {index}"));
        assert_eq!(response.status, 200, "chain turn {index} failed");
        assert_eq!(
            response.json().expect("json")["choices"][0]["message"]["content"],
            "flex",
            "a cache lease re-fronted a fallback_chain origin's declared order on turn \
             {index}; the operator's priority order is not the router's to reorder"
        );
    }
}

/// WOR-2650, the half that has to move: a provider that accepts the
/// connection and then goes quiet is bounded by the pre-header budget
/// and the request is handed to the next candidate. Before that budget
/// existed the only bound was the attempt's own `timeout_ms`, which has
/// to be long enough for a real completion, so nothing moved for as
/// long as it ran.
///
/// Runs against the `stream.local` origin, whose `fallback_chain` order
/// makes "the next candidate" both defined and deterministic: the first
/// declared provider stalls, the second answers, on every request.
#[test]
fn a_stream_that_never_produces_a_first_byte_fails_over_before_the_commit_point() {
    let gateway = start_gateway(Behavior {
        flex_stalls: true,
        ..Behavior::default()
    });

    let started = std::time::Instant::now();
    let response = gateway
        .proxy
        .post_json(
            "/v1/chat/completions",
            "stream.local",
            &json!({
                "model": MODEL_STALL,
                "stream": true,
                "messages": [{"role": "user", "content": "stream please"}]
            }),
            &[],
        )
        .expect("streaming request");
    let elapsed = started.elapsed();

    assert_eq!(
        response.status,
        200,
        "a stalled candidate should have been replaced, not relayed: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        response.text().unwrap_or_default().contains("flex backup"),
        "the successor's answer is the one the caller reads"
    );
    // Two seconds, not twenty. The harness client's own timeout is ten
    // seconds and `.expect("streaming request")` above panics first, so
    // any bound at or above it can never fire: raising
    // `pre_header_timeout_ms` from 400 to 9000 would have left the old
    // assertion green, which made WOR-2650's central number untested.
    assert!(
        elapsed < Duration::from_secs(2),
        "the pre-header budget is 400ms and the handoff has to happen on it, not on \
         the attempt's own timeout; took {elapsed:?}"
    );
    assert!(
        !gateway.flex.seen().is_empty(),
        "the stalled member was never dialed, so nothing here was a failover"
    );
    assert!(
        !gateway.flex_backup.seen().is_empty(),
        "the successor never answered, so the request was not handed on"
    );
}

/// The other half of the same budget, and the one that is a safety
/// property rather than an availability one: past the response headers
/// the caller is already reading this provider's output, so a later
/// candidate cannot replace it. A stream that dies mid-body ends,
/// truncated, rather than being silently restarted somewhere else with
/// a second copy of the answer.
///
/// The chain has a healthy successor sitting right behind the one that
/// dies, and it is the successor's dial count that carries the claim: a
/// post-commit failover, or a retry of the same provider, would make it
/// non-zero.
#[test]
fn a_stream_that_dies_after_the_first_byte_is_not_failed_over() {
    let gateway = start_gateway(Behavior {
        standard_dies_mid_stream: true,
        ..Behavior::default()
    });
    // Either a truncated body or a transport error is a correct outcome
    // for a stream that died after commit. What is not correct is a
    // second attempt.
    let _ = gateway.proxy.post_json(
        "/v1/chat/completions",
        "stream.local",
        &json!({
            "model": MODEL_STREAM,
            "stream": true,
            "messages": [{"role": "user", "content": "stream please"}]
        }),
        &[],
    );

    // A negative with no settle window passes on a race: the request
    // returns as soon as the stream dies, and a retry the proxy was
    // about to make would land after the assertions. Hold the window
    // open and re-check throughout, so a late dial fails the test at
    // the moment it happens rather than after it.
    let settle = std::time::Instant::now();
    while settle.elapsed() < Duration::from_secs(2) {
        assert!(
            gateway.standard_backup.seen().is_empty(),
            "a committed stream was moved to the chain's next candidate, which would \
             hand the caller a second copy of an answer it is already reading"
        );
        assert_eq!(
            gateway.standard.seen().len(),
            1,
            "the committed provider was retried"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// WOR-2654's dispatch half, running under everything else: two targets
/// answer, and neither one is on the caller's latency path.
#[test]
fn both_shadow_targets_run_beside_the_primary_and_neither_delays_it() {
    // Both copies hold their answers for well over a second, so "the
    // caller does not wait for them" is a measurement. With instant
    // stubs the claim is unfalsifiable: a gateway that awaited both
    // copies inline would still answer immediately.
    let gateway = start_gateway(Behavior {
        shadows_are_slow: true,
        ..Behavior::default()
    });
    let started = std::time::Instant::now();
    assert_eq!(gateway.chat(MODEL_STANDARD, "shadow me", &[]).status, 200);
    let elapsed = started.elapsed();
    assert!(
        elapsed < PRIMARY_WITHOUT_SHADOWS,
        "the primary waited on a shadow copy: each one holds its answer for \
         {SHADOW_STUB_DELAY:?} and the caller was served in {elapsed:?}"
    );

    for (name, stub) in [
        ("shadow-a", &gateway.shadow_a),
        ("shadow-b", &gateway.shadow_b),
    ] {
        let mut seen = 0;
        for _ in 0..60 {
            seen = stub.seen().len();
            if seen > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(seen > 0, "{name} never ran");
    }
    // The primary's answer is the primary's. A shadow reply reaching
    // the client would be the failure this whole design exists to
    // prevent.
    let body = gateway
        .chat(MODEL_STANDARD, "shadow me again", &[])
        .json()
        .expect("json");
    assert_eq!(
        body["choices"][0]["message"]["content"], "standard",
        "a shadow answer reached the caller: {body}"
    );
}

/// WOR-2654's retention half, and the gate that decides it: two
/// credentials on one route, one consenting to content recording and
/// one not. The consenting one's request retains the primary answer and
/// both candidates' answers as one pair; the other retains nothing at
/// all, not even a partial sample.
#[test]
fn content_recording_consent_decides_whether_the_shadow_pair_is_retained() {
    let gateway = start_gateway(Behavior::default());
    let (consenting, consenting_id) = gateway.mint_key("consents", true);
    let (refusing, refusing_id) = gateway.mint_key("does-not-consent", false);

    for (token, prompt) in [(&consenting, "keep this pair"), (&refusing, "keep nothing")] {
        let status = gateway
            .chat(MODEL_STANDARD, prompt, &[("x-sb-api", token.as_str())])
            .status;
        assert_eq!(status, 200, "chat under a governed key failed");
    }

    let consented = gateway.retained_pair(&consenting_id).sample();
    assert!(
        consented["output_text"]
            .as_str()
            .is_some_and(|text| !text.is_empty()),
        "the primary's own answer is half the pair: {consented}"
    );
    let shadows = consented["shadow_responses"]
        .as_array()
        .unwrap_or_else(|| panic!("no shadow_responses on a consenting sample: {consented}"));
    let targets: Vec<&str> = shadows
        .iter()
        .filter_map(|entry| entry["target"].as_str())
        .collect();
    assert!(
        targets.contains(&"shadow-a") && targets.contains(&"shadow-b"),
        "both candidates' answers belong in the pair: {targets:?}"
    );

    // A refusal, named by status, not merely an absence. `404` is the
    // content endpoint saying no sample was ever stored; a request row
    // that never appeared, or a sample that arrived slowly, would read
    // as a different variant and fail here rather than passing as
    // "nothing was retained".
    match gateway.retained_pair(&refusing_id) {
        RetainedPair::Refused(404) => {}
        other => panic!(
            "a key that did not consent to content recording must retain nothing, and \
             that includes the shadow half on its own: {other:?}"
        ),
    }
}

/// WOR-2654's aggregate view. Provenance leads, because a delta over
/// two pairs and a delta over two thousand read identically once each
/// is a single number.
#[test]
fn the_shadow_report_leads_with_provenance_and_names_every_target() {
    let gateway = start_gateway(Behavior::default());
    for turn in 0..3 {
        assert_eq!(
            gateway
                .chat(MODEL_STANDARD, &format!("report {turn}"), &[])
                .status,
            200
        );
    }
    // The shadow legs and the primary leg land from different tasks.
    let mut report = Value::Null;
    for _ in 0..80 {
        report = gateway.admin_json("/api/ai/shadow/report?window=1h");
        let paired = report["targets"]
            .as_array()
            .map(|targets| {
                targets
                    .iter()
                    .filter(|row| row["provenance"]["pairs_retained"].as_u64().unwrap_or(0) > 0)
                    .count()
            })
            .unwrap_or(0);
        if paired == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    assert_eq!(report["window_secs"], 3600, "{report}");
    let targets = report["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2, "one row per configured target: {report}");
    for row in targets {
        let name = row["target"].as_str().unwrap_or_default();
        let provenance = &row["provenance"];
        assert!(
            provenance["requests_seen"].as_u64().unwrap_or(0) >= 3,
            "{name} saw fewer requests than were sent: {provenance}"
        );
        assert!(
            provenance["pairs_retained"].as_u64().unwrap_or(0) > 0,
            "{name} retained no pair: {provenance}"
        );
        let dropped: u64 = provenance["pairs_dropped"]
            .as_object()
            .map(|map| map.values().filter_map(Value::as_u64).sum())
            .unwrap_or(0);
        assert_eq!(
            dropped + provenance["pairs_retained"].as_u64().unwrap_or(0),
            provenance["requests_seen"].as_u64().unwrap_or(0),
            "the provenance block has to sum: {provenance}"
        );
        assert!(
            row["latency"]["shadow_p95_ms"].is_number()
                && row["latency"]["delta_p50_ms"].is_number(),
            "latency is reported at p50 and p95, not as a mean: {row}"
        );
        assert!(
            row["finish_reasons"]
                .as_object()
                .is_some_and(|map| map.contains_key("stop")),
            "the finish-reason distribution is the cheapest disagreement signal: {row}"
        );
        assert_eq!(
            row["agreement"]["status"], "not_configured",
            "no judge is configured here, and a zero score would read as a tie: {row}"
        );
    }
}

/// The usage and request records, read as one operator would.
///
/// All five of WOR-2658's named facts are here: the model, the
/// provider, the serving credential, the prompt-cache read and write
/// counts, and the service tier that priced them.
#[test]
fn the_request_row_names_the_serving_credential_the_cache_tokens_and_the_tier() {
    let gateway = start_gateway(Behavior {
        flex_refuses_first_key: true,
        ..Behavior::default()
    });
    assert_eq!(
        gateway.chat(MODEL_FLEX, "account for this", &[]).status,
        200
    );

    let mut row = Value::Null;
    for _ in 0..80 {
        let rows: Vec<Value> = gateway
            .admin_json("/api/requests?limit=5")
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(first) = rows.into_iter().next() {
            row = first;
            if row["credential_source"].is_string() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(row["provider"], "openai-flex", "{row}");
    assert_eq!(row["model"], MODEL_FLEX, "{row}");
    assert_eq!(
        row["credential_source"], "fallback",
        "the row has to say which credential paid: {row}"
    );
    assert_eq!(
        row["tokens_cached"], 7,
        "the provider's prompt-cache read count reaches the record: {row}"
    );
    assert_eq!(
        row["tokens_cache_write"], 3,
        "and the cache-write count, which is the other column this branch adds: {row}"
    );
    assert_eq!(
        row["service_tier"], "flex",
        "the row has to name the tier that priced the tokens beside it: {row}"
    );

    // The ledger rows for the same request, which is where cost lives:
    // one primary and one per shadow target. Waiting for all three
    // rather than for the first, because the three are written by three
    // different tasks and "the first line that lands" is as likely to
    // be a shadow row as the primary.
    let usage = gateway.usage_rows(3);
    let primary = usage
        .iter()
        .find(|entry| entry["tag"] != json!("shadow"))
        .unwrap_or_else(|| panic!("no primary usage row: {usage:?}"));
    assert_eq!(primary["provider"], "openai-flex", "{primary}");
    assert_eq!(primary["model"], MODEL_FLEX, "{primary}");
    assert_eq!(
        primary["credential_source"], "fallback",
        "the ledger names the serving credential too: {primary}"
    );

    // And the shadow rows join back to it rather than floating free.
    let shadow_rows: Vec<&Value> = usage
        .iter()
        .filter(|entry| entry["tag"] == json!("shadow"))
        .collect();
    assert!(
        !shadow_rows.is_empty(),
        "shadow rows are missing from the ledger: {usage:?}"
    );
    for shadow in shadow_rows {
        assert!(
            shadow["shadow_of"].is_string(),
            "a shadow row with no join key cannot be compared to anything: {shadow}"
        );
    }
}

/// WOR-2653: the verb an operator runs once, against this very gateway,
/// and the reverse that has to leave the tree as it found it.
///
/// `CODEX_HOME` is a tempdir, so nothing here touches the developer's
/// own Codex install.
#[test]
fn sbproxy_connect_configures_a_client_and_disconnect_restores_it_byte_for_byte() {
    let gateway = start_gateway(Behavior::default());
    let codex_home = tempfile::tempdir().expect("codex home");
    let existing = codex_home.path().join("config.toml");
    let existing_bytes = b"# a hand-written Codex config\nmodel = \"gpt-5\"\n";
    std::fs::write(&existing, existing_bytes).expect("seed codex config");

    let run = |verb: &str| {
        std::process::Command::new(proxy_binary_path())
            .arg(verb)
            .arg("codex")
            .args(if verb == "connect" {
                vec!["--base-url".to_string(), gateway.proxy.base_url()]
            } else {
                Vec::new()
            })
            .env("CODEX_HOME", codex_home.path())
            .output()
            .unwrap_or_else(|error| panic!("`sbproxy {verb}` did not run: {error}"))
    };

    let connected = run("connect");
    assert!(
        connected.status.success(),
        "`sbproxy connect` failed: {}",
        String::from_utf8_lossy(&connected.stderr)
    );
    let profile = codex_home.path().join("sbproxy.config.toml");
    let profile_text = std::fs::read_to_string(&profile)
        .expect("connect writes a profile of its own, never your config.toml");
    assert!(
        profile_text.contains(&gateway.proxy.base_url()),
        "the profile has to point at this gateway: {profile_text}"
    );
    assert_eq!(
        std::fs::read(&existing).expect("read config.toml"),
        existing_bytes,
        "`connect` must never edit the operator's own config.toml"
    );

    let disconnected = run("disconnect");
    assert!(
        disconnected.status.success(),
        "`sbproxy disconnect` failed: {}",
        String::from_utf8_lossy(&disconnected.stderr)
    );
    assert!(
        !profile.exists(),
        "`disconnect` has to remove the profile it wrote"
    );
    assert_eq!(
        std::fs::read(&existing).expect("read config.toml"),
        existing_bytes,
        "the tree `disconnect` leaves has to be the tree `connect` found, byte for byte"
    );
    assert!(
        codex_home
            .path()
            .join("sbproxy.config.toml.sbproxy.removed")
            .exists(),
        "`disconnect` keeps the profile it removed beside the client's config, so an \
         edit made to it after connecting is recoverable rather than deleted"
    );
}
