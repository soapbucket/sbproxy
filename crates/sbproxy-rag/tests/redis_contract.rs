//! RESP wire, escaping, reconnect, and DNS revalidation contracts for
//! the Redis vector store.
//!
//! A tiny Tokio RESP server captures every command the adapter sends,
//! answers connection setup commands with `+OK`, and serves scripted
//! `FT.SEARCH` replies. The resolver and address policy are injected
//! through the adapter's test seam so reconnects can be steered at
//! scripted answers without live DNS.

#![cfg(feature = "vector-redis")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_ai::rag_config::{RagVectorStoreConfig, MAX_PROVIDER_RESPONSE_BYTES};
use sbproxy_rag::vector::redis::{
    escape_redis_tag, AddressPolicy, HostResolver, HostResolverFuture, RedisVectorStore,
};
use sbproxy_rag::{RagBuildError, RagBuildMode, VectorQuery, VectorStore, VectorStoreError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What a fixture connection does once its scripted replies run out.
#[derive(Clone, Copy)]
enum AfterReplies {
    /// Close the socket.
    CloseConnection,
    /// Keep reading but never answer another search.
    StallSilently,
}

/// Script for one accepted connection: replies served to `FT.SEARCH`
/// commands in order, then the exhaustion behavior.
struct ConnectionScript {
    search_replies: Vec<Vec<u8>>,
    after: AfterReplies,
}

/// Handle to a running RESP fixture.
struct RespFixture {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    commands: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
}

async fn spawn_resp_fixture(scripts: Vec<ConnectionScript>) -> RespFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(Mutex::new(Vec::new()));
    let accepts_task = Arc::clone(&accepts);
    let commands_task = Arc::clone(&commands);
    tokio::spawn(async move {
        for script in scripts {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            drive_connection(stream, script, Arc::clone(&commands_task)).await;
        }
    });
    RespFixture {
        addr,
        accepts,
        commands,
    }
}

async fn drive_connection(
    mut stream: tokio::net::TcpStream,
    script: ConnectionScript,
    commands: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
) {
    let mut buffer: Vec<u8> = Vec::new();
    let mut replies = script.search_replies.into_iter();
    loop {
        while let Some(arguments) = parse_resp_command(&mut buffer) {
            commands.lock().unwrap().push(arguments.clone());
            let is_search = arguments
                .first()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"FT.SEARCH"));
            if !is_search {
                // Connection setup commands (AUTH, CLIENT SETINFO) each
                // expect one reply.
                if stream.write_all(b"+OK\r\n").await.is_err() {
                    return;
                }
                continue;
            }
            match replies.next() {
                Some(reply) => {
                    if stream.write_all(&reply).await.is_err() {
                        return;
                    }
                    if replies.as_slice().is_empty()
                        && matches!(script.after, AfterReplies::CloseConnection)
                    {
                        return;
                    }
                }
                None => match script.after {
                    AfterReplies::CloseConnection => return,
                    AfterReplies::StallSilently => {}
                },
            }
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    }
}

/// Parses one complete RESP command (`*N` of `$len` bulk strings) from
/// the front of the buffer, consuming it, or returns `None` when the
/// buffer holds no complete command yet.
fn parse_resp_command(buffer: &mut Vec<u8>) -> Option<Vec<Vec<u8>>> {
    let mut cursor = 0usize;
    let count = parse_prefixed_number(buffer, &mut cursor, b'*')?;
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let length = parse_prefixed_number(buffer, &mut cursor, b'$')?;
        if buffer.len() < cursor + length + 2 {
            return None;
        }
        arguments.push(buffer[cursor..cursor + length].to_vec());
        cursor += length + 2;
    }
    buffer.drain(..cursor);
    Some(arguments)
}

fn parse_prefixed_number(buffer: &[u8], cursor: &mut usize, prefix: u8) -> Option<usize> {
    if buffer.len() <= *cursor || buffer[*cursor] != prefix {
        return None;
    }
    let line_end = buffer[*cursor..]
        .windows(2)
        .position(|window| window == b"\r\n")?
        + *cursor;
    let digits = std::str::from_utf8(&buffer[*cursor + 1..line_end]).ok()?;
    let value = digits.parse::<usize>().ok()?;
    *cursor = line_end + 2;
    Some(value)
}

fn resp_bulk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("${}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

fn resp_int(value: i64) -> Vec<u8> {
    format!(":{value}\r\n").into_bytes()
}

fn resp_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", items.len()).into_bytes();
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn resp_error(message: &str) -> Vec<u8> {
    format!("-{message}\r\n").into_bytes()
}

/// Encodes an `FT.SEARCH` reply: `[total, key, fields, ...]`.
fn search_reply(records: &[(&str, &[(&str, &str)])]) -> Vec<u8> {
    let mut items = vec![resp_int(records.len() as i64)];
    for (key, fields) in records {
        items.push(resp_bulk(key.as_bytes()));
        let mut field_items = Vec::new();
        for (name, value) in *fields {
            field_items.push(resp_bulk(name.as_bytes()));
            field_items.push(resp_bulk(value.as_bytes()));
        }
        items.push(resp_array(&field_items));
    }
    resp_array(&items)
}

fn valid_search_reply() -> Vec<u8> {
    search_reply(&[(
        "doc-1",
        &[
            ("content", "Refund policy text."),
            ("vector_distance", "0.4"),
        ],
    )])
}

fn one_reply_then_close(reply: Vec<u8>) -> ConnectionScript {
    ConnectionScript {
        search_replies: vec![reply],
        after: AfterReplies::CloseConnection,
    }
}

fn redis_config(url: &str, username: Option<&str>, password: Option<&str>) -> RagVectorStoreConfig {
    let mut value = serde_json::json!({
        "provider": "redis",
        "url": url,
        "index": "docs_idx",
        "vector_field": "embedding",
    });
    if let Some(username) = username {
        value["username"] = serde_json::json!(username);
    }
    if let Some(password) = password {
        value["password"] = serde_json::json!(password);
    }
    serde_json::from_value(value).expect("redis fixture config parses")
}

/// Resolver that serves one scripted answer set per call and records
/// the hostnames it was asked to resolve.
fn scripted_resolver(
    answers: Vec<Vec<SocketAddr>>,
    calls: Arc<AtomicUsize>,
    hosts: Arc<Mutex<Vec<String>>>,
) -> HostResolver {
    let answers = Arc::new(Mutex::new(answers.into_iter()));
    Arc::new(move |host: &str, _port: u16| -> HostResolverFuture {
        calls.fetch_add(1, Ordering::SeqCst);
        hosts.lock().unwrap().push(host.to_owned());
        let answer = answers.lock().unwrap().next();
        Box::pin(async move { answer.ok_or_else(|| "resolver script exhausted".to_owned()) })
    })
}

fn allow_all() -> AddressPolicy {
    Arc::new(|_addr| false)
}

fn fixture_statics() -> BTreeMap<String, String> {
    BTreeMap::from([("kind".to_owned(), "policy".to_owned())])
}

fn fixture_embedding() -> Vec<f32> {
    vec![0.1, 0.2]
}

fn fixture_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    for value in fixture_embedding() {
        blob.extend_from_slice(&value.to_le_bytes());
    }
    blob
}

/// Builds a store whose resolver always answers with `addr`.
fn store_for(
    addr: SocketAddr,
    config: &RagVectorStoreConfig,
    timeout: Duration,
) -> RedisVectorStore {
    let calls = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    RedisVectorStore::from_config_with_resolver(
        config,
        timeout,
        scripted_resolver(vec![vec![addr]; 8], calls, hosts),
        allow_all(),
    )
    .expect("store builds")
}

async fn run_search(
    store: &RedisVectorStore,
) -> Result<Vec<sbproxy_rag::RetrievedChunk>, VectorStoreError> {
    let statics = fixture_statics();
    let embedding = fixture_embedding();
    store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: "tenant-a",
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await
}

/// Runs a search on a background task so two can be in flight over one
/// cached connection at the same time.
fn spawn_search(
    store: Arc<RedisVectorStore>,
) -> tokio::task::JoinHandle<Result<Vec<sbproxy_rag::RetrievedChunk>, VectorStoreError>> {
    tokio::spawn(async move { run_search(&store).await })
}

fn find_command<'a>(commands: &'a [Vec<Vec<u8>>], name: &[u8]) -> Option<&'a Vec<Vec<u8>>> {
    commands.iter().find(|command| {
        command
            .first()
            .is_some_and(|first| first.eq_ignore_ascii_case(name))
    })
}

#[tokio::test]
async fn redis_search_emits_the_documented_command() {
    let fixture = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: vec![valid_search_reply()],
        after: AfterReplies::StallSilently,
    }])
    .await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));

    let chunks = run_search(&store).await.unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].source_id, "doc-1");
    assert_eq!(chunks[0].content, "Refund policy text.");
    assert!((chunks[0].score - 0.8).abs() < 1e-6, "unexpected score");

    let commands = fixture.commands.lock().unwrap();
    let search = find_command(&commands, b"FT.SEARCH").expect("search command was captured");
    let expected: Vec<Vec<u8>> = vec![
        b"FT.SEARCH".to_vec(),
        b"docs_idx".to_vec(),
        b"(@tenant_id:{tenant\\-a} @kind:{policy})=>[KNN 5 @embedding $BLOB AS vector_distance]"
            .to_vec(),
        b"PARAMS".to_vec(),
        b"2".to_vec(),
        b"BLOB".to_vec(),
        fixture_blob(),
        b"SORTBY".to_vec(),
        b"vector_distance".to_vec(),
        b"RETURN".to_vec(),
        b"2".to_vec(),
        b"content".to_vec(),
        b"vector_distance".to_vec(),
        b"DIALECT".to_vec(),
        b"2".to_vec(),
    ];
    assert_eq!(search, &expected);
}

#[tokio::test]
async fn redis_auth_uses_the_separate_credential_fields() {
    let fixture = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: vec![valid_search_reply()],
        after: AfterReplies::StallSilently,
    }])
    .await;
    let config = redis_config(
        "redis://redis-fixture.invalid:6390",
        Some("acl-user"),
        Some("fixture-password"),
    );
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    run_search(&store).await.unwrap();

    let commands = fixture.commands.lock().unwrap();
    let auth = find_command(&commands, b"AUTH").expect("auth command was not sent");
    let expected_auth: Vec<Vec<u8>> = vec![
        b"AUTH".to_vec(),
        b"acl-user".to_vec(),
        b"fixture-password".to_vec(),
    ];
    // Neither the expected nor the captured credential values may appear
    // in an assertion message, so compare with a fixed-text message.
    assert!(
        *auth == expected_auth,
        "auth command did not carry the configured username and password"
    );
    let auth_position = commands
        .iter()
        .position(|command| {
            command
                .first()
                .is_some_and(|f| f.eq_ignore_ascii_case(b"AUTH"))
        })
        .unwrap();
    let search_position = commands
        .iter()
        .position(|command| {
            command
                .first()
                .is_some_and(|f| f.eq_ignore_ascii_case(b"FT.SEARCH"))
        })
        .unwrap();
    assert!(auth_position < search_position, "auth must precede search");
}

#[test]
fn redis_escape_covers_the_documented_metacharacters() {
    assert_eq!(escape_redis_tag("a-b"), r"a\-b");
    assert_eq!(escape_redis_tag("a b"), r"a\ b");
    assert_eq!(escape_redis_tag("a|b"), r"a\|b");
    assert_eq!(escape_redis_tag("a{b}"), r"a\{b\}");
    assert_eq!(escape_redis_tag(r"a\b"), r"a\\b");
    assert_eq!(escape_redis_tag("a@b"), r"a\@b");
}

#[tokio::test]
async fn redis_hostile_tenant_stays_inside_the_tag_filter() {
    let fixture = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: vec![valid_search_reply()],
        after: AfterReplies::StallSilently,
    }])
    .await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));

    let hostile = "tenant-a\"} OR *";
    let statics = BTreeMap::new();
    let embedding = fixture_embedding();
    store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: hostile,
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await
        .unwrap();

    let commands = fixture.commands.lock().unwrap();
    let search = find_command(&commands, b"FT.SEARCH").expect("search command was captured");
    let expected_query = format!(
        "(@tenant_id:{{{}}})=>[KNN 5 @embedding $BLOB AS vector_distance]",
        escape_redis_tag(hostile)
    );
    assert_eq!(search[2], expected_query.into_bytes());
}

#[tokio::test]
async fn redis_reports_a_missing_search_module() {
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(resp_error(
        "ERR unknown command 'FT.SEARCH', with args beginning with: 'docs_idx'",
    ))])
    .await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis rejected the search command")
    );
}

#[tokio::test]
async fn redis_rejects_malformed_reply_shapes() {
    // Not an array at all.
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(b"+OK\r\n".to_vec())]).await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis reply is not an array")
    );

    // An array without the leading result count.
    let reply = resp_array(&[resp_bulk(b"doc-1")]);
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis reply is missing the result count")
    );

    // A dangling key without its field array.
    let reply = resp_array(&[resp_int(1), resp_bulk(b"doc-1")]);
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis reply records are misaligned")
    );
}

#[tokio::test]
async fn redis_rejects_missing_content() {
    let reply = search_reply(&[("doc-1", &[("vector_distance", "0.4")])]);
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis record is missing content")
    );
}

#[tokio::test]
async fn redis_rejects_bad_distances() {
    let cases: [(&str, VectorStoreError); 3] = [
        (
            "abc",
            VectorStoreError::MalformedResponse("redis vector distance is not numeric"),
        ),
        ("nan", VectorStoreError::NonFiniteScore),
        (
            "3.5",
            VectorStoreError::MalformedResponse(
                "cosine distance outside the documented 0.0..=2.0 range",
            ),
        ),
    ];
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    for (distance, expected) in cases {
        let reply = search_reply(&[(
            "doc-1",
            &[
                ("content", "Refund policy text."),
                ("vector_distance", distance),
            ],
        )]);
        let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
        let store = store_for(fixture.addr, &config, Duration::from_secs(2));
        let error = run_search(&store).await.unwrap_err();
        assert_eq!(error, expected);
    }
}

#[tokio::test]
async fn redis_rejects_more_records_than_requested() {
    let record: (&str, &[(&str, &str)]) = (
        "doc-1",
        &[
            ("content", "Refund policy text."),
            ("vector_distance", "0.4"),
        ],
    );
    let reply = search_reply(&[record; 6]);
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(2));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis returned more records than requested")
    );
}

#[tokio::test]
async fn redis_caps_decoded_content() {
    let oversized = "a".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1);
    let reply = search_reply(&[(
        "doc-1",
        &[("content", oversized.as_str()), ("vector_distance", "0.4")],
    )]);
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(reply)]).await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_secs(30));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(error, VectorStoreError::ResponseTooLarge);
}

#[tokio::test]
async fn redis_times_out_when_the_server_stalls() {
    let fixture = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: Vec::new(),
        after: AfterReplies::StallSilently,
    }])
    .await;
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = store_for(fixture.addr, &config, Duration::from_millis(300));
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(error, VectorStoreError::Timeout);
}

#[tokio::test]
async fn redis_reconnects_after_a_dropped_socket() {
    let fixture = spawn_resp_fixture(vec![
        one_reply_then_close(valid_search_reply()),
        one_reply_then_close(valid_search_reply()),
    ])
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = RedisVectorStore::from_config_with_resolver(
        &config,
        Duration::from_secs(2),
        scripted_resolver(
            vec![vec![fixture.addr], vec![fixture.addr]],
            Arc::clone(&calls),
            hosts,
        ),
        allow_all(),
    )
    .unwrap();

    // First search succeeds, then the fixture drops the socket.
    run_search(&store).await.unwrap();
    // The cached connection is dead; this search surfaces the failure
    // and discards the connection.
    let error = run_search(&store).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
    // The next search reconnects through the resolver and succeeds.
    run_search(&store).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2, "resolver call count");
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 2, "accept count");
}

#[tokio::test]
async fn redis_reconnect_revalidates_dns_before_dial() {
    let fixture = spawn_resp_fixture(vec![one_reply_then_close(valid_search_reply())]).await;
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let second_accepts = Arc::new(AtomicUsize::new(0));
    let second_accepts_task = Arc::clone(&second_accepts);
    tokio::spawn(async move {
        while second_listener.accept().await.is_ok() {
            second_accepts_task.fetch_add(1, Ordering::SeqCst);
        }
    });

    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let forbidden_port = second_addr.port();
    let policy: AddressPolicy = {
        let policy_calls = Arc::clone(&policy_calls);
        Arc::new(move |addr| {
            policy_calls.fetch_add(1, Ordering::SeqCst);
            addr.port() == forbidden_port
        })
    };
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = RedisVectorStore::from_config_with_resolver(
        &config,
        Duration::from_secs(2),
        scripted_resolver(
            vec![vec![fixture.addr], vec![second_addr]],
            Arc::clone(&resolver_calls),
            hosts,
        ),
        policy,
    )
    .unwrap();

    // First dial: resolver answer passes the policy, one command is
    // served, then the fixture drops the socket.
    run_search(&store).await.unwrap();
    // The dead cached connection surfaces and is discarded.
    let error = run_search(&store).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
    // Reconnect: the resolver's second answer is rejected by the policy
    // before any dial.
    let error = run_search(&store).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("redis endpoint resolved to a forbidden address")
    );
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2, "resolver calls");
    assert_eq!(policy_calls.load(Ordering::SeqCst), 2, "policy calls");
    assert_eq!(second_accepts.load(Ordering::SeqCst), 0, "second accepts");
}

/// A search failing on a socket that died earlier must not evict the
/// connection a later search already dialed.
///
/// Drives `RedisVectorStore::discard_connection`'s generation tag
/// through the public `search` seam: two searches share the first
/// connection and both stall, and the second one's timeout lands after a
/// third search has already dialed and cached a replacement. With an
/// untagged discard that straggler cleared the slot regardless of which
/// connection it had failed on, so the replacement was thrown away and
/// the fourth search dialed a third time.
#[tokio::test]
async fn redis_late_failure_keeps_the_replacement_connection() {
    // The stagger sets how far apart the two stalled searches time out,
    // which is the window the replacement dial has to land in. The test
    // asserts that ordering actually held rather than assuming it, so a
    // machine slow enough to break it fails loudly instead of passing
    // for the wrong reason.
    let store_timeout = Duration::from_millis(1500);
    let stagger = Duration::from_millis(800);

    // First dial: answers connection setup, then never answers a search.
    let stalling = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: Vec::new(),
        after: AfterReplies::StallSilently,
    }])
    .await;
    // Second dial: serves the replacement search, and the fourth search
    // too once the connection survives the straggler.
    let replacement = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: vec![valid_search_reply(), valid_search_reply()],
        after: AfterReplies::StallSilently,
    }])
    .await;
    // Third dial: must never happen. Counts accepts only.
    let third_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let third_addr = third_listener.local_addr().unwrap();
    let third_accepts = Arc::new(AtomicUsize::new(0));
    let third_accepts_task = Arc::clone(&third_accepts);
    tokio::spawn(async move {
        while third_listener.accept().await.is_ok() {
            third_accepts_task.fetch_add(1, Ordering::SeqCst);
        }
    });

    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let config = redis_config("redis://redis-fixture.invalid:6390", None, None);
    let store = Arc::new(
        RedisVectorStore::from_config_with_resolver(
            &config,
            store_timeout,
            scripted_resolver(
                vec![
                    vec![stalling.addr],
                    vec![replacement.addr],
                    vec![third_addr],
                ],
                Arc::clone(&resolver_calls),
                hosts,
            ),
            allow_all(),
        )
        .unwrap(),
    );

    // The first search dials and stalls. The second joins the same
    // cached connection `stagger` later and stalls too, so its timeout
    // lands `stagger` after the first one's.
    let first = spawn_search(Arc::clone(&store));
    tokio::time::sleep(stagger).await;
    let second = spawn_search(Arc::clone(&store));

    assert_eq!(
        first.await.unwrap().unwrap_err(),
        VectorStoreError::Timeout,
        "the first stalled search times out"
    );

    // Dials the replacement and caches it as the next generation.
    run_search(&store)
        .await
        .expect("the replacement search succeeds");
    assert!(
        !second.is_finished(),
        "fixture ordering broke: the straggler must still be in flight \
         when the replacement is cached, or this test proves nothing"
    );

    // The straggler now fails on the generation that is already gone.
    assert_eq!(
        second.await.unwrap().unwrap_err(),
        VectorStoreError::Timeout,
        "the straggling search times out"
    );

    // The search after the straggler must reuse the replacement.
    run_search(&store)
        .await
        .expect("the search after the straggler reuses the replacement");
    assert_eq!(
        third_accepts.load(Ordering::SeqCst),
        0,
        "the straggler's discard evicted the replacement and forced a third dial"
    );
    assert_eq!(
        resolver_calls.load(Ordering::SeqCst),
        2,
        "resolver calls: one per real dial, none after the straggler"
    );
    assert_eq!(
        replacement.accepts.load(Ordering::SeqCst),
        1,
        "both later searches ran over one replacement connection"
    );
    assert_eq!(
        stalling.accepts.load(Ordering::SeqCst),
        1,
        "the stalling fixture was dialed exactly once"
    );
}

#[tokio::test]
async fn redis_rejects_userinfo_urls_at_build() {
    let config = redis_config(
        "redis://acl-user:secret-credential@127.0.0.1:6390",
        None,
        None,
    );
    let error =
        match sbproxy_rag::vector::build(&config, Duration::from_secs(1), RagBuildMode::Validation)
        {
            Ok(_) => panic!("a userinfo URL must be rejected at build"),
            Err(error) => error,
        };
    assert!(matches!(error, RagBuildError::InvalidConfig(_)));
    assert!(!error.to_string().contains("secret-credential"));
}

#[tokio::test]
async fn rediss_pinning_keeps_original_hostname_for_tls() {
    // Two halves, deliberately split, because racing a real TLS dial made
    // this flaky: building the rustls configuration is slow enough under a
    // fully parallel workspace run that a deadline generous enough to be
    // reliable is also long enough to hurt, and the handshake can never
    // complete against a plaintext fixture anyway.
    //
    // Half one, over plaintext, proves the dial goes to the resolver's
    // pinned address and nowhere else. Half two proves a rediss:// client
    // keeps the configured hostname as the TLS server name while that
    // pinning is in force. Together they are the contract; neither needs a
    // handshake, and neither depends on timing.
    let fixture = spawn_resp_fixture(vec![ConnectionScript {
        search_replies: vec![valid_search_reply()],
        after: AfterReplies::CloseConnection,
    }])
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let plaintext = redis_config("redis://pinned-host.invalid:6390", None, None);
    let store = RedisVectorStore::from_config_with_resolver(
        &plaintext,
        Duration::from_secs(5),
        scripted_resolver(
            vec![vec![fixture.addr]],
            Arc::clone(&calls),
            Arc::clone(&hosts),
        ),
        allow_all(),
    )
    .unwrap();
    run_search(&store).await.expect("the pinned dial serves");
    assert_eq!(
        hosts.lock().unwrap().as_slice(),
        ["pinned-host.invalid"],
        "the resolver is asked for the configured hostname, not an address"
    );
    assert_eq!(
        fixture.accepts.load(Ordering::SeqCst),
        1,
        "the dial lands on the resolver's pinned address"
    );

    // The TLS half needs no I/O: `tls_host` is the string the redis rustls
    // connector hands to rustls as the server name, so preserving it is
    // exactly the property that keeps certificate verification honest while
    // the TCP destination stays pinned.
    let secure = redis_config("rediss://pinned-host.invalid:6390", None, None);
    let secure_store = RedisVectorStore::from_config_with_resolver(
        &secure,
        Duration::from_secs(5),
        scripted_resolver(
            vec![vec![fixture.addr]],
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Mutex::new(Vec::new())),
        ),
        allow_all(),
    )
    .unwrap();
    assert_eq!(secure_store.tls_host(), Some("pinned-host.invalid"));
    assert_eq!(
        store.tls_host(),
        None,
        "a plaintext client carries no TLS server name"
    );
}
