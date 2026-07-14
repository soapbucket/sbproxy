// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Deterministic OpenAI-compatible engine for managed-model end-to-end fixtures.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_MODEL: &str = "fixture-model";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FaultMode {
    Normal = 0,
    Unary = 1,
    Sse = 2,
    DelayedHeaders = 3,
    PreOutputError = 4,
    MidStreamError = 5,
    StreamUntilCancelled = 6,
}

impl FaultMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "normal" => Some(Self::Normal),
            "unary" => Some(Self::Unary),
            "sse" => Some(Self::Sse),
            "delayed_headers" => Some(Self::DelayedHeaders),
            "pre_output_error" => Some(Self::PreOutputError),
            "mid_stream_error" => Some(Self::MidStreamError),
            "stream_until_cancelled" => Some(Self::StreamUntilCancelled),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Unary => "unary",
            Self::Sse => "sse",
            Self::DelayedHeaders => "delayed_headers",
            Self::PreOutputError => "pre_output_error",
            Self::MidStreamError => "mid_stream_error",
            Self::StreamUntilCancelled => "stream_until_cancelled",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Unary,
            2 => Self::Sse,
            3 => Self::DelayedHeaders,
            4 => Self::PreOutputError,
            5 => Self::MidStreamError,
            6 => Self::StreamUntilCancelled,
            _ => Self::Normal,
        }
    }
}

struct EngineState {
    mode: AtomicU8,
    ready_after_probes: usize,
    ready_probes: AtomicUsize,
    active_requests: AtomicUsize,
    completion_requests: AtomicUsize,
    cancelled_requests: AtomicUsize,
    shutdown: AtomicBool,
}

impl EngineState {
    fn new(mode: FaultMode, ready_after_probes: usize) -> Self {
        Self {
            mode: AtomicU8::new(mode as u8),
            ready_after_probes,
            ready_probes: AtomicUsize::new(0),
            active_requests: AtomicUsize::new(0),
            completion_requests: AtomicUsize::new(0),
            cancelled_requests: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        }
    }

    fn mode(&self) -> FaultMode {
        FaultMode::from_u8(self.mode.load(Ordering::SeqCst))
    }

    fn set_mode(&self, mode: FaultMode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }

    fn reset_counts(&self) {
        self.active_requests.store(0, Ordering::SeqCst);
        self.completion_requests.store(0, Ordering::SeqCst);
        self.cancelled_requests.store(0, Ordering::SeqCst);
    }
}

struct ActiveRequest(Arc<EngineState>);

impl ActiveRequest {
    fn begin(state: Arc<EngineState>) -> Self {
        state.active_requests.fetch_add(1, Ordering::SeqCst);
        Self(state)
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn argument(name: &str) -> Option<String> {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments.next();
        }
    }
    None
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::with_capacity(4_096);
    let mut buffer = [0u8; 4_096];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(std::io::Error::other("request closed before headers"));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::other("request exceeds fixture bound"));
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| std::io::Error::other("request headers are not UTF-8"))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::other("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();
    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if header_end.saturating_add(content_length) > MAX_REQUEST_BYTES {
        return Err(std::io::Error::other("request body exceeds fixture bound"));
    }
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(std::io::Error::other("request closed before body"));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_json(
    stream: &mut TcpStream,
    status: &str,
    value: serde_json::Value,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
    write_response(stream, status, "application/json", &body)
}

fn configured_model() -> String {
    std::env::var("SBPROXY_FAKE_ENGINE_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}

fn unary_body() -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "model": configured_model(),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "fixture-ready"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
    })
}

fn sse_body() -> Vec<u8> {
    let model = configured_model();
    format!(
        "data: {{\"id\":\"chatcmpl-fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"{model}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"fixture-ready\"}},\"finish_reason\":null}}]}}\n\n\
data: {{\"id\":\"chatcmpl-fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"{model}\",\"choices\":[],\"usage\":{{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}}}\n\n\
data: [DONE]\n\n"
    )
    .into_bytes()
}

fn stream_until_cancelled(stream: &mut TcpStream, state: &EngineState) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000000000\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )?;
    let frame = format!(
        "data: {{\"id\":\"chatcmpl-cancel\",\"object\":\"chat.completion.chunk\",\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"tick\"}},\"finish_reason\":null}}]}}\n\n",
        configured_model()
    );
    loop {
        if stream
            .write_all(frame.as_bytes())
            .and_then(|()| stream.flush())
            .is_err()
        {
            state.cancelled_requests.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn write_mid_stream_error(stream: &mut TcpStream) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000000\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )?;
    stream.write_all(
        format!(
            "data: {{\"id\":\"chatcmpl-midstream\",\"object\":\"chat.completion.chunk\",\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"partial\"}},\"finish_reason\":null}}]}}\n\n",
            configured_model()
        )
        .as_bytes(),
    )?;
    stream.flush()
}

fn completion_is_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

fn handle_control(
    stream: &mut TcpStream,
    request: &HttpRequest,
    state: &EngineState,
) -> std::io::Result<bool> {
    if request.method == "GET" && request.path == "/__control" {
        write_json(
            stream,
            "200 OK",
            serde_json::json!({
                "mode": state.mode().as_str(),
                "ready_probes": state.ready_probes.load(Ordering::SeqCst),
                "active_requests": state.active_requests.load(Ordering::SeqCst),
                "completion_requests": state.completion_requests.load(Ordering::SeqCst),
                "cancelled_requests": state.cancelled_requests.load(Ordering::SeqCst),
            }),
        )?;
        return Ok(true);
    }
    if request.method == "POST" && request.path == "/__control/reset" {
        state.reset_counts();
        write_json(stream, "200 OK", serde_json::json!({"status": "reset"}))?;
        return Ok(true);
    }
    if request.method == "POST" {
        if let Some(mode) = request.path.strip_prefix("/__control/mode/") {
            let Some(mode) = FaultMode::parse(mode) else {
                write_json(
                    stream,
                    "400 Bad Request",
                    serde_json::json!({"error": "unknown fault mode"}),
                )?;
                return Ok(true);
            };
            state.set_mode(mode);
            write_json(stream, "200 OK", serde_json::json!({"mode": mode.as_str()}))?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn handle_connection(mut stream: TcpStream, state: Arc<EngineState>) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let request = read_request(&mut stream)?;
    if handle_control(&mut stream, &request, &state)? {
        return Ok(());
    }
    if request.method == "GET" && request.path == "/health" {
        let probe = state.ready_probes.fetch_add(1, Ordering::SeqCst) + 1;
        if probe <= state.ready_after_probes {
            return write_json(
                &mut stream,
                "503 Service Unavailable",
                serde_json::json!({"status": "loading"}),
            );
        }
        return write_json(
            &mut stream,
            "200 OK",
            serde_json::json!({"status": "ready"}),
        );
    }
    if request.method == "GET" && request.path == "/v1/models" {
        return write_json(
            &mut stream,
            "200 OK",
            serde_json::json!({
                "object": "list",
                "data": [{"id": configured_model(), "object": "model", "owned_by": "fixture"}]
            }),
        );
    }
    if request.method != "POST" || request.path != "/v1/chat/completions" {
        return write_json(
            &mut stream,
            "404 Not Found",
            serde_json::json!({"error": "not found"}),
        );
    }

    let _active = ActiveRequest::begin(Arc::clone(&state));
    state.completion_requests.fetch_add(1, Ordering::SeqCst);
    let mode = state.mode();
    if mode == FaultMode::DelayedHeaders {
        let delay = std::env::var("SBPROXY_FAKE_ENGINE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(250);
        thread::sleep(Duration::from_millis(delay));
    }
    match mode {
        FaultMode::PreOutputError => write_json(
            &mut stream,
            "503 Service Unavailable",
            serde_json::json!({"error": {"type": "fixture_pre_output_error"}}),
        ),
        FaultMode::MidStreamError => write_mid_stream_error(&mut stream),
        FaultMode::StreamUntilCancelled => stream_until_cancelled(&mut stream, &state),
        FaultMode::Sse => write_response(&mut stream, "200 OK", "text/event-stream", &sse_body()),
        FaultMode::Unary => write_json(&mut stream, "200 OK", unary_body()),
        FaultMode::Normal | FaultMode::DelayedHeaders => {
            if completion_is_streaming(&request.body) {
                write_response(&mut stream, "200 OK", "text/event-stream", &sse_body())
            } else {
                write_json(&mut stream, "200 OK", unary_body())
            }
        }
    }
}

fn serve(listener: TcpListener, state: Arc<EngineState>) -> std::io::Result<()> {
    for connection in listener.incoming() {
        if state.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let connection = connection?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let _ = handle_connection(connection, state);
        });
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let port = argument("--port")
        .ok_or_else(|| std::io::Error::other("missing --port"))?
        .parse::<u16>()
        .map_err(|error| std::io::Error::other(format!("invalid --port: {error}")))?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let ready_after_probes = std::env::var("SBPROXY_FAKE_ENGINE_READY_AFTER_PROBES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    serve(
        listener,
        Arc::new(EngineState::new(FaultMode::Normal, ready_after_probes)),
    )
}

#[cfg(test)]
struct TestEngine {
    address: std::net::SocketAddr,
    state: Arc<EngineState>,
    thread: Option<thread::JoinHandle<std::io::Result<()>>>,
}

#[cfg(test)]
impl TestEngine {
    fn start(mode: FaultMode) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let state = Arc::new(EngineState::new(mode, 0));
        let server_state = Arc::clone(&state);
        let thread = thread::spawn(move || serve(listener, server_state));
        Ok(Self {
            address,
            state,
            thread: Some(thread),
        })
    }

    const fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn cancelled(&self) -> usize {
        self.state.cancelled_requests.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
impl Drop for TestEngine {
    fn drop(&mut self) {
        self.state.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn fake_engine_streams_usage_and_observes_disconnect() {
        let engine = TestEngine::start(FaultMode::StreamUntilCancelled).expect("start engine");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client");
        let mut response = client
            .post(format!("http://{}/v1/chat/completions", engine.address()))
            .json(&serde_json::json!({"model": "fixture-model", "stream": true}))
            .send()
            .expect("stream response");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let mut first = [0u8; 128];
        let count = response.read(&mut first).expect("first stream frame");
        assert!(String::from_utf8_lossy(&first[..count]).starts_with("data: {"));
        drop(response);

        let deadline = Instant::now() + Duration::from_secs(2);
        while engine.cancelled() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(engine.cancelled(), 1);
    }
}
