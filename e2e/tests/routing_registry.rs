//! Production acceptance coverage for registered load-balancer strategies.
//!
//! Each case starts real loopback HTTP upstreams and compiles the strategy
//! through the same YAML action path used by the proxy process.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use sbproxy_e2e::{ProxyHarness, Response};

struct DelayedUpstream {
    port: u16,
    captured: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<JoinHandle<()>>,
}

impl DelayedUpstream {
    fn start(target: &'static str, delay: Duration) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let captured = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let captured_for_thread = Arc::clone(&captured);
        let shutdown_for_thread = Arc::clone(&shutdown);

        let join = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_for_thread.lock().expect("shutdown lock") {
                    break;
                }
                let Ok(mut stream) = stream else {
                    continue;
                };
                if serve(&mut stream, target, delay).is_ok() {
                    captured_for_thread.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn captured(&self) -> usize {
        self.captured.load(Ordering::Relaxed)
    }
}

impl Drop for DelayedUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().expect("shutdown lock") = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve(stream: &mut TcpStream, target: &str, delay: Duration) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..read]);
    }

    std::thread::sleep(delay);
    let body = format!(r#"{{"target":"{target}"}}"#);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn response_target(response: &Response) -> String {
    assert_eq!(response.status, 200);
    response.json().expect("JSON upstream response")["target"]
        .as_str()
        .expect("target response field")
        .to_string()
}

#[test]
fn bandit_samples_each_arm_then_converges_on_the_faster_target() {
    let slow = DelayedUpstream::start("slow", Duration::from_millis(200)).expect("slow upstream");
    let fast = DelayedUpstream::start("fast", Duration::ZERO).expect("fast upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "bandit.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      lb_method: plugin
      strategy: bandit
      strategy_config:
        epsilon: 0.0
      targets:
        - url: "{}"
        - url: "{}"
"#,
        slow.base_url(),
        fast.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let selected: Vec<String> = (0..8)
        .map(|_| {
            response_target(
                &proxy
                    .get("/v1/chat", "bandit.localhost")
                    .expect("route request"),
            )
        })
        .collect();

    assert_eq!(&selected[..2], ["slow", "fast"]);
    assert!(
        selected[2..].iter().all(|target| target == "fast"),
        "after both arms are sampled, the faster arm must win: {selected:?}"
    );
    assert_eq!(slow.captured(), 1);
    assert_eq!(fast.captured(), 7);
}

#[test]
fn first_healthy_compiles_and_selects_the_first_target() {
    let first = DelayedUpstream::start("first", Duration::ZERO).expect("first upstream");
    let second = DelayedUpstream::start("second", Duration::ZERO).expect("second upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "first-healthy.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      lb_method: plugin
      strategy: first-healthy
      targets:
        - url: "{}"
        - url: "{}"
"#,
        first.base_url(),
        second.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..3 {
        let response = proxy
            .get("/", "first-healthy.localhost")
            .expect("route request");
        assert_eq!(response_target(&response), "first");
    }
    assert_eq!(first.captured(), 3);
    assert_eq!(second.captured(), 0);
}

#[test]
fn gpu_aware_compiles_and_selects_the_lowest_utilization_target() {
    let busy = DelayedUpstream::start("busy", Duration::ZERO).expect("busy upstream");
    let idle = DelayedUpstream::start("idle", Duration::ZERO).expect("idle upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gpu.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      lb_method: plugin
      strategy: gpu-aware
      targets:
        - url: "{}"
          metadata:
            gpu_utilization: 0.9
        - url: "{}"
          metadata:
            gpu_utilization: 0.1
"#,
        busy.base_url(),
        idle.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy.get("/", "gpu.localhost").expect("route request");
    assert_eq!(response_target(&response), "idle");
    assert_eq!(busy.captured(), 0);
    assert_eq!(idle.captured(), 1);
}

#[test]
fn lora_aware_compiles_and_selects_the_warm_target() {
    let cold = DelayedUpstream::start("cold", Duration::ZERO).expect("cold upstream");
    let warm = DelayedUpstream::start("warm", Duration::ZERO).expect("warm upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lora.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      lb_method: plugin
      strategy: lora-aware
      targets:
        - url: "{}"
          metadata:
            loaded_adapters: [other-adapter]
        - url: "{}"
          metadata:
            loaded_adapters: [support]
"#,
        cold.base_url(),
        warm.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .get("/v1/chat?adapter=support", "lora.localhost")
        .expect("route request");
    assert_eq!(response_target(&response), "warm");
    assert_eq!(cold.captured(), 0);
    assert_eq!(warm.captured(), 1);
}
