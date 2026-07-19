use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use url::Url;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(100);
const PROXY_IO_TIMEOUT: Duration = Duration::from_secs(1);
const PROXY_MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(2);
const PROXY_ACCEPT_POLL: Duration = Duration::from_millis(5);

pub struct RedisServer {
    child: Option<Child>,
    _directory: TempDir,
    port: u16,
    mode: RedisServerMode,
}

pub struct RedisTlsServerConfig {
    pub server_cert_file: PathBuf,
    pub server_key_file: PathBuf,
    pub ca_cert_file: PathBuf,
    pub readiness_root_cert: Vec<u8>,
    pub readiness_client_cert: Vec<u8>,
    pub readiness_client_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedisProtocolCounts {
    pub tls: usize,
    pub plaintext: usize,
    pub other: usize,
}

pub struct RedisProtocolAuditProxy {
    port: u16,
    counts: Arc<ProtocolCounters>,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct ProtocolCounters {
    tls: AtomicUsize,
    plaintext: AtomicUsize,
    other: AtomicUsize,
}

enum RedisServerMode {
    Authenticated { password: String },
    AclFallbackTrap { username: String, password: String },
    Tls(RedisTlsServerConfig),
}

impl RedisProtocolAuditProxy {
    pub fn spawn(upstream_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|_| panic!("failed to bind the Redis protocol audit proxy"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|_| panic!("failed to configure the Redis protocol audit proxy"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| panic!("failed to inspect the Redis protocol audit proxy"))
            .port();
        let counts = Arc::new(ProtocolCounters::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_counts = Arc::clone(&counts);
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::spawn(move || {
            run_protocol_audit_proxy(listener, upstream_port, worker_counts, worker_shutdown);
        });

        Self {
            port,
            counts,
            shutdown,
            worker: Some(worker),
        }
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn protocol_counts(&self) -> RedisProtocolCounts {
        RedisProtocolCounts {
            tls: self.counts.tls.load(Ordering::Acquire),
            plaintext: self.counts.plaintext.load(Ordering::Acquire),
            other: self.counts.other.load(Ordering::Acquire),
        }
    }
}

impl Drop for RedisProtocolAuditProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_protocol_audit_proxy(
    listener: TcpListener,
    upstream_port: u16,
    counts: Arc<ProtocolCounters>,
    shutdown: Arc<AtomicBool>,
) {
    let mut handlers = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((client, _)) => {
                let connection_counts = Arc::clone(&counts);
                handlers.push(thread::spawn(move || {
                    proxy_redis_connection(client, upstream_port, &connection_counts);
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(PROXY_ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }

    for handler in handlers {
        let _ = handler.join();
    }
}

fn proxy_redis_connection(client: TcpStream, upstream_port: u16, counts: &ProtocolCounters) {
    let _ = client.set_read_timeout(Some(PROXY_IO_TIMEOUT));
    let _ = client.set_write_timeout(Some(PROXY_IO_TIMEOUT));

    let mut prefix = [0_u8; 1];
    match client.peek(&mut prefix) {
        Ok(1) if prefix[0] == 0x16 => {
            counts.tls.fetch_add(1, Ordering::AcqRel);
        }
        Ok(1) if prefix[0] == b'*' => {
            counts.plaintext.fetch_add(1, Ordering::AcqRel);
        }
        _ => {
            counts.other.fetch_add(1, Ordering::AcqRel);
            return;
        }
    }

    let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
    let Ok(upstream) = TcpStream::connect_timeout(&upstream_addr, PROXY_IO_TIMEOUT) else {
        return;
    };
    let _ = upstream.set_read_timeout(Some(PROXY_IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(PROXY_IO_TIMEOUT));

    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_writer) = upstream.try_clone() else {
        return;
    };
    let client_to_upstream = thread::spawn(move || {
        forward_bounded(&mut client_reader, &mut upstream_writer);
    });

    let mut upstream_reader = upstream;
    let mut client_writer = client;
    forward_bounded(&mut upstream_reader, &mut client_writer);
    let _ = client_to_upstream.join();
}

fn forward_bounded(reader: &mut TcpStream, writer: &mut TcpStream) {
    let deadline = Instant::now() + PROXY_MAX_CONNECTION_LIFETIME;
    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                if writer.write_all(&buffer[..length]).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = writer.shutdown(Shutdown::Write);
}

impl RedisServer {
    pub fn spawn_authenticated(password: &str) -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|_| panic!("failed to reserve a loopback port for redis-server"));
        let port = reservation
            .local_addr()
            .unwrap_or_else(|_| panic!("failed to inspect the reserved redis-server port"))
            .port();
        let directory = tempfile::tempdir()
            .unwrap_or_else(|_| panic!("failed to create the disposable redis-server directory"));
        drop(reservation);

        let mode = RedisServerMode::Authenticated {
            password: password.to_string(),
        };
        let child = spawn_child(port, directory.path(), &mode);
        let mut server = Self {
            child: Some(child),
            _directory: directory,
            port,
            mode,
        };
        server.wait_until_ready();
        server
    }

    pub fn spawn_acl_fallback_trap(username: &str, password: &str) -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|_| panic!("failed to reserve a loopback port for redis-server"));
        let port = reservation
            .local_addr()
            .unwrap_or_else(|_| panic!("failed to inspect the reserved redis-server port"))
            .port();
        let directory = tempfile::tempdir()
            .unwrap_or_else(|_| panic!("failed to create the disposable redis-server directory"));
        drop(reservation);

        let mode = RedisServerMode::AclFallbackTrap {
            username: username.to_string(),
            password: password.to_string(),
        };
        let child = spawn_child(port, directory.path(), &mode);
        let mut server = Self {
            child: Some(child),
            _directory: directory,
            port,
            mode,
        };
        server.wait_until_ready();
        server
    }

    pub fn spawn_tls(config: RedisTlsServerConfig) -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|_| panic!("failed to reserve a loopback port for TLS redis-server"));
        let port = reservation
            .local_addr()
            .unwrap_or_else(|_| panic!("failed to inspect the reserved TLS redis-server port"))
            .port();
        let directory = tempfile::tempdir().unwrap_or_else(|_| {
            panic!("failed to create the disposable TLS redis-server directory")
        });
        drop(reservation);

        let mode = RedisServerMode::Tls(config);
        let child = spawn_child(port, directory.path(), &mode);
        let mut server = Self {
            child: Some(child),
            _directory: directory,
            port,
            mode,
        };
        server.wait_until_ready();
        server
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    fn wait_until_ready(&mut self) {
        let client = readiness_client(self.port, &self.mode);
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if self
                .child
                .as_mut()
                .expect("redis-server child must exist while starting")
                .try_wait()
                .unwrap_or_else(|_| panic!("failed to inspect the redis-server child process"))
                .is_some()
            {
                panic!("redis-server exited before secure readiness");
            }
            let last_error_kind = match readiness_ping(&client) {
                Ok(()) => break,
                Err(error) => format!("{:?}", error.kind()),
            };
            if Instant::now() >= deadline {
                panic!(
                    "redis-server did not become ready for secure PING ({})",
                    last_error_kind
                );
            }
            thread::sleep(Duration::from_millis(20));
        }

        if let RedisServerMode::AclFallbackTrap { username, password } = &self.mode {
            configure_acl_user(self.port, username, password);
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn restart(&mut self) {
        self.stop();
        self.child = Some(spawn_child(self.port, self._directory.path(), &self.mode));
        self.wait_until_ready();
    }
}

impl Drop for RedisServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_child(port: u16, directory: &Path, mode: &RedisServerMode) -> Child {
    let mut command = Command::new("redis-server");
    command
        .args([
            "--bind",
            "127.0.0.1",
            "--protected-mode",
            "no",
            "--save",
            "",
            "--appendonly",
            "no",
            "--daemonize",
            "no",
        ])
        .arg("--dir")
        .arg(directory);
    match mode {
        RedisServerMode::Authenticated { password } => {
            command
                .arg("--port")
                .arg(port.to_string())
                .arg("--requirepass")
                .arg(password);
        }
        RedisServerMode::AclFallbackTrap { .. } => {
            command.arg("--port").arg(port.to_string());
        }
        RedisServerMode::Tls(config) => {
            command
                .args(["--port", "0", "--tls-port"])
                .arg(port.to_string())
                .arg("--tls-cert-file")
                .arg(&config.server_cert_file)
                .arg("--tls-key-file")
                .arg(&config.server_key_file)
                .arg("--tls-ca-cert-file")
                .arg(&config.ca_cert_file)
                .args(["--tls-auth-clients", "yes"]);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                panic!("redis-server prerequisite is missing from PATH");
            }
            panic!(
                "failed to spawn the redis-server prerequisite ({:?})",
                error.kind()
            );
        })
}

fn readiness_client(port: u16, mode: &RedisServerMode) -> redis::Client {
    match mode {
        RedisServerMode::Authenticated { password } => authenticated_client(port, password),
        RedisServerMode::AclFallbackTrap { .. } => anonymous_client(port),
        RedisServerMode::Tls(config) => redis::Client::build_with_tls(
            format!("rediss://127.0.0.1:{port}/0"),
            redis::TlsCertificates {
                client_tls: Some(redis::ClientTlsConfig {
                    client_cert: config.readiness_client_cert.clone(),
                    client_key: config.readiness_client_key.clone(),
                }),
                root_cert: Some(config.readiness_root_cert.clone()),
            },
        )
        .unwrap_or_else(|_| panic!("failed to build the TLS Redis readiness client")),
    }
}

fn anonymous_client(port: u16) -> redis::Client {
    redis::Client::open(format!("redis://127.0.0.1:{port}/0"))
        .unwrap_or_else(|_| panic!("failed to build the anonymous Redis probe client"))
}

fn configure_acl_user(port: u16, username: &str, password: &str) {
    let client = anonymous_client(port);
    let mut connection = client
        .get_connection_with_timeout(PROBE_TIMEOUT)
        .unwrap_or_else(|_| panic!("failed to connect while configuring the Redis ACL trap"));
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(username)
        .arg("reset")
        .arg("on")
        .arg(format!(">{password}"))
        .arg("~*")
        .arg("+@all")
        .query::<()>(&mut connection)
        .unwrap_or_else(|_| panic!("failed to configure the Redis ACL trap"));
}

fn authenticated_client(port: u16, password: &str) -> redis::Client {
    let mut url = Url::parse(&format!("redis://127.0.0.1:{port}/0"))
        .expect("the loopback Redis probe URL must be valid");
    url.set_username("default")
        .expect("the Redis probe username must be valid");
    url.set_password(Some(password))
        .expect("the Redis probe password must be valid");
    redis::Client::open(url.as_str())
        .unwrap_or_else(|_| panic!("failed to build the authenticated Redis readiness client"))
}

fn readiness_ping(client: &redis::Client) -> redis::RedisResult<()> {
    let mut connection = client.get_connection_with_timeout(PROBE_TIMEOUT)?;
    connection.set_read_timeout(Some(PROBE_TIMEOUT))?;
    connection.set_write_timeout(Some(PROBE_TIMEOUT))?;
    redis::cmd("PING")
        .query::<String>(&mut connection)
        .map(|_| ())
}
