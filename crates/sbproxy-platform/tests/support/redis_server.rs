use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use url::Url;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(100);

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

enum RedisServerMode {
    Authenticated { password: String },
    Tls(RedisTlsServerConfig),
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
                Ok(()) => return,
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
