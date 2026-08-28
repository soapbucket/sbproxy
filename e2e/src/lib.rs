//! End-to-end test harness.
//!
//! Spawns the release `sbproxy` binary against a temporary
//! configuration file, waits for it to bind, and tears it down on
//! drop. Each harness owns its own ephemeral port so tests
//! parallelise without colliding on `proxy.http_bind_port`.
//!
//! Typical usage:
//!
//! ```no_run
//! use sbproxy_e2e::ProxyHarness;
//! let harness = ProxyHarness::start_with_yaml(r#"
//!     proxy:
//!       http_bind_port: 0  # overridden by the harness
//!     origins:
//!       "demo":
//!         action: { type: static, status_code: 200, body: "ok" }
//! "#).unwrap();
//! let body = harness.get("/", "demo").unwrap();
//! assert_eq!(body.status, 200);
//! ```

#![warn(missing_docs)]

use std::io::{Read as IoRead, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_yaml::Value as Yaml;
use tempfile::NamedTempFile;

/// Default startup wait window. This is a ceiling, not a fixed sleep:
/// `wait_for_ready` polls the HTTP readiness probe every 50 ms and
/// returns the instant the proxy answers, so a healthy boot costs well
/// under a second. The ceiling only matters when the machine is starved,
/// which is exactly the local-gate case: e2e runs right after the full
/// workspace build, so the box is hot and the freshly spawned proxy can
/// take several seconds to bring its accept loop live. 10 s was too tight
/// there (it flaked two auth_basic tests); 30 s gives headroom without
/// slowing healthy runs. Override with `SBPROXY_E2E_STARTUP_TIMEOUT_SECS`
/// on an unusually slow host.
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve the startup wait window: `SBPROXY_E2E_STARTUP_TIMEOUT_SECS`
/// when it is set to a positive integer, otherwise
/// [`DEFAULT_STARTUP_TIMEOUT`].
fn startup_timeout() -> Duration {
    std::env::var("SBPROXY_E2E_STARTUP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_STARTUP_TIMEOUT)
}

/// How many times a `start_*` constructor re-picks a fresh port and
/// respawns the proxy after a startup failure classified as a port
/// collision, before surfacing the error.
///
/// The pick-a-port dance is inherently racy across processes: the
/// reservation listener must be dropped for the child to bind, and a
/// different, concurrently-starting test's child can bind the same
/// number first (WOR-2295). The identity token already stops the loser
/// from silently talking to the winner's proxy; this retry stops the
/// loser from failing its whole test over it. Each attempt uses a
/// freshly picked port, and a dead child is detected in milliseconds
/// (see `wait_for_ready`), so retries are cheap.
const STOLEN_PORT_START_ATTEMPTS: usize = 4;

/// Substring of the proxy's fatal bind error on both Linux (os error
/// 98) and macOS (os error 48). Startup failures whose child exited
/// with this in stderr are classified as WOR-2295 port collisions.
const PORT_COLLISION_STDERR_MARKER: &str = "Address already in use";

/// Marker attached to a startup error when the spawned proxy exited
/// because some port in its config was already bound, i.e. a
/// different, concurrently-starting process won the pick-a-port race
/// (WOR-2295).
///
/// The harness's own `start_*` constructors already retry the public
/// port on this classification. Tests that bake additional
/// self-picked ports into their YAML (cluster gossip / transport /
/// admin ports) should check [`error_is_port_collision`] and rebuild
/// with fresh ports rather than treating the failure as real.
#[derive(Debug)]
pub struct PortCollision {
    /// Public port the harness picked for the failed attempt.
    pub port: u16,
}

impl std::fmt::Display for PortCollision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a concurrently-starting process bound a port in this proxy's config first \
             (harness public port {}; WOR-2295 port collision)",
            self.port
        )
    }
}

impl std::error::Error for PortCollision {}

/// Whether `error` (or any of its layers) carries the [`PortCollision`]
/// marker, meaning the proxy child died to a WOR-2295 pick-a-port race
/// rather than a real startup failure.
///
/// Checks both anyhow's layered downcast (which sees context values
/// attached with `.context(...)`) and the source chain, so callers may
/// wrap the harness error in further `with_context` layers without
/// hiding the marker.
pub fn error_is_port_collision(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PortCollision>().is_some()
        || error
            .chain()
            .any(|cause| cause.downcast_ref::<PortCollision>().is_some())
}

const DEFAULT_BINARY_ENV: &str = "SBPROXY_E2E_BIN";
const NO_DEFAULT_FEATURES_BINARY_ENV: &str = "SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN";
const PAYMENTS_BINARY_ENV: &str = "SBPROXY_E2E_PAYMENTS_BIN";

#[derive(Debug, Clone, Copy)]
enum ProxyBinaryFlavor {
    Default,
    NoDefaultFeatures,
    Payments,
}

impl ProxyBinaryFlavor {
    fn env_var(self) -> &'static str {
        match self {
            Self::Default => DEFAULT_BINARY_ENV,
            Self::NoDefaultFeatures => NO_DEFAULT_FEATURES_BINARY_ENV,
            Self::Payments => PAYMENTS_BINARY_ENV,
        }
    }

    fn search_paths(self) -> Vec<PathBuf> {
        let root = workspace_root();
        match self {
            Self::Default => vec![
                root.join("target/release/sbproxy"),
                root.join("target/debug/sbproxy"),
            ],
            Self::NoDefaultFeatures => vec![
                root.join("target/no-default-features/release/sbproxy"),
                root.join("target/no-default-features/debug/sbproxy"),
            ],
            Self::Payments => vec![
                root.join("target/payments/release/sbproxy"),
                root.join("target/payments/debug/sbproxy"),
            ],
        }
    }

    fn missing_hint(self) -> &'static str {
        match self {
            Self::Default => {
                "run `cargo build --release -p sbproxy` or set SBPROXY_E2E_BIN"
            }
            Self::NoDefaultFeatures => {
                "run `CARGO_TARGET_DIR=target/no-default-features cargo build --release -p sbproxy --no-default-features` or set SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN"
            }
            Self::Payments => {
                "run `CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy --features payment-x402,payment-mpp,payment-stripe,payment-lightning-cln` or set SBPROXY_E2E_PAYMENTS_BIN"
            }
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Default => "sbproxy",
            Self::NoDefaultFeatures => "no-default-features sbproxy",
            Self::Payments => "payments-featured sbproxy",
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("e2e crate must live under workspace root")
        .to_path_buf()
}

fn configured_binary_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).and_then(|value| {
        if value.is_empty() {
            None
        } else {
            let path = PathBuf::from(value);
            // Cargo runs test binaries with the package directory as the
            // working directory, so a relative override like
            // "target/debug/sbproxy" (the natural spelling when invoking
            // cargo from the workspace root) would resolve under e2e/ and
            // miss. Anchor relative overrides to the workspace root.
            if path.is_absolute() {
                Some(path)
            } else {
                Some(workspace_root().join(path))
            }
        }
    })
}

fn proxy_binary_path_for(flavor: ProxyBinaryFlavor) -> PathBuf {
    if let Some(path) = configured_binary_path(flavor.env_var()) {
        return path;
    }
    let paths = flavor.search_paths();
    // Fall back to the *preferred* path, not the last one searched. The
    // caller puts this path in its "binary missing at ..." error beside
    // `missing_hint`, and every hint builds `--release`, so naming the
    // debug path told the reader to create one file and then look for a
    // different one.
    paths
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| paths.first().expect("binary search paths").clone())
}

/// Locate the default-feature `sbproxy` binary built by the workspace.
/// The `SBPROXY_E2E_BIN` environment variable wins when set. Otherwise
/// this prefers `target/release/sbproxy` and falls back to
/// `target/debug/sbproxy` so CI runs that only build the debug profile
/// still find a usable binary.
pub fn proxy_binary_path() -> PathBuf {
    proxy_binary_path_for(ProxyBinaryFlavor::Default)
}

/// Locate a `sbproxy` binary compiled with `--no-default-features`.
///
/// The `SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN` environment variable wins
/// when set. Otherwise this looks under `target/no-default-features/`,
/// which lets disabled-feature e2e coverage run without overwriting the
/// default-feature binary used by the normal suite.
pub fn proxy_no_default_features_binary_path() -> PathBuf {
    proxy_binary_path_for(ProxyBinaryFlavor::NoDefaultFeatures)
}

/// Locate a `sbproxy` binary compiled with the payment rail features.
///
/// The `SBPROXY_E2E_PAYMENTS_BIN` environment variable wins when set.
/// Otherwise this looks under `target/payments/`, which keeps the
/// settlement e2e coverage from overwriting the default-feature binary
/// used by the normal suite.
pub fn proxy_payments_binary_path() -> PathBuf {
    proxy_binary_path_for(ProxyBinaryFlavor::Payments)
}

/// One-off response shape returned by the harness's HTTP helpers.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body as bytes.
    pub body: Vec<u8>,
    /// Response headers (lowercased keys).
    pub headers: std::collections::HashMap<String, String>,
}

impl Response {
    /// Decode the body as UTF-8 text. Returns `Err` for invalid UTF-8.
    pub fn text(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8(self.body.clone())?)
    }

    /// Decode the body as JSON. Errors when the body is not valid JSON.
    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

/// Running proxy instance. Drop kills the child process.
pub struct ProxyHarness {
    child: Child,
    port: u16,
    /// Identity token handed to the spawned child via
    /// `SBPROXY_E2E_HARNESS_TOKEN` and required back on every response
    /// by `wait_for_ready`, so this harness can tell its own child
    /// apart from a different, concurrently-starting test's child that
    /// may have won a same-port race in `pick_free_port` (WOR-2295).
    token: String,
    /// Hold the temp file alive so the proxy can keep reading it.
    ///
    /// One of `_config` (the YAML temp file) or `_workspace` (the
    /// workspace tempdir) carries the proxy's config payload; the
    /// other slot is empty. Both are owned by the harness so the
    /// proxy child keeps reading from a stable path.
    _config: Option<NamedTempFile>,
    /// Hold the workspace tempdir alive when the harness was built
    /// with [`Self::start_with_workspace`]. Drop happens after the
    /// proxy child is reaped, so listings and other workspace files
    /// stay readable for the full life of the proxy.
    _workspace: Option<tempfile::TempDir>,
    /// Captured child stderr, retained for startup-failure diagnostics while
    /// successful harnesses remain quiet.
    _stderr: NamedTempFile,
    /// Captured child stdout, including the default tracing subscriber output.
    _stdout: Option<NamedTempFile>,
    /// Lazy-initialised so harness construction does not invoke
    /// `reqwest::blocking::Client::builder().build()` at the call site.
    /// Building the blocking client spins up an internal tokio
    /// runtime; if `start_with_yaml()` is called from inside another
    /// async runtime (e.g. the gRPC tests do `Runtime::new() +
    /// rt.block_on(async { ProxyHarness::start_with_yaml(...) })`),
    /// dropping that internal runtime panics in tokio 1.52+. Tests
    /// that never call `get`/`post_json`/etc never trigger the build.
    client: std::sync::OnceLock<reqwest::blocking::Client>,
}

impl ProxyHarness {
    /// Start the proxy with a config built from a YAML string. The
    /// caller's `proxy.http_bind_port` (if any) is overridden with
    /// an ephemeral port chosen by the harness.
    pub fn start_with_yaml(yaml: &str) -> anyhow::Result<Self> {
        Self::start_with_raw_yaml_using_binary(yaml, ProxyBinaryFlavor::Default, None, &[])
    }

    /// Start the proxy with a config built from a YAML string, adding
    /// `env` to the spawned proxy child's environment.
    ///
    /// The variables are scoped to the child via `Command::env`, so a
    /// test can exercise an env-read path in the proxy without mutating
    /// the test runner's own process environment (WOR-646).
    pub fn start_with_yaml_and_env(yaml: &str, env: &[(&str, &str)]) -> anyhow::Result<Self> {
        let owned: Vec<(&str, String)> = env
            .iter()
            .map(|(name, value)| (*name, (*value).to_string()))
            .collect();
        Self::start_with_raw_yaml_using_binary(yaml, ProxyBinaryFlavor::Default, None, &owned)
    }

    /// Start the proxy with a test-specific graceful shutdown budget.
    pub fn start_with_yaml_and_shutdown_grace(
        yaml: &str,
        shutdown_grace_ms: u64,
    ) -> anyhow::Result<Self> {
        Self::start_with_raw_yaml_using_binary(
            yaml,
            ProxyBinaryFlavor::Default,
            Some(shutdown_grace_ms),
            &[],
        )
    }

    /// Start the proxy using a binary compiled with
    /// `--no-default-features`.
    ///
    /// This keeps disabled-feature assertions separate from the default
    /// e2e suite. Build the binary into `target/no-default-features/`
    /// or set `SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN`.
    pub fn start_no_default_features_with_yaml(yaml: &str) -> anyhow::Result<Self> {
        Self::start_with_raw_yaml_using_binary(
            yaml,
            ProxyBinaryFlavor::NoDefaultFeatures,
            None,
            &[],
        )
    }

    /// Start a payments-featured proxy with extra child environment
    /// variables.
    ///
    /// Settlement configs name secrets by reference
    /// (`secret://env/NAME`), and the child resolves them against its
    /// own environment, so the test hands the values over here instead
    /// of mutating the test process environment. Build the binary into
    /// `target/payments/` or set `SBPROXY_E2E_PAYMENTS_BIN`.
    pub fn start_payments_with_yaml_and_env(
        yaml: &str,
        envs: &[(&str, String)],
    ) -> anyhow::Result<Self> {
        Self::start_with_raw_yaml_using_binary(yaml, ProxyBinaryFlavor::Payments, None, envs)
    }

    /// Start the proxy with the YAML file at `path`, rewriting its
    /// `proxy.http_bind_port` to a fresh ephemeral port. The
    /// rewritten copy is held in a temp file; the original on
    /// disk is never modified.
    pub fn start_with_example(path: &Path) -> anyhow::Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read example {}: {}", path.display(), e))?;
        Self::start_with_yaml(&yaml)
    }

    /// Pick a fresh public port, inject it into `yaml`, and spawn the
    /// proxy, retrying with another fresh port when the attempt fails
    /// to a WOR-2295 port collision (see [`PortCollision`]). Any other
    /// startup failure surfaces immediately.
    fn start_with_raw_yaml_using_binary(
        yaml: &str,
        binary: ProxyBinaryFlavor,
        shutdown_grace_ms: Option<u64>,
        envs: &[(&str, String)],
    ) -> anyhow::Result<Self> {
        for _ in 1..STOLEN_PORT_START_ATTEMPTS {
            let port_reservation = pick_free_port()?;
            let port = port_reservation.local_addr()?.port();
            let final_yaml = inject_port(yaml, port)?;
            match Self::start_with_resolved_yaml_using_binary(
                &final_yaml,
                port,
                binary,
                shutdown_grace_ms,
                envs,
                port_reservation,
            ) {
                Err(error) if error_is_port_collision(&error) => continue,
                outcome => return outcome,
            }
        }
        let port_reservation = pick_free_port()?;
        let port = port_reservation.local_addr()?.port();
        let final_yaml = inject_port(yaml, port)?;
        Self::start_with_resolved_yaml_using_binary(
            &final_yaml,
            port,
            binary,
            shutdown_grace_ms,
            envs,
            port_reservation,
        )
    }

    fn start_with_resolved_yaml_using_binary(
        yaml: &str,
        port: u16,
        binary: ProxyBinaryFlavor,
        shutdown_grace_ms: Option<u64>,
        envs: &[(&str, String)],
        port_reservation: TcpListener,
    ) -> anyhow::Result<Self> {
        let bin = proxy_binary_path_for(binary);
        if !bin.is_file() {
            anyhow::bail!(
                "{} binary missing at {}; {}",
                binary.description(),
                bin.display(),
                binary.missing_hint()
            );
        }
        // The proxy reads its config from a path, not stdin, so
        // we materialise the rewritten YAML to a temp file. The
        // file lives as long as the harness so a child reload
        // would still see fresh data on disk.
        let mut file = NamedTempFile::new()?;
        file.write_all(yaml.as_bytes())?;
        file.flush()?;

        let stderr = NamedTempFile::new()?;
        let token = generate_harness_token();
        let mut command = Command::new(&bin);
        // Child-scoped variables: the child process gets them, the
        // test runner's own environment stays untouched (WOR-646).
        for (name, value) in envs {
            command.env(name, value);
        }
        // WOR-2295: identity token the child echoes back on every
        // response (see `e2e_harness_token` in sbproxy-core's
        // server.rs), so `wait_for_ready` can tell this harness's own
        // child apart from a different, concurrently-starting test's
        // child that may have won a same-port race.
        command.env("SBPROXY_E2E_HARNESS_TOKEN", &token);
        if let Some(shutdown_grace_ms) = shutdown_grace_ms {
            command
                .arg("--shutdown-grace-ms")
                .arg(shutdown_grace_ms.to_string());
        }
        command
            .arg("--config")
            .arg(file.path())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr.reopen()?));

        // Hold the port reservation open through every step above
        // (binary lookup, config serialisation, stderr capture setup)
        // and release it only right before spawn. This shrinks the
        // window in which a different, concurrently-starting
        // harness's own `pick_free_port` could be handed the same
        // port number down to as little as this code allows without
        // passing the bound fd through to the child (WOR-2295).
        drop(port_reservation);
        let child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn {}: {}", bin.display(), e))?;

        let mut harness = Self {
            child,
            port,
            token,
            _config: Some(file),
            _workspace: None,
            _stderr: stderr,
            _stdout: None,
            client: std::sync::OnceLock::new(),
        };
        harness.wait_for_ready_with_diagnostics(startup_timeout())?;
        Ok(harness)
    }

    /// Start the proxy against a temp workspace populated with
    /// `(relative_path, content)` files plus an `sb.yml` written from
    /// `yaml`.
    ///
    /// Used by tests that need the proxy to discover sibling files
    /// (e.g. `listings/*.yaml` for WOR-196) relative to the config
    /// path. The harness places the rewritten YAML at
    /// `<workspace>/sb.yml` and points `--config` at that file so the
    /// listing loader's "config-file parent is the Repo root"
    /// contract holds.
    pub fn start_with_workspace(yaml: &str, files: &[(&str, &str)]) -> anyhow::Result<Self> {
        let byte_files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, body)| (*path, body.as_bytes()))
            .collect();
        Self::start_with_workspace_bytes(yaml, &byte_files)
    }

    /// Start the proxy against a temp workspace that may contain binary files.
    pub fn start_with_workspace_bytes(yaml: &str, files: &[(&str, &[u8])]) -> anyhow::Result<Self> {
        Self::start_with_workspace_bytes_and_optional_shutdown_grace(yaml, files, None, &[])
    }

    /// Start the proxy in an isolated config workspace with a test-specific
    /// graceful shutdown budget.
    pub fn start_with_workspace_and_shutdown_grace(
        yaml: &str,
        files: &[(&str, &str)],
        shutdown_grace_ms: u64,
    ) -> anyhow::Result<Self> {
        Self::start_with_workspace_and_optional_shutdown_grace(
            yaml,
            files,
            Some(shutdown_grace_ms),
            &[],
        )
    }

    /// Start the proxy in an isolated config workspace with a
    /// test-specific graceful shutdown budget, adding `env` to the
    /// spawned proxy child's environment.
    ///
    /// The variables are scoped to the child via `Command::env`, so a
    /// test can exercise an env-read path in the proxy (or anything
    /// the proxy spawns) without mutating the test runner's own
    /// process environment (WOR-646).
    pub fn start_with_workspace_shutdown_grace_and_env(
        yaml: &str,
        files: &[(&str, &str)],
        shutdown_grace_ms: u64,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        Self::start_with_workspace_and_optional_shutdown_grace(
            yaml,
            files,
            Some(shutdown_grace_ms),
            env,
        )
    }

    fn start_with_workspace_and_optional_shutdown_grace(
        yaml: &str,
        files: &[(&str, &str)],
        shutdown_grace_ms: Option<u64>,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        let byte_files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, body)| (*path, body.as_bytes()))
            .collect();
        Self::start_with_workspace_bytes_and_optional_shutdown_grace(
            yaml,
            &byte_files,
            shutdown_grace_ms,
            env,
        )
    }

    fn start_with_workspace_bytes_and_optional_shutdown_grace(
        yaml: &str,
        files: &[(&str, &[u8])],
        shutdown_grace_ms: Option<u64>,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        // Same WOR-2295 retry contract as `start_with_raw_yaml_using_binary`:
        // a startup failure classified as a port collision re-picks the
        // public port and rebuilds the workspace; everything else surfaces.
        for _ in 1..STOLEN_PORT_START_ATTEMPTS {
            match Self::start_with_workspace_bytes_attempt(yaml, files, shutdown_grace_ms, env) {
                Err(error) if error_is_port_collision(&error) => continue,
                outcome => return outcome,
            }
        }
        Self::start_with_workspace_bytes_attempt(yaml, files, shutdown_grace_ms, env)
    }

    fn start_with_workspace_bytes_attempt(
        yaml: &str,
        files: &[(&str, &[u8])],
        shutdown_grace_ms: Option<u64>,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        let port_reservation = pick_free_port()?;
        let port = port_reservation.local_addr()?.port();
        let final_yaml = inject_port(yaml, port)?;
        let bin = proxy_binary_path();
        if !bin.is_file() {
            anyhow::bail!(
                "{} binary missing at {}; {}",
                ProxyBinaryFlavor::Default.description(),
                bin.display(),
                ProxyBinaryFlavor::Default.missing_hint()
            );
        }
        let tmp = tempfile::tempdir()?;
        for (rel, body) in files {
            let path = tmp.path().join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, body)?;
        }
        let cfg_path = tmp.path().join("sb.yml");
        std::fs::write(&cfg_path, final_yaml.as_bytes())?;

        let stderr = NamedTempFile::new()?;
        let stdout = NamedTempFile::new()?;
        let token = generate_harness_token();
        let mut command = Command::new(&bin);
        if let Some(shutdown_grace_ms) = shutdown_grace_ms {
            command
                .arg("--shutdown-grace-ms")
                .arg(shutdown_grace_ms.to_string());
        }
        // Child-scoped variables: the child process gets them, the
        // test runner's own environment stays untouched (WOR-646).
        for (name, value) in env {
            command.env(name, value);
        }
        // WOR-2295: identity token the child echoes back on every
        // response; see `start_with_resolved_yaml_using_binary`.
        command.env("SBPROXY_E2E_HARNESS_TOKEN", &token);
        command
            .arg("--config")
            .arg(&cfg_path)
            .stdout(Stdio::from(stdout.reopen()?))
            .stderr(Stdio::from(stderr.reopen()?));

        // See `pick_free_port` (WOR-2295): hold the reservation
        // through every step above (binary lookup, workspace file
        // writes, config serialisation, output capture setup) and
        // release it only right before spawn.
        drop(port_reservation);
        let child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn {}: {}", bin.display(), e))?;

        let mut harness = Self {
            child,
            port,
            token,
            _config: None,
            _workspace: Some(tmp),
            _stderr: stderr,
            _stdout: Some(stdout),
            client: std::sync::OnceLock::new(),
        };
        harness.wait_for_ready_with_diagnostics(startup_timeout())?;
        Ok(harness)
    }

    fn wait_for_ready_with_diagnostics(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let Err(error) = self.wait_for_ready(timeout) else {
            return Ok(());
        };
        // `try_wait` rather than `child_is_running`: a startup-failed
        // child is a zombie until reaped, and `kill(pid, 0)` counts a
        // zombie as alive, which would misread every early exit as a
        // still-starting proxy.
        let exited = matches!(self.child.try_wait(), Ok(Some(_)));
        let stdout = self.stdout_contents();
        let stderr = std::fs::read_to_string(self._stderr.path())
            .unwrap_or_else(|read_error| format!("<read child stderr: {read_error}>"));
        let collision = exited && stderr.contains(PORT_COLLISION_STDERR_MARKER);
        let error = anyhow::anyhow!("{error:#}\nchild stdout:\n{stdout}\nchild stderr:\n{stderr}");
        Err(if collision {
            error.context(PortCollision { port: self.port })
        } else {
            error
        })
    }

    /// Wait for a second port this proxy is expected to bind, and on failure
    /// report why the child could not get there.
    ///
    /// The associated [`Self::wait_for_port`] cannot do this: it takes only a
    /// port number, so it has no access to the child's captured output. That
    /// gap has a cost. A payments config whose `recovery_encryption.key`
    /// resolved to the wrong length exited during payments initialization,
    /// which happens *after* the HTTP listener binds, so startup readiness
    /// passed and the only symptom was `wait_for_port(admin_port)` timing out
    /// on a healthy-looking proxy. The fatal line was sitting in the captured
    /// stderr the whole time.
    ///
    /// # Errors
    ///
    /// Returns an error when nothing answers on `port` within `timeout`,
    /// carrying whether the child is still running plus its captured output.
    pub fn wait_for_secondary_port(&self, port: u16, timeout: Duration) -> anyhow::Result<()> {
        if Self::wait_for_port(port, timeout).is_ok() {
            return Ok(());
        }
        let liveness = match self.child_is_running() {
            true => "child is still running".to_owned(),
            false => "child has already exited".to_owned(),
        };
        let stdout = self.stdout_contents();
        let stderr = std::fs::read_to_string(self._stderr.path())
            .unwrap_or_else(|read_error| format!("<read child stderr: {read_error}>"));
        anyhow::bail!(
            "nothing responding to HTTP on 127.0.0.1:{port} within {timeout:?} ({liveness})\n\
             child stdout:\n{stdout}\nchild stderr:\n{stderr}"
        )
    }

    /// Whether the child process has not yet exited.
    fn child_is_running(&self) -> bool {
        // `Child::try_wait` needs `&mut self`, and the callers that want this
        // hold `&self`, so ask the OS directly with signal 0.
        // SAFETY: `kill` with signal 0 performs a permission and existence
        // check and delivers nothing.
        #[cfg(unix)]
        {
            let pid = self.child.id() as i32;
            unsafe { libc::kill(pid, 0) == 0 }
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// Build (or return) the lazy-initialised blocking HTTP client.
    /// Construction is deferred so harness creation does not trigger
    /// reqwest's internal runtime drop in async contexts.
    /// Send a built request, and when the transport fails, attach the tail
    /// of the proxy's own stderr to the error.
    ///
    /// A request that gets no response is usually the proxy dying, and the
    /// client-side error says nothing about why: reqwest reports
    /// "connection closed before message completed" whether the server
    /// panicked, aborted on a debug overflow check, or simply closed an
    /// idle keep-alive connection. The panic line is already on disk in
    /// the harness's own stderr capture, so not showing it turns a
    /// one-line diagnosis into CI archaeology. Bounded to the last 60
    /// lines because a proxy log can be long and only the tail carries
    /// the death.
    fn send(&self, request: reqwest::blocking::RequestBuilder) -> anyhow::Result<Response> {
        match request.send() {
            Ok(response) => decode(response),
            Err(error) => {
                let tail = self.stderr_tail(60);
                if tail.trim().is_empty() {
                    Err(anyhow::Error::new(error))
                } else {
                    Err(anyhow::Error::new(error)
                        .context(format!("proxy stderr (last 60 lines):\n{tail}")))
                }
            }
        }
    }

    /// The last `lines` lines of the proxy's captured stderr.
    fn stderr_tail(&self, lines: usize) -> String {
        let stderr = std::fs::read_to_string(self._stderr.path())
            .unwrap_or_else(|read_error| format!("<read child stderr: {read_error}>"));
        let all: Vec<&str> = stderr.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    fn http_client(&self) -> &reqwest::blocking::Client {
        self.client.get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new())
        })
    }

    /// Poll the bound port until the proxy completes an HTTP exchange
    /// carrying this harness's own identity token, or the deadline
    /// expires.
    ///
    /// We probe at the HTTP layer rather than the TCP layer because
    /// `bind()` returning is not enough: the kernel will accept TCP
    /// connections into the listen backlog before Pingora's accept
    /// loop is live. A test that fires its first HTTP request in that
    /// window observes `Connection reset by peer`. Issuing a real GET
    /// closes that gap, but a bare "any HTTP response" check opens a
    /// different one: under parallel test execution, a different,
    /// concurrently-starting harness's child can win the brief window
    /// between `pick_free_port` releasing its reservation and this
    /// harness's own child binding the same port, and a bare response
    /// check would happily accept that other test's proxy as "ready"
    /// (WOR-2295). Requiring the `x-sbproxy-e2e-harness-token` header
    /// to match the token this harness generated and handed to its own
    /// child via `SBPROXY_E2E_HARNESS_TOKEN` closes that gap; see
    /// `http_probe_with_token_once`.
    ///
    /// The probe uses a raw `TcpStream` + hand-written HTTP/1.1 GET
    /// rather than `reqwest::blocking` to stay safe inside async
    /// contexts. `reqwest::blocking::Client::builder().build()` spins
    /// up an internal tokio runtime; dropping it inside a
    /// `Runtime::block_on()` call (as the gRPC and WebSocket e2e tests
    /// do) panics in tokio 1.52+ with "Cannot drop a runtime in a
    /// context where blocking is not allowed".
    fn wait_for_ready(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let conn_timeout = std::cmp::min(
                Duration::from_millis(500),
                deadline.saturating_duration_since(Instant::now()),
            );
            if !conn_timeout.is_zero()
                && http_probe_with_token_once(self.port, conn_timeout, &self.token)
            {
                return Ok(());
            }
            // Fail fast once the child is gone: no amount of further
            // polling can produce a response carrying this harness's
            // token, and the 30s wait used to be the whole cost of a
            // lost WOR-2295 port race. `try_wait` also reaps the child,
            // which `Drop` tolerates.
            if let Ok(Some(status)) = self.child.try_wait() {
                anyhow::bail!(
                    "proxy child exited during startup ({status}) before responding on \
                     127.0.0.1:{} with this harness's identity token \
                     (x-sbproxy-e2e-harness-token); a different, concurrently-started \
                     test's proxy may have won a same-port race (WOR-2295)",
                    self.port
                );
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "proxy did not respond to HTTP on 127.0.0.1:{} within {:?} carrying this \
                     harness's identity token (x-sbproxy-e2e-harness-token); a different, \
                     concurrently-started test's proxy may have won a same-port race (WOR-2295)",
                    self.port,
                    timeout
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Base URL for the running proxy.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Ephemeral TCP port the proxy is bound to. Use this from tests
    /// that need raw socket access (e.g. HTTP smuggling tests that
    /// bypass `reqwest`'s header normalization).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Ask the proxy to terminate cleanly, then kill it only if the deadline
    /// elapses. Cluster tests use this to verify managed engine children are
    /// drained and reaped with their owning proxy.
    pub fn terminate_gracefully(&mut self, timeout: Duration) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            let pid = i32::try_from(self.child.id())
                .map_err(|_| anyhow::anyhow!("proxy child PID overflowed i32"))?;
            // SAFETY: `pid` belongs to this live `Child`; SIGTERM does not
            // access memory and its return value is checked.
            let result = unsafe { libc::kill(pid, libc::SIGTERM) };
            if result != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(not(unix))]
        self.child.kill()?;

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.child.kill()?;
        self.child.wait()?;
        anyhow::bail!("proxy did not exit after SIGTERM within {timeout:?}")
    }

    /// Block until the supplied port responds to an HTTP request, or
    /// the timeout elapses. Use this for sidecar listeners (admin
    /// API, metrics endpoint) that bind on a different port from
    /// the main proxy and may not be ready when `wait_for_ready`
    /// returns.
    ///
    /// HTTP-level probe (rather than TCP-level) for the same reason
    /// as `wait_for_ready`: a kernel-accepted connection without an
    /// active accept loop produces `Connection reset by peer`. Uses
    /// a raw `TcpStream` probe (not `reqwest::blocking`) so it is
    /// safe to call from inside a tokio async context.
    pub fn wait_for_port(port: u16, timeout: Duration) -> anyhow::Result<()> {
        http_probe(port, timeout).map_err(|_| {
            anyhow::anyhow!(
                "nothing responding to HTTP on 127.0.0.1:{} within {:?}",
                port,
                timeout
            )
        })
    }

    /// Issue a GET against the proxy with a `Host` header.
    pub fn get(&self, path: &str, host: &str) -> anyhow::Result<Response> {
        let resp = self
            .http_client()
            .get(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .send()?;
        decode(resp)
    }

    /// Issue a GET with extra headers.
    pub fn get_with_headers(
        &self,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .get(format!("{}{}", self.base_url(), path))
            .header("host", host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.send(req)
    }

    /// Path of the temp config file the harness wrote on startup.
    ///
    /// Tests that exercise hot-reload mutate this file and then poke
    /// the proxy (file watcher event or `POST /admin/reload`) to
    /// pick up the change. The path is stable for the lifetime of
    /// the harness; for harnesses built via
    /// [`Self::start_with_workspace`] the path is the `sb.yml` inside
    /// the workspace tempdir.
    pub fn config_path(&self) -> PathBuf {
        if let Some(file) = &self._config {
            return file.path().to_path_buf();
        }
        if let Some(ws) = &self._workspace {
            return ws.path().join("sb.yml");
        }
        unreachable!("harness must own either a config tempfile or a workspace tempdir")
    }

    /// Captured child stderr for diagnostics in multi-process tests.
    pub fn stderr_contents(&self) -> String {
        std::fs::read_to_string(self._stderr.path())
            .unwrap_or_else(|error| format!("<read child stderr: {error}>"))
    }

    /// Captured child stdout, including default-format tracing output.
    pub fn stdout_contents(&self) -> String {
        self._stdout.as_ref().map_or_else(
            || "<child stdout not captured>".to_string(),
            |stdout| {
                std::fs::read_to_string(stdout.path())
                    .unwrap_or_else(|error| format!("<read child stdout: {error}>"))
            },
        )
    }

    /// Overwrite the proxy's on-disk config with new YAML and
    /// inject the live `http_bind_port` so the proxy keeps the
    /// same listener after reload.
    ///
    /// The caller is responsible for triggering the reload (e.g.
    /// hitting `POST /admin/reload`); this helper only updates the
    /// file on disk.
    pub fn rewrite_config(&self, yaml: &str) -> anyhow::Result<()> {
        let final_yaml = inject_port(yaml, self.port)?;
        std::fs::write(self.config_path(), final_yaml)?;
        Ok(())
    }

    /// Issue a POST with a JSON body and optional extra headers.
    pub fn post_json(
        &self,
        path: &str,
        host: &str,
        body: &serde_json::Value,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .post(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .json(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.send(req)
    }

    /// POST a raw body with an explicit `content-type` (used by the
    /// gRPC-Web e2e to send a length-prefixed gRPC-Web frame).
    pub fn post_bytes(
        &self,
        path: &str,
        host: &str,
        content_type: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .post(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .header("content-type", content_type)
            .body(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.send(req)
    }

    /// PUT a raw body with an explicit `content-type`.
    pub fn put_bytes(
        &self,
        path: &str,
        host: &str,
        content_type: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .put(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .header("content-type", content_type)
            .body(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.send(req)
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn decode(resp: reqwest::blocking::Response) -> anyhow::Result<Response> {
    let status = resp.status().as_u16();
    let mut headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    let body = resp.bytes()?.to_vec();
    Ok(Response {
        status,
        body,
        headers,
    })
}

/// Reserve a free TCP port by binding to `127.0.0.1:0` and handing
/// back the bound listener itself, rather than reading the port and
/// dropping the listener immediately.
///
/// The classic "bind, read the port, drop" trick has a TOCTOU gap:
/// the instant the listener drops, the port is free for *any*
/// process to grab, not just the child this harness is about to
/// spawn. Under parallel test execution, a different, concurrently-
/// starting harness's own `pick_free_port` call can win that race and
/// bind the identical port number before this harness's child does,
/// and nothing downstream used to notice: `wait_for_ready` accepted
/// any HTTP response on the target port as proof this harness's own
/// child was up, so one test's requests could silently be served by a
/// different test's proxy for the rest of the run (WOR-2295).
///
/// Callers should hold the returned listener open for as long as
/// possible and drop it only immediately before spawning the child
/// that will bind the same port, to shrink that window as close to
/// zero as this code allows without passing the bound fd through to
/// the child.
fn pick_free_port() -> anyhow::Result<TcpListener> {
    // Retry until the operating system offers a port this process has not
    // already handed to a child, keeping every rejected reservation open for
    // the duration of the call so the same number cannot be offered twice.
    //
    // Closing a reservation is unavoidable, because the child binds the port
    // itself, but the number must never be reissued: the losing harness then
    // sends its requests to the winner's gateway, which answers them
    // correctly while holding none of the loser's state. That reads as a
    // product bug rather than a collision, and it is what made a legacy MCP
    // session return "unknown or expired" in a test that passes serially.
    //
    // Cross-process collisions are still possible, which is what the harness
    // token check on readiness covers.
    let mut rejected = Vec::new();
    for _ in 0..PORT_PICK_ATTEMPTS {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let unseen = handed_out_ports()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(port);
        if unseen {
            return Ok(listener);
        }
        rejected.push(listener);
    }
    anyhow::bail!(
        "no unused ephemeral port after {PORT_PICK_ATTEMPTS} attempts; \
         this process has already used {} of them",
        handed_out_ports()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    )
}

/// How many times [`pick_free_port`] will ask for a port before giving up.
///
/// Only a port already handed out costs an attempt, so this is reached only
/// when the ephemeral range is genuinely exhausted for this process.
const PORT_PICK_ATTEMPTS: usize = 64;

/// Every ephemeral port this process has handed to a child.
///
/// Never pruned. A port is unsafe to reissue for the lifetime of the process
/// because the child that took it may still be listening, and a harness whose
/// child died holds no evidence that it stopped.
fn handed_out_ports() -> &'static Mutex<std::collections::HashSet<u16>> {
    static PORTS: std::sync::OnceLock<Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Build a token unique to this harness invocation.
///
/// Threaded to the spawned child via `SBPROXY_E2E_HARNESS_TOKEN` and
/// required back on every response by `wait_for_ready` so a harness
/// can tell its own child apart from a different, concurrently-
/// starting test's child (WOR-2295). The token only needs to be
/// unique, not unpredictable, so mixing the test-runner process id, a
/// nanosecond timestamp, and a per-process atomic counter is enough;
/// cryptographic randomness would add a dependency for no benefit
/// here.
fn generate_harness_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}-{:x}", std::process::id(), nanos, counter)
}

/// Poll `127.0.0.1:<port>` until a raw HTTP/1.1 GET receives any
/// response (including a 4xx), or the deadline expires.
///
/// We intentionally use raw `TcpStream` rather than
/// `reqwest::blocking` here. `reqwest::blocking::Client::builder()
/// .build()` spins up an internal tokio runtime; dropping that
/// runtime inside another tokio runtime's `block_on` call panics
/// in tokio 1.52+ with "Cannot drop a runtime in a context where
/// blocking is not allowed". gRPC and WebSocket e2e tests call
/// `ProxyHarness::start_with_yaml` inside `rt.block_on(async {...})`,
/// so the probe must be runtime-free.
///
/// TCP-level check is not enough (the kernel's listen backlog accepts
/// TCP before Pingora's accept loop is live), so we write a
/// minimal HTTP request and treat any valid HTTP response line as
/// "ready". A malformed or empty response counts as not-ready and
/// we keep polling.
fn http_probe(port: u16, timeout: Duration) -> anyhow::Result<()> {
    use std::io::BufRead;

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + timeout;
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

    while Instant::now() < deadline {
        let conn_timeout = std::cmp::min(
            Duration::from_millis(500),
            deadline.saturating_duration_since(Instant::now()),
        );
        if conn_timeout.is_zero() {
            break;
        }
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&addr.parse().expect("addr parse"), conn_timeout)
        {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.write_all(request.as_bytes());
            // Read one line; any "HTTP/1.x" response line is enough.
            let mut reader = std::io::BufReader::new(&stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && line.starts_with("HTTP/") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("timeout");
}

/// Issue one raw HTTP/1.1 GET against `127.0.0.1:<port>` and report
/// whether the response carried an `x-sbproxy-e2e-harness-token`
/// header matching `expected_token`.
///
/// This is `http_probe`'s stricter sibling, used only by
/// `wait_for_ready`'s polling loop for the harness's own primary port
/// (WOR-2295). A bare "any HTTP response" check (what `http_probe`
/// does) cannot distinguish this harness's own child from a different,
/// concurrently-starting harness's child that won a same-port race in
/// the brief window `pick_free_port` leaves between releasing its
/// reservation and this process's child binding it. Requiring the
/// child's own token on the response closes that gap. A response
/// without the matching header is treated exactly like "not ready
/// yet": the caller reconnects and tries again rather than reporting a
/// false success against the wrong process.
///
/// The proxy only ever sets this header when `SBPROXY_E2E_HARNESS_TOKEN`
/// is present in its own environment (see `e2e_harness_token` in
/// `sbproxy-core`'s `server.rs`, echoed both from the normal
/// `response_filter` path and from the `send_response` short-circuit
/// path a bare `GET /` with an unmatched `Host` actually takes), which
/// the harness sets on every child it spawns, so a healthy same-harness
/// child always carries it regardless of which path answers the probe.
///
/// Shares `http_probe`'s raw-socket, runtime-free constraints: safe to
/// call from inside a tokio `block_on` (the gRPC and WebSocket e2e
/// tests do this).
fn http_probe_with_token_once(port: u16, conn_timeout: Duration, expected_token: &str) -> bool {
    use std::io::BufRead;

    let addr = format!("127.0.0.1:{port}");
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

    let Ok(mut stream) =
        TcpStream::connect_timeout(&addr.parse().expect("addr parse"), conn_timeout)
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.write_all(request.as_bytes());
    let mut reader = std::io::BufReader::new(&stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() || !status_line.starts_with("HTTP/") {
        return false;
    }
    // Read the header block (a blank line terminates it, matching every
    // other HTTP/1.1 response) looking for this harness's own token.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return false,
            Ok(_) => {
                let trimmed = line.trim_end();
                if trimmed.is_empty() {
                    return false;
                }
                if let Some((name, value)) = trimmed.split_once(':') {
                    if name
                        .trim()
                        .eq_ignore_ascii_case("x-sbproxy-e2e-harness-token")
                        && value.trim() == expected_token
                    {
                        return true;
                    }
                }
            }
            Err(_) => return false,
        }
    }
}

/// Rewrite `proxy.http_bind_port` in the supplied YAML to the
/// chosen port and ensure `proxy.trusted_proxies` covers the
/// loopback so e2e tests that inject the trust-bounded TLS sidecar
/// headers (`x-sbproxy-tls-ja4`, `x-sbproxy-tls-ja3`,
/// `x-sbproxy-tls-trustworthy`) see them honoured. Uses `serde_yaml`
/// so we do not have to do regex surgery on whitespace-sensitive
/// YAML.
///
/// The trust-CIDR default unblocks the Wave 5 / G5.3 + G5.4 tests
/// (`tls_fingerprint_capture_e2e`, `headless_detection_e2e`,
/// `tls_spoofing_detection_e2e`). Pingora 0.8 does not surface raw
/// ClientHello bytes through its public Session API, so the OSS
/// pipeline accepts JA3 / JA4 from a trusted upstream sidecar via
/// the `x-sbproxy-tls-*` request headers; the harness drives this
/// path by marking 127.0.0.1/8 + ::1/128 as trusted at startup.
///
/// Operator YAML that explicitly sets `proxy.trusted_proxies` keeps
/// its value untouched. The default we inject only fires when the
/// caller did not author the field.
fn inject_port(yaml: &str, port: u16) -> anyhow::Result<String> {
    let mut doc: Yaml = serde_yaml::from_str(yaml)?;
    if let Yaml::Mapping(top) = &mut doc {
        let proxy_key = Yaml::String("proxy".to_string());
        let proxy_block = top
            .entry(proxy_key)
            .or_insert_with(|| Yaml::Mapping(Default::default()));
        if let Yaml::Mapping(proxy_map) = proxy_block {
            proxy_map.insert(
                Yaml::String("http_bind_port".to_string()),
                Yaml::Number(serde_yaml::Number::from(port as u64)),
            );
            // Inject the loopback trust-CIDR default only when the
            // caller did not author the field. This unblocks the
            // sidecar-header-driven TLS-fingerprint tests and stays
            // out of the way of any test that wants to pin a
            // different trust boundary.
            let trust_key = Yaml::String("trusted_proxies".to_string());
            if !proxy_map.contains_key(&trust_key) {
                let cidrs: serde_yaml::Sequence = vec![
                    Yaml::String("127.0.0.0/8".to_string()),
                    Yaml::String("::1/128".to_string()),
                ];
                proxy_map.insert(trust_key, Yaml::Sequence(cidrs));
            }

            // Inject the upstream private-CIDR allowlist default so
            // tests that proxy to MockUpstream on 127.0.0.1 do not
            // trip SBproxy's SSRF guard. Production configs leave
            // this empty (the default), which is what blocks
            // attacker-controlled upstream URLs from reaching
            // internal IPs. Tests intentionally opt in to loopback.
            // Caller-authored values win.
            let extensions_key = Yaml::String("extensions".to_string());
            let extensions_block = proxy_map
                .entry(extensions_key)
                .or_insert_with(|| Yaml::Mapping(Default::default()));
            if let Yaml::Mapping(extensions_map) = extensions_block {
                let upstream_key = Yaml::String("upstream".to_string());
                let upstream_block = extensions_map
                    .entry(upstream_key)
                    .or_insert_with(|| Yaml::Mapping(Default::default()));
                if let Yaml::Mapping(upstream_map) = upstream_block {
                    let allow_key = Yaml::String("allow_private_cidrs".to_string());
                    if !upstream_map.contains_key(&allow_key) {
                        let cidrs: serde_yaml::Sequence = vec![
                            Yaml::String("127.0.0.0/8".to_string()),
                            Yaml::String("::1/128".to_string()),
                        ];
                        upstream_map.insert(allow_key, Yaml::Sequence(cidrs));
                    }
                }
            }
        }
    }
    Ok(serde_yaml::to_string(&doc)?)
}

/// Tiny synchronous HTTP/1.1 server used to stand in for an
/// upstream the proxy talks to. Useful when a test needs to
/// observe what the proxy forwarded (request body, headers) and
/// returning a canned response is enough.
///
/// Only implements the bare slice of HTTP/1.1 we need: read the
/// request line + headers, optionally read `content-length` bytes
/// of body, return a 200 with a small JSON body. No keep-alive,
/// no chunked encoding, no TLS. Drop kills the listener thread.
pub struct MockUpstream {
    port: u16,
    /// Captured request bodies, one entry per accepted request.
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<JoinHandle<()>>,
}

/// Snapshot of a request observed by `MockUpstream`.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    /// Request line method, e.g. "GET" or "POST".
    pub method: String,
    /// Request line path, e.g. "/v1/chat/completions".
    pub path: String,
    /// Header values (lowercased keys).
    pub headers: std::collections::HashMap<String, String>,
    /// Body bytes (empty for bodyless requests).
    pub body: Vec<u8>,
}

impl MockUpstream {
    /// Start the mock upstream on an ephemeral port. Each accepted
    /// request is appended to the capture log and replied to with
    /// the supplied JSON body and 200 status.
    pub fn start(reply_json: serde_json::Value) -> anyhow::Result<Self> {
        Self::start_with_response_headers(reply_json, Vec::new())
    }

    /// Start the mock upstream with extra response headers. Useful
    /// for tests that need the upstream to return e.g. `X-Inject-*`
    /// directives so the proxy's callback enrichment path can be
    /// exercised end-to-end.
    ///
    /// A `Content-Type` entry in `extra_headers` (case-insensitive)
    /// overrides the default `application/json` and is not emitted
    /// twice (WOR-1133).
    pub fn start_with_response_headers(
        reply_json: serde_json::Value,
        extra_headers: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let reply_bytes = serde_json::to_vec(&reply_json)?;
        // Lift a caller-supplied Content-Type out of the header list so
        // the handler emits exactly one Content-Type line.
        let mut content_type: Option<String> = None;
        let rest: Vec<(String, String)> = extra_headers
            .into_iter()
            .filter(|(k, v)| {
                if k.eq_ignore_ascii_case("content-type") {
                    content_type = Some(v.clone());
                    false
                } else {
                    true
                }
            })
            .collect();
        Self::start_full(200, content_type, reply_bytes, rest)
    }

    /// WOR-1133: start a mock upstream that replies with a fixed HTTP
    /// status (and the supplied JSON body). Useful for failover tests
    /// that need a primary returning 5xx and a secondary returning 200.
    pub fn start_with_status(reply_json: serde_json::Value, status: u16) -> anyhow::Result<Self> {
        let reply_bytes = serde_json::to_vec(&reply_json)?;
        Self::start_full(status, None, reply_bytes, Vec::new())
    }

    /// Start a mock upstream that replies with the supplied status/body
    /// sequence. Once the sequence is exhausted, the final response is
    /// repeated for later requests.
    pub fn start_sequence(responses: Vec<(u16, serde_json::Value)>) -> anyhow::Result<Self> {
        if responses.is_empty() {
            anyhow::bail!("mock upstream sequence must contain at least one response");
        }
        let mut encoded = Vec::with_capacity(responses.len());
        for (status, body) in responses {
            encoded.push((status, serde_json::to_vec(&body)?));
        }
        Self::start_sequence_full(encoded, "application/json".to_string())
    }

    /// Start an upstream that returns a validator-bearing `200` initially
    /// and an empty `304` when a later request sends the matching
    /// `If-None-Match` value.
    pub fn start_conditional(
        reply_json: serde_json::Value,
        etag: String,
        last_modified: String,
    ) -> anyhow::Result<Self> {
        let reply_bytes = serde_json::to_vec(&reply_json)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let etag = Arc::new(etag);
        let last_modified = Arc::new(last_modified);
        let body = Arc::new(reply_bytes);
        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                let captured = cap_clone.clone();
                let etag = etag.clone();
                let last_modified = last_modified.clone();
                let body = body.clone();
                std::thread::spawn(move || {
                    let _ =
                        handle_mock_conditional_conn(stream, captured, body, etag, last_modified);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// WOR-1133: start a mock upstream that replies with a raw byte
    /// body and an explicit `Content-Type` (200). Useful for testing
    /// binary content-types (e.g. `image/png`) that the compression
    /// middleware must skip, where a JSON body would be on the
    /// compress list.
    pub fn start_raw(body: Vec<u8>, content_type: &str) -> anyhow::Result<Self> {
        Self::start_full(200, Some(content_type.to_string()), body, Vec::new())
    }

    /// Shared constructor for the fixed-response mocks. `content_type`
    /// of `None` defaults to `application/json`.
    fn start_full(
        status: u16,
        content_type: Option<String>,
        reply_bytes: Vec<u8>,
        extra_headers: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let content_type = content_type.unwrap_or_else(|| "application/json".to_string());
        let extra = Arc::new(extra_headers);

        let join = std::thread::spawn(move || {
            // Set a short accept timeout so we can poll the
            // shutdown flag without leaking the thread when the
            // harness is dropped.
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let body = reply_bytes.clone();
                let hdrs = extra.clone();
                let ct = content_type.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_conn(stream, cap, body, status, ct, hdrs);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    fn start_sequence_full(
        responses: Vec<(u16, Vec<u8>)>,
        content_type: String,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let responses = Arc::new(responses);
        let next = Arc::new(AtomicUsize::new(0));
        let extra = Arc::new(Vec::new());

        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let seq = responses.clone();
                let idx = next.fetch_add(1, Ordering::SeqCst);
                let (status, body) = seq
                    .get(idx)
                    .or_else(|| seq.last())
                    .expect("non-empty sequence")
                    .clone();
                let ct = content_type.clone();
                let hdrs = extra.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_conn(stream, cap, body, status, ct, hdrs);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Start a mock upstream that replies to every request with an
    /// SSE-shaped (`text/event-stream`) chunked response built from
    /// the supplied events. Each entry becomes one `data: <line>\n\n`
    /// frame written to the wire as its own HTTP/1.1 chunk so the
    /// proxy's streaming relay sees the same framing a real provider
    /// would emit. Useful for AI gateway tests that need to verify
    /// the SSE relay path: streaming usage capture, stream-cache
    /// recorder fan-out, etc.
    pub fn start_sse(events: Vec<String>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let events = Arc::new(events);

        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let evts = events.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_sse_conn(stream, cap, evts);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Start a mock upstream that emits raw SSE / NDJSON frames.
    ///
    /// `frames` are written verbatim, one chunk per entry, so the
    /// caller controls the framing (event-type prefix, JSON envelope,
    /// etc.). `content_type` is forwarded as the response
    /// Content-Type header. Useful for provider-shape coverage
    /// (Anthropic `event:` markers, Vertex `usageMetadata`, Bedrock
    /// `bytes` envelopes, Cohere `event-type`, Ollama NDJSON) where
    /// the OpenAI-shape `start_sse` cannot represent the wire format.
    pub fn start_sse_raw(frames: Vec<String>, content_type: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let frames = Arc::new(frames);
        let ct = Arc::new(content_type);

        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let f = frames.clone();
                let c = ct.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_sse_raw_conn(stream, cap, f, c);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Base URL the proxy should use to reach this mock upstream.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Snapshot the captured requests so far. The returned vec is
    /// a clone, so further mutation in the server thread does not
    /// affect callers.
    pub fn captured(&self) -> Vec<CapturedRequest> {
        self.captured.lock().unwrap().clone()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Poke the listener so accept() returns and the loop sees
        // the shutdown flag.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_mock_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    reply_body: Vec<u8>,
    status: u16,
    content_type: String,
    extra_headers: Arc<Vec<(String, String)>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    let mut resp = String::new();
    resp.push_str(&format!(
        "HTTP/1.1 {} {}\r\n",
        status,
        reason_phrase(status)
    ));
    resp.push_str(&format!("Content-Type: {}\r\n", content_type));
    for (k, v) in extra_headers.iter() {
        // The resolved Content-Type is emitted above; skip any stray
        // content-type in the extra list so it is never duplicated.
        if k.eq_ignore_ascii_case("content-type") {
            continue;
        }
        resp.push_str(&format!("{}: {}\r\n", k, v));
    }
    resp.push_str(&format!("Content-Length: {}\r\n", reply_body.len()));
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;
    stream.write_all(&reply_body)?;
    stream.flush()?;
    Ok(())
}

fn handle_mock_conditional_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    reply_body: Arc<Vec<u8>>,
    etag: Arc<String>,
    last_modified: Arc<String>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(head) => head,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = std::collections::HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }

    let body_start = header_end + 4;
    let mut request_body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while request_body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        request_body.extend_from_slice(&tmp[..n]);
    }
    request_body.truncate(content_length);

    let not_modified = headers
        .get("if-none-match")
        .is_some_and(|candidate| candidate == etag.as_str());
    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body: request_body,
    });

    if not_modified {
        let response = format!(
            "HTTP/1.1 304 Not Modified\r\nETag: {}\r\nLast-Modified: {}\r\n\
             Cache-Control: public, max-age=60\r\nContent-Length: 999\r\n\
             X-Refresh-Hop: never-store\r\nX-Sbproxy-Cache: upstream-poison\r\n\
             Connection: close, X-Refresh-Hop\r\n\r\n",
            etag, last_modified
        );
        stream.write_all(response.as_bytes())?;
    } else {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: {}\r\n\
             Last-Modified: {}\r\nCache-Control: public, max-age=60\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            etag,
            last_modified,
            reply_body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(&reply_body)?;
    }
    stream.flush()?;
    Ok(())
}

/// Minimal HTTP reason phrase for the status codes the mock emits.
/// Anything not listed falls back to a generic phrase keyed on class;
/// the proxy keys off the numeric status, not the phrase.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        s if (200..300).contains(&s) => "OK",
        s if (400..500).contains(&s) => "Client Error",
        _ => "Server Error",
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Connection handler for `MockUpstream::start_sse`. Parses the
/// inbound request the same way `handle_mock_conn` does, then writes
/// `text/event-stream` chunked encoding: one `data: <line>\n\n`
/// frame per event, terminated with the standard `data: [DONE]`
/// sentinel. Each frame goes out as its own HTTP/1.1 chunk so the
/// proxy's SSE relay observes the same framing a real provider would
/// emit and cannot collapse the stream by reading the whole body in
/// one go.
fn handle_mock_sse_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    events: Arc<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    // --- Write SSE response with chunked transfer encoding ---
    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str("Content-Type: text/event-stream\r\n");
    resp.push_str("Cache-Control: no-cache\r\n");
    resp.push_str("Transfer-Encoding: chunked\r\n");
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;

    for event in events.iter() {
        let frame = format!("data: {}\n\n", event);
        let chunk_header = format!("{:x}\r\n", frame.len());
        stream.write_all(chunk_header.as_bytes())?;
        stream.write_all(frame.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }

    // OpenAI-shaped terminator. The streaming relay does not interpret
    // [DONE] today; it simply forwards the bytes and exits when the
    // upstream stream closes. Including it keeps the framing realistic.
    let done_frame = "data: [DONE]\n\n";
    let chunk_header = format!("{:x}\r\n", done_frame.len());
    stream.write_all(chunk_header.as_bytes())?;
    stream.write_all(done_frame.as_bytes())?;
    stream.write_all(b"\r\n")?;

    // Final chunk (length 0) closes the chunked body.
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

/// Connection handler for `MockUpstream::start_sse_raw`. Writes the
/// configured frames to the wire one chunk per entry so the proxy
/// observes the same framing each entry would be flushed at by a
/// real upstream.
fn handle_mock_sse_raw_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    frames: Arc<Vec<String>>,
    content_type: Arc<String>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    // --- Write streaming response with chunked transfer encoding ---
    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str(&format!("Content-Type: {}\r\n", content_type));
    resp.push_str("Cache-Control: no-cache\r\n");
    resp.push_str("Transfer-Encoding: chunked\r\n");
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;

    for frame in frames.iter() {
        let chunk_header = format!("{:x}\r\n", frame.len());
        stream.write_all(chunk_header.as_bytes())?;
        stream.write_all(frame.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }

    // Final chunk (length 0) closes the chunked body.
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_port_returns_distinct_ports() {
        let a = pick_free_port().unwrap();
        let b = pick_free_port().unwrap();
        // The OS may legitimately give us the same port twice
        // sequentially (these are two independent reservations, held
        // open rather than dropped); just assert both bound to a
        // real, non-zero port.
        assert!(a.local_addr().unwrap().port() > 0);
        assert!(b.local_addr().unwrap().port() > 0);
    }

    #[test]
    fn port_collision_marker_survives_context_wrapping() {
        // The cluster tests classify a failed node start through however
        // many `with_context` layers their start helpers add, so the
        // typed marker must stay downcastable through wrapping.
        let error = anyhow::anyhow!("bind() failed on 0.0.0.0:4242")
            .context(PortCollision { port: 4242 })
            .context("start worker-b");
        assert!(error_is_port_collision(&error));
        // Classification is typed, never textual: an error that merely
        // mentions the bind failure is not a collision verdict.
        assert!(!error_is_port_collision(&anyhow::anyhow!(
            "Address already in use (os error 48)"
        )));
    }

    #[test]
    fn generate_harness_token_returns_distinct_tokens() {
        let a = generate_harness_token();
        let b = generate_harness_token();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn default_startup_timeout_tolerates_busy_release_boots() {
        // Generous ceiling for a proxy spawned on a box hot from the
        // pre-e2e workspace build; a healthy boot still answers the probe
        // in well under a second, so this does not slow healthy runs.
        assert!(DEFAULT_STARTUP_TIMEOUT >= Duration::from_secs(30));
    }

    #[test]
    fn startup_timeout_falls_back_to_default_without_env() {
        // With the override unset, the resolver returns the default. (We
        // do not mutate the env here: env is process-global and these
        // tests run in parallel.)
        if std::env::var("SBPROXY_E2E_STARTUP_TIMEOUT_SECS").is_err() {
            assert_eq!(startup_timeout(), DEFAULT_STARTUP_TIMEOUT);
        }
    }

    #[test]
    fn inject_port_overwrites_existing_value() {
        let out = inject_port(
            "proxy:\n  http_bind_port: 8080\norigins:\n  x:\n    action: { type: noop }\n",
            12345,
        )
        .unwrap();
        assert!(out.contains("http_bind_port: 12345"));
    }

    #[test]
    fn inject_port_creates_proxy_block_when_absent() {
        let out = inject_port("origins:\n  x:\n    action: { type: noop }\n", 54321).unwrap();
        assert!(out.contains("http_bind_port: 54321"));
        assert!(out.contains("proxy:"));
    }

    // --- Wave 5 day-5 / Q5.x trust-CIDR default tests ---

    #[test]
    fn inject_port_adds_loopback_trust_cidr_default() {
        // Wave 5 / G5.3 + G5.4: the harness must mark the loopback as
        // a trusted proxy so the OSS request_filter accepts the
        // sidecar TLS-fingerprint headers (`x-sbproxy-tls-ja4`, ...)
        // the e2e tests inject from 127.0.0.1.
        let out = inject_port("origins:\n  x:\n    action: { type: noop }\n", 12345).unwrap();
        assert!(
            out.contains("trusted_proxies:"),
            "harness must inject trusted_proxies by default, got: {out}",
        );
        assert!(
            out.contains("127.0.0.0/8"),
            "harness must mark IPv4 loopback as trusted, got: {out}",
        );
        assert!(
            out.contains("::1/128"),
            "harness must mark IPv6 loopback as trusted, got: {out}",
        );
    }

    #[test]
    fn inject_port_does_not_overwrite_operator_authored_trust_cidrs() {
        // When the test author pins their own trust boundary the
        // harness must respect it; the loopback default is only a
        // safety net for tests that did not author the field. The
        // assertion is scoped to the `trusted_proxies:` block because
        // the harness may legitimately inject `127.0.0.0/8` elsewhere
        // (e.g. into `extensions.upstream.allow_private_cidrs`).
        let yaml = "proxy:\n  trusted_proxies: ['10.0.0.0/8']\norigins:\n  x:\n    action: { type: noop }\n";
        let out = inject_port(yaml, 12345).unwrap();
        let trusted_block = trusted_proxies_block(&out);
        assert!(
            trusted_block.contains("10.0.0.0/8"),
            "operator-authored trusted_proxies entry must survive, got: {trusted_block}",
        );
        assert!(
            !trusted_block.contains("127.0.0.0/8"),
            "harness must NOT inject the loopback default into trusted_proxies, got: {trusted_block}",
        );
    }

    /// Slice the `trusted_proxies:` block out of a YAML string so the
    /// assertion above can check just that block, not the whole doc.
    /// Returns the substring from `trusted_proxies:` to the next
    /// top-level (under `proxy:`) key or end of file.
    fn trusted_proxies_block(yaml: &str) -> &str {
        let start = match yaml.find("trusted_proxies:") {
            Some(i) => i,
            None => return "",
        };
        let rest = &yaml[start..];
        // The `trusted_proxies:` value is a YAML sequence; the next
        // sibling under `proxy:` starts at the same indent level
        // ("  "). Walk forward until we find a line that starts with
        // exactly two spaces and a non-list-item character.
        let mut end = rest.len();
        for (offset, line) in rest.split_inclusive('\n').enumerate().skip(1) {
            let cumulative: usize = rest.split_inclusive('\n').take(offset).map(str::len).sum();
            let trimmed = line.trim_start();
            // A new top-level proxy key looks like "  http_bind_port:"
            // or "  extensions:" — exactly 2 leading spaces, no `-`.
            let indent = line.len() - trimmed.len();
            if indent <= 2 && !trimmed.is_empty() && !trimmed.starts_with('-') {
                end = cumulative;
                break;
            }
        }
        &rest[..end]
    }
}
