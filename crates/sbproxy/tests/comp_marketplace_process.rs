// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-level CoMP marketplace reachability (WOR-2673).
//!
//! `sbproxy-licensing`'s own tests drive its axum router, and this
//! binary never mounts that router: it serves the three CoMP
//! well-known URLs from the Pingora request path instead. Nothing in
//! the library crate can prove that path exists, that
//! `origins.<host>.comp` reaches it, or that the buyer-key registry the
//! config declares is the one a redeem is checked against.
//!
//! This test boots the released binary from an `sb.yml`, walks the
//! whole buyer flow over the public listener (manifest, quote, redeem),
//! and then drives the two refusals that matter most: a buyer key this
//! publisher never onboarded, and a `quote_id` this publisher never
//! issued. Both must fail closed, and neither refusal may carry a
//! token.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

/// The buyer's Ed25519 seed. Fixed so the config below can name its
/// public half without the test generating and re-serializing one.
const BUYER_SEED: [u8; 32] = [0x5Au8; 32];

/// The origin's OLP signing seed, hex, exactly as `olp.signing_key`
/// takes it. The bridge signs the license token it returns with this,
/// which is the whole reason the token verifies against this same
/// origin's OLP surface.
const OLP_SEED_HEX: &str = "1122334455667788990011223344556677889900112233445566778899001122";

/// Admin credential for the fixture's loopback admin listener. The
/// route under test is behind operator auth, so the test has to
/// present one, which is also what proves the gate is in front of it.
const ADMIN_PASSWORD: &str = "process-test-admin-password";

/// The CoMP quote-signing master key. Any value of 32 bytes or more;
/// HKDF expands it per rotation label.
const COMP_MASTER_KEY: &str = "comp-master-key-for-the-process-test-0123456789";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-comp-marketplace-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

/// What one transport attempt against the proxy reports.
///
/// These helpers returned `Option`, and every call site spent it on
/// `.expect("...")`. That threw the cause away: a refused connection,
/// a failed write and a read that timed out all arrived as the same
/// bare `None`, so the panic at step 8 said only
/// `admin licensing response` and named neither the port nor the
/// errno. The error half carries both now.
type Transport = Result<Vec<u8>, String>;

/// One HTTP/1.1 request over a fresh connection. Returns the raw
/// response bytes, or the transport error that stopped it.
fn request(port: u16, method: &str, path: &str, body: Option<&[u8]>) -> Transport {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("connect to 127.0.0.1:{port} for {method} {path}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set the read timeout on 127.0.0.1:{port}: {error}"))?;
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: marketplace.test\r\nConnection: close\r\n");
    if let Some(body) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|error| format!("write {method} {path} to 127.0.0.1:{port}: {error}"))?;
    if let Some(body) = body {
        stream.write_all(body).map_err(|error| {
            format!("write the {method} {path} body to 127.0.0.1:{port}: {error}")
        })?;
    }
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read {method} {path} from 127.0.0.1:{port}: {error}"))?;
    Ok(response)
}

/// One HTTP/1.1 GET carrying HTTP Basic credentials.
fn admin_get(port: u16, path: &str) -> Transport {
    let credential =
        base64::engine::general_purpose::STANDARD.encode(format!("admin:{ADMIN_PASSWORD}"));
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| {
        format!("connect to the admin listener on 127.0.0.1:{port} for GET {path}: {error}")
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set the read timeout on 127.0.0.1:{port}: {error}"))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {credential}\r\n\
         Connection: close\r\n\r\n"
    )
    .map_err(|error| format!("write GET {path} to 127.0.0.1:{port}: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read GET {path} from 127.0.0.1:{port}: {error}"))?;
    Ok(response)
}

/// The same request with no credential, to prove the gate is real.
fn admin_get_unauthenticated(port: u16, path: &str) -> Transport {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| {
        format!("connect to the admin listener on 127.0.0.1:{port} for an unauthenticated GET {path}: {error}")
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set the read timeout on 127.0.0.1:{port}: {error}"))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("write GET {path} to 127.0.0.1:{port}: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read GET {path} from 127.0.0.1:{port}: {error}"))?;
    Ok(response)
}

/// Split a raw response into its status line plus headers, and its body.
fn split(response: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(response).to_string();
    match text.split_once("\r\n\r\n") {
        Some((head, body)) => (head.to_string(), body.to_string()),
        None => (text, String::new()),
    }
}

/// 45s rather than the 20s its sibling federation test uses. Both spawn
/// a full proxy, and this file was observed hitting exactly 20s on a
/// machine that was still compiling the rest of the workspace. A startup
/// deadline that a busy machine can trip is a flake, not a signal: the
/// thing under test is what the proxy serves, not how fast it boots.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);

/// How many times a lost port is worth re-drawing before giving up.
///
/// A loopback port handed out by the kernel is only reserved until this
/// test drops the listener, and every other process test on the machine
/// is drawing from the same range. Losing one is ordinary and says
/// nothing about the proxy, so it is redrawn rather than reported.
/// Losing five in a row is not ordinary and is reported.
const PORT_ATTEMPTS: usize = 5;

/// What the child writes when a listener cannot take the port it was
/// handed.
///
/// Two spellings, because the runtime has two. Every other process test
/// in this workspace that has to recognize this condition carries both
/// (`chargeback_admin_wire.rs`, `classifier_hook_egress.rs`,
/// `generated_response_large_body.rs`), and `listener_startup.rs`, whose
/// whole subject is the public listener collision, requires both as
/// well. A detector narrower than those is a detector that reports an
/// ordinary redraw as a hard failure.
///
/// The two listeners report the same errno and are alike in nothing
/// else. The public bind is fatal: the process prints to stderr and
/// exits. The admin bind is not: `spawn_admin_server` logs at error
/// through `tracing`, which this binary writes to **stdout**, and then
/// the process goes on serving without an admin plane for the rest of
/// its life. So the failure this test actually trips over is the quiet
/// one, on the stream the test used to send to `/dev/null`, which is
/// most of why it was opaque. Both streams are captured and both are
/// searched.
const ADDRESS_IN_USE_MARKERS: [&str; 2] = ["address already in use", "address in use"];

/// Longest marker, so a scan that spans two reads carries enough of the
/// previous one to match across the seam. Derived rather than written
/// down, so adding a third spelling cannot leave the overlap short.
const LONGEST_MARKER: usize = {
    let first = ADDRESS_IN_USE_MARKERS[0].len();
    let second = ADDRESS_IN_USE_MARKERS[1].len();
    if first > second {
        first
    } else {
        second
    }
};

/// A running proxy and the two ports it actually took.
///
/// The ports come back from the start rather than going in, because a
/// collision is resolved by redrawing them: the caller cannot hold a
/// port that the start may have had to abandon.
struct Proxy {
    child: Child,
    port: u16,
    admin_port: u16,
    output: ChildOutput,
}

/// Both of the child's output streams, drained on their own threads.
///
/// Drained rather than left in the pipes for two reasons. The readiness
/// loop below has to read them while the child is still running, to
/// tell a lost port from a slow boot without waiting out the whole
/// deadline. And a child that fills a 64 KB pipe buffer blocks in
/// `write` forever when nobody is reading, which would turn a noisy
/// boot into a hang; the old `Stdio::null()` on stdout avoided that by
/// throwing away the stream the admin bind failure is written to.
struct ChildOutput {
    /// Retained bytes, for a panic message. Bounded, and bounded at the
    /// **front**: the interesting line is the last one the child wrote,
    /// so a full buffer drops the oldest bytes rather than refusing the
    /// newest.
    buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    /// Set by whichever pump sees a marker, so detection never depends
    /// on what survived the cap. The bind failure is logged at the end
    /// of a boot, which is exactly the part a front-filling buffer
    /// discards, so a chatty boot used to blind the detector at the
    /// moment it mattered.
    lost_a_port: std::sync::Arc<std::sync::atomic::AtomicBool>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl ChildOutput {
    /// Cap on what is retained for the transcript.
    const CAP: usize = 256 * 1024;

    /// How long `finish` waits for a pump to end before giving up on it.
    ///
    /// A pump ends when its pipe closes, which is when the last holder
    /// of the write end exits. That is normally the child, but a
    /// descendant that inherited the handle would keep it open, and an
    /// unbounded join on a path that is already failing turns a panic
    /// with a message into a hang with none.
    const JOIN_GRACE: Duration = Duration::from_secs(5);

    fn drain(stdout: std::process::ChildStdout, stderr: std::process::ChildStderr) -> Self {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lost_a_port = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers = vec![
            Self::pump(
                Box::new(stdout),
                std::sync::Arc::clone(&buffer),
                std::sync::Arc::clone(&lost_a_port),
            ),
            Self::pump(
                Box::new(stderr),
                std::sync::Arc::clone(&buffer),
                std::sync::Arc::clone(&lost_a_port),
            ),
        ];
        Self {
            buffer,
            lost_a_port,
            readers,
        }
    }

    fn pump(
        mut pipe: Box<dyn std::io::Read + Send>,
        sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        lost_a_port: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            // The tail of the previous read, lowercased, so a marker
            // split across two reads still matches.
            let mut carry: Vec<u8> = Vec::new();
            loop {
                let read = match pipe.read(&mut chunk) {
                    Ok(0) => return,
                    Ok(read) => read,
                    Err(error) => {
                        // Not the same thing as EOF, and the difference
                        // matters: a stream that stopped early leaves a
                        // partial transcript, and a reader who cannot
                        // see that will read the absence of a line as
                        // evidence the child never wrote it.
                        let note =
                            format!("\n[test harness: reading this stream failed: {error}]\n");
                        let mut held = sink.lock().unwrap_or_else(|e| e.into_inner());
                        Self::append(&mut held, note.as_bytes());
                        return;
                    }
                };
                let mut scan = carry.clone();
                scan.extend(chunk[..read].iter().map(|b| b.to_ascii_lowercase()));
                let scanned = String::from_utf8_lossy(&scan);
                if ADDRESS_IN_USE_MARKERS
                    .iter()
                    .any(|marker| scanned.contains(marker))
                {
                    lost_a_port.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let keep = scan.len().saturating_sub(LONGEST_MARKER.saturating_sub(1));
                carry = scan[keep..].to_vec();
                let mut held = sink.lock().unwrap_or_else(|e| e.into_inner());
                Self::append(&mut held, &chunk[..read]);
            }
        })
    }

    /// Append, dropping from the front rather than refusing at the back.
    fn append(held: &mut Vec<u8>, bytes: &[u8]) {
        held.extend_from_slice(bytes);
        if held.len() > Self::CAP {
            let excess = held.len() - Self::CAP;
            held.drain(..excess);
        }
    }

    fn snapshot(&self) -> String {
        let held = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&held).into_owned()
    }

    /// True once the child has said it could not take a port. Either
    /// listener, either stream, either spelling: see
    /// [`ADDRESS_IN_USE_MARKERS`].
    ///
    /// Reads one atomic. The readiness loop calls this every 50ms for up
    /// to 45 seconds, and the previous version cloned the whole buffer
    /// and lowercased the clone on each of those ~900 passes, which on a
    /// full buffer is hundreds of megabytes of churn contending with the
    /// two pumps.
    fn lost_a_port(&self) -> bool {
        self.lost_a_port.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Everything the readers retained, once they have ended or the
    /// grace has passed.
    fn finish(mut self) -> String {
        let deadline = Instant::now() + Self::JOIN_GRACE;
        let mut abandoned = 0usize;
        for reader in self.readers.drain(..) {
            while !reader.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if reader.is_finished() {
                let _ = reader.join();
            } else {
                abandoned += 1;
            }
        }
        let mut text = self.snapshot();
        if abandoned > 0 {
            text.push_str(&format!(
                "\n[test harness: {abandoned} of the child's streams were still open after \
                 {}s, so this transcript may be short; something still holds the write end]\n",
                Self::JOIN_GRACE.as_secs()
            ));
        }
        text
    }
}

/// True once the origin's ordinary route answers with an HTTP response.
///
/// The origin's ordinary route, not a licensing endpoint: both licensing
/// halves share one per-source budget, and a readiness loop that spent
/// it would leave the walkthrough below testing an exhausted bucket
/// rather than the flow.
///
/// An HTTP status line rather than merely a read that did not error.
/// `read_to_end` reports `Ok(0)` for a socket that was accepted and
/// closed without a byte on it, which the previous `is_some()` check
/// counted as ready.
fn serves_public_plane(port: u16) -> bool {
    request(port, "GET", "/", None).is_ok_and(|raw| raw.starts_with(b"HTTP/1.1"))
}

/// True once the admin listener answers `/admin/licensing` at all.
///
/// This is the check the old readiness loop did not have, and its
/// absence is the whole flake. The two listeners come up independently:
/// `run` binds the public one, and only afterwards spawns the thread
/// that builds its own runtime, builds a probe HTTP client, and finally
/// binds the admin port inside a spawned task. Nothing orders the
/// second against the first, so a proxy can serve the public plane
/// while the admin port is still refusing connections. Step 8 is the
/// first line in this file to touch that port, which is why the race
/// always surfaced there, and why a nextest retry did not absorb it:
/// the retry runs on the same loaded machine and loses the same race.
///
/// The status line and nothing else. An earlier version of this also
/// required `enabled: true` from the parsed body, which is exactly what
/// step 8 asserts, and that made step 8's assertions unreachable: any
/// state where they would fail is a state where this never returns
/// true, so a bridge reporting `enabled: false` came out as a 45 second
/// "did not serve" with neither the status nor the body in the message,
/// instead of `enabled was false`. Waiting on the answer is also a
/// retry wrapped around an assertion, spelled as readiness.
///
/// A 200 is the whole of what readiness needs here, because the defect
/// this closes is a refused connection. The route's own contents are
/// step 8's to judge, once.
///
/// Narrowing it is safe rather than merely cheaper, and the ordering is
/// why: `reload::load_pipeline` runs at `server/lifecycle.rs:3555`,
/// before `prepare_listeners` at `:3964` and long before the admin
/// thread is spawned at `:4358`. The pipeline is therefore published
/// before the admin port can bind, so an answer from this route already
/// carries the bridge. Waiting on `enabled: true` never proved anything
/// a 200 did not; it only moved step 8's failure into this loop's
/// timeout.
fn serves_admin_plane(port: u16) -> AdminProbe {
    match admin_get(port, "/admin/licensing") {
        Ok(raw) if raw.starts_with(b"HTTP/1.1 200") => AdminProbe::Serving,
        Ok(_) => AdminProbe::Answered,
        Err(_) => AdminProbe::Unreachable,
    }
}

/// What one probe of the admin plane cost and learned.
///
/// Split three ways because only one of the three spends anything. The
/// admin rate limiter is always on and defaults to 240 requests per
/// minute per IP, and `/admin/licensing` is not on its exemption list,
/// which covers only static console assets. A probe that is refused at
/// connect never reaches the limiter, so polling a port that is not yet
/// bound is free and can stay fast. A probe that gets an answer has
/// spent one, so a plane that answers something other than 200 has to
/// be asked slowly or the readiness loop exhausts in twelve seconds the
/// budget it is waiting on, and every later probe gets a 429 it can
/// never recover from.
enum AdminProbe {
    /// A 200. Readiness is satisfied.
    Serving,
    /// An answer, but not a 200. Cost one request against the limiter.
    Answered,
    /// Refused, reset, or timed out. Cost nothing.
    Unreachable,
}

/// Boot the shipped binary on a fresh pair of loopback ports and wait
/// until both planes this test drives are serving.
///
/// `config_for` renders the `sb.yml` for a given public and admin port.
/// It is a closure rather than a written file because a collision is
/// resolved by redrawing both ports, and the configuration names them.
fn start_proxy(root: &Path, config_for: impl Fn(u16, u16) -> String) -> Proxy {
    let mut lost = Vec::new();
    for attempt in 0..PORT_ATTEMPTS {
        // Both reservations are held at once and released together.
        // Taken one at a time, with the first released before the second
        // is asked for, the kernel is free to hand the same port back
        // twice: the proxy then binds it as its public listener, the
        // admin bind fails with the address in use, and every admin
        // request in this test lands on the public plane.
        let public_reservation =
            TcpListener::bind("127.0.0.1:0").expect("reserve an ephemeral port");
        let admin_reservation =
            TcpListener::bind("127.0.0.1:0").expect("reserve an ephemeral admin port");
        let port = public_reservation
            .local_addr()
            .expect("read the reserved address")
            .port();
        let admin_port = admin_reservation
            .local_addr()
            .expect("read the reserved admin address")
            .port();
        let config = root.join(format!("sb-{attempt}.yml"));
        std::fs::write(&config, config_for(port, admin_port)).expect("write the process config");
        // Released as late as possible. Nothing can close the window
        // between a reservation ending and the child's own bind, since
        // the child takes its ports from a file, so the window is kept
        // as narrow as it can be and a lost draw is redrawn below.
        drop(public_reservation);
        drop(admin_reservation);
        let mut command = Command::new(binary());
        command
            .arg("serve")
            .arg(&config)
            .env_remove("SB_CONFIG_FILE")
            .env(
                "SBPROXY_ENGINE_OWNERSHIP_DIR",
                root.join(format!("ownership-{attempt}")),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group, so the teardown can take down whatever
        // the proxy spawned rather than only the proxy itself. The same
        // move `sbproxy-config/src/source.rs:522` makes for its `git`
        // children, and for the same reason.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let mut child = command.spawn().expect("start sbproxy");
        let output = ChildOutput::drain(
            child.stdout.take().expect("sbproxy stdout is piped"),
            child.stderr.take().expect("sbproxy stderr is piped"),
        );
        match wait_until_serving(&mut child, &output, port, admin_port) {
            Startup::Serving => {
                return Proxy {
                    child,
                    port,
                    admin_port,
                    output,
                }
            }
            Startup::LostAPort => {
                let _ = child.kill();
                let _ = child.wait();
                lost.push(format!("attempt {attempt}: {port}/{admin_port}"));
            }
            Startup::Exited => {
                let _ = child.wait();
                // Re-checked on the completed transcript rather than on
                // the snapshot the loop happened to see. The child
                // writes its bind failure and exits immediately after,
                // so a reader thread that had not drained the pipe yet
                // when `try_wait` observed the exit would turn a lost
                // port into a hard failure. `finish` joins the readers,
                // so what it returns is everything the child ever said.
                let transcript = output.finish();
                let lowered = transcript.to_ascii_lowercase();
                if ADDRESS_IN_USE_MARKERS
                    .iter()
                    .any(|marker| lowered.contains(marker))
                {
                    lost.push(format!("attempt {attempt}: {port}/{admin_port}"));
                    continue;
                }
                panic!("sbproxy exited before serving the CoMP manifest: {transcript}");
            }
            Startup::TimedOut => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "sbproxy did not serve both the CoMP manifest on {port} and \
                     /admin/licensing on {admin_port} within {}s: {}",
                    STARTUP_TIMEOUT.as_secs(),
                    output.finish()
                );
            }
        }
    }
    panic!(
        "sbproxy lost a loopback port to another process on every attempt: {}",
        lost.join("; ")
    );
}

impl Drop for Proxy {
    /// Kill and reap the child on every path that unwinds or returns.
    ///
    /// Not "whatever ended the test", which is what this said and could
    /// not deliver. `Drop` runs on a normal return and on a panic
    /// unwind, and both of those are now covered where before only the
    /// happy path was. It cannot run when the harness itself is killed
    /// outright, and no amount of care here changes that: a SIGKILL to
    /// this process leaves the proxy reparented to init, which is the
    /// likeliest explanation for the orphan from this test found alive
    /// in another worktree after a day and a half. That orphan is
    /// evidence for the cost of leaking, not for what this `Drop` can
    /// prevent.
    ///
    /// What leaking costs is the reason to close the paths that can be
    /// closed: an orphan holds both its loopback ports for as long as it
    /// lives, so a leak on one failure raises the odds of the port
    /// collision that fails the next run.
    ///
    /// The teardown at the end of the test is now this, and only this,
    /// so there is one owner rather than a happy path that cleans up and
    /// a failure path that does not.
    fn drop(&mut self) {
        // Read before reaping: once `wait` returns, the pid is free to
        // be recycled, and signalling a recycled pid's group would hit
        // an unrelated process.
        let pid = self.child.id();
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        // The whole group, while the child is still unreaped and so
        // still holds the pid this group is named by. `kill` above ends
        // the proxy; this ends anything the proxy started that would
        // otherwise keep a port.
        #[cfg(unix)]
        {
            let _ = Command::new("/bin/kill")
                .arg("-KILL")
                .arg(format!("-{pid}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.wait();
    }
}

/// Why a startup stopped.
enum Startup {
    /// Both planes answer.
    Serving,
    /// A listener could not take the port it was handed, so the draw is
    /// worth repeating. Not a failure of anything this test covers.
    LostAPort,
    /// The child is gone.
    Exited,
    /// Neither of the above inside [`STARTUP_TIMEOUT`].
    TimedOut,
}

fn wait_until_serving(
    child: &mut Child,
    output: &ChildOutput,
    port: u16,
    admin_port: u16,
) -> Startup {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        // Checked before the child's own status: an admin bind that lost
        // its port is logged and then survived, so waiting for an exit
        // that never comes would spend the whole deadline on a condition
        // one line of the captured output already settles. That line is
        // on stdout, not stderr, which is the distinction the first cut
        // of this fix got wrong.
        if output.lost_a_port() {
            return Startup::LostAPort;
        }
        if child.try_wait().expect("poll sbproxy").is_some() {
            return Startup::Exited;
        }
        let mut answered_without_serving = false;
        if serves_public_plane(port) {
            match serves_admin_plane(admin_port) {
                AdminProbe::Serving => return Startup::Serving,
                AdminProbe::Answered => answered_without_serving = true,
                AdminProbe::Unreachable => {}
            }
        }
        if Instant::now() >= deadline {
            return Startup::TimedOut;
        }
        // A probe that was answered spent one of the 240 the admin
        // limiter allows per minute, so it is asked once a second rather
        // than twenty times. A refused one spent nothing and keeps the
        // fast cadence, which is the case this loop exists for.
        std::thread::sleep(if answered_without_serving {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(50)
        });
    }
}

/// Unwrap a transport attempt, saying what the proxy was doing when it
/// failed.
///
/// A refused connection and a dead proxy are the same errno from the
/// socket's side, and the second is the one worth knowing: it means the
/// process exited and wrote the reason to its output. Reporting only the
/// errno is how a connection refused by an admin listener that was not
/// up yet read as a licensing bug for two CI rounds.
fn expect_response(proxy: &mut Proxy, attempt: Transport, what: &str) -> Vec<u8> {
    match attempt {
        Ok(raw) => raw,
        Err(error) => {
            let fate = match proxy.child.try_wait() {
                Ok(Some(status)) => format!("the proxy had already exited with {status}"),
                Ok(None) => "the proxy was still running".to_string(),
                Err(error) => format!("the proxy's status could not be read: {error}"),
            };
            panic!(
                "{what}: {error}; {fate}. proxy output:\n{}",
                proxy.output.snapshot()
            );
        }
    }
}

/// The current time as the RFC 3339 stamp a buyer puts in its
/// acceptance. The redeem path bounds how far this may sit from the
/// bridge's own clock, so a frozen date would fail for the wrong reason.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Serialize a redeem request and sign it the way an onboarded buyer's
/// client does: over the whole body with `buyer_signature.value`
/// cleared.
fn signed_redeem(
    quote: &sbproxy_licensing::comp::CompQuoteResponse,
    quote_id: &str,
    kid: &str,
    signer: &SigningKey,
) -> Vec<u8> {
    use sbproxy_licensing::comp::{
        quote_acceptance_hash, CompAcceptance, CompPaymentProof, CompRedeemRequest, CompSignature,
        COMP_VERSION,
    };
    let mut request = CompRedeemRequest {
        comp_version: COMP_VERSION.into(),
        quote_id: quote_id.to_string(),
        buyer_signature: CompSignature {
            alg: "ed25519".into(),
            kid: kid.into(),
            value: String::new(),
        },
        buyer_acceptance: CompAcceptance {
            accepted_quote_hash: quote_acceptance_hash(quote).expect("hash the quote"),
            accepted_at: rfc3339_now(),
            buyer_legal_entity: "Acme AI Inc.".into(),
        },
        payment_proof: CompPaymentProof {
            rail: "x402".into(),
            txhash: Some("0xdeadbeef".into()),
            chain: Some("base".into()),
            receipt_id: None,
        },
    };
    let signing_input = serde_json::to_vec(&request).expect("serialize for signing");
    let signature = signer.sign(&signing_input);
    request.buyer_signature.value =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    serde_json::to_vec(&request).expect("serialize redeem")
}

#[test]
fn security_boundary_a_configured_origin_sells_licenses_and_refuses_the_rest() {
    let root = temp_dir();
    let buyer = SigningKey::from_bytes(&BUYER_SEED);
    let buyer_public =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buyer.verifying_key().to_bytes());
    let mut proxy = start_proxy(&root, |port, admin_port| {
        format!(
            r#"proxy:
  http_bind_port: {port}
  bind_address: 127.0.0.1
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: admin
    password: {ADMIN_PASSWORD}
origins:
  "marketplace.test":
    action:
      type: static
      status_code: 418
      content_type: text/plain
      body: origin-fallback-must-not-answer
    olp:
      enabled: true
      signing_key: "{OLP_SEED_HEX}"
      key_id: process-test-olp-key
      issuer: https://marketplace.test
      default_scope: ai-input
      default_ttl_secs: 3600
      # Small on purpose, so step 10 can walk past it. Not as small as
      # the three requests it takes to demonstrate exhaustion: the CoMP
      # half shares this budget, so the walkthrough above spends some of
      # it first, and step 10 counts what is left rather than assuming.
      token_rate_limit_per_minute: 20
    comp:
      enabled: true
      master_key: "{COMP_MASTER_KEY}"
      rotation_id: 2026-q3-001
      publisher:
        name: Example Publishing Co.
        contact: licensing@example.com
      tiers:
        - id: tier_ai_inference
          name: AI inference
          description: Per-request inference access.
          license: urn:rsl:pay-per-inference:default
          shape: json-envelope
          authorization: olp
          route_glob: "/api/v1/inference/**"
          pricing:
            model: per_request
            currency: USD
            amount_micros: 2500
      buyer_keys:
        - kid: buyer-acme-001
          public_key: "{buyer_public}"
"#
        )
    });
    let port = proxy.port;
    let admin_port = proxy.admin_port;

    // --- 1. The manifest, from the config block ---
    let raw = expect_response(
        &mut proxy,
        request(port, "GET", "/.well-known/iab-comp/manifest.json", None),
        "manifest response",
    );
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let lowered = head.to_ascii_lowercase();
    assert!(
        lowered.contains("content-type: application/iab-comp+json"),
        "{head}"
    );
    // Both headers come from the crate's own body rather than from a
    // second hand-rolled copy in the request path. A copy is what left
    // every federation metric family flat on this binary once already.
    assert!(lowered.contains("cache-control:"), "{head}");
    assert!(lowered.contains("x-comp-version: 1.0"), "{head}");
    let manifest: serde_json::Value = serde_json::from_str(&body).expect("manifest is JSON");
    assert_eq!(manifest["publisher"]["domain"], "marketplace.test");
    assert_eq!(manifest["publisher"]["name"], "Example Publishing Co.");
    assert_eq!(manifest["tiers"][0]["id"], "tier_ai_inference");
    assert_eq!(manifest["tiers"][0]["pricing"]["amount_micros"], 2500);
    assert_eq!(
        manifest["endpoints"]["redeem"],
        "https://marketplace.test/.well-known/iab-comp/redeem"
    );
    // Computed by the proxy over the manifest it publishes, not a
    // placeholder carried through from config.
    let hash = manifest["manifest_hash"]
        .as_str()
        .expect("manifest_hash is a string");
    assert!(hash.starts_with("sha256:"), "{hash}");
    assert_eq!(hash.len(), "sha256:".len() + 64, "{hash}");

    // --- 2. A quote ---
    let quote_body = serde_json::json!({
        "comp_version": "1.0",
        "buyer": { "agent_id": "agent_acme_001", "organization": "Acme AI Inc." },
        "tier_id": "tier_ai_inference",
        "requested_volume": {
            "model": "per_request", "expected_count": 1000, "duration_days": 30
        },
        "audience": "marketplace.test",
    })
    .to_string();
    let raw = expect_response(
        &mut proxy,
        request(
            port,
            "POST",
            "/.well-known/iab-comp/quote",
            Some(quote_body.as_bytes()),
        ),
        "quote response",
    );
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "a signed price must not be cached: {head}"
    );
    let quote: sbproxy_licensing::comp::CompQuoteResponse =
        serde_json::from_str(&body).expect("quote is a CompQuoteResponse");
    assert_eq!(quote.tier_id, "tier_ai_inference");
    assert_eq!(quote.pricing.amount_micros, 2500 * 1000);
    assert!(
        quote.signature.kid.starts_with("comp-"),
        "quotes sign under this crate's own kid namespace: {}",
        quote.signature.kid
    );

    // --- 3. The redeem, and the token it mints ---
    let redeem = signed_redeem(&quote, &quote.quote_id, "buyer-acme-001", &buyer);
    let raw = expect_response(
        &mut proxy,
        request(port, "POST", "/.well-known/iab-comp/redeem", Some(&redeem)),
        "redeem response",
    );
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "a license token must not be cached: {head}"
    );
    let redeemed: serde_json::Value = serde_json::from_str(&body).expect("redeem is JSON");
    assert_eq!(redeemed["token_type"], "Bearer");
    assert_eq!(redeemed["license"], "urn:rsl:pay-per-inference:default");
    assert_eq!(redeemed["route_glob"], "/api/v1/inference/**");
    let token = redeemed["license_token"]
        .as_str()
        .expect("a license token came back");
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "the token is a compact JWS: {token}");
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("the JWS header is base64url"),
    )
    .expect("the JWS header is JSON");
    // The token is minted under the origin's own OLP key id, which is
    // what makes it verifiable against this origin's OLP surface rather
    // than against a second issuer nobody configured.
    assert_eq!(header["kid"], "process-test-olp-key");
    assert_eq!(header["typ"], "olp-license+jws");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[1])
            .expect("the JWS payload is base64url"),
    )
    .expect("the JWS payload is JSON");
    assert_eq!(claims["iss"], "https://marketplace.test");
    assert_eq!(claims["aud"], "marketplace.test");
    assert_eq!(claims["license_urn"], "urn:rsl:pay-per-inference:default");

    // --- 4. Fails closed: a key this publisher never onboarded ---
    let stranger = SigningKey::from_bytes(&[0x7Bu8; 32]);
    let forged = signed_redeem(&quote, &quote.quote_id, "buyer-not-onboarded", &stranger);
    let (head, body) = split(&expect_response(
        &mut proxy,
        request(port, "POST", "/.well-known/iab-comp/redeem", Some(&forged)),
        "the refusal of a key this publisher never onboarded",
    ));
    assert!(head.starts_with("HTTP/1.1 401"), "{head}\n{body}");
    assert!(body.contains("unknown_key"), "{body}");
    assert!(
        !body.contains("license_token"),
        "a refusal must not carry a token: {body}"
    );

    // --- 5. Fails closed: a quote_id this publisher never issued ---
    let fabricated = signed_redeem(
        &quote,
        "01JFABRICATEDQUOTEID000000",
        "buyer-acme-001",
        &buyer,
    );
    let (head, body) = split(&expect_response(
        &mut proxy,
        request(
            port,
            "POST",
            "/.well-known/iab-comp/redeem",
            Some(&fabricated),
        ),
        "the refusal of a quote_id this publisher never issued",
    ));
    assert!(head.starts_with("HTTP/1.1 403"), "{head}\n{body}");
    assert!(body.contains("unknown_quote"), "{body}");
    assert!(
        !body.contains("license_token"),
        "a refusal must not carry a token: {body}"
    );

    // --- 6. Fails closed: a body this endpoint cannot read ---
    let (head, body) = split(&expect_response(
        &mut proxy,
        request(
            port,
            "POST",
            "/.well-known/iab-comp/quote",
            Some(b"{not json"),
        ),
        "the refusal of a body this endpoint cannot read",
    ));
    assert!(head.starts_with("HTTP/1.1 400"), "{head}\n{body}");
    assert!(body.contains("malformed"), "{body}");

    // --- 7. The method contract, in the shared shape ---
    //
    // WOR-2673 verification residual: asserting only the status left a
    // revert to a silent `send_error` green on the shipped binary's
    // transport, which is the shape N1 came from one transport over.
    // The body and the cache directive are what prove the refusal came
    // from `comp/serve.rs` and therefore moved a counter and wrote a
    // decision event.
    for path in [
        "/.well-known/iab-comp/redeem",
        "/.well-known/iab-comp/quote",
    ] {
        let (head, body) = split(&expect_response(
            &mut proxy,
            request(port, "GET", path, None),
            "the method contract refusal",
        ));
        assert!(head.starts_with("HTTP/1.1 405"), "{path}: {head}");
        let lowered = head.to_ascii_lowercase();
        assert!(
            lowered.contains("content-type: application/json"),
            "{path} must be refused in the shared JSON shape: {head}"
        );
        assert!(
            lowered.contains("cache-control: no-store"),
            "{path}: {head}"
        );
        assert!(body.contains("method_not_allowed"), "{path}: {body}");
    }
    // The manifest route is the GET one, so POST is its wrong method.
    let (head, body) = split(&expect_response(
        &mut proxy,
        request(
            port,
            "POST",
            "/.well-known/iab-comp/manifest.json",
            Some(b"{}"),
        ),
        "the manifest route's wrong-method refusal",
    ));
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
    assert!(body.contains("method_not_allowed"), "{body}");

    // --- 8. The operator surface, on a process that has a bridge ---
    //
    // WOR-2673 review M4 and m8. The example documents this curl, and
    // only the empty branch of the route had a test: an
    // `enabled: false` answer would have satisfied both. This is the
    // populated branch, over the wire, on a running proxy, behind the
    // auth gate the route is documented to sit behind.
    let (head, body) = split(&expect_response(
        &mut proxy,
        admin_get(admin_port, "/admin/licensing"),
        "admin licensing response",
    ));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    let admin: serde_json::Value = serde_json::from_str(&body).expect("admin body is JSON");
    assert_eq!(admin["enabled"], true, "{body}");
    let origin = &admin["origins"][0];
    assert_eq!(origin["hostname"], "marketplace.test", "{body}");
    // Both halves nest and both carry `enabled`, so one field answers
    // "does this origin have a bridge" (WOR-2673 re-review N2).
    let comp = &origin["comp"];
    assert_eq!(comp["enabled"], true, "{body}");
    assert_eq!(origin["olp"]["enabled"], true, "{body}");
    assert_eq!(
        origin["olp"]["signing_kid"], "process-test-olp-key",
        "{body}"
    );
    assert_eq!(comp["publisher_name"], "Example Publishing Co.", "{body}");
    assert_eq!(comp["tier_count"], 1, "{body}");
    assert_eq!(comp["olp_tier_count"], 1, "{body}");
    // Not `null`: a null here means no rotation was activated and every
    // quote request fails closed, which is the field's whole job.
    assert_eq!(comp["active_signing_kid"], "comp-2026-q3-001", "{body}");
    assert_eq!(comp["trusted_kid_count"], 1, "{body}");
    assert_eq!(comp["manifest_hash"], hash, "{body}");
    assert_eq!(
        comp["endpoints"]["redeem"], "https://marketplace.test/.well-known/iab-comp/redeem",
        "{body}"
    );
    // No secret and no minted token reaches the operator surface.
    assert!(!body.contains(COMP_MASTER_KEY), "{body}");
    assert!(!body.contains(OLP_SEED_HEX), "{body}");
    assert!(!body.contains(token), "{body}");

    // The gate itself: the same route with no credential.
    let (head, _) = split(&expect_response(
        &mut proxy,
        admin_get_unauthenticated(admin_port, "/admin/licensing"),
        "the unauthenticated admin licensing response",
    ));
    assert!(
        head.starts_with("HTTP/1.1 401"),
        "the licensing route must sit behind operator auth: {head}"
    );

    // --- 10. One source cannot mint license tokens without bound ---
    //
    // WOR-2673. `POST /.well-known/olp/token` is unauthenticated by
    // design: an RSL crawler following a `WWW-Authenticate: License`
    // challenge has no credential yet, and a body that is not a
    // `client_credentials` form mints under an anonymous `sub`. Every
    // call signs a fresh Ed25519 bearer token, and the endpoint answers
    // from `request_filter` ahead of bot detection, threat protection,
    // authentication, and the policy chain, so nothing else on the path
    // bounds it. The budget configured above is the bound, and this is
    // it holding over the wire from one source.
    let mut minted = 0usize;
    let mut refused = 0usize;
    // More attempts than the configured budget, so the bucket is
    // guaranteed to run out inside the loop whatever the walkthrough
    // above already spent.
    for _ in 0..40 {
        let (head, body) = split(&expect_response(
            &mut proxy,
            request(port, "POST", "/.well-known/olp/token", Some(b"{}")),
            "an OLP token mint",
        ));
        if head.starts_with("HTTP/1.1 200") {
            assert_eq!(
                refused, 0,
                "the budget must not let a mint through after it has started refusing: {head}"
            );
            minted += 1;
            assert!(body.contains("access_token"), "{body}");
        } else {
            assert!(head.starts_with("HTTP/1.1 429"), "{head}\n{body}");
            assert!(body.contains("slow_down"), "{body}");
            assert!(
                head.to_ascii_lowercase().contains("retry-after:"),
                "a 429 a client should back off from carries Retry-After: {head}"
            );
            assert!(
                !body.contains("access_token"),
                "a refused mint must not carry a token: {body}"
            );
            refused += 1;
        }
    }
    assert!(minted > 0, "a source inside its budget mints");
    assert!(
        refused > 0,
        "a single source must not mint without bound: 40 attempts against a budget of 20 \
         produced no refusal"
    );
    assert!(
        minted <= 20,
        "no more mints than the configured budget: {minted}"
    );

    // --- 11. The CoMP half carries the same budget as the OLP half ---
    //
    // WOR-2673 verification residual. These endpoints answer ahead of
    // every stage that could rate-limit them, exactly like the token
    // endpoint next to them, and until now only that one was budgeted.
    // The budget is this origin's `olp.token_rate_limit_per_minute`,
    // which step 10 has already spent, so the very next CoMP call is
    // refused. That shared exhaustion is itself the point: one number
    // governs both halves of one licensing surface.
    let (head, body) = split(&expect_response(
        &mut proxy,
        request(port, "GET", "/.well-known/iab-comp/manifest.json", None),
        "the manifest request that shares the origin's budget",
    ));
    assert!(
        head.starts_with("HTTP/1.1 429"),
        "the CoMP half must share the origin's budget: {head}\n{body}"
    );
    assert!(body.contains("rate_limited"), "{body}");
    assert!(
        head.to_ascii_lowercase().contains("retry-after:"),
        "a 429 a client should back off from carries Retry-After: {head}"
    );

    // Dropped before the directory is removed, so the proxy is gone
    // before its configuration and ownership directory go with it.
    drop(proxy);
    let _ = std::fs::remove_dir_all(root);
}
