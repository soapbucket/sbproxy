//! Integration tests for the WOR-2653 `sbproxy connect` / `sbproxy disconnect`
//! subcommands.
//!
//! This verb writes files on a developer's own machine, so what these tests
//! pin is not "does it produce the right TOML" (the unit tests in
//! `src/connect.rs` do that against the renderer) but the three properties an
//! operator's trust actually rests on:
//!
//! 1. `--dry-run` leaves the tree byte for byte identical.
//! 2. The user's own `~/.codex/config.toml` is never opened for writing.
//! 3. A second run changes nothing, and does not blow away the backup the
//!    first one took.
//!
//! Every test drives the real binary with a fixture `HOME` and `PATH` passed
//! through `Command::env`. Nothing here mutates this process's environment:
//! `scripts/check-env-mutation.sh` refuses that in production code and a test
//! that did it would race every other test in the binary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Path to the `sbproxy` binary built by Cargo for this test target.
fn sbproxy_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbproxy"))
}

/// A throwaway fixture: a fake `HOME`, and a `bin` directory that stands in
/// for `PATH`.
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "sbproxy-connect-cli-{}-{nanos}-{name}",
            std::process::id()
        ));
        let home = root.join("home");
        let bin = root.join("bin");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(&bin).expect("mkdir bin");
        Self { root, home, bin }
    }

    /// `~/.codex`, created on demand.
    fn codex_dir(&self) -> PathBuf {
        let dir = self.home.join(".codex");
        std::fs::create_dir_all(&dir).expect("mkdir .codex");
        dir
    }

    /// Put an executable of `name` on the fixture `PATH`, so the verb's probe
    /// reports the client as installed and on `PATH`.
    fn install_launcher(&self, name: &str) {
        let path = self.bin.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write launcher");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod launcher");
        }
    }

    /// Run the binary against this fixture. `HOME` and `PATH` are the only
    /// two variables the verb reads, plus `CODEX_HOME`, which is removed so a
    /// developer's own relocated Codex install cannot reach in.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(sbproxy_bin())
            .args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("PATH", &self.bin)
            .env_remove("CODEX_HOME")
            .env_remove("SB_CONFIG_FILE")
            .output()
            .expect("run sbproxy")
    }

    /// Every regular file under the fixture home, with its bytes. Compared
    /// whole rather than hashed, so a failure says which file moved.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        collect(&self.home, &self.home, &mut files);
        files
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn collect(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(base, &path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            let key = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
            out.insert(key, bytes);
        }
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A `~/.codex/config.toml` shaped like one Codex has actually been used with:
/// comments, top-level keys, and per-project state.
const USER_CONFIG_TOML: &str = r#"# the operator's own notes
model = "gpt-5"
model_reasoning_effort = "high"

[projects."/home/me/work"]
trust_level = "trusted"

[marketplaces.openai-bundled]
source_type = "builtin"
"#;

// --- 1. --dry-run changes nothing -------------------------------------

#[test]
fn dry_run_prints_the_diff_and_leaves_the_tree_byte_identical() {
    let fixture = Fixture::new("dryrun");
    fixture.install_launcher("codex");
    let config = fixture.codex_dir().join("config.toml");
    std::fs::write(&config, USER_CONFIG_TOML).expect("seed config.toml");

    let before = fixture.snapshot();
    let output = fixture.run(&["connect", "codex", "--dry-run"]);
    let after = fixture.snapshot();

    assert!(
        output.status.success(),
        "connect --dry-run failed: {}",
        stderr_of(&output)
    );
    assert_eq!(
        before,
        after,
        "--dry-run wrote to the tree; stdout was:\n{}",
        stdout_of(&output)
    );

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("would write: ~/.codex/sbproxy.config.toml"),
        "no plan line:\n{stdout}"
    );
    assert!(
        stdout.contains("+[model_providers.sbproxy]"),
        "no diff of the new provider block:\n{stdout}"
    );
    assert!(
        stdout.contains("nothing was written (--dry-run)"),
        "no closing statement:\n{stdout}"
    );
}

// --- 2. the user's own config.toml is never touched -------------------

#[test]
fn connect_writes_a_profile_of_its_own_and_never_touches_config_toml() {
    let fixture = Fixture::new("profile");
    fixture.install_launcher("codex");
    let config = fixture.codex_dir().join("config.toml");
    std::fs::write(&config, USER_CONFIG_TOML).expect("seed config.toml");

    let output = fixture.run(&["connect", "codex"]);
    assert!(
        output.status.success(),
        "connect failed: {}",
        stderr_of(&output)
    );

    assert_eq!(
        std::fs::read_to_string(&config).expect("read config.toml"),
        USER_CONFIG_TOML,
        "the operator's own config.toml was modified"
    );

    let profile = fixture.codex_dir().join("sbproxy.config.toml");
    let body = std::fs::read_to_string(&profile).expect("the profile should exist");
    assert!(body.contains("[model_providers.sbproxy]"), "{body}");
    assert!(
        body.contains("base_url = \"http://127.0.0.1:8080/v1\""),
        "{body}"
    );
    assert!(body.contains("env_key = \"SBPROXY_API_KEY\""), "{body}");
    assert!(body.contains("wire_api = \"responses\""), "{body}");

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("codex --profile sbproxy"),
        "the run has to say how to use what it wrote:\n{stdout}"
    );
    assert!(
        stdout.contains("undo: sbproxy disconnect"),
        "the run has to say how to undo itself:\n{stdout}"
    );

    // Nothing was staged and abandoned.
    let leftovers: Vec<String> = std::fs::read_dir(fixture.codex_dir())
        .expect("readdir")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

// --- 3. a second run is a no-op and keeps the first backup ------------

#[test]
fn a_second_connect_changes_nothing_and_preserves_the_first_backup() {
    let fixture = Fixture::new("idempotent");
    fixture.install_launcher("codex");
    let codex = fixture.codex_dir();
    // A profile the operator has already edited, so the first run has
    // something to back up and something to preserve.
    let profile = codex.join("sbproxy.config.toml");
    let hand_written = "# mine\nmodel_reasoning_effort = \"low\"\n";
    std::fs::write(&profile, hand_written).expect("seed profile");

    let first = fixture.run(&["connect", "codex"]);
    assert!(first.status.success(), "{}", stderr_of(&first));
    let after_first = std::fs::read_to_string(&profile).expect("read profile");
    assert!(
        after_first.contains("# mine") && after_first.contains("model_reasoning_effort"),
        "the operator's own lines were dropped:\n{after_first}"
    );

    let backup = codex.join("sbproxy.config.toml.sbproxy.bak");
    assert_eq!(
        std::fs::read_to_string(&backup).expect("read backup"),
        hand_written,
        "the backup must hold the file as it was before the first connect"
    );

    let snapshot = fixture.snapshot();
    let second = fixture.run(&["connect", "codex"]);
    assert!(second.status.success(), "{}", stderr_of(&second));
    assert_eq!(
        snapshot,
        fixture.snapshot(),
        "a second identical run rewrote the tree; stdout was:\n{}",
        stdout_of(&second)
    );
    assert!(
        stdout_of(&second).contains("unchanged: ~/.codex/sbproxy.config.toml already says this"),
        "the second run should say it did nothing:\n{}",
        stdout_of(&second)
    );

    // The load-bearing half: a third run that *does* change the file must
    // still not overwrite the pristine backup.
    let third = fixture.run(&["connect", "codex", "--base-url", "http://127.0.0.1:9999/v1"]);
    assert!(third.status.success(), "{}", stderr_of(&third));
    assert_eq!(
        std::fs::read_to_string(&backup).expect("read backup"),
        hand_written,
        "a later run overwrote the only copy of the operator's original"
    );
}

// --- 4. no credential flows through this verb -------------------------

#[test]
fn no_gateway_key_in_the_environment_reaches_stdout_stderr_or_the_file() {
    let fixture = Fixture::new("nokey");
    fixture.install_launcher("codex");
    fixture.codex_dir();

    const SENTINEL: &str = "sbp-do-not-leak-me-9d3f";
    let output = Command::new(sbproxy_bin())
        .args(["connect", "codex"])
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("PATH", &fixture.bin)
        .env("SBPROXY_API_KEY", SENTINEL)
        .env("ANTHROPIC_AUTH_TOKEN", SENTINEL)
        .env("OPENAI_API_KEY", SENTINEL)
        .env_remove("CODEX_HOME")
        .output()
        .expect("run sbproxy");

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        !stdout_of(&output).contains(SENTINEL),
        "a credential reached stdout"
    );
    assert!(
        !stderr_of(&output).contains(SENTINEL),
        "a credential reached stderr"
    );
    let body = std::fs::read_to_string(fixture.codex_dir().join("sbproxy.config.toml"))
        .expect("read profile");
    assert!(
        !body.contains(SENTINEL),
        "a credential was written into the config:\n{body}"
    );
    assert!(
        body.contains("env_key"),
        "the config should name the variable instead:\n{body}"
    );
}

// --- 5. detection tells the three states apart ------------------------

#[test]
fn an_uninstalled_client_named_on_the_command_line_is_an_error() {
    let fixture = Fixture::new("named-absent");
    let before = fixture.snapshot();
    let output = fixture.run(&["connect", "cursor"]);
    assert!(
        !output.status.success(),
        "naming a client that is not installed should fail"
    );
    assert!(
        stderr_of(&output).contains("cursor not found on this machine"),
        "unhelpful message: {}",
        stderr_of(&output)
    );
    assert_eq!(before, fixture.snapshot(), "something was written anyway");
}

#[test]
fn the_default_sweep_over_a_bare_home_writes_nothing_and_exits_clean() {
    let fixture = Fixture::new("bare");
    let before = fixture.snapshot();
    let output = fixture.run(&["connect"]);
    assert!(
        output.status.success(),
        "an empty machine is an answer, not a fault: {}",
        stderr_of(&output)
    );
    assert_eq!(before, fixture.snapshot(), "something was written anyway");
    let stdout = stdout_of(&output);
    for slug in ["codex", "claude-code", "cursor", "cline", "copilot"] {
        assert!(
            stdout.contains(slug),
            "{slug} missing from the report:\n{stdout}"
        );
    }
    assert!(
        stdout.matches("found: not installed").count() == 5,
        "every client should report absent:\n{stdout}"
    );
    assert!(
        !fixture.home.join(".codex").exists(),
        "a config directory was created for a client that is not installed"
    );
}

#[test]
fn an_install_off_path_is_reported_differently_from_one_on_path() {
    let off_path = Fixture::new("offpath");
    off_path.codex_dir();
    let seen = stdout_of(&off_path.run(&["connect", "codex", "--dry-run"]));
    assert!(
        seen.contains("state directory; no launcher on PATH"),
        "an install PATH cannot see should say so:\n{seen}"
    );

    let on_path = Fixture::new("onpath");
    on_path.install_launcher("codex");
    let seen = stdout_of(&on_path.run(&["connect", "codex", "--dry-run"]));
    assert!(seen.contains("(on PATH)"), "{seen}");
    assert!(
        seen.contains("backup: none, this file did not exist yet"),
        "installed-but-never-configured should read as a create:\n{seen}"
    );
}

// --- 6. disconnect reverses connect -----------------------------------

#[test]
fn disconnect_removes_the_profile_and_leaves_everything_else_alone() {
    let fixture = Fixture::new("disconnect");
    fixture.install_launcher("codex");
    let config = fixture.codex_dir().join("config.toml");
    std::fs::write(&config, USER_CONFIG_TOML).expect("seed config.toml");

    assert!(fixture.run(&["connect", "codex"]).status.success());
    let profile = fixture.codex_dir().join("sbproxy.config.toml");
    assert!(profile.is_file());

    let output = fixture.run(&["disconnect", "codex"]);
    assert!(
        output.status.success(),
        "disconnect failed: {}",
        stderr_of(&output)
    );
    assert!(!profile.exists(), "the profile should be gone");
    assert_eq!(
        std::fs::read_to_string(&config).expect("read config.toml"),
        USER_CONFIG_TOML,
        "disconnect touched the operator's own config.toml"
    );
    assert!(
        stdout_of(&output).contains("removed: ~/.codex/sbproxy.config.toml"),
        "{}",
        stdout_of(&output)
    );

    // Reversing twice is not an error.
    let again = fixture.run(&["disconnect", "codex"]);
    assert!(again.status.success(), "{}", stderr_of(&again));
    assert!(
        stdout_of(&again).contains("unchanged"),
        "{}",
        stdout_of(&again)
    );
}

// --- 7. the JSON surface ----------------------------------------------

#[test]
fn json_output_names_every_requested_client_and_its_status() {
    let fixture = Fixture::new("json");
    fixture.install_launcher("codex");
    fixture.install_launcher("claude");
    let output = fixture.run(&["connect", "--dry-run", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("connect --format json stdout is valid JSON");
    assert_eq!(parsed["action"], "connect");
    assert_eq!(parsed["dry_run"], true);
    assert_eq!(parsed["base_url"], "http://127.0.0.1:8080/v1");

    let clients = parsed["clients"].as_array().expect("clients array");
    assert_eq!(clients.len(), 5);
    let by_slug: BTreeMap<&str, &serde_json::Value> = clients
        .iter()
        .map(|entry| (entry["client"].as_str().unwrap_or_default(), entry))
        .collect();
    assert_eq!(by_slug["codex"]["status"], "would_write");
    assert_eq!(by_slug["claude-code"]["status"], "env_only");
    assert_eq!(
        by_slug["claude-code"]["env"]["ANTHROPIC_BASE_URL"],
        "http://127.0.0.1:8080"
    );
    assert_eq!(by_slug["cursor"]["status"], "not_installed");

    // The JSON surface must not carry a key field for anybody to fill in.
    assert!(
        !stdout.contains("api_key"),
        "the JSON report advertises a credential slot:\n{stdout}"
    );
}

// --- 8. a bad base URL is refused before anything is written ----------

#[test]
fn a_base_url_with_no_scheme_is_refused_and_writes_nothing() {
    let fixture = Fixture::new("badurl");
    fixture.install_launcher("codex");
    fixture.codex_dir();
    let before = fixture.snapshot();

    let output = fixture.run(&["connect", "codex", "--base-url", "127.0.0.1:8080"]);
    assert!(
        !output.status.success(),
        "a bare host:port should be refused"
    );
    assert!(
        stderr_of(&output).contains("must start with http:// or https://"),
        "unhelpful message: {}",
        stderr_of(&output)
    );
    assert_eq!(before, fixture.snapshot(), "something was written anyway");
}
