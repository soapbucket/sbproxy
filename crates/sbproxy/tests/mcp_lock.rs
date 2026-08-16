// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `sbproxy mcp lock` / `sbproxy mcp verify-lock` (WOR-2443).
//!
//! The tool-versioning gate reads a committed lockfile whose every entry
//! carries a `contract_digest`, and until these commands existed nothing
//! in the product produced one. An operator had to read `compat/digest.rs`
//! and reimplement RFC 8785 canonical JSON over an undocumented field
//! projection, so in practice the gate stayed off.
//!
//! These tests drive the real binary against a config whose federated
//! server is `type: openapi`, which derives its tools from the inline
//! spec rather than dialing an upstream. That keeps the test hermetic
//! while still exercising the whole path an operator uses: compile the
//! action the way boot does, discover through the same federation
//! handle, digest through the same owner the gate compares with, write
//! the file, then read it back.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-mcp-lock-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

/// A gateway federating one OpenAPI-backed server.
///
/// `summary` becomes the derived tool's description, which is the field
/// the drift test moves. It is part of the contract on purpose: the
/// description is what the model reads, so editing it changes what the
/// tool means even when the schema is untouched.
fn config(summary: &str) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway
        version: "1.0.0"
      refresh_interval: "1h"
      tool_versioning:
        lockfile: tool-versions.lock.yaml
        mode: block
      federated_servers:
        - type: openapi
          origin: "http://127.0.0.1:9"
          spec:
            openapi: "3.0.0"
            info:
              title: Pets
              version: "1.0"
            paths:
              "/pets":
                get:
                  operationId: listPets
                  summary: "{summary}"
"#
    )
}

/// Run a subcommand with `root` as the working directory.
///
/// The gate resolves a relative `tool_versioning.lockfile` against the
/// process working directory, so these commands have to as well. Running
/// from `root` is what makes that agreement observable rather than
/// assumed.
fn run(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .args(args)
        .current_dir(root)
        .env_remove("SB_CONFIG_FILE")
        .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
        .output()
        .expect("run sbproxy")
}

fn write_config(root: &Path, summary: &str) {
    std::fs::write(root.join("sb.yml"), config(summary)).expect("write config");
}

#[test]
fn lock_writes_a_baseline_that_verify_lock_then_accepts() {
    let root = temp_dir("roundtrip");
    write_config(&root, "List pets.");

    let locked = run(&root, &["mcp", "lock", "-f", "sb.yml"]);
    assert!(
        locked.status.success(),
        "mcp lock failed: {}{}",
        String::from_utf8_lossy(&locked.stdout),
        String::from_utf8_lossy(&locked.stderr)
    );

    // Written where the gate looks: relative to the working directory,
    // which is what `tool_versioning.lockfile` means at refresh time.
    let lockfile = root.join("tool-versions.lock.yaml");
    let yaml = std::fs::read_to_string(&lockfile).expect("lockfile written next to the run");

    // The digest recipe, asserted rather than assumed. v2 is the scheme
    // WOR-2387 defined, and the embedded contract is what lets a later
    // change be graded structurally instead of only detected.
    assert!(
        yaml.contains("mcp-contract-v2-sha256:"),
        "generator must emit the v2 scheme: {yaml}"
    );
    assert!(
        yaml.contains("contract:"),
        "each entry must embed its contract: {yaml}"
    );
    assert!(
        !yaml.contains("sha256:0000"),
        "a zeroed placeholder can never match, which is the state the shipped example was \
         stuck in: {yaml}"
    );
    assert!(yaml.contains("listPets"), "derived tool missing: {yaml}");

    // The acceptance criterion: the baseline this wrote is one the gate
    // agrees with. Nothing changed in between, so drift is a bug.
    let verified = run(&root, &["mcp", "verify-lock", "-f", "sb.yml"]);
    assert!(
        verified.status.success(),
        "verify-lock rejected a baseline that lock had just written: {}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_lock_exits_2_when_a_tool_contract_moves() {
    let root = temp_dir("drift");
    write_config(&root, "List pets.");
    assert!(
        run(&root, &["mcp", "lock", "-f", "sb.yml"])
            .status
            .success(),
        "baseline generation must succeed before drift can be measured"
    );

    // Same tool, different description: the contract moved without the
    // lockfile moving with it.
    write_config(&root, "List every pet, including archived ones.");

    let verified = run(&root, &["mcp", "verify-lock", "-f", "sb.yml"]);
    let stdout = String::from_utf8_lossy(&verified.stdout);
    // Exit 2, not 1, matching `models verify-lock`, so CI can tell drift
    // from a command that failed to run at all.
    assert_eq!(
        verified.status.code(),
        Some(2),
        "drift must exit 2 for CI; got {:?}: {stdout}{}",
        verified.status.code(),
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        stdout.contains("listPets") && stdout.contains("changed"),
        "the report must name the tool and what happened to it: {stdout}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_new_tool_is_reported_as_drift_rather_than_ignored() {
    let root = temp_dir("added");
    write_config(&root, "List pets.");
    assert!(run(&root, &["mcp", "lock", "-f", "sb.yml"])
        .status
        .success());

    // Add a second operation. A tool that appears after the baseline is
    // exactly the case `block_unlocked` exists for, so verify-lock has
    // to surface it rather than pass because everything it knew about
    // is unchanged.
    let with_second = config("List pets.").replace(
        r#"                  summary: "List pets.""#,
        "                  summary: \"List pets.\"\n              \"/pets/{id}\":\n                get:\n                  operationId: getPet\n                  summary: \"Fetch one pet.\"\n                  parameters:\n                    - name: id\n                      in: path\n                      required: true\n                      schema:\n                        type: string",
    );
    std::fs::write(root.join("sb.yml"), with_second).expect("write config");

    let verified = run(&root, &["mcp", "verify-lock", "-f", "sb.yml"]);
    let stdout = String::from_utf8_lossy(&verified.stdout);
    assert_eq!(
        verified.status.code(),
        Some(2),
        "an unlocked tool is drift: {stdout}{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        stdout.contains("getPet") && stdout.contains("added"),
        "the report must name the new tool: {stdout}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn regenerating_after_drift_keeps_the_changed_tool_in_the_baseline() {
    // The point of `mcp lock` is to accept a reviewed change, and the
    // config that change happens under is `mode: block`. Discovery runs
    // with the gate compiled out for exactly this reason: a live
    // block-mode gate filters the tools it judges in violation, so
    // regenerating through one would drop the tool whose contract moved.
    // The operator would get a lockfile that silently no longer mentions
    // it, and the next verify-lock would call that a removal.
    let root = temp_dir("regen");
    write_config(&root, "List pets.");
    assert!(run(&root, &["mcp", "lock", "-f", "sb.yml"])
        .status
        .success());

    write_config(&root, "List every pet, including archived ones.");
    assert_eq!(
        run(&root, &["mcp", "verify-lock", "-f", "sb.yml"])
            .status
            .code(),
        Some(2),
        "the description edit must register as drift first, or this test proves nothing"
    );

    let relocked = run(&root, &["mcp", "lock", "-f", "sb.yml"]);
    assert!(
        relocked.status.success(),
        "regeneration failed: {}",
        String::from_utf8_lossy(&relocked.stderr)
    );
    let yaml = std::fs::read_to_string(root.join("tool-versions.lock.yaml")).expect("regenerated");
    assert!(
        yaml.contains("listPets"),
        "the regenerated baseline dropped the tool it was regenerated for: {yaml}"
    );
    assert!(
        yaml.contains("including archived ones"),
        "the regenerated baseline still embeds the old contract: {yaml}"
    );
    assert!(
        run(&root, &["mcp", "verify-lock", "-f", "sb.yml"])
            .status
            .success(),
        "a freshly regenerated baseline must verify clean"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_lock_says_how_to_create_a_missing_baseline() {
    // The first thing an operator hits. "No such file" names the
    // problem; it does not name the command that fixes it, and the
    // whole point of this ticket is that the command was not
    // discoverable.
    let root = temp_dir("missing");
    write_config(&root, "List pets.");

    let verified = run(&root, &["mcp", "verify-lock", "-f", "sb.yml"]);
    assert!(!verified.status.success());
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(
        stderr.contains("sbproxy mcp lock"),
        "a missing lockfile must name the command that writes one: {stderr}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_config_with_no_mcp_action_says_so() {
    let root = temp_dir("no-mcp");
    std::fs::write(
        root.join("sb.yml"),
        r#"proxy:
  http_bind_port: 0
origins:
  "static.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#,
    )
    .expect("write config");

    let locked = run(&root, &["mcp", "lock", "-f", "sb.yml"]);
    assert!(!locked.status.success());
    let stderr = String::from_utf8_lossy(&locked.stderr);
    assert!(
        stderr.contains("no `type: mcp` action"),
        "the error must say what was missing: {stderr}"
    );

    let _ = std::fs::remove_dir_all(root);
}
