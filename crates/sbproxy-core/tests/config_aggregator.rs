// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The aggregator, end to end (WOR-2437, WOR-2438, WOR-2439).
//!
//! Every test here drives the real [`Aggregator`] against a fixture
//! cloner installed through the same [`FetchContext`] seam production
//! uses, so nothing about the composition, the change detection, the
//! failure policy or the publish path is stubbed. What the fixture
//! replaces is one subprocess: `git`.
//!
//! The publishing tests run against a real [`ConfigAuthority`] with a
//! real signing key and a real durable store, because "publishes through
//! the existing publish path" is the claim under test and a fake
//! publisher would prove only that the aggregator can call a function.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sbproxy_config::config_bundle::BundleMode;
use sbproxy_config::source::{
    Cloner, ConfigSourceError, FetchContext, FetchRequest, LsRemoteRequest, ResolvedRevision,
};
use sbproxy_config::types::ConfigAuthorityPublishConfig;
use sbproxy_core::config_aggregator::{
    aggregation_loop, AggregateError, Aggregator, AuthorityPublisher, CompositionPublisher,
    RoundOutcome,
};
use sbproxy_core::config_authority::ConfigAuthority;

// --- the fixture git surface -----------------------------------------

/// One repository the fixture serves: a commit and the files at it.
#[derive(Debug, Clone)]
struct Repo {
    commit: String,
    files: BTreeMap<String, String>,
}

/// A [`Cloner`] that serves committed fixtures instead of contacting a
/// repository.
///
/// It counts fetches and `ls-remote` calls separately, which is what
/// lets a test assert the clone path was *not* entered rather than
/// merely that the result was right. Both counters are what WOR-2438's
/// acceptance lines are actually about.
#[derive(Debug, Default)]
struct FixtureGit {
    repos: Mutex<BTreeMap<String, Repo>>,
    fetches: AtomicUsize,
    polls: AtomicUsize,
    /// Repositories that refuse to fetch, by URL.
    unreachable: Mutex<Vec<String>>,
    /// Repositories whose fetch fails while their poll still answers.
    /// A push the aggregator saw and could not read is a different state
    /// from a repository that is down, and it is the one that leaves an
    /// entry owed.
    fetch_unreachable: Mutex<Vec<String>>,
    /// Extra wall-clock every fetch takes, for the deadline tests.
    fetch_delay: Mutex<Duration>,
    /// Fetches seen so far, in order, for the concurrency assertions.
    seen: Mutex<Vec<String>>,
    /// Peak simultaneous fetches, for the bounded-pool assertion.
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    /// What `ls_remote` answers, when it should disagree with the
    /// commit a checkout reports. That is what an annotated tag does.
    ls_remote_sha: Mutex<Option<String>>,
    /// Extra wall-clock every `ls_remote` takes. The real one is a
    /// network round trip; the fixture's is instant, which is why the
    /// serial poll phase was invisible to the whole suite.
    poll_delay: Mutex<Duration>,
    /// Peak simultaneous polls, for the bounded-poll assertion.
    polls_in_flight: AtomicUsize,
    peak_polls_in_flight: AtomicUsize,
    /// Paths the checkout materializes as symlinks rather than files,
    /// pointing at the given target. That is what `git clone` does with
    /// a symlink a project repository committed.
    links: Mutex<BTreeMap<String, PathBuf>>,
    /// Paths the checkout materializes with raw bytes, so a test can
    /// produce a file that is there and is not readable as text.
    raw: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl FixtureGit {
    fn with(repo: &str, commit: &str, files: &[(&str, &str)]) -> Self {
        let fixture = Self::default();
        fixture.set(repo, commit, files);
        fixture
    }

    fn set(&self, repo: &str, commit: &str, files: &[(&str, &str)]) {
        let files = files
            .iter()
            .map(|(path, body)| ((*path).to_string(), (*body).to_string()))
            .collect();
        self.repos.lock().expect("repos").insert(
            repo.to_string(),
            Repo {
                commit: commit.to_string(),
                files,
            },
        );
    }

    fn break_repo(&self, repo: &str) {
        self.unreachable
            .lock()
            .expect("unreachable")
            .push(repo.to_string());
    }

    fn break_fetch(&self, repo: &str) {
        self.fetch_unreachable
            .lock()
            .expect("fetch unreachable")
            .push(repo.to_string());
    }

    fn unbreak_fetch(&self, repo: &str) {
        self.fetch_unreachable
            .lock()
            .expect("fetch unreachable")
            .retain(|entry| entry != repo);
    }

    fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    fn poll_count(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }

    fn peak_concurrency(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }

    fn peak_poll_concurrency(&self) -> usize {
        self.peak_polls_in_flight.load(Ordering::SeqCst)
    }

    /// Materialize `path` with bytes that are not valid UTF-8.
    fn write_raw(&self, path: &str, bytes: Vec<u8>) {
        self.raw
            .lock()
            .expect("raw")
            .insert(path.to_string(), bytes);
    }

    /// Materialize `path` as a symlink at `target` instead of a file.
    fn link(&self, path: &str, target: PathBuf) {
        self.links
            .lock()
            .expect("links")
            .insert(path.to_string(), target);
    }
}

/// The `Box<dyn Cloner>` a [`FetchContext`] takes, sharing one fixture.
struct SharedGit(Arc<FixtureGit>);

impl Cloner for SharedGit {
    fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
        self.0.fetches.fetch_add(1, Ordering::SeqCst);
        self.0
            .seen
            .lock()
            .expect("seen")
            .push(request.repo.to_string());
        let now = self.0.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.peak_in_flight.fetch_max(now, Ordering::SeqCst);
        // A refusal is immediate and a slow repository is slow. Sleeping
        // first would make "this host said no" indistinguishable from
        // "this host ran out of the round's budget", and the two are
        // counted differently.
        let refused = self.refusal(request.repo);
        let delay = *self.0.fetch_delay.lock().expect("delay");
        if refused.is_none() && !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let outcome = match refused {
            Some(error) => Err(error),
            None => self.materialize(request),
        };
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    fn ls_remote(
        &self,
        request: &LsRemoteRequest<'_>,
    ) -> Result<Option<String>, ConfigSourceError> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        let now = self.0.polls_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.peak_polls_in_flight.fetch_max(now, Ordering::SeqCst);
        let delay = *self.0.poll_delay.lock().expect("poll delay");
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        self.0.polls_in_flight.fetch_sub(1, Ordering::SeqCst);
        if self
            .0
            .unreachable
            .lock()
            .expect("unreachable")
            .iter()
            .any(|repo| repo == request.repo)
        {
            return Err(ConfigSourceError::Clone("fixture: unreachable".to_string()));
        }
        if let Some(sha) = self.0.ls_remote_sha.lock().expect("sha").clone() {
            return Ok(Some(sha));
        }
        Ok(self
            .0
            .repos
            .lock()
            .expect("repos")
            .get(request.repo)
            .map(|repo| repo.commit.clone()))
    }
}

impl SharedGit {
    /// Why this repository refuses to be fetched, if it does.
    fn refusal(&self, repo: &str) -> Option<ConfigSourceError> {
        let unreachable = self
            .0
            .unreachable
            .lock()
            .expect("unreachable")
            .iter()
            .chain(
                self.0
                    .fetch_unreachable
                    .lock()
                    .expect("fetch unreachable")
                    .iter(),
            )
            .any(|entry| entry == repo);
        unreachable.then(|| ConfigSourceError::Clone(format!("fixture: {repo} is unreachable")))
    }

    fn materialize(
        &self,
        request: &FetchRequest<'_>,
    ) -> Result<ResolvedRevision, ConfigSourceError> {
        if self
            .0
            .unreachable
            .lock()
            .expect("unreachable")
            .iter()
            .chain(
                self.0
                    .fetch_unreachable
                    .lock()
                    .expect("fetch unreachable")
                    .iter(),
            )
            .any(|repo| repo == request.repo)
        {
            return Err(ConfigSourceError::Clone(format!(
                "fixture: {} is unreachable",
                request.repo
            )));
        }
        let repos = self.0.repos.lock().expect("repos");
        let Some(repo) = repos.get(request.repo) else {
            return Err(ConfigSourceError::Clone(format!(
                "fixture: no repository at {}",
                request.repo
            )));
        };
        let links = self.0.links.lock().expect("links").clone();
        let raw = self.0.raw.lock().expect("raw").clone();
        for (path, body) in &repo.files {
            let full = request.dest.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| ConfigSourceError::Clone(error.to_string()))?;
            }
            // `git clone` materializes a committed symlink as a symlink,
            // which is the half of the trust boundary the checkout owns.
            if let Some(target) = links.get(path) {
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, &full)
                    .map_err(|error| ConfigSourceError::Clone(error.to_string()))?;
                #[cfg(not(unix))]
                let _ = target;
                continue;
            }
            match raw.get(path) {
                Some(bytes) => std::fs::write(&full, bytes),
                None => std::fs::write(&full, body),
            }
            .map_err(|error| ConfigSourceError::Clone(error.to_string()))?;
        }
        Ok(ResolvedRevision {
            repo: request.repo.to_string(),
            reference: request.revision.unwrap_or("HEAD").to_string(),
            commit: repo.commit.clone(),
        })
    }
}

fn context(git: &Arc<FixtureGit>) -> FetchContext {
    FetchContext::with_cloner(Box::new(SharedGit(Arc::clone(git))))
}

// --- documents --------------------------------------------------------

const CHECKOUT_PROFILE: &str = r#"
name: checkout
inputs:
  - name: upstream
    description: where the service actually lives
spec:
  api:
    base:
      action:
        type: proxy
        url: "{{vars.upstream}}"
      policies:
        - name: rate_limit
          type: rate_limiting
          requests_per_minute: 600
    environments:
      prod:
        policies:
          - name: rate_limit
            requests_per_minute: 6000
"#;

const BILLING_PROFILE: &str = r#"
name: billing
spec:
  api:
    base:
      action:
        type: proxy
        url: https://billing.internal
"#;

/// A runtime document with one entry, composed against a platform floor.
///
/// The `proxy:` block is the shipped shape, not a minimal one. Every
/// node that can run the in-process aggregator declares
/// `proxy.config_authority` by construction, and every entry with a
/// `credential:` needs a `proxy.secrets` backend in the same file to
/// resolve it against, exactly as `examples/origin-profiles/sb.yml`
/// does. Both are on `AUTHORITY_DENIED_PATHS`. A fixture that carried
/// only `http_bind_port` was a config no operator could write, and it
/// hid a payload that every real configuration would have had refused
/// (WOR-2432 review, Blocker 1). A hand-written `origins:` key is here
/// for the same reason: it has to reach the fleet, because the runtime
/// document is the aggregator's and not each subscriber's.
fn runtime(entries: &str) -> String {
    runtime_with_proxy(AGGREGATOR_NODE_PROXY, entries)
}

/// The offline half's runtime document: a single node with no config
/// authority at all.
///
/// `--out` is explicitly the path for a deployment that has none, and a
/// composed document carrying a `config_authority.publish` block whose
/// signing key does not exist is refused by `compile_config` for a
/// reason that has nothing to do with composition. The publish tests use
/// [`AGGREGATOR_NODE_PROXY`], which is the shape that matters there.
fn single_node_runtime(entries: &str) -> String {
    runtime_with_proxy(SINGLE_NODE_PROXY, entries)
}

/// The `proxy:` block of a node that runs the in-process aggregator.
///
/// `config_authority.publish` is here because the loop only starts where
/// one is; `secrets` is here because an entry with a `credential:` needs
/// a backend in the same file; `admin` carries a real password because a
/// publishing node's admin API guards a fleet-wide write and
/// `compile_config` refuses the shipped default there. All three are on
/// `AUTHORITY_DENIED_PATHS`, which is the point.
const AGGREGATOR_NODE_PROXY: &str = r#"proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: 0
    password: fixture-admin-password
  secrets:
    backends:
      - type: local
        name: ci
        entries:
          github-token: "local-dev-token"
  config_authority:
    publish:
      authority_id: fixture-authority
      key_id: fixture-key
      signing_key_file: /nonexistent/fixture.key
      store_dir: /nonexistent/store
      bind: 127.0.0.1:65535"#;

/// The `proxy:` block of a single node that composes to a file.
const SINGLE_NODE_PROXY: &str = r#"proxy:
  http_bind_port: 0
  secrets:
    backends:
      - type: local
        name: ci
        entries:
          github-token: "local-dev-token""#;

fn runtime_with_proxy(proxy: &str, entries: &str) -> String {
    format!(
        r#"
{proxy}
origins:
  "status.acme.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
origin_defaults:
  policies:
    - name: platform_waf
      type: waf
      locked: true
      owasp_crs:
        enabled: true
      action_on_match: block
origin_sources:
  tier: development
  aggregator:
    poll_interval_secs: 1
    debounce_secs: 0
    max_deferral_secs: 1
    concurrency: 4
    deadline_secs: 30
  entries:
{entries}
"#
    )
}

const ONE_ENTRY: &str = r#"    - name: checkout
      repo: https://example.test/checkout.git
      path: sbproxy/origin.yaml
      environment: prod
      inputs:
        upstream: https://checkout.internal
      hosts:
        api: [api.acme.test]
"#;

fn one_entry() -> String {
    runtime(ONE_ENTRY)
}

/// The same entry on a node with no config authority, for the offline
/// tests: `--out` exists for exactly that deployment.
fn one_entry_single_node() -> String {
    single_node_runtime(ONE_ENTRY)
}

fn aggregator(document: &str, git: &Arc<FixtureGit>) -> Aggregator {
    Aggregator::with_fetch_context(document, context(git)).expect("aggregator builds")
}

/// A publisher that records what it was handed and never refuses.
#[derive(Debug, Default)]
struct RecordingPublisher {
    published: Mutex<Vec<String>>,
}

impl CompositionPublisher for RecordingPublisher {
    fn publish(&self, config_yaml: &str) -> Result<u64, String> {
        let mut published = self.published.lock().expect("published");
        published.push(config_yaml.to_string());
        Ok(published.len() as u64)
    }
}

// --- WOR-2437: fetch, compose, publish --------------------------------

#[test]
fn the_aggregator_resolves_every_entry_composes_and_publishes_through_the_authority() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);

    let outcome = aggregator.run_round(&publisher).expect("round publishes");
    let RoundOutcome::Published { revision, outcome } = outcome else {
        panic!("the first round must publish");
    };
    assert_eq!(revision, 1, "the authority assigns the first revision");
    assert_eq!(outcome.origins, 1);
    assert_eq!(authority.current_revision(), 1);

    // The offline document really carries the origin, the floor, and the
    // environment layer, and it carries neither composition block.
    let composed: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&outcome.yaml).expect("composed document parses");
    assert!(composed.origins.contains_key("api.acme.test"));
    assert!(composed.origin_sources.is_none());
    assert!(composed.origin_defaults.is_none());
    assert!(
        outcome.yaml.contains("6000"),
        "the prod environment layer overrode the base rate limit: {}",
        outcome.yaml
    );
    assert!(
        outcome.yaml.contains("owasp_crs"),
        "the platform floor reached the composed origin"
    );
}

/// The published payload carries no path a subscriber owns outright.
///
/// The fixture runtime document declares `proxy.config_authority`,
/// `proxy.secrets` and `proxy.admin`, all three on
/// `AUTHORITY_DENIED_PATHS`, because that is what a real aggregator node
/// looks like: the in-process loop only starts where an authority is
/// configured, and an entry with a `credential:` needs a backend in the
/// same file to resolve it against.
///
/// A payload built by removing two keys from the runtime document keeps
/// all three, so `validate_publish_payload` refuses every round with
/// `denied_path` and nothing is ever published (WOR-2432 review,
/// Blocker 1). The payload is built up from the origins instead, so the
/// refusal is unreachable by shape rather than by list.
#[test]
fn the_published_payload_carries_no_denied_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let document = one_entry();
    // The fixture is only worth anything if it really carries them.
    for denied in ["proxy.config_authority", "proxy.secrets", "proxy.admin"] {
        let key = denied.split('.').next_back().expect("a key");
        assert!(
            document.contains(&format!("  {key}:")),
            "the fixture runtime document must declare {denied}, or this test proves nothing"
        );
    }
    assert!(
        !sbproxy_config::denied_paths_in(&document)
            .expect("the runtime document parses")
            .is_empty(),
        "the runtime document itself is full of denied paths, which is the whole point"
    );

    let mut aggregator = aggregator(&document, &git);
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);
    let outcome = aggregator
        .run_round(&publisher)
        .expect("a real runtime document must publish");
    let RoundOutcome::Published { revision, outcome } = outcome else {
        panic!("the first round must publish");
    };
    assert_eq!(revision, 1);
    assert_eq!(authority.current_revision(), 1);

    let denied = sbproxy_config::denied_paths_in(&outcome.payload).expect("the payload parses");
    assert!(
        denied.is_empty(),
        "the published payload names path(s) every subscriber owns: {denied:?}\n{}",
        outcome.payload
    );

    // And it is the right narrow shape, not merely a clean one.
    let payload: serde_yaml::Mapping =
        serde_yaml::from_str(&outcome.payload).expect("the payload is a mapping");
    let keys: Vec<String> = payload
        .keys()
        .filter_map(|key| key.as_str().map(str::to_string))
        .collect();
    assert_eq!(
        keys,
        vec!["origin_defaults".to_string(), "origins".to_string()],
        "the payload is built up from the origins overlay, not cut down from the document"
    );
    let parsed: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&outcome.payload).expect("the payload is a config document");
    assert!(
        parsed.origins.contains_key("api.acme.test"),
        "the composed origin travels"
    );
    assert!(
        parsed.origins.contains_key("status.acme.test"),
        "and so does the hand-written one, because the runtime document is the aggregator's and \
         not each subscriber's"
    );
    assert!(
        parsed.origin_defaults.is_some(),
        "`origin_defaults` is deliberately not a denied path: it is the platform's floor channel"
    );
}

#[test]
fn a_profile_referencing_an_env_var_does_not_read_the_aggregators_environment() {
    // The confined pass is the boundary, and this is the test WOR-2437
    // names for it. `PATH` is set in every process this can run in, so a
    // resolver that read the environment would substitute it rather than
    // refuse, and the refusal is what proves the seal.
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: "https://collect.example/${PATH}"
"#;
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "b".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", profile)],
    ));
    // No `inputs:` on the entry, because this profile declares none: the
    // refusal under test has to be the confinement, not a binding error.
    let document = runtime(
        r#"    - name: checkout
      repo: https://example.test/checkout.git
      path: sbproxy/origin.yaml
      hosts:
        api: [api.acme.test]
"#,
    );
    let mut aggregator = aggregator(&document, &git);
    let error = aggregator
        .compose()
        .expect_err("a confined document is sealed");
    let message = error.to_string();
    assert!(
        message.contains("PATH") || message.to_lowercase().contains("environment"),
        "the refusal names the reference: {message}"
    );
    let real_path = std::env::var("PATH").unwrap_or_default();
    assert!(
        !real_path.is_empty() && !message.contains(&real_path),
        "the refusal must not carry the resolved value: {message}"
    );
}

#[test]
fn entry_fetches_run_concurrently_under_a_bounded_pool() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..6 {
        let repo = format!("https://example.test/svc{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "c".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: svc{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n      \
             hosts:\n        api: [svc{index}.acme.test]\n"
        ));
    }
    *git.fetch_delay.lock().expect("delay") = Duration::from_millis(120);
    let document = runtime(&entries).replace("concurrency: 4", "concurrency: 3");
    let mut aggregator = aggregator(&document, &git);
    let outcome = aggregator.compose().expect("composes");
    assert_eq!(outcome.origins, 6);
    assert!(
        git.peak_concurrency() > 1,
        "fetches must overlap; peak was {}",
        git.peak_concurrency()
    );
    assert!(
        git.peak_concurrency() <= 3,
        "the pool is bounded by `concurrency`; peak was {}",
        git.peak_concurrency()
    );
}

#[test]
fn the_global_deadline_is_enforced_and_names_what_was_outstanding() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..4 {
        let repo = format!("https://example.test/slow{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "d".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: slow{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n      \
             hosts:\n        api: [slow{index}.acme.test]\n"
        ));
    }
    // One worker, each fetch slower than the whole round's budget, so
    // the second entry can never get a turn.
    *git.fetch_delay.lock().expect("delay") = Duration::from_millis(1_200);
    let document = runtime(&entries)
        .replace("concurrency: 4", "concurrency: 1")
        .replace("deadline_secs: 30", "deadline_secs: 1");
    let mut aggregator = aggregator(&document, &git);
    let error = aggregator.compose().expect_err("the deadline fires");
    let AggregateError::Deadline {
        outstanding, total, ..
    } = &error
    else {
        panic!("expected a deadline refusal, got {error}");
    };
    assert_eq!(*total, 4);
    assert!(
        outstanding.len() >= 2,
        "at least the entries that never started are outstanding: {outstanding:?}"
    );
    assert!(
        error.to_string().contains("deadline_secs"),
        "the message tells the operator which knob to turn: {error}"
    );
}

#[test]
fn one_unreachable_entry_is_named_and_the_others_keep_their_last_resolved_state() {
    let git = Arc::new(FixtureGit::default());
    git.set(
        "https://example.test/checkout.git",
        &"e".repeat(40),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    );
    git.set(
        "https://example.test/billing.git",
        &"f".repeat(40),
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    );
    let document = runtime(
        r#"    - name: checkout
      repo: https://example.test/checkout.git
      path: sbproxy/origin.yaml
      inputs:
        upstream: https://checkout.internal
      hosts:
        api: [api.acme.test]
    - name: billing
      repo: https://example.test/billing.git
      path: sbproxy/origin.yaml
      hosts:
        api: [billing.acme.test]
"#,
    );
    let mut aggregator = aggregator(&document, &git);
    let first = aggregator.compose().expect("the first round resolves both");
    assert_eq!(first.origins, 2);
    assert!(first.failed.is_empty());

    // Now billing goes away. The poll is what notices: an `ls-remote`
    // that errors is not evidence that nothing happened, so the entry is
    // treated as moved and the fetch is what settles it.
    git.break_repo("https://example.test/billing.git");
    let moved = aggregator.poll();
    assert_eq!(
        moved,
        vec!["billing".to_string()],
        "an unreachable remote reports as moved rather than as unchanged"
    );
    let second = aggregator
        .compose()
        .expect("one unreachable entry does not discard the round");
    assert_eq!(
        second.origins, 2,
        "billing's host survives on its last resolved document"
    );
    assert_eq!(second.failed.len(), 1, "exactly one entry is reported");
    let failure = &second.failed[0];
    assert_eq!(failure.entry, "billing");
    assert_eq!(
        failure.reused_commit.as_deref(),
        Some("f".repeat(40).as_str())
    );
    assert!(
        second
            .resolved
            .iter()
            .any(|entry| entry.entry == "billing" && entry.from_cache),
        "the reuse is recorded on the entry, not only on the failure"
    );
    assert!(
        second
            .resolved
            .iter()
            .any(|entry| entry.entry == "checkout" && !entry.from_cache),
        "the reachable entry is unaffected"
    );
}

#[test]
fn an_entry_that_never_resolved_aborts_the_round_rather_than_dropping_its_hosts() {
    let git = Arc::new(FixtureGit::default());
    git.set(
        "https://example.test/checkout.git",
        &"a".repeat(40),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    );
    git.break_repo("https://example.test/checkout.git");
    let mut aggregator = aggregator(&one_entry(), &git);
    let error = aggregator.compose().expect_err("nothing to fall back to");
    let AggregateError::Unresolvable { entries, .. } = &error else {
        panic!("expected an unresolvable refusal, got {error}");
    };
    assert_eq!(entries, &["checkout".to_string()]);
    assert!(
        error.to_string().contains("missing their hosts"),
        "the message says why publishing anyway would be wrong: {error}"
    );
}

#[test]
fn a_composed_document_that_fails_validation_is_not_published() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `url:` is required on a proxy action, so the composed origin
    // compiles as a document and fails to construct as a pipeline, which
    // is exactly the class `validate_publish_payload` exists to catch.
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
"#;
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", profile)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);
    let error = aggregator
        .run_round(&publisher)
        .expect_err("a document that will not construct is refused");
    assert_eq!(
        authority.current_revision(),
        0,
        "no revision was consumed by a refused payload"
    );
    let message = error.to_string();
    assert!(
        message.contains("url") || message.contains("checkout"),
        "the refusal points at what is wrong: {message}"
    );
}

#[test]
fn a_realistic_composition_measures_its_own_headroom_against_the_bundle_limit() {
    // WOR-2437 asks for the realistic number before the refusal is
    // written, because "it might be too big" without an arithmetic is
    // not a limit anybody can plan around. This composes the shape a
    // real profile has (a proxy action, three policies from the floor,
    // one project policy, one modifier) against fifty hosts and pins
    // the per-origin cost, so a change that triples it goes red here
    // rather than at somebody's first fleet-sized publish.
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal.example.com
        preserve_query: true
      policies:
        - name: rate_limit
          type: rate_limiting
          requests_per_minute: 1200
          burst: 240
        - name: project_body_cap
          type: request_limit
          max_body_size: 1048576
      response_modifiers:
        - name: service_headers
          headers:
            set:
              X-Service: checkout
"#;
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", profile)],
    ));
    let hosts: Vec<String> = (0..50)
        .map(|index| format!("svc{index}.acme.test"))
        .collect();
    let entries = format!(
        "    - name: checkout\n      repo: https://example.test/checkout.git\n      \
         path: sbproxy/origin.yaml\n      hosts:\n        api:\n{}",
        hosts
            .iter()
            .map(|host| format!("          - {host}\n"))
            .collect::<String>()
    );
    let mut aggregator = aggregator(&runtime(&entries), &git);
    let composed = aggregator.compose().expect("composes");
    assert_eq!(
        composed.origins, 50,
        "an origin is materialized once per host"
    );
    let per_origin = composed.yaml.len() / composed.origins;
    let headroom = sbproxy_config::MAX_CONFIG_YAML_BYTES / per_origin;
    // The measured figures at the time this landed: 435 bytes per
    // composed origin against this floor, so the 4 MiB bundle limit is
    // reached at about 9,600 hosts. The assertion is a band rather than
    // an equality, because a formatting change should not fail a test
    // about orders of magnitude.
    assert!(
        (200..=1200).contains(&per_origin),
        "a realistic composed origin is a few hundred bytes; measured {per_origin}"
    );
    assert!(
        headroom > 3_000,
        "the bundle limit has to be far enough away that an operator plans for hosts rather \
         than for bytes; measured headroom {headroom} origins"
    );
}

#[test]
fn a_composed_document_past_the_size_limit_names_the_limit_and_the_origin_count() {
    // A realistic shape rather than one giant string: many origins, each
    // materialized once per host. The profile below composes to about
    // 700 bytes of YAML per origin against this floor, so the 4 MiB
    // bundle limit is reached somewhere near six thousand hosts. The
    // fixture reaches it with a large per-origin body instead of six
    // thousand hosts, and the assertion is on the reported arithmetic.
    let filler = "x".repeat(64 * 1024);
    let profile = format!(
        r#"
name: checkout
spec:
  api:
    base:
      action:
        type: static
        status_code: 200
        content_type: text/plain
        body: "{filler}"
"#
    );
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..70 {
        let repo = format!("https://example.test/big{index}.git");
        git.set(
            &repo,
            &format!("{index:02}{}", "a".repeat(38)),
            &[("sbproxy/origin.yaml", profile.as_str())],
        );
        entries.push_str(&format!(
            "    - name: big{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n      \
             hosts:\n        api: [big{index}.acme.test]\n"
        ));
    }
    let mut aggregator = aggregator(&runtime(&entries), &git);
    let error = aggregator.compose().expect_err("past the bundle limit");
    let AggregateError::TooLarge {
        bytes,
        limit,
        origins,
        bytes_per_origin,
        ..
    } = &error
    else {
        panic!("expected a size refusal, got {error}");
    };
    assert_eq!(*limit, sbproxy_config::MAX_CONFIG_YAML_BYTES);
    assert!(*bytes > *limit);
    assert_eq!(*origins, 70);
    assert!(*bytes_per_origin > 0);
    let message = error.to_string();
    assert!(
        message.contains("MAX_CONFIG_YAML_BYTES") && message.contains("70 origins"),
        "the message names the limit and how many origins materialized: {message}"
    );
    assert!(
        message.contains("once per host"),
        "and says what makes the count grow: {message}"
    );
}

#[test]
fn rollback_restores_the_previous_composed_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);
    aggregator.run_round(&publisher).expect("first publish");

    // A project pushes a change, and it publishes as revision 2.
    git.set(
        "https://example.test/checkout.git",
        &"b".repeat(40),
        &[(
            "sbproxy/origin.yaml",
            &CHECKOUT_PROFILE.replace("requests_per_minute: 6000", "requests_per_minute: 9"),
        )],
    );
    // The poll is what notices; a compose fetches what the last poll saw
    // move, and does not poll again, so that a round costs one
    // `ls-remote` per repository rather than two.
    assert_eq!(aggregator.poll(), vec!["checkout".to_string()]);
    let second = aggregator.run_round(&publisher).expect("second publish");
    let RoundOutcome::Published { revision, outcome } = second else {
        panic!("a moved project publishes");
    };
    assert_eq!(revision, 2);
    assert!(outcome.yaml.contains("requests_per_minute: 9"));

    let rollback = authority.rollback().expect("rollback");
    assert_eq!(rollback.restored_from_revision, 1);
    assert_eq!(rollback.outcome.revision, 3, "a rollback is a new revision");
    assert_eq!(authority.current_revision(), 3);
}

#[test]
fn one_round_writes_every_metric_the_ticket_names() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let publisher = RecordingPublisher::default();
    aggregator.run_round(&publisher).expect("round publishes");

    let families = prometheus::gather();
    let names: Vec<&str> = families
        .iter()
        .map(prometheus::proto::MetricFamily::name)
        .collect();
    for expected in [
        "sbproxy_aggregate_entries",
        "sbproxy_aggregate_compose_duration_seconds",
        "sbproxy_aggregate_published_revision",
        "sbproxy_aggregate_rounds_total",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} must be written by a round; saw {names:?}"
        );
    }
    let entries = families
        .iter()
        .find(|family| family.name() == "sbproxy_aggregate_entries")
        .expect("the entries gauge");
    let labels: Vec<String> = entries
        .get_metric()
        .iter()
        .flat_map(|metric| {
            metric
                .get_label()
                .iter()
                .map(|pair| pair.value().to_string())
        })
        .collect();
    for outcome in ["resolved", "unchanged", "failed"] {
        assert!(
            labels.contains(&outcome.to_string()),
            "every outcome is written on every round, including the zeroes: {labels:?}"
        );
    }
}

// --- WOR-2438: change detection and coalescing ------------------------

#[test]
fn an_annotated_tag_is_compared_against_its_peeled_commit() {
    // `git ls-remote <repo> refs/tags/v1` prints the tag object and,
    // under a `^{}` suffix, the commit it points at. Comparing the tag
    // object against a checkout's commit would find them different
    // forever and clone on every round, and a production tier pins with
    // `refs/tags/<name>`, so this is the main case rather than an edge.
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    ));
    // The fixture answers `ls_remote` with the tag object and `fetch`
    // with the peeled commit, which is the disagreement under test.
    *git.ls_remote_sha.lock().expect("sha") = Some("t".repeat(40));
    let document = runtime(
        r#"    - name: checkout
      repo: https://example.test/checkout.git
      revision: refs/tags/v1.4.2
      path: sbproxy/origin.yaml
      hosts:
        api: [api.acme.test]
"#,
    );
    let mut aggregator = aggregator(&document, &git);
    aggregator.compose().expect("first compose");
    let fetches = git.fetch_count();
    for _ in 0..3 {
        assert!(
            aggregator.poll().is_empty(),
            "the tag has not moved, so nothing should be reported"
        );
        aggregator.compose().expect("later composes");
    }
    assert_eq!(
        git.fetch_count(),
        fetches,
        "a tag that did not move must not be re-cloned every round"
    );
}

#[test]
fn polling_uses_ls_remote_and_does_not_clone_when_the_sha_is_unchanged() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    aggregator.compose().expect("first compose");
    let after_first = git.fetch_count();
    assert_eq!(after_first, 1);

    let moved = aggregator.poll();
    assert!(moved.is_empty(), "nothing moved: {moved:?}");
    assert_eq!(
        git.fetch_count(),
        after_first,
        "the clone path must not be entered by a poll"
    );
    assert!(git.poll_count() > 0, "the cheap path is the one that ran");

    aggregator.compose().expect("second compose");
    assert_eq!(
        git.fetch_count(),
        after_first,
        "an unchanged sha does not clone on compose either"
    );
}

#[test]
fn an_entry_pinned_to_a_full_sha_is_polled_once_and_never_again() {
    let sha = "a".repeat(40);
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        &sha,
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    ));
    let document = runtime(&format!(
        "    - name: checkout\n      repo: https://example.test/checkout.git\n      \
         revision: {sha}\n      path: sbproxy/origin.yaml\n      hosts:\n        \
         api: [api.acme.test]\n"
    ));
    let mut aggregator = aggregator(&document, &git);
    aggregator.compose().expect("first compose");
    let polls_after_first = git.poll_count();
    assert_eq!(
        polls_after_first, 0,
        "a full sha answers itself; the remote is never asked"
    );
    for _ in 0..5 {
        assert!(aggregator.poll().is_empty(), "a pinned sha cannot move");
    }
    assert_eq!(
        git.poll_count(),
        0,
        "and still nothing was asked of the remote"
    );
}

#[test]
fn two_entries_sharing_a_repo_and_revision_resolve_with_one_fetch() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/mono.git",
        "a".repeat(40).as_str(),
        &[
            ("services/checkout/origin.yaml", CHECKOUT_PROFILE),
            ("services/billing/origin.yaml", BILLING_PROFILE),
        ],
    ));
    let document = runtime(
        r#"    - name: checkout
      repo: https://example.test/mono.git
      path: services/checkout/origin.yaml
      inputs:
        upstream: https://checkout.internal
      hosts:
        api: [api.acme.test]
    - name: billing
      repo: https://example.test/mono.git
      path: services/billing/origin.yaml
      hosts:
        api: [billing.acme.test]
"#,
    );
    let mut aggregator = aggregator(&document, &git);
    let outcome = aggregator.compose().expect("composes");
    assert_eq!(outcome.origins, 2, "both entries composed");
    assert_eq!(
        git.fetch_count(),
        1,
        "one repository at one revision is one fetch"
    );
}

#[test]
fn a_round_with_no_movement_publishes_nothing_and_the_revision_does_not_advance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);
    aggregator.run_round(&publisher).expect("first round");
    assert_eq!(authority.current_revision(), 1);

    for _ in 0..3 {
        let outcome = aggregator.run_round(&publisher).expect("later rounds");
        assert!(
            matches!(outcome, RoundOutcome::Unchanged { .. }),
            "an unchanged composition publishes nothing"
        );
    }
    assert_eq!(
        authority.current_revision(),
        1,
        "the published revision does not advance"
    );
}

#[test]
fn the_loop_publishes_once_for_a_fleet_that_stops_moving() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let publisher = RecordingPublisher::default();
    // The bound counts poll cycles rather than compositions, which is
    // the only bound that can be reached: a fleet where nothing moves
    // composes nothing, so a loop counting compositions would never
    // return. Three polls, one movement (the first), one publish.
    aggregation_loop(&mut aggregator, &publisher, Some(3));
    let published = publisher.published.lock().expect("published");
    assert_eq!(
        published.len(),
        1,
        "three poll cycles against an unmoving fleet publish exactly once"
    );
    assert!(
        git.poll_count() >= 2,
        "and it really kept polling after the publish; polls were {}",
        git.poll_count()
    );
}

// --- WOR-2439: offline composition ------------------------------------

#[test]
fn out_writes_a_composed_document_that_validates_and_carries_no_origin_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry_single_node(), &git);
    let composed = aggregator.compose().expect("composes");
    Aggregator::write_composed(&composed, &out).expect("writes");

    let written = std::fs::read_to_string(&out).expect("read back");
    let parsed: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&written).expect("the written document parses");
    assert!(
        parsed.origin_sources.is_none(),
        "a composed output is not a source of further composition; re-composing it would loop"
    );
    assert!(parsed.origin_defaults.is_none());
    assert!(parsed.origins.contains_key("api.acme.test"));
    // The same validation `sbproxy validate` runs, so "it boots
    // unmodified" is a claim this file checks rather than asserts.
    sbproxy_config::compile_config(&written).expect("the written document compiles");
}

#[test]
fn the_composed_output_is_byte_identical_across_two_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let first = {
        let mut aggregator = aggregator(&one_entry_single_node(), &git);
        let composed = aggregator.compose().expect("composes");
        let path = dir.path().join("first.yml");
        Aggregator::write_composed(&composed, &path).expect("writes");
        std::fs::read_to_string(&path).expect("read")
    };
    let second = {
        // A fresh aggregator, so nothing carries over between runs.
        let mut aggregator = aggregator(&one_entry_single_node(), &git);
        let composed = aggregator.compose().expect("composes");
        let path = dir.path().join("second.yml");
        Aggregator::write_composed(&composed, &path).expect("writes");
        std::fs::read_to_string(&path).expect("read")
    };
    assert_eq!(
        first, second,
        "the same inputs at the same revisions produce a byte-identical file, so a CI diff means \
         something"
    );
}

#[test]
fn out_writes_nothing_at_all_when_an_entry_will_not_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    let git = Arc::new(FixtureGit::default());
    git.set(
        "https://example.test/checkout.git",
        &"a".repeat(40),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    );
    git.break_repo("https://example.test/checkout.git");
    let mut aggregator = aggregator(&one_entry_single_node(), &git);
    assert!(aggregator.compose().is_err(), "the resolve fails");
    assert!(
        !out.exists(),
        "no partial file is left where a node would boot from it"
    );
    // And the temporary the writer would have used is not left behind
    // either, which is the half a naive `write` gets wrong.
    assert!(!out.with_extension("sbproxy-aggregate-tmp").exists());
}

#[test]
fn the_composed_header_names_every_source_entry_and_its_resolved_sha() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry_single_node(), &git);
    let composed = aggregator.compose().expect("composes");
    let header = composed.header();
    assert!(header.starts_with("# composed by sbproxy aggregate"));
    assert!(header.contains("checkout"));
    assert!(header.contains("https://example.test/checkout.git"));
    assert!(
        header.contains(&"a".repeat(40)),
        "the resolved sha is what makes the file traceable: {header}"
    );
    // The header really sits above a real document, checked against the
    // file rather than against an in-memory string, because the file is
    // what lands in a repository.
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    Aggregator::write_composed(&composed, &out).expect("writes");
    let written = std::fs::read_to_string(&out).expect("read back");
    assert!(written.starts_with(&header));
    assert!(written.contains("origins:"));
    assert!(
        written.contains("api.acme.test"),
        "and the document under the header is the composed one"
    );
}

#[test]
fn dry_run_reports_what_would_change_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry_single_node(), &git);
    let composed = aggregator.compose().expect("composes");

    // Nothing there yet.
    assert!(
        Aggregator::diff_against(&composed, &out)
            .expect("diff")
            .is_none(),
        "an absent file is reported as absent rather than as an empty diff"
    );

    Aggregator::write_composed(&composed, &out).expect("writes");
    let unchanged = Aggregator::diff_against(&composed, &out)
        .expect("diff")
        .expect("the file exists now");
    assert!(unchanged.is_empty(), "no changes against its own output");

    git.set(
        "https://example.test/checkout.git",
        &"b".repeat(40),
        &[(
            "sbproxy/origin.yaml",
            &CHECKOUT_PROFILE.replace("requests_per_minute: 6000", "requests_per_minute: 42"),
        )],
    );
    assert_eq!(aggregator.poll(), vec!["checkout".to_string()]);
    let moved = aggregator.compose().expect("composes again");
    let diff = Aggregator::diff_against(&moved, &out)
        .expect("diff")
        .expect("the file exists");
    assert!(
        diff.iter().any(|line| line.contains("42")),
        "the change is reported: {diff:?}"
    );
    let on_disk = std::fs::read_to_string(&out).expect("read");
    assert!(
        !on_disk.contains("requests_per_minute: 42"),
        "a diff writes nothing"
    );
}

// --- shared authority fixture ----------------------------------------

/// A publish block an operator could actually write, in a tempdir.
fn publish_config(dir: &Path) -> ConfigAuthorityPublishConfig {
    let key_path = dir.join("authority-signing.key");
    std::fs::write(&key_path, BASE64.encode([9u8; 32])).expect("write signing key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("tighten signing key permissions");
    }
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let publish = ConfigAuthorityPublishConfig {
        authority_id: "aggregator-test".to_string(),
        key_id: "authority-2026-08".to_string(),
        signing_key_file: key_path.display().to_string(),
        store_dir: dir.join("authority-store").display().to_string(),
        bind: format!("127.0.0.1:{port}"),
        tls: None,
        rate_limit_per_subscriber_per_minute: 1_000,
        rate_limit_total_per_minute: 1_000,
        archive_keep: sbproxy_config::config_authority::DEFAULT_ARCHIVE_KEEP,
    };
    publish.validate().expect("fixture publish validates");
    publish
}

// --- the review's findings, each with the test that would have caught it

/// The entry gauges are written on the abort paths too.
///
/// The gauge's own doc and `docs/configuration.md` both promise "every
/// outcome on every round including the zeroes, so a failure that clears
/// shows as the drop rather than as a series that stops moving". That
/// used to be false on exactly the two paths an operator alerts on: a
/// partition that takes out every repository returned `Unresolvable`
/// with the gauges left showing the last good round, which reads as
/// evidence of absence (WOR-2432 review, Major 2).
#[test]
fn the_entry_gauges_are_written_when_the_round_aborts() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..3 {
        let repo = format!("https://example.test/down{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "a".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        git.break_repo(&repo);
        entries.push_str(&format!(
            "    - name: down{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n      \
             hosts:\n        api: [down{index}.acme.test]\n"
        ));
    }
    // A good round first, so the gauge holds numbers that would be stale
    // rather than absent. Absent and stale look different to an alert
    // and the stale one is worse.
    {
        let healthy = Arc::new(FixtureGit::with(
            "https://example.test/checkout.git",
            "a".repeat(40).as_str(),
            &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
        ));
        aggregator(&one_entry(), &healthy)
            .compose()
            .expect("a healthy round");
    }
    assert_eq!(gauge_value("failed"), 0, "the healthy round left failed=0");

    let mut aggregator = aggregator(&runtime(&entries), &git);
    let error = aggregator
        .compose()
        .expect_err("nothing has ever resolved, so the round aborts");
    assert!(matches!(error, AggregateError::Unresolvable { .. }));
    assert_eq!(
        gauge_value("failed"),
        3,
        "an abort has to move the gauge an operator alerts on"
    );
    assert_eq!(gauge_value("resolved"), 0);
}

/// The current value of one `sbproxy_aggregate_entries` series.
fn gauge_value(outcome: &str) -> i64 {
    prometheus::gather()
        .iter()
        .find(|family| family.name() == "sbproxy_aggregate_entries")
        .and_then(|family| {
            family
                .get_metric()
                .iter()
                .find(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|pair| pair.name() == "outcome" && pair.value() == outcome)
                })
                .map(|metric| metric.get_gauge().value() as i64)
        })
        .unwrap_or(-1)
}

/// The poll phase runs under the same bounded pool the fetch phase does.
///
/// Serially it was neither bounded nor deadline-capped, so a handful of
/// blackholing git hosts turned a two-minute poll interval into a
/// continuous poll storm against the healthy repositories while nothing
/// composed at all. Invisible to the whole suite, because the fixture's
/// `ls_remote` returned instantly and honored no delay unlike its
/// `fetch` (WOR-2432 review, Major 3).
#[test]
fn the_poll_phase_is_bounded_and_runs_concurrently() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..6 {
        let repo = format!("https://example.test/slowpoll{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "a".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: slowpoll{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n \
             \x20    hosts:\n        api: [slowpoll{index}.acme.test]\n"
        ));
    }
    *git.poll_delay.lock().expect("poll delay") = Duration::from_millis(150);
    let document = runtime(&entries).replace("concurrency: 4", "concurrency: 3");
    let mut aggregator = aggregator(&document, &git);
    let started = Instant::now();
    let moved = aggregator.poll();
    let elapsed = started.elapsed();
    assert_eq!(moved.len(), 6, "every entry is new, so every entry moved");
    assert!(
        git.peak_poll_concurrency() > 1,
        "polls must overlap; peak was {}",
        git.peak_poll_concurrency()
    );
    assert!(
        git.peak_poll_concurrency() <= 3,
        "and stay under `concurrency`; peak was {}",
        git.peak_poll_concurrency()
    );
    assert!(
        elapsed < Duration::from_millis(6 * 150),
        "six serial polls would take {}ms; this took {}ms",
        6 * 150,
        elapsed.as_millis()
    );
}

/// A poll that outruns the round's deadline does not hold the cycle.
#[test]
fn the_poll_phase_stops_at_the_round_deadline() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..4 {
        let repo = format!("https://example.test/blackhole{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "a".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: blackhole{index}\n      repo: {repo}\n      path: \
             sbproxy/origin.yaml\n      timeout_secs: 60\n      hosts:\n        \
             api: [blackhole{index}.acme.test]\n"
        ));
    }
    *git.poll_delay.lock().expect("poll delay") = Duration::from_millis(700);
    let document = runtime(&entries)
        .replace("concurrency: 4", "concurrency: 1")
        .replace("deadline_secs: 30", "deadline_secs: 1");
    let mut aggregator = aggregator(&document, &git);
    let started = Instant::now();
    let moved = aggregator.poll();
    let elapsed = started.elapsed();
    assert_eq!(
        moved.len(),
        4,
        "an entry whose poll never got a turn is reported as moved, which is the safe direction"
    );
    assert!(
        elapsed < Duration::from_millis(1_600),
        "the round's one-second deadline bounds the poll phase; four serial 700ms polls would \
         be 2.8s and four serial 60s timeouts would be four minutes. This took {}ms",
        elapsed.as_millis()
    );
    assert!(
        git.poll_count() < 4,
        "a poll that never got a turn before the deadline must not have run; {} of 4 ran",
        git.poll_count()
    );
}

/// A reordering is a change, and `--dry-run` has to say so.
///
/// The diff was a set difference, so two documents with the same lines
/// in a different order compared equal, and `report_aggregate_dry_run`
/// read the empty diff as "unchanged" and exited 0. Swapping two
/// services' `hosts:` between entries is exactly that shape, and a CI
/// gate keyed on exit 2 would have passed while `--out` wrote a
/// genuinely different file (WOR-2432 review, Major 4).
#[test]
fn a_reordering_is_reported_as_a_change_rather_than_as_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    let git = Arc::new(FixtureGit::default());
    git.set(
        "https://example.test/a.git",
        &"a".repeat(40),
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    );
    git.set(
        "https://example.test/b.git",
        &"b".repeat(40),
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    );
    // Two *different* profiles, so swapping which entry claims which
    // host really changes the composed content while leaving the line
    // multiset identical. That is the shape a set difference cannot see.
    git.set(
        "https://example.test/b.git",
        &"b".repeat(40),
        &[(
            "sbproxy/origin.yaml",
            &BILLING_PROFILE.replace("https://billing.internal", "https://ledger.internal"),
        )],
    );
    let swap = |first: &str, second: &str| {
        single_node_runtime(&format!(
            "    - name: alpha\n      repo: https://example.test/a.git\n      path: \
             sbproxy/origin.yaml\n      hosts:\n        api: [{first}]\n    - name: beta\n      \
             repo: https://example.test/b.git\n      path: sbproxy/origin.yaml\n      hosts:\n \
             \x20      api: [{second}]\n"
        ))
    };

    let before = aggregator(&swap("one.acme.test", "two.acme.test"), &git)
        .compose()
        .expect("composes");
    Aggregator::write_composed(&before, &out).expect("writes");

    // The two profiles are identical, so swapping which entry claims
    // which host produces a document with the same line multiset.
    let after = aggregator(&swap("two.acme.test", "one.acme.test"), &git)
        .compose()
        .expect("composes");
    let second = dir.path().join("second.yml");
    Aggregator::write_composed(&after, &second).expect("writes");
    assert_ne!(
        std::fs::read_to_string(&out).expect("read back"),
        std::fs::read_to_string(&second).expect("read back"),
        "the fixture has to actually differ, or this test proves nothing"
    );
    assert_eq!(
        std::fs::read_to_string(&out)
            .expect("read")
            .lines()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>(),
        std::fs::read_to_string(&second)
            .expect("read")
            .lines()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>(),
        "and it has to differ only in order, which is the case a set difference cannot see"
    );

    let diff = Aggregator::diff_against(&after, &out)
        .expect("diff")
        .expect("the file exists");
    assert!(
        !diff.is_empty(),
        "a document whose lines are the same in a different order is still a different document"
    );
}

/// A project committing its profile as a symlink is refused.
///
/// The traversal guard constrained `entry.path`, which the platform
/// writes. `git clone` materializes symlinks, so the untrusted half of
/// the boundary could point the profile at any file the composing
/// process can read (WOR-2432 review, Major 6).
#[cfg(unix)]
#[test]
fn a_profile_committed_as_a_symlink_is_refused_rather_than_followed() {
    let secret = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(secret.path(), "name: stolen\nspec: {}\n").expect("write the target");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    git.link("sbproxy/origin.yaml", secret.path().to_path_buf());
    let mut aggregator = aggregator(&one_entry(), &git);
    let error = aggregator.compose().expect_err("a symlink is refused");
    let message = error.to_string();
    assert!(
        message.contains("symbolic link"),
        "the refusal says what it refused: {message}"
    );
    assert!(
        !message.contains("stolen"),
        "and never carries the target's contents: {message}"
    );
    // A dropped `\` continuation renders as a run of spaces in the
    // middle of a sentence an operator reads (WOR-2432 re-review,
    // Minor 5). `cargo fmt` cannot see it, because rustfmt does not
    // reformat string literals without `format_strings`.
    assert!(
        !message.contains("  "),
        "the refusal reads as one sentence, with no dropped line continuation: {message:?}"
    );
}

/// A profile past the read cap is refused before it is allocated.
///
/// `read_to_string` had no bound and `MAX_CONFIG_YAML_BYTES` was checked
/// after the read, after two parses and after the merge. One project
/// committing a large generated blob would take down the one process
/// the whole fleet composes in, and recover into the same read next
/// round (WOR-2432 review, Major 7).
#[test]
fn a_profile_past_the_read_cap_is_refused() {
    let oversized = format!(
        "name: checkout\n# {}\nspec: {{}}\n",
        "x".repeat(
            usize::try_from(sbproxy_config::source::MAX_CHECKOUT_FILE_BYTES).unwrap_or(0) + 16
        )
    );
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", oversized.as_str())],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let error = aggregator
        .compose()
        .expect_err("an oversized profile is refused");
    let message = error.to_string();
    assert!(
        message.contains("past the") && message.contains("byte limit"),
        "the refusal names the cap: {message}"
    );
}

/// The loop re-reads the runtime document between rounds.
///
/// `spawn` read the file once and the aggregator kept it for the process
/// lifetime, so a SIGHUP or a config-watcher reload updated the node's
/// own pipeline and `GET /admin/origin-composition` while the aggregator
/// kept publishing the boot-time document. The two halves of one admin
/// response disagreed and the operator's only signal was that nothing
/// happened (WOR-2432 review, Major 8).
#[test]
fn the_loop_re_reads_the_runtime_document_between_rounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sb.yml");
    let git = Arc::new(FixtureGit::default());
    git.set(
        "https://example.test/checkout.git",
        &"a".repeat(40),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    );
    git.set(
        "https://example.test/billing.git",
        &"b".repeat(40),
        &[("sbproxy/origin.yaml", BILLING_PROFILE)],
    );
    std::fs::write(&path, one_entry()).expect("write the runtime document");

    let mut aggregator =
        Aggregator::from_path(&path, context(&git)).expect("the aggregator reads the file");
    let publisher = RecordingPublisher::default();
    // Through the loop rather than through a refresh helper, because the
    // loop is the seam that was broken: `spawn` read the file once and
    // nothing re-read it for the process lifetime.
    aggregation_loop(&mut aggregator, &publisher, Some(1));
    {
        let published = publisher.published.lock().expect("published");
        assert_eq!(published.len(), 1, "the first cycle publishes");
        assert!(!published[0].contains("billing.acme.test"));
    }

    // The platform engineer adds a service and reloads. Nothing restarts
    // the aggregator.
    let with_two = runtime(&format!(
        "{ONE_ENTRY}    - name: billing\n      repo: https://example.test/billing.git\n      \
         path: sbproxy/origin.yaml\n      hosts:\n        api: [billing.acme.test]\n"
    ));
    std::fs::write(&path, &with_two).expect("rewrite the runtime document");

    aggregation_loop(&mut aggregator, &publisher, Some(1));
    let published = publisher.published.lock().expect("published");
    assert_eq!(
        published.len(),
        2,
        "the changed document is a new composition, so it publishes"
    );
    assert!(
        published[1].contains("billing.acme.test"),
        "and the new entry's origins reach the fleet without a restart: {}",
        published[1]
    );
}

/// A restart does not republish what the authority already serves.
///
/// The digest lived only in memory, so a restart composed the same
/// payload, saw no previous digest, and published a byte-identical
/// revision, which is a full pipeline rebuild on every subscriber
/// (WOR-2432 review, Minor 10).
#[test]
fn a_seeded_digest_stops_a_restart_republishing_the_same_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let authority = Arc::new(
        ConfigAuthority::from_config(&publish_config(dir.path())).expect("authority builds"),
    );
    let publisher = AuthorityPublisher::new(Arc::clone(&authority), BundleMode::Overlay);
    aggregator(&one_entry(), &git)
        .run_round(&publisher)
        .expect("the first process publishes");
    assert_eq!(authority.current_revision(), 1);
    let digest = authority
        .current_content_digest()
        .expect("the authority is serving something");

    // A second process, same document, same repositories.
    let mut restarted = aggregator(&one_entry(), &git);
    restarted.seed_published_digest(digest);
    let outcome = restarted
        .run_round(&publisher)
        .expect("the restarted process runs a round");
    assert!(
        matches!(outcome, RoundOutcome::Unchanged { .. }),
        "a restart must not republish a payload the authority is already serving"
    );
    assert_eq!(authority.current_revision(), 1);
}

/// A one-shot publish reports the entries it actually resolved.
///
/// The CLI composed once for `--explain` and the summary, then called
/// `run_round`, which composed again; the second pass found everything
/// cached and reported every entry as `unchanged`, so
/// `sbproxy_aggregate_entries{outcome="resolved"}` read zero immediately
/// after a publish that resolved every entry (WOR-2432 review, Minor
/// 11).
#[test]
fn a_one_shot_publish_reports_the_entries_it_resolved() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    let publisher = RecordingPublisher::default();
    let composed = aggregator.compose().expect("composes once");
    assert_eq!(gauge_value("resolved"), 1);
    let outcome = aggregator
        .publish_composed(composed, &publisher)
        .expect("publishes the composition already in hand");
    assert!(matches!(outcome, RoundOutcome::Published { .. }));
    assert_eq!(
        gauge_value("resolved"),
        1,
        "publishing a composition must not recompose it and report every entry as unchanged"
    );
    assert_eq!(git.fetch_count(), 1, "and must not fetch a second time");
}

/// The confinement seam refuses every host-backed reference form.
///
/// The `${VAR}` case was the only one pinned at this seam; `env:`,
/// `file:` and `vault://env/` were pinned one layer down in
/// `confined_template` (WOR-2432 review, Minor 13).
#[test]
fn every_host_backed_reference_form_is_refused_at_the_aggregator_seam() {
    for reference in [
        "${PATH}",
        "env:PATH",
        "file:/etc/passwd",
        "vault://env/PATH",
    ] {
        // Each form as a whole value, which is what a host-backed
        // reference is: the confined pass asks whether a value *is* one,
        // not whether a URL happens to contain the characters.
        let profile = format!(
            "name: checkout\nspec:\n  api:\n    base:\n      action:\n        type: proxy\n      \
             \x20 url: \"{reference}\"\n"
        );
        let git = Arc::new(FixtureGit::with(
            "https://example.test/checkout.git",
            "a".repeat(40).as_str(),
            &[("sbproxy/origin.yaml", profile.as_str())],
        ));
        let document = runtime(
            r#"    - name: checkout
      repo: https://example.test/checkout.git
      path: sbproxy/origin.yaml
      hosts:
        api: [api.acme.test]
"#,
        );
        let error = aggregator(&document, &git).compose().err();
        let Some(error) = error else {
            panic!("`{reference}` composed instead of being refused");
        };
        let message = error.to_string();
        assert!(
            !message.contains("/usr/bin") && !message.contains("root:"),
            "and the refusal carries no resolved host value: {message}"
        );
    }
}

/// With `debounce_secs` above `poll_interval_secs`, a bounded run still
/// composes for the window it opened.
///
/// The last window is never closed by a `decide` in that configuration,
/// so a `--polls n` run observed movement and then exited without
/// composing for it, which is a silent no-op a cron-shaped invocation
/// would never notice (WOR-2432 review, Minor 15).
#[test]
fn a_bounded_run_drains_a_window_the_debounce_left_open() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    // The fixture already polls every second; the window is what moves.
    let document = one_entry()
        .replace("debounce_secs: 0", "debounce_secs: 600")
        .replace("max_deferral_secs: 1", "max_deferral_secs: 600");
    let mut aggregator = aggregator(&document, &git);
    let publisher = RecordingPublisher::default();
    aggregation_loop(&mut aggregator, &publisher, Some(1));
    assert_eq!(
        publisher.published.lock().expect("published").len(),
        1,
        "a bounded run that saw movement must compose for it before it returns"
    );
}

/// A profile that is there but unreadable says which of the two it is.
///
/// "Not in the repository at the resolved revision" is the wrong answer
/// for a file that is there and is not UTF-8, and the two send an
/// operator to different places (WOR-2432 review, Minor 16).
#[test]
fn a_profile_that_is_there_but_not_utf8_is_reported_as_such() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", "placeholder")],
    ));
    let mut aggregator = aggregator(&one_entry(), &git);
    // Compose once so the checkout shape is exercised, then replace the
    // file with bytes that are not UTF-8 on the next fetch.
    git.set(
        "https://example.test/checkout.git",
        &"b".repeat(40),
        &[("sbproxy/origin.yaml", "placeholder")],
    );
    git.write_raw("sbproxy/origin.yaml", vec![0xff, 0xfe, 0xfd]);
    let error = aggregator
        .compose()
        .expect_err("unreadable bytes are refused");
    let message = error.to_string();
    assert!(
        message.contains("could not be read") || message.contains("UTF-8"),
        "the refusal distinguishes unreadable from missing: {message}"
    );
    assert!(
        !message.contains("is not in the repository"),
        "and does not claim the file is absent when it is there: {message}"
    );
}

/// The poll `compose()` takes before a fetch runs under the round's pool
/// and its deadline too.
///
/// `poll()` was put under the bounded pool and `compose()` was not: for
/// every group it was about to fetch it called `poll_one` in order,
/// bounded only by that entry's own `timeout_secs`, default 60. Ten
/// blackholing repositories then cost ten minutes inside one `compose()`
/// before the first fetch started, and by then the round deadline had
/// passed and every group was reported outstanding. That is the failure
/// the round set out to remove, moved one function over, and the suite
/// could not see it because every compose test set `fetch_delay` only
/// (WOR-2432 re-review, Major 1).
#[test]
fn the_pre_fetch_poll_runs_under_the_round_pool_and_deadline() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..6 {
        let repo = format!("https://example.test/slowcompose{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "a".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: slowcompose{index}\n      repo: {repo}\n      path: \
             sbproxy/origin.yaml\n      timeout_secs: 60\n      hosts:\n        \
             api: [slowcompose{index}.acme.test]\n"
        ));
    }
    *git.poll_delay.lock().expect("poll delay") = Duration::from_millis(150);
    let document = runtime(&entries).replace("concurrency: 4", "concurrency: 3");
    let mut aggregator = aggregator(&document, &git);
    let started = Instant::now();
    let outcome = aggregator.compose().expect("composes");
    let elapsed = started.elapsed();
    assert_eq!(outcome.resolved.len(), 6, "every entry resolves");
    assert!(
        git.peak_poll_concurrency() > 1,
        "the pre-fetch polls must overlap; peak was {}",
        git.peak_poll_concurrency()
    );
    assert!(
        git.peak_poll_concurrency() <= 3,
        "and stay under `concurrency`; peak was {}",
        git.peak_poll_concurrency()
    );
    assert!(
        elapsed < Duration::from_millis(6 * 150),
        "six serial pre-fetch polls would take {}ms; this took {}ms",
        6 * 150,
        elapsed.as_millis()
    );
}

/// An edit that moves no repository still reaches the fleet.
///
/// The loop re-read the document and then threw the answer away: the
/// only thing that opened a coalescing window was `poll()` reporting
/// repository movement. So raising a floor in `origin_defaults`, or
/// changing an entry's `hosts:`, `inputs:`, `environment:` or `path:`,
/// composed nothing and published nothing, and the operator's signal was
/// that the reload appeared to succeed and the fleet did not change
/// (WOR-2432 re-review, Major 2).
#[test]
fn an_edit_that_moves_no_repository_still_reaches_the_fleet() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sb.yml");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    std::fs::write(&path, one_entry()).expect("write the runtime document");

    let mut aggregator =
        Aggregator::from_path(&path, context(&git)).expect("the aggregator reads the file");
    let publisher = RecordingPublisher::default();
    aggregation_loop(&mut aggregator, &publisher, Some(1));
    {
        let published = publisher.published.lock().expect("published");
        assert_eq!(published.len(), 1, "the first cycle publishes");
        assert!(!published[0].contains("second.acme.test"));
    }

    // The platform engineer binds the same profile to a second host.
    // No repository moved: same repo, same revision, same commit.
    let with_two_hosts = one_entry().replace(
        "        api: [api.acme.test]\n",
        "        api: [api.acme.test, second.acme.test]\n",
    );
    assert_ne!(with_two_hosts, one_entry(), "the fixture edit has to apply");
    std::fs::write(&path, &with_two_hosts).expect("rewrite the runtime document");

    aggregation_loop(&mut aggregator, &publisher, Some(1));
    let published = publisher.published.lock().expect("published");
    assert_eq!(
        published.len(),
        2,
        "a document-only edit is a new composition, so it publishes"
    );
    assert!(
        published[1].contains("second.acme.test"),
        "and the new binding reaches the fleet: {}",
        published[1]
    );
    assert_eq!(
        git.fetch_count(),
        1,
        "composing for a document edit costs no fetch: the profile is cached"
    );
}

/// A fetch that failed stays owed after the document is edited.
///
/// `refresh_document` cleared `dirty` and left `observed` holding the
/// new sha, so the next poll compared equal and never re-reported the
/// movement. An entry whose fetch had failed then composed from its
/// cached profile forever, reported as a healthy round, and no later
/// poll could re-detect the push (WOR-2432 re-review, Major 3).
#[test]
fn a_failed_fetch_is_still_owed_after_the_document_is_edited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sb.yml");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    std::fs::write(&path, one_entry()).expect("write the runtime document");
    let mut aggregator =
        Aggregator::from_path(&path, context(&git)).expect("the aggregator reads the file");
    let publisher = RecordingPublisher::default();
    aggregation_loop(&mut aggregator, &publisher, Some(1));

    // The project pushes a rewritten profile and the repository goes
    // unreachable before the aggregator can read it. The same profile
    // with one number changed, so the entry's `inputs:` binding still
    // matches what the profile declares and the only thing under test is
    // whether the push was read at all.
    let rewritten =
        CHECKOUT_PROFILE.replace("requests_per_minute: 6000", "requests_per_minute: 7000");
    git.set(
        "https://example.test/checkout.git",
        "b".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", rewritten.as_str())],
    );
    // The poll answers with the new sha; the fetch is what fails, so the
    // aggregator has recorded the movement and has not read the tree.
    git.break_fetch("https://example.test/checkout.git");
    aggregation_loop(&mut aggregator, &publisher, Some(1));

    // The platform engineer edits the document for an unrelated reason,
    // and the repository comes back.
    let edited = one_entry().replace(
        "        api: [api.acme.test]\n",
        "        api: [api.acme.test, third.acme.test]\n",
    );
    std::fs::write(&path, &edited).expect("rewrite the runtime document");
    git.unbreak_fetch("https://example.test/checkout.git");

    aggregation_loop(&mut aggregator, &publisher, Some(1));
    let published = publisher.published.lock().expect("published");
    let last = published.last().expect("something published");
    assert!(
        last.contains("7000"),
        "the push the failed fetch owed has to be re-read, not dropped: {last}"
    );
}

/// A hand-written origin that reaches a host file is refused where it
/// composes, not where it publishes.
///
/// The payload carries the aggregator node's own `origins:` and each
/// entry's `overrides:`, and `validate_publish_payload` runs
/// `check_confined_document` over the whole thing. `spec_file`,
/// `rego_module_path`, `module_path` and `sha1_file` are all legal
/// inside an origin and all on `HOST_FILE_KEYS`, so a node whose own
/// `origins:` validates against an OpenAPI document on disk had every
/// round refused with `Confinement`, which is the Blocker's failure
/// shape on a narrower configuration. `--out` and `--dry-run` saw
/// nothing at all (WOR-2432 re-review, Major 4).
#[test]
fn a_hand_written_origin_reaching_a_host_file_is_refused_at_compose() {
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let document = one_entry().replace(
        "      body: ok\n",
        "      body: ok\n    policies:\n      - name: contract\n        type: \
         openapi_validation\n        spec_file: /etc/sbproxy/openapi.yaml\n",
    );
    assert!(
        document.contains("spec_file"),
        "the fixture edit has to apply"
    );
    let mut aggregator = aggregator(&document, &git);
    let error = aggregator
        .compose()
        .expect_err("a payload the authority would refuse is refused here");
    let message = error.to_string();
    assert!(
        message.contains("spec_file"),
        "the refusal names the key an operator has to change: {message}"
    );
}

/// A group whose fetch failed is counted as failed on the deadline path.
///
/// The "finished" set was `unchanged || fetched.contains_key(...)`, and
/// `fetch_groups` inserts a failure into that map as `Err(_)`, so a
/// group that failed fast counted as resolved and only the entries that
/// never got a turn reached `failed`. That is the same "reads as
/// evidence of absence" the gauge fix was about, one degree smaller
/// (WOR-2432 re-review, Minor 7).
#[test]
fn a_failed_group_counts_as_failed_when_the_round_times_out() {
    let git = Arc::new(FixtureGit::default());
    let mut entries = String::new();
    for index in 0..4 {
        let repo = format!("https://example.test/mixed{index}.git");
        git.set(
            &repo,
            &format!("{index}{}", "a".repeat(39)),
            &[("sbproxy/origin.yaml", BILLING_PROFILE)],
        );
        entries.push_str(&format!(
            "    - name: mixed{index}\n      repo: {repo}\n      path: sbproxy/origin.yaml\n \
             \x20    hosts:\n        api: [mixed{index}.acme.test]\n"
        ));
    }
    // `mixed0` refuses immediately. `mixed1` takes longer than the whole
    // round, so it finishes past the deadline and the last two never get
    // a turn. One worker, so the order is the group order.
    git.break_repo("https://example.test/mixed0.git");
    *git.fetch_delay.lock().expect("delay") = Duration::from_millis(1_200);
    let document = runtime(&entries)
        .replace("concurrency: 4", "concurrency: 1")
        .replace("deadline_secs: 30", "deadline_secs: 1");
    let mut aggregator = aggregator(&document, &git);
    let error = aggregator.compose().expect_err("the deadline passes");
    assert!(
        matches!(error, AggregateError::Deadline { .. }),
        "the round ends on the deadline: {error}"
    );
    assert_eq!(
        gauge_value("failed"),
        3,
        "the refusal and the two entries that never got a turn are all failures"
    );
    assert_eq!(
        gauge_value("resolved"),
        1,
        "and only the entry that really fetched is a resolution"
    );
}

/// A file that differs only in its trailing newline is a change.
///
/// `line_diff` works on `str::lines()`, which drops the trailing
/// newline and any `\r`, so two texts that differ only there produced an
/// empty diff. `report_aggregate_dry_run` reads the diff's emptiness as
/// the changed decision, so `--dry-run` printed "already holds this
/// composition" and exited 0 while `--out` would have rewritten the file
/// (WOR-2432 re-review, Minor 6).
#[test]
fn a_difference_only_in_line_endings_is_still_reported_as_a_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("composed.yml");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        &[("sbproxy/origin.yaml", CHECKOUT_PROFILE)],
    ));
    let mut aggregator = aggregator(&one_entry_single_node(), &git);
    let composed = aggregator.compose().expect("composes");
    Aggregator::write_composed(&composed, &out).expect("writes");

    let written = std::fs::read_to_string(&out).expect("read back");
    // CRLF, which is what a checkout on Windows or a normalizing CI step
    // produces. `str::lines()` strips the `\r`, so the line vectors are
    // identical while the bytes are not.
    let crlf = written.replace('\n', "\r\n");
    assert_ne!(crlf, written, "the fixture edit has to change the bytes");
    assert_eq!(
        crlf.lines().collect::<Vec<_>>(),
        written.lines().collect::<Vec<_>>(),
        "and has to be invisible to a line diff, or this test proves nothing"
    );
    std::fs::write(&out, &crlf).expect("rewrite with CRLF");
    let diff = Aggregator::diff_against(&composed, &out)
        .expect("diffs")
        .expect("the file exists");
    assert!(
        !diff.is_empty(),
        "a file whose bytes differ is a change, whatever `lines()` makes of it"
    );
}

/// A symlinked directory component cannot walk the read out of the
/// checkout.
///
/// The leaf-link case had a test and the canonicalize-and-compare branch
/// did not, so the half of the guard that catches `sbproxy` linked at
/// `/etc` had never been watched go red (WOR-2432 re-review, Minor 9).
#[cfg(unix)]
#[test]
fn a_symlinked_directory_component_is_refused_rather_than_followed() {
    let outside = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        outside.path().join("origin.yaml"),
        "name: stolen\nspec: {}\n",
    )
    .expect("write the target");
    let git = Arc::new(FixtureGit::with(
        "https://example.test/checkout.git",
        "a".repeat(40).as_str(),
        // The directory itself is the committed entry, so the checkout
        // materializes `sbproxy` as a link and `sbproxy/origin.yaml`
        // resolves through it.
        &[("sbproxy", "")],
    ));
    git.link("sbproxy", outside.path().to_path_buf());
    let mut aggregator = aggregator(&one_entry(), &git);
    let error = aggregator
        .compose()
        .expect_err("a path that resolves outside the checkout is refused");
    let message = error.to_string();
    assert!(
        message.contains("resolves outside the checkout"),
        "the refusal names what it refused: {message}"
    );
    assert!(
        !message.contains("stolen"),
        "and never carries the target's contents: {message}"
    );
}
