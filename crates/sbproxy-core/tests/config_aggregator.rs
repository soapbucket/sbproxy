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
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

    fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    fn poll_count(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }

    fn peak_concurrency(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
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
        let delay = *self.0.fetch_delay.lock().expect("delay");
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let outcome = self.materialize(request);
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    fn ls_remote(
        &self,
        request: &LsRemoteRequest<'_>,
    ) -> Result<Option<String>, ConfigSourceError> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
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
        for (path, body) in &repo.files {
            let full = request.dest.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| ConfigSourceError::Clone(error.to_string()))?;
            }
            std::fs::write(&full, body)
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
fn runtime(entries: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
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

fn one_entry() -> String {
    runtime(
        r#"    - name: checkout
      repo: https://example.test/checkout.git
      path: sbproxy/origin.yaml
      environment: prod
      inputs:
        upstream: https://checkout.internal
      hosts:
        api: [api.acme.test]
"#,
    )
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

    // The composed document really carries the origin, the floor, and
    // the environment layer, and it carries neither composition block.
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
    let AggregateError::Unresolvable { entries } = &error else {
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
    let timings = aggregator.timings().clone();
    let publisher = RecordingPublisher::default();
    // The bound counts poll cycles rather than compositions, which is
    // the only bound that can be reached: a fleet where nothing moves
    // composes nothing, so a loop counting compositions would never
    // return. Three polls, one movement (the first), one publish.
    aggregation_loop(&mut aggregator, &publisher, &timings, Some(3));
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
    let mut aggregator = aggregator(&one_entry(), &git);
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
        let mut aggregator = aggregator(&one_entry(), &git);
        let composed = aggregator.compose().expect("composes");
        let path = dir.path().join("first.yml");
        Aggregator::write_composed(&composed, &path).expect("writes");
        std::fs::read_to_string(&path).expect("read")
    };
    let second = {
        // A fresh aggregator, so nothing carries over between runs.
        let mut aggregator = aggregator(&one_entry(), &git);
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
    let mut aggregator = aggregator(&one_entry(), &git);
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
    let mut aggregator = aggregator(&one_entry(), &git);
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
    let mut aggregator = aggregator(&one_entry(), &git);
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
    };
    publish.validate().expect("fixture publish validates");
    publish
}
