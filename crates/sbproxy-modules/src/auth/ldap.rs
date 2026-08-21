//! WOR-2519: `ldap_auth` provider, directory-bind authentication.
//!
//! The client presents HTTP Basic credentials; the provider composes a
//! bind DN from a configured attribute plus `base_dn` and attempts an
//! LDAP simple bind against the directory with the supplied password.
//! The bind result is the only signal used: the password is never
//! stored, never forwarded upstream, and never logged.
//!
//! # Bind model
//!
//! This is the direct-bind (DN template) model used by Apache APISIX's
//! `ldap-auth` plugin: DN = `<uid_attribute>=<username>,<base_dn>`,
//! with `uid_attribute` defaulting to `cn`. The alternative
//! search-then-bind model (bind as a service account, search for the
//! user's entry by filter, then bind as the found DN), used by nginx's
//! LDAP auth reference implementation and by most IdP LDAP federation
//! backends, supports directories whose login attribute is not part of
//! the entry DN, but requires managing a standing service-account
//! credential and doubles the round-trips per request. Direct bind
//! covers the confirmed target deployments and keeps this provider
//! credential-free at rest; search-then-bind can be added later as an
//! additive config shape without breaking this one.
//!
//! # Security posture
//!
//! * A plaintext `ldap://` URL without StartTLS is refused at config
//!   load unless `allow_insecure: true` is set explicitly. The refusal
//!   is the default because a simple bind transmits the password in
//!   the clear (RFC 4513 section 6.3.1 calls out this exposure).
//! * An empty password is refused before any dial. RFC 4513 section
//!   5.1.2 defines a name-plus-empty-password simple bind as an
//!   *unauthenticated* bind, which directories commonly accept with a
//!   success result code; treating that success as proof of identity
//!   is the classic LDAP auth bypass.
//! * The username is escaped per RFC 4514 before DN composition so a
//!   crafted username cannot splice additional RDNs (for example
//!   `alice,cn=admin`) into the bind DN.
//! * Directory unreachable fails closed: the caller maps it to a
//!   refusal, never an allow. This provider adds a network round-trip
//!   to the request hot path (unlike every other built-in auth type
//!   except `forward_auth`); the deliberate decision recorded on
//!   WOR-2519 is to accept that latency rather than cache *successful*
//!   bind results, because a success cache is a password-equivalence
//!   cache: it would extend a credential's validity past a
//!   directory-side revocation or password change.
//!
//! # Bounding the outbound bind
//!
//! Authentication runs before an origin's `policies:` are evaluated, so
//! an origin's `rate_limit` or `ddos` policy cannot cap what this
//! provider dials. Left unbounded that makes the gateway a 1:1
//! amplifier pointed at the customer's directory, reachable by anyone
//! who can send an `Authorization: Basic` header, and it hands an
//! attacker directory-side account lockout for any guessable username.
//!
//! Three bounds run before the dial, none of which caches a success:
//!
//! * **Refused-credential cache.** A credential the directory has
//!   already refused is refused locally for
//!   `REFUSED_CREDENTIAL_TTL` without a second dial. Only ever
//!   turns an allow into nothing: the entry is keyed on a salted
//!   SHA-256 of the username and password, so it can match nothing but
//!   the exact pair the directory rejected, and it expires quickly.
//! * **Per-username failed-bind budget.** After
//!   `MAX_FAILED_BINDS_PER_USERNAME` directory-attributed failures
//!   inside `FAILED_BIND_WINDOW`, that username reaches the directory
//!   at most once per `OVER_BUDGET_DIAL_SPACING` instead of on every
//!   request, which drops a guessing run from as fast as the attacker
//!   can send to the budget's rate. A successful bind clears it.
//!
//!   It throttles rather than blocks, and the difference is the whole
//!   design. Blocking would let anyone who knows a username spend its
//!   budget with a handful of wrong guesses and have every later
//!   request refused, including the owner's with the correct password.
//!   That is the same deny-service-by-exhaustion this module rejects a
//!   global budget for, aimed at one victim. Past the budget the
//!   directory still gets asked, just less often, so a correct password
//!   costs its owner a delay and never a lockout.
//! * **Outbound concurrency cap.** At most
//!   `MAX_IN_FLIGHT_BINDS` binds are in flight at once, so a burst
//!   cannot hold open an unbounded number of directory connections for
//!   `timeout_secs` each. Over the cap the request is refused as
//!   `DirectoryUnavailable`, which fails closed.
//!
//! What is still unbounded: an attacker who cycles *distinct*
//! usernames pays one dial per new name, because a per-username budget
//! by construction cannot see across names. Bounding that needs either
//! a global failed-bind budget, which lets an attacker deny service to
//! honest users by exhausting it, or evaluating cheap policies before
//! authentication so an origin's own `rate_limit` applies. The second
//! is the real fix and is a phase-ordering change, not a change to
//! this file.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use tracing::{info, warn};

/// Default seconds allowed for the connect + bind exchange.
pub const DEFAULT_LDAP_TIMEOUT_SECS: u64 = 5;

/// Default directory attribute the username is matched against when
/// composing the bind DN. `cn` mirrors Apache APISIX's `ldap-auth`
/// default for the same knob.
pub const DEFAULT_UID_ATTRIBUTE: &str = "cn";

/// How long a credential the directory refused is refused locally.
///
/// Short on purpose. The entry can only ever refuse the exact
/// username-and-password pair the directory already rejected, but it is
/// still proxy-side state standing in for a directory answer, so it
/// expires before an operator who fixes an account has to wonder why.
pub const REFUSED_CREDENTIAL_TTL: Duration = Duration::from_secs(30);

/// Window over which per-username failed binds are counted.
pub const FAILED_BIND_WINDOW: Duration = Duration::from_secs(60);

/// Directory-attributed failures one username may spend inside
/// [`FAILED_BIND_WINDOW`] before the proxy stops dialing for it.
///
/// Sits below the lockout thresholds directories ship (Active
/// Directory's account lockout policy is commonly 5 to 10), so the
/// proxy stops forwarding failures before the directory starts
/// counting them toward a lockout. A human retrying a typo three or
/// four times stays inside it, and the budget clears on the next
/// success.
pub const MAX_FAILED_BINDS_PER_USERNAME: u32 = 5;

/// Minimum spacing between dials for a username whose budget is spent.
///
/// A spent budget throttles, it does not block. Blocking was the first
/// shape of this and it was wrong: an attacker who knows a username can
/// spend its budget with five cheap wrong guesses, and every later
/// request, including the owner's with the correct password, is refused
/// without the directory ever being asked. That is the same
/// deny-service-by-exhaustion this module rejects a global budget for,
/// scoped to one victim instead of everyone, and it is worse than the
/// amplification it was meant to stop.
///
/// So past the budget a username still reaches the directory, at most
/// once per this interval. The sustained failure rate stays at the
/// budget's rate, and a correct password costs its owner one interval
/// of delay rather than a lockout.
pub const OVER_BUDGET_DIAL_SPACING: Duration =
    Duration::from_secs(FAILED_BIND_WINDOW.as_secs() / MAX_FAILED_BINDS_PER_USERNAME as u64);

/// Directory binds this provider will have in flight at once.
///
/// Bounds how many directory connections a burst can hold open for
/// `timeout_secs` each. Generous for a gateway in front of one
/// directory; the point is that the number exists, not that it is
/// tight.
pub const MAX_IN_FLIGHT_BINDS: usize = 32;

/// Entries the refused-credential cache and the per-username budget
/// each hold before evicting. Bounds the memory an attacker cycling
/// usernames can cause the provider to hold.
const BIND_GUARD_CAPACITY: usize = 4096;

/// Outcome of one directory-bind authentication attempt.
///
/// The variants separate the axes the caller must not conflate: a
/// caller that offered no credentials is neutral, a caller whose
/// credentials the directory refused offered an invalid proof, and a
/// directory that could not be consulted is a backend failure that
/// must fail closed (refuse, never allow).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapBindOutcome {
    /// The directory accepted the bind. `username` is the value that
    /// was matched against `uid_attribute`, surfaced so the caller can
    /// stamp it as the authenticated subject.
    Allowed {
        /// Username the directory authenticated (the client-supplied
        /// Basic username, post-validation).
        username: String,
    },
    /// The request carried no decodable `Authorization: Basic` header.
    NoCredentials,
    /// Credentials were offered and refused: wrong password, unknown
    /// user, a username the DN cannot be composed from, or an empty
    /// password (refused locally per RFC 4513 section 5.1.2 without
    /// consulting the directory).
    InvalidCredentials,
    /// The directory could not be consulted: dial failure, timeout,
    /// TLS failure, or a directory-side result code that is not an
    /// authentication verdict. Callers must refuse the request.
    DirectoryUnavailable,
}

/// Why a request never reached the directory.
///
/// Separated from [`LdapBindOutcome`] because the two answer different
/// questions: this one is about whether the proxy was willing to spend
/// a bind, and only then does the directory get to rule on the
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindRefusal {
    /// This exact credential was refused by the directory recently.
    AlreadyRefused,
    /// The username has spent its failed-bind budget and dialed too
    /// recently. A delay, not a verdict: the next dial past
    /// [`OVER_BUDGET_DIAL_SPACING`] goes through whatever the credential
    /// is, so this can never hold a correct password out indefinitely.
    UsernameThrottled,
    /// Too many binds already in flight against the directory.
    TooManyInFlight,
}

/// Held for the duration of one outbound bind; releases the slot on
/// drop, including on an early return or a panic.
struct InFlightPermit<'a> {
    in_flight: &'a AtomicUsize,
}

impl Drop for InFlightPermit<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-username failed-bind budget for one [`FAILED_BIND_WINDOW`].
#[derive(Debug, Clone, Copy)]
struct FailureBudget {
    spent: u32,
    window_started: Instant,
    /// When this username last reached the directory. Only consulted
    /// once the budget is spent, to space the dials that follow.
    last_dial_at: Instant,
}

#[derive(Debug, Default)]
struct BindGuardState {
    /// Salted credential digest -> when the directory refused it.
    refused: HashMap<[u8; 32], Instant>,
    /// Username -> failures spent in the current window.
    failures: HashMap<String, FailureBudget>,
}

/// The bounds that stand between an inbound request and an outbound
/// directory bind. See "Bounding the outbound bind" in the module docs.
///
/// Shared behind an `Arc` so cloning the provider (the config compiler
/// does) shares one budget rather than handing an attacker a fresh one.
struct BindGuard {
    in_flight: AtomicUsize,
    state: Mutex<BindGuardState>,
    /// Per-process random salt. Keeps the cache keys from being
    /// precomputable from a username and a password guess, so the map
    /// cannot be probed as a credential oracle by anything that gets a
    /// look at proxy memory or a heap dump.
    salt: [u8; 32],
}

impl std::fmt::Debug for BindGuard {
    /// Counts only. The state map keys are usernames and salted
    /// credential digests, and the salt is what makes those digests
    /// unguessable, so none of the three belongs in a debug dump of the
    /// provider (which `Auth`'s own `Debug` will happily print).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (refused, budgeted) = match self.state.lock() {
            Ok(state) => (state.refused.len(), state.failures.len()),
            Err(poisoned) => {
                let state = poisoned.into_inner();
                (state.refused.len(), state.failures.len())
            }
        };
        f.debug_struct("BindGuard")
            .field("in_flight", &self.in_flight.load(Ordering::Acquire))
            .field("refused_credentials", &refused)
            .field("budgeted_usernames", &budgeted)
            .finish_non_exhaustive()
    }
}

impl BindGuard {
    fn new() -> Self {
        use rand::RngCore as _;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            in_flight: AtomicUsize::new(0),
            state: Mutex::new(BindGuardState::default()),
            salt,
        }
    }

    /// Salted digest of one credential. The password is hashed and
    /// never stored; nothing reverses this back to either field.
    fn digest(&self, username: &str, password: &str) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(username.as_bytes());
        // Length-prefix-free inputs would let ("ab", "c") and ("a",
        // "bc") collide; the separator cannot appear in either field
        // because both come out of a UTF-8 Basic credential split on
        // `:`, and a NUL is not a legal username character.
        hasher.update([0u8]);
        hasher.update(password.as_bytes());
        hasher.finalize().into()
    }

    /// Decide whether this credential earns a directory bind.
    ///
    /// Returns the in-flight permit on success, so the slot cannot be
    /// taken without also being released.
    fn admit(
        &self,
        username: &str,
        digest: &[u8; 32],
        now: Instant,
    ) -> Result<InFlightPermit<'_>, BindRefusal> {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(refused_at) = state.refused.get(digest) {
                if now.duration_since(*refused_at) < REFUSED_CREDENTIAL_TTL {
                    return Err(BindRefusal::AlreadyRefused);
                }
                state.refused.remove(digest);
            }
            // Sequential borrows rather than one `get_mut` arm doing
            // both, because the expiry branch needs its own mutable
            // borrow of the same map.
            let window_expired = state
                .failures
                .get(username)
                .is_some_and(|b| now.duration_since(b.window_started) >= FAILED_BIND_WINDOW);
            if window_expired {
                state.failures.remove(username);
            }
            if let Some(budget) = state.failures.get_mut(username) {
                if budget.spent >= MAX_FAILED_BINDS_PER_USERNAME {
                    if now.duration_since(budget.last_dial_at) < OVER_BUDGET_DIAL_SPACING {
                        return Err(BindRefusal::UsernameThrottled);
                    }
                    // Letting this one through is the whole point: the
                    // credential might be the right one, and only the
                    // directory can say. Start the next interval here so
                    // the rate holds whatever the answer turns out to be.
                    budget.last_dial_at = now;
                }
            }
        }

        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_IN_FLIGHT_BINDS).then_some(current + 1)
            })
            .map(|_| InFlightPermit {
                in_flight: &self.in_flight,
            })
            .map_err(|_| BindRefusal::TooManyInFlight)
    }

    /// Record a refusal the directory itself returned.
    ///
    /// Only directory-attributed refusals land here. A local refusal
    /// (empty password) and a directory-side failure (timeout, dial
    /// error) both cost nothing to produce, so counting them would let
    /// an attacker spend an honest user's budget without spending a
    /// bind of their own.
    fn record_directory_refusal(&self, username: &str, digest: [u8; 32], now: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        evict_expired(&mut state, now);
        if state.refused.len() < BIND_GUARD_CAPACITY {
            state.refused.insert(digest, now);
        }
        match state.failures.get_mut(username) {
            Some(budget) if now.duration_since(budget.window_started) < FAILED_BIND_WINDOW => {
                budget.spent = budget.spent.saturating_add(1);
                budget.last_dial_at = now;
            }
            Some(budget) => {
                *budget = FailureBudget {
                    spent: 1,
                    window_started: now,
                    last_dial_at: now,
                };
            }
            None => {
                if state.failures.len() >= BIND_GUARD_CAPACITY {
                    evict_oldest_budget(&mut state);
                }
                state.failures.insert(
                    username.to_owned(),
                    FailureBudget {
                        spent: 1,
                        window_started: now,
                        last_dial_at: now,
                    },
                );
            }
        }
    }

    /// Clear a username's budget after the directory accepted it.
    fn record_success(&self, username: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.failures.remove(username);
    }
}

fn evict_expired(state: &mut BindGuardState, now: Instant) {
    state
        .refused
        .retain(|_, at| now.duration_since(*at) < REFUSED_CREDENTIAL_TTL);
    state
        .failures
        .retain(|_, budget| now.duration_since(budget.window_started) < FAILED_BIND_WINDOW);
}

/// Make room by dropping the least recently started window.
///
/// An attacker who floods distinct usernames can push an honest user's
/// budget out this way, but every junk username they add costs them a
/// real bind, and the alternative is an unbounded map.
fn evict_oldest_budget(state: &mut BindGuardState) {
    let oldest = state
        .failures
        .iter()
        .min_by_key(|(_, budget)| budget.window_started)
        .map(|(username, _)| username.clone());
    if let Some(username) = oldest {
        state.failures.remove(&username);
    }
}

/// LDAP directory-bind authentication provider (`type: ldap_auth`).
///
/// See the module docs for the bind model and the security posture.
#[derive(Debug, Clone)]
pub struct LdapAuthProvider {
    /// Directory URL: `ldap://host[:port]` or `ldaps://host[:port]`.
    pub url: String,
    /// Base DN appended to the composed RDN, for example
    /// `ou=users,dc=example,dc=org`.
    pub base_dn: String,
    /// Attribute the username is bound under when composing the DN.
    /// Defaults to [`DEFAULT_UID_ATTRIBUTE`].
    pub uid_attribute: String,
    /// Upgrade an `ldap://` connection with StartTLS before the bind.
    /// Invalid together with an `ldaps://` URL (implicit TLS and
    /// StartTLS are mutually exclusive on one connection).
    pub use_tls: bool,
    /// Verify the directory's TLS certificate (default `true`). When
    /// verification is on, the URL host must match the certificate,
    /// the same caveat APISIX documents for its `tls_verify` knob.
    pub tls_verify: bool,
    /// Accept a plaintext `ldap://` connection with no StartTLS.
    /// Default `false`: the config is refused at load time instead.
    pub allow_insecure: bool,
    /// Deadline in seconds for the whole connect + bind exchange.
    /// Defaults to [`DEFAULT_LDAP_TIMEOUT_SECS`].
    pub timeout_secs: u64,
    /// Bounds on what this provider will dial. Private and shared
    /// across clones: an attacker must not be able to reset a budget,
    /// and no caller outside this module should be able to construct a
    /// provider without one.
    bind_guard: Arc<BindGuard>,
}

/// Serde shape for [`LdapAuthProvider::from_config`]. Kept separate so
/// validation runs after deserialization and every refusal names the
/// offending field.
#[derive(Deserialize)]
struct RawLdapConfig {
    url: String,
    base_dn: String,
    #[serde(default)]
    uid_attribute: Option<String>,
    #[serde(default)]
    use_tls: bool,
    #[serde(default = "default_tls_verify")]
    tls_verify: bool,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

fn default_tls_verify() -> bool {
    true
}

impl LdapAuthProvider {
    /// Build an `LdapAuthProvider` from a generic JSON config value,
    /// refusing insecure or contradictory shapes at load time:
    ///
    /// * URL scheme must be `ldap` or `ldaps`.
    /// * `ldap://` with neither `use_tls: true` (StartTLS) nor an
    ///   explicit `allow_insecure: true` is refused.
    /// * `ldaps://` together with `use_tls: true` is refused as
    ///   contradictory.
    /// * `base_dn` must be non-empty; `uid_attribute` must be a valid
    ///   LDAP attribute descriptor (RFC 4512 section 2.5) so the
    ///   composed DN stays well-formed.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let raw: RawLdapConfig = serde_json::from_value(value)?;

        let parsed = url::Url::parse(&raw.url)
            .map_err(|e| anyhow::anyhow!("ldap_auth: invalid url: {e}"))?;
        let scheme = parsed.scheme();
        if scheme != "ldap" && scheme != "ldaps" {
            anyhow::bail!("ldap_auth: url scheme must be ldap:// or ldaps:// (got {scheme}://)");
        }
        if parsed.host_str().is_none() {
            anyhow::bail!("ldap_auth: url has no host");
        }
        if scheme == "ldaps" && raw.use_tls {
            anyhow::bail!(
                "ldap_auth: use_tls (StartTLS) cannot be combined with an ldaps:// url; \
                 pick one TLS mode"
            );
        }
        if scheme == "ldap" && !raw.use_tls && !raw.allow_insecure {
            anyhow::bail!(
                "ldap_auth: refusing plaintext ldap:// without StartTLS; a simple bind \
                 sends the password in the clear. Set `use_tls: true` (StartTLS), use an \
                 ldaps:// url, or set `allow_insecure: true` to accept the exposure \
                 explicitly"
            );
        }

        if raw.base_dn.trim().is_empty() {
            anyhow::bail!("ldap_auth: base_dn must be non-empty");
        }

        let uid_attribute = raw
            .uid_attribute
            .unwrap_or_else(|| DEFAULT_UID_ATTRIBUTE.to_string());
        if !is_valid_attribute_descriptor(&uid_attribute) {
            anyhow::bail!(
                "ldap_auth: uid_attribute {uid_attribute:?} is not a valid LDAP attribute \
                 descriptor (RFC 4512 section 2.5: leading letter, then letters, digits, \
                 or hyphens)"
            );
        }

        Ok(Self {
            url: raw.url,
            base_dn: raw.base_dn,
            uid_attribute,
            use_tls: raw.use_tls,
            tls_verify: raw.tls_verify,
            allow_insecure: raw.allow_insecure,
            timeout_secs: raw.timeout_secs.unwrap_or(DEFAULT_LDAP_TIMEOUT_SECS),
            bind_guard: Arc::new(BindGuard::new()),
        })
    }

    /// Compose the bind DN for `username`, escaping the attribute
    /// value per RFC 4514 so a crafted username cannot splice extra
    /// RDNs into the DN.
    pub fn bind_dn(&self, username: &str) -> String {
        format!(
            "{}={},{}",
            self.uid_attribute,
            ldap3::dn_escape(username),
            self.base_dn
        )
    }

    /// Authenticate one request by binding its HTTP Basic credentials
    /// against the directory.
    ///
    /// This is the one built-in auth check besides `forward_auth` that
    /// dials out on the request hot path. Like `forward_auth`'s
    /// subrequest (and unlike egress-authorized purposes such as token
    /// exchange), the dial goes straight to the operator-configured
    /// endpoint under a config-scoped deadline; the URL is validated
    /// at config load, not per request.
    ///
    /// Not every call reaches the directory. Authentication runs
    /// before an origin's `policies:`, so nothing downstream can cap
    /// what this dials; the bounds in "Bounding the outbound bind"
    /// (module docs) run first and can refuse before any dial. A
    /// refusal that never touched the directory is reported as
    /// `InvalidCredentials` when it is about the credential and as
    /// `DirectoryUnavailable` when it is about capacity, so the caller
    /// keeps failing closed either way.
    ///
    /// Never logs the password. The bind DN (which contains only the
    /// username and operator config) is logged on refusals.
    pub async fn authenticate(&self, headers: &http::HeaderMap) -> LdapBindOutcome {
        let Some((username, password)) = basic_credentials(headers) else {
            return LdapBindOutcome::NoCredentials;
        };
        if username.is_empty() {
            return LdapBindOutcome::InvalidCredentials;
        }
        if password.is_empty() {
            // RFC 4513 section 5.1.2: a simple bind with a name and an
            // empty password is an *unauthenticated* bind, and
            // directories commonly answer it with success. Refuse
            // locally so that success can never be mistaken for a
            // verified credential.
            // `info`, not `debug`: the release profile pins tracing to
            // `release_max_level_info`, so a `debug!` here compiles out
            // and the shipped binary logs nothing at all for a refused
            // bind. The username is an identifier; the password is not
            // touched.
            info!(
                username = %username,
                "ldap_auth: refusing empty password (would be an unauthenticated bind)"
            );
            return LdapBindOutcome::InvalidCredentials;
        }

        // Everything above refuses without dialing anyway. From here
        // on a call costs the directory a connection and a bind, so the
        // bounds get their say first.
        let now = Instant::now();
        let digest = self.bind_guard.digest(&username, &password);
        let permit = match self.bind_guard.admit(&username, &digest, now) {
            Ok(permit) => permit,
            Err(BindRefusal::AlreadyRefused) => {
                info!(
                    username = %username,
                    "ldap_auth: credential already refused by the directory; refusing without a new bind"
                );
                return LdapBindOutcome::InvalidCredentials;
            }
            Err(BindRefusal::UsernameThrottled) => {
                // `DirectoryUnavailable`, not `InvalidCredentials`. The
                // proxy has not consulted the directory and has no idea
                // whether this credential is good; saying "wrong
                // password" to the owner of a correct one would be a
                // lie the caller then renders as a 401. A 503 says what
                // actually happened, and is retryable.
                info!(
                    username = %username,
                    spacing_secs = OVER_BUDGET_DIAL_SPACING.as_secs(),
                    budget = MAX_FAILED_BINDS_PER_USERNAME,
                    "ldap_auth: username over its failed-bind budget; deferring the next bind"
                );
                return LdapBindOutcome::DirectoryUnavailable;
            }
            Err(BindRefusal::TooManyInFlight) => {
                warn!(
                    url = %self.url,
                    cap = MAX_IN_FLIGHT_BINDS,
                    "ldap_auth: outbound bind concurrency cap reached; refusing"
                );
                return LdapBindOutcome::DirectoryUnavailable;
            }
        };

        let bind_dn = self.bind_dn(&username);
        let deadline = Duration::from_secs(self.timeout_secs.max(1));
        let result = tokio::time::timeout(deadline, self.simple_bind(&bind_dn, &password)).await;
        drop(permit);
        match result {
            Err(_elapsed) => {
                warn!(url = %self.url, "ldap_auth: directory bind timed out; refusing");
                LdapBindOutcome::DirectoryUnavailable
            }
            Ok(Err(err)) => {
                // Transport-level failure (dial refused, TLS failure,
                // stream error). The error text never contains the
                // password: it is not interpolated anywhere on this
                // path and the ldap3 error types carry protocol state
                // only.
                warn!(url = %self.url, error = %err, "ldap_auth: directory unreachable; refusing");
                LdapBindOutcome::DirectoryUnavailable
            }
            Ok(Ok(rc)) => match rc {
                0 => {
                    self.bind_guard.record_success(&username);
                    LdapBindOutcome::Allowed { username }
                }
                // RFC 4511 appendix A result codes attributable to the
                // presented credential: invalidCredentials(49),
                // noSuchObject(32) for an unknown user's DN, and
                // invalidDNSyntax(34) for a username the DN cannot be
                // composed from.
                49 | 32 | 34 => {
                    // The directory itself ruled on this credential, so
                    // it is the only refusal that spends the username's
                    // budget and seeds the refused-credential cache.
                    self.bind_guard
                        .record_directory_refusal(&username, digest, Instant::now());
                    // `info` for the same reason as the empty-password
                    // refusal above: `debug!` does not survive the release
                    // build. The DN names the identity, never the secret.
                    info!(bind_dn = %bind_dn, result_code = rc, "ldap_auth: bind refused");
                    LdapBindOutcome::InvalidCredentials
                }
                // Anything else (unwillingToPerform, busy, unavailable,
                // strongerAuthRequired, ...) is a directory-side
                // condition, not a verdict on the credential. Fail
                // closed without blaming the caller.
                other => {
                    warn!(
                        url = %self.url,
                        result_code = other,
                        "ldap_auth: directory returned a non-auth result code; refusing"
                    );
                    LdapBindOutcome::DirectoryUnavailable
                }
            },
        }
    }

    /// Dial the directory and perform one simple bind, returning the
    /// LDAP result code. TLS (ldaps or StartTLS) rides the workspace
    /// rustls stack via the `ldap3` crate's `tls-rustls-ring` feature.
    async fn simple_bind(&self, bind_dn: &str, password: &str) -> Result<u32, ldap3::LdapError> {
        let mut settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.timeout_secs.max(1)));
        if self.use_tls {
            settings = settings.set_starttls(true);
        }
        if !self.tls_verify {
            settings = settings.set_no_tls_verify(true);
        }
        let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &self.url).await?;
        ldap3::drive!(conn);
        let result = ldap.simple_bind(bind_dn, password).await?;
        // Result observed; the unbind is a courtesy notice and its
        // failure carries no signal.
        let _ = ldap.unbind().await;
        Ok(result.rc)
    }
}

/// RFC 4512 section 2.5 attribute descriptor: a leading ALPHA followed
/// by ALPHA / DIGIT / HYPHEN. Enforced on `uid_attribute` so operator
/// config cannot produce a malformed DN.
fn is_valid_attribute_descriptor(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Decode `Authorization: Basic <base64>` into `(username, password)`.
/// Mirrors the `basic_auth` provider's parsing: standard base64, split
/// on the first `:`.
fn basic_credentials(headers: &http::HeaderMap) -> Option<(String, String)> {
    let auth_value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let encoded = auth_value.strip_prefix("Basic ")?;
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = std::str::from_utf8(&decoded_bytes).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Config-load validation ---

    fn base_config() -> serde_json::Value {
        serde_json::json!({
            "type": "ldap_auth",
            "url": "ldaps://directory.example.org:636",
            "base_dn": "ou=users,dc=example,dc=org",
        })
    }

    #[test]
    fn secure_ldaps_config_loads_with_defaults() {
        let p = LdapAuthProvider::from_config(base_config()).unwrap();
        assert_eq!(p.uid_attribute, "cn");
        assert!(p.tls_verify);
        assert!(!p.allow_insecure);
        assert_eq!(p.timeout_secs, DEFAULT_LDAP_TIMEOUT_SECS);
    }

    /// WOR-2519 acceptance: a plaintext ldap:// URL is refused at
    /// config load unless the operator opts in explicitly.
    #[test]
    fn insecure_ldap_url_refused_at_config_load() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        let err = LdapAuthProvider::from_config(cfg).unwrap_err();
        assert!(
            err.to_string().contains("allow_insecure"),
            "refusal must name the opt-out flag: {err}"
        );
    }

    #[test]
    fn insecure_ldap_url_accepted_with_explicit_flag() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        cfg["allow_insecure"] = true.into();
        let p = LdapAuthProvider::from_config(cfg).unwrap();
        assert!(p.allow_insecure);
    }

    #[test]
    fn starttls_ldap_url_accepted_without_flag() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        cfg["use_tls"] = true.into();
        let p = LdapAuthProvider::from_config(cfg).unwrap();
        assert!(p.use_tls);
        assert!(!p.allow_insecure);
    }

    #[test]
    fn ldaps_with_starttls_refused_as_contradictory() {
        let mut cfg = base_config();
        cfg["use_tls"] = true.into();
        let err = LdapAuthProvider::from_config(cfg).unwrap_err();
        assert!(err.to_string().contains("StartTLS"), "{err}");
    }

    #[test]
    fn non_ldap_scheme_refused() {
        let mut cfg = base_config();
        cfg["url"] = "https://directory.example.org".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    #[test]
    fn empty_base_dn_refused() {
        let mut cfg = base_config();
        cfg["base_dn"] = "  ".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    #[test]
    fn malformed_uid_attribute_refused() {
        let mut cfg = base_config();
        cfg["uid_attribute"] = "cn=admin,ou".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    // --- DN composition ---

    /// A username carrying RDN separators is escaped, not spliced.
    #[test]
    fn bind_dn_escapes_rdn_splicing_username() {
        let p = LdapAuthProvider::from_config({
            let mut cfg = base_config();
            cfg["uid_attribute"] = "uid".into();
            cfg
        })
        .unwrap();
        let dn = p.bind_dn("alice,cn=admin");
        assert_eq!(dn, "uid=alice\\2ccn\\3dadmin,ou=users,dc=example,dc=org");
    }

    // --- Bind behavior against a scripted in-process directory ---

    /// Minimal in-process LDAP listener speaking just enough BER to
    /// answer one simple bind: it parses the bind request's message
    /// id, DN, and password, and answers success only for the
    /// constructor's expected pair. Everything else gets
    /// invalidCredentials(49). Runs over plaintext, so the provider
    /// under test uses `allow_insecure: true`; TLS configuration is
    /// covered by the config-load tests above.
    struct ScriptedDirectory {
        port: u16,
        handle: tokio::task::JoinHandle<()>,
    }

    impl ScriptedDirectory {
        async fn start(expected_dn: &str, expected_password: &str) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let expected_dn = expected_dn.to_string();
            let expected_password = expected_password.to_string();
            let handle = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let (msgid, dn, password) = parse_simple_bind(&buf[..n]).expect("bind request");
                let rc = if dn == expected_dn && password == expected_password {
                    0u8
                } else {
                    49u8
                };
                let response = [
                    0x30, 0x0c, // LDAPMessage SEQUENCE
                    0x02, 0x01, msgid, // messageID
                    0x61, 0x07, // [APPLICATION 1] BindResponse
                    0x0a, 0x01, rc, // resultCode
                    0x04, 0x00, // matchedDN ""
                    0x04, 0x00, // diagnosticMessage ""
                ];
                stream.write_all(&response).await.unwrap();
                // Drain the client's unbind notice until it hangs up.
                let _ = stream.read(&mut buf).await;
            });
            Self { port, handle }
        }
    }

    impl Drop for ScriptedDirectory {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    /// Parse `(message id, bind DN, simple password)` out of an LDAP
    /// simple BindRequest. Short-form BER lengths only, which holds
    /// for the small DNs these tests send.
    fn parse_simple_bind(bytes: &[u8]) -> Option<(u8, String, String)> {
        // Outer: 0x30 <len>, then messageID: 0x02 0x01 <id>.
        if bytes.len() < 9 || bytes[0] != 0x30 || bytes[2] != 0x02 || bytes[3] != 0x01 {
            return None;
        }
        let msgid = bytes[4];
        // BindRequest: 0x60 <len>, version: 0x02 0x01 0x03.
        if bytes[5] != 0x60 || bytes[7] != 0x02 || bytes[8] != 0x01 {
            return None;
        }
        // name: 0x04 <len> <dn>.
        let mut i = 10;
        if bytes.get(i)? != &0x04 {
            return None;
        }
        let dn_len = *bytes.get(i + 1)? as usize;
        let dn = String::from_utf8(bytes.get(i + 2..i + 2 + dn_len)?.to_vec()).ok()?;
        i += 2 + dn_len;
        // authentication simple: context tag 0x80 <len> <password>.
        if bytes.get(i)? != &0x80 {
            return None;
        }
        let pw_len = *bytes.get(i + 1)? as usize;
        let password = String::from_utf8(bytes.get(i + 2..i + 2 + pw_len)?.to_vec()).ok()?;
        Some((msgid, dn, password))
    }

    fn provider_for_port(port: u16) -> LdapAuthProvider {
        LdapAuthProvider::from_config(serde_json::json!({
            "type": "ldap_auth",
            "url": format!("ldap://127.0.0.1:{port}"),
            "base_dn": "ou=users,dc=example,dc=org",
            "allow_insecure": true,
            "timeout_secs": 2,
        }))
        .unwrap()
    }

    /// Like `ScriptedDirectory` but serves every connection it is
    /// offered and counts the bind requests it receives, which is the
    /// number these tests are actually about: how many times an
    /// inbound HTTP request reaches the customer's directory.
    struct CountingDirectory {
        port: u16,
        binds: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl CountingDirectory {
        async fn start(expected_dn: &str, expected_password: &str) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let expected_dn = expected_dn.to_string();
            let expected_password = expected_password.to_string();
            let binds = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&binds);
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let counter = Arc::clone(&counter);
                    let expected_dn = expected_dn.clone();
                    let expected_password = expected_password.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        loop {
                            let Ok(n) = stream.read(&mut buf).await else {
                                return;
                            };
                            if n == 0 {
                                return;
                            }
                            let Some((msgid, dn, password)) = parse_simple_bind(&buf[..n]) else {
                                // An unbind notice, not a bind. Not counted.
                                return;
                            };
                            counter.fetch_add(1, Ordering::SeqCst);
                            let rc = if dn == expected_dn && password == expected_password {
                                0u8
                            } else {
                                49u8
                            };
                            let response = [
                                0x30, 0x0c, 0x02, 0x01, msgid, 0x61, 0x07, 0x0a, 0x01, rc, 0x04,
                                0x00, 0x04, 0x00,
                            ];
                            if stream.write_all(&response).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            Self {
                port,
                binds,
                handle,
            }
        }

        fn binds(&self) -> usize {
            self.binds.load(Ordering::SeqCst)
        }
    }

    impl Drop for CountingDirectory {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    fn basic_header(username: &str, password: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        headers
    }

    /// WOR-2519 acceptance: a good bind authenticates and surfaces the
    /// username for attribution.
    #[tokio::test]
    async fn good_bind_authenticates_with_attribution() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "s3cret").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider
            .authenticate(&basic_header("alice", "s3cret"))
            .await;
        assert_eq!(
            outcome,
            LdapBindOutcome::Allowed {
                username: "alice".to_string()
            }
        );
    }

    /// WOR-2519 acceptance: a bad password is refused.
    #[tokio::test]
    async fn bad_password_refused() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "s3cret").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider.authenticate(&basic_header("alice", "wrong")).await;
        assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
    }

    /// WOR-2519 acceptance: an unreachable directory refuses; it never
    /// allows. The port comes from a listener that is bound and then
    /// dropped, so nothing answers.
    #[tokio::test]
    async fn unreachable_directory_refuses() {
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let provider = provider_for_port(port);
        let outcome = provider
            .authenticate(&basic_header("alice", "s3cret"))
            .await;
        assert_eq!(outcome, LdapBindOutcome::DirectoryUnavailable);
    }

    /// RFC 4513 section 5.1.2: an empty password must be refused
    /// locally. The scripted directory here would answer *success* for
    /// the empty password, so this test is red if the guard is
    /// missing: the bypass would authenticate.
    #[tokio::test]
    async fn empty_password_refused_without_trusting_the_directory() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider.authenticate(&basic_header("alice", "")).await;
        assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
    }

    #[tokio::test]
    async fn missing_credentials_is_no_credentials() {
        let provider = provider_for_port(1);
        let outcome = provider.authenticate(&http::HeaderMap::new()).await;
        assert_eq!(outcome, LdapBindOutcome::NoCredentials);
    }

    /// The DN the directory sees for a splicing username is the
    /// escaped one, end to end through the real client encoding.
    #[tokio::test]
    async fn spliced_username_reaches_directory_escaped() {
        let dir = ScriptedDirectory::start(
            "cn=alice\\2ccn\\3dadmin,ou=users,dc=example,dc=org",
            "s3cret",
        )
        .await;
        let provider = provider_for_port(dir.port);
        let outcome = provider
            .authenticate(&basic_header("alice,cn=admin", "s3cret"))
            .await;
        // The scripted directory only answers success when the DN it
        // parsed off the wire equals the escaped form.
        assert_eq!(
            outcome,
            LdapBindOutcome::Allowed {
                username: "alice,cn=admin".to_string()
            }
        );
    }

    // --- Bounding the outbound bind ---
    //
    // Authentication runs before an origin's `policies:`, so no
    // `rate_limit` or `ddos` policy an operator writes can cap what
    // this provider dials. These pin the bounds that stand in for it.
    // The assertion is always on binds the *directory* saw, because
    // that is the resource being amplified.

    #[tokio::test]
    async fn repeated_identical_bad_credentials_cost_one_bind() {
        let dir = CountingDirectory::start("cn=alice,ou=users,dc=example,dc=org", "right").await;
        let provider = provider_for_port(dir.port);

        for _ in 0..6 {
            assert_eq!(
                provider.authenticate(&basic_header("alice", "wrong")).await,
                LdapBindOutcome::InvalidCredentials,
                "a refused credential stays refused"
            );
        }

        assert_eq!(
            dir.binds(),
            1,
            "six requests with one already-refused credential must cost the directory \
             one bind, not six"
        );
    }

    #[tokio::test]
    async fn a_username_under_password_guessing_is_throttled_at_the_directory() {
        let dir = CountingDirectory::start("cn=alice,ou=users,dc=example,dc=org", "right").await;
        let provider = provider_for_port(dir.port);

        // A distinct password each time, so the refused-credential
        // cache never hits and only the per-username budget can bound
        // this. This is the shape that drives directory-side account
        // lockout for a username the attacker does not own.
        let budget = usize::try_from(MAX_FAILED_BINDS_PER_USERNAME).unwrap();
        let attempts = budget * 4;
        let mut refused_by_directory = 0usize;
        let mut throttled = 0usize;
        for attempt in 0..attempts {
            match provider
                .authenticate(&basic_header("alice", &format!("guess-{attempt}")))
                .await
            {
                LdapBindOutcome::InvalidCredentials => refused_by_directory += 1,
                // Not a verdict on the credential: the proxy declined to
                // spend a bind on it yet. Never `InvalidCredentials`,
                // because the directory was not asked.
                LdapBindOutcome::DirectoryUnavailable => throttled += 1,
                other => panic!("a wrong password must never be admitted, got {other:?}"),
            }
        }

        assert_eq!(
            dir.binds(),
            budget,
            "{attempts} guesses inside one spacing interval must cost the directory only \
             the {budget}-bind budget"
        );
        assert_eq!(
            refused_by_directory, budget,
            "only the guesses that actually reached the directory carry its verdict"
        );
        assert_eq!(
            throttled,
            attempts - budget,
            "the rest wait for a slot rather than being called bad credentials"
        );
    }

    /// The budget must not become a way to lock an honest user out.
    #[tokio::test]
    async fn a_successful_bind_clears_the_username_budget() {
        let dir = CountingDirectory::start("cn=alice,ou=users,dc=example,dc=org", "right").await;
        let provider = provider_for_port(dir.port);

        for attempt in 0..2 {
            assert_eq!(
                provider
                    .authenticate(&basic_header("alice", &format!("typo-{attempt}")))
                    .await,
                LdapBindOutcome::InvalidCredentials
            );
        }
        assert_eq!(
            provider.authenticate(&basic_header("alice", "right")).await,
            LdapBindOutcome::Allowed {
                username: "alice".to_string()
            },
            "the real password still works after a couple of typos"
        );

        // Budget cleared: alice gets her full allowance again rather
        // than the two failures she already spent.
        let further = usize::try_from(MAX_FAILED_BINDS_PER_USERNAME).unwrap();
        for attempt in 0..further {
            assert_eq!(
                provider
                    .authenticate(&basic_header("alice", &format!("later-{attempt}")))
                    .await,
                LdapBindOutcome::InvalidCredentials
            );
        }
        assert_eq!(
            dir.binds(),
            2 + 1 + further,
            "the success must reset the budget rather than leaving it spent"
        );
    }

    /// The concurrency cap refuses rather than queueing, so a burst
    /// cannot hold open an unbounded number of directory connections
    /// for `timeout_secs` each.
    #[test]
    fn the_in_flight_cap_refuses_once_it_is_full() {
        let guard = BindGuard::new();
        let now = Instant::now();
        let digest = guard.digest("alice", "pw");

        let permits: Vec<_> = (0..MAX_IN_FLIGHT_BINDS)
            .map(|_| {
                guard
                    .admit("alice", &digest, now)
                    .expect("cap admits up to MAX_IN_FLIGHT_BINDS")
            })
            .collect();
        assert!(
            matches!(
                guard.admit("alice", &digest, now),
                Err(BindRefusal::TooManyInFlight)
            ),
            "a bind past the cap of {MAX_IN_FLIGHT_BINDS} must be refused, not queued"
        );

        drop(permits);
        assert!(
            guard.admit("alice", &digest, now).is_ok(),
            "slots must come back when the binds finish"
        );
    }

    /// The refused-credential entry is keyed on the exact pair, so a
    /// password change is not shadowed by a stale refusal.
    #[test]
    fn a_refusal_only_matches_the_credential_the_directory_refused() {
        let guard = BindGuard::new();
        let now = Instant::now();
        let refused = guard.digest("alice", "old");
        guard.record_directory_refusal("alice", refused, now);

        assert!(
            matches!(
                guard.admit("alice", &refused, now),
                Err(BindRefusal::AlreadyRefused)
            ),
            "the exact credential the directory refused must not dial again"
        );
        assert!(
            guard
                .admit("alice", &guard.digest("alice", "new"), now)
                .is_ok(),
            "a different password is a different credential"
        );
        assert!(
            guard.admit("bob", &guard.digest("bob", "old"), now).is_ok(),
            "another user's identical password is a different credential"
        );
    }

    /// A spent budget must never answer a correct password with a
    /// refusal the directory never issued.
    ///
    /// The first shape of this budget blocked outright, which handed
    /// anyone who knew a username a repeatable lockout of its owner: five
    /// cheap wrong guesses, and every later request was refused without
    /// the directory being asked, the owner's correct password included.
    #[tokio::test]
    async fn a_spent_budget_does_not_call_a_correct_password_wrong() {
        let dir = CountingDirectory::start("cn=alice,ou=users,dc=example,dc=org", "right").await;
        let provider = provider_for_port(dir.port);

        // An attacker who knows only the username spends alice's budget.
        for attempt in 0..MAX_FAILED_BINDS_PER_USERNAME {
            assert_eq!(
                provider
                    .authenticate(&basic_header("alice", &format!("guess-{attempt}")))
                    .await,
                LdapBindOutcome::InvalidCredentials
            );
        }

        // Alice now presents the correct password. The proxy has not
        // asked the directory about it, so it must not claim it is wrong.
        let outcome = provider.authenticate(&basic_header("alice", "right")).await;
        assert_ne!(
            outcome,
            LdapBindOutcome::InvalidCredentials,
            "a throttled request must not be reported as a bad credential; \
             the directory was never consulted about it"
        );
        assert_eq!(
            outcome,
            LdapBindOutcome::DirectoryUnavailable,
            "the honest answer is that the directory could not be consulted yet"
        );
    }

    /// The throttle has to let go, or it is just a slower lockout.
    #[test]
    fn a_spent_budget_dials_again_once_the_spacing_elapses() {
        let guard = BindGuard::new();
        let start = Instant::now();

        for attempt in 0..MAX_FAILED_BINDS_PER_USERNAME {
            let digest = guard.digest("alice", &format!("guess-{attempt}"));
            guard
                .admit("alice", &digest, start)
                .expect("every guess inside the budget reaches the directory");
            guard.record_directory_refusal("alice", digest, start);
        }

        // Immediately after: throttled, not refused outright.
        let correct = guard.digest("alice", "right");
        assert!(
            matches!(
                guard.admit("alice", &correct, start),
                Err(BindRefusal::UsernameThrottled)
            ),
            "the request past the budget waits for a slot"
        );

        // One spacing interval later the same credential goes through,
        // which is what keeps this a delay rather than a lockout.
        let later = start + OVER_BUDGET_DIAL_SPACING;
        assert!(
            guard.admit("alice", &correct, later).is_ok(),
            "a spent budget must not hold a credential out past {}s",
            OVER_BUDGET_DIAL_SPACING.as_secs()
        );
    }

    /// A `{:?}` of the provider must not dump who has been failing.
    #[test]
    fn debug_never_prints_usernames_the_salt_or_a_credential_digest() {
        let provider = LdapAuthProvider::from_config(base_config()).unwrap();
        provider.bind_guard.record_directory_refusal(
            "alice",
            provider.bind_guard.digest("alice", "s3cret"),
            Instant::now(),
        );

        let rendered = format!("{provider:?}");
        assert!(
            !rendered.contains("alice"),
            "a username under a failed-bind budget must not reach a debug dump: {rendered}"
        );
        assert!(
            !rendered.contains("s3cret") && !rendered.contains("salt"),
            "neither the credential nor the digest salt belongs in a debug dump: {rendered}"
        );
        assert!(
            rendered.contains("budgeted_usernames: 1"),
            "the counts are what a debug dump is for: {rendered}"
        );
    }

    /// A refusal the directory never issued must not spend a budget.
    /// Otherwise an attacker sending empty passwords, which never dial,
    /// could refuse an honest user for free.
    #[tokio::test]
    async fn local_refusals_do_not_spend_the_budget() {
        let dir = CountingDirectory::start("cn=alice,ou=users,dc=example,dc=org", "right").await;
        let provider = provider_for_port(dir.port);

        for _ in 0..(MAX_FAILED_BINDS_PER_USERNAME * 4) {
            assert_eq!(
                provider.authenticate(&basic_header("alice", "")).await,
                LdapBindOutcome::InvalidCredentials
            );
        }
        assert_eq!(dir.binds(), 0, "an empty password never dials");

        assert_eq!(
            provider.authenticate(&basic_header("alice", "right")).await,
            LdapBindOutcome::Allowed {
                username: "alice".to_string()
            },
            "alice's budget must be untouched by refusals the directory never saw"
        );
    }
}
