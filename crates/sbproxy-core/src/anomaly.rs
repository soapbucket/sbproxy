//! WOR-2666: behavioral anomaly detection, and the reputation score it
//! feeds.
//!
//! `sbproxy-plugin` has declared [`sbproxy_plugin::AnomalyDetectorHook`],
//! its [`sbproxy_plugin::AnomalyVerdict`] return type, and a registration function since
//! Wave 5, and the response phase has iterated the registry since then.
//! Nothing implemented the trait, so the iteration ran over an empty
//! list on every request and the verdicts, had there been any, were
//! dropped after a `debug!`. This module is the implementation and the
//! consumer.
//!
//! # What it detects
//!
//! Not signatures. The detector keeps a rolling 28-day histogram per
//! tenant and agent class of the categorical signals the proxy already
//! collects, and flags an observation whose relative frequency sits in
//! the long tail:
//!
//! * **`ja4_outlier`** - a TLS fingerprint this agent class has
//!   essentially never presented before. A crawler that claims to be
//!   GPTBot and dials with a JA4 no GPTBot has ever used is the case
//!   this is for.
//! * **`ml_inconsistency`** - the request was resolved to this class by
//!   a *different* identity source than the class normally uses. The
//!   name predates the check: it compares the resolver-source label
//!   (`user_agent`, `bot_auth`, `rdns`, ...), not an ML verdict.
//!   Verified sources are observed but never judged, so turning on Web
//!   Bot Auth or KYA for an existing class cannot flag the class for
//!   having become verified; the reverse, a class that normally
//!   verifies arriving unverified, still is.
//! * **`headless_library`** - a headless-browser library in the tail of
//!   the *other headless detections* for the class. Always at least
//!   `warn`, because it is a signal that arrives with intent attached.
//!   The denominator is detections, not requests: `NotDetected` is not
//!   observed, so a deployment that only ever sees one headless library
//!   has that library at frequency 1.0 and this arm stays quiet by
//!   construction.
//! * **`request_rate_spike`** - one IP past the class's per-IP mean by
//!   a configured multiple today.
//!
//! Comparative detection buys the thing a rule list cannot: it needs no
//! prior knowledge of the attack. It costs the thing a rule list has:
//! it says nothing until it has a baseline, which is what
//! `min_observations` is the floor for, and it is only as good as the
//! traffic it learned from.
//!
//! # Where it runs, and what that excludes
//!
//! The detector is dispatched from `response_filter`. A request that
//! never reaches a response filter is never judged and never learned
//! from: a `static` or `mock` origin, a hot-cache or reserve hit, and
//! anything auth, a policy, or a rate limiter already refused. The
//! population the detector calls "normal" is therefore the population
//! that reached an origin, and an attacker whose requests are all being
//! refused contributes nothing. `docs/anomaly-detection.md` says the
//! same thing where an operator reads it.
//!
//! # The per-request cost is bounded, on purpose
//!
//! Every categorical dimension the detector reads is derived from
//! something the *client* controls: a JA4 comes out of the ClientHello,
//! so a caller can present a new one per connection. A detector whose
//! per-request work grows with the number of distinct values it has
//! seen is therefore a detector a caller can make expensive, and the
//! lock it holds makes that cost non-parallelizable.
//!
//! Two bounds close that:
//!
//! * The denominator is a **running total per field per day**, so
//!   reading it is 28 integer loads rather than a scan over every
//!   distinct value in the window.
//! * The distinct set per field per day is a **bounded LRU**
//!   (`MAX_CATEGORICAL_VALUES_PER_DAY`, 1,024), so both the memory and
//!   eviction are O(1) per observation.
//!
//! This is the standard shape for cardinality under adversarial input:
//! Cloudflare's analytics and DDoS pipelines estimate distinct-value
//! counts with bounded sketches rather than exact sets, and Envoy
//! refuses to grow stat cardinality from request-derived strings at
//! all. Both encode one rule: a caller must not be able to buy work or
//! memory by varying a field it chooses.
//!
//! Eviction is not free of consequence, and it fails in the safe
//! direction. An evicted value loses its history, so the next sighting
//! has `prior = 0` against a denominator that still counts every
//! observation. The frequency comes out lower, and the verdict comes
//! out stronger. A flooding client makes the detector noisier about
//! itself, not blinder.
//!
//! The state is also sharded across 16 mutexes keyed by the
//! same `(tenant, agent class)` pair the histogram is keyed by, so one
//! busy class does not serialize every other class behind it.
//!
//! # The window is in memory, and that is a decision
//!
//! There is no persistence option, so a restart empties 28 days of
//! signal and the detector is silent until it has re-learned a
//! baseline. The alternative is a database the proxy cannot start
//! without, which the rule this port ships under forbids. An operator
//! should read `sbproxy_anomaly_detected_total` with that in mind: a
//! quiet detector after a deploy is a detector that is still learning,
//! not a quiet network.
//!
//! A config **reload** does not cost the window. `install` keeps the
//! running detector when the resolved settings are unchanged, which is
//! the common case: a reload triggered by a neighboring file, or by an
//! edit somewhere else in the config, leaves the baseline alone. A
//! reload that genuinely changes `proxy.anomaly` does start over, and
//! that is stated where an operator reads it.
//!
//! # Reputation
//!
//! Verdicts feed a per-tenant, per-agent-class score, published as
//! `sbproxy_agent_reputation_score`. Weighted counts decay by rolling
//! out of the same 28-day window rather than by a scheduled sweep, so a
//! class that stops misbehaving recovers on its own and there is no
//! timer task to own or to fail. The gauge is republished on every
//! analysis, not only when a verdict fires, so a recovering class's
//! number moves while it recovers. A class that goes entirely silent
//! keeps its last published score until it sends again: there is no
//! timer, and inventing one to decay a number nobody is producing would
//! be a background task whose only job is to make a dashboard look
//! better.
//!
//! **What reads the score.** An operator's dashboard, and, when they
//! ask for it, admission. `proxy.anomaly.reputation.deny_below` and
//! `challenge_below` are unset by default: the score is published and
//! nothing acts on it until an operator picks a number. That is the
//! same shape Cloudflare's threat score has, where the number is always
//! there and a WAF rule decides whether it means anything.
//!
//! A refusal is not a one-way door. The gate rolls the window forward
//! before it reads the score and feeds the refused request back into
//! the detector, so a class floored by a flood recovers as that flood's
//! weight rolls out of the window. Without that, a refusal would freeze
//! the window at its worst value for the life of the process, on a
//! class any caller can join by choosing a User-Agent.
//!
//! Two properties matter before anyone picks a number, and both are
//! stated in `docs/anomaly-detection.md` rather than buried here: the
//! score is keyed on a *claimed* identity unless the resolver source
//! was a verified one, and the class `unknown` is a shared bucket for
//! everything the resolver did not recognize. Admission carries the
//! resolver source on its decision record so a rule can tell the two
//! apart after the fact.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use chrono::NaiveDate;
use lru::LruCache;
use parking_lot::Mutex;
use sbproxy_plugin::{AnomalyVerdict, RequestContextView};

/// Days the rolling window spans.
const WINDOW_DAYS: usize = 28;

/// Mutex shards the histogram map is split across.
///
/// One lock for the whole process made every request on every tenant
/// wait behind whichever class was busiest. The shard is chosen from
/// the same `(tenant, agent class)` key the map is keyed by, so a key
/// always lands in one shard and no read ever spans two.
pub(crate) const SHARDS: usize = 16;

/// Distinct `(tenant, agent class)` pairs tracked at once.
///
/// The class comes from the resolver's closed taxonomy, so this cap is
/// never reached in a healthy deployment. It exists because the
/// detector would otherwise allocate a 28-day histogram for whatever
/// string reached it, and "the caller only ever passes taxonomy values"
/// is an invariant held by convention rather than by the type. Larger
/// than the class taxonomy on its own because the key gained a tenant
/// dimension: a proxy fronting thirty tenants has thirty times the
/// keys and the same taxonomy.
const MAX_TRACKED_KEYS: usize = 512;

/// Distinct IPs tracked per class per day.
const MAX_IPS_TRACKED: usize = 4096;

/// Distinct categorical values tracked per field per day.
///
/// A bounded LRU rather than an unbounded map: the values are
/// client-controlled, so an unbounded set is memory a caller can buy.
/// Past the cap the least recently observed value is evicted, which
/// costs that value its history and makes its next sighting look
/// *more* anomalous, not less.
pub(crate) const MAX_CATEGORICAL_VALUES_PER_DAY: usize = 1024;

/// Histogram field for TLS fingerprints.
const FIELD_JA4: &str = "ja4";
/// Histogram field for identity-resolver sources.
const FIELD_ML_CLASS: &str = "ml_class";
/// Histogram field for headless-library detections.
const FIELD_HEADLESS: &str = "headless_library";

/// Resolver sources that are cryptographically or DNS verified.
///
/// These are observed into the baseline but never judged as outliers.
/// A class whose traffic becomes verified has not become anomalous, and
/// judging it that way meant an operator's first experience of enabling
/// Web Bot Auth was a flood of critical verdicts and a class floored at
/// zero reputation for strengthening its identity. The reverse
/// direction still fires: a class that normally verifies, arriving
/// unverified, is a `user_agent` observation in a `bot_auth`
/// population.
const VERIFIED_IDENTITY_SOURCES: &[&str] = &["bot_auth", "kya", "rdns", "tls_fingerprint"];

/// Weighted count at which a class's score reaches zero.
const REPUTATION_SATURATION: f64 = 100.0;
/// Weight one `warn` verdict contributes to the score.
const WEIGHT_WARN: u32 = 1;
/// Weight one `critical` verdict contributes. Five times a warning, so
/// a single critical finding visibly moves the number.
const WEIGHT_CRITICAL: u32 = 5;

/// Floor the operator-set outlier frequency is clamped to.
///
/// `clamp(f64::MIN_POSITIVE, 1.0)` was not a floor: it turned `0.0`
/// into 2.2e-308, which flags only a value with literally no prior
/// observations and reads to an operator as "the detector is
/// configured and quiet". One in a million is a real floor and is
/// documented as one.
const MIN_OUTLIER_FREQUENCY: f64 = 1e-6;

/// Stable verdict kind labels. These are the strings
/// [`sbproxy_plugin::AnomalyVerdict::kind`] documents, and the metric's
/// label values.
const KIND_JA4_OUTLIER: &str = "ja4_outlier";
const KIND_ML_INCONSISTENCY: &str = "ml_inconsistency";
const KIND_HEADLESS_LIBRARY: &str = "headless_library";
const KIND_REQUEST_RATE_SPIKE: &str = "request_rate_spike";

/// Stable severity labels.
const SEVERITY_INFO: &str = "info";
const SEVERITY_WARN: &str = "warn";
const SEVERITY_CRITICAL: &str = "critical";

/// Separator between the tenant and the agent class in a histogram key.
///
/// A unit separator rather than `:` because both halves are strings the
/// host stamps and neither is length-prefixed; a printable separator
/// would let one tenant's name plus a class collide with another's.
const KEY_SEPARATOR: char = '\u{1f}';

/// One day's counts for one histogram key.
#[derive(Debug, Default)]
struct DayBucket {
    day: Option<NaiveDate>,
    /// Bounded distinct-value counts per field. Reads use `peek` so a
    /// judgment does not reorder the eviction queue; only an
    /// observation promotes.
    categorical: HashMap<&'static str, LruCache<String, u64>>,
    /// Running observation count per field, maintained alongside
    /// `categorical`.
    ///
    /// This is the denominator, and it is a counter rather than a sum
    /// over `categorical` for two reasons: the sum was O(distinct) per
    /// request under a process-global lock, and eviction would make it
    /// undercount. An observation the LRU dropped still happened.
    categorical_totals: HashMap<&'static str, u64>,
    per_ip: HashMap<IpAddr, u64>,
    /// Weighted anomaly count for the day, feeding the reputation
    /// score. Held here rather than in a second structure so it decays
    /// by the same rotation as everything else.
    anomaly_weight: u32,
}

/// A rolling day-bucketed histogram for one `(tenant, agent class)`.
#[derive(Debug)]
struct ClassHistogram {
    /// Index 0 is today; index `WINDOW_DAYS - 1` is the oldest day
    /// still inside the window. A fixed-size array rather than a `Vec`
    /// so `days[0]` is an invariant the type holds.
    days: [DayBucket; WINDOW_DAYS],
    /// The last day `analyze_on` judged a request for this key.
    ///
    /// Only the eviction order reads it. `days[0].day` moves on a
    /// rotation whoever triggered it, including the admission gate, so
    /// it cannot answer "which key has nothing asking about it".
    last_analyzed: Option<NaiveDate>,
}

impl Default for ClassHistogram {
    fn default() -> Self {
        Self {
            days: std::array::from_fn(|_| DayBucket::default()),
            last_analyzed: None,
        }
    }
}

impl ClassHistogram {
    /// Align day 0 with `today`, dropping what fell out of the window.
    ///
    /// A gap longer than the window clears the histogram: a class that
    /// has been silent for 28 days has no baseline worth keeping, and
    /// carrying the old one forward would judge new traffic against a
    /// month-old population.
    fn rotate_to(&mut self, today: NaiveDate) {
        let Some(latest) = self.days[0].day else {
            self.days[0].day = Some(today);
            return;
        };
        if today <= latest {
            // Same day, or a clock that went backwards. Either way
            // there is nothing to roll.
            return;
        }
        let shift = (today - latest).num_days().max(0) as usize;
        if shift >= WINDOW_DAYS {
            self.days = std::array::from_fn(|_| DayBucket::default());
            self.days[0].day = Some(today);
            return;
        }
        for index in (shift..WINDOW_DAYS).rev() {
            self.days[index] = std::mem::take(&mut self.days[index - shift]);
        }
        for (offset, slot) in self.days.iter_mut().take(shift).enumerate() {
            *slot = DayBucket::default();
            slot.day = Some(today - chrono::Duration::days(offset as i64));
        }
    }

    /// Count one observation of `field`, and learn `value` unless the
    /// caller says not to.
    ///
    /// The split exists for one case. A value the detector just scored
    /// `critical` must not be trained into the baseline by the same
    /// call that flagged it: an attacker who keeps sending would
    /// otherwise cross the outlier threshold on its own volume, stop
    /// being flagged, and become part of the population that judges
    /// everyone else. The observation still counts toward the
    /// denominator, because the request happened.
    fn observe_categorical(&mut self, field: &'static str, value: &str, learn: bool) {
        let bucket = &mut self.days[0];
        let total = bucket.categorical_totals.entry(field).or_insert(0);
        *total = total.saturating_add(1);
        if !learn {
            return;
        }
        let counts = bucket.categorical.entry(field).or_insert_with(|| {
            LruCache::new(
                NonZeroUsize::new(MAX_CATEGORICAL_VALUES_PER_DAY).unwrap_or(NonZeroUsize::MIN),
            )
        });
        if let Some(slot) = counts.get_mut(value) {
            *slot = slot.saturating_add(1);
            return;
        }
        // `put` evicts the least recently used entry when the cache is
        // full, in constant time. That is the whole bound.
        counts.put(value.to_string(), 1);
    }

    fn observe_request(&mut self, ip: IpAddr) {
        let bucket = &mut self.days[0];
        if let Some(slot) = bucket.per_ip.get_mut(&ip) {
            *slot = slot.saturating_add(1);
            return;
        }
        if bucket.per_ip.len() >= MAX_IPS_TRACKED {
            // Evict the quietest tracked IP. With a distributed
            // attacker this forgets an honest one, which is why the
            // per-IP rate is one signal of four rather than the whole
            // detector.
            let victim = bucket
                .per_ip
                .iter()
                .min_by_key(|(_, count)| **count)
                .map(|(ip, _)| *ip);
            if let Some(victim) = victim {
                bucket.per_ip.remove(&victim);
            }
        }
        bucket.per_ip.insert(ip, 1);
    }

    /// Prior observations of one value, across the window.
    ///
    /// `peek` rather than `get`: reading a value to judge it must not
    /// promote it in the eviction order, or a flood of judgments would
    /// keep the flooded values alive at the expense of the baseline.
    fn count_categorical(&self, field: &'static str, value: &str) -> u64 {
        self.days
            .iter()
            .filter_map(|day| day.categorical.get(field))
            .filter_map(|counts| counts.peek(value))
            .sum()
    }

    /// Total observations of one field across the window.
    ///
    /// 28 integer loads, whatever the client has done to the
    /// distinct-value count. This is the bound WOR-2666's review named:
    /// summing the per-value map made the per-request cost
    /// `O(28 x distinct)` behind a lock a caller could saturate from
    /// its own ClientHello.
    fn total_for_field(&self, field: &'static str) -> u64 {
        self.days
            .iter()
            .filter_map(|day| day.categorical_totals.get(field).copied())
            .fold(0u64, u64::saturating_add)
    }

    fn ip_count_today(&self, ip: IpAddr) -> u64 {
        self.days[0].per_ip.get(&ip).copied().unwrap_or(0)
    }

    fn mean_ip_rate_today(&self) -> f64 {
        let tracked = self.days[0].per_ip.len();
        if tracked == 0 {
            return 0.0;
        }
        let total: u64 = self.days[0].per_ip.values().sum();
        total as f64 / tracked as f64
    }

    fn add_anomaly_weight(&mut self, weight: u32) {
        let bucket = &mut self.days[0];
        bucket.anomaly_weight = bucket.anomaly_weight.saturating_add(weight);
    }

    fn weighted_anomalies(&self) -> u32 {
        self.days
            .iter()
            .map(|day| day.anomaly_weight)
            .fold(0u32, u32::saturating_add)
    }
}

/// Turn a window's weighted anomaly count into a score in `[0.0, 1.0]`.
///
/// Higher is better; 1.0 is a class that has produced nothing.
/// Deliberately linear and deliberately saturating: an operator reading
/// a dashboard should be able to say what a 0.87 means without knowing
/// the curve, and a class 400 criticals deep is not usefully worse than
/// one 100 deep.
fn score_from_weight(weighted: u32) -> f64 {
    1.0 - (weighted as f64 / REPUTATION_SATURATION).clamp(0.0, 1.0)
}

/// The band a score falls in, for a decision record.
///
/// A band rather than the number: the record is a security artifact an
/// analyst pivots on, and a float that moves on every request is not a
/// term anyone can select. Five bands, named for what they mean rather
/// than for their bounds.
pub(crate) fn reputation_bucket(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "clean",
        s if s >= 0.7 => "watch",
        s if s >= 0.4 => "suspect",
        s if s > 0.0 => "bad",
        _ => "floored",
    }
}

/// What an operator's reputation thresholds ask admission to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationAction {
    /// Refuse the request outright.
    Deny,
    /// Refuse with a challenge status, so a caller that can prove
    /// itself has somewhere to go.
    Challenge,
}

impl ReputationAction {
    /// Status the refusal answers with.
    ///
    /// `403` for a deny. `429` for a challenge, because there is no
    /// interactive challenge to serve here and the honest meaning is
    /// "slow down and come back with better standing"; a `401` would
    /// tell a caller to fetch a credential that would not change the
    /// answer.
    pub fn status(self) -> u16 {
        match self {
            Self::Deny => 403,
            Self::Challenge => 429,
        }
    }

    /// Stable label for the decision record and the log line.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Challenge => "challenge",
        }
    }

    /// What the refused caller is told.
    ///
    /// Deliberately generic, and deliberately not the reason string the
    /// log line and the decision record carry. Those name the agent
    /// class and the reputation band; handing them back tells a hostile
    /// caller which class the gateway resolved it into and how close to
    /// the floor it currently sits, which is a probe oracle for a
    /// dimension the same caller controls by choosing a User-Agent.
    pub fn client_message(self) -> &'static str {
        match self {
            Self::Deny => "forbidden",
            Self::Challenge => "too many requests",
        }
    }
}

/// Detector settings, resolved from `proxy.anomaly`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalySettings {
    /// Observations a dimension needs before anything is called an
    /// outlier.
    pub min_observations: u64,
    /// Relative frequency below which an observation is an outlier.
    pub outlier_frequency: f64,
    /// Multiple of the per-IP mean that counts as a rate spike.
    pub rate_spike_multiplier: f64,
    /// Mean per-IP rate below which the spike check does not engage.
    pub rate_spike_min_mean: f64,
    /// Score at or below which admission refuses the request. `None`
    /// leaves the score advisory, which is the default.
    pub deny_below: Option<f64>,
    /// Score at or below which admission answers a challenge status.
    /// `None` leaves the score advisory, which is the default.
    pub challenge_below: Option<f64>,
}

impl AnomalySettings {
    /// Read the settings out of a compiled config block, clamping the
    /// values an operator can set to nonsense.
    ///
    /// A zero `min_observations` would flag every first sighting; a
    /// zero or negative frequency threshold would flag nothing, which
    /// is worse, because the detector would look configured and say
    /// nothing forever.
    pub fn from_config(config: &sbproxy_config::AnomalyConfig) -> Self {
        Self {
            min_observations: config.min_observations.max(1),
            outlier_frequency: config.outlier_frequency.clamp(MIN_OUTLIER_FREQUENCY, 1.0),
            rate_spike_multiplier: config.rate_spike_multiplier.max(1.0),
            rate_spike_min_mean: config.rate_spike_min_mean.max(0.0),
            deny_below: config
                .reputation
                .deny_below
                .map(|value| value.clamp(0.0, 1.0)),
            challenge_below: config
                .reputation
                .challenge_below
                .map(|value| value.clamp(0.0, 1.0)),
        }
    }

    /// Whether any threshold is set, so the request path can skip the
    /// lookup entirely when nobody asked for one.
    fn admission_configured(&self) -> bool {
        self.deny_below.is_some() || self.challenge_below.is_some()
    }

    /// What a score asks admission to do.
    ///
    /// Deny wins over challenge when both are set and both match, which
    /// is the only ordering that lets an operator write "challenge
    /// below 0.6, refuse below 0.2" and get what they wrote.
    fn action_for(&self, score: f64) -> Option<ReputationAction> {
        if self.deny_below.is_some_and(|floor| score < floor) {
            return Some(ReputationAction::Deny);
        }
        if self.challenge_below.is_some_and(|floor| score < floor) {
            return Some(ReputationAction::Challenge);
        }
        None
    }
}

/// The rolling histogram, its settings, and the reputation it feeds.
pub struct AnomalyDetector {
    settings: AnomalySettings,
    /// Sharded so one busy class does not serialize every other class.
    shards: Box<[Mutex<HashMap<String, ClassHistogram>>]>,
    /// Keys tracked across every shard, so the cap stays a process-wide
    /// bound rather than a per-shard one that hash skew could break.
    tracked: AtomicUsize,
}

impl std::fmt::Debug for AnomalyDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalyDetector")
            .field("settings", &self.settings)
            .field("tracked_keys", &self.tracked.load(Ordering::Relaxed))
            .finish()
    }
}

impl AnomalyDetector {
    /// Build a detector with the given settings and an empty window.
    pub fn new(settings: AnomalySettings) -> Self {
        Self {
            settings,
            shards: (0..SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            tracked: AtomicUsize::new(0),
        }
    }

    /// The settings this detector was built with, so a reload can tell
    /// whether it has to build a new one.
    pub fn settings(&self) -> &AnomalySettings {
        &self.settings
    }

    /// Histogram key for one tenant and agent class.
    fn key_for(tenant: &str, agent_class: &str) -> String {
        let mut key = String::with_capacity(tenant.len() + agent_class.len() + 1);
        key.push_str(tenant);
        key.push(KEY_SEPARATOR);
        key.push_str(agent_class);
        key
    }

    fn shard_for(&self, key: &str) -> &Mutex<HashMap<String, ClassHistogram>> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.shards.len();
        &self.shards[index]
    }

    /// Claim one of the process-wide key slots, or say the budget is
    /// spent.
    fn reserve_key_slot(&self) -> bool {
        self.tracked
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |tracked| {
                (tracked < MAX_TRACKED_KEYS).then_some(tracked + 1)
            })
            .is_ok()
    }

    /// Make room for a new key by dropping the one in this shard that
    /// has gone longest without being analyzed.
    ///
    /// # Why evict rather than refuse
    ///
    /// The budget is process-wide and a slot was never released, so the
    /// first version refused every unseen `(tenant, class)` past the
    /// cap: `analyze_on` returned empty, `reputation()` returned `None`,
    /// and `admission_for` reads `None` as "admit". One tenant's key
    /// growth therefore switched off another tenant's `deny_below`,
    /// silently, with no counter and no log line. 512 is reachable in
    /// normal operation (thirty tenants at seventeen classes), so this
    /// was not a theoretical cliff.
    ///
    /// Evicting the stalest key in the shard the new key hashes to
    /// keeps the bound and keeps enforcement alive: the class that
    /// loses its window is the one nothing has asked about, and it
    /// relearns from the next request. The scan is bounded by the
    /// shard's own size, which the same cap bounds.
    fn evict_stalest(guard: &mut HashMap<String, ClassHistogram>) -> bool {
        let Some(victim) = guard
            .iter()
            .min_by_key(|(_, histogram)| histogram.last_analyzed)
            .map(|(key, _)| key.clone())
        else {
            return false;
        };
        guard.remove(&victim);
        true
    }

    /// Tracked keys, for the gauge and for `Debug`.
    pub fn tracked_keys(&self) -> usize {
        self.tracked.load(Ordering::Acquire)
    }

    /// Reputation score for one tenant's agent class, or `None` when
    /// the pair has never been seen.
    pub fn reputation(&self, tenant: &str, agent_class: &str) -> Option<f64> {
        let key = Self::key_for(tenant, agent_class);
        self.shard_for(&key)
            .lock()
            .get(&key)
            .map(|histogram| score_from_weight(histogram.weighted_anomalies()))
    }

    /// Roll one key's window forward to `today`, republish its gauge,
    /// and return the rolled score. `None` when the pair is unknown.
    ///
    /// # Why this exists
    ///
    /// `rotate_to` used to run only from `analyze_on`, which runs only
    /// from the response phase. A class refused by `deny_below` never
    /// reaches a response phase, so its window never rolled and its
    /// weight never decayed: one flood that floored a class locked that
    /// class out for the life of the process, while the page an
    /// operator reads before setting a floor promised a 28-day decay.
    /// A class any caller can join by sending a User-Agent is not a
    /// class to hand a permanent ban.
    ///
    /// So the refusal path rolls the window itself. Rotation is now
    /// driven by the request that is *about* to be judged rather than
    /// by the one that got through, which is the only ordering that
    /// lets a floored class recover.
    pub fn refresh_reputation(
        &self,
        tenant: &str,
        agent_class: &str,
        today: NaiveDate,
    ) -> Option<f64> {
        let key = Self::key_for(tenant, agent_class);
        let mut guard = self.shard_for(&key).lock();
        let histogram = guard.get_mut(&key)?;
        histogram.rotate_to(today);
        let score = score_from_weight(histogram.weighted_anomalies());
        drop(guard);
        sbproxy_observe::metrics::set_agent_reputation_score(tenant, agent_class, score);
        Some(score)
    }

    /// What an operator's thresholds say about this caller, or `None`
    /// when no threshold is set or the class has no history.
    ///
    /// The window is rolled to `today` first, so the decision is taken
    /// on a score that has decayed rather than on the one the class was
    /// frozen at when it was last analyzed. Without that a refusal is
    /// permanent, because a refused request never reaches the response
    /// phase that used to be the only thing that rotated.
    ///
    /// A class with no history is admitted. A score that has never been
    /// computed is not a bad score, and refusing on the absence of
    /// evidence would refuse every caller for the first
    /// `min_observations` requests after every restart.
    pub fn admission_for(
        &self,
        tenant: &str,
        agent_class: &str,
        today: NaiveDate,
    ) -> Option<(ReputationAction, f64)> {
        if !self.settings.admission_configured() {
            return None;
        }
        let score = self.refresh_reputation(tenant, agent_class, today)?;
        self.settings
            .action_for(score)
            .map(|action| (action, score))
    }

    /// Analyze one request and return every verdict it produced.
    ///
    /// `today` is a parameter rather than a `Utc::now()` call so the
    /// day-boundary behavior is testable without waiting a day.
    pub fn analyze_on(
        &self,
        view: &RequestContextView<'_>,
        today: NaiveDate,
    ) -> Vec<AnomalyVerdict> {
        let agent_class = view.agent_id.unwrap_or("unknown");
        let key = Self::key_for(view.tenant_id, agent_class);
        let shard = self.shard_for(&key);
        let mut guard = shard.lock();
        if !guard.contains_key(&key) && !self.reserve_key_slot() {
            // The budget is spent. Make room by dropping the key in
            // this shard nothing has asked about for longest, rather
            // than refusing to learn the new one: refusing meant
            // `reputation()` stayed `None` for it forever, and
            // `admission_for` reads `None` as "admit", so one tenant's
            // key growth switched off another tenant's enforcement.
            if !Self::evict_stalest(&mut guard) {
                // This shard is empty and the budget is still spent, so
                // every slot is held by another shard. Count it and say
                // nothing rather than judge on no baseline.
                sbproxy_observe::metrics::record_anomaly_key_budget_spent();
                return Vec::new();
            }
            sbproxy_observe::metrics::record_anomaly_key_budget_spent();
        }
        let histogram = guard.entry(key).or_default();
        histogram.rotate_to(today);
        histogram.last_analyzed = Some(today);

        let mut verdicts = Vec::new();

        // A JA4 the gateway does not trust (the connection came through
        // something that re-terminates TLS) is not evidence about the
        // caller, so it is neither observed nor judged.
        if let Some(ja4) = view.ja4_fingerprint.filter(|_| view.ja4_trustworthy) {
            if let Some(severity) = self.judge_categorical(histogram, FIELD_JA4, ja4, true) {
                verdicts.push(verdict(KIND_JA4_OUTLIER, severity, agent_class, ja4));
            }
        }
        if let Some(source) = view.agent_id_source {
            // A verified source is learned but never judged: becoming
            // verified is not an anomaly. See
            // `VERIFIED_IDENTITY_SOURCES`.
            let judge = !VERIFIED_IDENTITY_SOURCES.contains(&source);
            if let Some(severity) = self.judge_categorical(histogram, FIELD_ML_CLASS, source, judge)
            {
                verdicts.push(verdict(
                    KIND_ML_INCONSISTENCY,
                    severity,
                    agent_class,
                    source,
                ));
            }
        }
        if let Some(library) = view.headless_library {
            if let Some(severity) = self.judge_categorical(histogram, FIELD_HEADLESS, library, true)
            {
                // A headless library in the tail arrives with intent
                // attached, so it never stays at `info`.
                let severity = escalate_to_warn(severity);
                verdicts.push(verdict(
                    KIND_HEADLESS_LIBRARY,
                    severity,
                    agent_class,
                    library,
                ));
            }
        }
        if let Some(ip) = view.client_ip {
            let mean_before = histogram.mean_ip_rate_today();
            histogram.observe_request(ip);
            let count_now = histogram.ip_count_today(ip);
            if mean_before >= self.settings.rate_spike_min_mean
                && count_now as f64 > mean_before * self.settings.rate_spike_multiplier
            {
                let severity =
                    if count_now as f64 > mean_before * self.settings.rate_spike_multiplier * 5.0 {
                        SEVERITY_CRITICAL
                    } else {
                        SEVERITY_WARN
                    };
                // The IP is not in the reason string. It is client data
                // on a line that reaches logs and audit records, and the
                // access log already carries it under its own column.
                verdicts.push(AnomalyVerdict {
                    kind: KIND_REQUEST_RATE_SPIKE,
                    severity,
                    reason: format!(
                        "one address is at {count_now} requests today against a per-address \
                         mean of {mean_before:.1} for agent class {agent_class}"
                    ),
                });
            }
        }

        for entry in &verdicts {
            histogram.add_anomaly_weight(weight_for(entry.severity));
        }
        let score = score_from_weight(histogram.weighted_anomalies());
        drop(guard);

        // Published on every analysis, not only when a verdict fires.
        // Gated on a verdict, a class that produced four criticals on
        // day one and clean traffic for a month kept reading 0.80 on
        // the dashboard an operator was told to alert on, while its
        // internal weight had long since rolled out of the window.
        sbproxy_observe::metrics::set_agent_reputation_score(view.tenant_id, agent_class, score);
        // One atomic store, and the only figure that turns "the caps
        // are bounded" into a resident-set size an operator can plan
        // against. Published here rather than on a timer because there
        // is no timer to own and this is where the count changes.
        sbproxy_observe::metrics::set_anomaly_tracked_keys(self.tracked_keys());
        verdicts
    }

    /// Observe one value and say whether it is an outlier.
    ///
    /// The totals are read *before* the observation is recorded, so the
    /// very first sighting of a never-seen value can be flagged as long
    /// as the class has enough other history. Recording first would
    /// make every new value at least as frequent as one observation out
    /// of the window, which is the bug that makes this kind of detector
    /// silent on exactly the case it exists for.
    ///
    /// `judge` false observes without judging, for a dimension whose
    /// value is a property of the gateway's configuration rather than
    /// of the caller.
    fn judge_categorical(
        &self,
        histogram: &mut ClassHistogram,
        field: &'static str,
        value: &str,
        judge: bool,
    ) -> Option<&'static str> {
        let total = histogram.total_for_field(field);
        let prior = histogram.count_categorical(field, value);
        if !judge {
            histogram.observe_categorical(field, value, true);
            return None;
        }
        if total < self.settings.min_observations {
            histogram.observe_categorical(field, value, true);
            return None;
        }
        let frequency = prior as f64 / total as f64;
        if frequency >= self.settings.outlier_frequency {
            histogram.observe_categorical(field, value, true);
            return None;
        }
        let severity = severity_for_frequency(frequency, self.settings.outlier_frequency);
        // A value this call scored `critical` is counted but not
        // learned. Learning it is how a slow-ramp attacker buys its way
        // into the baseline: keep sending, cross the outlier threshold
        // on your own volume, and become the population that judges
        // everyone else.
        histogram.observe_categorical(field, value, severity != SEVERITY_CRITICAL);
        Some(severity)
    }
}

/// How rare something has to be before it stops being interesting and
/// starts being alarming.
fn severity_for_frequency(frequency: f64, threshold: f64) -> &'static str {
    if frequency == 0.0 {
        SEVERITY_CRITICAL
    } else if frequency < threshold / 10.0 {
        SEVERITY_WARN
    } else {
        SEVERITY_INFO
    }
}

fn escalate_to_warn(severity: &'static str) -> &'static str {
    if severity == SEVERITY_INFO {
        SEVERITY_WARN
    } else {
        severity
    }
}

fn weight_for(severity: &str) -> u32 {
    match severity {
        SEVERITY_CRITICAL => WEIGHT_CRITICAL,
        SEVERITY_WARN => WEIGHT_WARN,
        _ => 0,
    }
}

/// Build a verdict whose reason names the class and the dimension but
/// never the request.
fn verdict(
    kind: &'static str,
    severity: &'static str,
    agent_class: &str,
    value: &str,
) -> AnomalyVerdict {
    AnomalyVerdict {
        kind,
        severity,
        // The observed value is a fingerprint, a source label, or a
        // library name: gateway-derived categories, not request content.
        reason: format!("{value} is in the long tail for agent class {agent_class}"),
    }
}

// --- Installation ---

/// The live detector, or `None` when `proxy.anomaly` is absent or
/// disabled.
static DETECTOR: ArcSwapOption<AnomalyDetector> = ArcSwapOption::const_empty();

/// Guards the one hook registration this process makes.
static HOOK_REGISTERED: OnceLock<()> = OnceLock::new();

/// Install (or replace, or remove) the detector, and make sure exactly
/// one hook is registered for it.
///
/// The plugin registry only appends, so registering a hook per config
/// reload would leave one stale detector per reload running against the
/// same requests. What is registered is therefore a forwarder that
/// reads this slot, once per process; reload swaps the slot underneath
/// it, and disabling the feature swaps in `None` so the forwarder
/// returns nothing.
///
/// A reload whose resolved settings match the running detector's keeps
/// the running detector, window and all. Rebuilding unconditionally
/// meant any reload at all, including one triggered by a neighboring
/// file, threw away up to 28 days of baseline; a deployment reloading
/// daily could never accumulate one.
pub fn install(settings: Option<AnomalySettings>) {
    let next = match settings {
        None => None,
        Some(settings) => match DETECTOR.load_full() {
            Some(running) if *running.settings() == settings => Some(running),
            _ => Some(Arc::new(AnomalyDetector::new(settings))),
        },
    };
    DETECTOR.store(next);
    HOOK_REGISTERED.get_or_init(|| {
        sbproxy_plugin::register_anomaly_hook(Arc::new(ConfiguredDetectorHook));
    });
}

/// Install a detector built elsewhere, for the tests that need to drive
/// a seam with a pre-warmed window.
///
/// Test-only and `pub(crate)` on purpose. Production installs through
/// [`install`], which owns the reuse decision; a second public entry
/// point would let a caller swap the detector without it.
#[cfg(test)]
pub(crate) fn install_detector(detector: Option<Arc<AnomalyDetector>>) {
    DETECTOR.store(detector);
    HOOK_REGISTERED.get_or_init(|| {
        sbproxy_plugin::register_anomaly_hook(Arc::new(ConfiguredDetectorHook));
    });
}

/// The detector currently installed, if any.
pub fn detector() -> Option<Arc<AnomalyDetector>> {
    DETECTOR.load_full()
}

/// The registered hook. Holds no state of its own: it reads whatever
/// detector is installed at the moment the request runs.
struct ConfiguredDetectorHook;

impl sbproxy_plugin::AnomalyDetectorHook for ConfiguredDetectorHook {
    fn analyze<'a>(
        &'a self,
        ctx: &'a RequestContextView<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<AnomalyVerdict>> + Send + 'a>> {
        Box::pin(async move {
            let Some(detector) = detector() else {
                return Vec::new();
            };
            detector.analyze_on(ctx, chrono::Utc::now().date_naive())
        })
    }
}

/// Record what a verdict concluded, on every surface that carries it.
///
/// Called from the response phase for every verdict any registered
/// hook returns, including one from a plugin, so the metric counts what
/// the pipeline saw rather than what the built-in detector produced.
/// Before WOR-2666 the verdicts were dropped after a `debug!`, and
/// `sbproxy_anomaly_detected_total`, which the trait's own
/// documentation promised, did not exist.
///
/// Every severity logs at `info` or above. `debug!` for the `info`
/// severity meant a counted verdict had no record at all in a release
/// build, where `release_max_level_info` compiles the macro out: an
/// operator watching the `info` series climb during an incident could
/// not find out what had been flagged. The verdicts are already
/// rate-bounded by the outlier threshold, so this is not a volume
/// problem.
pub(crate) fn record_verdict(hostname: &str, verdict: &AnomalyVerdict) {
    sbproxy_observe::metrics::record_anomaly_detected(verdict.kind, verdict.severity);
    match verdict.severity {
        SEVERITY_CRITICAL | SEVERITY_WARN => tracing::warn!(
            hostname = %hostname,
            kind = verdict.kind,
            severity = verdict.severity,
            reason = %verdict.reason,
            "anomaly detected"
        ),
        _ => tracing::info!(
            hostname = %hostname,
            kind = verdict.kind,
            severity = verdict.severity,
            reason = %verdict.reason,
            "anomaly detected"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AnomalySettings {
        AnomalySettings {
            min_observations: 50,
            outlier_frequency: 0.01,
            rate_spike_multiplier: 10.0,
            rate_spike_min_mean: 5.0,
            deny_below: None,
            challenge_below: None,
        }
    }

    fn view<'a>(
        agent_class: &'a str,
        ja4: Option<&'a str>,
        headless: Option<&'a str>,
        ip: Option<IpAddr>,
    ) -> RequestContextView<'a> {
        RequestContextView {
            tenant_id: "acme",
            hostname: "api.test",
            method: "GET",
            path: "/",
            query: "",
            agent_id: Some(agent_class),
            agent_id_source: None,
            ja4_fingerprint: ja4,
            ja4_trustworthy: ja4.is_some(),
            headless_library: headless,
            client_ip: ip,
        }
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 27).expect("a real date")
    }

    /// What the `sbproxy_agent_reputation_score` gauge currently reads
    /// for one tenant and class. The gauge is the surface an operator
    /// alerts on, so a claim about recovery has to be checked here
    /// rather than on the internal accessor.
    fn published_score(tenant: &str, agent_class: &str) -> Option<f64> {
        sbproxy_observe::metrics::metrics()
            .agent_reputation_score
            .as_ref()
            .map(|gauge| gauge.with_label_values(&[tenant, agent_class]).get())
    }

    #[test]
    fn a_cold_detector_says_nothing() {
        let detector = AnomalyDetector::new(settings());
        // The first request presents a fingerprint nothing has ever
        // seen, and gets no verdict, because there is no baseline to
        // call it rare against.
        let verdicts =
            detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), today());
        assert!(verdicts.is_empty(), "{verdicts:?}");
    }

    #[test]
    fn a_novel_fingerprint_is_flagged_once_a_baseline_exists() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..60 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        let verdicts =
            detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), today());
        assert_eq!(verdicts.len(), 1, "{verdicts:?}");
        assert_eq!(verdicts[0].kind, KIND_JA4_OUTLIER);
        assert_eq!(
            verdicts[0].severity, SEVERITY_CRITICAL,
            "a fingerprint with no prior observations at all is the strongest case"
        );
    }

    #[test]
    fn the_usual_fingerprint_is_never_flagged() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..200 {
            let verdicts =
                detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
            assert!(verdicts.is_empty(), "{verdicts:?}");
        }
    }

    #[test]
    fn an_untrusted_fingerprint_is_neither_learned_nor_judged() {
        let detector = AnomalyDetector::new(settings());
        let mut untrusted = view("gptbot", Some("t13d_CDN"), None, None);
        untrusted.ja4_trustworthy = false;
        for _ in 0..200 {
            assert!(detector.analyze_on(&untrusted, today()).is_empty());
        }
        // Nothing was learned, so a genuine baseline is still absent
        // and a novel fingerprint is still unjudgeable.
        let verdicts = detector.analyze_on(&view("gptbot", Some("t13d_NEW"), None, None), today());
        assert!(
            verdicts.is_empty(),
            "a fingerprint the gateway does not trust must not become the baseline"
        );
    }

    /// WOR-2666 review F14. The old shape was
    /// `if let Some(entry) = verdicts.first()`, which passed when
    /// nothing was flagged: deleting the whole `headless_library` arm
    /// left it green. The fixture also observed the literal `"none"`,
    /// which the request path never produces, because
    /// `HeadlessSignal::NotDetected` maps to `None` and is not
    /// observed at all. Two real library names is the population the
    /// detector actually sees.
    #[test]
    fn a_headless_library_in_the_tail_never_stays_at_info() {
        let detector = AnomalyDetector::new(settings());
        // 995 playwright detections and 5 puppeteer ones, so puppeteer
        // sits at 0.5% of the class's headless detections: inside the
        // 1% outlier threshold, and above zero, which on frequency
        // alone would score `info`.
        for index in 0..1000 {
            let library = if index % 200 == 0 {
                "puppeteer"
            } else {
                "playwright"
            };
            detector.analyze_on(&view("browser", None, Some(library), None), today());
        }
        let verdicts =
            detector.analyze_on(&view("browser", None, Some("puppeteer"), None), today());
        let entry = verdicts
            .first()
            .expect("a library in the tail of the class's headless detections must be flagged");
        assert_eq!(entry.kind, KIND_HEADLESS_LIBRARY);
        assert_ne!(
            entry.severity, SEVERITY_INFO,
            "a headless library arrives with intent attached"
        );
    }

    #[test]
    fn one_address_far_past_the_mean_is_a_rate_spike() {
        let detector = AnomalyDetector::new(settings());
        // Twenty quiet addresses, ten requests each, to establish a
        // mean the spike check will engage against.
        for octet in 1..=20u8 {
            let ip: IpAddr = format!("10.0.0.{octet}").parse().expect("an address");
            for _ in 0..10 {
                detector.analyze_on(&view("gptbot", None, None, Some(ip)), today());
            }
        }
        let noisy: IpAddr = "10.0.9.9".parse().expect("an address");
        let mut flagged = None;
        for _ in 0..400 {
            let verdicts = detector.analyze_on(&view("gptbot", None, None, Some(noisy)), today());
            if let Some(entry) = verdicts.into_iter().next() {
                flagged = Some(entry);
                break;
            }
        }
        let entry = flagged.expect("a sustained burst from one address must be flagged");
        assert_eq!(entry.kind, KIND_REQUEST_RATE_SPIKE);
    }

    /// WOR-2666 re-review N8, red first. `examples/anomaly-detection/`
    /// ships a walkthrough with exact numbers in it, and nothing
    /// checked them: the settings it uses are not the ones any other
    /// test exercises, and the first version's "nothing is flagged
    /// yet" step actually fired twice, because `mean_before` is read
    /// before the observation, so with one address the count is always
    /// one past the mean.
    ///
    /// This is the example's config and the example's walkthrough. If
    /// it goes red, the README is wrong.
    #[test]
    fn the_shipped_example_walkthrough_produces_the_numbers_it_prints() {
        const EXAMPLE_MIN_MEAN: f64 = 6.0;
        const EXAMPLE_MULTIPLIER: f64 = 1.0;
        const QUIET_REQUESTS: usize = 5;
        const NOISY_REQUESTS: usize = 8;

        let detector = AnomalyDetector::new(AnomalySettings {
            min_observations: 5,
            outlier_frequency: 0.01,
            rate_spike_multiplier: EXAMPLE_MULTIPLIER,
            rate_spike_min_mean: EXAMPLE_MIN_MEAN,
            deny_below: None,
            challenge_below: None,
        });
        let quiet: IpAddr = "198.51.100.7".parse().expect("an address");
        let noisy: IpAddr = "203.0.113.9".parse().expect("an address");

        // Step one: five requests from one address. The README says
        // nothing is flagged, and with one address the per-address mean
        // is that address's own rate, so nothing can be meaningfully
        // past it.
        for _ in 0..QUIET_REQUESTS {
            let verdicts = detector.analyze_on(&view("unknown", None, None, Some(quiet)), today());
            assert!(
                verdicts.is_empty(),
                "the first loop must stay quiet or the README's first step is a lie: {verdicts:?}"
            );
        }

        // Step two: eight from a second address. Exactly one fires, and
        // it is the last one.
        let mut flagged = Vec::new();
        for request in 1..=NOISY_REQUESTS {
            let verdicts = detector.analyze_on(&view("unknown", None, None, Some(noisy)), today());
            for entry in verdicts {
                flagged.push((request, entry));
            }
        }
        assert_eq!(
            flagged.len(),
            1,
            "the README prints a count of 1: {flagged:?}"
        );
        let (request, entry) = &flagged[0];
        assert_eq!(*request, NOISY_REQUESTS, "and says which request fires it");
        assert_eq!(entry.kind, KIND_REQUEST_RATE_SPIKE);
        assert_eq!(entry.severity, SEVERITY_WARN, "the README prints `warn`");
        assert_eq!(
            detector.reputation("acme", "unknown"),
            Some(0.99),
            "one warn is one point of a hundred, which is the score the README prints"
        );
    }

    #[test]
    fn a_rate_spike_reason_does_not_carry_the_address() {
        let detector = AnomalyDetector::new(settings());
        for octet in 1..=20u8 {
            let ip: IpAddr = format!("10.0.0.{octet}").parse().expect("an address");
            for _ in 0..10 {
                detector.analyze_on(&view("gptbot", None, None, Some(ip)), today());
            }
        }
        let noisy: IpAddr = "203.0.113.7".parse().expect("an address");
        for _ in 0..400 {
            for entry in detector.analyze_on(&view("gptbot", None, None, Some(noisy)), today()) {
                assert!(
                    !entry.reason.contains("203.0.113.7"),
                    "a client address must not ride the reason string: {}",
                    entry.reason
                );
            }
        }
    }

    /// WOR-2666 review F7, red first. This used to assert on
    /// `detector.reputation()`, which no production code called, so it
    /// passed while the *gauge* an operator alerts on stayed pinned at
    /// the class's worst score for the whole month it was recovering.
    /// The assertion is on the gauge now.
    #[test]
    fn the_window_rolls_and_the_published_score_recovers() {
        let tenant = "f7-tenant";
        let class = "f7-class";
        let detector = AnomalyDetector::new(settings());
        let mut usual = view(class, Some("t13d_USUAL"), None, None);
        usual.tenant_id = tenant;
        for _ in 0..60 {
            detector.analyze_on(&usual, today());
        }
        let mut novel = view(class, Some("t13d_NOVEL"), None, None);
        novel.tenant_id = tenant;
        assert!(!detector.analyze_on(&novel, today()).is_empty());
        let bruised = published_score(tenant, class).expect("the gauge is registered");
        assert!(
            bruised < 1.0,
            "a critical verdict must move the published score, not only the internal one"
        );

        // Twenty-nine days later, every bucket holding that verdict has
        // rolled out of the window, and the class is sending clean
        // traffic that produces no verdict at all.
        let later = today() + chrono::Duration::days(WINDOW_DAYS as i64 + 1);
        let verdicts = detector.analyze_on(&usual, later);
        assert!(
            verdicts.is_empty(),
            "the recovering request must produce nothing, which is the whole point: \
             the gauge has to move without a verdict to trigger it"
        );
        assert_eq!(
            published_score(tenant, class),
            Some(1.0),
            "a class that stopped misbehaving must recover on the gauge an operator alerts on"
        );
    }

    /// WOR-2666 review F8, red first. The histogram and the gauge used
    /// to be keyed on the agent class alone, so one tenant's crawler
    /// decided what another tenant's threshold read.
    #[test]
    fn reputation_is_keyed_per_tenant() {
        let detector = AnomalyDetector::new(settings());
        let mut noisy = view("shared-class", Some("t13d_USUAL"), None, None);
        noisy.tenant_id = "tenant-a";
        for _ in 0..60 {
            detector.analyze_on(&noisy, today());
        }
        let mut novel = view("shared-class", Some("t13d_NOVEL"), None, None);
        novel.tenant_id = "tenant-a";
        assert!(!detector.analyze_on(&novel, today()).is_empty());

        assert!(
            detector
                .reputation("tenant-a", "shared-class")
                .expect("seen")
                < 1.0,
            "the tenant whose traffic produced the verdict carries it"
        );
        assert_eq!(
            detector.reputation("tenant-b", "shared-class"),
            None,
            "a second tenant with the same class name must not inherit the first tenant's score"
        );
    }

    /// WOR-2666 review F2, red first. Every categorical dimension is
    /// client-controlled, and the denominator used to be a sum over the
    /// distinct-value map: `O(28 x distinct)` per field per request,
    /// under one process-global lock, with `distinct` inflatable to the
    /// cap from a varied ClientHello.
    ///
    /// Two bounds are asserted, both structural rather than timed. The
    /// distinct set never grows past its cap, and the denominator is a
    /// running counter (28 integer loads) that still reports every
    /// observation after eviction has thrown values away.
    #[test]
    fn client_controlled_variation_cannot_inflate_the_per_request_scan() {
        let detector = AnomalyDetector::new(settings());
        let flood = MAX_CATEGORICAL_VALUES_PER_DAY * 4;
        for index in 0..flood {
            let ja4 = format!("t13d_{index:06}");
            detector.analyze_on(&view("gptbot", Some(&ja4), None, None), today());
        }

        let key = AnomalyDetector::key_for("acme", "gptbot");
        let guard = detector.shard_for(&key).lock();
        let histogram = guard.get(&key).expect("the class is tracked");
        let distinct = histogram.days[0]
            .categorical
            .get(FIELD_JA4)
            .map(|counts| counts.len())
            .unwrap_or(0);
        assert!(
            distinct <= MAX_CATEGORICAL_VALUES_PER_DAY,
            "a caller varying its ClientHello must not grow the distinct set past the cap, \
             got {distinct}"
        );
        assert_eq!(
            histogram.days[0].categorical_totals.get(FIELD_JA4).copied(),
            Some(flood as u64),
            "the denominator is a running counter, so it survives eviction and costs 28 loads"
        );
        assert_eq!(
            histogram.total_for_field(FIELD_JA4),
            flood as u64,
            "and the window total reads the same counter"
        );
    }

    /// WOR-2666 review F15, red first. A value flagged `critical` used
    /// to be trained into the baseline by the very call that flagged
    /// it, so a client that kept sending crossed the outlier threshold
    /// on its own volume and stopped being flagged.
    #[test]
    fn a_flagged_value_is_not_trained_into_the_baseline() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..1000 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        // Well past 1% of the window if every sighting were learned.
        let mut flagged = 0usize;
        for _ in 0..200 {
            let verdicts =
                detector.analyze_on(&view("gptbot", Some("t13d_ATTACK"), None, None), today());
            if verdicts.iter().any(|v| v.kind == KIND_JA4_OUTLIER) {
                flagged += 1;
            }
        }
        assert_eq!(
            flagged, 200,
            "an attacker must not be able to launder its own fingerprint into the baseline"
        );
    }

    /// WOR-2666 review F9, red first. `ml_inconsistency` judges the
    /// resolver-source label, so turning on Web Bot Auth for an
    /// established class used to score the first verified request
    /// `critical` and floor the class for having become verified.
    #[test]
    fn becoming_verified_is_not_an_anomaly() {
        let detector = AnomalyDetector::new(settings());
        let mut unverified = view("gptbot", None, None, None);
        unverified.agent_id_source = Some("user_agent");
        for _ in 0..1000 {
            detector.analyze_on(&unverified, today());
        }

        let mut verified = view("gptbot", None, None, None);
        verified.agent_id_source = Some("bot_auth");
        let verdicts = detector.analyze_on(&verified, today());
        assert!(
            verdicts.is_empty(),
            "an operator enabling Web Bot Auth must not be told their class is anomalous: \
             {verdicts:?}"
        );
        assert_eq!(
            detector.reputation("acme", "gptbot"),
            Some(1.0),
            "and the class must not be floored for strengthening its identity"
        );
    }

    /// The other direction still fires: a class whose population is
    /// verified, arriving unverified, is exactly what this dimension is
    /// for.
    #[test]
    fn a_verified_class_arriving_unverified_is_still_flagged() {
        let detector = AnomalyDetector::new(settings());
        let mut verified = view("gptbot", None, None, None);
        verified.agent_id_source = Some("bot_auth");
        for _ in 0..1000 {
            detector.analyze_on(&verified, today());
        }
        let mut unverified = view("gptbot", None, None, None);
        unverified.agent_id_source = Some("user_agent");
        let verdicts = detector.analyze_on(&unverified, today());
        assert_eq!(verdicts.len(), 1, "{verdicts:?}");
        assert_eq!(verdicts[0].kind, KIND_ML_INCONSISTENCY);
    }

    #[test]
    fn the_score_is_linear_and_saturating() {
        assert_eq!(score_from_weight(0), 1.0);
        assert!((score_from_weight(50) - 0.5).abs() < f64::EPSILON);
        assert_eq!(score_from_weight(100), 0.0);
        assert_eq!(
            score_from_weight(u32::MAX),
            0.0,
            "the score must saturate rather than go negative"
        );
    }

    #[test]
    fn the_tracked_key_count_is_capped() {
        let detector = AnomalyDetector::new(settings());
        for index in 0..(MAX_TRACKED_KEYS + 20) {
            let class = format!("class-{index}");
            detector.analyze_on(&view(&class, Some("t13d"), None, None), today());
        }
        let tracked: usize = detector.shards.iter().map(|shard| shard.lock().len()).sum();
        assert_eq!(
            tracked, MAX_TRACKED_KEYS,
            "a caller passing arbitrary class strings must not grow the window without bound"
        );
    }

    /// WOR-2666 re-review N6, red first. Past the cap the detector used
    /// to refuse to learn a new key, and `admission_for` reads a
    /// missing score as "admit", so one tenant's key growth silently
    /// switched off another tenant's `deny_below`. It evicts the
    /// stalest key in the shard instead, so a class that arrives after
    /// the cap is still judged.
    #[test]
    fn a_key_arriving_past_the_cap_is_still_judged() {
        let detector = AnomalyDetector::new(settings());
        for index in 0..MAX_TRACKED_KEYS {
            let class = format!("class-{index}");
            detector.analyze_on(&view(&class, Some("t13d"), None, None), today());
        }
        assert_eq!(detector.tracked_keys(), MAX_TRACKED_KEYS);

        // A new class, arriving with the budget already spent. Give it
        // a baseline and then a novel fingerprint: it has to be flagged,
        // which is only possible if it got a window at all.
        let latecomer = "class-arrived-late";
        for _ in 0..60 {
            detector.analyze_on(&view(latecomer, Some("t13d_USUAL"), None, None), today());
        }
        let verdicts =
            detector.analyze_on(&view(latecomer, Some("t13d_NOVEL"), None, None), today());
        assert_eq!(
            verdicts.len(),
            1,
            "a class that arrived after the cap must still be judged, or the cap is a way to \
             switch enforcement off: {verdicts:?}"
        );
        assert!(
            detector.reputation("acme", latecomer).is_some(),
            "and it must have a score, because no score is admitted"
        );
        assert_eq!(
            detector.tracked_keys(),
            MAX_TRACKED_KEYS,
            "while the bound still holds"
        );
    }

    #[test]
    fn settings_clamp_values_that_would_disable_the_detector_silently() {
        let clamped = AnomalySettings::from_config(&sbproxy_config::AnomalyConfig {
            enabled: true,
            min_observations: 0,
            outlier_frequency: 0.0,
            rate_spike_multiplier: 0.0,
            rate_spike_min_mean: -5.0,
            reputation: sbproxy_config::AnomalyReputationConfig::default(),
        });
        assert_eq!(clamped.min_observations, 1);
        assert_eq!(
            clamped.outlier_frequency, MIN_OUTLIER_FREQUENCY,
            "a zero threshold must clamp to a real floor, not to 2.2e-308, which flags only a \
             value with literally no history and reads as a configured, silent detector"
        );
        assert_eq!(clamped.rate_spike_multiplier, 1.0);
        assert_eq!(clamped.rate_spike_min_mean, 0.0);
        assert_eq!(clamped.deny_below, None, "admission is off by default");
        assert_eq!(clamped.challenge_below, None);
    }

    /// WOR-2666 ruling 3. Thresholds are unset by default and the score
    /// stays advisory; setting one turns the published number into an
    /// admission decision.
    #[test]
    fn admission_reads_the_score_only_when_a_threshold_is_set() {
        let advisory = AnomalyDetector::new(settings());
        for _ in 0..60 {
            advisory.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        advisory.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), today());
        assert!(
            advisory.admission_for("acme", "gptbot", today()).is_none(),
            "the default must publish the score and act on nothing"
        );

        let mut gated = settings();
        gated.deny_below = Some(0.5);
        gated.challenge_below = Some(0.99);
        let detector = AnomalyDetector::new(gated);
        for _ in 0..60 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        // One critical verdict is weight 5, so the score is 0.95:
        // under the challenge floor and over the deny floor.
        detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), today());
        let (action, score) = detector
            .admission_for("acme", "gptbot", today())
            .expect("a score under the challenge floor is an admission decision");
        assert_eq!(action, ReputationAction::Challenge);
        assert!(score < 0.99 && score > 0.5, "{score}");

        // Nineteen more criticals floor the class, and deny wins over
        // challenge once both floors match.
        for index in 0..19 {
            let ja4 = format!("t13d_NOVEL_{index}");
            detector.analyze_on(&view("gptbot", Some(&ja4), None, None), today());
        }
        let (action, _) = detector
            .admission_for("acme", "gptbot", today())
            .expect("a floored class is still an admission decision");
        assert_eq!(
            action,
            ReputationAction::Deny,
            "deny has to win over challenge when both floors match"
        );
    }

    /// A class nobody has seen is admitted. Refusing on the absence of
    /// evidence would refuse every caller for the first
    /// `min_observations` requests after every restart.
    #[test]
    fn an_unseen_class_is_admitted() {
        let mut gated = settings();
        gated.deny_below = Some(1.0);
        let detector = AnomalyDetector::new(gated);
        assert!(detector
            .admission_for("acme", "never-seen", today())
            .is_none());
    }

    #[test]
    fn reputation_buckets_are_a_closed_set() {
        assert_eq!(reputation_bucket(1.0), "clean");
        assert_eq!(reputation_bucket(0.9), "clean");
        assert_eq!(reputation_bucket(0.7), "watch");
        assert_eq!(reputation_bucket(0.4), "suspect");
        assert_eq!(reputation_bucket(0.39), "bad");
        assert_eq!(reputation_bucket(0.0), "floored");
    }

    #[test]
    fn a_gap_longer_than_the_window_clears_the_baseline() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..60 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        let much_later = today() + chrono::Duration::days(400);
        let verdicts =
            detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), much_later);
        assert!(
            verdicts.is_empty(),
            "a year-old population must not judge today's traffic"
        );
    }

    /// The seam, by name. `AnomalyDetectorHook` was declared, the
    /// registry was iterated from the response phase, and nothing
    /// implemented the trait, so the loop ran over an empty list on
    /// every request. What this pins is that a configured detector
    /// reaches that loop.
    ///
    /// **Process-global state, and the constraint that makes it safe.**
    /// This test and `a_reload_that_changes_nothing_keeps_the_window`
    /// both write `DETECTOR`, which `CompiledPipeline::from_config`
    /// also writes. Nextest runs each test in its own process, which is
    /// what keeps them from racing; `cargo test` does not, and neither
    /// does any future test in this crate that compiles a config with
    /// `proxy.anomaly` enabled. A `parking_lot` guard held across the
    /// awaits below would trip `clippy::await_holding_lock`, so the
    /// constraint is written down rather than enforced: run this crate
    /// under nextest, and put any third detector-mutating test here
    /// beside these two.
    #[tokio::test]
    async fn an_installed_detector_is_reachable_through_the_plugin_registry() {
        let detector = Arc::new(AnomalyDetector::new(settings()));
        for _ in 0..60 {
            detector.analyze_on(
                &view("registry-probe", Some("t13d_USUAL"), None, None),
                today(),
            );
        }
        install_detector(Some(detector));

        let probe = view("registry-probe", Some("t13d_NOVEL"), None, None);
        let mut saw_verdict = false;
        for hook in sbproxy_plugin::anomaly_hooks().iter() {
            for entry in hook.analyze(&probe).await {
                if entry.kind == KIND_JA4_OUTLIER {
                    saw_verdict = true;
                }
            }
        }
        assert!(
            saw_verdict,
            "a configured detector must be reachable from the registry the response phase iterates"
        );

        // Turning the block off takes the detector out with it: the
        // registration stays (the registry only appends) and the
        // forwarder finds nothing to forward to.
        install_detector(None);
        let mut saw_after_removal = false;
        for hook in sbproxy_plugin::anomaly_hooks().iter() {
            saw_after_removal |= !hook.analyze(&probe).await.is_empty();
        }
        assert!(
            !saw_after_removal,
            "a disabled detector must produce nothing, not a stale one"
        );
    }

    /// WOR-2666 review F10, red first. Every reload used to build a
    /// fresh detector with an empty map, so a deployment reloading
    /// daily never accumulated a baseline past 24 hours and read as a
    /// quiet network.
    ///
    /// Mutates the process-global `DETECTOR`; see the note on
    /// `an_installed_detector_is_reachable_through_the_plugin_registry`.
    #[test]
    fn a_reload_that_changes_nothing_keeps_the_window() {
        install_detector(None);
        install(Some(settings()));
        let first = detector().expect("installed");
        for _ in 0..60 {
            first.analyze_on(
                &view("reload-probe", Some("t13d_USUAL"), None, None),
                today(),
            );
        }

        install(Some(settings()));
        let second = detector().expect("still installed");
        assert!(
            Arc::ptr_eq(&first, &second),
            "an unchanged config must keep the running detector, window and all"
        );
        let verdicts = second.analyze_on(
            &view("reload-probe", Some("t13d_NOVEL"), None, None),
            today(),
        );
        assert!(
            !verdicts.is_empty(),
            "and the baseline it learned has to still be there"
        );

        // A reload that genuinely changes the settings does start over,
        // which is the honest cost and is documented as one.
        let mut changed = settings();
        changed.min_observations = 5;
        install(Some(changed));
        let third = detector().expect("installed");
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(third.reputation("acme", "reload-probe"), None);
        install_detector(None);
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_rotate() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..60 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        let yesterday = today() - chrono::Duration::days(1);
        let verdicts =
            detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), yesterday);
        assert_eq!(
            verdicts.len(),
            1,
            "a backwards clock must not throw away the baseline"
        );
    }
}
