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
//! agent class of the categorical signals the proxy already collects,
//! and flags an observation whose relative frequency sits in the long
//! tail:
//!
//! * **`ja4_outlier`** - a TLS fingerprint this agent class has
//!   essentially never presented before. A crawler that claims to be
//!   GPTBot and dials with a JA4 no GPTBot has ever used is the case
//!   this is for.
//! * **`ml_inconsistency`** - the ML classifier's verdict disagrees
//!   with what the class normally produces.
//! * **`headless_library`** - a headless-browser library showing up in
//!   the tail. Always at least `warn`, because it is a signal that
//!   arrives with intent attached.
//! * **`request_rate_spike`** - one IP past the class's per-IP mean by
//!   a configured multiple today.
//!
//! Comparative detection buys the thing a rule list cannot: it needs no
//! prior knowledge of the attack. It costs the thing a rule list has:
//! it says nothing until it has a baseline, which is what
//! `min_observations` is the floor for, and it is only as good as the
//! traffic it learned from.
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
//! # Reputation
//!
//! Verdicts feed a per-agent-class score, published as
//! `sbproxy_agent_reputation_score`. Weighted counts decay by rolling
//! out of the same 28-day window rather than by a scheduled sweep, so a
//! class that stops misbehaving recovers on its own and there is no
//! timer task to own or to fail.
//!
//! **What reads the score is an operator, not the request path.** The
//! score is a gauge and a console panel today, deliberately: wiring it
//! into an admission decision means answering what a request should do
//! when its class scores 0.4, and that question has not been answered
//! yet. Publishing a number nobody has decided how to act on is honest;
//! acting on it without deciding is not.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use chrono::NaiveDate;
use parking_lot::Mutex;
use sbproxy_plugin::{AnomalyVerdict, RequestContextView};

/// Days the rolling window spans.
const WINDOW_DAYS: usize = 28;

/// Agent classes tracked at once.
///
/// The class comes from the resolver's closed taxonomy, so this cap is
/// never reached in a healthy deployment. It exists because the
/// detector would otherwise allocate a 28-day histogram for whatever
/// string reached it, and "the caller only ever passes taxonomy values"
/// is an invariant held by convention rather than by the type.
const MAX_TRACKED_CLASSES: usize = 64;

/// Distinct IPs tracked per class per day.
const MAX_IPS_TRACKED: usize = 4096;

/// Distinct categorical values tracked per field per day. Anything past
/// this falls into one overflow bucket, which the detector treats as a
/// value with no learned baseline.
const MAX_CATEGORICAL_VALUES_PER_DAY: usize = 1024;

/// Histogram field for TLS fingerprints.
const FIELD_JA4: &str = "ja4";
/// Histogram field for ML classifier verdicts.
const FIELD_ML_CLASS: &str = "ml_class";
/// Histogram field for headless-library detections.
const FIELD_HEADLESS: &str = "headless_library";

/// Weighted count at which a class's score reaches zero.
const REPUTATION_SATURATION: f64 = 100.0;
/// Weight one `warn` verdict contributes to the score.
const WEIGHT_WARN: u32 = 1;
/// Weight one `critical` verdict contributes. Five times a warning, so
/// a single critical finding visibly moves the number.
const WEIGHT_CRITICAL: u32 = 5;

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

/// One day's counts for one agent class.
#[derive(Debug, Default, Clone)]
struct DayBucket {
    day: Option<NaiveDate>,
    categorical: HashMap<&'static str, HashMap<String, u64>>,
    per_ip: HashMap<IpAddr, u64>,
    /// Weighted anomaly count for the day, feeding the reputation
    /// score. Held here rather than in a second structure so it decays
    /// by the same rotation as everything else.
    anomaly_weight: u32,
}

/// A rolling day-bucketed histogram for one agent class.
#[derive(Debug, Clone)]
struct ClassHistogram {
    /// Index 0 is today; index `WINDOW_DAYS - 1` is the oldest day
    /// still inside the window.
    days: Vec<DayBucket>,
}

impl Default for ClassHistogram {
    fn default() -> Self {
        Self {
            days: vec![DayBucket::default(); WINDOW_DAYS],
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
            self.days = vec![DayBucket::default(); WINDOW_DAYS];
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

    fn observe_categorical(&mut self, field: &'static str, value: &str) {
        let bucket = &mut self.days[0];
        let counts = bucket.categorical.entry(field).or_default();
        if counts.len() >= MAX_CATEGORICAL_VALUES_PER_DAY && !counts.contains_key(value) {
            *counts.entry("__overflow__".to_string()).or_insert(0) += 1;
            return;
        }
        *counts.entry(value.to_string()).or_insert(0) += 1;
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

    fn count_categorical(&self, field: &'static str, value: &str) -> u64 {
        self.days
            .iter()
            .filter_map(|day| day.categorical.get(field))
            .filter_map(|counts| counts.get(value))
            .sum()
    }

    fn total_for_field(&self, field: &'static str) -> u64 {
        self.days
            .iter()
            .filter_map(|day| day.categorical.get(field))
            .flat_map(|counts| counts.values().copied())
            .sum()
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

/// Detector settings, resolved from `proxy.anomaly`.
#[derive(Debug, Clone)]
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
            outlier_frequency: config.outlier_frequency.clamp(f64::MIN_POSITIVE, 1.0),
            rate_spike_multiplier: config.rate_spike_multiplier.max(1.0),
            rate_spike_min_mean: config.rate_spike_min_mean.max(0.0),
        }
    }
}

/// The rolling histogram, its settings, and the reputation it feeds.
pub struct AnomalyDetector {
    settings: AnomalySettings,
    classes: Mutex<HashMap<String, ClassHistogram>>,
}

impl std::fmt::Debug for AnomalyDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalyDetector")
            .field("settings", &self.settings)
            .field("tracked_classes", &self.classes.lock().len())
            .finish()
    }
}

impl AnomalyDetector {
    /// Build a detector with the given settings and an empty window.
    pub fn new(settings: AnomalySettings) -> Self {
        Self {
            settings,
            classes: Mutex::new(HashMap::new()),
        }
    }

    /// Reputation score for one agent class, or `None` when the class
    /// has never been seen.
    pub fn reputation(&self, agent_class: &str) -> Option<f64> {
        self.classes
            .lock()
            .get(agent_class)
            .map(|histogram| score_from_weight(histogram.weighted_anomalies()))
    }

    /// Analyse one request and return every verdict it produced.
    ///
    /// `today` is a parameter rather than a `Utc::now()` call so the
    /// day-boundary behavior is testable without waiting a day.
    pub fn analyze_on(
        &self,
        view: &RequestContextView<'_>,
        today: NaiveDate,
    ) -> Vec<AnomalyVerdict> {
        let agent_class = view.agent_id.unwrap_or("unknown");
        let mut guard = self.classes.lock();
        if !guard.contains_key(agent_class) && guard.len() >= MAX_TRACKED_CLASSES {
            // Past the cap the detector stops learning new classes
            // rather than growing without bound. Silence is the right
            // failure here: a fabricated verdict is worse than none.
            return Vec::new();
        }
        let histogram = guard.entry(agent_class.to_string()).or_default();
        histogram.rotate_to(today);

        let mut verdicts = Vec::new();

        // A JA4 the gateway does not trust (the connection came through
        // something that re-terminates TLS) is not evidence about the
        // caller, so it is neither observed nor judged.
        if let Some(ja4) = view.ja4_fingerprint.filter(|_| view.ja4_trustworthy) {
            if let Some(severity) = self.judge_categorical(histogram, FIELD_JA4, ja4) {
                verdicts.push(verdict(KIND_JA4_OUTLIER, severity, agent_class, ja4));
            }
        }
        if let Some(source) = view.agent_id_source {
            if let Some(severity) = self.judge_categorical(histogram, FIELD_ML_CLASS, source) {
                verdicts.push(verdict(
                    KIND_ML_INCONSISTENCY,
                    severity,
                    agent_class,
                    source,
                ));
            }
        }
        if let Some(library) = view.headless_library {
            if let Some(severity) = self.judge_categorical(histogram, FIELD_HEADLESS, library) {
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

        if !verdicts.is_empty() {
            sbproxy_observe::metrics::set_agent_reputation_score(agent_class, score);
        }
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
    fn judge_categorical(
        &self,
        histogram: &mut ClassHistogram,
        field: &'static str,
        value: &str,
    ) -> Option<&'static str> {
        let total = histogram.total_for_field(field);
        let prior = histogram.count_categorical(field, value);
        histogram.observe_categorical(field, value);
        if total < self.settings.min_observations {
            return None;
        }
        let frequency = prior as f64 / total as f64;
        if frequency >= self.settings.outlier_frequency {
            return None;
        }
        Some(severity_for_frequency(
            frequency,
            self.settings.outlier_frequency,
        ))
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
pub fn install(detector: Option<Arc<AnomalyDetector>>) {
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
        _ => tracing::debug!(
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
        }
    }

    fn view<'a>(
        agent_class: &'a str,
        ja4: Option<&'a str>,
        headless: Option<&'a str>,
        ip: Option<IpAddr>,
    ) -> RequestContextView<'a> {
        RequestContextView {
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

    #[test]
    fn a_headless_library_in_the_tail_never_stays_at_info() {
        let detector = AnomalyDetector::new(settings());
        // Build a baseline where `puppeteer` is rare but present, which
        // on its own would score `info`.
        for index in 0..1000 {
            let library = if index % 200 == 0 {
                "puppeteer"
            } else {
                "none"
            };
            detector.analyze_on(&view("browser", None, Some(library), None), today());
        }
        let verdicts =
            detector.analyze_on(&view("browser", None, Some("puppeteer"), None), today());
        if let Some(entry) = verdicts.first() {
            assert_ne!(
                entry.severity, SEVERITY_INFO,
                "a headless library arrives with intent attached"
            );
        }
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

    #[test]
    fn the_window_rolls_and_the_score_recovers() {
        let detector = AnomalyDetector::new(settings());
        for _ in 0..60 {
            detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), today());
        }
        let verdicts =
            detector.analyze_on(&view("gptbot", Some("t13d_NOVEL"), None, None), today());
        assert!(!verdicts.is_empty());
        let bruised = detector.reputation("gptbot").expect("a tracked class");
        assert!(bruised < 1.0, "a critical verdict must move the score");

        // Twenty-nine days later, every bucket holding that verdict has
        // rolled out of the window.
        let later = today() + chrono::Duration::days(WINDOW_DAYS as i64 + 1);
        detector.analyze_on(&view("gptbot", Some("t13d_USUAL"), None, None), later);
        assert_eq!(
            detector.reputation("gptbot"),
            Some(1.0),
            "a class that stopped misbehaving must recover without a sweep"
        );
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
    fn the_tracked_class_count_is_capped() {
        let detector = AnomalyDetector::new(settings());
        for index in 0..(MAX_TRACKED_CLASSES + 20) {
            let class = format!("class-{index}");
            detector.analyze_on(&view(&class, Some("t13d"), None, None), today());
        }
        assert_eq!(
            detector.classes.lock().len(),
            MAX_TRACKED_CLASSES,
            "a caller passing arbitrary class strings must not grow the window without bound"
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
        });
        assert_eq!(clamped.min_observations, 1);
        assert!(clamped.outlier_frequency > 0.0);
        assert_eq!(clamped.rate_spike_multiplier, 1.0);
        assert_eq!(clamped.rate_spike_min_mean, 0.0);
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
    #[tokio::test]
    async fn an_installed_detector_is_reachable_through_the_plugin_registry() {
        let detector = Arc::new(AnomalyDetector::new(settings()));
        for _ in 0..60 {
            detector.analyze_on(
                &view("registry-probe", Some("t13d_USUAL"), None, None),
                today(),
            );
        }
        install(Some(detector));

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
        install(None);
        let mut saw_after_removal = false;
        for hook in sbproxy_plugin::anomaly_hooks().iter() {
            saw_after_removal |= !hook.analyze(&probe).await.is_empty();
        }
        assert!(
            !saw_after_removal,
            "a disabled detector must produce nothing, not a stale one"
        );
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
