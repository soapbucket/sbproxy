//! Track metadata for resolved secrets.
//!
//! Metadata is useful for auditing (first/last resolved timestamps, resolution
//! counts) and for surfacing secret usage in the admin API.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata associated with a single resolved secret.
#[derive(Debug, Clone)]
pub struct SecretMeta {
    /// Logical name of the secret.
    pub name: String,
    /// ISO 8601 timestamp when the secret was first successfully resolved.
    pub first_resolved: String,
    /// ISO 8601 timestamp of the most recent successful resolution.
    pub last_resolved: String,
    /// Total number of times the secret has been resolved.
    pub resolve_count: u64,
    /// Source that provided the secret value (e.g. `"hashicorp"`, `"aws"`,
    /// `"env"`, `"file"`, `"local"`).
    pub source: String,
}

/// Thread-safe tracker for secret resolution metadata.
pub struct SecretMetadataTracker {
    entries: Mutex<HashMap<String, SecretMeta>>,
}

impl SecretMetadataTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record a successful resolution of `name` from the given `source`.
    ///
    /// - On first call for a name: sets `first_resolved` and `last_resolved`.
    /// - On subsequent calls: updates `last_resolved` and increments `resolve_count`.
    pub fn record_resolve(&self, name: &str, source: &str) {
        let now = iso8601_now();
        let mut map = self.entries.lock().unwrap();
        if let Some(entry) = map.get_mut(name) {
            entry.last_resolved = now;
            entry.resolve_count += 1;
            entry.source = source.to_string();
        } else {
            map.insert(
                name.to_string(),
                SecretMeta {
                    name: name.to_string(),
                    first_resolved: now.clone(),
                    last_resolved: now,
                    resolve_count: 1,
                    source: source.to_string(),
                },
            );
        }
    }

    /// Return the metadata for `name`, or `None` if it has never been resolved.
    pub fn get(&self, name: &str) -> Option<SecretMeta> {
        self.entries.lock().unwrap().get(name).cloned()
    }

    /// Return all tracked secrets as a list.
    pub fn list(&self) -> Vec<SecretMeta> {
        self.entries.lock().unwrap().values().cloned().collect()
    }
}

impl Default for SecretMetadataTracker {
    fn default() -> Self {
        Self::new()
    }
}

// --- helpers ---

fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal ISO 8601 representation: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;
    // Gregorian calendar approximation (good until ~2100).
    let (year, doy) = days_to_year_doy(days);
    let (month, day) = doy_to_month_day(year, doy);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn days_to_year_doy(days: u64) -> (u64, u64) {
    let mut remaining = days;
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining < days_in_year {
            return (year, remaining);
        }
        remaining -= days_in_year;
        year += 1;
    }
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn doy_to_month_day(year: u64, doy: u64) -> (u64, u64) {
    let months = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut remaining = doy;
    for (i, &days) in months.iter().enumerate() {
        if remaining < days {
            return (i as u64 + 1, remaining + 1);
        }
        remaining -= days;
    }
    (12, 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_get() {
        let tracker = SecretMetadataTracker::new();
        tracker.record_resolve("my_secret", "local");
        let meta = tracker.get("my_secret").unwrap();
        assert_eq!(meta.name, "my_secret");
        assert_eq!(meta.source, "local");
        assert_eq!(meta.resolve_count, 1);
        assert!(!meta.first_resolved.is_empty());
        assert!(!meta.last_resolved.is_empty());
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let tracker = SecretMetadataTracker::new();
        assert!(tracker.get("does_not_exist").is_none());
    }

    #[test]
    fn resolve_count_increments_on_repeated_calls() {
        let tracker = SecretMetadataTracker::new();
        tracker.record_resolve("counter_secret", "env");
        tracker.record_resolve("counter_secret", "env");
        tracker.record_resolve("counter_secret", "env");
        let meta = tracker.get("counter_secret").unwrap();
        assert_eq!(meta.resolve_count, 3);
    }

    #[test]
    fn first_resolved_does_not_change_on_subsequent_calls() {
        let tracker = SecretMetadataTracker::new();
        tracker.record_resolve("stable_secret", "hashicorp");
        let first = tracker.get("stable_secret").unwrap().first_resolved.clone();
        // Record again.
        tracker.record_resolve("stable_secret", "hashicorp");
        let again = tracker.get("stable_secret").unwrap().first_resolved;
        assert_eq!(first, again);
    }

    #[test]
    fn list_returns_all_entries() {
        let tracker = SecretMetadataTracker::new();
        tracker.record_resolve("secret_a", "aws");
        tracker.record_resolve("secret_b", "local");
        tracker.record_resolve("secret_c", "env");
        let mut list = tracker.list();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "secret_a");
        assert_eq!(list[1].name, "secret_b");
        assert_eq!(list[2].name, "secret_c");
    }

    #[test]
    fn list_empty_initially() {
        let tracker = SecretMetadataTracker::new();
        assert!(tracker.list().is_empty());
    }

    #[test]
    fn source_updated_on_subsequent_resolve() {
        let tracker = SecretMetadataTracker::new();
        tracker.record_resolve("migrated", "local");
        tracker.record_resolve("migrated", "hashicorp");
        let meta = tracker.get("migrated").unwrap();
        assert_eq!(meta.source, "hashicorp");
    }

    #[test]
    fn iso8601_now_format() {
        let ts = iso8601_now();
        // Minimal sanity: YYYY-MM-DDTHH:MM:SSZ is 20 chars.
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
