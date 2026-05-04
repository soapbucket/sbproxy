//! Host filtering for hostname validation (HashSet-based, bloom filter upgrade later).

use std::collections::HashSet;

/// Simple host filter backed by a HashSet.
/// Can be upgraded to a probabilistic bloom filter for large host lists.
pub struct HostFilter {
    hosts: HashSet<String>,
}

impl HostFilter {
    /// Create a new host filter from an iterator of hostnames.
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            hosts: hosts.into_iter().collect(),
        }
    }

    /// Check if a hostname is present in the filter.
    pub fn contains(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }

    /// Return the number of hostnames in the filter.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Return true if the filter contains no hostnames.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_known_host() {
        let filter = HostFilter::new(vec!["example.com".to_string(), "test.org".to_string()]);
        assert!(filter.contains("example.com"));
        assert!(filter.contains("test.org"));
    }

    #[test]
    fn test_does_not_contain_unknown_host() {
        let filter = HostFilter::new(vec!["example.com".to_string()]);
        assert!(!filter.contains("unknown.com"));
    }

    #[test]
    fn test_empty_filter() {
        let filter = HostFilter::new(Vec::<String>::new());
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
        assert!(!filter.contains("anything"));
    }

    #[test]
    fn test_len() {
        let filter = HostFilter::new(vec![
            "a.com".to_string(),
            "b.com".to_string(),
            "c.com".to_string(),
        ]);
        assert_eq!(filter.len(), 3);
        assert!(!filter.is_empty());
    }
}
