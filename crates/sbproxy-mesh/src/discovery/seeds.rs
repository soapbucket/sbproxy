//! Static seed peer discovery.

use super::Discovery;

/// Discovery backend that returns a pre-configured list of seed addresses.
pub struct SeedDiscovery {
    seeds: Vec<String>,
}

impl SeedDiscovery {
    /// Create a new seed-based discovery with the given addresses.
    pub fn new(seeds: Vec<String>) -> Self {
        Self { seeds }
    }
}

impl Discovery for SeedDiscovery {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.seeds.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Discovery;

    #[test]
    fn returns_configured_seeds() {
        let seeds = vec!["10.0.0.1:7946".to_string(), "10.0.0.2:7946".to_string()];
        let discovery = SeedDiscovery::new(seeds.clone());
        let result = discovery.discover().expect("discover");
        assert_eq!(result, seeds);
    }

    #[test]
    fn empty_seeds_returns_empty() {
        let discovery = SeedDiscovery::new(vec![]);
        let result = discovery.discover().expect("discover");
        assert!(result.is_empty());
    }

    #[test]
    fn single_seed() {
        let discovery = SeedDiscovery::new(vec!["192.168.1.1:7946".to_string()]);
        let result = discovery.discover().expect("discover");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "192.168.1.1:7946");
    }
}
