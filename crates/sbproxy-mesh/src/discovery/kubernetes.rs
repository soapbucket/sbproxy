//! Kubernetes API-based peer discovery.
//! Queries K8s API for pods matching a label selector.

use super::Discovery;

/// Discovers mesh peers by querying the Kubernetes API for matching pods.
pub struct KubernetesDiscovery {
    pub namespace: String,
    pub label_selector: String,
    pub port: u16,
    /// Kubernetes API base URL. Defaults to `<https://kubernetes.default.svc>`.
    pub api_url: String,
    /// Bearer token for K8s API authentication (usually mounted in-pod).
    pub token: Option<String>,
}

impl KubernetesDiscovery {
    /// Create a new KubernetesDiscovery with default K8s API URL.
    pub fn new(namespace: &str, label_selector: &str, port: u16) -> Self {
        Self {
            namespace: namespace.to_string(),
            label_selector: label_selector.to_string(),
            port,
            api_url: "https://kubernetes.default.svc".to_string(),
            token: None,
        }
    }

    /// Build the K8s API URL for listing pods in the configured namespace.
    pub fn pods_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/pods?labelSelector={}",
            self.api_url, self.namespace, self.label_selector
        )
    }
}

impl Discovery for KubernetesDiscovery {
    /// Discover peers via the K8s API.
    ///
    /// In production this would call the K8s API, parse pod IPs, and return
    /// `ip:port` addresses. Returns empty when no K8s API is reachable.
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        // Production implementation would:
        // 1. Read token from /var/run/secrets/kubernetes.io/serviceaccount/token
        // 2. GET self.pods_url() with Authorization: Bearer <token>
        // 3. Parse PodList JSON and extract pod IPs from status.podIP
        // 4. Return format!("{}:{}", ip, self.port) for each ready pod
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_default_api_url() {
        let kd = KubernetesDiscovery::new("default", "app=sbproxy", 7946);
        assert_eq!(kd.api_url, "https://kubernetes.default.svc");
        assert_eq!(kd.namespace, "default");
        assert_eq!(kd.label_selector, "app=sbproxy");
        assert_eq!(kd.port, 7946);
        assert!(kd.token.is_none());
    }

    #[test]
    fn pods_url_format_default_api() {
        let kd = KubernetesDiscovery::new("production", "app=mesh,tier=proxy", 8946);
        let url = kd.pods_url();
        assert_eq!(
            url,
            "https://kubernetes.default.svc/api/v1/namespaces/production/pods?labelSelector=app=mesh,tier=proxy"
        );
    }

    #[test]
    fn pods_url_format_custom_api() {
        let mut kd = KubernetesDiscovery::new("staging", "app=proxy", 7946);
        kd.api_url = "https://my-k8s-api:6443".to_string();
        let url = kd.pods_url();
        assert_eq!(
            url,
            "https://my-k8s-api:6443/api/v1/namespaces/staging/pods?labelSelector=app=proxy"
        );
    }

    #[test]
    fn discover_returns_empty_without_k8s() {
        let kd = KubernetesDiscovery::new("default", "app=sbproxy", 7946);
        let peers = kd.discover().expect("discover should not error");
        assert!(peers.is_empty(), "expected no peers without a real K8s API");
    }

    #[test]
    fn token_can_be_set() {
        let mut kd = KubernetesDiscovery::new("default", "app=sbproxy", 7946);
        kd.token = Some("eyJhbGci...".to_string());
        assert!(kd.token.is_some());
    }

    #[test]
    fn discover_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KubernetesDiscovery>();
    }
}
