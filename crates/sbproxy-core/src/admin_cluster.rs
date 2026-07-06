// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Fleet-metrics admin endpoint (WOR-1721): `GET /admin/cluster/metrics`.
//!
//! Reports the mesh-aggregated fleet totals for a curated set of
//! `sbproxy_*` metrics, plus the node count, from a single node. Backed
//! by the process-global aggregator in [`crate::cluster_metrics`], which
//! is populated only when the mesh key tier is on; without it this
//! returns a 404 so an operator knows fleet metrics are not enabled (the
//! external-Prometheus path is the default and is unaffected).

/// Dispatch a `/admin/cluster/metrics` request. Returns `None` for other
/// paths so the caller falls through to the next admin route.
pub fn dispatch(method: &str, path: &str) -> Option<(u16, &'static str, String)> {
    if path != "/admin/cluster/metrics" {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") {
        return Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        ));
    }
    match crate::cluster_metrics::fleet_metrics_json() {
        Some(body) => Some((200, "application/json", body)),
        None => Some((
            404,
            "application/json",
            r#"{"error":"cluster metrics not enabled; requires the mesh key tier (use an external Prometheus otherwise)"}"#
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_matching_path_returns_none() {
        assert!(dispatch("GET", "/metrics").is_none());
        assert!(dispatch("GET", "/admin/model-host/status").is_none());
    }

    #[test]
    fn non_get_is_405() {
        let (status, _, _) = dispatch("POST", "/admin/cluster/metrics").expect("matched");
        assert_eq!(status, 405);
    }

    #[test]
    fn get_returns_200_or_404_depending_on_install() {
        // Ours to answer either way; both are valid JSON responses.
        let (status, ct, _) = dispatch("GET", "/admin/cluster/metrics").expect("matched");
        assert!(status == 200 || status == 404, "status {status}");
        assert_eq!(ct, "application/json");
    }
}
