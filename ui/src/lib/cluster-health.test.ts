import { describe, expect, it } from "vitest";

import type {
  ClusterMetrics,
  ClusterNode,
  ClusterNodeAlert,
  PlacementAssignment,
} from "../api";
import {
  clusterMetricsSummary,
  clusterNodeAnchorId,
  formatAgeMs,
  formatReasonCode,
  placementAssignmentKey,
  sortClusterNodes,
  sortNodeAlerts,
} from "./cluster-health";

function clusterNode(
  node_id: string,
  local: boolean,
  health: ClusterNode["health"] = "healthy",
): ClusterNode {
  return {
    node_id,
    local,
    membership_state: "alive",
    address: null,
    last_ack_age_ms: 0,
    incarnation: 1,
    health,
    unhealthy: health === "unhealthy",
    unhealthy_reasons: [],
    roles: ["worker"],
    labels: {},
    model_endpoint: null,
    model_eligible: true,
    exclusion_reason: null,
    snapshot_age_ms: null,
    snapshot_generation: null,
    observed_schema_version: null,
    normalized_schema_version: null,
    reported_health: null,
    engine_count: 0,
    device_count: 0,
    ready_artifact_count: 0,
    replicas: [],
  };
}

function nodeAlert(
  node_id: string,
  health: ClusterNodeAlert["health"],
): ClusterNodeAlert {
  return {
    node_id,
    health,
    reasons: [],
    membership_state: "alive",
    last_ack_age_ms: 0,
    snapshot_age_ms: null,
    model_endpoint: null,
  };
}

function placementAssignment(
  artifact_digest: string,
  device_index: number,
): PlacementAssignment {
  return {
    node_id: "worker-a",
    model_endpoint: "https://worker-a.internal:9443",
    variant_id: "q4",
    artifact_digest,
    engine: "llama_cpp",
    accelerator: "cuda",
    device_index,
    required_memory_bytes: 8_000,
    available_memory_bytes: 16_000,
    artifact_cached: true,
    failure_domains: { zone: "a" },
  };
}

describe("cluster health presentation", () => {
  it("keeps a node anchor stable when roster order and membership change", () => {
    const target = clusterNode("worker/a", false);
    const anchorFor = (nodes: ClusterNode[]) =>
      new Map(
        sortClusterNodes(nodes).map((node) => [
          node.node_id,
          clusterNodeAnchorId(node.node_id),
        ]),
      ).get(target.node_id);

    const original = [clusterNode("worker-z", false), target];
    const reordered = [target, clusterNode("worker-z", false)];
    const added = [...original, clusterNode("worker-a", false)];
    const removed = [target];
    const localChanged = [{ ...target, local: true }, clusterNode("worker-z", false)];

    expect(anchorFor(reordered)).toBe(anchorFor(original));
    expect(anchorFor(added)).toBe(anchorFor(original));
    expect(anchorFor(removed)).toBe(anchorFor(original));
    expect(anchorFor(localChanged)).toBe(anchorFor(original));
  });

  it("encodes valid special node IDs into bounded distinct safe anchors", () => {
    const nodeIds = [
      "worker.a",
      "worker-a",
      "worker_a",
      "WORKER-A",
      "worker-A",
      "a",
      "A",
      "x".repeat(128),
    ];
    const anchors = nodeIds.map(clusterNodeAnchorId);

    expect(new Set(anchors).size).toBe(nodeIds.length);
    for (const anchor of anchors) {
      expect(anchor).toMatch(/^cluster-node-[a-z0-9_-]+$/);
      expect(anchor.length).toBeLessThanOrEqual(64);
    }
  });

  it("distinguishes initial metric loading from retained-data refresh", () => {
    const retained: ClusterMetrics = {
      nodes: 2,
      metrics: { sbproxy_requests_total: 12 },
    };

    expect(
      clusterMetricsSummary({
        metrics: null,
        loading: true,
        notEnabled: false,
        error: false,
      }),
    ).toBe("Loading fleet metrics");
    expect(
      clusterMetricsSummary({
        metrics: retained,
        loading: true,
        notEnabled: false,
        error: false,
      }),
    ).toBe("Refreshing fleet metrics");
  });

  it("prioritizes metric error and disabled summaries over loading copy", () => {
    const retained: ClusterMetrics = { nodes: 2, metrics: {} };

    expect(
      clusterMetricsSummary({
        metrics: retained,
        loading: true,
        notEnabled: true,
        error: true,
      }),
    ).toBe("Fleet metrics unavailable");
    expect(
      clusterMetricsSummary({
        metrics: retained,
        loading: true,
        notEnabled: true,
        error: false,
      }),
    ).toBe("Fleet metrics not enabled");
  });

  it("keys deployment assignments by stable identity instead of position", () => {
    const first = placementAssignment("a".repeat(64), 0);
    const second = placementAssignment("b".repeat(64), 1);
    const original = [first, second].map(placementAssignmentKey);
    const reordered = [second, first].map(placementAssignmentKey);

    expect(new Set(original).size).toBe(2);
    expect(reordered).toEqual([original[1], original[0]]);
  });

  it("orders the local node first and then orders every other node by ID", () => {
    const original = [
      clusterNode("worker-z", false),
      clusterNode("worker-b", false),
      clusterNode("worker-local", true),
      clusterNode("worker-a", false),
    ];

    expect(sortClusterNodes(original).map((node) => node.node_id)).toEqual([
      "worker-local",
      "worker-a",
      "worker-b",
      "worker-z",
    ]);
    expect(original.map((node) => node.node_id)).toEqual([
      "worker-z",
      "worker-b",
      "worker-local",
      "worker-a",
    ]);
  });

  it("orders unhealthy alerts before degraded and healthy alerts deterministically", () => {
    const alerts = [
      nodeAlert("healthy-a", "healthy"),
      nodeAlert("unhealthy-z", "unhealthy"),
      nodeAlert("degraded-a", "degraded"),
      nodeAlert("unhealthy-a", "unhealthy"),
    ];

    expect(sortNodeAlerts(alerts).map((alert) => alert.node_id)).toEqual([
      "unhealthy-a",
      "unhealthy-z",
      "degraded-a",
      "healthy-a",
    ]);
  });

  it("formats nullable millisecond ages into compact operator-readable text", () => {
    expect(formatAgeMs(null)).toBe("Unknown");
    expect(formatAgeMs(999)).toBe("Just now");
    expect(formatAgeMs(1_000)).toBe("1s");
    expect(formatAgeMs(61_000)).toBe("1m 1s");
    expect(formatAgeMs(3_661_000)).toBe("1h 1m");
    expect(formatAgeMs(90_000_000)).toBe("1d 1h");
  });

  it("renders known reason codes as plain language with a safe fallback", () => {
    expect(formatReasonCode("membership_unreachable")).toBe(
      "Membership is unreachable",
    );
    expect(formatReasonCode("directory_not_collected")).toBe(
      "Model directory has not been collected",
    );
    expect(formatReasonCode("engine_unavailable")).toBe("Engine unavailable");
    expect(formatReasonCode("")).toBe("Unknown reason");
  });
});
