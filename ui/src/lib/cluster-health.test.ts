import { describe, expect, it } from "vitest";

import type { ClusterNode, ClusterNodeAlert } from "../api";
import {
  formatAgeMs,
  formatReasonCode,
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

describe("cluster health presentation", () => {
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
