import type { ClusterNode, ClusterNodeAlert } from "../api";

function compareText(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

export function sortClusterNodes(nodes: readonly ClusterNode[]): ClusterNode[] {
  return [...nodes].sort((left, right) => {
    if (left.local !== right.local) return left.local ? -1 : 1;
    return compareText(left.node_id, right.node_id);
  });
}

const HEALTH_ORDER: Record<ClusterNodeAlert["health"], number> = {
  unhealthy: 0,
  degraded: 1,
  healthy: 2,
};

export function sortNodeAlerts(
  alerts: readonly ClusterNodeAlert[],
): ClusterNodeAlert[] {
  return [...alerts].sort((left, right) => {
    const healthOrder = HEALTH_ORDER[left.health] - HEALTH_ORDER[right.health];
    return healthOrder || compareText(left.node_id, right.node_id);
  });
}

export function formatAgeMs(ageMs: number | null): string {
  if (ageMs === null || !Number.isFinite(ageMs) || ageMs < 0) return "Unknown";

  const totalSeconds = Math.floor(ageMs / 1_000);
  if (totalSeconds === 0) return "Just now";

  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  if (minutes > 0) {
    return seconds > 0 ? `${minutes}m ${seconds}s` : `${minutes}m`;
  }
  return `${seconds}s`;
}

const REASON_LABELS: Readonly<Record<string, string>> = {
  membership_suspect: "Membership is suspect",
  membership_dead: "Membership reports this node as dead",
  membership_unreachable: "Membership is unreachable",
  directory_not_collected: "Model directory has not been collected",
  directory_stale: "Model directory data is stale",
};

export function formatReasonCode(reason: string): string {
  const normalized = reason.trim();
  if (!normalized) return "Unknown reason";
  const known = REASON_LABELS[normalized];
  if (known) return known;
  const words = normalized.replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
