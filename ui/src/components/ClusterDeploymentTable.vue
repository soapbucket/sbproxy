<script setup lang="ts">
import type { ClusterDeploymentRolloutStatus } from "../api";
import { formatReasonCode } from "../lib/cluster-health";
import { formatBytes, formatTime } from "../lib/format";
import EmptyState from "./EmptyState.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  deployments: readonly ClusterDeploymentRolloutStatus[];
  rolloutsInProgress: number;
  unplacedReplicas: number;
}>();

function phaseTone(
  deployment: ClusterDeploymentRolloutStatus,
): "ok" | "warn" | "err" {
  if (deployment.timed_out || deployment.phase === "timed_out") return "err";
  if (deployment.phase === "stable" && deployment.target_ready) return "ok";
  return "warn";
}

function rejectionEntries(
  deployment: ClusterDeploymentRolloutStatus,
): [string, string][] {
  return Object.entries(deployment.rejections)
    .sort(([left], [right]) => left.localeCompare(right))
    .slice(0, 3);
}

function rejectionOverflow(deployment: ClusterDeploymentRolloutStatus): number {
  return Math.max(0, Object.keys(deployment.rejections).length - 3);
}
</script>

<template>
  <section class="data-section" aria-labelledby="deployments-heading">
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Desired versus observed</p>
        <h2 id="deployments-heading">Deployment rollouts</h2>
      </div>
      <p class="section-context">
        {{ rolloutsInProgress }} active rollouts, {{ unplacedReplicas }} unplaced replicas
      </p>
    </div>

    <div v-if="props.deployments.length" class="sb-card table-shell">
      <div class="table-wrap" role="region" aria-label="Cluster deployment rollouts" tabindex="0">
        <table class="sb-table deployment-table">
          <thead>
            <tr>
              <th>Deployment</th>
              <th>Replicas</th>
              <th>Rollout</th>
              <th>Target</th>
              <th>Assignments</th>
              <th>Placement rejections</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="deployment in props.deployments" :key="deployment.deployment_id">
              <td>
                <strong class="sb-mono">{{ deployment.deployment_id }}</strong>
                <span class="table-detail">{{ deployment.model }}</span>
                <span class="table-detail">Generation {{ deployment.generation }}</span>
              </td>
              <td>
                <div class="replica-counts">
                  <span><strong>{{ deployment.desired_replicas }}</strong> desired</span>
                  <span><strong>{{ deployment.placed_replicas }}</strong> placed</span>
                  <span :class="{ 'count-alert': deployment.unplaced_replicas > 0 }">
                    <strong>{{ deployment.unplaced_replicas }}</strong> unplaced
                  </span>
                </div>
              </td>
              <td>
                <StatusBadge
                  :label="formatReasonCode(deployment.phase)"
                  :tone="phaseTone(deployment)"
                />
                <span class="table-detail">
                  {{ deployment.timed_out ? "Timed out" : "Within timeout" }}
                </span>
                <span class="table-detail">
                  Handoff deadline {{ formatTime(deployment.handoff_deadline_unix_ms) }}
                </span>
              </td>
              <td>
                <StatusBadge
                  :label="deployment.target_ready ? 'Ready' : 'Waiting'"
                  :tone="deployment.target_ready ? 'ok' : 'warn'"
                />
                <span class="table-detail">{{ deployment.retained.length }} retained</span>
                <span class="table-detail">{{ deployment.draining.length }} draining</span>
              </td>
              <td>
                <ul v-if="deployment.assignments.length" class="assignment-list">
                  <li
                    v-for="(assignment, index) in deployment.assignments"
                    :key="`${assignment.node_id}:${index}`"
                  >
                    <strong class="sb-mono">{{ assignment.node_id }}</strong>
                    <span>{{ assignment.variant_id }}</span>
                    <span>
                      {{ assignment.engine }} / {{ assignment.accelerator }} device
                      {{ assignment.device_index }}
                    </span>
                    <span>
                      {{ formatBytes(assignment.required_memory_bytes) }} required,
                      {{ formatBytes(assignment.available_memory_bytes) }} available
                    </span>
                    <span>{{ assignment.artifact_cached ? "Artifact cached" : "Artifact not cached" }}</span>
                  </li>
                </ul>
                <span v-else class="table-detail">No target assignments</span>
              </td>
              <td>
                <ul v-if="rejectionEntries(deployment).length" class="rejection-list">
                  <li v-for="([nodeId, reason]) in rejectionEntries(deployment)" :key="nodeId">
                    <span class="sb-mono">{{ nodeId }}</span>
                    <span>{{ formatReasonCode(reason) }}</span>
                  </li>
                </ul>
                <span v-else class="table-detail">No placement rejections</span>
                <span v-if="rejectionOverflow(deployment)" class="table-detail">
                  +{{ rejectionOverflow(deployment) }} more nodes
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <EmptyState v-else message="No cluster deployments are active." />
  </section>
</template>

<style scoped>
.data-section {
  margin-bottom: var(--sb-space-6);
}

.section-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}

.section-heading .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.section-context {
  max-width: 50%;
  margin: 0;
  color: var(--sb-text-faint);
  font-size: 0.78rem;
  text-align: right;
}

.table-shell {
  padding: 0;
  overflow: hidden;
}

.table-wrap {
  overflow-x: auto;
}

.table-wrap:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: -3px;
}

.deployment-table {
  min-width: 1220px;
}

.table-detail {
  display: block;
  margin-top: var(--sb-space-1);
  color: var(--sb-text-faint);
  font-size: 0.72rem;
  overflow-wrap: anywhere;
}

.replica-counts {
  display: grid;
  gap: var(--sb-space-2);
  color: var(--sb-text-muted);
  font-size: 0.72rem;
}

.replica-counts strong {
  color: var(--sb-text);
  font-family: var(--sb-font-mono);
}

.count-alert,
.count-alert strong {
  color: var(--sb-err);
}

.assignment-list,
.rejection-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.assignment-list li,
.rejection-list li {
  padding-bottom: var(--sb-space-2);
  margin-bottom: var(--sb-space-2);
  border-bottom: 1px solid var(--sb-border);
}

.assignment-list li:last-child,
.rejection-list li:last-child {
  padding-bottom: 0;
  margin-bottom: 0;
  border-bottom: 0;
}

.assignment-list span,
.rejection-list span {
  display: block;
  margin-top: 2px;
  color: var(--sb-text-faint);
  font-size: 0.68rem;
}

.rejection-list .sb-mono {
  color: var(--sb-text);
}

@media (max-width: 760px) {
  .section-heading {
    display: block;
  }

  .section-context {
    max-width: none;
    margin-top: var(--sb-space-2);
    text-align: left;
  }
}
</style>
