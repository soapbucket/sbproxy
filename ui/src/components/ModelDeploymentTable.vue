<script setup lang="ts">
import type { DeploymentRuntimeState } from "../api";
import { formatReasonCode } from "../lib/cluster-health";
import { formatBytes } from "../lib/format";
import {
  deploymentRemovalGuard,
  type ModelDeploymentRow,
} from "../lib/model-management";
import EmptyState from "./EmptyState.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  rows: readonly ModelDeploymentRow[];
  canMutate: boolean;
  persistentReadOnlyReason?: string | null;
  lifecycleBusy?: string;
  mutationBusy?: boolean;
  throughputByModel?: Readonly<Record<string, number>>;
}>();

defineEmits<{
  (event: "edit", row: ModelDeploymentRow): void;
  (event: "remove", row: ModelDeploymentRow): void;
  (event: "load", deploymentId: string): void;
  (event: "stop", deploymentId: string): void;
  (event: "reset", deploymentId: string): void;
}>();

function stateTone(
  state: DeploymentRuntimeState | null,
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (state === "ready") return "ok";
  if (state === "failed") return "err";
  if (state === "preparing" || state === "draining") return "warn";
  if (state === "assigned" || state === "cached") return "info";
  return "neutral";
}

function lifecycleIsBusy(action: string, deploymentId: string): boolean {
  return props.lifecycleBusy === `${action}:${deploymentId}`;
}

function loadDisabled(row: ModelDeploymentRow): boolean {
  const state = row.runtime?.state ?? null;
  return (
    Boolean(props.lifecycleBusy) ||
    state === "ready" ||
    state === "preparing" ||
    state === "draining"
  );
}

function stopDisabled(row: ModelDeploymentRow): boolean {
  const state = row.runtime?.state ?? null;
  return (
    Boolean(props.lifecycleBusy) ||
    state === null ||
    state === "stopped" ||
    state === "draining"
  );
}

function resetDisabled(row: ModelDeploymentRow): boolean {
  return Boolean(props.lifecycleBusy) || row.runtime?.state !== "failed";
}

function removeReason(row: ModelDeploymentRow): string | null {
  const runtimeReason = deploymentRemovalGuard(row.runtime?.state ?? null).reason;
  if (runtimeReason) return runtimeReason;
  if (!props.canMutate) {
    return props.persistentReadOnlyReason ?? "Persistent desired state is read-only.";
  }
  return null;
}

function labels(row: ModelDeploymentRow): string {
  const entries = Object.entries(row.desired?.required_labels ?? {});
  return entries.length
    ? entries.map(([key, value]) => `${key}=${value}`).join(", ")
    : "Any eligible worker";
}
</script>

<template>
  <div v-if="rows.length" class="sb-card table-shell">
    <div class="table-wrap" role="region" aria-label="Model deployments" tabindex="0">
      <table class="sb-table deployment-table">
        <thead>
          <tr>
            <th>Deployment</th>
            <th>Desired configuration</th>
            <th>Runtime residency</th>
            <th>Placement and policy</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.deploymentId">
            <td>
              <strong class="sb-mono deployment-id">{{ row.deploymentId }}</strong>
              <span v-if="row.desired" class="table-detail">Configured desired state</span>
              <span v-else class="table-detail table-detail--warn">Runtime status only</span>
            </td>
            <td>
              <template v-if="row.desired">
                <strong class="sb-mono">{{ row.desired.model }}</strong>
                <span class="table-detail">
                  {{ row.desired.variant ? `Variant ${row.desired.variant}` : "Automatic variant" }}
                </span>
                <span class="table-detail">
                  {{ row.desired.replicas }} {{ row.desired.replicas === 1 ? "replica" : "replicas" }}
                  · {{ row.desired.heterogeneous_variants ? "heterogeneous allowed" : "homogeneous" }}
                </span>
              </template>
              <span v-else class="table-detail">Management metadata is unavailable for this deployment.</span>
            </td>
            <td>
              <template v-if="row.runtime">
                <StatusBadge
                  :label="formatReasonCode(row.runtime.state)"
                  :tone="stateTone(row.runtime.state)"
                />
                <span class="table-detail">Generation {{ row.runtime.generation }}</span>
                <span class="table-detail">
                  {{ row.runtime.active_requests }} active · {{ row.runtime.queued_requests }} queued
                </span>
                <span v-if="row.runtime.engine" class="table-detail">
                  {{ formatReasonCode(row.runtime.engine) }}
                  <template v-if="row.runtime.selected_devices.length">
                    · device {{ row.runtime.selected_devices.join(", ") }}
                  </template>
                </span>
                <span v-if="row.runtime.memory" class="table-detail">
                  {{ formatBytes(row.runtime.memory.total_bytes) }} reserved
                </span>
                <span
                  v-if="row.desired && throughputByModel?.[row.desired.model] !== undefined"
                  class="table-detail"
                >
                  {{ throughputByModel[row.desired.model].toFixed(1) }} tok/s average
                </span>
                <span v-if="row.runtime.last_error" class="runtime-error">
                  {{ row.runtime.last_error }}
                </span>
              </template>
              <template v-else>
                <StatusBadge label="Not observed" tone="neutral" />
                <span class="table-detail">No local runtime status is currently reported.</span>
              </template>
            </td>
            <td>
              <template v-if="row.desired">
                <span class="policy-line">
                  <strong>{{ formatReasonCode(row.desired.pull) }}</strong>
                  · {{ row.desired.warm ? "warm" : "cold start allowed" }}
                </span>
                <span class="table-detail">
                  Engine {{ formatReasonCode(row.desired.engine) }} · {{ formatReasonCode(row.desired.rollout) }} rollout
                </span>
                <span class="table-detail">
                  {{ row.desired.max_concurrency ?? "Default" }} max concurrency ·
                  {{ row.desired.max_queue_depth }} queued
                </span>
                <span class="table-detail placement-labels">{{ labels(row) }}</span>
                <span v-if="row.desired.spread_by.length" class="table-detail">
                  Spread by {{ row.desired.spread_by.join(", ") }}
                </span>
              </template>
              <span v-else class="table-detail">Desired policy could not be loaded.</span>
            </td>
            <td class="actions-cell">
              <div class="action-group" aria-label="Lifecycle actions">
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="loadDisabled(row)"
                  :title="row.runtime?.state === 'ready' ? 'Deployment is already ready.' : undefined"
                  @click="$emit('load', row.deploymentId)"
                >
                  {{ lifecycleIsBusy("load", row.deploymentId) ? "Loading..." : "Load" }}
                </button>
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="stopDisabled(row)"
                  :title="row.runtime?.state === 'draining' ? 'Deployment is already draining.' : undefined"
                  @click="$emit('stop', row.deploymentId)"
                >
                  {{ lifecycleIsBusy("stop", row.deploymentId) ? "Stopping..." : "Stop" }}
                </button>
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="resetDisabled(row)"
                  title="Reset is available after a retained runtime failure."
                  @click="$emit('reset', row.deploymentId)"
                >
                  {{ lifecycleIsBusy("reset", row.deploymentId) ? "Resetting..." : "Reset" }}
                </button>
              </div>
              <div v-if="row.desired" class="action-group action-group--persistent" aria-label="Desired state actions">
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="!canMutate || mutationBusy"
                  :title="!canMutate ? persistentReadOnlyReason ?? undefined : undefined"
                  @click="$emit('edit', row)"
                >
                  Edit
                </button>
                <button
                  class="sb-btn sb-btn--sm sb-btn--danger"
                  :disabled="Boolean(removeReason(row)) || mutationBusy"
                  :title="removeReason(row) ?? undefined"
                  @click="$emit('remove', row)"
                >
                  Remove
                </button>
              </div>
              <span v-if="row.desired && removeReason(row)" class="action-reason">
                {{ removeReason(row) }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
  <EmptyState v-else message="No desired or runtime deployments are available." />
</template>

<style scoped>
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
  min-width: 1120px;
}

.deployment-table th:nth-child(1) {
  width: 15%;
}

.deployment-table th:nth-child(2) {
  width: 22%;
}

.deployment-table th:nth-child(3) {
  width: 20%;
}

.deployment-table th:nth-child(4) {
  width: 22%;
}

.deployment-id,
.placement-labels {
  overflow-wrap: anywhere;
}

.table-detail,
.policy-line,
.runtime-error,
.action-reason {
  display: block;
  margin-top: var(--sb-space-1);
  font-size: 0.72rem;
}

.table-detail {
  color: var(--sb-text-faint);
}

.table-detail--warn {
  color: var(--sb-warn-fg);
}

.policy-line {
  color: var(--sb-text-muted);
}

.runtime-error {
  max-width: 34ch;
  color: var(--sb-err);
  overflow-wrap: anywhere;
}

.actions-cell {
  min-width: 225px;
}

.action-group {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-1);
}

.action-group--persistent {
  padding-top: var(--sb-space-2);
  margin-top: var(--sb-space-2);
  border-top: 1px solid var(--sb-border);
}

.action-reason {
  max-width: 28ch;
  color: var(--sb-text-faint);
}

@media (max-width: 760px) {
  .deployment-table {
    min-width: 980px;
  }
}
</style>
