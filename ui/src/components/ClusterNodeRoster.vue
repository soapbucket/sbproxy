<script setup lang="ts">
import { computed } from "vue";
import type { ClusterNode } from "../api";
import {
  clusterNodeAnchorId,
  formatAgeMs,
  formatReasonCode,
  sortClusterNodes,
} from "../lib/cluster-health";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{ nodes: readonly ClusterNode[] }>();
const orderedNodes = computed(() => sortClusterNodes(props.nodes));

function healthTone(health: ClusterNode["health"]): "ok" | "warn" | "err" {
  if (health === "healthy") return "ok";
  if (health === "degraded") return "warn";
  return "err";
}

function membershipTone(
  membership: ClusterNode["membership_state"],
): "ok" | "warn" | "err" {
  if (membership === "alive") return "ok";
  if (membership === "suspect") return "warn";
  return "err";
}

function ageAgo(ageMs: number): string {
  const age = formatAgeMs(ageMs);
  return age === "Just now" ? age : `${age} ago`;
}

function labelEntries(labels: Record<string, string>): [string, string][] {
  return Object.entries(labels).sort(([left], [right]) =>
    left.localeCompare(right),
  );
}
</script>

<template>
  <section id="node-roster" class="data-section" aria-labelledby="node-roster-heading">
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Complete membership</p>
        <h2 id="node-roster-heading">Node roster</h2>
      </div>
      <p class="section-context">Healthy, degraded, excluded, and unhealthy nodes</p>
    </div>

    <div class="sb-card table-shell">
      <div class="table-wrap" role="region" aria-label="Complete cluster node roster" tabindex="0">
        <table class="sb-table roster-table">
          <thead>
            <tr>
              <th>Node</th>
              <th>Roles and labels</th>
              <th>Health</th>
              <th>Membership</th>
              <th>Freshness</th>
              <th>Serving inventory</th>
              <th>Placement</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="node in orderedNodes"
              :id="clusterNodeAnchorId(node.node_id)"
              :key="node.node_id"
              :class="{ 'roster-row--unhealthy': node.health === 'unhealthy' }"
            >
              <td>
                <div class="node-identity">
                  <span v-if="node.local" class="local-marker">Local</span>
                  <strong class="sb-mono">{{ node.node_id }}</strong>
                </div>
                <span class="table-detail sb-mono">{{ node.model_endpoint ?? "No model endpoint" }}</span>
                <span class="table-detail sb-mono">{{ node.address ?? "No membership address" }}</span>
              </td>
              <td>
                <div class="tag-list">
                  <span v-for="role in node.roles" :key="role" class="data-tag">{{ role }}</span>
                  <span v-if="!node.roles.length" class="table-detail">No roles reported</span>
                </div>
                <div class="label-list">
                  <code v-for="([key, value]) in labelEntries(node.labels)" :key="key">
                    {{ key }}={{ value }}
                  </code>
                  <span v-if="!labelEntries(node.labels).length" class="table-detail">No labels</span>
                </div>
              </td>
              <td>
                <StatusBadge :label="node.health" :tone="healthTone(node.health)" />
                <span v-if="node.reported_health" class="table-detail">
                  Reported {{ node.reported_health.state }}
                </span>
                <span
                  v-for="reason in node.unhealthy_reasons"
                  :key="reason"
                  class="table-detail table-detail--reason"
                >
                  {{ formatReasonCode(reason) }}
                </span>
              </td>
              <td>
                <StatusBadge
                  :label="node.membership_state"
                  :tone="membershipTone(node.membership_state)"
                />
                <span class="table-detail">Ack {{ ageAgo(node.last_ack_age_ms) }}</span>
                <span class="table-detail">Incarnation {{ node.incarnation }}</span>
              </td>
              <td>
                <strong>
                  {{ node.snapshot_age_ms === null ? "No snapshot" : ageAgo(node.snapshot_age_ms) }}
                </strong>
                <span class="table-detail">Generation {{ node.snapshot_generation ?? "Unknown" }}</span>
                <span class="table-detail">
                  Schema {{ node.normalized_schema_version ?? node.observed_schema_version ?? "Unknown" }}
                </span>
              </td>
              <td>
                <div class="inventory-grid">
                  <span><strong>{{ node.engine_count }}</strong> engines</span>
                  <span><strong>{{ node.device_count }}</strong> devices</span>
                  <span><strong>{{ node.ready_artifact_count }}</strong> artifacts</span>
                  <span><strong>{{ node.replicas.length }}</strong> replicas</span>
                </div>
              </td>
              <td>
                <StatusBadge
                  :label="node.model_eligible ? 'Eligible' : 'Excluded'"
                  :tone="node.model_eligible ? 'ok' : 'warn'"
                />
                <span v-if="node.exclusion_reason" class="table-detail table-detail--reason">
                  {{ formatReasonCode(node.exclusion_reason) }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
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

.roster-table {
  min-width: 1160px;
}

.sb-table tbody tr {
  scroll-margin-top: var(--sb-space-4);
}

.sb-table tbody tr:target {
  background: var(--sb-accent-tint);
  box-shadow: inset 4px 0 0 var(--sb-accent);
}

.roster-row--unhealthy {
  background: var(--sb-err-bg);
}

.node-identity {
  display: flex;
  align-items: center;
  gap: var(--sb-space-2);
  margin-bottom: var(--sb-space-1);
}

.local-marker,
.data-tag {
  display: inline-flex;
  padding: 1px 6px;
  border-radius: var(--sb-radius-pill);
  font-size: 0.65rem;
  font-weight: 700;
  line-height: 1.5;
  text-transform: uppercase;
}

.local-marker {
  color: var(--sb-on-navy);
  background: var(--sb-navy);
}

.data-tag {
  color: var(--sb-text-muted);
  background: var(--sb-surface-2);
  border: 1px solid var(--sb-border);
}

.tag-list,
.label-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-1);
}

.label-list {
  margin-top: var(--sb-space-2);
}

.label-list code {
  padding: 1px 5px;
  color: var(--sb-text-muted);
  background: var(--sb-bg-sunken);
  border-radius: var(--sb-radius-sm);
  font-size: 0.68rem;
}

.table-detail {
  display: block;
  margin-top: var(--sb-space-1);
  color: var(--sb-text-faint);
  font-size: 0.72rem;
  overflow-wrap: anywhere;
}

.table-detail--reason {
  max-width: 26ch;
  color: var(--sb-text-muted);
}

.inventory-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(76px, 1fr));
  gap: var(--sb-space-2);
  color: var(--sb-text-muted);
  font-size: 0.72rem;
}

.inventory-grid strong {
  color: var(--sb-text);
  font-family: var(--sb-font-mono);
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
