<script setup lang="ts">
/*
 * Inbound mesh admission panel.
 *
 * The Cluster page shows who is in the fleet. This shows who was not let
 * in: connections this node refused at admission, or tore down against a
 * deadline. Until now that only reached the node's log, so an operator
 * chasing a peer that will not join had nothing on this page to look at.
 *
 * The idle reclaim is kept out of the headline number on purpose. See
 * ../lib/mesh-admission.ts.
 */
import { computed } from "vue";
import type { ApiError } from "../api";
import { inboundAdmission } from "../lib/mesh-admission";
import { formatNumber } from "../lib/format";
import type { MetricFamily } from "../lib/metrics";
import EmptyState from "./EmptyState.vue";
import ErrorState from "./ErrorState.vue";
import StatCard from "./StatCard.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  families: MetricFamily[];
  loading: boolean;
  error: ApiError | null;
}>();

defineEmits<{ (event: "retry"): void }>();

const report = computed(() => inboundAdmission(props.families));
</script>

<template>
  <section class="panel" aria-labelledby="cluster-inbound-admission-heading">
    <h2 id="cluster-inbound-admission-heading">Inbound peer admission</h2>

    <ErrorState
      v-if="error"
      :error="error"
      title="Could not read the metrics endpoint"
      @retry="$emit('retry')"
    />
    <EmptyState
      v-else-if="loading && !report"
      message="Reading inbound admission metrics..."
    />
    <EmptyState
      v-else-if="!report"
      message="This node has refused no inbound peer connection since it started, so the counter is not reported. A row appears here the first time a peer is turned away at admission or torn down against a deadline."
    />

    <template v-else>
      <p class="hint">
        Inbound cache RPC connections this node did not keep, counted since
        the process started. The peer address is in the node log, never in a
        label.
      </p>

      <div class="tiles">
        <StatCard
          label="Peers turned away"
          :value="formatNumber(report.refusals)"
          sub="refused at admission or torn down against a deadline"
          :tone="report.refusals > 0 ? 'accent' : 'default'"
        />
        <StatCard
          label="At the connection ceiling"
          :value="formatNumber(report.connectionLimit)"
          sub="closed because this node was already full"
        />
        <StatCard
          label="Idle connections reclaimed"
          :value="formatNumber(report.idleReclaims)"
          sub="routine housekeeping, not a refusal"
        />
      </div>

      <div class="table-wrap" role="region" aria-label="Admission reasons" tabindex="0">
        <table class="sb-table admission-table">
          <thead>
            <tr>
              <th>Reason</th>
              <th>Kind</th>
              <th>Count</th>
              <th>What it means</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in report.rows" :key="row.reason">
              <th scope="row" class="sb-mono">{{ row.reason }}</th>
              <td>
                <StatusBadge
                  :label="row.refusal ? 'refused' : 'reclaimed'"
                  :tone="row.refusal ? 'warn' : 'neutral'"
                />
              </td>
              <td class="count">{{ formatNumber(row.count) }}</td>
              <td class="meaning">{{ row.meaning }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>

<style scoped>
.panel {
  margin-bottom: var(--sb-space-6);
}
.panel h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 var(--sb-space-2);
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 0 0 var(--sb-space-3);
  max-width: 72ch;
}
.table-wrap {
  overflow-x: auto;
}
.table-wrap:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: -3px;
}
.admission-table {
  min-width: 640px;
}
.admission-table th[scope="row"] {
  min-width: 0;
  overflow-wrap: anywhere;
}
.count {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.meaning {
  color: var(--sb-text-muted);
  font-size: 0.82rem;
  max-width: 46ch;
}
</style>
