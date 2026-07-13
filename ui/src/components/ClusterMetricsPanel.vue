<script setup lang="ts">
import { computed } from "vue";
import type { ApiError, ClusterMetrics } from "../api";
import { clusterMetricsSummary } from "../lib/cluster-health";
import { formatNumber } from "../lib/format";
import EmptyState from "./EmptyState.vue";
import ErrorState from "./ErrorState.vue";

const props = defineProps<{
  metrics: ClusterMetrics | null;
  loading: boolean;
  notEnabled: boolean;
  error: ApiError | null;
}>();

defineEmits<{ (event: "retry"): void }>();

const metricRows = computed(() =>
  Object.entries(props.metrics?.metrics ?? {})
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => left.name.localeCompare(right.name)),
);

const summaryText = computed(() =>
  clusterMetricsSummary({
    metrics: props.metrics,
    loading: props.loading,
    notEnabled: props.notEnabled,
    error: props.error !== null,
  }),
);
</script>

<template>
  <details class="sb-card metrics-panel">
    <summary>
      <span>
        <span class="sb-eyebrow">Secondary telemetry</span>
        <strong>Fleet metrics</strong>
      </span>
      <span class="metrics-panel__summary">{{ summaryText }}</span>
    </summary>

    <div class="metrics-panel__body">
      <ErrorState
        v-if="error"
        :error="error"
        title="Could not load fleet metrics"
        @retry="$emit('retry')"
      />
      <EmptyState
        v-else-if="notEnabled"
        message="Fleet metrics are not enabled. Use the local Metrics view or an external Prometheus collector."
      />
      <EmptyState
        v-else-if="loading && !metrics"
        message="Loading fleet metrics..."
      />
      <div
        v-else-if="metricRows.length"
        class="table-wrap"
        role="region"
        aria-label="Fleet metrics"
        tabindex="0"
      >
        <table class="sb-table metrics-table">
          <thead>
            <tr><th>Metric</th><th>Fleet total</th></tr>
          </thead>
          <tbody>
            <tr v-for="metric in metricRows" :key="metric.name">
              <td class="sb-mono">{{ metric.name }}</td>
              <td>{{ formatNumber(metric.value) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <EmptyState v-else message="No fleet metrics have been published yet." />
    </div>
  </details>
</template>

<style scoped>
.metrics-panel {
  padding: 0;
  overflow: hidden;
}

.metrics-panel summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-4);
  padding: var(--sb-space-4) var(--sb-space-5);
  cursor: pointer;
  list-style-position: inside;
}

.metrics-panel summary:hover {
  background: var(--sb-surface-2);
}

.metrics-panel summary:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: -3px;
}

.metrics-panel summary > span:first-child {
  display: inline-grid;
  gap: var(--sb-space-1);
}

.metrics-panel__summary {
  color: var(--sb-text-faint);
  font-size: 0.76rem;
}

.metrics-panel__body {
  padding: var(--sb-space-5);
  border-top: 1px solid var(--sb-border);
}

.table-wrap {
  overflow-x: auto;
}

.table-wrap:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: -3px;
}

.metrics-table {
  min-width: 520px;
}

@media (max-width: 760px) {
  .metrics-panel summary {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
