<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, ApiError } from "../api";
import { formatNumber } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const nodes = ref<number | null>(null);
const metrics = ref<Record<string, number>>({});
const loading = ref(false);
const notEnabled = ref(false);
const err = ref<ApiError | null>(null);

async function load() {
  loading.value = true;
  err.value = null;
  notEnabled.value = false;
  try {
    const cm = await api.clusterMetrics();
    nodes.value = cm.nodes ?? null;
    metrics.value = cm.metrics ?? {};
  } catch (e) {
    // 404 = fleet metrics not enabled (single node / no mesh tier).
    if (e instanceof ApiError && e.status === 404) {
      notEnabled.value = true;
    } else {
      err.value = e instanceof ApiError ? e : new ApiError(0, String(e));
    }
  } finally {
    loading.value = false;
  }
}
onMounted(load);

const metricRows = computed(() =>
  Object.entries(metrics.value)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => a.name.localeCompare(b.name)),
);
</script>

<template>
  <PageHeader
    title="Cluster"
    subtitle="Fleet-aggregated metrics across mesh nodes."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" :disabled="loading" @click="load">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="err" :error="err" @retry="load" />
  <EmptyState
    v-else-if="notEnabled"
    message="Fleet metrics are not enabled on this node. Aggregated cluster metrics require the mesh key tier; a single node uses the local Metrics view, or scrape each node with an external Prometheus."
  />
  <template v-else>
    <div class="grid">
      <StatCard label="Nodes" :value="nodes ?? '-'" tone="accent" />
      <StatCard label="Metrics" :value="metricRows.length" />
    </div>

    <div class="sb-card" v-if="metricRows.length">
      <h3>Aggregated across the fleet</h3>
      <div class="table-wrap">
        <table class="sb-table">
          <thead>
            <tr><th>Metric</th><th>Fleet total</th></tr>
          </thead>
          <tbody>
            <tr v-for="m in metricRows" :key="m.name">
              <td class="sb-mono">{{ m.name }}</td>
              <td>{{ formatNumber(m.value) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <EmptyState v-else message="No fleet metrics published yet." />
  </template>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.sb-card h3 {
  margin-bottom: var(--sb-space-3);
}
.table-wrap {
  overflow-x: auto;
}
</style>
