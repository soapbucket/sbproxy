<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { useAsync } from "../composables/useAsync";
import {
  parsePrometheus,
  findFamily,
  groupByLabel,
  sumSamples,
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import MiniBars from "../components/MiniBars.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.metrics());
onMounted(req.run);

const showRaw = ref(false);

const families = computed<MetricFamily[]>(() => {
  const text = req.data.value;
  return text ? parsePrometheus(text) : [];
});

const sbFamilies = computed(() => families.value.filter((f) => f.name.startsWith("sbproxy_")));

// Requests by status label (looks for a request-count family).
const requestFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_requests_total",
    "sbproxy_http_requests_total",
    "sbproxy_request_total",
  ),
);
const requestsByStatus = computed(() => {
  const f = requestFamily.value;
  if (!f) return [];
  // Prefer a status/code label; fall back to any label present.
  const label = ["status", "code", "status_code", "status_class"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  if (!label) return [];
  return groupByLabel(f, label).slice(0, 12);
});
const totalRequests = computed(() => sumSamples(requestFamily.value));

// AI token and cost families, if present.
const tokenFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_tokens_total",
    "sbproxy_tokens_total",
    "sbproxy_ai_token_total",
  ),
);
const costFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_cost_usd_total",
    "sbproxy_cost_usd_total",
    "sbproxy_ai_cost_total",
  ),
);
const totalTokens = computed(() => (tokenFamily.value ? sumSamples(tokenFamily.value) : undefined));
const totalCost = computed(() => (costFamily.value ? sumSamples(costFamily.value) : undefined));

const tokensByKind = computed(() => {
  const f = tokenFamily.value;
  if (!f) return [];
  const label = ["kind", "type", "direction", "token_type"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  return label ? groupByLabel(f, label).slice(0, 8) : [];
});

// Model-host gauges (any sbproxy_model_host_* or sbproxy_*vram* gauge).
const modelHostGauges = computed(() => {
  const out: { key: string; value: number }[] = [];
  for (const f of sbFamilies.value) {
    if (/model_host|vram|resident|gpu/i.test(f.name)) {
      const v = sumSamples(f);
      out.push({ key: f.name.replace(/^sbproxy_/, ""), value: v });
    }
  }
  return out.slice(0, 10);
});

const tiles = computed(() => {
  const t: { label: string; value: string | number; sub?: string }[] = [];
  t.push({ label: "Total requests", value: formatNumber(totalRequests.value) });
  if (totalTokens.value !== undefined) {
    t.push({ label: "AI tokens", value: formatNumber(totalTokens.value) });
  }
  if (totalCost.value !== undefined) {
    t.push({ label: "AI cost (USD)", value: `$${formatNumber(totalCost.value)}` });
  }
  t.push({ label: "sbproxy_* series", value: sbFamilies.value.length });
  return t;
});

const rawText = computed(() => req.data.value ?? "");
</script>

<template>
  <PageHeader
    title="Metrics"
    subtitle="A read of the Prometheus /metrics endpoint. A few key sbproxy series are summarized here; the full scrape is your source of truth."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="showRaw = !showRaw">
        {{ showRaw ? "Hide raw" : "View raw" }}
      </button>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState
    v-else-if="req.data.value !== null && !sbFamilies.length"
    message="No sbproxy_* metrics found in the scrape. The metrics endpoint may be disabled or empty."
  />
  <template v-else>
    <pre class="sb-code" v-if="showRaw">{{ rawText }}</pre>

    <template v-else>
      <div class="grid">
        <StatCard
          v-for="t in tiles"
          :key="t.label"
          :label="t.label"
          :value="t.value"
          :sub="t.sub"
          :tone="t.label === 'Total requests' ? 'accent' : 'default'"
        />
      </div>

      <div class="panels">
        <div class="sb-card" v-if="requestsByStatus.length">
          <h3>Requests by status</h3>
          <MiniBars :items="requestsByStatus" />
        </div>
        <div class="sb-card" v-if="tokensByKind.length">
          <h3>Tokens by kind</h3>
          <MiniBars :items="tokensByKind" />
        </div>
        <div class="sb-card" v-if="modelHostGauges.length">
          <h3>Model-host gauges</h3>
          <MiniBars :items="modelHostGauges" />
        </div>
      </div>

      <p class="sb-faint" v-if="!requestsByStatus.length && !tokensByKind.length && !modelHostGauges.length">
        No labelled series matched the known request, token, or model-host families. Use View raw to inspect the full scrape.
      </p>
    </template>
  </template>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.panels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--sb-space-4);
}
.panels h3 {
  margin-bottom: var(--sb-space-4);
}
</style>
