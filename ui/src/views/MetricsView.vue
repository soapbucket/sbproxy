<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { useAsync } from "../composables/useAsync";
import {
  parsePrometheus,
  findFamily,
  groupByLabel,
  sumSamples,
  histogramQuantile,
  histogramAvgByLabel,
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber, formatMs, formatUsd } from "../lib/format";
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

const requestsByMethod = computed(() => {
  const f = requestFamily.value;
  if (!f || !f.samples.some((s) => "method" in s.labels)) return [];
  return groupByLabel(f, "method").slice(0, 8);
});
const requestsByHost = computed(() => {
  const f = requestFamily.value;
  const label = ["hostname", "host", "origin"].find((l) =>
    f?.samples.some((s) => l in s.labels),
  );
  return f && label ? groupByLabel(f, label).slice(0, 8) : [];
});
const errorRate = computed(() => {
  const total = totalRequests.value;
  if (!total) return undefined;
  const errs = requestsByStatus.value
    .filter((s) => /^[45]/.test(s.key))
    .reduce((acc, s) => acc + s.value, 0);
  return (errs / total) * 100;
});

// Latency percentiles from the request-duration histogram (seconds -> ms).
const latencyFamily = computed(() =>
  findFamily(families.value, "sbproxy_request_duration_seconds"),
);
const latencyPercentiles = computed(() => {
  const f = latencyFamily.value;
  if (!f) return [];
  return [
    { key: "p50", q: 0.5 },
    { key: "p95", q: 0.95 },
    { key: "p99", q: 0.99 },
  ]
    .map(({ key, q }) => {
      const secs = histogramQuantile(f, q);
      return secs === undefined ? null : { key, value: secs * 1000 };
    })
    .filter((x): x is { key: string; value: number } => x !== null);
});

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
    // The server emits cost in micro-USD; keep the older names as fallbacks.
    "sbproxy_ai_cost_usd_micros_total",
    "sbproxy_ai_cost_usd_total",
    "sbproxy_cost_usd_total",
    "sbproxy_ai_cost_total",
  ),
);
const totalTokens = computed(() => (tokenFamily.value ? sumSamples(tokenFamily.value) : undefined));
const totalCost = computed(() => {
  const f = costFamily.value;
  if (!f) return undefined;
  const raw = sumSamples(f);
  // Micro-USD counter -> USD.
  return f.name.includes("micros") ? raw / 1e6 : raw;
});

const tokensByKind = computed(() => {
  const f = tokenFamily.value;
  if (!f) return [];
  const label = ["direction", "kind", "type", "token_type"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  return label ? groupByLabel(f, label).slice(0, 8) : [];
});
const tokensByProvider = computed(() => {
  const f = tokenFamily.value;
  return f && f.samples.some((s) => "provider" in s.labels)
    ? groupByLabel(f, "provider").slice(0, 8)
    : [];
});

const activeConnections = computed(() => {
  const f = findFamily(families.value, "sbproxy_active_connections");
  return f ? sumSamples(f) : undefined;
});

// Token throughput (avg tok/s) per model, the standard local-model
// measure. Populated by streaming completions (WOR-895).
const throughputByModel = computed(() =>
  histogramAvgByLabel(
    findFamily(families.value, "sbproxy_ai_output_throughput_tokens_per_second"),
    "model",
  )
    .map((m) => ({ key: m.key, value: Math.round(m.value * 10) / 10 }))
    .slice(0, 8),
);

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
  if (errorRate.value !== undefined) {
    t.push({ label: "Error rate", value: `${errorRate.value.toFixed(1)}%` });
  }
  const p95 = latencyPercentiles.value.find((p) => p.key === "p95");
  if (p95) t.push({ label: "p95 latency", value: formatMs(p95.value) });
  if (activeConnections.value !== undefined) {
    t.push({ label: "Active connections", value: formatNumber(activeConnections.value) });
  }
  if (totalTokens.value !== undefined) {
    t.push({ label: "AI tokens", value: formatNumber(totalTokens.value) });
  }
  if (totalCost.value !== undefined) {
    t.push({ label: "AI cost", value: formatUsd(totalCost.value) });
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
        <div class="sb-card" v-if="throughputByModel.length">
          <h3>Token throughput (avg tok/s)</h3>
          <MiniBars :items="throughputByModel" />
        </div>
        <div class="sb-card" v-if="latencyPercentiles.length">
          <h3>Request latency</h3>
          <dl class="pctl">
            <template v-for="p in latencyPercentiles" :key="p.key">
              <dt>{{ p.key }}</dt>
              <dd>{{ formatMs(p.value) }}</dd>
            </template>
          </dl>
        </div>
        <div class="sb-card" v-if="requestsByStatus.length">
          <h3>Requests by status</h3>
          <MiniBars :items="requestsByStatus" />
        </div>
        <div class="sb-card" v-if="requestsByMethod.length">
          <h3>Requests by method</h3>
          <MiniBars :items="requestsByMethod" />
        </div>
        <div class="sb-card" v-if="requestsByHost.length">
          <h3>Requests by host</h3>
          <MiniBars :items="requestsByHost" />
        </div>
        <div class="sb-card" v-if="tokensByProvider.length">
          <h3>Tokens by provider</h3>
          <MiniBars :items="tokensByProvider" />
        </div>
        <div class="sb-card" v-if="tokensByKind.length">
          <h3>Tokens by direction</h3>
          <MiniBars :items="tokensByKind" />
        </div>
        <div class="sb-card" v-if="modelHostGauges.length">
          <h3>Model-host gauges</h3>
          <MiniBars :items="modelHostGauges" />
        </div>
      </div>

      <p
        class="sb-faint"
        v-if="!requestsByStatus.length && !requestsByMethod.length && !requestsByHost.length && !latencyPercentiles.length && !throughputByModel.length && !tokensByKind.length && !tokensByProvider.length && !modelHostGauges.length"
      >
        No labelled series matched the known request, latency, token, or model-host families. Use View raw to inspect the full scrape.
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
.pctl {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: var(--sb-space-2) var(--sb-space-4);
  margin: 0;
}
.pctl dt {
  font-variant-numeric: tabular-nums;
  color: var(--sb-text-muted);
  text-transform: uppercase;
  font-size: 0.85em;
  letter-spacing: 0.03em;
}
.pctl dd {
  margin: 0;
  font-variant-numeric: tabular-nums;
  text-align: right;
  font-weight: 600;
}
</style>
