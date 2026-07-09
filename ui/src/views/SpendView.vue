<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api } from "../api";
import { useAsync } from "../composables/useAsync";
import {
  parsePrometheus,
  findFamily,
  groupByLabel,
  sumSamples,
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber, formatUsd } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import MiniBars from "../components/MiniBars.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.metrics());
onMounted(req.run);

const families = computed<MetricFamily[]>(() => {
  const text = req.data.value;
  return text ? parsePrometheus(text) : [];
});

// Cost by (provider, model): the base AI cost counter.
const costFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_cost_dollars_total"),
);
// Tokens by (provider, model, direction: input|output).
const tokensFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_tokens_total"),
);
// AI request count by (provider, model, ...).
const aiRequestsFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_requests_total"),
);
// Per-virtual-key cost.
const keyCostFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_key_cost_dollars_total"),
);
// Attributed cost carries project/team/environment partitions.
const attributedCostFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_cost_dollars_attributed_total"),
);

const totalSpend = computed(() => sumSamples(costFamily.value));
const tokensIn = computed(() =>
  sumSamples(tokensFamily.value, { direction: "input" }),
);
const tokensOut = computed(() =>
  sumSamples(tokensFamily.value, { direction: "output" }),
);
const totalAiRequests = computed(() => sumSamples(aiRequestsFamily.value));

const spendByModel = computed(() => groupByLabel(costFamily.value, "model"));
const spendByProvider = computed(() =>
  groupByLabel(costFamily.value, "provider"),
);
const spendByKey = computed(() =>
  groupByLabel(keyCostFamily.value, "virtual_key"),
);
const spendByTeam = computed(() =>
  groupByLabel(attributedCostFamily.value, "team"),
);
const spendByProject = computed(() =>
  groupByLabel(attributedCostFamily.value, "project"),
);

// Per-model detail rows: cost + tokens + requests joined on model.
interface ModelRow {
  model: string;
  cost: number;
  tokensIn: number;
  tokensOut: number;
  requests: number;
}
const modelRows = computed<ModelRow[]>(() =>
  spendByModel.value.map(({ key, value }) => ({
    model: key,
    cost: value,
    tokensIn: sumSamples(tokensFamily.value, {
      model: key,
      direction: "input",
    }),
    tokensOut: sumSamples(tokensFamily.value, {
      model: key,
      direction: "output",
    }),
    requests: sumSamples(aiRequestsFamily.value, { model: key }),
  })),
);

const hasSpend = computed(() => totalSpend.value > 0);
// Attribution partitions only exist when credentials carry tags; hide
// empty breakdowns rather than showing a lone "(none)" row.
const hasTeams = computed(() =>
  spendByTeam.value.some((r) => r.key !== "(none)" && r.value > 0),
);
const hasProjects = computed(() =>
  spendByProject.value.some((r) => r.key !== "(none)" && r.value > 0),
);
const hasKeys = computed(() => spendByKey.value.length > 0);
</script>

<template>
  <PageHeader
    title="Spend"
    subtitle="Estimated AI cost from the live counters. Totals accumulate since process start and reset on restart; scrape /metrics into Prometheus for history."
  />

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />

  <EmptyState
    v-else-if="!req.loading.value && !hasSpend"
    message="No AI spend recorded since the proxy started. Spend appears here after the first AI request flows through an ai_proxy origin."
  />

  <template v-else-if="hasSpend">
    <div class="tiles">
      <StatCard label="Total spend" :value="formatUsd(totalSpend)" tone="accent" sub="since start" />
      <StatCard label="AI requests" :value="formatNumber(totalAiRequests)" sub="since start" />
      <StatCard label="Tokens in" :value="formatNumber(tokensIn)" sub="prompt" />
      <StatCard label="Tokens out" :value="formatNumber(tokensOut)" sub="completion" />
    </div>

    <section class="panel">
      <h2>Spend by model</h2>
      <MiniBars :items="spendByModel" unit="$" />
      <table class="detail">
        <thead>
          <tr>
            <th>Model</th>
            <th>Cost</th>
            <th>Tokens in</th>
            <th>Tokens out</th>
            <th>Requests</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in modelRows" :key="r.model">
            <td>{{ r.model }}</td>
            <td>{{ formatUsd(r.cost) }}</td>
            <td>{{ formatNumber(r.tokensIn) }}</td>
            <td>{{ formatNumber(r.tokensOut) }}</td>
            <td>{{ formatNumber(r.requests) }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Spend by provider</h2>
      <MiniBars :items="spendByProvider" unit="$" />
    </section>

    <section class="panel" v-if="hasKeys">
      <h2>Spend by virtual key</h2>
      <MiniBars :items="spendByKey" unit="$" />
    </section>

    <section class="panel" v-if="hasTeams">
      <h2>Spend by team</h2>
      <MiniBars :items="spendByTeam" unit="$" />
    </section>

    <section class="panel" v-if="hasProjects">
      <h2>Spend by project</h2>
      <MiniBars :items="spendByProject" unit="$" />
    </section>
  </template>
</template>

<style scoped>
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.panel {
  margin-bottom: 24px;
}
.panel h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 8px;
}
.detail {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 13px;
}
.detail th {
  text-align: left;
  font-weight: 500;
  color: var(--sb-text-muted);
  padding: 6px 8px;
  border-bottom: 1px solid var(--sb-border);
}
.detail td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--sb-border);
  font-variant-numeric: tabular-nums;
}
</style>
