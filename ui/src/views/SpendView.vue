<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { api, type SpendWindowResponse } from "../api";
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

// The attributed families are what the live AI path populates
// (emit_ai_billing_event); they carry model/provider plus the
// attribution partitions (team, project, api_key_id) in one counter.
// The unattributed names are kept as fallbacks for older builds.
const costFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_cost_dollars_attributed_total",
    "sbproxy_ai_cost_dollars_total",
  ),
);
// Tokens by direction (input|output, plus cache/reasoning variants).
const tokensFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_tokens_attributed_total",
    "sbproxy_ai_tokens_total",
  ),
);
const aiRequestsFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_requests_attributed_total",
    "sbproxy_ai_requests_total",
  ),
);

const totalSpend = computed(() => sumSamples(costFamily.value));
const tokensIn = computed(() =>
  sumSamples(tokensFamily.value, { direction: "input" }),
);
const tokensOut = computed(() =>
  sumSamples(tokensFamily.value, { direction: "output" }),
);
const totalAiRequests = computed(() => sumSamples(aiRequestsFamily.value));

// Attribution labels are empty strings for uncredentialed traffic and
// "(none)" when the label is absent entirely; both mean "no data" for
// a breakdown row.
function labeled(rows: { key: string; value: number }[]) {
  return rows.filter((r) => r.key !== "" && r.key !== "(none)" && r.value > 0);
}

const spendByModel = computed(() => groupByLabel(costFamily.value, "model"));
const spendByProvider = computed(() =>
  groupByLabel(costFamily.value, "provider"),
);
const spendByKey = computed(() =>
  labeled(groupByLabel(costFamily.value, "api_key_id")),
);
const spendByTeam = computed(() =>
  labeled(groupByLabel(costFamily.value, "team")),
);
const spendByProject = computed(() =>
  labeled(groupByLabel(costFamily.value, "project")),
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
// Attribution partitions only exist when credentials carry tags; the
// sections hide entirely rather than showing a lone empty row.
const hasTeams = computed(() => spendByTeam.value.length > 0);
const hasProjects = computed(() => spendByProject.value.length > 0);
const hasKeys = computed(() => spendByKey.value.length > 0);

// --- Spend history from the durable rollups (WOR-1875) ---
// Served by /api/usage/spend?window=&group_by=; survives restarts.
const HISTORY_WINDOWS = ["1h", "24h", "7d", "30d"] as const;
const HISTORY_GROUPS = [
  { value: "total", label: "Total" },
  { value: "model", label: "Model" },
  { value: "provider", label: "Provider" },
  { value: "team", label: "Team" },
  { value: "project", label: "Project" },
  { value: "api_key", label: "API key" },
] as const;
const historyWindow = ref<(typeof HISTORY_WINDOWS)[number]>("24h");
const historyGroup = ref<string>("model");
const history = useAsync(() =>
  api.spendWindow(historyWindow.value, historyGroup.value),
);
onMounted(history.run);
watch([historyWindow, historyGroup], () => history.run());

// Rollups disabled (503) reads as a hint, not a failure. The detail
// lives in the response body, not the error message.
const historyDisabled = computed(() => {
  const e = history.error.value;
  if (!e) return false;
  return `${e.message} ${e.body}`.includes("not enabled");
});

function bucketLabel(tsSecs: number, bucketSecs: number): string {
  const d = new Date(tsSecs * 1000);
  if (bucketSecs >= 86400) {
    return `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }
  return `${String(d.getHours()).padStart(2, "0")}:00`;
}

// Spend over time: one bar per bucket, groups folded together.
const historyOverTime = computed(() => {
  const res: SpendWindowResponse | null = history.data.value;
  if (!res) return [];
  const byTs = new Map<number, number>();
  for (const b of res.buckets) {
    byTs.set(b.ts_secs, (byTs.get(b.ts_secs) ?? 0) + b.cost_usd_micros);
  }
  return [...byTs.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([ts, micros]) => ({
      key: bucketLabel(ts, res.bucket_secs),
      value: micros / 1_000_000,
    }));
});

// Per-group totals across the window, for the table.
interface HistoryRow {
  group: string;
  cost: number;
  tokensIn: number;
  tokensOut: number;
  requests: number;
  blocked: number;
}
const historyRows = computed<HistoryRow[]>(() => {
  const res: SpendWindowResponse | null = history.data.value;
  if (!res) return [];
  const byGroup = new Map<string, HistoryRow>();
  for (const b of res.buckets) {
    const key = b.group === "" ? "(unattributed)" : b.group;
    const row = byGroup.get(key) ?? {
      group: key,
      cost: 0,
      tokensIn: 0,
      tokensOut: 0,
      requests: 0,
      blocked: 0,
    };
    row.cost += b.cost_usd_micros / 1_000_000;
    row.tokensIn += b.tokens_in;
    row.tokensOut += b.tokens_out;
    row.requests += b.requests;
    row.blocked += b.blocked;
    byGroup.set(key, row);
  }
  return [...byGroup.values()].sort((a, b) => b.cost - a.cost);
});
const historyTotals = computed(() => history.data.value?.totals ?? null);
const hasHistory = computed(() => historyRows.value.length > 0);
</script>

<template>
  <PageHeader
    title="Spend"
    subtitle="Estimated AI cost. History comes from the durable usage rollups and survives restarts; the live sections below accumulate since process start."
  />

  <section class="panel">
    <div class="history-head">
      <h2>Spend history</h2>
      <div class="pickers">
        <div class="segmented" role="group" aria-label="Time range">
          <button
            v-for="w in HISTORY_WINDOWS"
            :key="w"
            :class="{ active: historyWindow === w }"
            @click="historyWindow = w"
          >
            {{ w }}
          </button>
        </div>
        <select v-model="historyGroup" aria-label="Group by">
          <option v-for="g in HISTORY_GROUPS" :key="g.value" :value="g.value">
            {{ g.label }}
          </option>
        </select>
      </div>
    </div>

    <p v-if="historyDisabled" class="hint">
      Usage rollups are not enabled, so windowed history is unavailable.
      Enable proxy.observability.usage_rollups (on by default) and make
      sure its path is writable.
    </p>
    <ErrorState
      v-else-if="history.error.value"
      :error="history.error.value"
      @retry="history.run"
    />
    <p v-else-if="!history.loading.value && !hasHistory" class="hint">
      No spend recorded in this window yet. History fills in as AI
      requests flow; totals survive restarts.
    </p>
    <template v-else-if="hasHistory">
      <MiniBars :items="historyOverTime" :format="formatUsd" />
      <div class="tiles history-tiles" v-if="historyTotals">
        <StatCard
          label="Window spend"
          :value="formatUsd(historyTotals.cost_usd_micros / 1_000_000)"
          tone="accent"
        />
        <StatCard label="Requests" :value="formatNumber(historyTotals.requests)" />
        <StatCard label="Blocked" :value="formatNumber(historyTotals.blocked)" />
        <StatCard
          label="Tokens"
          :value="formatNumber(historyTotals.tokens_in + historyTotals.tokens_out)"
        />
      </div>
      <table class="detail">
        <thead>
          <tr>
            <th>{{ HISTORY_GROUPS.find((g) => g.value === historyGroup)?.label ?? "Group" }}</th>
            <th>Cost</th>
            <th>Tokens in</th>
            <th>Tokens out</th>
            <th>Requests</th>
            <th>Blocked</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in historyRows" :key="r.group">
            <td>{{ r.group }}</td>
            <td>{{ formatUsd(r.cost) }}</td>
            <td>{{ formatNumber(r.tokensIn) }}</td>
            <td>{{ formatNumber(r.tokensOut) }}</td>
            <td>{{ formatNumber(r.requests) }}</td>
            <td>{{ formatNumber(r.blocked) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
  </section>

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
      <MiniBars :items="spendByModel" :format="formatUsd" />
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
      <MiniBars :items="spendByProvider" :format="formatUsd" />
    </section>

    <section class="panel" v-if="hasKeys">
      <h2>Spend by API key</h2>
      <MiniBars :items="spendByKey" :format="formatUsd" />
    </section>

    <section class="panel" v-if="hasTeams">
      <h2>Spend by team</h2>
      <MiniBars :items="spendByTeam" :format="formatUsd" />
    </section>

    <section class="panel" v-if="hasProjects">
      <h2>Spend by project</h2>
      <MiniBars :items="spendByProject" :format="formatUsd" />
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
.history-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.history-head h2 {
  margin: 0;
}
.pickers {
  display: flex;
  align-items: center;
  gap: 8px;
}
.segmented {
  display: inline-flex;
  border: 1px solid var(--sb-border);
  border-radius: 0;
  overflow: hidden;
}
.segmented button {
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--sb-text-muted);
  font: inherit;
  font-size: 12px;
  padding: 4px 10px;
  cursor: pointer;
}
.segmented button + button {
  border-left: 1px solid var(--sb-border);
}
.segmented button.active {
  background: var(--sb-accent-tint);
  color: var(--sb-text);
}
.pickers select {
  font: inherit;
  font-size: 12px;
  padding: 4px 8px;
  border: 1px solid var(--sb-border);
  border-radius: 0;
  background: transparent;
  color: var(--sb-text);
}
.history-tiles {
  margin-top: 12px;
  margin-bottom: 0;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 0;
}
</style>
