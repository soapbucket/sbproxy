<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  api,
  ApiError,
  type RequestFilters,
  type RequestReportResponse,
  type ScoreAggregate,
  type ScoresResponse,
} from "../api";
import { useAsync } from "../composables/useAsync";
import {
  filterStateFromQuery,
  filterStateToQuery,
  groupByFromQuery,
} from "../lib/filter-url";
import { formatNumber, formatUsd } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";

const route = useRoute();
const router = useRouter();

// The four report dimensions, selectable simultaneously (OpenRouter
// groups an export by Model, Key, or Creator; this view takes all of
// them at once). `user` is the resolved human subject behind the call.
const DIMENSIONS = [
  { value: "model", label: "Model" },
  { value: "api_key_id", label: "API key" },
  { value: "tenant", label: "Tenant" },
  { value: "user", label: "User" },
] as const;
const FILTER_KEYS = DIMENSIONS.map((d) => d.value);

// One ref per filter dimension; empty string means "not filtered".
const fModel = ref("");
const fApiKeyId = ref("");
const fTenant = ref("");
const fUser = ref("");
const groupBy = ref<string[]>(["model"]);

function currentFilters(): RequestFilters {
  return {
    ...(fModel.value ? { model: fModel.value } : {}),
    ...(fApiKeyId.value ? { apiKeyId: fApiKeyId.value } : {}),
    ...(fTenant.value ? { tenant: fTenant.value } : {}),
    ...(fUser.value ? { user: fUser.value } : {}),
  };
}

// The committed view: what the table shows, what the URL carries, and
// what an export downloads, all read from here rather than from the
// live inputs. `applyFilters` is the only writer. Reading the live refs
// instead is how a link under-filters: an operator who types a tenant
// and refreshes narrows the table while the address bar still says
// "every tenant", and the colleague they send it to sees every tenant.
const appliedFilters = ref<RequestFilters>({});
const appliedGroupBy = ref<string[]>(["model"]);

const req = useAsync(() =>
  api.requestsReport(appliedGroupBy.value, appliedFilters.value),
);
const report = computed<RequestReportResponse | null>(() => req.data.value);
const rows = computed(() => report.value?.rows ?? []);
const totals = computed(() => report.value?.totals ?? null);
const groupedColumns = computed(() =>
  DIMENSIONS.filter((d) => groupBy.value.includes(d.value)),
);

// LiteLLM's pattern: the URL is the saved filter. Filter and grouping
// state serializes into query params on every applied change, so the
// address bar is always a shareable link to this exact view.
function syncStateToUrl() {
  router.replace({
    query: filterStateToQuery({
      model: fModel.value,
      api_key_id: fApiKeyId.value,
      tenant: fTenant.value,
      user: fUser.value,
      group_by: groupBy.value.join(","),
    }),
  });
}

function applyFilters() {
  appliedFilters.value = currentFilters();
  appliedGroupBy.value = [...groupBy.value];
  syncStateToUrl();
  req.run();
}

function clearFilters() {
  fModel.value = "";
  fApiKeyId.value = "";
  fTenant.value = "";
  fUser.value = "";
  applyFilters();
}

function toggleDimension(dim: string) {
  if (groupBy.value.includes(dim)) {
    // The report needs at least one dimension; refuse to drop the last.
    if (groupBy.value.length === 1) return;
    groupBy.value = groupBy.value.filter((d) => d !== dim);
  } else {
    // Keep the canonical order so equal selections build equal links.
    groupBy.value = FILTER_KEYS.filter(
      (d) => groupBy.value.includes(d) || d === dim,
    );
  }
  applyFilters();
}

onMounted(() => {
  // A shared link restores the exact view: filters and grouping both
  // come back out of the URL before the first fetch.
  const state = filterStateFromQuery(route.query, [...FILTER_KEYS, "group_by"]);
  fModel.value = state.model;
  fApiKeyId.value = state.api_key_id;
  fTenant.value = state.tenant;
  fUser.value = state.user;
  // A hand-edited link can name an unknown or repeated dimension, and
  // the report API refuses both. Normalize instead of erroring: a
  // shared link degrades to a usable view.
  const dims = groupByFromQuery(state.group_by, FILTER_KEYS);
  if (dims.length) groupBy.value = dims;
  // Commit before the first fetch so the table, the URL and the export
  // links all describe the same view from the first paint.
  appliedFilters.value = currentFilters();
  appliedGroupBy.value = [...groupBy.value];
  req.run();
});

// Export the committed filtered view (raw rows, not the grouped ones).
// The href is real and copyable, and a right-click save still works;
// the click path goes through the typed client instead, because a bare
// <a download> never enters `request()`'s failure handling and a lapsed
// session would save `{"error":"Unauthorized"}` as `requests.csv` with
// nothing on screen. The response is bounded server-side by the ring
// cap, so holding it long enough to name the file is bounded too.
const exportCsvUrl = computed(() =>
  api.requestsExportUrl("csv", appliedFilters.value),
);
const exportJsonlUrl = computed(() =>
  api.requestsExportUrl("jsonl", appliedFilters.value),
);
const exporting = ref<"csv" | "jsonl" | null>(null);
const exportError = ref<string | null>(null);

const EXPORT_CONTENT_TYPES = {
  csv: "text/csv",
  jsonl: "application/x-ndjson",
} as const;

async function downloadExport(format: "csv" | "jsonl") {
  exporting.value = format;
  exportError.value = null;
  try {
    const body = await api.requestsExport(format, appliedFilters.value);
    saveAs(body, `requests.${format}`, EXPORT_CONTENT_TYPES[format]);
  } catch (e) {
    exportError.value =
      e instanceof ApiError
        ? e.hint
        : e instanceof Error
          ? e.message
          : "The export failed.";
  } finally {
    exporting.value = null;
  }
}

function saveAs(body: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function groupValue(row: { group: Record<string, string> }, dim: string): string {
  return row.group[dim] || "(unattributed)";
}

// The composite group IS the row identity, and its values are
// arbitrary caller strings, so join them through JSON rather than a
// separator any value could contain. A model literally named
// "a b" must not collide with the group ["a", "b"].
function rowKey(row: { group: Record<string, string> }): string {
  return JSON.stringify(groupBy.value.map((d) => row.group[d] ?? ""));
}

// ---- scores and feedback (WOR-2581) ----
//
// The sibling reporting dimension. sbproxy computes no scores: these
// arrive from an eval harness, a thumbs widget, or a human, keyed to a
// request id, and this charts what came in.
//
// Deliberately a panel on this page rather than a page of its own. A
// score is only meaningful next to what it is scoring, and a standalone
// "Scores" page would be a list of integers with no context.
const scores = useAsync(() => api.scores());
onMounted(scores.run);

const scoreAggregates = computed<ScoreAggregate[]>(
  () => scores.data.value?.aggregates ?? [],
);
const scoreData = computed<ScoresResponse | null>(() => scores.data.value ?? null);

// An empty sink is the common state and is not an error: most
// deployments never post a score. Say what would put one here rather
// than rendering a bare "no data".
const noScores = computed(
  () => scores.succeeded.value && !(scores.data.value?.scores.length ?? 0),
);

/*
 * Mean is the number an operator reads first, so give it a tone.
 * Thresholds are display-only and deliberately coarse: sbproxy has no
 * opinion about what a good score is, because it does not know what the
 * evaluator was measuring.
 */
function meanTone(mean: number): "ok" | "warn" | "err" {
  if (mean > 2) return "ok";
  if (mean >= -2) return "warn";
  return "err";
}
</script>

<template>
  <PageHeader
    title="Reports"
    subtitle="Spend and usage over the recent-request ring, grouped by any mix of model, API key, tenant, and user. The URL carries the whole view, so a filtered report is a shareable link."
  >
    <template #actions>
      <a
        class="sb-btn"
        :href="exportCsvUrl"
        download="requests.csv"
        :aria-busy="exporting === 'csv'"
        @click.prevent="downloadExport('csv')"
        >Export CSV</a
      >
      <a
        class="sb-btn"
        :href="exportJsonlUrl"
        download="requests.jsonl"
        :aria-busy="exporting === 'jsonl'"
        @click.prevent="downloadExport('jsonl')"
        >Export JSONL</a
      >
      <button class="sb-btn sb-btn--primary" @click="applyFilters">Refresh</button>
    </template>
  </PageHeader>

  <!-- Scores and feedback (WOR-2581) -->
  <section class="section">
    <div class="section__head">
      <h2>Scores and feedback</h2>
      <span class="sb-faint">
        Quality signals posted against logged requests. sbproxy stores these; it
        does not compute them.
      </span>
      <button class="sb-btn sb-btn--sm" :disabled="scores.loading.value" @click="scores.run">
        {{ scores.loading.value ? "Loading..." : "Refresh" }}
      </button>
    </div>
    <EmptyState
      v-if="noScores"
      message="No scores recorded. Post one with POST /api/requests/{id}/scores from an eval harness, a thumbs up/down widget, or a review tool, and it charts here."
    />
    <ErrorState
      v-else-if="scores.error.value"
      :error="scores.error.value"
      @retry="scores.run"
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Evaluator</th>
            <th>Scores</th>
            <th>Mean</th>
            <th>Range</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in scoreAggregates" :key="row.label">
            <td class="sb-mono">{{ row.label }}</td>
            <td class="sb-mono">{{ formatNumber(row.count) }}</td>
            <td>
              <StatusBadge :label="String(row.mean)" :tone="meanTone(row.mean)" />
            </td>
            <td class="sb-mono">{{ row.min }} to {{ row.max }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="scoreData" class="sb-faint">
        Accepted range {{ scoreData.range.min }} to {{ scoreData.range.max }}. The
        last {{ formatNumber(scoreData.capacity) }} scores are kept in process; ship
        the sbproxy::admin::scores log lines to keep history.
      </p>
    </div>
  </section>

  <section class="filter-panel" aria-label="Report filters">
    <div class="filters">
      <input
        v-model="fModel"
        class="sb-input"
        placeholder="Model"
        aria-label="Filter by model"
        @keydown.enter="applyFilters"
      />
      <input
        v-model="fApiKeyId"
        class="sb-input"
        placeholder="API key id"
        aria-label="Filter by API key id"
        @keydown.enter="applyFilters"
      />
      <input
        v-model="fTenant"
        class="sb-input"
        placeholder="Tenant"
        aria-label="Filter by tenant"
        @keydown.enter="applyFilters"
      />
      <input
        v-model="fUser"
        class="sb-input"
        placeholder="User"
        aria-label="Filter by user"
        @keydown.enter="applyFilters"
      />
      <button class="sb-btn sb-btn--sm" @click="applyFilters">Apply</button>
      <button class="sb-btn sb-btn--sm" @click="clearFilters">Clear</button>
    </div>
    <div class="filters group-row" role="group" aria-label="Group by dimensions">
      <span class="sb-faint">Group by</span>
      <button
        v-for="dim in DIMENSIONS"
        :key="dim.value"
        class="sb-btn sb-btn--sm"
        :class="{ 'sb-btn--primary': groupBy.includes(dim.value) }"
        :aria-pressed="groupBy.includes(dim.value)"
        @click="toggleDimension(dim.value)"
      >
        {{ dim.label }}
      </button>
    </div>
  </section>

  <p v-if="exportError" class="export-error" role="alert">{{ exportError }}</p>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState
    v-else-if="!req.loading.value && !rows.length"
    message="No requests match the current filters. The report reads the in-memory recent-request ring, so it fills in as traffic flows and clears on restart."
  />
  <template v-else-if="rows.length">
    <div v-if="totals" class="tiles">
      <StatCard
        label="Spend"
        :value="formatUsd(totals.cost_usd_micros / 1_000_000)"
        tone="accent"
        sub="filtered"
      />
      <StatCard label="Requests" :value="formatNumber(totals.requests)" sub="filtered" />
      <StatCard label="Tokens in" :value="formatNumber(totals.tokens_in)" sub="prompt" />
      <StatCard label="Tokens out" :value="formatNumber(totals.tokens_out)" sub="completion" />
    </div>
    <div class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th v-for="dim in groupedColumns" :key="dim.value">{{ dim.label }}</th>
            <th class="num">Requests</th>
            <th class="num">Tokens in</th>
            <th class="num">Tokens out</th>
            <th class="num">Cost</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="rowKey(row)">
            <td v-for="dim in groupedColumns" :key="dim.value" class="sb-mono">
              {{ groupValue(row, dim.value) }}
            </td>
            <td class="num">{{ formatNumber(row.requests) }}</td>
            <td class="num">{{ formatNumber(row.tokens_in) }}</td>
            <td class="num">{{ formatNumber(row.tokens_out) }}</td>
            <td class="num">{{ formatUsd(row.cost_usd_micros / 1_000_000) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>

<style scoped>
.export-error {
  margin: 0 0 12px;
  color: var(--sb-err);
  font-size: 13px;
}
.filter-panel {
  margin-bottom: 16px;
}
.filters {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.group-row {
  margin-top: 8px;
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
</style>
