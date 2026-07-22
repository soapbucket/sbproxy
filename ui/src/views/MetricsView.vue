<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, shallowRef } from "vue";
import { api, ApiError } from "../api";
import { toast } from "../composables/useToasts";
import {
  parsePrometheus,
  findFamily,
  groupByLabel,
  sumSamples,
  histogramAvgByLabel,
  histogramQuantileByLabels,
  type MetricFamily,
} from "../lib/metrics";
import {
  ScrapeHistory,
  rateSeries,
  ratioSeries,
  intervalQuantileSeries,
  bucketMap,
  mapQuantile,
  lastValue,
  type SeriesPoint,
} from "../lib/timeseries";
import {
  formatNumber,
  formatMs,
  formatUsd,
  formatBytes,
  formatDuration,
} from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import MiniBars from "../components/MiniBars.vue";
import LineChart from "../components/LineChart.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

/* ---- Live scrape loop ----
 * The metrics endpoint is a cumulative snapshot, so the page polls it
 * and charts the deltas between consecutive scrapes. The initial
 * fetch failing renders the page error state; a background poll
 * failing raises a toast instead, and repeated failures pause the
 * loop rather than spamming it.
 */
const POLL_MS = 5000;
const HISTORY_POINTS = 121; // ~10 minutes at 5s

const rawText = shallowRef<string | null>(null);
const initialError = ref<ApiError | null>(null);
const live = ref(true);
const showRaw = ref(false);
const history = new ScrapeHistory(HISTORY_POINTS);
const historyTick = ref(0);
let timer: ReturnType<typeof setInterval> | null = null;
let pollFailures = 0;

function asApiError(e: unknown): ApiError {
  return e instanceof ApiError ? e : new ApiError(0, String(e));
}

async function scrape(kind: "initial" | "manual" | "poll"): Promise<void> {
  try {
    const text = await api.metrics();
    rawText.value = text;
    initialError.value = null;
    pollFailures = 0;
    history.push(Date.now(), parsePrometheus(text));
    historyTick.value++;
  } catch (e) {
    if (kind === "initial") {
      initialError.value = asApiError(e);
      return;
    }
    if (kind === "manual") {
      toast.error(e, "Refresh metrics");
      return;
    }
    pollFailures++;
    if (pollFailures >= 3) {
      setLive(false);
      toast.warn(
        "Live sampling paused",
        "Three scrapes in a row failed. Turn Live back on to resume.",
      );
    } else {
      toast.error(e, "Metrics scrape");
    }
  }
}

function setLive(on: boolean): void {
  live.value = on;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  if (on) {
    pollFailures = 0;
    timer = setInterval(() => scrape("poll"), POLL_MS);
  }
}

onMounted(async () => {
  await scrape("initial");
  setLive(true);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
});

/* ---- Current snapshot ---- */

const families = computed<MetricFamily[]>(() => {
  historyTick.value;
  const snaps = history.snapshots;
  return snaps.length ? snaps[snaps.length - 1].families : [];
});

const sbFamilies = computed(() => families.value.filter((f) => f.name.startsWith("sbproxy_")));

// Core proxy families (canonical names, with the legacy fallbacks the
// UI has always tolerated for older binaries).
const requestFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_requests_total",
    "sbproxy_http_requests_total",
    "sbproxy_request_total",
  ),
);
const latencyFamilyName = "sbproxy_request_duration_seconds";
const latencyFamily = computed(() => findFamily(families.value, latencyFamilyName));
const errorsFamily = computed(() => findFamily(families.value, "sbproxy_errors_total"));
const bytesFamily = computed(() => findFamily(families.value, "sbproxy_bytes_total"));
const cacheFamily = computed(() =>
  findFamily(families.value, "sbproxy_cache_results_total"),
);
const authFamily = computed(() =>
  findFamily(families.value, "sbproxy_auth_results_total"),
);

const tokenFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_tokens_attributed_total",
    "sbproxy_tokens_attributed_total",
    "sbproxy_ai_tokens_total",
    "sbproxy_tokens_total",
  ),
);
const costFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_cost_usd_micros_total",
    "sbproxy_ai_cost_dollars_attributed_total",
    "sbproxy_ai_cost_usd_total",
    "sbproxy_ai_cost_total",
  ),
);
const providerErrorsFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_provider_errors_total"),
);

/* ---- Origin scoping (multi-tenant view) ----
 * The request counter and duration histogram carry a hostname label
 * per configured origin, so every traffic panel can be scoped to one
 * origin. "All origins" is the unfiltered default.
 */
const selectedOrigin = ref("");
const hostLabel = computed(() => {
  const f = requestFamily.value;
  return ["hostname", "host", "origin"].find((l) =>
    f?.samples.some((s) => l in s.labels),
  );
});
const originOptions = computed(() => {
  const f = requestFamily.value;
  const label = hostLabel.value;
  if (!f || !label) return [];
  return [...new Set(f.samples.map((s) => s.labels[label]).filter(Boolean))].sort();
});
const originFilter = computed<Record<string, string>>(() =>
  selectedOrigin.value && hostLabel.value
    ? { [hostLabel.value]: selectedOrigin.value }
    : {},
);
/** The request family with the origin filter applied to its samples. */
const scopedRequests = computed<MetricFamily | undefined>(() => {
  const f = requestFamily.value;
  const entries = Object.entries(originFilter.value);
  if (!f || !entries.length) return f;
  return {
    ...f,
    samples: f.samples.filter((s) =>
      entries.every(([k, v]) => s.labels[k] === v),
    ),
  };
});

/**
 * Scope any family to the selected origin via whichever of the given
 * labels it carries. A family with none of them is returned unchanged
 * (it stays an all-origins aggregate; the panel says so).
 */
function scopeByOrigin(
  f: MetricFamily | undefined,
  labels: string[] = ["origin", "hostname"],
): MetricFamily | undefined {
  const selected = selectedOrigin.value;
  if (!f || !selected) return f;
  const label = labels.find((l) => f.samples.some((s) => l in s.labels));
  if (!label) return f;
  return {
    ...f,
    samples: f.samples.filter((s) => s.labels[label] === selected),
  };
}

const totalRequests = computed(() => sumSamples(scopedRequests.value));

const requestsByStatus = computed(() => {
  const f = scopedRequests.value;
  if (!f) return [];
  const label = ["status", "code", "status_code", "status_class"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  if (!label) return [];
  return groupByLabel(f, label).slice(0, 12);
});

const STATUS_COLORS: [RegExp, string][] = [
  [/^2/, "var(--sb-ok)"],
  [/^3/, "var(--sb-info)"],
  [/^4/, "var(--sb-warn)"],
  [/^5/, "var(--sb-err)"],
];
const statusBars = computed(() =>
  requestsByStatus.value.map((row) => ({
    ...row,
    color: STATUS_COLORS.find(([re]) => re.test(row.key))?.[1],
  })),
);

const requestsByMethod = computed(() => {
  const f = scopedRequests.value;
  if (!f || !f.samples.some((s) => "method" in s.labels)) return [];
  return groupByLabel(f, "method").slice(0, 8);
});
const errorsByType = computed(() => {
  const f = scopeByOrigin(errorsFamily.value);
  return f ? groupByLabel(f, "error_type").slice(0, 8) : [];
});
const cacheResults = computed(() => {
  const f = scopeByOrigin(cacheFamily.value);
  return f ? groupByLabel(f, "result").slice(0, 6) : [];
});
const authResults = computed(() => {
  const f = scopeByOrigin(authFamily.value);
  if (!f) return [];
  return groupByLabel(f, "result")
    .slice(0, 6)
    .map((row) => ({
      ...row,
      color: /ok|success|allow/i.test(row.key)
        ? "var(--sb-ok)"
        : /deny|fail|reject|error/i.test(row.key)
          ? "var(--sb-err)"
          : undefined,
    }));
});
const bytesByDirection = computed(() => {
  const f = scopeByOrigin(bytesFamily.value);
  return f ? groupByLabel(f, "direction").slice(0, 4) : [];
});

const errorRate = computed(() => {
  const total = totalRequests.value;
  if (!total) return undefined;
  const errs = requestsByStatus.value
    .filter((s) => /^[45]/.test(s.key))
    .reduce((acc, s) => acc + s.value, 0);
  return (errs / total) * 100;
});

const totalTokens = computed(() => {
  const f = scopeByOrigin(tokenFamily.value, ["origin"]);
  return f ? sumSamples(f) : undefined;
});
const totalCost = computed(() => {
  const f = scopeByOrigin(costFamily.value, ["origin"]);
  if (!f) return undefined;
  const raw = sumSamples(f);
  return f.name.includes("micros") ? raw / 1e6 : raw;
});

const tokensByDirection = computed(() => {
  const f = scopeByOrigin(tokenFamily.value, ["origin"]);
  if (!f) return [];
  const label = ["direction", "kind", "type", "token_type"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  return label ? groupByLabel(f, label).slice(0, 8) : [];
});
const tokensByProvider = computed(() => {
  const f = scopeByOrigin(tokenFamily.value, ["origin"]);
  return f && f.samples.some((s) => "provider" in s.labels)
    ? groupByLabel(f, "provider").slice(0, 8)
    : [];
});
const providerErrors = computed(() => {
  const f = providerErrorsFamily.value;
  if (!f) return [];
  const label = ["provider", "reason"].find((l) =>
    f.samples.some((s) => l in s.labels),
  );
  return label ? groupByLabel(f, label).slice(0, 8) : [];
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

/* ---- Derived time series ---- */

const snapshots = computed(() => {
  historyTick.value;
  return [...history.snapshots];
});

function familyTotal(name: string[], filter?: Record<string, string>) {
  return (fams: MetricFamily[]) => sumSamples(findFamily(fams, ...name), filter);
}

const requestNames = [
  "sbproxy_requests_total",
  "sbproxy_http_requests_total",
  "sbproxy_request_total",
];

const reqRate = computed(() =>
  rateSeries(snapshots.value, familyTotal(requestNames, originFilter.value)),
);

const errRateSeries = computed(() => {
  const scope = originFilter.value;
  return ratioSeries(
    snapshots.value,
    (fams) => {
      const f = findFamily(fams, ...requestNames);
      if (!f) return 0;
      const label = ["status", "code", "status_code", "status_class"].find((l) =>
        f.samples.some((s) => l in s.labels),
      );
      if (!label) return 0;
      const scopeEntries = Object.entries(scope);
      return f.samples
        .filter((s) => scopeEntries.every(([k, v]) => s.labels[k] === v))
        .filter((s) => /^[45]/.test(s.labels[label] ?? ""))
        .reduce((acc, s) => acc + s.value, 0);
    },
    familyTotal(requestNames, scope),
  );
});

function latencySeries(q: number) {
  return intervalQuantileSeries(
    snapshots.value,
    latencyFamilyName,
    q,
    originFilter.value,
  ).map((p) => ({ t: p.t, v: p.v * 1000 }));
}
const p50Series = computed(() => latencySeries(0.5));
const p95Series = computed(() => latencySeries(0.95));
const p99Series = computed(() => latencySeries(0.99));

const tokenRateSeries = computed(() => {
  const f = tokenFamily.value;
  if (!f) return [] as { name: string; points: SeriesPoint[] }[];
  // The attributed counter carries an origin label, so the token
  // charts honor the origin filter when one is selected.
  const scope: Record<string, string> =
    selectedOrigin.value && f.samples.some((s) => "origin" in s.labels)
      ? { origin: selectedOrigin.value }
      : {};
  const hasDirection = f.samples.some((s) => "direction" in s.labels);
  if (!hasDirection) {
    return [
      { name: "tokens/s", points: rateSeries(snapshots.value, familyTotal([f.name], scope)) },
    ];
  }
  return [
    {
      name: "input",
      points: rateSeries(
        snapshots.value,
        familyTotal([f.name], { direction: "input", ...scope }),
      ),
    },
    {
      name: "output",
      points: rateSeries(
        snapshots.value,
        familyTotal([f.name], { direction: "output", ...scope }),
      ),
    },
  ];
});
const hasTokenRate = computed(() =>
  tokenRateSeries.value.some((s) => s.points.length >= 2),
);

const connectionsSeries = computed<SeriesPoint[]>(() =>
  snapshots.value.map((s) => ({
    t: s.t,
    v: sumSamples(findFamily(s.families, "sbproxy_active_connections")),
  })),
);

/* ---- Tiles ---- */

const liveReqRate = computed(() => lastValue(reqRate.value));
const liveErrRate = computed(() => lastValue(errRateSeries.value));
const liveP95 = computed(() => lastValue(p95Series.value));

// Cumulative percentiles since process start, the fallback shown
// until the live window has data. Honors the origin filter.
const cumulativePercentiles = computed(() => {
  if (!latencyFamily.value) return [];
  const byLe = bucketMap(families.value, latencyFamilyName, originFilter.value);
  return [
    { key: "p50", q: 0.5 },
    { key: "p95", q: 0.95 },
    { key: "p99", q: 0.99 },
  ]
    .map(({ key, q }) => {
      const secs = mapQuantile(byLe, q);
      return secs === undefined ? null : { key, value: secs * 1000 };
    })
    .filter((x): x is { key: string; value: number } => x !== null);
});

/* ---- Per-origin activity (multi-tenant triage table) ---- */
interface OriginRow {
  origin: string;
  requests: number;
  successPct: number;
  p50Ms: number | undefined;
  p95Ms: number | undefined;
}
const originRows = computed<OriginRow[]>(() => {
  const f = requestFamily.value;
  const label = hostLabel.value;
  if (!f || !label) return [];
  const statusLabel = ["status", "code", "status_code", "status_class"].find(
    (l) => f.samples.some((s) => l in s.labels),
  );
  const p50 = new Map(
    histogramQuantileByLabels(latencyFamily.value, 0.5, [label]).map((r) => [
      r.key,
      r.value * 1000,
    ]),
  );
  const p95 = new Map(
    histogramQuantileByLabels(latencyFamily.value, 0.95, [label]).map((r) => [
      r.key,
      r.value * 1000,
    ]),
  );
  return groupByLabel(f, label)
    .map(({ key, value }) => {
      const errs = statusLabel
        ? f.samples
            .filter((s) => s.labels[label] === key)
            .filter((s) => /^[45]/.test(s.labels[statusLabel] ?? ""))
            .reduce((acc, s) => acc + s.value, 0)
        : 0;
      return {
        origin: key,
        requests: value,
        successPct: value > 0 ? (1 - errs / value) * 100 : 100,
        p50Ms: p50.get(key),
        p95Ms: p95.get(key),
      };
    })
    .slice(0, 12);
});
function successTone(pct: number): string {
  if (pct >= 99) return "var(--sb-ok)";
  if (pct >= 95) return "var(--sb-warn)";
  return "var(--sb-err)";
}

const percentileChips = computed(() => {
  const liveChips = [
    { key: "p50", series: p50Series.value },
    { key: "p95", series: p95Series.value },
    { key: "p99", series: p99Series.value },
  ]
    .map(({ key, series }) => {
      const v = lastValue(series);
      return v === undefined ? null : { key, value: v };
    })
    .filter((x): x is { key: string; value: number } => x !== null);
  return liveChips.length ? liveChips : cumulativePercentiles.value;
});

// The sampled window, from real timestamps. The poll interval is not
// a reliable clock: browsers throttle background-tab timers, so
// points * 5s would claim a shorter window than the charts span.
const windowLabel = computed(() => {
  const snaps = snapshots.value;
  if (snaps.length < 2) return "";
  return `last ${formatDuration((snaps[snaps.length - 1].t - snaps[0].t) / 1000)}`;
});

const hasAnyPanel = computed(
  () =>
    statusBars.value.length ||
    requestsByMethod.value.length ||
    errorsByType.value.length ||
    cacheResults.value.length ||
    authResults.value.length ||
    bytesByDirection.value.length ||
    tokensByDirection.value.length ||
    tokensByProvider.value.length ||
    providerErrors.value.length ||
    throughputByModel.value.length ||
    modelHostGauges.value.length,
);

function formatRate(v: number | undefined | null): string {
  if (v === undefined || v === null || !isFinite(v)) return "n/a";
  return `${v.toLocaleString(undefined, { maximumFractionDigits: v < 10 ? 1 : 0 })}/s`;
}
function formatPct(v: number): string {
  return `${v.toFixed(1)}%`;
}
</script>

<template>
  <PageHeader
    title="Metrics"
    subtitle="Live reads of the Prometheus /metrics endpoint, sampled every five seconds while this page is open. Rates and percentiles chart what happened between samples; the full scrape is your source of truth."
  >
    <template #actions>
      <button
        class="sb-btn sb-btn--sm live"
        :class="{ 'live--on': live }"
        :aria-pressed="live"
        @click="setLive(!live)"
      >
        <span class="live__dot" aria-hidden="true" />
        {{ live ? "Live" : "Paused" }}
      </button>
      <button class="sb-btn sb-btn--sm" @click="showRaw = !showRaw">
        {{ showRaw ? "Hide raw" : "View raw" }}
      </button>
      <button class="sb-btn sb-btn--primary" @click="scrape('manual')">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="initialError" :error="initialError" @retry="scrape('initial')" />
  <EmptyState
    v-else-if="rawText !== null && !sbFamilies.length"
    message="No sbproxy_* metrics found in the scrape. The metrics endpoint may be disabled or empty."
  />
  <template v-else>
    <pre class="sb-code raw" v-if="showRaw">{{ rawText ?? "" }}</pre>

    <template v-else>
      <div class="filterrow" v-if="originOptions.length > 1">
        <label class="sb-eyebrow" for="origin-filter">origin</label>
        <select id="origin-filter" class="sb-select filterrow__select" v-model="selectedOrigin">
          <option value="">all origins</option>
          <option v-for="o in originOptions" :key="o" :value="o">{{ o }}</option>
        </select>
      </div>

      <div class="grid">
        <StatCard
          label="requests/s"
          :value="formatRate(liveReqRate)"
          tone="accent"
          :spark="reqRate"
        />
        <StatCard label="requests total" :value="formatNumber(totalRequests)" sub="since start" />
        <StatCard
          v-if="errorRate !== undefined || errRateSeries.length"
          label="error rate"
          :value="liveErrRate !== undefined ? formatPct(liveErrRate) : errorRate !== undefined ? formatPct(errorRate) : 'n/a'"
          :spark="errRateSeries"
          spark-color="var(--sb-err)"
          :sub="liveErrRate === undefined ? 'since start' : undefined"
        />
        <StatCard
          v-if="liveP95 !== undefined || cumulativePercentiles.length"
          label="p95 latency"
          :value="formatMs(liveP95 ?? cumulativePercentiles.find((p) => p.key === 'p95')?.value)"
          :spark="p95Series"
          spark-color="var(--sb-chart-2)"
          :sub="liveP95 === undefined ? 'since start' : undefined"
        />
        <StatCard
          v-if="activeConnections !== undefined"
          label="connections"
          :value="formatNumber(activeConnections)"
          :spark="connectionsSeries"
          spark-color="var(--sb-chart-3)"
        />
        <StatCard
          v-if="totalTokens !== undefined"
          label="ai tokens"
          :value="formatNumber(totalTokens)"
          sub="since start"
        />
        <StatCard
          v-if="totalCost !== undefined"
          label="ai cost"
          :value="formatUsd(totalCost)"
          sub="since start"
        />
      </div>

      <section class="plate">
        <div class="plate__head">
          <h2 class="sb-eyebrow">traffic</h2>
          <span class="sb-eyebrow plate__note">{{ windowLabel }}</span>
        </div>
        <div class="plate__charts">
          <div>
            <h3 class="chart-title">Requests per second</h3>
            <LineChart
              :series="[{ name: 'requests/s', points: reqRate }]"
              :format="(v: number) => v.toLocaleString(undefined, { maximumFractionDigits: 1 })"
            />
          </div>
          <div>
            <h3 class="chart-title">Error rate</h3>
            <LineChart
              :series="[{ name: 'errors %', points: errRateSeries, color: 'var(--sb-err)' }]"
              :format="formatPct"
              :max="Math.max(5, ...errRateSeries.map((p) => p.v * 1.2))"
            />
          </div>
        </div>
      </section>

      <section class="plate" v-if="percentileChips.length || p95Series.length">
        <div class="plate__head">
          <h2 class="sb-eyebrow">latency</h2>
          <dl class="pctl" v-if="percentileChips.length">
            <template v-for="p in percentileChips" :key="p.key">
              <dt class="sb-mono">{{ p.key }}</dt>
              <dd>{{ formatMs(p.value) }}</dd>
            </template>
          </dl>
        </div>
        <LineChart
          :series="[
            { name: 'p50', points: p50Series },
            { name: 'p95', points: p95Series },
            { name: 'p99', points: p99Series },
          ]"
          :format="formatMs"
        />
      </section>

      <section class="plate" v-if="originRows.length">
        <div class="plate__head">
          <h2 class="sb-eyebrow">origins</h2>
          <span class="sb-eyebrow plate__note">since start</span>
        </div>
        <div class="table-wrap">
          <table class="sb-table">
            <thead>
              <tr>
                <th>origin</th>
                <th>requests</th>
                <th>success</th>
                <th>p50</th>
                <th>p95</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in originRows" :key="r.origin">
                <td class="sb-mono">{{ r.origin }}</td>
                <td>{{ formatNumber(r.requests) }}</td>
                <td>
                  <span class="sb-mono" :style="{ color: successTone(r.successPct), fontWeight: 600 }">
                    {{ r.successPct.toFixed(r.successPct >= 99.95 ? 0 : 1) }}%
                  </span>
                </td>
                <td>{{ formatMs(r.p50Ms) }}</td>
                <td>{{ formatMs(r.p95Ms) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="plate" v-if="hasTokenRate">
        <div class="plate__head">
          <h2 class="sb-eyebrow">ai tokens</h2>
        </div>
        <h3 class="chart-title">Tokens per second</h3>
        <LineChart
          :series="tokenRateSeries.map((s, i) => ({
            ...s,
            color: i === 0 ? 'var(--sb-chart-1)' : 'var(--sb-chart-3)',
          }))"
          :format="(v: number) => v.toLocaleString(undefined, { maximumFractionDigits: 1 })"
        />
      </section>

      <div class="panels" v-if="hasAnyPanel">
        <div class="sb-card" v-if="statusBars.length">
          <h3>Requests by status</h3>
          <MiniBars :items="statusBars" />
        </div>
        <div class="sb-card" v-if="requestsByMethod.length">
          <h3>Requests by method</h3>
          <MiniBars :items="requestsByMethod" />
        </div>
        <div class="sb-card" v-if="errorsByType.length">
          <h3>Errors by type</h3>
          <MiniBars :items="errorsByType" color="var(--sb-err)" />
        </div>
        <div class="sb-card" v-if="cacheResults.length">
          <h3>Cache results</h3>
          <MiniBars :items="cacheResults" />
        </div>
        <div class="sb-card" v-if="authResults.length">
          <h3>Auth results</h3>
          <MiniBars :items="authResults" />
        </div>
        <div class="sb-card" v-if="bytesByDirection.length">
          <h3>Bytes by direction</h3>
          <MiniBars :items="bytesByDirection" :format="formatBytes" />
        </div>
        <div class="sb-card" v-if="tokensByProvider.length">
          <h3>Tokens by provider</h3>
          <MiniBars :items="tokensByProvider" />
        </div>
        <div class="sb-card" v-if="tokensByDirection.length">
          <h3>Tokens by direction</h3>
          <MiniBars :items="tokensByDirection" />
        </div>
        <div class="sb-card" v-if="providerErrors.length">
          <h3>Provider errors <span v-if="selectedOrigin" class="sb-eyebrow">all origins</span></h3>
          <MiniBars :items="providerErrors" color="var(--sb-err)" />
        </div>
        <div class="sb-card" v-if="throughputByModel.length">
          <h3>Token throughput (avg tok/s) <span v-if="selectedOrigin" class="sb-eyebrow">all origins</span></h3>
          <MiniBars :items="throughputByModel" />
        </div>
        <div class="sb-card" v-if="modelHostGauges.length">
          <h3>Model-host gauges <span v-if="selectedOrigin" class="sb-eyebrow">all origins</span></h3>
          <MiniBars :items="modelHostGauges" />
        </div>
      </div>

      <p class="sb-faint" v-if="!hasAnyPanel">
        No labelled series matched the known request, latency, cache, auth,
        token, or model-host families. Use View raw to inspect the full scrape.
      </p>
    </template>
  </template>
</template>

<style scoped>
.filterrow {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.filterrow__select {
  width: auto;
  min-width: 200px;
  font-family: var(--sb-font-mono);
  font-size: 0.78rem;
}
.table-wrap {
  overflow-x: auto;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-5);
}
.raw {
  max-height: 70vh;
}
.plate {
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
  border-top: 2px solid var(--sb-border-ink);
  padding: var(--sb-space-4) var(--sb-space-5) var(--sb-space-5);
  margin-bottom: var(--sb-space-4);
}
.plate__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}
.plate__note {
  color: var(--sb-text-faint);
}
.plate__charts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--sb-space-5);
}
.chart-title {
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: var(--sb-space-2);
}
.pctl {
  display: flex;
  gap: var(--sb-space-2) var(--sb-space-4);
  margin: 0;
  align-items: baseline;
}
.pctl dt {
  color: var(--sb-text-faint);
  font-size: 0.7rem;
}
.pctl dd {
  margin: 0;
  font-variant-numeric: tabular-nums;
  font-weight: 600;
  font-size: 0.85rem;
}
.panels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--sb-space-4);
}
.panels h3 {
  margin-bottom: var(--sb-space-4);
}
.live {
  gap: 6px;
}
.live__dot {
  width: 7px;
  height: 7px;
  border-radius: var(--sb-radius-pill);
  background: var(--sb-text-faint);
}
.live--on .live__dot {
  background: var(--sb-accent);
}
.live--on {
  border-color: var(--sb-accent);
  color: var(--sb-accent-strong);
}
</style>
