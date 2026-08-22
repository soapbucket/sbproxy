<script setup lang="ts">
/**
 * Spend: what the gateway estimates you spent, what it saved you, and
 * how much of the number is measured rather than guessed.
 *
 * Two data sources, and the page never mixes them inside one row:
 *
 *  - `GET /api/usage/spend` is the durable rollup. Everything above the
 *    fold and the whole breakdown come from it, windowed, and survive a
 *    restart. Two calls: the selected window, and the equal-length
 *    window before it, which is what turns a total into a change.
 *  - `GET /metrics` is a process-lifetime scrape. The savings counters,
 *    the trust panel and the scope gauge live there, they reset on
 *    restart, and they cannot be windowed. Every block reading them
 *    says so in its own header rather than leaving the reader to
 *    discover that two numbers on one page count different things.
 *
 * The honesty rule that shapes the tile row: the savings counters are
 * not in the rollup, so a "saved in this window" tile would be a
 * fabrication. Savings gets its own panel with its own stated basis.
 */
import { computed, onMounted, ref, watch } from "vue";
import { api, type SpendWindowResponse } from "../api";
import { useAsync } from "../composables/useAsync";
import {
  findFamily,
  groupByLabels,
  parsePrometheus,
  sumSamples,
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber, formatShare, formatUsd } from "../lib/format";
import { spendGroupOptions } from "../lib/spend-grouping";
import { priceSourceShares } from "../lib/cost-trust";
import {
  SPEND_WINDOWS,
  compareRows,
  costPerMillionTokens,
  cumulative,
  drillDownLink,
  microsToUsd,
  priorWindowRange,
  rebucket,
  rowsByGroup,
  runRate,
  shiftForward,
  spendDelta,
  spendVariance,
  toSeriesPoints,
  tooCoarseForChart,
  topNWithOther,
  unattributedSpend,
  type SpendWindow,
  type TimePoint,
} from "../lib/spend-derive";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import MiniBars from "../components/MiniBars.vue";
import LineChart from "../components/LineChart.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import BudgetHeadroom from "../components/BudgetHeadroom.vue";
import CostTrustPanel from "../components/CostTrustPanel.vue";

const activeWindow = ref<SpendWindow>("24h");
const groupBy = ref<string>("model");
const chartMode = ref<"bucket" | "cumulative">("bucket");

/* ---- loaders ---- */

const metricsReq = useAsync(() => api.metrics());
const history = useAsync(() => api.spendWindow(activeWindow.value, groupBy.value));
// Computed at fetch time rather than held in a ref: the window is
// rolling, so a range captured on mount would drift further from "the
// period before this one" with every minute the page stays open.
const prior = useAsync(() => {
  const range = priorWindowRange(activeWindow.value, Date.now() / 1000);
  return api.spendRange(range.from, range.to, groupBy.value);
});

const budgets = ref<InstanceType<typeof BudgetHeadroom> | null>(null);

function loadAll() {
  void metricsReq.run();
  void history.run();
  void prior.run();
  budgets.value?.refresh();
}

onMounted(() => {
  void metricsReq.run();
  void history.run();
  void prior.run();
});
watch([activeWindow, groupBy], () => {
  void history.run();
  void prior.run();
});

/* ---- rollup: this window and the one before it ---- */

const families = computed<MetricFamily[]>(() => {
  const text = metricsReq.data.value;
  return text ? parsePrometheus(text) : [];
});

const windowData = computed<SpendWindowResponse | null>(() => history.data.value);
const priorData = computed<SpendWindowResponse | null>(() => prior.data.value);

const groupOptions = computed(() => {
  const keys = windowData.value?.property_keys ?? [];
  const propertyQueryUnavailable =
    history.error.value?.status === 400 && groupBy.value.startsWith("property:");
  return spendGroupOptions(
    propertyQueryUnavailable
      ? keys.filter((key) => `property:${key}` !== groupBy.value)
      : keys,
    groupBy.value,
  );
});
const selectedOption = computed(() =>
  groupOptions.value.find((option) => option.value === groupBy.value),
);
const dimensionLabel = computed(() => selectedOption.value?.label ?? "Group");
// `group_by=total` writes an empty group key for every row by
// construction, so "unattributed" and "coverage" mean nothing there.
const attributionApplies = computed(() => groupBy.value !== "total");

// A 503 means rollups are switched off. That is a configuration fact,
// not a failure, and it reads as a hint rather than an error panel.
const rollupsDisabled = computed(() => {
  const e = history.error.value;
  if (!e) return false;
  return `${e.message} ${e.body}`.includes("not enabled");
});

const rows = computed(() =>
  windowData.value ? rowsByGroup(windowData.value.buckets) : [],
);
const priorRows = computed(() =>
  priorData.value ? rowsByGroup(priorData.value.buckets) : [],
);
const hasHistory = computed(() => rows.value.length > 0);

const totalUsd = computed(() =>
  microsToUsd(windowData.value?.totals.cost_usd_micros ?? 0),
);
const priorTotalUsd = computed(() =>
  microsToUsd(priorData.value?.totals.cost_usd_micros ?? 0),
);
// The prior window is a second request. Until it lands, the page shows
// the total without a comparison rather than a comparison against zero.
// It can also fail on its own: `group_by=property:<key>` is a 400 when
// the earlier range holds no row carrying that key. Every comparison on
// the page is gated on this, because an absent prior window and a prior
// window in which nothing ran produce the same empty list, and treating
// them alike labels every row `new`.
const priorLoaded = computed(() => priorData.value !== null);
const priorFailed = computed(
  () => priorData.value === null && prior.error.value !== null,
);
const delta = computed(() => spendDelta(totalUsd.value, priorTotalUsd.value));

const rate = computed(() =>
  windowData.value
    ? runRate(windowData.value, activeWindow.value, Date.now() / 1000)
    : undefined,
);

const unattributed = computed(() =>
  windowData.value ? unattributedSpend(windowData.value) : undefined,
);
const attributedShare = computed(() => {
  const share = unattributed.value?.share;
  return share === undefined ? undefined : 1 - share;
});

const unitCost = computed(() => {
  const totals = windowData.value?.totals;
  if (!totals) return undefined;
  return costPerMillionTokens(totalUsd.value, totals.tokens_in, totals.tokens_out);
});

/* ---- the honesty line ---- */

const priceSources = computed(() =>
  priceSourceShares(findFamily(families.value, "sbproxy_ai_price_source_total")),
);
// A scrape that has not landed yet is not the same claim as a build
// that does not report provenance. `loading` only covers a first load
// already in flight, and the first paint happens before `onMounted`
// fires, so the presence of data is what separates the two.
const scrapeLoaded = computed(() => metricsReq.data.value !== null);
const priceSourceSentence = computed(() => {
  if (metricsReq.error.value) {
    return "Price provenance is unavailable while /metrics cannot be read.";
  }
  if (!scrapeLoaded.value) return "Reading price provenance.";
  const reading = priceSources.value;
  if (!reading) return "Price provenance is not reported by this build.";
  if (reading.total === 0) return "No price has been looked up yet.";
  const share = (source: string) =>
    reading.shares.find((s) => s.source === source)?.share ?? 0;
  // Rounded to a whole percent, a real fallback share of 0.4% would
  // print "0%" on the one line whose job is to say some of these
  // dollars were invented. `formatShare` prints "<1%" instead.
  return (
    `${formatShare(share("catalog"))} of price lookups used the shipped ` +
    `catalog. ${formatShare(share("fallback"))} fell back to the flat rate.`
  );
});
const coverageSentence = computed(() => {
  if (!attributionApplies.value) {
    return "Grouped by total, so no dimension is being attributed.";
  }
  const share = attributedShare.value;
  if (share === undefined) return "No spend in this window to attribute.";
  return `${formatShare(share)} of spend in this window carries a ${dimensionLabel.value.toLowerCase()}.`;
});

/* ---- the chart ---- */

const noChartReason = computed(() => {
  const res = windowData.value;
  if (!res) return undefined;
  return tooCoarseForChart(activeWindow.value, res.bucket_secs)
    ? "Hourly is the finest rollup bucket, so a one hour window is a single point. Use 24 hours for a trend."
    : undefined;
});

/**
 * The width both series are folded to.
 *
 * The store answers in hourly buckets inside its hourly retention and
 * daily ones outside it, so a 7d window can come back hourly while the
 * 7d before it comes back daily. Folding each series to the width its
 * own response suggests puts daily sums against six-hourly sums on one
 * y-axis, and the previous period draws four times higher than it was.
 * Both series fold to the wider of the two.
 */
const commonFoldSecs = computed(() => {
  const current = windowData.value;
  if (!current) return 0;
  const mine = rebucket(current.buckets, current.bucket_secs).foldedSecs;
  const res = priorData.value;
  if (!res) return mine;
  return Math.max(mine, rebucket(res.buckets, res.bucket_secs).foldedSecs);
});

const folded = computed(() => {
  const res = windowData.value;
  return res
    ? rebucket(res.buckets, res.bucket_secs, 40, commonFoldSecs.value)
    : undefined;
});
const currentPoints = computed(() => folded.value?.points ?? []);

/**
 * X-axis labels at the width the points actually cover.
 *
 * The chart's default tick is a wall clock, which is correct for a live
 * scrape and useless for daily folds: thirty daily points would print
 * "00:00:00" three times.
 */
function chartTick(t: number): string {
  const d = new Date(t);
  const day = `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const hour = `${String(d.getHours()).padStart(2, "0")}:00`;
  const width = folded.value?.foldedSecs ?? 3600;
  if (width >= 86_400) return day;
  return activeWindow.value === "24h" ? hour : `${day} ${hour}`;
}
const priorPoints = computed(() => {
  const res = priorData.value;
  if (!res) return [];
  // Shifted forward one window length so both series share an x-axis.
  return shiftForward(
    rebucket(res.buckets, res.bucket_secs, 40, commonFoldSecs.value).points,
    activeWindow.value,
  );
});

const series = computed(() => {
  const shape = (points: TimePoint[]) =>
    toSeriesPoints(chartMode.value === "cumulative" ? cumulative(points) : points);
  const out = [
    {
      name: `this ${activeWindow.value}`,
      points: shape(currentPoints.value),
      color: "var(--sb-chart-1)",
    },
  ];
  // No second series until the second call answers. An empty series
  // still draws its legend entry, and a named line with nothing under it
  // reads as a period that cost nothing.
  if (priorLoaded.value) {
    out.push({
      name: `previous ${activeWindow.value}`,
      points: shape(priorPoints.value),
      color: "var(--sb-chart-2)",
    });
  }
  return out;
});

/* ---- where it went ---- */

const comparedRows = computed(() =>
  compareRows(rows.value, priorRows.value, totalUsd.value, priorLoaded.value),
);
const barItems = computed(() => topNWithOther(rows.value, 8));

const variance = computed(() => {
  const now = windowData.value?.totals;
  const before = priorData.value?.totals;
  if (!now || !before) return undefined;
  return spendVariance(
    totalUsd.value,
    now.tokens_in + now.tokens_out,
    priorTotalUsd.value,
    before.tokens_in + before.tokens_out,
  );
});
const varianceSentence = computed(() => {
  const v = variance.value;
  if (!v || v.total === 0) return undefined;
  const direction = v.total > 0 ? "rose" : "fell";
  const volumeClause =
    v.volume >= 0
      ? `${formatUsd(v.volume)} from more tokens`
      : `${formatUsd(-v.volume)} back from fewer tokens`;
  const mixClause =
    v.mix >= 0
      ? `${formatUsd(v.mix)} from a shift toward more expensive models`
      : `${formatUsd(-v.mix)} back from a shift toward cheaper models`;
  return `Spend ${direction} ${formatUsd(Math.abs(v.total))}: ${volumeClause}, ${mixClause}.`;
});

function groupLabel(group: string): string {
  return group === "" ? "(unattributed)" : group;
}
function rowLink(group: string): string | undefined {
  return drillDownLink(groupBy.value, group);
}

/* ---- what it saved ----
 *
 * All process-lifetime counters. Each row renders on the family being
 * present, never on its value being above zero, because
 * `sumSamples(undefined)` is 0 and an unconfigured cache would
 * otherwise render an authoritative "$0.00 saved".
 */

const cacheSavedFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_cost_saved_micros_total"),
);
const cacheTokensFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_tokens_saved_total"),
);
const cacheResultsFamily = computed(() =>
  findFamily(families.value, "sbproxy_semantic_cache_results_total"),
);
const compressionSavedFamily = computed(() =>
  findFamily(
    families.value,
    "sbproxy_ai_compression_value_cost_saved_micros_total",
  ),
);
const compressionTokensFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_compression_value_tokens_saved_total"),
);
const attributedRequestsFamily = computed(() =>
  findFamily(families.value, "sbproxy_ai_requests_attributed_total"),
);

const cacheSavedUsd = computed(() =>
  cacheSavedFamily.value
    ? microsToUsd(sumSamples(cacheSavedFamily.value))
    : undefined,
);
const cachePromptTokens = computed(() =>
  cacheTokensFamily.value
    ? sumSamples(cacheTokensFamily.value, { kind: "prompt" })
    : undefined,
);
const cacheCompletionTokens = computed(() =>
  cacheTokensFamily.value
    ? sumSamples(cacheTokensFamily.value, { kind: "completion" })
    : undefined,
);
const cacheHitRate = computed(() => {
  const family = cacheResultsFamily.value;
  if (!family) return undefined;
  const total = sumSamples(family);
  if (total <= 0) return undefined;
  return sumSamples(family, { result: "hit" }) / total;
});

const compressionSavedUsd = computed(() =>
  compressionSavedFamily.value
    ? microsToUsd(sumSamples(compressionSavedFamily.value))
    : undefined,
);
// `lever` names which compression stage saved the money and
// `token_count_precision` says whether the saving was counted exactly or
// approximated. Keeping precision visible is the point: the two are not
// the same claim.
const compressionByLever = computed(() =>
  groupByLabels(compressionSavedFamily.value, [
    "lever",
    "token_count_precision",
  ]).map((row) => ({ key: row.key, value: microsToUsd(row.value) })),
);
const compressionTokens = computed(() =>
  compressionTokensFamily.value
    ? sumSamples(compressionTokensFamily.value)
    : undefined,
);

// Refusals ride the attributed request counter, which every AI request
// writes. A zero here is a real zero, not an absent family, which is why
// this row shows a count rather than "not reported".
const refusalOutcomes = computed(() => {
  const family = attributedRequestsFamily.value;
  if (!family) return undefined;
  const outcomes = ["budget_exceeded", "price_ceiling_block"];
  const rows = outcomes.map((outcome) => ({
    outcome,
    count: sumSamples(family, { outcome }),
  }));
  return { rows, total: rows.reduce((sum, row) => sum + row.count, 0) };
});

const hasSavingsPanel = computed(
  () =>
    cacheSavedFamily.value !== undefined ||
    compressionSavedFamily.value !== undefined ||
    refusalOutcomes.value !== undefined,
);

/* ---- budget headroom input ---- */

// The rollup only knows spend per key when the page is grouped by key.
// Passing it only then keeps the ordering claim in BudgetHeadroom true.
const spendByKey = computed(() => {
  if (groupBy.value !== "api_key") return undefined;
  const out: Record<string, number> = {};
  for (const row of rows.value) {
    if (row.group !== "") out[row.group] = row.costUsd;
  }
  return out;
});

</script>

<template>
  <PageHeader
    title="Spend"
    subtitle="What the gateway estimates you spent, what it saved you, and how much of the number is measured rather than guessed."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="loadAll">Refresh</button>
    </template>
  </PageHeader>

  <section class="controls">
    <div class="segmented" role="group" aria-label="Time range">
      <button
        v-for="w in SPEND_WINDOWS"
        :key="w"
        :class="{ active: activeWindow === w }"
        @click="activeWindow = w"
      >
        {{ w }}
      </button>
    </div>
    <label class="group-by">
      <span class="sb-faint">Group by</span>
      <select v-model="groupBy" aria-label="Group by">
        <option v-for="g in groupOptions" :key="g.value" :value="g.value">
          {{ g.label }}
        </option>
      </select>
    </label>
  </section>

  <p class="honesty">{{ priceSourceSentence }} {{ coverageSentence }}</p>

  <p v-if="selectedOption?.unavailable" class="hint">
    This promoted property has no rollup data in the selected window. The
    selection is preserved so the query remains explicit.
  </p>

  <p v-if="rollupsDisabled" class="hint">
    Usage rollups are not enabled, so windowed spend is unavailable. Enable
    proxy.observability.usage_rollups (on by default) and make sure its path
    is writable.
  </p>
  <ErrorState
    v-else-if="history.error.value"
    :error="history.error.value"
    @retry="history.run"
  />
  <EmptyState
    v-else-if="!history.loading.value && !hasHistory"
    message="No spend recorded in this window. Rows appear as AI requests flow, and the rollup survives a restart."
  />
  <template v-else-if="hasHistory">
    <div class="tiles">
      <StatCard
        :label="`Spend, ${activeWindow}`"
        :value="formatUsd(totalUsd)"
        tone="accent"
        :sub="
          priorFailed
            ? `the previous ${activeWindow} could not be read`
            : !priorLoaded
              ? 'comparing with the previous period'
              : delta.ratio === undefined
                ? `nothing recorded in the previous ${activeWindow}`
                : `${formatUsd(priorTotalUsd)} in the previous ${activeWindow}, ${delta.absolute >= 0 ? '+' : ''}${formatShare(delta.ratio)}`
        "
      />
      <StatCard
        label="Run rate"
        :value="rate ? `${formatUsd(rate.perDay)} / day` : 'n/a'"
        :sub="
          rate
            ? `from the last ${Math.round(rate.basisSecs / 3600)}h; ${formatUsd(rate.overWindow)} over ${activeWindow} if it holds`
            : 'needs at least three complete buckets covering six hours'
        "
      />
      <StatCard
        label="Unattributed"
        :value="
          !attributionApplies || !unattributed ? 'n/a' : formatUsd(unattributed.usd)
        "
        :sub="
          !attributionApplies
            ? 'group by a dimension to see what it cannot name'
            : unattributed?.share === undefined
              ? 'no spend in this window'
              : `${formatShare(unattributed.share)} of window spend has no ${dimensionLabel.toLowerCase()}`
        "
      />
      <StatCard
        label="Per 1M tokens"
        :value="unitCost === undefined ? 'n/a' : formatUsd(unitCost)"
        :sub="
          unitCost === undefined
            ? 'no tokens recorded in this window'
            : 'input and output, blended'
        "
      />
    </div>

    <section class="chart-block">
      <div class="chart-head">
        <div class="segmented" role="group" aria-label="Chart mode">
          <button
            :class="{ active: chartMode === 'bucket' }"
            @click="chartMode = 'bucket'"
          >
            Per bucket
          </button>
          <button
            :class="{ active: chartMode === 'cumulative' }"
            @click="chartMode = 'cumulative'"
          >
            Cumulative
          </button>
        </div>
      </div>
      <p v-if="noChartReason" class="hint">{{ noChartReason }}</p>
      <LineChart
        v-else
        :series="series"
        :format="formatUsd"
        :x-format="chartTick"
        :height="200"
      />
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Where it went</h2>
        <RouterLink class="panel-link" to="/reports?group_by=model,api_key_id">
          Break down by two dimensions
        </RouterLink>
      </div>

      <p v-if="varianceSentence" class="hint">{{ varianceSentence }}</p>
      <p v-if="priorFailed" class="hint">
        The previous {{ activeWindow }} could not be read, so no row carries a
        delta and none is marked new or gone. Everything else on this page is
        the selected window and is unaffected.
      </p>
      <p
        v-if="attributionApplies && unattributed && unattributed.usd > 0"
        class="hint"
      >
        {{ formatUsd(unattributed.usd) }} of {{ formatUsd(unattributed.totalUsd) }}
        ({{ formatShare(unattributed.share) }}) carries no
        {{ dimensionLabel.toLowerCase() }}.
      </p>

      <!-- The bars are deliberately unlinked. `linkFor` applies to every
           label in the chart, and this one carries an Other row and an
           unattributed row that nothing can filter on, so linking here
           would render exactly the dead label MiniBars warns against.
           The table below links per row instead. -->
      <MiniBars :items="barItems" :format="formatUsd" />

      <div class="sb-table-wrap">
        <table class="sb-table breakdown">
          <thead>
            <tr>
              <th>{{ dimensionLabel }}</th>
              <th>Spend</th>
              <th>Share</th>
              <th>vs prev</th>
              <th>Requests</th>
              <th>Tokens in</th>
              <th>Tokens out</th>
              <th>$/1M tok</th>
              <th>Blocked</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in comparedRows" :key="row.group">
              <td>
                <RouterLink v-if="rowLink(row.group)" :to="rowLink(row.group)!">
                  {{ groupLabel(row.group) }}
                </RouterLink>
                <span v-else class="sb-mono">{{ groupLabel(row.group) }}</span>
                <span v-if="row.presence === 'new'" class="tag sb-faint">new</span>
                <span v-if="row.presence === 'gone'" class="tag sb-faint">gone</span>
                <!-- Only once the comparison is known to have failed. In
                     flight is the ordinary state on every load and does
                     not deserve a tag on every row. -->
                <span
                  v-if="row.presence === 'unknown' && priorFailed"
                  class="tag sb-faint"
                >
                  no comparison
                </span>
              </td>
              <td>{{ formatUsd(row.costUsd) }}</td>
              <td>{{ formatShare(row.share, 1) }}</td>
              <td>
                {{
                  row.vsPrior === undefined
                    ? "n/a"
                    : `${row.vsPrior >= 0 ? "+" : "-"}${formatUsd(Math.abs(row.vsPrior))}`
                }}
              </td>
              <td>{{ formatNumber(row.requests) }}</td>
              <td>{{ formatNumber(row.tokensIn) }}</td>
              <td>{{ formatNumber(row.tokensOut) }}</td>
              <td>
                {{
                  row.perMillionTokens === undefined
                    ? "n/a"
                    : formatUsd(row.perMillionTokens)
                }}
              </td>
              <td>{{ formatNumber(row.blocked) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="hint">
        Totals here come from the durable rollup. Following a row opens the
        request list, which holds the last requests on this instance and
        clears on restart. It is a recent sample, not the whole window.
      </p>
    </section>
  </template>

  <section class="panel" v-if="hasSavingsPanel">
    <h2>What it saved</h2>
    <p class="hint">
      Savings counters are process-lifetime and are not in the durable rollup,
      so these are totals since this instance started and do not follow the
      window above.
    </p>

    <div class="saving" v-if="cacheSavedUsd !== undefined">
      <div class="saving__head">
        <span class="saving__name">Semantic cache</span>
        <span class="saving__val">{{ formatUsd(cacheSavedUsd) }}</span>
      </div>
      <p class="hint">
        {{
          cachePromptTokens === undefined
            ? "Tokens saved are not reported."
            : `${formatNumber(cachePromptTokens)} prompt tokens and ${formatNumber(cacheCompletionTokens ?? 0)} completion tokens avoided.`
        }}
        {{
          cacheHitRate === undefined
            ? "Hit rate is not reported."
            : `${formatShare(cacheHitRate)} of cache lookups hit.`
        }}
      </p>
      <p class="hint">
        Priced from the cached response's own usage block. A cached response
        with no usage block counts as a hit and contributes zero dollars, so
        this under-reports relative to the hit rate.
      </p>
    </div>

    <div class="saving" v-if="compressionSavedUsd !== undefined">
      <div class="saving__head">
        <span class="saving__name">Context compression</span>
        <span class="saving__val">{{ formatUsd(compressionSavedUsd) }}</span>
      </div>
      <MiniBars
        v-if="compressionByLever.length"
        :items="compressionByLever"
        :format="formatUsd"
      />
      <p class="hint">
        {{
          compressionTokens === undefined
            ? "Tokens saved are not reported."
            : `${formatNumber(compressionTokens)} input tokens avoided.`
        }}
        Each bar is a lever and how its tokens were counted: exact means the
        tokenizer counted them, approximate means they were estimated.
      </p>
    </div>

    <div class="saving" v-if="refusalOutcomes">
      <div class="saving__head">
        <span class="saving__name">Refused before dispatch</span>
        <span class="saving__val">
          {{ formatNumber(refusalOutcomes.total) }} requests
        </span>
      </div>
      <p class="hint">
        <span v-for="row in refusalOutcomes.rows" :key="row.outcome" class="pair">
          {{ row.outcome }} {{ formatNumber(row.count) }}
        </span>
      </p>
      <p class="hint">
        The dollars these avoided are not measured. Nothing accumulates the
        price of a request that never went out, and multiplying the count by
        an average price would print a plausible number rather than a
        measured one.
      </p>
    </div>
  </section>

  <ErrorState
    v-if="metricsReq.error.value"
    :error="metricsReq.error.value"
    title="Could not read /metrics"
    @retry="metricsReq.run"
  />
  <template v-else>
    <BudgetHeadroom
      ref="budgets"
      :families="families"
      :spend-by-key="spendByKey"
      :scrape-loaded="scrapeLoaded"
    />
    <CostTrustPanel
      :families="families"
      :attributed-share="attributedShare"
      :dimension-label="dimensionLabel"
      :attribution-applies="attributionApplies"
      :scrape-loaded="scrapeLoaded"
    />
  </template>
</template>

<style scoped>
.controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.group-by {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}
.honesty {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 0 0 16px;
  max-width: 80ch;
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.chart-block {
  margin-bottom: 24px;
}
.chart-head {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 6px;
}
.panel {
  margin-bottom: 24px;
}
.panel h2,
.panel-head h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 8px;
}
.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.panel-link {
  font-size: 12px;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 8px;
  max-width: 80ch;
}
.breakdown {
  margin-top: 12px;
  min-width: 860px;
}
.breakdown td {
  font-variant-numeric: tabular-nums;
}
.tag {
  margin-left: 6px;
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.saving {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid var(--sb-border);
}
.saving__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  font-size: 0.85rem;
}
.saving__name {
  font-weight: 600;
}
.saving__val {
  font-variant-numeric: tabular-nums;
}
.pair + .pair::before {
  content: ", ";
}
.segmented {
  display: inline-flex;
  border: 1px solid var(--sb-border);
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
.group-by select {
  font: inherit;
  font-size: 12px;
  padding: 4px 8px;
  border: 1px solid var(--sb-border);
  background: transparent;
  color: var(--sb-text);
}
</style>
