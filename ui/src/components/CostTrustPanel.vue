<script setup lang="ts">
/**
 * How much to trust the spend number.
 *
 * Four readouts over families that appear in no dashboard, no alert
 * rule, and no console view today. Nobody in the AI gateway cohort
 * ships price provenance at all, which is the reason this panel exists
 * and also the reason its copy has to be exact: a guard narrower than
 * its claim is worse than no guard.
 *
 * Every family here only starts existing once a specific feature is
 * configured, and `sumSamples(undefined)` returns 0, so each block
 * branches on whether the family was found before it reads a value.
 * "Not reported" and "reported zero" are different sentences.
 */
import { computed } from "vue";
import { formatNumber, formatShare, formatUsd } from "../lib/format";
import {
  estimateErrorByModel,
  priceCeilingOutcomes,
  priceSourceShares,
} from "../lib/cost-trust";
import { findFamily, sumSamples, type MetricFamily } from "../lib/metrics";

const props = defineProps<{
  /** Parsed `/metrics` families, scraped once by the page. */
  families: MetricFamily[];
  /**
   * Share of this window's rollup spend that carries a value for the
   * dimension the page is grouped by. Computed from the rollup, not from
   * a metric, so it moves when the group-by moves.
   */
  attributedShare?: number;
  /** The dimension that share is about, named for a reader. */
  dimensionLabel: string;
  /** False for `group_by=total`, where every row is unattributed by
   *  construction and the coverage question does not apply. */
  attributionApplies: boolean;
  /**
   * Whether the first `/metrics` scrape has landed.
   *
   * Every readout here says "not reported" when its family is missing,
   * and an unfetched scrape has no families at all. Without this the
   * panel opens by asserting that price provenance, the ceiling counter
   * and the estimator are all unconfigured, which is four wrong claims
   * about the deployment before a single byte has been read.
   */
  scrapeLoaded: boolean;
}>();

/* --- Price provenance --- */

const priceSourceFamily = computed(() =>
  findFamily(props.families, "sbproxy_ai_price_source_total"),
);
const priceSources = computed(() => priceSourceShares(priceSourceFamily.value));

/** Fallback wears the warning color: a rising share of it is the signal. */
const SOURCE_COLORS: Record<string, string> = {
  catalog: "var(--sb-chart-1)",
  rate_card: "var(--sb-chart-3)",
  config: "var(--sb-chart-5)",
  fallback: "var(--sb-warn)",
};
function sourceColor(source: string): string {
  return SOURCE_COLORS[source] ?? "var(--sb-chart-2)";
}

/* --- Price ceiling --- */

const ceilingFamily = computed(() =>
  findFamily(props.families, "sbproxy_ai_price_ceiling_total"),
);
const ceilingOutcomes = computed(() => priceCeilingOutcomes(ceilingFamily.value));

/* --- Estimator accuracy --- */

const estimateFamily = computed(() =>
  findFamily(props.families, "sbproxy_ai_token_estimate_error_ratio"),
);
const estimateRows = computed(() => estimateErrorByModel(estimateFamily.value));

function signedPercent(v: number): string {
  return `${v >= 0 ? "+" : ""}${(v * 100).toFixed(1)}%`;
}

/* --- The gateway's own spend --- */

// The compression summarizer bills onto the attributed counter under
// surface="compression_summary". It writes no rollup event and debits no
// budget, so this money is real, is not caller traffic, and is not in
// the windowed history above. Saying so beats having a buyer find it.
const attributedCostFamily = computed(() =>
  findFamily(props.families, "sbproxy_ai_cost_dollars_attributed_total"),
);
const gatewayOwnSpend = computed(() => {
  const family = attributedCostFamily.value;
  if (!family) return undefined;
  return sumSamples(family, { surface: "compression_summary" });
});
</script>

<template>
  <section class="panel">
    <h2>How much to trust this</h2>

    <h3>Price provenance</h3>
    <p v-if="!scrapeLoaded" class="hint sb-faint">Reading /metrics.</p>
    <p v-else-if="priceSources === undefined" class="hint sb-faint">
      Price provenance is not reported by this build.
    </p>
    <p v-else-if="priceSources.total === 0" class="hint sb-faint">
      No price has been looked up yet, so there is nothing to attribute.
    </p>
    <template v-else>
      <div class="share">
        <div
          v-for="share in priceSources.shares"
          :key="share.source"
          class="share__seg"
          :style="{
            width: `${(share.share ?? 0) * 100}%`,
            background: sourceColor(share.source),
          }"
          :title="`${share.label}: ${formatNumber(share.count)} lookups`"
        />
      </div>
      <ul class="legend">
        <li v-for="share in priceSources.shares" :key="share.source">
          <span class="legend__swatch" :style="{ background: sourceColor(share.source) }" />
          <span class="legend__name">{{ share.label }}</span>
          <span class="legend__val sb-mono">
            {{ formatShare(share.share, 1) }}
          </span>
        </li>
      </ul>
      <p class="hint">
        Counted per price lookup, not per request, and the family carries no
        model label. A rising fallback share says price estimates are being
        invented, and cannot say which model caused it. Fallback is the
        pessimistic default of $5 per million tokens in and $5 per million
        out, which usually sits above a real price, so a rising fallback
        share normally overstates spend and can trip budget caps and the
        price ceiling early.
      </p>
    </template>

    <h3>Attribution coverage</h3>
    <p v-if="!attributionApplies" class="hint sb-faint">
      The window is grouped by total, so every row is one bucket and there
      is no dimension to attribute against. Pick a dimension above.
    </p>
    <p v-else-if="attributedShare === undefined" class="hint sb-faint">
      No spend in this window, so there is no coverage to report.
    </p>
    <p v-else class="hint">
      {{ formatShare(attributedShare) }} of spend in this window carries a
      {{ dimensionLabel.toLowerCase() }}. This is computed from
      the durable rollup and changes with the dimension you group by.
    </p>

    <h3>Price ceiling activity</h3>
    <p v-if="!scrapeLoaded" class="hint sb-faint">Reading /metrics.</p>
    <p v-else-if="ceilingOutcomes === undefined" class="hint sb-faint">
      The price ceiling is not reported. The counter appears once a request
      carries an x-sbproxy-max-price header or an origin sets a ceiling.
    </p>
    <ul v-else-if="ceilingOutcomes" class="outcomes">
      <li v-for="row in ceilingOutcomes" :key="row.outcome">
        <div class="outcomes__head">
          <span class="outcomes__label">{{ row.label }}</span>
          <RouterLink v-if="row.link && row.count > 0" :to="row.link" class="outcomes__val sb-mono">
            {{ formatNumber(row.count) }}
          </RouterLink>
          <span v-else class="outcomes__val sb-mono">{{ formatNumber(row.count) }}</span>
        </div>
        <p class="hint">{{ row.note }}</p>
      </li>
    </ul>
    <p v-if="scrapeLoaded && ceilingOutcomes" class="hint">
      Steady exclusions with no refusals is the healthy shape.
    </p>

    <h3>Estimator accuracy</h3>
    <p v-if="!scrapeLoaded" class="hint sb-faint">Reading /metrics.</p>
    <p
      v-else-if="estimateRows === undefined || !estimateRows.length"
      class="hint sb-faint"
    >
      Estimator accuracy is only measured for models that have a per-model
      rate limit configured. None are configured here, so the estimator that
      drives budget debits and the price ceiling is running unmeasured.
    </p>
    <table v-else-if="estimateRows && estimateRows.length" class="detail">
      <thead>
        <tr>
          <th>Model</th>
          <th>Reserved too much (p05)</th>
          <th>Typical (p50)</th>
          <th>Reserved too little (p95)</th>
          <th>Reconciled requests</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in estimateRows" :key="row.model">
          <td class="sb-mono">{{ row.model }}</td>
          <td>{{ signedPercent(row.p05) }}</td>
          <td>{{ signedPercent(row.p50) }}</td>
          <td>{{ signedPercent(row.p95) }}</td>
          <td>{{ formatNumber(row.samples) }}</td>
        </tr>
      </tbody>
    </table>
    <p v-if="scrapeLoaded && estimateRows && estimateRows.length" class="hint">
      Measured against the upstream prompt token count on a reconciled
      admission, as (actual - estimated) / actual. Positive means the
      estimator reserved too little and a budget can overshoot; negative
      means it reserved too much and held rate-limit headroom the request
      never used. The histogram's buckets cut at plus and minus 10%, so
      that is the band worth watching.
    </p>

    <template v-if="gatewayOwnSpend !== undefined && gatewayOwnSpend > 0">
      <h3>The gateway's own spend</h3>
      <p class="hint">
        {{ formatUsd(gatewayOwnSpend) }} of attributed spend since start came
        from the gateway's own summarizer, not from caller traffic. It debits
        no budget and is not in the windowed history above.
      </p>
    </template>
  </section>
</template>

<style scoped>
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
.panel h3 {
  font-size: 13px;
  font-weight: 600;
  color: var(--sb-text);
  margin: 20px 0 6px;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 0;
  max-width: 72ch;
}
.share {
  display: flex;
  height: 10px;
  background: var(--sb-bg-sunken);
  margin: 6px 0 8px;
}
.share__seg {
  height: 100%;
}
.legend {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 6px 20px;
}
.legend li {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.74rem;
  color: var(--sb-text-muted);
}
.legend__swatch {
  width: 10px;
  height: 10px;
}
.legend__val {
  color: var(--sb-text);
  font-variant-numeric: tabular-nums;
}
.outcomes {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px 24px;
}
.outcomes__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  font-size: 0.8rem;
  border-bottom: 1px solid var(--sb-border);
  padding-bottom: 3px;
}
.outcomes__label {
  color: var(--sb-text);
}
.outcomes__val {
  font-variant-numeric: tabular-nums;
}
.detail {
  width: 100%;
  border-collapse: collapse;
  margin-top: 8px;
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
