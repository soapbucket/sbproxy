/**
 * Pure derivations behind the Spend view.
 *
 * Everything here runs over `GET /api/usage/spend` responses: the durable
 * rollups, which survive a restart. Nothing in this file reads a
 * Prometheus counter, and nothing in it invents a number the rollup does
 * not carry.
 *
 * Two rules hold throughout:
 *
 *  - A ratio whose denominator is zero is `undefined`, never `0`. A run
 *    rate with too little basis is `undefined`, never a smaller number.
 *    The view renders those as "not reported" or suppresses the claim;
 *    it never prints a confident zero over an absent measurement.
 *  - A group key of `""` means the rollup recorded the row with no value
 *    for the selected dimension. That is the unattributed segment, and
 *    it is a fact worth a headline rather than a footnote. The one
 *    exception is `group_by=total`, where the server writes `""` for
 *    every row by construction (`usage_rollup.rs`, `GroupBy::Total =>
 *    String::new()`), so "unattributed" is meaningless there and the
 *    caller must not ask.
 */
import type { SpendWindowBucket, SpendWindowResponse } from "../api";

export const SPEND_WINDOWS = ["1h", "24h", "7d", "30d"] as const;
export type SpendWindow = (typeof SPEND_WINDOWS)[number];

/** Window lengths in seconds, matching `parse_spend_window` server-side. */
export const WINDOW_SECS: Record<SpendWindow, number> = {
  "1h": 3_600,
  "24h": 86_400,
  "7d": 604_800,
  "30d": 2_592_000,
};

const HOUR_SECS = 3_600;
const DAY_SECS = 86_400;

/** Micro-USD to USD. The rollup stores cost as an integer micro-dollar. */
export function microsToUsd(micros: number): number {
  return micros / 1_000_000;
}

/* -------------------------------------------------------------------- */
/* The prior equal-length window                                         */
/* -------------------------------------------------------------------- */

export interface SpendRange {
  /** Unix seconds, inclusive lower bound. */
  from: number;
  /** Unix seconds, exclusive upper bound. */
  to: number;
}

/**
 * The equal-length window immediately before the selected one.
 *
 * The server takes `from`/`to` as Unix seconds and requires `from < to`,
 * so both are integers here. The comparison is "the same amount of time,
 * immediately before", not "the same calendar period": the selected
 * window is rolling, so a calendar comparison would compare unequal
 * amounts of traffic.
 */
export function priorWindowRange(
  window: SpendWindow,
  nowSecs: number,
): SpendRange {
  const span = WINDOW_SECS[window];
  const to = Math.floor(nowSecs) - span;
  return { from: to - span, to };
}

export interface SpendDelta {
  /** Now minus prior, in the same unit as the inputs. */
  absolute: number;
  /**
   * Fraction of the prior value, e.g. 0.18 for +18%. `undefined` when
   * the prior window is zero: there is no percentage change from nothing,
   * and rendering "+Infinity%" or "+100%" would both be inventions.
   */
  ratio: number | undefined;
}

export function spendDelta(now: number, prior: number): SpendDelta {
  return {
    absolute: now - prior,
    ratio: prior > 0 ? (now - prior) / prior : undefined,
  };
}

/* -------------------------------------------------------------------- */
/* Run rate                                                              */
/* -------------------------------------------------------------------- */

export interface RunRate {
  /** Dollars per day, extrapolated from the basis period. */
  perDay: number;
  /** How much wall-clock time the extrapolation is based on, in seconds. */
  basisSecs: number;
  /** What that rate comes to over the selected window, if it holds. */
  overWindow: number;
}

/**
 * Dollars per day from the most recent complete rollup buckets.
 *
 * Not a forecast, and the view must never label it one. There is no
 * seasonal model here: the bill arrives late but the meter is on the
 * request path, so the rate we measured over the last few hours is a
 * measurement, and extrapolating it is arithmetic the reader can check.
 *
 * Absent buckets count as zero spend, because the rollup only writes a
 * bucket when traffic happened. Averaging over present buckets instead
 * would overstate the rate on bursty traffic by exactly the idle time.
 *
 * `undefined` when fewer than three complete buckets fit the basis: an
 * extrapolation from one or two points is noise wearing a dollar sign.
 */
export function runRate(
  response: SpendWindowResponse,
  window: SpendWindow,
  nowSecs: number,
): RunRate | undefined {
  const bucketSecs = response.bucket_secs;
  if (!Number.isFinite(bucketSecs) || bucketSecs <= 0) return undefined;
  // Six hours of basis, or three buckets, whichever is longer.
  const basisSecs = Math.max(6 * HOUR_SECS, bucketSecs * 3);
  if (basisSecs / bucketSecs < 3) return undefined;
  // The last bucket boundary that has fully elapsed.
  const end = Math.floor(nowSecs / bucketSecs) * bucketSecs;
  const start = end - basisSecs;
  if (start < response.from) return undefined;

  let micros = 0;
  for (const bucket of response.buckets) {
    if (bucket.ts_secs >= start && bucket.ts_secs < end) {
      micros += bucket.cost_usd_micros;
    }
  }
  const perDay = (microsToUsd(micros) / basisSecs) * DAY_SECS;
  return {
    perDay,
    basisSecs,
    overWindow: (perDay / DAY_SECS) * WINDOW_SECS[window],
  };
}

/* -------------------------------------------------------------------- */
/* Unit cost and attribution coverage                                    */
/* -------------------------------------------------------------------- */

/**
 * Blended dollars per million tokens, input plus output.
 *
 * Cost per token is unreadable; cost per million is a number people have
 * intuitions about. `undefined` when the window moved no tokens, because
 * a unit cost over zero units is not a small number, it is no number.
 */
export function costPerMillionTokens(
  costUsd: number,
  tokensIn: number,
  tokensOut: number,
): number | undefined {
  const tokens = tokensIn + tokensOut;
  if (tokens <= 0) return undefined;
  return costUsd / (tokens / 1_000_000);
}

export interface UnattributedSpend {
  /** Dollars whose group key is empty for the selected dimension. */
  usd: number;
  /** Dollars in the window, attributed or not. */
  totalUsd: number;
  /** Unattributed over total, or `undefined` when the window is empty. */
  share: number | undefined;
}

/**
 * Spend the selected dimension could not name.
 *
 * Kubecost renders `__unallocated__` as a literal row; CloudZero calls it
 * "Not In Dimension". Both promote it rather than folding it away,
 * because a breakdown that silently omits its own remainder is how a
 * finance reader stops believing the page. This is that number, promoted
 * one further step to a headline tile.
 *
 * Never call this with `group_by=total`: the server writes an empty group
 * for every bucket there, so the answer would be a meaningless 100%.
 */
export function unattributedSpend(
  response: SpendWindowResponse,
): UnattributedSpend {
  let micros = 0;
  for (const bucket of response.buckets) {
    if (bucket.group === "") micros += bucket.cost_usd_micros;
  }
  const totalUsd = microsToUsd(response.totals.cost_usd_micros);
  const usd = microsToUsd(micros);
  return {
    usd,
    totalUsd,
    share: totalUsd > 0 ? usd / totalUsd : undefined,
  };
}

/* -------------------------------------------------------------------- */
/* Breakdown rows                                                        */
/* -------------------------------------------------------------------- */

export interface SpendRow {
  /** The raw group key. `""` is the unattributed segment. */
  group: string;
  costUsd: number;
  tokensIn: number;
  tokensOut: number;
  requests: number;
  blocked: number;
}

/** Fold a bucket list into one row per group, highest spend first. */
export function rowsByGroup(buckets: SpendWindowBucket[]): SpendRow[] {
  const byGroup = new Map<string, SpendRow>();
  for (const bucket of buckets) {
    const row = byGroup.get(bucket.group) ?? {
      group: bucket.group,
      costUsd: 0,
      tokensIn: 0,
      tokensOut: 0,
      requests: 0,
      blocked: 0,
    };
    row.costUsd += microsToUsd(bucket.cost_usd_micros);
    row.tokensIn += bucket.tokens_in;
    row.tokensOut += bucket.tokens_out;
    row.requests += bucket.requests;
    row.blocked += bucket.blocked;
    byGroup.set(bucket.group, row);
  }
  return [...byGroup.values()].sort((a, b) => b.costUsd - a.costUsd);
}

/** Whether a row appeared in only one of the two windows. */
export type RowPresence = "both" | "new" | "gone";

export interface ComparedSpendRow extends SpendRow {
  /** Row cost over the window total, or `undefined` on an empty window. */
  share: number | undefined;
  /** This window's cost minus the same group's cost in the prior one. */
  vsPrior: number | undefined;
  presence: RowPresence;
  /** Blended dollars per million tokens for this row. */
  perMillionTokens: number | undefined;
}

/**
 * Join this window's rows to the prior window's, keeping both sides.
 *
 * A group present in one window and absent in the other is the
 * interesting case, not the edge case: it is a model that was switched
 * on, or a key that went quiet. Rendering the delta as a silent zero
 * hides exactly that, so presence is carried out to the view and a
 * `gone` row keeps its old dollars.
 */
export function compareRows(
  rows: SpendRow[],
  priorRows: SpendRow[],
  totalUsd: number,
): ComparedSpendRow[] {
  const prior = new Map(priorRows.map((row) => [row.group, row]));
  const seen = new Set<string>();
  const out: ComparedSpendRow[] = [];
  for (const row of rows) {
    seen.add(row.group);
    const before = prior.get(row.group);
    out.push({
      ...row,
      share: totalUsd > 0 ? row.costUsd / totalUsd : undefined,
      vsPrior: before ? row.costUsd - before.costUsd : undefined,
      presence: before ? "both" : "new",
      perMillionTokens: costPerMillionTokens(
        row.costUsd,
        row.tokensIn,
        row.tokensOut,
      ),
    });
  }
  for (const row of priorRows) {
    if (seen.has(row.group)) continue;
    out.push({
      group: row.group,
      costUsd: 0,
      tokensIn: 0,
      tokensOut: 0,
      requests: 0,
      blocked: 0,
      share: totalUsd > 0 ? 0 : undefined,
      vsPrior: -row.costUsd,
      presence: "gone",
      perMillionTokens: undefined,
    });
  }
  return out.sort((a, b) => b.costUsd - a.costUsd);
}

export interface TopNItem {
  key: string;
  value: number;
  /** How many groups the Other row folds together. */
  folded?: number;
}

/**
 * The top N groups plus an explicit Other row carrying its own dollars.
 *
 * LangSmith collapses past the top six into "Other"; the rest of the
 * cohort truncates without saying so. The Other row is what keeps the
 * bars summing to the headline, and a breakdown whose parts do not add
 * up to the total is the fastest way to lose a finance reader.
 */
export function topNWithOther(
  rows: { group: string; costUsd: number }[],
  n: number,
  unattributedLabel = "(unattributed)",
): TopNItem[] {
  const ranked = [...rows].sort((a, b) => b.costUsd - a.costUsd);
  const head = ranked.slice(0, n).map((row) => ({
    key: row.group === "" ? unattributedLabel : row.group,
    value: row.costUsd,
  }));
  const tail = ranked.slice(n);
  if (tail.length === 0) return head;
  return [
    ...head,
    {
      key: `Other (${tail.length} more)`,
      value: tail.reduce((sum, row) => sum + row.costUsd, 0),
      folded: tail.length,
    },
  ];
}

/* -------------------------------------------------------------------- */
/* Re-bucketing for the chart                                            */
/* -------------------------------------------------------------------- */

export interface TimePoint {
  /** Bucket start, Unix seconds. */
  tsSecs: number;
  /** Dollars in the bucket. */
  usd: number;
}

export interface RebucketResult {
  points: TimePoint[];
  /** The width each rendered point covers, in seconds. */
  foldedSecs: number;
}

/**
 * Fold server buckets down to a readable number of points.
 *
 * `RollupStore::query` returns hourly buckets for anything inside the
 * hourly retention (90 days by default), so 7d is 168 rows and 30d is
 * 720. A line with 720 points on a 600px chart is a smear. Folding is
 * done here rather than server-side because the server's bucket width is
 * a storage decision and this is a rendering one.
 *
 * Factors are whole numbers of hours that divide a day, so a folded
 * bucket always starts on a clock boundary an operator recognizes.
 */
const FOLD_FACTORS_HOURS = [1, 2, 3, 4, 6, 8, 12, 24] as const;

export function rebucket(
  buckets: SpendWindowBucket[],
  bucketSecs: number,
  maxPoints = 40,
): RebucketResult {
  const byTs = new Map<number, number>();
  for (const bucket of buckets) {
    byTs.set(
      bucket.ts_secs,
      (byTs.get(bucket.ts_secs) ?? 0) + bucket.cost_usd_micros,
    );
  }
  const raw = [...byTs.entries()].sort((a, b) => a[0] - b[0]);
  if (raw.length === 0) return { points: [], foldedSecs: bucketSecs };

  const span = raw[raw.length - 1][0] - raw[0][0] + bucketSecs;
  let foldedSecs = bucketSecs;
  for (const hours of FOLD_FACTORS_HOURS) {
    const candidate = hours * HOUR_SECS;
    if (candidate < bucketSecs) continue;
    foldedSecs = candidate;
    if (Math.ceil(span / candidate) <= maxPoints) break;
  }

  const folded = new Map<number, number>();
  for (const [ts, micros] of raw) {
    const slot = Math.floor(ts / foldedSecs) * foldedSecs;
    folded.set(slot, (folded.get(slot) ?? 0) + micros);
  }
  return {
    points: [...folded.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([tsSecs, micros]) => ({ tsSecs, usd: microsToUsd(micros) })),
    foldedSecs,
  };
}

/**
 * Whether a window is too short for the rollup to draw a line.
 *
 * Hourly is the finest bucket the store keeps, so a one hour window is
 * one or two points. Saying that is more useful than drawing two dots
 * and calling it a trend.
 */
export function tooCoarseForChart(
  window: SpendWindow,
  bucketSecs: number,
): boolean {
  return WINDOW_SECS[window] / Math.max(1, bucketSecs) < 3;
}

/** Running total over a point series, for the burn-down view. */
export function cumulative(points: TimePoint[]): TimePoint[] {
  let sum = 0;
  return points.map((point) => {
    sum += point.usd;
    return { tsSecs: point.tsSecs, usd: sum };
  });
}

/**
 * Shift a prior-window series forward by one window length.
 *
 * Both series then share an x-axis, which is what makes "this window
 * against the last one" a comparison rather than two charts.
 */
export function shiftForward(
  points: TimePoint[],
  window: SpendWindow,
): TimePoint[] {
  const span = WINDOW_SECS[window];
  return points.map((point) => ({
    tsSecs: point.tsSecs + span,
    usd: point.usd,
  }));
}

/** Point series to the chart component's millisecond-based shape. */
export function toSeriesPoints(
  points: TimePoint[],
): { t: number; v: number }[] {
  return points.map((point) => ({ t: point.tsSecs * 1000, v: point.usd }));
}

/* -------------------------------------------------------------------- */
/* Price-volume variance                                                 */
/* -------------------------------------------------------------------- */

export interface SpendVariance {
  /** Total change in dollars. */
  total: number;
  /** The part explained by moving more or fewer tokens at the old rate. */
  volume: number;
  /** The remainder: a shift in what a token costs on average. */
  mix: number;
}

/**
 * Split a spend change into "more traffic" and "different traffic".
 *
 * The standard price-volume variance, computable exactly from the rollup
 * because it carries cost and tokens per bucket. The mix part is called
 * a model-mix change in the copy rather than a price change: on this
 * path a shift in blended dollars per token is a routing or catalog
 * change, essentially never a provider repricing.
 *
 * `undefined` when either window moved no tokens, rather than dividing.
 */
export function spendVariance(
  costNow: number,
  tokensNow: number,
  costPrior: number,
  tokensPrior: number,
): SpendVariance | undefined {
  if (tokensNow <= 0 || tokensPrior <= 0) return undefined;
  const unitPrior = costPrior / tokensPrior;
  const volume = (tokensNow - tokensPrior) * unitPrior;
  const total = costNow - costPrior;
  return { total, volume, mix: total - volume };
}

/* -------------------------------------------------------------------- */
/* Drill-down links                                                      */
/* -------------------------------------------------------------------- */

/**
 * Where a breakdown label leads, or nothing.
 *
 * A label that looks clickable and lands on an unfiltered page is worse
 * than a plain label, so a dimension only gets a link when the
 * destination both accepts it as a query parameter and shows the
 * operator the filter it applied.
 *
 *  - `origin` and `api_key` restore visible inputs on Logs.
 *  - `property:<key>` restores the Logs property pair.
 *  - `model` and `tenant` go to Reports, which filters the same ring on
 *    exactly those dimensions and prints cost per row. Logs has no model
 *    or tenant input at all, so linking there would drop the filter.
 *  - `provider`, `team`, `project`, `agent` and `total` have no filter
 *    on either page. They stay unlinked.
 */
export function drillDownLink(
  groupBy: string,
  key: string,
): string | undefined {
  if (key === "") return undefined;
  const value = encodeURIComponent(key);
  if (groupBy === "origin") return `/logs?origin=${value}`;
  if (groupBy === "api_key") return `/logs?api_key_id=${value}`;
  if (groupBy === "model") return `/reports?model=${value}&group_by=model`;
  if (groupBy === "tenant") return `/reports?tenant=${value}&group_by=tenant`;
  if (groupBy.startsWith("property:")) {
    const propertyKey = encodeURIComponent(groupBy.slice("property:".length));
    return `/logs?property_key=${propertyKey}&property_value=${value}`;
  }
  return undefined;
}
