/**
 * Rolling time series derived from repeated Prometheus scrapes.
 *
 * The metrics endpoint is a point-in-time cumulative snapshot, so the
 * live charts poll it and chart the *differences* between consecutive
 * scrapes: counter deltas become per-second rates, histogram bucket
 * deltas become per-interval quantiles. Counter resets (a proxy
 * restart mid-session) clamp to zero rather than plotting a negative
 * spike.
 */

import type { MetricFamily } from "./metrics";

export interface SeriesPoint {
  /** Sample time, epoch milliseconds. */
  t: number;
  v: number;
}

export interface Snapshot {
  /** Scrape time, epoch milliseconds. */
  t: number;
  families: MetricFamily[];
}

/** Bounded scrape history; push() drops the oldest beyond capacity. */
export class ScrapeHistory {
  readonly capacity: number;
  readonly snapshots: Snapshot[] = [];

  constructor(capacity = 121) {
    this.capacity = capacity;
  }

  push(t: number, families: MetricFamily[]): void {
    this.snapshots.push({ t, families });
    while (this.snapshots.length > this.capacity) {
      this.snapshots.shift();
    }
  }

  clear(): void {
    this.snapshots.length = 0;
  }
}

/**
 * Per-second rate of a cumulative value between consecutive scrapes.
 * `total` reads the cumulative value out of one scrape. Yields one
 * point per interval, timestamped at the interval's end.
 */
export function rateSeries(
  snapshots: readonly Snapshot[],
  total: (families: MetricFamily[]) => number,
): SeriesPoint[] {
  const out: SeriesPoint[] = [];
  for (let i = 1; i < snapshots.length; i++) {
    const prev = snapshots[i - 1];
    const cur = snapshots[i];
    const dt = (cur.t - prev.t) / 1000;
    if (dt <= 0) continue;
    const delta = total(cur.families) - total(prev.families);
    out.push({ t: cur.t, v: delta < 0 ? 0 : delta / dt });
  }
  return out;
}

/**
 * Ratio (0..100) of two cumulative values' deltas per interval, e.g.
 * error requests over total requests. Intervals where the denominator
 * did not move yield 0 (no traffic means no error rate).
 */
export function ratioSeries(
  snapshots: readonly Snapshot[],
  numerator: (families: MetricFamily[]) => number,
  denominator: (families: MetricFamily[]) => number,
): SeriesPoint[] {
  const out: SeriesPoint[] = [];
  for (let i = 1; i < snapshots.length; i++) {
    const prev = snapshots[i - 1];
    const cur = snapshots[i];
    if (cur.t <= prev.t) continue;
    const dNum = numerator(cur.families) - numerator(prev.families);
    const dDen = denominator(cur.families) - denominator(prev.families);
    if (dDen <= 0 || dNum < 0) {
      out.push({ t: cur.t, v: 0 });
    } else {
      out.push({ t: cur.t, v: Math.min(100, (dNum / dDen) * 100) });
    }
  }
  return out;
}

/** Cumulative `le -> count` map for a histogram family in one scrape. */
export function bucketMap(
  families: MetricFamily[],
  name: string,
  labelFilter: Record<string, string> = {},
): Map<number, number> {
  const byLe = new Map<number, number>();
  const family = families.find((f) => f.name === name);
  if (!family) return byLe;
  const filterEntries = Object.entries(labelFilter);
  for (const s of family.samples) {
    if (!s.name.endsWith("_bucket")) continue;
    if (!filterEntries.every(([k, v]) => s.labels[k] === v)) continue;
    const leRaw = s.labels.le;
    if (leRaw === undefined) continue;
    const le = leRaw === "+Inf" ? Infinity : Number(leRaw);
    if (Number.isNaN(le)) continue;
    byLe.set(le, (byLe.get(le) ?? 0) + s.value);
  }
  return byLe;
}

function quantileFromDeltaBuckets(
  prev: Map<number, number>,
  cur: Map<number, number>,
  q: number,
): number | undefined {
  const les = [...cur.keys()].sort((a, b) => a - b);
  if (!les.length) return undefined;
  const deltas: [number, number][] = [];
  let reset = false;
  for (const le of les) {
    const d = (cur.get(le) ?? 0) - (prev.get(le) ?? 0);
    if (d < 0) reset = true;
    deltas.push([le, d]);
  }
  if (reset) return undefined;
  const total = deltas[deltas.length - 1][1];
  if (total <= 0) return undefined;
  const target = q * total;
  let prevLe = 0;
  let prevCount = 0;
  for (const [le, count] of deltas) {
    if (count >= target) {
      if (!Number.isFinite(le)) return prevLe;
      const bucketCount = count - prevCount;
      if (bucketCount <= 0) return le;
      const frac = (target - prevCount) / bucketCount;
      return prevLe + (le - prevLe) * frac;
    }
    prevLe = Number.isFinite(le) ? le : prevLe;
    prevCount = count;
  }
  return prevLe;
}

/** Quantile of one cumulative bucket map (since process start). */
export function mapQuantile(
  byLe: Map<number, number>,
  q: number,
): number | undefined {
  return quantileFromDeltaBuckets(new Map(), byLe, q);
}

/**
 * Per-interval histogram quantile: the q-quantile of only the
 * observations recorded between consecutive scrapes. Quiet intervals
 * (no new observations) are skipped so the line reflects real
 * traffic, not a flat repeat of the cumulative value.
 */
export function intervalQuantileSeries(
  snapshots: readonly Snapshot[],
  familyName: string,
  q: number,
  labelFilter: Record<string, string> = {},
): SeriesPoint[] {
  const out: SeriesPoint[] = [];
  for (let i = 1; i < snapshots.length; i++) {
    const prev = snapshots[i - 1];
    const cur = snapshots[i];
    if (cur.t <= prev.t) continue;
    const v = quantileFromDeltaBuckets(
      bucketMap(prev.families, familyName, labelFilter),
      bucketMap(cur.families, familyName, labelFilter),
      q,
    );
    if (v !== undefined) out.push({ t: cur.t, v });
  }
  return out;
}

/** The most recent point's value, for pairing a tile with its spark. */
export function lastValue(series: readonly SeriesPoint[]): number | undefined {
  return series.length ? series[series.length - 1].v : undefined;
}
