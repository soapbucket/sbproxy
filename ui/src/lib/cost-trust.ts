/**
 * Pure derivations for the two panels that say how far to trust the
 * spend number: price provenance, price-ceiling activity, estimator
 * accuracy, and per-key budget headroom.
 *
 * The rule these share with `spend-derive.ts`: an absent measurement is
 * `undefined`, never `0`. `sumSamples(undefined)` returns `0`, so a
 * family nothing writes and a family writing a real zero are the same
 * number downstream, and every one of the families read here only
 * appears once a specific feature is configured. Callers branch on the
 * family, then on these `undefined`s, and print "not reported" rather
 * than a healthy-looking zero.
 */
import { keyPolicyDraft, type AdminKey, type GovernanceCounterSnapshot } from "../api";
import type { MetricFamily } from "./metrics";

/* -------------------------------------------------------------------- */
/* Price provenance                                                      */
/* -------------------------------------------------------------------- */

/**
 * The four `source` values `sbproxy_ai_price_source_total` reports, in
 * descending order of how much the price can be trusted.
 *
 * Nothing in the AI gateway cohort ships price provenance at all, which
 * is why the copy has to be exact. The family counts one sample per
 * price lookup, not per request, and carries no `model` label: it can
 * say that some share of lookups was invented and cannot say which model
 * caused it. `compat: alpha`, so the name is pinned by a test.
 */
export const PRICE_SOURCE_ORDER = [
  "catalog",
  "rate_card",
  "config",
  "fallback",
] as const;

export const PRICE_SOURCE_LABELS: Record<string, string> = {
  catalog: "Shipped catalog",
  rate_card: "Provider rate card",
  config: "Operator config",
  fallback: "Flat fallback rate",
};

export interface PriceSourceShare {
  source: string;
  label: string;
  count: number;
  /** Share of this family's own total, or `undefined` on no lookups. */
  share: number | undefined;
}

export interface PriceSourceReading {
  total: number;
  shares: PriceSourceShare[];
}

/**
 * Share of price lookups per source layer.
 *
 * Divided by the family's own total, never by the request counter: the
 * two count different events, and one guardrail-blocked chat completion
 * produces two price lookups.
 *
 * A source value this build has never heard of is kept and shown rather
 * than dropped, so the segments always sum to the whole.
 */
export function priceSourceShares(
  family: MetricFamily | undefined,
): PriceSourceReading | undefined {
  if (!family) return undefined;
  const counts = new Map<string, number>();
  for (const sample of family.samples) {
    const source = sample.labels.source;
    if (source === undefined) continue;
    counts.set(source, (counts.get(source) ?? 0) + sample.value);
  }
  const total = [...counts.values()].reduce((sum, v) => sum + v, 0);
  const extra = [...counts.keys()]
    .filter((s) => !(PRICE_SOURCE_ORDER as readonly string[]).includes(s))
    .sort();
  const shares = [...PRICE_SOURCE_ORDER, ...extra].map((source) => {
    const count = counts.get(source) ?? 0;
    return {
      source,
      label: PRICE_SOURCE_LABELS[source] ?? source,
      count,
      share: total > 0 ? count / total : undefined,
    };
  });
  return { total, shares };
}

/* -------------------------------------------------------------------- */
/* Price ceiling                                                         */
/* -------------------------------------------------------------------- */

export interface PriceCeilingOutcome {
  outcome: string;
  label: string;
  count: number;
  /** What this count means, and what a rise in it says. */
  note: string;
  /** Where to see the requests, when a page can filter on them. */
  link?: string;
}

/**
 * The four `sbproxy_ai_price_ceiling_total{outcome}` values, read.
 *
 * Steady exclusions with no refusals is the healthy shape: candidates
 * are being priced and the expensive ones dropped. Refusals climbing
 * means the ceiling is now under the cheapest candidate available, which
 * is a configuration problem rather than a savings win. `compat: alpha`,
 * so the name is pinned by a test.
 */
export function priceCeilingOutcomes(
  family: MetricFamily | undefined,
): PriceCeilingOutcome[] | undefined {
  if (!family) return undefined;
  const counts = new Map<string, number>();
  for (const sample of family.samples) {
    const outcome = sample.labels.outcome;
    if (outcome === undefined) continue;
    counts.set(outcome, (counts.get(outcome) ?? 0) + sample.value);
  }
  const known: Omit<PriceCeilingOutcome, "count">[] = [
    {
      outcome: "candidate_excluded",
      label: "Candidates excluded",
      note: "Routing candidates dropped for being priced over the ceiling. Counted per candidate, so one request can contribute several.",
    },
    {
      outcome: "refused",
      label: "Requests refused",
      note: "Every candidate was over the ceiling, so the request was answered 402. Refusals climbing means the ceiling is now below the cheapest available candidate.",
      link: "/logs?status=402",
    },
    {
      outcome: "invalid_header",
      label: "Unparseable ceiling header",
      note: "A caller sent an x-sbproxy-max-price the gateway could not read. This is a client integration bug, not a spend event.",
    },
    {
      outcome: "unsupported_surface",
      label: "Ceiling on an unpriceable surface",
      note: "A caller set a header ceiling on a surface with no pre-dispatch cost estimate. It is enforceable only on chat completions, messages, and responses.",
    },
  ];
  const extra = [...counts.keys()]
    .filter((o) => !known.some((k) => k.outcome === o))
    .sort()
    .map((outcome) => ({
      outcome,
      label: outcome,
      note: "Reported by the running binary and not described by this console build.",
    }));
  return [...known, ...extra].map((entry) => ({
    ...entry,
    count: counts.get(entry.outcome) ?? 0,
  }));
}

/* -------------------------------------------------------------------- */
/* Estimator accuracy                                                    */
/* -------------------------------------------------------------------- */

/**
 * A quantile over a histogram whose buckets straddle zero.
 *
 * `sbproxy_ai_token_estimate_error_ratio` runs from -1.0 to +1.0, and
 * the sign is the whole point: positive means the estimator
 * under-reserved, which is the direction that overspends a budget. The
 * shared `histogramQuantile` helper anchors its interpolation at 0, so
 * the lowest bucket of a signed histogram interpolates across zero and
 * reports a value the estimator never produced. This anchors at the
 * lowest finite bucket bound instead.
 */
function signedQuantileFromBuckets(
  byLe: Map<number, number>,
  q: number,
): number | undefined {
  const buckets = [...byLe.entries()].sort((a, b) => a[0] - b[0]);
  if (buckets.length === 0) return undefined;
  const total = buckets[buckets.length - 1][1];
  if (total <= 0) return undefined;
  const target = q * total;
  const floor = Number.isFinite(buckets[0][0]) ? buckets[0][0] : 0;
  let prevLe = floor;
  let prevCount = 0;
  for (const [le, count] of buckets) {
    if (count >= target) {
      if (!Number.isFinite(le)) return prevLe;
      if (le === floor) return le;
      const inBucket = count - prevCount;
      if (inBucket <= 0) return le;
      return prevLe + (le - prevLe) * ((target - prevCount) / inBucket);
    }
    prevLe = Number.isFinite(le) ? le : prevLe;
    prevCount = count;
  }
  return prevLe;
}

export interface EstimateErrorRow {
  model: string;
  /** The over-reserving tail. Negative means the estimate ran high. */
  p05: number;
  p50: number;
  /** The under-reserving tail. Positive means the estimate ran low. */
  p95: number;
  /** Total observations behind the row. */
  samples: number;
}

/**
 * Signed p05, p50 and p95 of the estimate error, per model, worst first.
 *
 * Both tails, because both cost money in different ways. The sample is
 * `(actual - estimated) / actual`, so a positive p95 is an estimator
 * that reserved too little and let a budget overshoot, and a negative
 * p05 is one that reserved too much and held rate-limit headroom the
 * request never used. A p95 near zero says nothing about the second.
 *
 * Only recorded on a reconciled rate-limit admission, which needs an
 * entry in `config.model_rate_limits` for the model. On a deployment
 * with none, this returns an empty list while the estimator is still
 * driving budget debits and the price ceiling, and the view says exactly
 * that rather than drawing an empty chart.
 */
export function estimateErrorByModel(
  family: MetricFamily | undefined,
): EstimateErrorRow[] | undefined {
  if (!family) return undefined;
  const groups = new Map<string, Map<number, number>>();
  for (const sample of family.samples) {
    if (!sample.name.endsWith("_bucket")) continue;
    const raw = sample.labels.le;
    if (raw === undefined) continue;
    const le = raw === "+Inf" ? Infinity : Number(raw);
    if (Number.isNaN(le)) continue;
    const model = sample.labels.model ?? "(no model)";
    const byLe = groups.get(model) ?? new Map<number, number>();
    byLe.set(le, (byLe.get(le) ?? 0) + sample.value);
    groups.set(model, byLe);
  }
  const rows: EstimateErrorRow[] = [];
  for (const [model, byLe] of groups) {
    const p05 = signedQuantileFromBuckets(byLe, 0.05);
    const p50 = signedQuantileFromBuckets(byLe, 0.5);
    const p95 = signedQuantileFromBuckets(byLe, 0.95);
    if (p05 === undefined || p50 === undefined || p95 === undefined) continue;
    const sorted = [...byLe.entries()].sort((a, b) => a[0] - b[0]);
    rows.push({ model, p05, p50, p95, samples: sorted[sorted.length - 1][1] });
  }
  // Worst first, by whichever tail is further from a correct estimate.
  const worst = (row: EstimateErrorRow) =>
    Math.max(Math.abs(row.p05), Math.abs(row.p95));
  return rows.sort((a, b) => worst(b) - worst(a));
}

/* -------------------------------------------------------------------- */
/* Budget headroom                                                       */
/* -------------------------------------------------------------------- */

export type BudgetTone = "ok" | "warn" | "err";

export function budgetTone(ratio: number): BudgetTone {
  if (ratio > 0.9) return "err";
  if (ratio >= 0.75) return "warn";
  return "ok";
}

export interface BudgetBar {
  limitUsd: number;
  usedUsd: number;
  /** Committed and not yet settled. Real money, just not spent yet. */
  reservedUsd: number;
  remainingUsd: number;
  /** (used + reserved) / limit. Can exceed 1 on an approximate backend. */
  ratio: number;
  /** Bar widths in percent, clamped to sum to at most 100. */
  usedPct: number;
  reservedPct: number;
  tone: BudgetTone;
}

/**
 * One key's dollar cap as a three-segment bar.
 *
 * `reserved` gets its own segment rather than being folded into used or
 * dropped. It is money the gateway has committed against the cap and not
 * yet settled, so hiding it makes the bar understate the wall by exactly
 * that much, and the caller hits a 402 while the bar still shows room.
 *
 * `undefined` when the dimension has no configured cap: a key with no
 * dollar budget has no headroom to report, and a full green bar would
 * claim it did.
 */
export function budgetBar(
  snapshot: GovernanceCounterSnapshot,
): BudgetBar | undefined {
  const limitUsd = snapshot.limit === null ? 0 : snapshot.limit / 1_000_000;
  if (snapshot.limit === null || limitUsd <= 0) return undefined;
  const usedUsd = snapshot.used / 1_000_000;
  const reservedUsd = snapshot.reserved / 1_000_000;
  const remainingUsd =
    snapshot.remaining === null
      ? Math.max(0, limitUsd - usedUsd - reservedUsd)
      : snapshot.remaining / 1_000_000;
  const ratio = (usedUsd + reservedUsd) / limitUsd;
  const usedPct = Math.min(100, (usedUsd / limitUsd) * 100);
  const reservedPct = Math.min(
    100 - usedPct,
    (reservedUsd / limitUsd) * 100,
  );
  return {
    limitUsd,
    usedUsd,
    reservedUsd,
    remainingUsd,
    ratio,
    usedPct,
    reservedPct,
    tone: budgetTone(ratio),
  };
}

export interface CappedKey {
  id: string;
  label: string;
  /** The enforced dollar cap, override included. */
  capUsd: number;
  /** This window's rollup spend for the key, when the caller knows it. */
  windowSpendUsd: number | undefined;
}

/**
 * The dollar cap actually enforced on a key, or nothing.
 *
 * `effective_budget` is base plus any active temporary raise, which is
 * the number the request path checks against. The older flat fields are
 * the fallback for a build that predates it.
 */
export function keyDollarCap(key: AdminKey): number | undefined {
  const effective = key.effective_budget?.max_cost_usd;
  if (typeof effective === "number" && effective > 0) return effective;
  const draft = keyPolicyDraft(key).max_budget_usd;
  return typeof draft === "number" && draft > 0 ? draft : undefined;
}

export interface CappedKeySelection {
  rows: CappedKey[];
  /** How many capped keys exist, before the fan-out bound. */
  total: number;
  truncated: boolean;
  /** Which ordering decided who made the cut. */
  orderedBy: "spend" | "cap";
}

/**
 * Which capped keys to spend a `/usage` request on.
 *
 * Headroom is one call per key, so the panel picks an order and stops.
 * Spend in the selected window is the better order and is only available
 * when the page is grouped by key; the configured cap is the fallback.
 * Either way the view says which order it used and how many keys it left
 * out, because a list that silently stops at twenty reads as the whole
 * fleet.
 *
 * A spend map that names none of the capped keys is treated as absent.
 * The rollup groups by the id the request path stamped and the key list
 * comes from the admin store, so the two can fail to join; claiming
 * "highest spend first" over a join that matched nothing would describe
 * an order the list is not in.
 */
export function selectCappedKeys(
  keys: AdminKey[],
  spendByKey: Record<string, number> | undefined,
  limit = 20,
): CappedKeySelection {
  const capped: CappedKey[] = [];
  for (const key of keys) {
    const capUsd = keyDollarCap(key);
    if (capUsd === undefined) continue;
    const id = String(key.id ?? key.key_id ?? key.prefix ?? key.name ?? "");
    if (!id) continue;
    capped.push({
      id,
      label: String(key.name ?? key.label ?? id),
      capUsd,
      windowSpendUsd: spendByKey?.[id],
    });
  }
  const spendJoins = capped.some((row) => row.windowSpendUsd !== undefined);
  const orderedBy = spendByKey && spendJoins ? "spend" : "cap";
  capped.sort((a, b) => {
    if (orderedBy === "spend") {
      const delta = (b.windowSpendUsd ?? 0) - (a.windowSpendUsd ?? 0);
      if (delta !== 0) return delta;
    }
    if (b.capUsd !== a.capUsd) return b.capUsd - a.capUsd;
    return a.id.localeCompare(b.id);
  });
  return {
    rows: capped.slice(0, limit),
    total: capped.length,
    truncated: capped.length > limit,
    orderedBy,
  };
}

export interface ScopeUtilization {
  scope: string;
  /** The highest single budget in this scope, as a fraction of its limit. */
  ratio: number;
  tone: BudgetTone;
}

/**
 * `sbproxy_ai_budget_utilization_ratio{scope}`, highest per scope.
 *
 * The gauge carries no identity, so the most it can say is "some budget
 * in this scope is at 91%". Taking the max is the only honest reduction:
 * a mean would hide the one that is about to refuse traffic. The label
 * above the bars has to say the gauge cannot name the workspace or key,
 * or the bars claim more than the metric supports.
 */
export function utilizationByScope(
  family: MetricFamily | undefined,
): ScopeUtilization[] | undefined {
  if (!family) return undefined;
  const max = new Map<string, number>();
  for (const sample of family.samples) {
    const scope = sample.labels.scope;
    if (scope === undefined) continue;
    max.set(scope, Math.max(max.get(scope) ?? 0, sample.value));
  }
  return [...max.entries()]
    .map(([scope, ratio]) => ({ scope, ratio, tone: budgetTone(ratio) }))
    .sort((a, b) => b.ratio - a.ratio);
}
