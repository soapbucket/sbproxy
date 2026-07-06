/** Minimal Prometheus text-exposition parser. */

export interface MetricSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export interface MetricFamily {
  name: string;
  help?: string;
  type?: string;
  samples: MetricSample[];
}

const LINE_RE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(.+)$/;

function parseLabels(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  // labels look like: a="1",b="two, with comma"
  const re = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    out[m[1]] = m[2].replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
  }
  return out;
}

export function parsePrometheus(text: string): MetricFamily[] {
  const families = new Map<string, MetricFamily>();

  const family = (name: string): MetricFamily => {
    let f = families.get(name);
    if (!f) {
      f = { name, samples: [] };
      families.set(name, f);
    }
    return f;
  };

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      const parts = line.split(/\s+/);
      // # HELP name text...   or   # TYPE name kind
      if (parts[1] === "HELP" && parts[2]) {
        family(parts[2]).help = parts.slice(3).join(" ");
      } else if (parts[1] === "TYPE" && parts[2]) {
        family(parts[2]).type = parts[3];
      }
      continue;
    }
    const m = LINE_RE.exec(line);
    if (!m) continue;
    const name = m[1];
    const labels = parseLabels(m[3]);
    const value = Number(m[4].split(/\s+/)[0]);
    if (Number.isNaN(value)) continue;
    // Fold histogram/summary component suffixes (_bucket/_sum/_count)
    // back to the base family so a family groups its own samples. A
    // `_total` counter keeps its own name (the `_total` IS the metric).
    const base = name.replace(/_(bucket|sum|count|total)$/, (s) =>
      s === "_total" ? "_total" : "",
    );
    const f = family(base === name ? name : base);
    f.samples.push({ name, labels, value });
  }

  return [...families.values()];
}

/** Sum every sample of a family whose labels match the given filter. */
export function sumSamples(
  family: MetricFamily | undefined,
  labelFilter: Record<string, string> = {},
): number {
  if (!family) return 0;
  return family.samples
    .filter((s) =>
      Object.entries(labelFilter).every(([k, v]) => s.labels[k] === v),
    )
    .reduce((acc, s) => acc + s.value, 0);
}

/** Group a family's samples by the value of one label. */
export function groupByLabel(
  family: MetricFamily | undefined,
  label: string,
): { key: string; value: number }[] {
  if (!family) return [];
  const acc = new Map<string, number>();
  for (const s of family.samples) {
    const key = s.labels[label] ?? "(none)";
    acc.set(key, (acc.get(key) ?? 0) + s.value);
  }
  return [...acc.entries()]
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value);
}

/**
 * Estimate a quantile (`q` in 0..1) from a histogram family's `_bucket`
 * samples, summing cumulative buckets across all label sets by their `le`
 * bound and interpolating linearly within the matched bucket. Returns the
 * value in the metric's own unit, or `undefined` if there are no buckets.
 */
export function histogramQuantile(
  family: MetricFamily | undefined,
  q: number,
): number | undefined {
  if (!family) return undefined;
  const byLe = new Map<number, number>();
  let hasBuckets = false;
  for (const s of family.samples) {
    if (!s.name.endsWith("_bucket")) continue;
    const leRaw = s.labels.le;
    if (leRaw === undefined) continue;
    const le = leRaw === "+Inf" ? Infinity : Number(leRaw);
    if (Number.isNaN(le)) continue;
    hasBuckets = true;
    byLe.set(le, (byLe.get(le) ?? 0) + s.value);
  }
  if (!hasBuckets) return undefined;
  const buckets = [...byLe.entries()].sort((a, b) => a[0] - b[0]);
  const total = buckets.length ? buckets[buckets.length - 1][1] : 0;
  if (total <= 0) return undefined;
  const target = q * total;
  let prevLe = 0;
  let prevCount = 0;
  for (const [le, count] of buckets) {
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

/**
 * Average of a histogram family per label value: `sum(_sum)/sum(_count)`.
 * Used for per-model token throughput (avg tok/s). Returns descending by
 * value.
 */
export function histogramAvgByLabel(
  family: MetricFamily | undefined,
  label: string,
): { key: string; value: number }[] {
  if (!family) return [];
  const sums = new Map<string, number>();
  const counts = new Map<string, number>();
  for (const s of family.samples) {
    const key = s.labels[label];
    if (key === undefined) continue;
    if (s.name.endsWith("_sum")) {
      sums.set(key, (sums.get(key) ?? 0) + s.value);
    } else if (s.name.endsWith("_count")) {
      counts.set(key, (counts.get(key) ?? 0) + s.value);
    }
  }
  const out: { key: string; value: number }[] = [];
  for (const [key, sum] of sums) {
    const c = counts.get(key) ?? 0;
    if (c > 0) out.push({ key, value: sum / c });
  }
  return out.sort((a, b) => b.value - a.value);
}

export function findFamily(
  families: MetricFamily[],
  ...names: string[]
): MetricFamily | undefined {
  for (const n of names) {
    const exact = families.find((f) => f.name === n);
    if (exact) return exact;
  }
  // Loose contains match as a fallback.
  for (const n of names) {
    const loose = families.find((f) => f.name.includes(n));
    if (loose) return loose;
  }
  return undefined;
}
