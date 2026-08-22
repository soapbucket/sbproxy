/*
 * Storage backend operations, derived from the Prometheus scrape.
 *
 * `sbproxy_storage_op_duration_seconds` and
 * `sbproxy_storage_op_errors_total` are wrapped
 * around every call a storage backend makes (`crates/sbproxy-storage/src/
 * metrics.rs`, `observe_op`). They answer a question the Storage page could
 * not answer before: whether the backend behind the gateway is answering,
 * and how fast. Nothing in the console named either family, so a
 * disconnected Redis was visible only in the logs.
 *
 * Three facts about the exporter shape drive this module.
 *
 * 1. Both families register lazily, on the first operation. A deployment
 *    with no external storage backend in use publishes neither, so absent
 *    means "no backend has run an operation", not "zero operations". The
 *    report is `undefined` in that case and the panel says so in words.
 *
 * 2. The error counter increments only on `Err`. A backend that has served
 *    a million reads cleanly publishes the duration family and no error
 *    family at all, and that reads as a real zero, not as a gap. So the
 *    report exists as soon as *either* family is there, and errors default
 *    to 0 when only the duration family is.
 *
 * 3. The duration family is a histogram, so its samples carry `_bucket`,
 *    `_sum` and `_count` names folded into one family. Summing the family
 *    with `sumSamples` would add every cumulative bucket (including the
 *    `+Inf` one) and every `_sum` to the real counts and produce a number
 *    that means nothing. Operation totals come off `_count` only.
 *
 * Both families were renamed into the sanctioned `sbproxy_` prefix that
 * `crates/sbproxy-capability/src/scan.rs` recognizes, and both are now in
 * `crates/sbproxy-observe/src/metric_registry.rs` and
 * `docs/metrics-stability.md`. That rename is why the names here are
 * pinned by assertions rather than left as bare literals: the registry
 * and the drift guard catch a rename on the Rust side, and nothing on
 * either side reaches into this file, so a rename that landed while this
 * panel was being written would blank it in silence. It did land while
 * this panel was being written, and it did blank it, which is the reason
 * the pins are worth their line count.
 */

import {
  groupByLabel,
  histogramQuantile,
  histogramQuantileByLabels,
  type MetricFamily,
} from "./metrics";

/** Histogram family: latency of every storage backend operation. */
export const STORAGE_OP_DURATION_FAMILY = "sbproxy_storage_op_duration_seconds";
/** Counter family: storage backend operations that returned an error. */
export const STORAGE_OP_ERRORS_FAMILY = "sbproxy_storage_op_errors_total";

/** One `backend / op` latency row. */
export interface StorageOpLatencyRow {
  key: string;
  /** p95 in seconds. */
  value: number;
}

/** One `error_kind` row. */
export interface StorageOpErrorRow {
  key: string;
  value: number;
}

/** What the panel renders when the backend has run at least one operation. */
export interface StorageOpsReport {
  /** Operations completed since start, from the histogram `_count`. */
  operations: number;
  /** Operations that returned an error. Zero is a real zero here. */
  errors: number;
  /** `errors / operations`, clamped to 1. Zero when nothing has run. */
  errorRate: number;
  /** p95 across every backend and operation, in seconds. */
  p95Seconds: number | undefined;
  /** p95 per `backend / op`, slowest first. */
  slowest: StorageOpLatencyRow[];
  /** Error totals per `error_kind`, largest first. */
  errorsByKind: StorageOpErrorRow[];
  /** Backend names seen in the scrape, e.g. `redis`. */
  backends: string[];
}

/** Sum only the `_count` samples of a histogram family. */
function histogramCount(family: MetricFamily | undefined): number {
  if (!family) return 0;
  return family.samples
    .filter((sample) => sample.name.endsWith("_count"))
    .reduce((total, sample) => total + sample.value, 0);
}

/**
 * Distinct values of one label across a family's samples, sorted.
 *
 * Samples missing the label are skipped rather than bucketed under
 * `"(none)"`: an unlabeled backend is not a backend an operator can act on,
 * and `groupByLabel` would otherwise invent that row.
 */
function labelValues(
  family: MetricFamily | undefined,
  label: string,
): string[] {
  if (!family) return [];
  const seen = new Set<string>();
  for (const sample of family.samples) {
    const value = sample.labels[label];
    if (value !== undefined && value !== "") seen.add(value);
  }
  return [...seen].sort();
}

/**
 * Read storage backend health out of a parsed scrape.
 *
 * Returns `undefined` when neither family is present, which means no
 * storage backend has completed an operation on this node. That is not a
 * zero and the panel must not draw it as one.
 */
export function storageOps(
  families: MetricFamily[],
): StorageOpsReport | undefined {
  const duration = families.find(
    (f) => f.name === STORAGE_OP_DURATION_FAMILY,
  );
  const errorFamily = families.find(
    (f) => f.name === STORAGE_OP_ERRORS_FAMILY,
  );
  if (!duration && !errorFamily) return undefined;

  const operations = histogramCount(duration);
  const errors = errorFamily
    ? errorFamily.samples.reduce((total, sample) => total + sample.value, 0)
    : 0;

  return {
    operations,
    errors,
    errorRate:
      operations > 0 ? Math.min(errors / operations, 1) : errors > 0 ? 1 : 0,
    p95Seconds: histogramQuantile(duration, 0.95),
    slowest: histogramQuantileByLabels(duration, 0.95, ["backend", "op"]),
    errorsByKind: errorFamily ? groupByLabel(errorFamily, "error_kind") : [],
    backends: labelValues(duration ?? errorFamily, "backend"),
  };
}
