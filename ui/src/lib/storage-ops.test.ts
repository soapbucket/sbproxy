import { describe, expect, it } from "vitest";

import { parsePrometheus } from "./metrics";
import {
  STORAGE_OP_DURATION_FAMILY,
  STORAGE_OP_ERRORS_FAMILY,
  storageOps,
} from "./storage-ops";

function histogram(
  op: string,
  backend: string,
  kind: string,
  buckets: [string, number][],
  sum: number,
  count: number,
): string[] {
  const labels = (extra: string) =>
    `{op="${op}",backend="${backend}",kind="${kind}"${extra}}`;
  return [
    ...buckets.map(
      ([le, value]) =>
        `storage_op_duration_seconds_bucket${labels(`,le="${le}"`)} ${value}`,
    ),
    `storage_op_duration_seconds_sum${labels("")} ${sum}`,
    `storage_op_duration_seconds_count${labels("")} ${count}`,
  ];
}

const SCRAPE = [
  "# TYPE storage_op_duration_seconds histogram",
  ...histogram(
    "get",
    "redis",
    "ephemeral",
    [
      ["0.001", 80],
      ["0.005", 95],
      ["0.01", 100],
      ["+Inf", 100],
    ],
    0.15,
    100,
  ),
  ...histogram(
    "put",
    "redis",
    "persistent",
    [
      ["0.001", 0],
      ["0.005", 10],
      ["0.01", 40],
      ["+Inf", 40],
    ],
    0.3,
    40,
  ),
  "# TYPE storage_op_errors_total counter",
  'storage_op_errors_total{op="get",backend="redis",kind="ephemeral",error_kind="backend"} 3',
  'storage_op_errors_total{op="put",backend="redis",kind="persistent",error_kind="timeout"} 1',
].join("\n");

describe("storage backend operations", () => {
  it("reads the families the storage crate actually exports", () => {
    // Neither name carries the sbproxy_ or mesh_ prefix that the metric
    // drift guard scans, so nothing in the Rust build fails if they are
    // renamed. These two assertions are the whole safety net.
    expect(STORAGE_OP_DURATION_FAMILY).toBe("storage_op_duration_seconds");
    expect(STORAGE_OP_ERRORS_FAMILY).toBe("storage_op_errors_total");
  });

  it("counts operations off the histogram _count, never the buckets", () => {
    const report = storageOps(parsePrometheus(SCRAPE));

    // Summing every sample in the folded family would add 325 bucket
    // observations to the two counts and report 465 operations.
    expect(report?.operations).toBe(140);
    expect(report?.errors).toBe(4);
    expect(report?.backends).toEqual(["redis"]);
  });

  it("derives an error rate and the slowest backend and operation", () => {
    const report = storageOps(parsePrometheus(SCRAPE));

    expect(report?.errorRate).toBeCloseTo(4 / 140, 6);
    expect(report?.slowest[0].key).toBe("redis / put");
    expect(report?.slowest[0].value).toBeGreaterThan(
      report?.slowest[1].value ?? Infinity,
    );
    expect(report?.p95Seconds).toBeGreaterThan(0);
    expect(report?.errorsByKind.map((row) => row.key)).toEqual([
      "backend",
      "timeout",
    ]);
  });

  it("reports absent rather than zero when no backend has run", () => {
    // Both families register lazily, on the first operation. A deployment
    // with no external storage backend publishes neither, and a zero here
    // would read as a healthy backend rather than as no backend.
    expect(
      storageOps(
        parsePrometheus(
          ["# TYPE sbproxy_requests_total counter", "sbproxy_requests_total 5"].join(
            "\n",
          ),
        ),
      ),
    ).toBeUndefined();
  });

  it("treats a missing error counter as a true zero once latency is reported", () => {
    // The error counter increments only on Err, so a backend that has
    // never failed publishes latency and no error family at all. That is
    // a real zero and must be shown as one.
    const clean = [
      "# TYPE storage_op_duration_seconds histogram",
      ...histogram(
        "get",
        "in_memory",
        "ephemeral",
        [
          ["0.001", 10],
          ["+Inf", 10],
        ],
        0.002,
        10,
      ),
    ].join("\n");

    const report = storageOps(parsePrometheus(clean));
    expect(report).toBeDefined();
    expect(report?.errors).toBe(0);
    expect(report?.errorRate).toBe(0);
    expect(report?.errorsByKind).toEqual([]);
    expect(report?.backends).toEqual(["in_memory"]);
  });

  it("still reports when only the error counter is present", () => {
    const report = storageOps(
      parsePrometheus(
        [
          "# TYPE storage_op_errors_total counter",
          'storage_op_errors_total{op="get",backend="redis",kind="ephemeral",error_kind="unavailable"} 9',
        ].join("\n"),
      ),
    );

    expect(report?.operations).toBe(0);
    expect(report?.errors).toBe(9);
    // No denominator, but failures are real: do not render 0%.
    expect(report?.errorRate).toBe(1);
    expect(report?.p95Seconds).toBeUndefined();
  });
});
