import { describe, expect, it } from "vitest";
import { parsePrometheus } from "./metrics";
import {
  ScrapeHistory,
  rateSeries,
  ratioSeries,
  intervalQuantileSeries,
  bucketMap,
  lastValue,
} from "./timeseries";
import { findFamily, sumSamples } from "./metrics";
import type { MetricFamily } from "./metrics";

function requestScrape(byStatus: Record<string, number>): MetricFamily[] {
  const lines = Object.entries(byStatus).map(
    ([status, v]) => `sbproxy_requests_total{status="${status}"} ${v}`,
  );
  return parsePrometheus(lines.join("\n"));
}

function total(families: MetricFamily[]): number {
  return sumSamples(findFamily(families, "sbproxy_requests_total"));
}

describe("ScrapeHistory", () => {
  it("bounds retained snapshots to capacity", () => {
    const h = new ScrapeHistory(3);
    for (let i = 0; i < 5; i++) h.push(i * 1000, []);
    expect(h.snapshots.length).toBe(3);
    expect(h.snapshots[0].t).toBe(2000);
  });
});

describe("rateSeries", () => {
  it("computes per-second deltas between scrapes", () => {
    const snaps = [
      { t: 0, families: requestScrape({ "200": 100 }) },
      { t: 5000, families: requestScrape({ "200": 150 }) },
      { t: 10000, families: requestScrape({ "200": 155 }) },
    ];
    const series = rateSeries(snaps, total);
    expect(series).toEqual([
      { t: 5000, v: 10 },
      { t: 10000, v: 1 },
    ]);
  });

  it("clamps a counter reset to zero instead of a negative rate", () => {
    const snaps = [
      { t: 0, families: requestScrape({ "200": 500 }) },
      { t: 5000, families: requestScrape({ "200": 3 }) },
    ];
    expect(rateSeries(snaps, total)).toEqual([{ t: 5000, v: 0 }]);
  });
});

describe("ratioSeries", () => {
  const errors = (families: MetricFamily[]) =>
    sumSamples(findFamily(families, "sbproxy_requests_total"), { status: "500" });

  it("computes the delta ratio as a percentage", () => {
    const snaps = [
      { t: 0, families: requestScrape({ "200": 90, "500": 10 }) },
      { t: 5000, families: requestScrape({ "200": 170, "500": 30 }) },
    ];
    // 20 new errors out of 100 new requests.
    expect(ratioSeries(snaps, errors, total)).toEqual([{ t: 5000, v: 20 }]);
  });

  it("yields zero when the denominator does not move", () => {
    const snaps = [
      { t: 0, families: requestScrape({ "200": 90, "500": 10 }) },
      { t: 5000, families: requestScrape({ "200": 90, "500": 10 }) },
    ];
    expect(ratioSeries(snaps, errors, total)).toEqual([{ t: 5000, v: 0 }]);
  });
});

describe("intervalQuantileSeries", () => {
  function histScrape(buckets: Record<string, number>): MetricFamily[] {
    const lines = Object.entries(buckets).map(
      ([le, v]) => `sbproxy_request_duration_seconds_bucket{le="${le}"} ${v}`,
    );
    return parsePrometheus(lines.join("\n"));
  }

  it("computes the quantile of only the new observations", () => {
    const snaps = [
      // 100 observations, all fast.
      { t: 0, families: histScrape({ "0.1": 100, "1": 100, "+Inf": 100 }) },
      // 100 more, all between 0.1s and 1s.
      { t: 5000, families: histScrape({ "0.1": 100, "1": 200, "+Inf": 200 }) },
    ];
    const series = intervalQuantileSeries(
      snaps,
      "sbproxy_request_duration_seconds",
      0.5,
    );
    expect(series).toHaveLength(1);
    // Median of the delta interpolates inside the (0.1, 1] bucket.
    expect(series[0].v).toBeGreaterThan(0.1);
    expect(series[0].v).toBeLessThanOrEqual(1);
  });

  it("skips quiet intervals and bucket resets", () => {
    const quiet = [
      { t: 0, families: histScrape({ "1": 50, "+Inf": 50 }) },
      { t: 5000, families: histScrape({ "1": 50, "+Inf": 50 }) },
    ];
    expect(
      intervalQuantileSeries(quiet, "sbproxy_request_duration_seconds", 0.95),
    ).toEqual([]);

    const reset = [
      { t: 0, families: histScrape({ "1": 50, "+Inf": 50 }) },
      { t: 5000, families: histScrape({ "1": 2, "+Inf": 2 }) },
    ];
    expect(
      intervalQuantileSeries(reset, "sbproxy_request_duration_seconds", 0.95),
    ).toEqual([]);
  });
});

describe("bucketMap", () => {
  it("sums buckets across label sets by le", () => {
    const families = parsePrometheus(
      [
        'sbproxy_request_duration_seconds_bucket{hostname="a",le="0.1"} 5',
        'sbproxy_request_duration_seconds_bucket{hostname="b",le="0.1"} 7',
        'sbproxy_request_duration_seconds_bucket{hostname="a",le="+Inf"} 9',
      ].join("\n"),
    );
    const map = bucketMap(families, "sbproxy_request_duration_seconds");
    expect(map.get(0.1)).toBe(12);
    expect(map.get(Infinity)).toBe(9);
  });

  it("scopes to one label set when a filter is given", () => {
    const families = parsePrometheus(
      [
        'sbproxy_request_duration_seconds_bucket{hostname="a",le="0.1"} 5',
        'sbproxy_request_duration_seconds_bucket{hostname="b",le="0.1"} 7',
      ].join("\n"),
    );
    const map = bucketMap(families, "sbproxy_request_duration_seconds", {
      hostname: "b",
    });
    expect(map.get(0.1)).toBe(7);
  });
});

describe("lastValue", () => {
  it("reads the newest point", () => {
    expect(lastValue([])).toBeUndefined();
    expect(
      lastValue([
        { t: 1, v: 5 },
        { t: 2, v: 9 },
      ]),
    ).toBe(9);
  });
});
