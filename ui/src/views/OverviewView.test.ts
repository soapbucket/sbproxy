import { describe, expect, it } from "vitest";

import overviewView from "./OverviewView.vue?raw";

describe("Overview certificate store visibility", () => {
  it("reads the scrape for the gauge and loads it on mount", () => {
    // /health does not carry the certificate store, so the page reads
    // the metrics endpoint for this one gauge. `refresh` is what
    // onMounted calls, so the new handle has to be in it or the row
    // never appears.
    expect(overviewView).toContain("api.metrics()");
    expect(overviewView).toContain("certMetrics.run()");
    expect(overviewView).toMatch(/onMounted\([\s\S]*?refresh/);
  });

  it("derives the state through the shared reader, not a sum", () => {
    // sumSamples(undefined) is 0, which would render "no certificate
    // store configured" as "the store opened cleanly".
    expect(overviewView).toContain("certStoreStatus(parsePrometheus(text))");
    expect(overviewView).not.toContain("sumSamples");
  });

  it("hoists every non-persisting state into a warning block, not a row to read past", () => {
    // Gating on `headline` rather than on `state === 'degraded'` is what
    // gets the memory backend into the block. It opens cleanly, so it is
    // not degraded, and it still persists nothing.
    expect(overviewView).toContain('v-if="certStore?.headline"');
    expect(overviewView).not.toContain("certStore?.state === 'degraded'");
    expect(overviewView).toContain('class="cert-alert"');
    expect(overviewView).toContain("var(--sb-warn)");
  });

  it("renders the status through the shared badge with an explicit tone", () => {
    // "not reported" is not in StatusBadge's inferred vocabulary and
    // would fall back to neutral by accident rather than on purpose.
    expect(overviewView).toContain(
      '<StatusBadge :label="certRow.label" :tone="certRow.tone" />',
    );
    expect(overviewView).toContain("certificate store");
  });

  it("keeps the row when the scrape failed rather than dropping it", () => {
    // A dropped row reads as "no certificate store on this node", which is
    // a claim the console cannot make when the fetch never answered.
    expect(overviewView).toContain("certMetrics.error.value");
    expect(overviewView).toContain('label: "unavailable"');
  });

  it("shows the row whenever the scrape answered, even with no health components", () => {
    expect(overviewView).toContain(
      'v-if="healthComponents.length || certRow"',
    );
  });
});
