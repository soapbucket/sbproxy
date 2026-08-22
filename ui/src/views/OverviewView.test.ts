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
    expect(overviewView).toContain("onMounted(refresh)");
  });

  it("derives the state through the shared reader, not a sum", () => {
    // sumSamples(undefined) is 0, which would render "no certificate
    // store configured" as "the store opened cleanly".
    expect(overviewView).toContain("certStoreStatus(parsePrometheus(text))");
    expect(overviewView).not.toContain("sumSamples");
  });

  it("hoists the degraded state into a warning block, not a row to read past", () => {
    expect(overviewView).toContain("certStore?.state === 'degraded'");
    expect(overviewView).toContain(
      "The certificate store fell back to memory.",
    );
    expect(overviewView).toContain('class="cert-alert"');
    expect(overviewView).toContain("var(--sb-warn)");
  });

  it("renders the status through the shared badge with an explicit tone", () => {
    // "not reported" is not in StatusBadge's inferred vocabulary and
    // would fall back to neutral by accident rather than on purpose.
    expect(overviewView).toContain(
      '<StatusBadge :label="certStore.label" :tone="certStore.tone" />',
    );
    expect(overviewView).toContain("certificate store");
  });

  it("shows the row whenever the scrape answered, even with no health components", () => {
    expect(overviewView).toContain(
      'v-if="healthComponents.length || certStore"',
    );
  });
});
