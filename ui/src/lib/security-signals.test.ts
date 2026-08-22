import { describe, expect, it } from "vitest";

import { parsePrometheus } from "./metrics";
import {
  certStoreStatus,
  corsRefusals,
  legacySignatureDerivations,
  CERT_STORE_DEGRADED_FAMILY,
  CORS_REFUSALS_FAMILY,
  SIGNATURE_LEGACY_DERIVATION_FAMILY,
} from "./security-signals";

/** A scrape carrying no security families at all. */
const UNRELATED = [
  "# TYPE sbproxy_requests_total counter",
  'sbproxy_requests_total{hostname="api.example.com",status="200"} 42',
].join("\n");

function families(...lines: string[]) {
  return parsePrometheus([UNRELATED, ...lines].join("\n"));
}

describe("metric family names", () => {
  // These three literals are the whole contract with the exporter. A
  // rename in crates/sbproxy-observe/src/metric_registry.rs has to break
  // here rather than draw a flat zero in the console forever.
  it("names the exact families the registry declares", () => {
    expect(CORS_REFUSALS_FAMILY).toBe("sbproxy_cors_refusals_total");
    expect(SIGNATURE_LEGACY_DERIVATION_FAMILY).toBe(
      "sbproxy_signature_legacy_derivation_total",
    );
    expect(CERT_STORE_DEGRADED_FAMILY).toBe("sbproxy_cert_store_degraded");
  });
});

describe("corsRefusals", () => {
  it("is undefined when the counter was never registered", () => {
    // Not zero. The counter is created on the first refusal, so a scrape
    // without it means nothing has been refused, and rendering a 0 would
    // claim a measurement nobody took.
    expect(corsRefusals(families())).toBeUndefined();
  });

  it("totals the refusals and breaks them down by reason", () => {
    const signal = corsRefusals(
      families(
        "# TYPE sbproxy_cors_refusals_total counter",
        'sbproxy_cors_refusals_total{reason="wildcard_with_credentials"} 17',
      ),
    );
    expect(signal).toEqual({
      total: 17,
      breakdown: [{ key: "wildcard_with_credentials", value: 17 }],
    });
  });

  it("is undefined for a family the scrape names but never sampled", () => {
    // parsePrometheus creates a family from a bare HELP or TYPE line.
    // Summing that gives 0, which is the healthy-looking zero this whole
    // module exists to avoid drawing.
    expect(
      corsRefusals(families("# TYPE sbproxy_cors_refusals_total counter")),
    ).toBeUndefined();
    expect(
      legacySignatureDerivations(
        families("# TYPE sbproxy_signature_legacy_derivation_total counter"),
      ),
    ).toBeUndefined();
  });

  it("drops the synthetic (none) bucket rather than labeling it", () => {
    // groupByLabel invents "(none)" for a sample missing the label. A bar
    // named "(none)" reads as a refusal reason and is not one.
    const signal = corsRefusals(
      families(
        "# TYPE sbproxy_cors_refusals_total counter",
        "sbproxy_cors_refusals_total 3",
      ),
    );
    expect(signal?.total).toBe(3);
    expect(signal?.breakdown).toEqual([]);
  });
});

describe("legacySignatureDerivations", () => {
  it("is undefined when no signer has been accepted on the old base", () => {
    expect(legacySignatureDerivations(families())).toBeUndefined();
  });

  it("breaks the acceptances down by covered component, worst first", () => {
    const signal = legacySignatureDerivations(
      families(
        "# TYPE sbproxy_signature_legacy_derivation_total counter",
        'sbproxy_signature_legacy_derivation_total{component="@target-uri"} 4',
        'sbproxy_signature_legacy_derivation_total{component="@request-target"} 9',
      ),
    );
    expect(signal?.total).toBe(13);
    expect(signal?.breakdown).toEqual([
      { key: "@request-target", value: 9 },
      { key: "@target-uri", value: 4 },
    ]);
  });
});

describe("certStoreStatus", () => {
  it("reports not reported when the gauge is absent", () => {
    // The gauge is published on the success path too, so absent is a real
    // third state: no certificate store was opened on this node. It must
    // never render as the healthy zero.
    const status = certStoreStatus(families());
    expect(status.state).toBe("not-reported");
    expect(status.label).toBe("not reported");
    expect(status.tone).toBe("neutral");
    expect(status.backends).toEqual([]);
    expect(status.headline).toBeUndefined();
  });

  it("reports ok when the configured backend opened", () => {
    const status = certStoreStatus(
      families(
        "# TYPE sbproxy_cert_store_degraded gauge",
        'sbproxy_cert_store_degraded{backend="redb"} 0',
      ),
    );
    expect(status.state).toBe("opened");
    expect(status.tone).toBe("ok");
    expect(status.backends).toEqual(["redb"]);
    expect(status.degradedBackends).toEqual([]);
    expect(status.summary).toContain("redb");
    // No warning block for a store that actually persists.
    expect(status.headline).toBeUndefined();
  });

  it("does not call a memory backend healthy just because the gauge is zero", () => {
    // `acme.storage_backend: memory` is a supported value and it opens, so
    // the gauge honestly reads 0. Nothing is written down: certificates are
    // lost on restart and re-issued on every boot, which is the same cost
    // the degraded branch warns about. A green "ok" here would be the
    // healthy-looking reading this module exists to prevent.
    const status = certStoreStatus(
      families(
        "# TYPE sbproxy_cert_store_degraded gauge",
        'sbproxy_cert_store_degraded{backend="memory"} 0',
      ),
    );
    expect(status.state).toBe("ephemeral");
    expect(status.tone).toBe("warn");
    expect(status.label).toBe("in memory");
    expect(status.summary).toContain("do not persist");
    expect(status.headline).toBeDefined();
    expect(status.detail).toContain("acme.storage_backend");
  });

  it("prefers degraded over ephemeral when a backend is at 1", () => {
    const status = certStoreStatus(
      families(
        "# TYPE sbproxy_cert_store_degraded gauge",
        'sbproxy_cert_store_degraded{backend="memory"} 1',
      ),
    );
    expect(status.state).toBe("degraded");
    expect(status.headline).toBe(
      "The certificate store fell back to memory.",
    );
  });

  it("reports degraded with the backend named and what it costs", () => {
    const status = certStoreStatus(
      families(
        "# TYPE sbproxy_cert_store_degraded gauge",
        'sbproxy_cert_store_degraded{backend="sqlite"} 1',
      ),
    );
    expect(status.state).toBe("degraded");
    expect(status.tone).toBe("warn");
    expect(status.degradedBackends).toEqual(["sqlite"]);
    expect(status.detail).toContain("sqlite");
    expect(status.detail).toContain("in-memory store");
    expect(status.detail).toContain("acme.storage_path");
  });

  it("degrades if any backend is at 1, even next to one that opened", () => {
    // A zero next to a one must not average out into a healthy read.
    const status = certStoreStatus(
      families(
        "# TYPE sbproxy_cert_store_degraded gauge",
        'sbproxy_cert_store_degraded{backend="redb"} 0',
        'sbproxy_cert_store_degraded{backend="sqlite"} 1',
      ),
    );
    expect(status.state).toBe("degraded");
    expect(status.degradedBackends).toEqual(["sqlite"]);
    expect(status.backends).toEqual(["redb", "sqlite"]);
  });

  it("treats a registered gauge with no samples as not reported", () => {
    expect(
      certStoreStatus([
        { name: CERT_STORE_DEGRADED_FAMILY, type: "gauge", samples: [] },
      ]).state,
    ).toBe("not-reported");
  });
});
