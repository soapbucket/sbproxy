import { describe, expect, it } from "vitest";

import { parsePrometheus } from "./metrics";
import {
  IDLE_RECLAIM_REASON,
  MESH_INBOUND_REJECTED_FAMILY,
  inboundAdmission,
} from "./mesh-admission";

const SCRAPE = [
  "# HELP mesh_transport_inbound_rejected_total Inbound cache RPC connections refused",
  "# TYPE mesh_transport_inbound_rejected_total counter",
  'mesh_transport_inbound_rejected_total{reason="connection_limit"} 41',
  'mesh_transport_inbound_rejected_total{reason="handshake_failed"} 7',
  'mesh_transport_inbound_rejected_total{reason="idle_timeout"} 2140',
  "# TYPE mesh_peer_count gauge",
  "mesh_peer_count 3",
].join("\n");

describe("inbound mesh admission", () => {
  it("reads the family the mesh crate actually exports", () => {
    // The console curates families by name. If this constant and the name
    // in crates/sbproxy-mesh/src/metrics.rs ever disagree, the panel goes
    // quiet and says "not reported" over a node that is refusing peers.
    expect(MESH_INBOUND_REJECTED_FAMILY).toBe(
      "mesh_transport_inbound_rejected_total",
    );
  });

  it("keeps the idle reclaim out of the refusal count", () => {
    const report = inboundAdmission(parsePrometheus(SCRAPE));

    // 2140 idle reclaims on a quiet three-node cluster is normal. Summing
    // all six reasons would report 2188 "rejections" and send an operator
    // hunting an attack that is not happening.
    expect(report?.refusals).toBe(48);
    expect(report?.idleReclaims).toBe(2140);
    expect(report?.connectionLimit).toBe(41);
  });

  it("orders refusals ahead of reclaims, largest first inside each half", () => {
    const report = inboundAdmission(parsePrometheus(SCRAPE));

    expect(report?.rows.map((row) => row.reason)).toEqual([
      "connection_limit",
      "handshake_failed",
      IDLE_RECLAIM_REASON,
    ]);
    expect(report?.rows.map((row) => row.refusal)).toEqual([
      true,
      true,
      false,
    ]);
  });

  it("explains each reason in operator terms, including one it has no copy for", () => {
    const report = inboundAdmission(parsePrometheus(SCRAPE));

    expect(report?.rows[0].meaning).toContain("maximum inbound connections");
    expect(report?.rows[2].meaning).toContain("quiet cluster");

    const unknown = inboundAdmission(
      parsePrometheus(
        [
          "# TYPE mesh_transport_inbound_rejected_total counter",
          'mesh_transport_inbound_rejected_total{reason="quantum_flux"} 1',
        ].join("\n"),
      ),
    );
    expect(unknown?.rows[0].meaning).toContain("does not have copy for yet");
    expect(unknown?.rows[0].refusal).toBe(true);
  });

  it("reports absent rather than zero when the counter has never incremented", () => {
    // The family registers lazily on its first increment, so a node that
    // has refused nothing publishes no family at all. Returning a zeroed
    // report here would draw a healthy-looking zero over a signal that has
    // never been observed.
    const report = inboundAdmission(
      parsePrometheus(["# TYPE mesh_peer_count gauge", "mesh_peer_count 3"].join("\n")),
    );

    expect(report).toBeUndefined();
  });

  it("reports a real zero when the family is present and empty", () => {
    const report = inboundAdmission(
      parsePrometheus(
        [
          "# TYPE mesh_transport_inbound_rejected_total counter",
          'mesh_transport_inbound_rejected_total{reason="idle_timeout"} 0',
        ].join("\n"),
      ),
    );

    expect(report).toBeDefined();
    expect(report?.refusals).toBe(0);
    expect(report?.idleReclaims).toBe(0);
  });
});
